"""`vulnhound prove`: run a PoC in a sandbox and report PROVEN / SAFE / UNVERIFIED."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

from vulnhound.poc import PROVEN_MARKER, SAFE_MARKER

run_sandboxed = None

EXIT_PROVEN, EXIT_SAFE, EXIT_USAGE, EXIT_UNVERIFIED = 0, 1, 2, 3


def _detail(stdout: str, marker: str) -> str:
    for line in stdout.splitlines():
        if line.startswith(marker):
            return line[len(marker) :].lstrip(": ").strip()
    return ""


def _tail(text: str, n: int = 300) -> str:
    return text.strip()[-n:]


def _verdict(res) -> tuple[str, str, int]:
    """Map a SandboxResult to (verdict, detail, exit code)."""
    if not res.available:
        return "UNVERIFIED", res.reason or "no sandbox available (need docker or unshare)", 3
    if res.killed or res.timed_out:
        why = res.reason or ("timed out" if res.timed_out else "killed")
        return "UNVERIFIED", why, 3
    if PROVEN_MARKER in res.stdout:
        return "PROVEN", _detail(res.stdout, PROVEN_MARKER), 0
    if res.exit_code == 0:
        return "SAFE", _detail(res.stdout, SAFE_MARKER), 1
    if SAFE_MARKER in res.stdout:
        return "SAFE", _detail(res.stdout, SAFE_MARKER), 1
    return "UNVERIFIED", f"PoC error (exit {res.exit_code}): {_tail(res.stderr)}", 3


def run(
    root: Path,
    finding_id: str,
    poc: Path,
    *,
    backend: str = "auto",
    timeout: float = 10.0,
    as_json: bool = False,
    verbose: bool = False,
) -> int:
    from vulnhound import store

    try:
        finding = store.get_finding(root, finding_id)
    except FileNotFoundError:
        print("vulnhound: no findings stored; run `vulnhound analyze` first", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, ValueError, KeyError) as e:
        print(f"vulnhound: could not read stored findings: {e}", file=sys.stderr)
        return EXIT_USAGE
    if finding is None:
        print(f"vulnhound: unknown finding id: {finding_id}", file=sys.stderr)
        return EXIT_USAGE
    if not poc.is_file():
        print(f"vulnhound: PoC file not found: {poc}", file=sys.stderr)
        return EXIT_USAGE

    global run_sandboxed
    if run_sandboxed is None:  # lazy import; tests may monkeypatch the module attribute
        try:
            from vulnhound.sandbox import run_sandboxed as _rs
        except ImportError:
            print("UNVERIFIED " + finding_id + ": sandbox module unavailable")
            return EXIT_UNVERIFIED
        run_sandboxed = _rs
    workdir = Path(tempfile.mkdtemp(prefix="vulnhound-prove-"))
    try:
        poc_in = workdir / "poc.py"
        shutil.copyfile(poc, poc_in)
        token = "VH-CANARY-" + secrets.token_hex(8)
        canary = workdir / "canary.txt"
        canary.write_text(token, encoding="utf-8")
        # Expose the vulnhound package itself read-only so the PoC can
        # `from vulnhound.poc import proven, safe, canary_path` inside the sandbox.
        pkg_dir = Path(__file__).resolve().parent.parent  # the dir containing `vulnhound/`
        ro_paths = [root]
        if pkg_dir != root and pkg_dir not in ro_paths:
            ro_paths.append(pkg_dir)
        env = {
            "PYTHONPATH": os.pathsep.join(str(p) for p in (root, pkg_dir)),
            "VULNHOUND_CANARY": str(canary),
        }
        res = run_sandboxed(
            ["python3", str(poc_in)],
            workdir=workdir,
            read_only_paths=ro_paths,
            env=env,
            timeout_s=timeout,
            backend=None if backend == "auto" else backend,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    verdict, detail, code = _verdict(res)
    if as_json:
        out = {
            "id": finding_id,
            "verdict": verdict,
            "detail": detail,
            "backend": res.backend,
            "exit_code": res.exit_code,
            "duration_s": round(res.duration_s, 3),
        }
        if verbose:
            out["stdout"], out["stderr"] = res.stdout, res.stderr
        print(json.dumps(out))
    else:
        print(f"{verdict} {finding_id}" + (f": {detail}" if detail else ""))
        if verbose:
            print(f"-- backend={res.backend} exit={res.exit_code}\n{res.stdout}", end="")
            if res.stderr:
                print(f"-- stderr\n{res.stderr}", file=sys.stderr, end="")
    return code
