"""vulnhound command line interface. Output is deliberately terse."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from vulnhound import __version__

SKIP_DIRS = {
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    "venv",
    "env",
    "site-packages",
}
EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2
SEVERITIES = ["low", "medium", "high", "critical"]


def _not_implemented(what: str) -> int:
    print(
        f"vulnhound: '{what}' is not implemented yet in this version ({__version__}).",
        file=sys.stderr,
    )
    return EXIT_USAGE


def _skip_dir(name: str) -> bool:
    return name.startswith(".") or name in SKIP_DIRS or name.endswith(".egg-info")


def estimate_tree(root: Path) -> dict:
    files = lines = size = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            try:
                data = (Path(dirpath) / fn).read_bytes()
            except OSError:
                continue
            files += 1
            size += len(data)
            lines += data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    return {
        "root": str(root),
        "files": files,
        "lines": lines,
        "bytes": size,
        "naive_tokens": size // 4,
    }


def cmd_estimate(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.is_dir():
        print(f"vulnhound: not a directory: {root}", file=sys.stderr)
        return EXIT_USAGE
    est = estimate_tree(root)
    if args.json:
        print(json.dumps(est))
        return EXIT_OK
    print(f"{est['files']} .py files, {est['lines']} lines, {est['bytes']} bytes")
    print(f"naive (read whole repo): ~{est['naive_tokens']} tokens (bytes/4)")
    print("vulnhound: Claude reads only `analyze` output + small slices, not the repo.")
    return EXIT_OK


def cmd_analyze(args: argparse.Namespace) -> int:
    from vulnhound import report, store
    from vulnhound.index import build_index
    from vulnhound.taint.engine import analyze

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"vulnhound: not a directory: {root}", file=sys.stderr)
        return EXIT_USAGE
    findings = analyze(build_index(root, use_cache=not args.no_cache))
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings = [f for f in findings if order[f.severity.value] >= order[args.min_severity]]
    findings.sort(key=lambda f: (-order[f.severity.value], f.sink.path, f.sink.line))
    meta = {"version": __version__, "root": str(root)}
    try:
        store.save_findings(root, findings, meta)
    except OSError as e:
        print(f"vulnhound: could not save findings: {e}", file=sys.stderr)
    if args.json:
        print(report.to_json(findings, meta))
    else:
        for f in findings:
            print(f"{f.severity.value.upper()} {f.id} {f.rule} {f.sink} {f.message}")
        if not findings:
            print("no findings")
    return EXIT_FINDINGS if findings else EXIT_OK


def cmd_slice(args: argparse.Namespace) -> int:
    try:
        from vulnhound import slicer  # type: ignore[attr-defined]
    except ImportError:
        return _not_implemented("slice")
    return slicer.run(Path(args.root).resolve(), args.id)


def cmd_prove(args: argparse.Namespace) -> int:
    try:
        from vulnhound import prove  # type: ignore[attr-defined]
    except ImportError:
        return _not_implemented("prove")
    return prove.run(args.id, Path(args.poc))


def cmd_report(args: argparse.Namespace) -> int:
    from vulnhound import report, store
    from vulnhound.index import build_index
    from vulnhound.taint.engine import analyze

    root = Path(args.root).resolve()
    try:
        findings, meta = store.load_findings(root)
    except (OSError, ValueError, KeyError):
        findings = analyze(build_index(root))
        meta = {}
    meta = {**meta, "version": __version__, "root": meta.get("root", str(root))}
    render = {"json": report.to_json, "sarif": report.to_sarif, "markdown": report.to_markdown}
    out = render[args.format](findings, meta)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)
    return EXIT_OK


def cmd_version(_: argparse.Namespace) -> int:
    print(__version__)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnhound",
        description="Token-thrifty vulnerability finder for Python projects.",
    )
    sub = p.add_subparsers(dest="cmd", metavar="<command>")

    a = sub.add_parser("analyze", help="static taint analysis, short JSON output")
    a.add_argument("path", nargs="?", default=".")
    a.add_argument("--json", action="store_true", help="machine-readable output")
    a.add_argument("--no-cache", action="store_true", help="ignore the index cache")
    a.add_argument("--min-severity", choices=SEVERITIES, default="low")
    a.set_defaults(func=cmd_analyze)

    s = sub.add_parser("slice", help="print the minimal code slice for a finding")
    s.add_argument("id")
    s.add_argument("--root", default=".", help="project root of the last analyze run")
    s.set_defaults(func=cmd_slice)

    pr = sub.add_parser("prove", help="run a PoC for a finding in a sandbox")
    pr.add_argument("id")
    pr.add_argument("--poc", required=True, metavar="FILE")
    pr.add_argument("--root", default=".", help="project root of the last analyze run")
    pr.set_defaults(func=cmd_prove)

    e = sub.add_parser("estimate", help="estimate tokens to naively read the repo")
    e.add_argument("path", nargs="?", default=".")
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=cmd_estimate)

    r = sub.add_parser("report", help="render findings as json, sarif or markdown")
    r.add_argument("--format", choices=["json", "sarif", "markdown"], default="markdown")
    r.add_argument("-o", "--output", metavar="FILE")
    r.add_argument("--root", default=".", help="project root (default: current directory)")
    r.set_defaults(func=cmd_report)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
