import json
import os
import textwrap
from types import SimpleNamespace

import pytest

from vulnhound import cli, prove, store
from vulnhound.models import Finding, Location, Severity

FID = "VH-test01"


def _finding():
    return Finding(
        FID, "path-traversal", "CWE-22", Severity.HIGH, 0.8, "msg",
        Location("app.py", 3), Location("app.py", 5), "app.read_file", [],
    )


@pytest.fixture
def proj(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    store.save_findings(root, [_finding()], {"root": str(root)})
    poc = tmp_path / "poc.py"
    poc.write_text("print('x')\n")
    return root, poc


def _fake(monkeypatch, **kw):
    base = dict(backend="fake", available=True, exit_code=0, stdout="", stderr="",
                timed_out=False, killed=False, reason=None, duration_s=0.1)
    base.update(kw)
    calls = []

    def fake(argv, **k):
        calls.append((argv, k))
        return SimpleNamespace(**base)

    monkeypatch.setattr(prove, "run_sandboxed", fake)
    return calls


def _run(root, poc, **kw):
    return prove.run(root, FID, poc, **kw)


def test_proven(proj, monkeypatch, capsys):
    root, poc = proj
    calls = _fake(monkeypatch, stdout="noise\nVULNHOUND-PROVEN: read canary\n")
    assert _run(root, poc) == 0
    out = capsys.readouterr().out
    assert out.startswith("PROVEN") and "read canary" in out and "noise" not in out
    argv, k = calls[0]
    # root is exposed read-only and first on PYTHONPATH; the vulnhound package
    # dir is also exposed so the PoC can import vulnhound.poc inside the sandbox.
    assert root in k["read_only_paths"]
    assert k["env"]["PYTHONPATH"].split(os.pathsep)[0] == str(root)
    assert "VULNHOUND_CANARY" in k["env"]


def test_safe(proj, monkeypatch, capsys):
    root, poc = proj
    _fake(monkeypatch, stdout="VULNHOUND-SAFE: blocked\n")
    assert _run(root, poc) == 1
    assert capsys.readouterr().out.startswith("SAFE")
    _fake(monkeypatch, stdout="")
    assert _run(root, poc) == 1


def test_unavailable(proj, monkeypatch, capsys):
    root, poc = proj
    _fake(monkeypatch, available=False, exit_code=None, reason="no sandbox backend")
    assert _run(root, poc) == 3
    assert "UNVERIFIED" in capsys.readouterr().out


@pytest.mark.parametrize("kw", [{"timed_out": True}, {"killed": True, "reason": "oom"}])
def test_timeout_killed(proj, monkeypatch, capsys, kw):
    root, poc = proj
    _fake(monkeypatch, exit_code=None, **kw)
    assert _run(root, poc) == 3
    assert "UNVERIFIED" in capsys.readouterr().out


def test_poc_error(proj, monkeypatch, capsys):
    root, poc = proj
    _fake(monkeypatch, exit_code=1, stderr="Traceback ... ImportError")
    assert _run(root, poc) == 3
    assert "ImportError" in capsys.readouterr().out


def test_json(proj, monkeypatch, capsys):
    root, poc = proj
    _fake(monkeypatch, stdout="VULNHOUND-PROVEN: ok\n")
    assert _run(root, poc, as_json=True) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["verdict"] == "PROVEN" and d["detail"] == "ok"


def test_unknown_id_and_missing_store(proj, tmp_path, capsys):
    root, poc = proj
    assert prove.run(root, "VH-nope", poc) == 2
    assert prove.run(tmp_path / "empty", FID, poc) == 2
    assert capsys.readouterr().out == ""


def test_cli_prove_wired(proj, monkeypatch, capsys):
    root, poc = proj
    _fake(monkeypatch, stdout="VULNHOUND-PROVEN: x\n")
    rc = cli.main(["prove", FID, "--poc", str(poc), "--root", str(root), "--json"])
    assert rc == 0 and json.loads(capsys.readouterr().out)["verdict"] == "PROVEN"


# ---- real sandbox integration ----

def _backends():
    try:
        from vulnhound.sandbox import available_backends

        return available_backends()
    except ImportError:
        return []


needs_sandbox = pytest.mark.skipif(not _backends(), reason="no sandbox backend available")

POC = textwrap.dedent(
    """
    import os
    from vulnhound.poc import canary_path, proven, safe
    import app
    target = os.path.relpath(canary_path(), app.BASE)
    try:
        data = app.read_file(target)
    except Exception as e:
        safe(f"blocked: {e}")
        raise SystemExit(0)
    if data.startswith("VH-CANARY-"):
        proven("read canary via traversal")
    else:
        safe("no leak")
    """
)

APP = textwrap.dedent(
    """
    import os
    BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")

    def read_file(user_path):
        with open(os.path.join(BASE, %s)) as fh:
            return fh.read()
    """
)


def _build(tmp_path, expr):
    root = tmp_path / "proj"
    (root / "files").mkdir(parents=True)
    (root / "files" / "a.txt").write_text("hello")
    (root / "app.py").write_text(APP % expr)
    store.save_findings(root, [_finding()], {"root": str(root)})
    poc = tmp_path / "poc.py"
    poc.write_text(POC)
    return root, poc


@needs_sandbox
def test_integration_proven(tmp_path, capsys):
    root, poc = _build(tmp_path, "user_path")
    be = "unshare" if "unshare" in _backends() else "auto"
    assert prove.run(root, FID, poc, backend=be, timeout=30) == 0
    assert capsys.readouterr().out.startswith("PROVEN")


@needs_sandbox
def test_integration_safe(tmp_path, capsys):
    root, poc = _build(tmp_path, "os.path.basename(user_path)")
    be = "unshare" if "unshare" in _backends() else "auto"
    assert prove.run(root, FID, poc, backend=be, timeout=30) == 1
    assert capsys.readouterr().out.startswith("SAFE")
