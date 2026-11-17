from __future__ import annotations

from pathlib import Path

from vulnhound import slicer
from vulnhound.index import build_index
from vulnhound.models import Finding, Location, Severity, Step
from vulnhound.store import save_findings

APP = """\
import sqlite3
from flask import Flask, request

app = Flask(__name__)
UNRELATED = 1


def helper():
    return 42


def run_query(q):
    # a comment
    conn = sqlite3.connect("x.db")
    cur = conn.cursor()
    return cur.execute(q)


@app.route("/user")
def user():
    name = request.args["name"]
    unrelated = helper()
    if not name.isalnum():
        return "bad"
    q = "SELECT * FROM u WHERE n = '" + name + "'"
    print(unrelated)
    return run_query(q)
"""


def _setup(tmp_path: Path, app: str = APP) -> tuple[Path, Finding]:
    (tmp_path / "app.py").write_text(app)
    f = Finding(
        id="VH-abc123", rule="sqli", cwe="CWE-89", severity=Severity.HIGH, confidence=0.9,
        message="m", source=Location("app.py", 21), sink=Location("app.py", 16),
        function="app.run_query",
        path=[
            Step(Location("app.py", 21), 'name = request.args["name"]', "source"),
            Step(Location("app.py", 25), "q = \"SELECT * FROM u WHERE n = '\" + name + \"'\"", "q"),
            Step(Location("app.py", 27), "return run_query(q)", "call"),
            Step(Location("app.py", 16), "return cur.execute(q)", "sink"),
        ],
    )  # fmt: skip
    save_findings(tmp_path, [f], {})
    return tmp_path, f


def test_slice_content(tmp_path):
    root, f = _setup(tmp_path)
    out = slicer.build_slice(build_index(root), f)
    lines = out.splitlines()
    assert lines[0] == "VH-abc123 sqli CWE-89 high conf=0.9"
    assert "# app.py :: app.user" in out and "# app.py :: app.run_query" in out
    assert any(ln.startswith("  21| ") and ln.endswith("◀ source") for ln in lines)
    assert any(ln.startswith("  16| ") and ln.endswith("◀ sink") for ln in lines)
    assert '  19| @app.route("/user")' in out  # decorator kept
    assert "  23| " in out and "isalnum" in out  # guard if
    assert '  24|         return "bad"' in out
    assert "helper()" not in out and "UNRELATED" not in out and "# a comment" not in out
    assert "   …" in out
    assert "file changed" not in out
    # interprocedural: callee def + hop appear, user() comes before run_query()
    assert out.index("app.user") < out.index("app.run_query")
    assert "def run_query(q):" in out


def test_line_cap(tmp_path):
    root, f = _setup(tmp_path)
    out = slicer.build_slice(build_index(root), f, max_lines=14)
    assert len(out.splitlines()) <= 14
    assert "◀ sink" in out and "◀ source" in out
    assert "isalnum" not in out  # optional guard dropped first


def test_changed_file_warning(tmp_path):
    root, f = _setup(tmp_path)
    p = root / "app.py"
    p.write_text(p.read_text().replace("cur.execute(q)", "cur.executescript(q)"))
    out = slicer.build_slice(build_index(root), f)
    assert "! file changed since analyze; re-run vulnhound analyze" in out


def test_run_ok_and_errors(tmp_path, capsys):
    assert slicer.run(tmp_path, "VH-abc123") == 2
    assert "vulnhound analyze" in capsys.readouterr().err
    root, _ = _setup(tmp_path)
    assert slicer.run(root, "VH-nope") == 2
    assert "unknown" in capsys.readouterr().err
    assert slicer.run(root, "VH-abc123") == 0
    assert "VH-abc123 sqli" in capsys.readouterr().out


def test_slice_includes_helper_and_strips_expect(tmp_path):
    from vulnhound.taint.engine import analyze

    root = Path(__file__).parent / "fixtures" / "vuln"
    index = build_index(root, use_cache=False)
    (f,) = [x for x in analyze(index) if x.sink.path == "pkg_helpers/app.py"]
    out = slicer.build_slice(index, f)
    assert "def _normalize(text):" in out
    assert 'return " ".join(parts)' in out
    assert "def make_command(opts):" in out
    assert 'return "convert " + cleaned' in out
    assert "VH-EXPECT" not in out
    (g,) = [x for x in analyze(index) if x.sink.path == "pkg_inter/shell.py"]
    out = slicer.build_slice(index, g)
    assert "def _build(opts):" in out and 'return "mytool " + opts' in out
    assert "VH-EXPECT" not in out
