import json

from vulnhound import __version__
from vulnhound.cli import main


def test_version(capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == __version__


def _make_tree(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\ny = 2\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "skip.py").write_text("z = 3\n")
    (tmp_path / ".hidden").mkdir()
    (tmp_path / ".hidden" / "skip.py").write_text("z = 3\n")


def test_estimate_text(tmp_path, capsys):
    _make_tree(tmp_path)
    assert main(["estimate", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "1 .py files, 2 lines" in out
    assert "naive (read whole repo)" in out


def test_estimate_json(tmp_path, capsys):
    _make_tree(tmp_path)
    assert main(["estimate", str(tmp_path), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["files"] == 1 and data["lines"] == 2
    assert data["bytes"] == 12 and data["naive_tokens"] == 3


def test_slice_without_analysis(tmp_path, capsys):
    assert main(["slice", "VH-000000", "--root", str(tmp_path)]) == 2
    assert "analyze" in capsys.readouterr().err


_VULN = (
    "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n"
    "@app.route('/x')\ndef x():\n    os.system(request.args['c'])\n"
)


def test_discover_excludes_tests_below_root_only(tmp_path):
    from vulnhound.project import discover

    root = tmp_path / "tests" / "proj"  # ancestors named tests must not matter
    (root / "tests").mkdir(parents=True)
    (root / "pkg").mkdir()
    (root / "tests" / "t.py").write_text("x=1\n")
    (root / "pkg" / "test_a.py").write_text("x=1\n")
    (root / "pkg" / "a_test.py").write_text("x=1\n")
    (root / "conftest.py").write_text("x=1\n")
    (root / "pkg" / "a.py").write_text("x=1\n")
    assert [p.name for p in discover(root, include_tests=False)] == ["a.py"]
    assert len(discover(root)) == 5


def test_analyze_excludes_tests_by_default(tmp_path, capsys):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "app.py").write_text(_VULN)
    assert main(["analyze", str(tmp_path), "--no-cache"]) == 0
    assert main(["analyze", str(tmp_path), "--no-cache", "--include-tests"]) == 1


def test_analyze_groups_and_no_group(tmp_path, capsys):
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/x')\ndef x():\n    c = request.args['c']\n    d = request.args['d']\n"
        "    os.system(c)\n    os.system(d)\n"
    )
    main(["analyze", str(tmp_path), "--no-cache", "--json"])
    grouped = json.loads(capsys.readouterr().out)["findings"]
    main(["analyze", str(tmp_path), "--no-cache", "--json", "--no-group"])
    flat = json.loads(capsys.readouterr().out)["findings"]
    assert len(flat) >= 2 and len(grouped) == 1 and grouped[0]["n"] == len(flat)
    # all ids stay sliceable
    for f in flat:
        assert main(["slice", f["id"], "--root", str(tmp_path)]) == 0
        capsys.readouterr()
