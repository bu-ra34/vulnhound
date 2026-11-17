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


def test_slice_not_implemented(capsys):
    assert main(["slice", "VH-000000"]) == 2
    assert "not implemented" in capsys.readouterr().err
