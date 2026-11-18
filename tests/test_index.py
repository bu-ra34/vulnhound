from pathlib import Path

import pytest

from vulnhound.index import build_index, extract
from vulnhound.project import discover, module_name_for


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


@pytest.fixture
def proj(tmp_path):
    return write(
        tmp_path,
        {
            "src/app/__init__.py": "from .db import run as run_query\n",
            "src/app/db.py": (
                "import sqlite3\n\ndef run(q):\n"
                "    return sqlite3.connect('x').execute(q)\n"
            ),
            "src/app/views.py": (
                "import subprocess as sp\n"
                "from . import db\n"
                "from .db import run as r\n"
                "from app import run_query\n"
                "from flask import Flask\n"
                "app = Flask(__name__)\n\n"
                "@app.route('/x', methods=['GET'])\n"
                "async def view(request, *a, k=1, **kw):\n"
                "    db.run(request)\n    r(request)\n    run_query(1)\n"
                "    sp.run(['ls'])\n    return Svc(1).go()\n\n"
                "class Svc:\n"
                "    def __init__(self, x):\n        self.x = x\n"
                "    def go(self):\n        return self.helper()\n"
                "    def helper(self):\n        def inner():\n            return view(1)\n"
                "        return inner()\n"
                "class Sub(Svc):\n    def other(self):\n        return self.helper()\n"
                "print(view(1))\n"
            ),
            ".venv/lib/x.py": "x = 1\n",
            "node_modules/a.py": "",
            ".hidden/a.py": "",
        },
    )


def test_discover_and_module_names(proj):
    names = sorted(module_name_for(proj, p) for p in discover(proj))
    assert names == ["app", "app.db", "app.views"]
    (proj / "pkg").mkdir()
    (proj / "pkg" / "__init__.py").write_text("")
    assert module_name_for(proj, proj / "pkg" / "__init__.py") == "pkg"
    assert module_name_for(proj, proj / "setup.py") == "setup"


def test_extraction_and_resolution(proj):
    idx = build_index(proj, use_cache=False)
    v = idx.functions["app.views.view"]
    assert v.decorators == ["app.route"]
    assert v.params == ["request", "a", "k", "kw"]
    assert v.location.path == "src/app/views.py"
    assert v.end_line > v.location.line
    assert "app.db.run" in v.calls  # db.run, r(), and run_query re-export all collapse
    assert "subprocess.run" in v.calls  # alias
    assert "app.views.Svc.__init__" in v.calls  # class instantiation
    go = idx.functions["app.views.Svc.go"]
    assert go.is_method and go.calls == ["app.views.Svc.helper"]
    assert idx.functions["app.views.Sub.other"].calls == ["app.views.Svc.helper"]  # inherited
    inner = "app.views.Svc.helper.<locals>.inner"
    assert inner in idx.functions and idx.functions["app.views.Svc.helper"].calls == [inner]
    mod = idx.functions["app.views.<module>"]
    assert "app.views.view" in mod.calls and "print" in mod.calls
    assert idx.modules["app.views"].imports["r"] == "app.db.run"


def test_resolve_api(proj):
    idx = build_index(proj)
    assert idx.resolve("app.views", "db.run") == "app.db.run"
    assert idx.resolve("app.views", "sp.run") == "subprocess.run"
    got = idx.resolve("app.views", "self.helper", function="app.views.Svc.go")
    assert got == "app.views.Svc.helper"
    assert idx.resolve("app.views", "self.go") == "app.views.Svc.go"  # unique-method fallback
    assert idx.resolve("app.views", "nothing.here") == "nothing.here"


def test_call_graph_across_modules(proj):
    idx = build_index(proj)
    assert "app.views.view" in idx.callers("app.db.run")
    assert "app.views.<module>" in idx.callers("app.views.view")
    assert "app.db.run" in idx.callees("app.views.view")
    assert "subprocess.run" not in idx.callees("app.views.view")
    assert idx.callers("nope") == [] and idx.callees("nope") == []


def test_relative_import_in_subpackage(tmp_path):
    write(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a.py": "def f():\n    pass\n",
            "pkg/sub/__init__.py": "from ..a import f\n",
            "pkg/sub/b.py": (
                "from .. import a\nfrom . import f as g\n\ndef h():\n    a.f()\n    g()\n"
            ),
        },
    )
    idx = build_index(tmp_path, use_cache=False)
    assert idx.functions["pkg.sub.b.h"].calls == ["pkg.a.f"]


def test_ast_and_source_lines_lazy(proj):
    idx = build_index(proj)
    assert idx._ast == {}
    tree = idx.ast_for("app.db")
    assert idx.ast_for("app.db") is tree
    assert idx.source_lines("app.db")[2] == "def run(q):"


def test_syntax_error_and_encoding(tmp_path):
    write(tmp_path, {"ok.py": "def f():\n    pass\n", "bad.py": "def (:\n"})
    (tmp_path / "latin.py").write_bytes(b"# caf\xe9\ndef g():\n    pass\n")
    idx = build_index(tmp_path)
    assert idx.modules["bad"].parse_error and idx.modules["bad"].functions == []
    assert idx.modules["ok"].parse_error is None
    assert "latin.g" in idx.functions


def test_cache_hit_and_invalidation(proj, monkeypatch):
    calls = []
    real = extract.extract_module

    def counting(*a, **k):
        calls.append(a[0])
        return real(*a, **k)

    monkeypatch.setattr(extract, "extract_module", counting)
    first = build_index(proj)
    assert len(calls) == 3
    assert (proj / ".vulnhound" / "cache").is_dir()
    calls.clear()
    second = build_index(proj)
    assert calls == []
    assert second.functions["app.views.view"].calls == first.functions["app.views.view"].calls
    (proj / "src/app/db.py").write_text("def run(q):\n    return 1\n\ndef extra():\n    pass\n")
    third = build_index(proj)
    assert calls == ["app.db"]
    assert "app.db.extra" in third.functions


def test_corrupt_cache_ignored(proj):
    build_index(proj)
    for p in (proj / ".vulnhound" / "cache").glob("*.json"):
        p.write_text("{not json")
    idx = build_index(proj)
    assert "app.db.run" in idx.functions
    for p in (proj / ".vulnhound" / "cache").glob("*.json"):
        p.write_text('{"schema": 999}')
    assert "app.db.run" in build_index(proj).functions


def test_six_moves_and_future_shims_normalized(tmp_path):
    write(
        tmp_path,
        {
            "m.py": (
                "from six.moves.http_client import HTTPConnection\n"
                "from six.moves.urllib.request import urlopen\n"
                "from six.moves import cPickle, configparser\n"
                "from six.moves import urllib\n"
                "import six\n"
                "from future.moves.urllib.parse import urlparse\n"
            ),
        },
    )
    idx = build_index(tmp_path)
    r = lambda d: idx.resolve("m", d)  # noqa: E731
    assert r("HTTPConnection") == "http.client.HTTPConnection"
    assert r("urlopen") == "urllib.request.urlopen"
    assert r("cPickle.loads") == "pickle.loads"
    assert r("configparser.ConfigParser") == "configparser.ConfigParser"
    assert r("urllib.request.urlopen") == "urllib.request.urlopen"
    assert r("six.moves.cPickle.load") == "pickle.load"
    assert r("urlparse") == "urllib.parse.urlparse"
