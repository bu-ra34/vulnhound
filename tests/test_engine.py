"""Unit tests for the taint engine, each on a tiny tmp project."""

from __future__ import annotations

import textwrap

from vulnhound.index import build_index
from vulnhound.taint.engine import analyze


def run(tmp_path, files: dict[str, str]):
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return analyze(build_index(tmp_path, use_cache=False))


def lines(findings):
    return sorted(f.sink.line for f in findings)


def marked(tmp_path, name):
    """1-based line numbers of source lines tagged ``# SINK``."""
    text = (tmp_path / name).read_text().splitlines()
    return [i for i, ln in enumerate(text, 1) if "# SINK" in ln]


def rules(findings):
    return sorted(f.rule for f in findings)


FLASK = "from flask import Flask, request\napp = Flask(__name__)\n"


def test_sqli_fstring_and_percent(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import sqlite3
@app.route("/a")
def a():
    c = sqlite3.connect("x").cursor()
    c.execute("select * from t where n = '%s'" % request.args["n"])
    c.execute(f"select * from t where n = {request.form['n']}")
"""
        },
    )
    assert rules(fs) == ["sqli", "sqli"]
    assert all(f.sink.path == "a.py" for f in fs)
    assert fs[0].message.startswith("request.")


def test_sqli_parameterized_is_safe(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import sqlite3
@app.route("/a")
def a():
    c = sqlite3.connect("x").cursor()
    c.execute("select * from t where n = ?", (request.args["n"],))
"""
        },
    )
    assert fs == []


def test_cmdi_shell_true_vs_list(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import subprocess
@app.route("/a")
def a():
    subprocess.run("ls " + request.args["d"], shell=True)
@app.route("/b")
def b():
    subprocess.run(["ls", "-l"])
"""
        },
    )
    assert rules(fs) == ["cmdi"]
    assert fs[0].severity.value == "critical"


def test_cmdi_list_argv_is_medium(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import subprocess
@app.route("/a")
def a():
    subprocess.run(["ls", request.args["d"]])
"""
        },
    )
    assert [f.severity.value for f in fs] == ["medium"]


def test_code_exec_ssti_ssrf_pathtrav_deser_redirect(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import pickle, requests
from flask import redirect, render_template_string
@app.route("/a")
def a():
    x = request.args["x"]
    eval(x)
    render_template_string(x)
    requests.get(x)
    open(x)
    pickle.loads(request.data)
    return redirect(x)
"""
        },
    )
    assert rules(fs) == [
        "code-exec",
        "deserialization",
        "open-redirect",
        "path-traversal",
        "ssrf",
        "ssti",
    ]


def test_sanitizers(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import os, shlex, subprocess
@app.route("/a")
def a():
    d = shlex.quote(request.args["d"])
    subprocess.run(f"ls {d}", shell=True)
    n = int(request.args["n"])
    os.system("echo " + str(n))
    open(os.path.basename(request.args["f"]))
"""
        },
    )
    assert fs == []


def test_sanitizer_is_rule_specific(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import os, shlex
@app.route("/a")
def a():
    d = shlex.quote(request.args["d"])
    open(d)
"""
        },
    )
    assert rules(fs) == ["path-traversal"]


def test_yaml_loader(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import yaml
@app.route("/a")
def a():
    yaml.load(request.data, Loader=yaml.SafeLoader)
    yaml.safe_load(request.data)
    yaml.load(request.data)  # SINK
"""
        },
    )
    assert rules(fs) == ["deserialization"]
    assert lines(fs) == marked(tmp_path, "a.py")


def test_fastapi_int_param_safe_str_param_flagged(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": """
        import sqlite3
        from fastapi import FastAPI
        app = FastAPI()
        @app.get("/a/{i}")
        def a(i: int):
            return sqlite3.connect("x").execute(f"select {i}")
        @app.get("/b")
        def b(q: str):
            return sqlite3.connect("x").execute(f"select {q}")  # SINK
        """
        },
    )
    assert rules(fs) == ["sqli"]
    assert lines(fs) == marked(tmp_path, "a.py")


def test_django_request_param(tmp_path):
    fs = run(
        tmp_path,
        {
            "views.py": """
        import os
        def v(request):
            os.system(request.GET["c"])
        def w(request):
            os.system(request.method)
        """
        },
    )
    assert rules(fs) == ["cmdi"]
    assert fs[0].sink.line == 4


def test_script_sources_and_weak_env(tmp_path):
    fs = run(
        tmp_path,
        {
            "s.py": """
        import os, sys
        os.system("x " + sys.argv[1])
        os.system("x " + os.environ["HOME"])
        """
        },
    )
    assert len(fs) == 2
    by_line = {f.sink.line: f for f in fs}
    assert by_line[3].severity.value == "critical"
    weak = by_line[4]
    assert weak.severity.value == "high" and weak.confidence < by_line[3].confidence


def test_interprocedural_across_modules(tmp_path):
    fs = run(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/db.py": """
            import os
            def q(name):
                return os.popen("echo " + name).read()  # SINK
            """,
            "pkg/web.py": """
            from flask import Flask, request
            from pkg.db import q
            app = Flask(__name__)
            @app.route("/")
            def v():
                return str(q(request.args["n"]))
            """,
        },
    )
    assert rules(fs) == ["cmdi"]
    f = fs[0]
    assert f.sink.path == "pkg/db.py" and f.source.path == "pkg/web.py"
    assert f.confidence == 0.7
    assert f.sink.line == marked(tmp_path, "pkg/db.py")[0]
    assert f.path[0].note.startswith("source") and f.path[-1].note.startswith("sink")
    assert any("passed to q" in s.note for s in f.path)
    assert len(f.path) <= 8


def test_interprocedural_two_hops(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import os
def inner(c):
    os.system(c)  # SINK
def outer(c):
    inner("echo " + c)
@app.route("/")
def v():
    outer(request.args["c"])
"""
        },
    )
    assert rules(fs) == ["cmdi"]
    assert lines(fs) == marked(tmp_path, "a.py")


def test_param_to_return_propagation(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import os
def build(x):
    return "tool " + x
def const(x):
    return "fixed"
@app.route("/")
def v():
    os.system(build(request.args["c"]))  # SINK
    os.system(const(request.args["c"]))
"""
        },
    )
    assert rules(fs) == ["cmdi"]
    assert lines(fs) == marked(tmp_path, "a.py")


def test_source_returned_from_helper(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import os
def get():
    return request.args["c"]
def v():
    os.system(get())
"""
        },
    )
    assert rules(fs) == ["cmdi"]


def test_branch_overwrite_and_tuple_unpack(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import os
@app.route("/")
def v():
    a, b = request.args["a"], "safe"
    os.system(b)
    c = request.args["c"]
    c = "const"
    os.system(c)
    os.system(a)  # SINK
"""
        },
    )
    assert lines(fs) == marked(tmp_path, "a.py")


def test_findings_are_deduplicated_and_ids_stable(tmp_path):
    files = {
        "a.py": FLASK
        + """
import os
@app.route("/")
def v():
    os.system(request.args["c"])
"""
    }
    a = run(tmp_path, files)
    b = run(tmp_path, files)
    assert [f.id for f in a] == [f.id for f in b] and len(a) == 1


def test_clean_project_has_no_findings(tmp_path):
    assert run(tmp_path, {"a.py": "import os\nos.system('ls')\neval('1+1')\n"}) == []


# ---- closures, globals, object fields, loops ----------------------------------


def test_module_global_read_in_function(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": """
import os, sys
cmd = sys.argv[1]
def go():
    os.system(cmd)  # SINK
"""
        },
    )
    assert lines(fs) == marked(tmp_path, "a.py")
    assert any("global variable cmd" in s.note for s in fs[0].path)


def test_module_global_shadowed_or_sanitized_is_safe(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": """
import os, sys, shlex
cmd = sys.argv[1]
safe = shlex.quote(sys.argv[2])
def go(cmd):
    os.system(cmd)
def go2():
    cmd = "ls"
    os.system(cmd)
def go3():
    os.system(safe)
"""
        },
    )
    assert fs == []


def test_closure_variable(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import os
@app.route("/a")
def a():
    n = request.args["n"]
    def inner():
        os.system(n)  # SINK
    inner()
"""
        },
    )
    assert lines(fs) == marked(tmp_path, "a.py")
    assert any("closure variable n" in s.note for s in fs[0].path)


def test_field_written_in_init_read_in_method(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": """
import os, sys
class R:
    def __init__(self):
        self.c = sys.argv[1]
    def go(self):
        os.system(self.c)  # SINK
"""
        },
    )
    assert lines(fs) == marked(tmp_path, "a.py")


def test_field_written_by_setter_param_then_read(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import os
class R:
    def set(self, v):
        self.v = v
    def go(self):
        os.system(self.v)  # SINK
@app.route("/a")
def a():
    r = R()
    r.set(request.args["x"])
    r.go()
"""
        },
    )
    assert lines(fs) == marked(tmp_path, "a.py")


def test_fields_are_per_attribute_and_class(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": """
import os, sys
class R:
    def __init__(self):
        self.bad = sys.argv[1]
        self.ok = "ls"
    def go(self):
        os.system(self.ok)
class S:
    def go(self):
        os.system(self.bad)
"""
        },
    )
    assert fs == []


def test_loop_carried_taint_for(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import os
@app.route("/a")
def a():
    prev = ""
    cur = ""
    for _ in range(3):
        os.system(cur)  # SINK
        cur = prev
        prev = request.args["x"]
"""
        },
    )
    assert lines(fs) == marked(tmp_path, "a.py")


def test_loop_carried_taint_while_and_clean_loop(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK
            + """
import os
@app.route("/a")
def a():
    acc = ""
    parts = request.args.getlist("p")
    while parts:
        acc = acc + parts.pop()
    os.system(acc)  # SINK
@app.route("/b")
def b():
    acc = ""
    for p in ["x", "y"]:
        acc = acc + p
    os.system(acc)
"""
        },
    )
    assert lines(fs) == marked(tmp_path, "a.py")


def test_return_hop_steps_recorded(tmp_path):
    fs = run(
        tmp_path,
        {
            "s.py": """
import os
def _build(o):
    return "x " + o  # RET
def run(o):
    c = _build(o)
    os.popen(c)
""",
            "r.py": FLASK
            + """
from s import run
@app.route("/a")
def a():
    run(request.args["o"])
""",
        },
    )
    assert len(fs) == 1
    assert ("s.py", 4) in [(s.location.path, s.location.line) for s in fs[0].path]
