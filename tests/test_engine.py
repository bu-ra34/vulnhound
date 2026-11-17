"""Unit tests for the taint engine, each on a tiny tmp project."""

from __future__ import annotations

import textwrap

from vulnhound.index import build_index
from vulnhound.taint.engine import analyze


def run(tmp_path, files: dict[str, str], **kw):
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return analyze(build_index(tmp_path, use_cache=False), **kw)


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
        include_local_sources=True,
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
        include_local_sources=True,
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
        include_local_sources=True,
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


# --------------------------------------------------------------------------- guards / sources


def test_local_sources_off_by_default(tmp_path):
    src = {
        "s.py": (
            "import os, sys\nos.system('x ' + sys.argv[1])\nexec(input())\n"
            "os.system(os.environ['A'])\n"
        )
    }
    assert run(tmp_path, src) == []
    assert len(run(tmp_path, src, include_local_sources=True)) == 3


def test_local_source_does_not_hide_web_source(tmp_path):
    fs = run(
        tmp_path,
        {
            "a.py": FLASK + "import os, sys\n@app.route('/')\ndef f():\n"
            "    os.system(sys.argv[0] + request.args['a'])\n"
        },
    )
    assert rules(fs) == ["cmdi"]


GUARD_APP = FLASK + "import os, abort_mod\nfrom flask import abort, redirect\n"


def _g(tmp_path, body: str, **kw):
    return run(tmp_path, {"a.py": GUARD_APP + body}, **kw)


def test_startswith_exit_guard_cleans(tmp_path):
    body = """
@app.route("/")
def f():
    p = request.args["p"]
    if not os.path.abspath(p).startswith("/base"):
        abort(400)
    open(p)
"""
    assert _g(tmp_path, body) == []


def test_startswith_without_exit_still_flagged(tmp_path):
    body = """
@app.route("/")
def f():
    p = request.args["p"]
    if not p.startswith("/base"):
        print("x")
    open(p)
"""
    assert rules(_g(tmp_path, body)) == ["path-traversal"]


def test_guard_only_clears_listed_rules(tmp_path):
    body = """
@app.route("/")
def f():
    p = request.args["p"]
    if not p.startswith("/base"):
        abort(400)
    os.system(p)
"""
    assert rules(_g(tmp_path, body)) == ["cmdi"]


def test_validator_statement_and_value_validators(tmp_path):
    body = """
def validate_p(x): pass
@app.route("/")
def f():
    p = request.args["p"]
    validate_p(p)
    open(p)
    q = request.args["q"]
    open(safe_join("/b", q))
    open(request.args["z"])
"""
    fs = _g(tmp_path, body)
    assert rules(fs) == ["path-traversal"] and fs[0].sink.line == lines(fs)[0]
    assert len(fs) == 1


def test_predicate_in_if_positive_branch_and_bool_ops(tmp_path):
    body = """
@app.route("/")
def f():
    u = request.args["u"]
    if is_safe_url(u) and u:
        return redirect(u)
    return redirect(u)
"""
    fs = _g(tmp_path, body)
    assert len(fs) == 1


def test_netloc_comparison_guard(tmp_path):
    body = """
from urllib.parse import urlparse
@app.route("/")
def f():
    u = request.args["u"]
    p = urlparse(u)
    if p.netloc not in ("a.com",):
        abort(400)
    return redirect(u)
"""
    assert _g(tmp_path, body) == []


def test_helper_that_raises_validates_param(tmp_path):
    body = """
def ensure(p):
    if not os.path.abspath(p).startswith("/b"):
        raise ValueError(p)
def lenient(p):
    if not p:
        return None
@app.route("/")
def f():
    p = request.args["p"]
    ensure(p)
    open(p)
@app.route("/2")
def g():
    p = request.args["p"]
    lenient(p)
    open(p)
"""
    fs = _g(tmp_path, body)
    assert len(fs) == 1 and fs[0].function.endswith(".g")


def test_dotdot_check_path_only(tmp_path):
    body = """
@app.route("/")
def f():
    p = request.args["p"]
    if ".." in p:
        abort(400)
    open(p)
    os.system(p)
"""
    assert rules(_g(tmp_path, body)) == ["cmdi"]


def test_drf_and_tornado_sources(tmp_path):
    fs = run(
        tmp_path,
        {
            "v.py": """
import os
import tornado.web
from rest_framework.views import APIView
class V(APIView):
    def post(self, request):
        os.system(request.data["x"])
    def get(self, request):
        os.system(self.request.query_params.get("x"))
class B(tornado.web.RequestHandler): pass
class H(B):
    def get(self, job):
        os.system(job)
    def post(self):
        os.system(self.get_argument("c"))
        os.system(self.request.body)
    def util(self, other):
        os.system(other)
class NotHandler:
    def get(self, job):
        os.system(job)
"""
        },
    )
    assert lines(fs) == [7, 9, 13, 15, 16]


def test_subprocess_env_not_cmdi(tmp_path):
    src = {
        "a.py": FLASK
        + """
import os, subprocess
@app.route("/")
def f():
    env = os.environ.copy()
    env["X"] = request.args["x"]
    subprocess.run(["ls"], env=env)
    subprocess.run(["ls"], env=os.environ.copy(), cwd="/")
"""
    }
    assert run(tmp_path, src) == []
    assert run(tmp_path, src, include_local_sources=True) == []


def test_sqlalchemy_builders_and_bindparams_safe(tmp_path):
    body = (
        FLASK
        + """
from sqlalchemy import insert, select, update, text
@app.route("/")
def f(session, t):
    q = request.args["q"]
    session.execute(insert(t).values(name=f"{q}"))
    session.execute(update(t).values(a="x" + q))
    session.execute(select(t).where(t.c.a == "%" + q))
    session.execute(text("select 1 where a like :p").bindparams(p=f"%{q}%"))
    session.execute(t.insert().values(a="x" + q))
@app.route("/bad")
def g(session):
    q = request.args["q"]
    session.execute(text(f"select {q}"))
"""
    )
    fs = run(tmp_path, {"a.py": body})
    assert rules(fs) == ["sqli"] and fs[0].function.endswith(".g")


def test_validator_that_itself_hits_a_sink_is_still_reported(tmp_path):
    body = """
import urllib.request
def validate_url(u):
    urllib.request.urlopen(u)
    return u
@app.route("/")
def f():
    validate_url(request.args["u"])
"""
    fs = _g(tmp_path, body)
    assert rules(fs) == ["ssrf"]


# --------------------------------------------------------------------------- URL position
URL_APP = (
    "import requests\nfrom urllib.parse import urljoin, urlparse\n"
    "from flask import Flask, redirect, request, url_for\napp = Flask(__name__)\n"
    'CFG = "http://backend.internal"\n'
)


def _line_of(tmp_path, needle: str) -> int:
    text = (tmp_path / "a.py").read_text().splitlines()
    return next(i for i, ln in enumerate(text, 1) if needle in ln)


def _u(tmp_path, body: str):
    return run(tmp_path, {"a.py": URL_APP + body})


def test_url_prefix_controlled_is_reported(tmp_path):
    body = """
@app.route("/")
def f():
    n = request.args["n"]
    redirect(n)  # SINK
    redirect(n + "/x")  # SINK
    redirect("/" + n)  # SINK
    redirect("//" + n)  # SINK
    redirect(f"https://{n}/x")  # SINK
    redirect("%s/x" % n)  # SINK
    redirect("{}/x".format(n))  # SINK
    requests.get(n)  # SINK
    requests.get(urljoin(CFG, n))  # SINK
    requests.get("http://" + n + "/s")  # SINK
    requests.get("https://api.example.com" + n)  # SINK
"""
    fs = _u(tmp_path, body)
    assert lines(fs) == marked(tmp_path, "a.py")


def test_url_fixed_head_is_not_open_redirect_or_ssrf(tmp_path):
    body = """
@app.route("/")
def f():
    n = request.args["n"]
    redirect("/items/" + n)
    redirect(f"/items/{n}?x=1")
    redirect("/items/%s" % n)
    redirect("/items/{}".format(n))
    redirect("/items/%s/%s" % (n, n))
    requests.get("https://api.example.com/v1/" + n)
    requests.get(f"{CFG}/{n}")
    requests.get(CFG + n)
    redirect("?next=" + n)
"""
    assert _u(tmp_path, body) == []


def test_url_taint_after_separator_is_safe_but_head_is_not(tmp_path):
    body = """
@app.route("/")
def f():
    a, b = request.args["a"], request.args["b"]
    redirect(a + "?next=" + b)  # SINK
    redirect(url_for("x") + "?next=" + b)
"""
    fs = _u(tmp_path, body)
    assert lines(fs) == marked(tmp_path, "a.py")
    assert {f.source.line for f in fs} == {_line_of(tmp_path, 'a, b = request.args["a"]')}


def test_same_host_request_attributes_are_not_redirect_targets(tmp_path):
    body = """
@app.route("/")
def f():
    redirect(request.path)
    redirect(request.script_root + request.full_path.rstrip("?"))
    redirect(request.path + "?" + request.query_string.decode())
    p = urlparse(request.args["next"])
    redirect(p.path + "?" + p.query)
    redirect(urlparse(request.args["next"]).path)
    redirect(request.url)  # SINK
    redirect(request.args["next"])  # SINK
"""
    assert lines(_u(tmp_path, body)) == marked(tmp_path, "a.py")


def test_django_reverse_and_get_full_path(tmp_path):
    body = """
from django.shortcuts import redirect
from django.urls import reverse
def v(request):
    redirect(request.get_full_path())
    redirect(reverse("home") + "?" + request.GET["q"])
    redirect(request.GET["next"])  # SINK
"""
    fs = run(tmp_path, {"a.py": body})
    assert lines(fs) == marked(tmp_path, "a.py")


def test_merged_with_param_keeps_source_side_cleaning(tmp_path):
    body = """
def pick(nxt):
    target = nxt
    if not target:
        target = request.script_root + request.path
    return redirect(target)  # SINK
@app.route("/")
def f():
    return pick(request.args["n"])
"""
    fs = _u(tmp_path, body)
    # only the real attacker value reaches the sink; request.path (same-host) is not reported
    assert [x.source.line for x in fs] == [_line_of(tmp_path, 'pick(request.args["n"])')]


# --------------------------------------------------------------------------- lookups
LOOKUP_APP = (
    "import requests\nfrom flask import Flask, redirect, request, send_file\n"
    "from django.shortcuts import get_object_or_404\napp = Flask(__name__)\n"
)


def _l(tmp_path, body: str):
    return run(tmp_path, {"a.py": LOOKUP_APP + body})


def test_database_lookup_results_are_clean(tmp_path):
    body = """
class UserDAO:
    @staticmethod
    def find_by_id(i):
        return i
@app.route("/")
def f(session, repo):
    store = get_store()
    i = request.args["id"]
    redirect(Doc.objects.get(pk=i).url)
    redirect(Doc.objects.filter(a=i).first().url)
    redirect(get_object_or_404(Doc, pk=i).url)
    redirect(session.get(Doc, i).url)
    redirect(session.query(Doc).filter_by(n=i).one().url)
    redirect(UserDAO.find_by_id(i).url)
    redirect(repo.find_by_name(i).url)
    redirect(repo.get_by_id(i).url)
    redirect(store.get_trace_info(i).url)
    send_file(Doc.objects.get(pk=i).path)
"""
    assert _l(tmp_path, body) == []


def test_lookup_key_and_non_lookups_stay_tainted(tmp_path):
    body = """
@app.route("/")
def f(cache):
    i = request.args["id"]
    Doc.objects.get(pk=i)
    redirect(i)  # SINK
    redirect(cache.get(i))  # SINK
    redirect({"a": i}.get("a"))  # SINK
    send_file(i)  # SINK
"""
    assert lines(_l(tmp_path, body)) == marked(tmp_path, "a.py")


def test_lookup_still_checks_sinks_on_its_arguments(tmp_path):
    body = """
@app.route("/")
def f():
    return Doc.objects.raw("select * from d where n = '%s'" % request.args["n"])  # SINK
"""
    fs = _l(tmp_path, body)
    assert rules(fs) == ["sqli"] and lines(fs) == marked(tmp_path, "a.py")


def test_lookup_helper_project_function_does_not_leak_return_taint(tmp_path):
    body = """
def load(i):
    return Doc.objects.get(pk=i)
def load_by(i):
    return i
@app.route("/")
def f():
    i = request.args["id"]
    redirect(load(i).url)
    redirect(load_by(i))  # SINK
"""
    assert lines(_l(tmp_path, body)) == marked(tmp_path, "a.py")


# --------------------------------------------------------------------------- positive guards
def test_positive_branch_guards(tmp_path):
    body = """
def is_safe_url(u):
    return u.startswith("/")
def helper():
    x = request.args.get("next")
    if x and is_safe_url(x):
        return x
    return None
def helper_ifexp():
    x = request.args.get("next")
    return x if is_safe_url(x) else "/"
def helper_param(fallback):
    x = request.args.get("next")
    if x and is_safe_url(x):
        return x
    return fallback
@app.route("/")
def f():
    redirect(helper())
    redirect(helper_ifexp())
    redirect(helper_param("/"))
    x = request.args.get("n")
    redirect(is_safe_url(x) and x or "/")
    if validate(x):
        redirect(x)
"""
    assert _u(tmp_path, body) == []


def test_negative_arms_of_guards_stay_tainted(tmp_path):
    body = """
def is_safe_url(u):
    return u.startswith("/")
@app.route("/")
def f():
    x = request.args.get("n")
    redirect("/" if is_safe_url(x) else x)  # SINK
    redirect(x or "/")  # SINK
    if is_safe_url(x):
        pass
    else:
        redirect(x)  # SINK
    if x:
        redirect(x)  # SINK
"""
    assert lines(_u(tmp_path, body)) == marked(tmp_path, "a.py")


# --------------------------------------------------------------------------- validator reassign
def test_reassigned_validator_result_and_falsy_branch(tmp_path):
    body = """
import os, posixpath
def validate_path_is_safe(p):
    if ".." in p:
        raise ValueError(p)
    return p
@app.route("/")
def f():
    path = request.args.get("path")
    if path:
        path = validate_path_is_safe(path)
        open(posixpath.join("attachments", path))
        open(os.path.abspath(path))
    open(path or "x")
"""
    assert run(tmp_path, {"a.py": FLASK + body}) == []


def test_validator_in_one_branch_only_is_incomplete(tmp_path):
    body = """
def validate_path_is_safe(p):
    return p
@app.route("/")
def f():
    path = request.args.get("path")
    if request.args.get("strict"):
        path = validate_path_is_safe(path)
    open(path)  # SINK
    other = validate_path_is_safe(request.args["a"])
    open(other + request.args["b"])  # SINK
"""
    fs = run(tmp_path, {"a.py": FLASK + body})
    assert lines(fs) == marked(tmp_path, "a.py")
