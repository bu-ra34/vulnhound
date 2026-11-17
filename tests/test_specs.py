import ast
import re
from pathlib import Path

from vulnhound.models import Severity
from vulnhound.taint import specs
from vulnhound.taint.specs import RULES, is_sanitizer, match_sink, match_source

FIXTURES = Path(__file__).parent / "fixtures"
EXPECT = re.compile(r"#\s*VH-EXPECT:\s*([\w-]+)")


def test_exact_sink():
    s = match_sink("os.system")
    assert [x.rule for x in s] == ["cmdi"]
    assert s[0].cwe == "CWE-78"


def test_wildcard_sink_fallback():
    assert {x.rule for x in match_sink("self.db.execute")} == {"sqli"}
    assert match_sink("nothing.here") == []
    assert match_sink("execute") == []  # bare name is not a method call


def test_exact_beats_wildcard():
    # requests.get must not fall through to a wildcard
    assert all(x.pattern == "requests.get" for x in match_sink("requests.get"))


def test_subprocess_shell_requires_kwarg():
    s = match_sink("subprocess.run")
    shell = [x for x in s if x.requires_kwarg == {"shell": True}]
    plain = [x for x in s if not x.requires_kwarg]
    assert shell and shell[0].severity == Severity.CRITICAL
    assert plain and plain[0].severity == Severity.MEDIUM


def test_yaml_load_safe_loaders():
    (s,) = match_sink("yaml.load")
    assert "yaml.SafeLoader" in s.safe_kwarg_values["Loader"]
    assert match_sink("yaml.safe_load") == []


def test_sources():
    assert match_source("flask.request.args").kind == "flask-request"
    assert match_source("flask.request.args.get").pattern == "flask.request.args"
    assert match_source("sys.argv").kind == "argv"
    assert match_source("os.environ").weak
    assert match_source("flask.app") is None


def test_sanitizers():
    assert is_sanitizer("int", "sqli")
    assert is_sanitizer("shlex.quote", "cmdi")
    assert not is_sanitizer("shlex.quote", "sqli")
    assert is_sanitizer("werkzeug.utils.secure_filename", "path-traversal")
    assert is_sanitizer("markupsafe.escape", "ssti")
    assert not is_sanitizer("urllib.parse.quote", "ssrf")
    assert not is_sanitizer("os.path.join", "path-traversal")


def test_all_sink_rules_known_and_cwe_consistent():
    for s in specs.SINKS:
        assert s.rule in RULES, s
        assert RULES[s.rule][0] == s.cwe or s.pattern in (
            "importlib.import_module",
            "__import__",
        ), s
    for san in specs.SANITIZERS:
        assert all(r == "*" or r in RULES for r in san.rules), san


def test_cwe_ids():
    assert RULES["sqli"][0] == "CWE-89"
    assert RULES["ssti"][0] == "CWE-1336"
    assert RULES["ssrf"][0] == "CWE-918"
    assert RULES["deserialization"][0] == "CWE-502"
    assert RULES["open-redirect"][0] == "CWE-601"


def test_fixtures_parse_and_expectations_known():
    files = list(FIXTURES.rglob("*.py"))
    assert len(files) >= 20
    expected = 0
    for f in files:
        src = f.read_text()
        ast.parse(src, filename=str(f))
        found = EXPECT.findall(src)
        if "safe" in f.relative_to(FIXTURES).parts:
            assert not found, f
        for rule in found:
            assert rule in RULES, (f, rule)
        expected += len(found)
    assert expected >= 20


def test_new_ssrf_sinks():
    for name in (
        "httpx.Client.send",
        "httpx.AsyncClient.send",
        "httpx.Client.build_request",
        "requests.Session.send",
        "requests.Request",
        "urllib3.PoolManager.urlopen",
        "aiohttp.ClientSession.get",
        "http.client.HTTPSConnection",
    ):
        assert [x.rule for x in match_sink(name)][:1] == ["ssrf"], name
    assert match_sink("httpx.Client.build_request")[0].arg_positions == (1,)


def test_filestorage_save_and_filename_source():
    (s,) = match_sink("werkzeug.datastructures.FileStorage.save")
    assert s.rule == "path-traversal" and s.arg_positions == (0,)
    assert match_sink("flask.request.files[].save")[0].rule == "path-traversal"
    assert match_sink("f.save")[0].pattern == "*.save"
    assert match_source("werkzeug.datastructures.FileStorage.filename").kind == "flask-request"


def test_drf_and_tornado_constants():
    assert specs.DRF_REQUEST_ATTRS == ("data", "query_params")
    assert set(specs.DRF_REQUEST_ATTRS) <= specs.DJANGO_REQUEST_ATTRS
    assert specs.TORNADO_HANDLER_BASES == ("tornado.web.RequestHandler",)
    assert "get_query_argument" in specs.TORNADO_ARG_METHODS
    assert match_sink("tornado.web.RequestHandler.redirect")[0].rule == "open-redirect"
    assert match_source("rest_framework.request.Request.data").kind == "django-request"


def test_archive_response_and_deser_sinks():
    for name in ("shutil.unpack_archive", "starlette.responses.FileResponse"):
        assert match_sink(name)[0].rule == "path-traversal", name
    assert match_sink("starlette.responses.RedirectResponse")[0].rule == "open-redirect"
    assert match_sink("mako.template.Template")[0].rule == "ssti"
    (n,) = match_sink("numpy.load")
    assert n.requires_kwarg == {"allow_pickle": True}
    for name in ("pandas.read_pickle", "torch.load", "joblib.load", "dill.loads"):
        assert match_sink(name)[0].rule == "deserialization", name
