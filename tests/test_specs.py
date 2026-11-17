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
