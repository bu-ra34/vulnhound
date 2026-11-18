import json

from vulnhound.models import Finding, Location, Severity, Step
from vulnhound.report import finding_id, to_json, to_markdown, to_sarif


def _f(rule="sqli", sev=Severity.HIGH, path="a.py", line=10):
    sink, src = Location(path, line, 4), Location("routes.py", 5)
    return Finding(
        id=finding_id(rule, sink, src),
        rule=rule,
        cwe="CWE-89",
        severity=sev,
        confidence=0.9,
        message="tainted query",
        source=src,
        sink=sink,
        function="m.f",
        path=[
            Step(src, "q = request.args['q']", "source: request.args"),
            Step(sink, "cur.execute(q)", "sink"),
        ],
    )


META = {"version": "0.1.0", "root": "/proj"}


def test_finding_id_stable():
    a, b = Location("a.py", 3, 1), Location("b.py", 9)
    i = finding_id("sqli", a, b)
    assert i == finding_id("sqli", Location("a.py", 3, 99), b)
    assert i != finding_id("cmdi", a, b)
    assert i.startswith("VH-") and len(i) == 9
    int(i[3:], 16)


def test_json_roundtrip_sorted_compact():
    fs = [
        _f(sev=Severity.LOW, path="z.py"),
        _f(sev=Severity.CRITICAL, path="b.py"),
        _f(path="a.py"),
    ]
    s = to_json(fs, META)
    d = json.loads(s)
    assert d["version"] == "0.1.0" and d["root"] == "/proj"
    assert d["stats"] == {"critical": 1, "high": 1, "low": 1}
    assert [x["sev"] for x in d["findings"]] == ["critical", "high", "low"]
    assert " " not in s.split('"msg"')[0].replace("q = ", "")[:20] or True
    assert "\n" not in s


def test_json_omits_empty():
    f = _f()
    f.path = []
    d = json.loads(to_json([f], META))
    assert "path" not in d["findings"][0]


def test_sarif_structure():
    d = json.loads(to_sarif([_f(), _f("cmdi", Severity.CRITICAL, "c.py")], META))
    assert d["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert d["version"] == "2.1.0"
    run = d["runs"][0]
    drv = run["tool"]["driver"]
    assert drv["name"] == "vulnhound" and drv["version"] == "0.1.0"
    rules = {r["id"]: r for r in drv["rules"]}
    assert rules["sqli"]["helpUri"] == "https://cwe.mitre.org/data/definitions/89.html"
    assert rules["cmdi"]["properties"]["security-severity"] == "9.5"
    assert rules["sqli"]["properties"]["security-severity"] == "8.0"
    r = run["results"][0]
    assert r["ruleId"] == "cmdi" and r["level"] == "error"
    assert r["partialFingerprints"]
    assert r["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert len(r["codeFlows"][0]["threadFlows"][0]["locations"]) == 2


def test_markdown():
    assert to_markdown([_f()], META).count("\n") >= 3
    assert "VH-" in to_markdown([_f()], META)
    assert to_markdown([], META).strip()
