import json

from vulnhound.group import group_findings
from vulnhound.models import Finding, Location, Severity
from vulnhound.report import to_json


def F(id, sink, src, sev=Severity.HIGH, conf=0.8, rule="open-redirect", fn="m.f"):
    sp, sl = sink.split(":")
    cp, cl = src.split(":")
    return Finding(
        id=id, rule=rule, cwe="CWE-601", severity=sev, confidence=conf, message="m",
        source=Location(cp, int(cl)), sink=Location(sp, int(sl)), function=fn,
    )  # fmt: skip


def test_same_sink_groups_with_best_rep():
    a = F("A", "v.py:10", "v.py:1", sev=Severity.LOW)
    b = F("B", "v.py:10", "w.py:2", sev=Severity.HIGH)
    c = F("C", "v.py:50", "v.py:3", fn="m.g")
    gs = group_findings([a, b, c])
    assert [(g.rep.id, g.count) for g in gs] == [("B", 2), ("C", 1)]
    assert gs[0].also == ["v.py:1"]


def test_same_helper_source_groups_across_files():
    fs = [F(f"X{i}", f"views{i}.py:5", "utils.py:18", fn=f"v{i}") for i in range(4)]
    (g,) = group_findings(fs)
    assert g.count == 4 and len(g.also) == 3


def test_same_sink_function_groups_and_rule_separates():
    a = F("A", "v.py:10", "v.py:1")
    b = F("B", "v.py:20", "v.py:2")
    c = F("C", "v.py:10", "v.py:1", rule="sqli")
    gs = group_findings([a, b, c])
    assert sorted(g.count for g in gs) == [1, 2]


def test_json_grouped_and_flat():
    fs = [F("A", "v.py:10", "v.py:1"), F("B", "v.py:10", "v.py:2")]
    d = json.loads(to_json(fs, {}, grouped=True))
    assert len(d["findings"]) == 1
    assert (
        d["findings"][0]["n"] == 2
        and d["findings"][0]["also"] == ["v.py:2"]
        or d["findings"][0]["also"] == ["v.py:1"]
    )
    assert len(json.loads(to_json(fs, {}))["findings"]) == 2
