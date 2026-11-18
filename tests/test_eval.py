from pathlib import Path

import pytest

from vulnhound import evaluate as ev
from vulnhound.models import Finding, Location, Severity

FIX = Path(__file__).parent / "fixtures"


def _f(path, line, rule):
    loc = Location(path, line)
    return Finding("VH-x", rule, "CWE-0", Severity.HIGH, 0.9, "m", loc, loc, "f")


def test_load_expectations(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\nrun(x)  # VH-EXPECT: cmdi\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("\n\nq(x)  # VH-EXPECT: sqli, ssrf\n")
    assert ev.load_expectations(tmp_path) == {
        ("a.py", 2, "cmdi"),
        ("sub/b.py", 3, "sqli"),
        ("sub/b.py", 3, "ssrf"),
    }


def test_score_and_format():
    exp = {("a.py", 2, "cmdi"), ("b.py", 3, "sqli")}
    r = ev.score(exp, [_f("a.py", 2, "cmdi"), _f("c.py", 9, "ssrf"), _f("a.py", 2, "sqli")])
    assert r.tp == [("a.py", 2, "cmdi")]
    assert sorted(r.fp) == [("a.py", 2, "sqli"), ("c.py", 9, "ssrf")]
    assert r.fn == [("b.py", 3, "sqli")]
    assert r.precision == pytest.approx(1 / 3) and r.recall == 0.5
    out = r.format()
    assert "FN b.py:3 sqli" in out and "FP c.py:9 ssrf" in out


def test_evaluate_with_monkeypatched_engine(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("run(x)  # VH-EXPECT: cmdi\n")
    monkeypatch.setattr(ev, "analyze", lambda idx: [_f("a.py", 1, "cmdi")])
    r = ev.evaluate(tmp_path)
    assert r.recall == 1.0 and r.precision == 1.0


def test_fixture_quality():
    pytest.importorskip("vulnhound.taint.engine")
    vuln = ev.evaluate(FIX / "vuln")
    safe = ev.evaluate(FIX / "safe")
    assert vuln.recall >= 0.8, "\n" + vuln.format()
    assert not safe.fp, "\n" + safe.format()
