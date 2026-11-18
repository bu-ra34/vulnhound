from vulnhound.models import Finding, Location, Severity, Step
from vulnhound.store import get_finding, load_findings, save_findings


def test_roundtrip(tmp_path):
    f = Finding(
        "VH-abc123", "sqli", "CWE-89", Severity.HIGH, 0.8, "msg",
        Location("a.py", 3), Location("a.py", 5), "a.view",
        [Step(Location("a.py", 3), "q = request.args['q']", "source")],
    )
    save_findings(tmp_path, [f], {"root": "."})
    got, meta = load_findings(tmp_path)
    assert got == [f] and meta == {"root": "."}
    assert get_finding(tmp_path, "VH-abc123") == f
    assert get_finding(tmp_path, "VH-none") is None
