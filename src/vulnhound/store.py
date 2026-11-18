"""Persist the last analysis so `slice` and `prove` can look findings up by id.

File: <root>/.vulnhound/last.json = {"meta": {...}, "findings": [Finding.to_dict(), ...]}
Plain JSON only (never pickle). Writes are atomic.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from vulnhound.models import Finding, Location, Severity, Step

LAST_FILE = "last.json"


def _path(root: Path) -> Path:
    return Path(root) / ".vulnhound" / LAST_FILE


def save_findings(root: Path, findings: list[Finding], meta: dict) -> Path:
    target = _path(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    gi = target.parent / ".gitignore"
    if not gi.exists():
        gi.write_text("*\n")
    data = {"meta": meta, "findings": [f.to_dict() for f in findings]}
    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, target)
    return target


def _loc(d: dict) -> Location:
    return Location(d["path"], d["line"], d.get("col", 0))


def finding_from_dict(d: dict) -> Finding:
    return Finding(
        id=d["id"],
        rule=d["rule"],
        cwe=d["cwe"],
        severity=Severity(d["severity"]),
        confidence=d["confidence"],
        message=d["message"],
        source=_loc(d["source"]),
        sink=_loc(d["sink"]),
        function=d["function"],
        path=[Step(_loc(s["location"]), s["code"], s["note"]) for s in d.get("path", [])],
    )


def load_findings(root: Path) -> tuple[list[Finding], dict]:
    """Return (findings, meta). Raises FileNotFoundError if `analyze` has not run."""
    data = json.loads(_path(root).read_text(encoding="utf-8"))
    return [finding_from_dict(d) for d in data["findings"]], data.get("meta", {})


def get_finding(root: Path, finding_id: str) -> Finding | None:
    findings, _ = load_findings(root)
    return next((f for f in findings if f.id == finding_id), None)
