"""Output formatters: compact JSON (for Claude), SARIF 2.1.0 (GitHub), Markdown."""

from __future__ import annotations

import hashlib
import json

from vulnhound.models import Finding, Location, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def finding_id(rule: str, sink: Location, source: Location) -> str:
    """Stable id: 'VH-' + 6 hex chars of sha256 over rule and both locations (cols ignored)."""
    key = f"{rule}|{sink.path}:{sink.line}|{source.path}:{source.line}"
    return "VH-" + hashlib.sha256(key.encode()).hexdigest()[:6]


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_ORDER[f.severity], f.sink.path, f.sink.line, f.id))


def _stats(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity.value] = out.get(f.severity.value, 0) + 1
    return {s.value: out[s.value] for s in sorted(_ORDER, key=_ORDER.get) if s.value in out}


def _compact(f: Finding) -> dict:
    d: dict = {
        "id": f.id,
        "rule": f.rule,
        "cwe": f.cwe,
        "sev": f.severity.value,
        "conf": round(f.confidence, 2),
        "msg": f.message,
        "sink": str(f.sink),
        "source": str(f.source),
        "fn": f.function,
    }
    if f.path:
        d["path"] = [f"{s.location}: {s.note}" + (f" | {s.code}" if s.code else "") for s in f.path]
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def to_json(findings: list[Finding], meta: dict) -> str:
    fs = _sorted(findings)
    doc = {
        "version": meta.get("version", ""),
        "root": meta.get("root", ""),
        "stats": _stats(fs),
        "findings": [_compact(f) for f in fs],
    }
    for k, v in meta.items():
        if k not in doc and v not in (None, "", [], {}):
            doc[k] = v
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False)


def _rule_info(rule: str) -> tuple[str, str]:
    try:
        from vulnhound.taint.specs import RULES

        _, _, title = RULES[rule]
        return title, rule
    except (ImportError, KeyError):
        return rule, rule


def _region(loc: Location) -> dict:
    return {"startLine": max(loc.line, 1), "startColumn": loc.col + 1}


def _physical(loc: Location) -> dict:
    return {"artifactLocation": {"uri": loc.path}, "region": _region(loc)}


def to_sarif(findings: list[Finding], meta: dict) -> str:
    fs = _sorted(findings)
    rules: dict[str, dict] = {}
    for f in fs:
        if f.rule in rules:
            continue
        title, _ = _rule_info(f.rule)
        num = f.cwe.split("-")[-1]
        rules[f.rule] = {
            "id": f.rule,
            "name": f.rule,
            "shortDescription": {"text": f"{title} ({f.cwe})"},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{num}.html",
            "properties": {
                "security-severity": _SECURITY_SEVERITY[f.severity],
                "tags": ["security", f.cwe],
            },
        }
    results = []
    for f in fs:
        r: dict = {
            "ruleId": f.rule,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{"physicalLocation": _physical(f.sink)}],
            "partialFingerprints": {"vulnhound/v1": f.id},
            "properties": {"confidence": round(f.confidence, 2), "id": f.id},
        }
        if f.path:
            r["codeFlows"] = [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": _physical(s.location),
                                        "message": {"text": s.note},
                                    }
                                }
                                for s in f.path
                            ]
                        }
                    ]
                }
            ]
        results.append(r)
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnhound",
                        "version": str(meta.get("version", "0")),
                        "informationUri": "https://github.com/vulnhound/vulnhound",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def to_markdown(findings: list[Finding], meta: dict) -> str:
    fs = _sorted(findings)
    if not fs:
        return "No findings.\n"
    lines = ["| Severity | ID | Rule | Location | Message |", "|---|---|---|---|---|"]
    for f in fs:
        msg = f.message.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {f.severity.value} | {f.id} | {f.rule} ({f.cwe}) | {f.sink} | {msg} |")
    return "\n".join(lines) + "\n"
