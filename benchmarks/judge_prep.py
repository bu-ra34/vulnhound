#!/usr/bin/env python3
"""Dump every current finding's slice + its hidden label, for the engine+Claude experiment.

Mirrors the CLI defaults (grouped, tests excluded), the same path real_projects.py uses.
Writes a JSONL: {key, label, category, project, rule, severity, sink, slice}.
The judge is shown only the slice (never the label).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from real_projects import project_root  # noqa: E402

from vulnhound.group import group_findings  # noqa: E402
from vulnhound.index import build_index  # noqa: E402
from vulnhound.slicer import build_slice  # noqa: E402
from vulnhound.taint.engine import analyze  # noqa: E402


def key_of(project: str, f) -> str:
    return f"{project}|{f.rule}|{f.sink.path}:{f.sink.line}|{f.source.path}:{f.source.line}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("labels")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    labels = json.loads(Path(a.labels).read_text())
    labels = labels.get("labels", labels)
    corpus = Path(a.corpus)
    rows = []
    for proj in sorted(p for p in corpus.iterdir() if p.is_dir()):
        root = project_root(proj)
        index = build_index(root, use_cache=False, include_tests=False)
        findings = analyze(index)
        groups = group_findings(findings)
        for g in groups:
            f = g.rep
            k = key_of(proj.name, f)
            lab = labels.get(k, {})
            rows.append({
                "key": k,
                "project": proj.name,
                "rule": f.rule,
                "severity": f.severity.value,
                "sink": f"{f.sink.path}:{f.sink.line}",
                "label": lab.get("label", "UNLABELED"),
                "category": lab.get("category", ""),
                "slice": build_slice(index, f),
            })
    Path(a.out).write_text("\n".join(json.dumps(r) for r in rows))
    print(f"{len(rows)} findings -> {a.out}")
    by = {}
    for r in rows:
        by[r["label"]] = by.get(r["label"], 0) + 1
    print("labels:", by)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
