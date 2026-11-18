"""Measure precision of the taint engine against a hand-labeled finding set.

Usage: python benchmarks/precision.py CORPUS_DIR [LABELS.json] [--json OUT.json] [--strict]
                                      [--list-new OUT.json] [NAME ...]

CORPUS_DIR holds one extracted project per sub-directory (same layout as
real_projects.py). Findings are the CLI defaults: grouped, tests excluded, one
representative per group. Each is keyed ``project|rule|sink_path:line|source_path:line``
and looked up in the labels file (default: precision_labels.json next to this script).
Projects are only read and parsed, never imported or executed.

Precision = tp / (tp + fp); ``unclear`` and unlabeled findings are excluded.
Exit status is 1 only with --strict when unlabeled findings exist.
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
from vulnhound.taint.engine import analyze  # noqa: E402

DEFAULT_LABELS = Path(__file__).resolve().parent / "precision_labels.json"


def finding_key(project: str, f) -> str:
    return f"{project}|{f.rule}|{f.sink.path}:{f.sink.line}|{f.source.path}:{f.source.line}"


def run_project(name: str, root: Path) -> list:
    idx = build_index(root)
    findings = analyze(idx)
    return [g.rep for g in group_findings(findings)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("labels", nargs="?", default=str(DEFAULT_LABELS))
    ap.add_argument("names", nargs="*", help="restrict to these project dirs")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any finding is unlabeled")
    a = ap.parse_args()

    labels = json.loads(Path(a.labels).read_text())["labels"]
    base = Path(a.corpus).resolve()
    dirs = sorted(d for d in base.iterdir() if d.is_dir() and (not a.names or d.name in a.names))
    rows, unlabeled_all, seen_keys = [], [], set()
    for d in dirs:
        root = project_root(d)
        found = run_project(d.name, root)
        c = {"tp": 0, "fp": 0, "unclear": 0}
        unl = []
        for f in found:
            k = finding_key(d.name, f)
            seen_keys.add(k)
            lab = labels.get(k)
            if lab is None:
                unl.append({"key": k, "message": f.message, "severity": f.severity.value})
            else:
                c[lab["label"]] += 1
        rows.append({"project": d.name, "findings": len(found), **c, "unlabeled": unl})
        unlabeled_all += unl

    print(f"{'project':<26}{'finds':>6}{'tp':>4}{'fp':>4}{'unclr':>6}{'UNLAB':>6}")
    for r in rows:
        print(f"{r['project']:<26}{r['findings']:>6}{r['tp']:>4}{r['fp']:>4}"
              f"{r['unclear']:>6}{len(r['unlabeled']):>6}")  # fmt: skip
    tot = {k: sum(r[k] for r in rows) for k in ("findings", "tp", "fp", "unclear")}
    prec = tot["tp"] / (tot["tp"] + tot["fp"]) if tot["tp"] + tot["fp"] else None
    print(f"{'TOTAL':<26}{tot['findings']:>6}{tot['tp']:>4}{tot['fp']:>4}"
          f"{tot['unclear']:>6}{len(unlabeled_all):>6}")  # fmt: skip
    print("precision = tp/(tp+fp) =", "n/a" if prec is None else f"{prec:.3f}",
          f"({tot['tp']}/{tot['tp'] + tot['fp']})")  # fmt: skip
    if unlabeled_all:
        print("\nUNLABELED (need triage):")
        for u in unlabeled_all:
            print(f"  {u['key']}\n      [{u['severity']}] {u['message'][:150]}")
    if not a.names:  # stale = labeled but no longer reported (engine got stricter or code moved)
        stale = sorted(k for k in labels if k not in seen_keys)
        if stale:
            by = {"tp": 0, "fp": 0, "unclear": 0}
            for k in stale:
                by[labels[k]["label"]] += 1
            print(f"\nstale labels (no longer reported): {len(stale)} {by}")
    if a.json_out:
        out = {"total": tot, "precision": prec, "projects": rows}
        Path(a.json_out).write_text(json.dumps(out, indent=2))
    return 1 if a.strict and unlabeled_all else 0


if __name__ == "__main__":
    raise SystemExit(main())
