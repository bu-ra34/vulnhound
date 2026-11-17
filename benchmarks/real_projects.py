"""Measure speed and token savings on real extracted projects.

Usage: python benchmarks/real_projects.py ROOT_DIR [--json OUT.json] [--dump DIR] [NAME ...]

ROOT_DIR holds one extracted project per sub-directory. Projects are only read
and parsed (never imported or executed). Tokens are approximated as bytes / 4.
The cache of each project (<project>/.vulnhound) is wiped before the cold run.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vulnhound import report  # noqa: E402
from vulnhound.index import build_index  # noqa: E402
from vulnhound.project import discover  # noqa: E402
from vulnhound.slicer import build_slice  # noqa: E402
from vulnhound.taint.engine import analyze  # noqa: E402

SEVS = ("critical", "high", "medium", "low")


def project_root(d: Path) -> Path:
    """Descend through a sole sdist top-level dir (``name-1.0/``) so module names are right."""
    while True:
        kids = [c for c in d.iterdir() if not c.name.startswith(".")]
        if len(kids) == 1 and kids[0].is_dir() and not (kids[0] / "__init__.py").exists():
            d = kids[0]
        else:
            return d


def measure(root: Path, dump: Path | None, name: str) -> dict:
    files = discover(root)
    sizes = {p.relative_to(root).as_posix(): p.stat().st_size for p in files}
    lines = 0
    for p in files:
        with p.open("rb") as fh:
            lines += sum(1 for _ in fh)
    total_bytes = sum(sizes.values())
    shutil.rmtree(root / ".vulnhound", ignore_errors=True)

    t = time.perf_counter()
    idx = build_index(root)
    cold = time.perf_counter() - t
    t = time.perf_counter()
    idx = build_index(root)
    warm = time.perf_counter() - t
    t = time.perf_counter()
    findings = analyze(idx)
    t_an = time.perf_counter() - t
    findings.sort(key=lambda f: (SEVS.index(f.severity.value), f.sink.path, f.sink.line))

    meta = {"version": "bench", "root": str(root)}
    json_bytes = len(report.to_json(findings, meta).encode())
    t = time.perf_counter()
    slices, slice_errors = [], []
    for f in findings:
        try:
            slices.append(build_slice(idx, f))
        except Exception as e:  # report, do not abort the whole benchmark
            slices.append("")
            slice_errors.append(f"{f.id}: {type(e).__name__}: {e}")
    t_sl = time.perf_counter() - t
    slice_bytes = sum(len(s.encode()) for s in slices)
    touched: set[str] = set()
    for f in findings:
        touched |= {f.source.path, f.sink.path, *(s.location.path for s in f.path)}
    touched_bytes = sum(sizes.get(p, 0) for p in touched)
    reads = json_bytes + slice_bytes
    sev = {s: sum(1 for f in findings if f.severity.value == s) for s in SEVS}
    if dump:
        dump.mkdir(parents=True, exist_ok=True)
        out = [{"finding": f.to_dict(), "slice": s} for f, s in zip(findings, slices, strict=True)]
        (dump / f"{name}.json").write_text(json.dumps(out, indent=1))
    return {
        "project": name, "files": len(files), "lines": lines, "bytes": total_bytes,
        "functions": len(idx.functions), "naive_tokens": total_bytes // 4,
        "index_cold_s": round(cold, 2), "index_warm_s": round(warm, 2),
        "analyze_s": round(t_an, 2), "slice_all_s": round(t_sl, 2),
        "findings": len(findings), "slice_errors": slice_errors, "by_severity": sev,
        "json_bytes": json_bytes, "slice_bytes": slice_bytes,
        "claude_reads_tokens": reads // 4,
        "files_with_findings": len(touched), "touched_bytes": touched_bytes,
        "touched_tokens": touched_bytes // 4,
        "saving_vs_repo": round(total_bytes / reads, 1) if reads else None,
        "saving_vs_touched": round(touched_bytes / reads, 2) if reads else None,
    }  # fmt: skip


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("names", nargs="*")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--dump", help="write findings+slices per project to this dir")
    a = ap.parse_args()
    base = Path(a.root).resolve()
    dirs = sorted(d for d in base.iterdir() if d.is_dir() and (not a.names or d.name in a.names))
    rows = []
    hdr = (f"{'project':<24}{'files':>6}{'lines':>8}{'funcs':>7}{'naive tok':>10}{'cold s':>7}"
           f"{'warm s':>7}{'anlz s':>7}{'find':>5}{'json B':>8}{'slice B':>9}{'reads tok':>10}"
           f"{'touch tok':>10}{'x repo':>8}{'x touch':>8}")  # fmt: skip
    print(hdr)
    for d in dirs:
        r = measure(project_root(d), Path(a.dump) if a.dump else None, d.name)
        rows.append(r)
        print(f"{r['project']:<24}{r['files']:>6}{r['lines']:>8}{r['functions']:>7}"
              f"{r['naive_tokens']:>10}{r['index_cold_s']:>7}{r['index_warm_s']:>7}"
              f"{r['analyze_s']:>7}{r['findings']:>5}{r['json_bytes']:>8}{r['slice_bytes']:>9}"
              f"{r['claude_reads_tokens']:>10}{r['touched_tokens']:>10}"
              f"{r['saving_vs_repo'] or 0:>8}{r['saving_vs_touched'] or 0:>8}", flush=True)  # noqa: E501
    for r in rows:
        print(r["project"], "severity:", r["by_severity"], f"slice_all_s={r['slice_all_s']}",
              f"slice_errors={len(r['slice_errors'])}")
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
