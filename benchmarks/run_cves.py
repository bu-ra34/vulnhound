"""Run vulnhound over the real-CVE corpus (benchmarks/cves.json).

Usage: run_cves.py [--cache DIR] [--out results.json] [--entries cves.json] [--tolerance 3]

For every entry the vulnerable and the fixed release are analyzed (scope subdirectory only,
no cache). Per CVE:
  FOUND   a finding with the same rule in the right file within +-tolerance lines of the sink
          (or of one of the entry's alt_lines)
  MISSED  otherwise
  fixed_clean  (FOUND only) the matched finding's rule+file+function no longer yields a finding
          in the fixed release
  noise   all other findings in the vulnerable scope
Releases are downloaded/extracted on demand via fetch_cves (never installed or executed).
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")  # untrusted sources trigger SyntaxWarnings while parsing
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fetch_cves  # noqa: E402

from vulnhound.index.core import build_index  # noqa: E402
from vulnhound.taint.engine import analyze  # noqa: E402


def run_scope(root: Path, scope: str) -> tuple[list[dict], float, str | None]:
    """Analyze root/scope; return findings with paths relative to the source root."""
    base = root / scope
    t0 = time.perf_counter()
    try:
        findings = analyze(build_index(base, use_cache=False))
    except Exception as ex:  # a crash is a result too: report it, do not hide it
        return [], time.perf_counter() - t0, f"{type(ex).__name__}: {ex}"
    dt = time.perf_counter() - t0
    out = []
    for f in findings:
        out.append(
            {
                "rule": f.rule,
                "file": (Path(scope) / f.sink.path).as_posix(),
                "line": f.sink.line,
                "function": f.function,
                "source_file": (Path(scope) / f.source.path).as_posix(),
                "source_line": f.source.line,
            }
        )
    return out, dt, None


def match(entry: dict, findings: list[dict], tol: int) -> list[dict]:
    lines = [entry["line"], *entry.get("alt_lines", [])]
    return [
        f
        for f in findings
        if f["rule"] == entry["rule"]
        and f["file"] == entry["file"]
        and any(abs(f["line"] - ln) <= tol for ln in lines)
    ]


def evaluate(entry: dict, cache: Path, tol: int) -> dict:
    pkg = entry["package"]
    vdir = fetch_cves.fetch(cache, pkg, entry["vulnerable"])
    fdir = fetch_cves.fetch(cache, pkg, entry["fixed"])
    vf, vt, verr = run_scope(vdir, entry["scope"])
    ff, ft, ferr = run_scope(fdir, entry["scope"])
    hits = match(entry, vf, tol)
    found = bool(hits)
    fixed_clean = None
    if found:
        keys = {(h["rule"], h["file"], h["function"]) for h in hits}
        fixed_clean = not any((f["rule"], f["file"], f["function"]) in keys for f in ff)
    noise = len(vf) - len(hits)
    return {
        "id": entry["id"],
        "package": pkg,
        "vulnerable": entry["vulnerable"],
        "fixed": entry["fixed"],
        "rule": entry["rule"],
        "fix_kind": entry.get("fix_kind", ""),
        "status": "FOUND" if found else "MISSED",
        "fixed_clean": fixed_clean,
        "vuln_findings": len(vf),
        "fixed_findings": len(ff),
        "noise": noise,
        "vuln_seconds": round(vt, 2),
        "fixed_seconds": round(ft, 2),
        "matched": hits,
        "same_rule_in_file": [
            f["line"] for f in vf if f["rule"] == entry["rule"] and f["file"] == entry["file"]
        ],
        "errors": [e for e in (verr, ferr) if e],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", type=Path, default=fetch_cves.DEFAULT_CACHE)
    ap.add_argument("--entries", type=Path, default=HERE / "cves.json")
    ap.add_argument("--out", type=Path, default=HERE / "cves_results.json")
    ap.add_argument("--tolerance", type=int, default=3)
    args = ap.parse_args()

    entries = json.loads(args.entries.read_text())
    rows = [evaluate(e, args.cache, args.tolerance) for e in entries]

    hdr = f"{'CVE':16} {'package':14} {'rule':15} {'status':7} {'fixed-clean':11} {'noise':>5} {'vuln s':>7}"  # noqa: E501
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        fc = {True: "yes", False: "NO", None: "-"}[r["fixed_clean"]]
        print(
            f"{r['id']:16} {r['package']:14} {r['rule']:15} {r['status']:7} {fc:11} "
            f"{r['noise']:>5} {r['vuln_seconds']:>7.2f}"
            + (f"  ERROR {r['errors']}" if r["errors"] else "")
        )

    n = len(rows)
    nf = sum(r["status"] == "FOUND" for r in rows)
    clean = sum(r["fixed_clean"] is True for r in rows)
    noises = [r["noise"] for r in rows]
    totals = {
        "cves": n,
        "found": nf,
        "recall": round(nf / n, 3) if n else 0.0,
        "fixed_clean": clean,
        "fixed_clean_rate_of_found": round(clean / nf, 3) if nf else None,
        "median_noise": statistics.median(noises) if noises else 0,
        "total_noise": sum(noises),
        "total_seconds": round(sum(r["vuln_seconds"] + r["fixed_seconds"] for r in rows), 1),
    }
    print()
    print(
        f"recall {nf}/{n} = {totals['recall']:.0%}; fixed-clean {clean}/{nf} of found; "
        f"median noise {totals['median_noise']} other findings/scope; total {totals['total_seconds']}s"  # noqa: E501
    )
    args.out.write_text(json.dumps({"totals": totals, "results": rows}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
