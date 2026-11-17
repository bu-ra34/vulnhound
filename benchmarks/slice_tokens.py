"""Compare slice size with the size of the full files a finding touches.

Usage: python benchmarks/slice_tokens.py [PROJECT_ROOT]   (needs .vulnhound/last.json)
Tokens are approximated as bytes / 4.
"""

from __future__ import annotations

import sys
from pathlib import Path

from vulnhound.index import build_index
from vulnhound.slicer import build_slice
from vulnhound.store import load_findings


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    try:
        findings, _ = load_findings(root)
    except FileNotFoundError:
        print("no last.json; run `vulnhound analyze` first", file=sys.stderr)
        return 2
    index = build_index(root)
    tot_slice = tot_full = 0
    print(f"{'id':<11}{'rule':<16}{'slice B':>8}{'~tok':>6}{'files B':>9}{'~tok':>7}{'ratio':>7}")
    for f in findings:
        text = build_slice(index, f)
        paths = {f.source.path, f.sink.path, *(s.location.path for s in f.path)}
        full = sum((root / p).stat().st_size for p in paths if (root / p).is_file())
        sb = len(text.encode())
        tot_slice += sb
        tot_full += full
        ratio = full / sb if sb else 0
        print(f"{f.id:<11}{f.rule:<16}{sb:>8}{sb // 4:>6}{full:>9}{full // 4:>7}{ratio:>6.1f}x")
    ratio = tot_full / tot_slice if tot_slice else 0
    tot = f"{'TOTAL':<27}{tot_slice:>8}{tot_slice // 4:>6}"
    print(f"{tot}{tot_full:>9}{tot_full // 4:>7}{ratio:>6.1f}x")
    print(f"{len(findings)} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
