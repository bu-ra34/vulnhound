"""Evaluate the taint engine on tests/fixtures. Usage: eval_fixtures.py [min_recall=0.8]"""

import sys
from pathlib import Path

from vulnhound.evaluate import evaluate

FIX = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def main(argv: list[str]) -> int:
    threshold = float(argv[1]) if len(argv) > 1 else 0.8
    vuln = evaluate(FIX / "vuln")
    safe = evaluate(FIX / "safe")
    print("vuln/\n" + vuln.format())
    print("safe/\n" + safe.format())
    ok = vuln.recall >= threshold and not safe.fp
    print("PASS" if ok else f"FAIL (recall<{threshold} or findings in safe/)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
