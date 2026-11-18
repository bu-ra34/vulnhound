"""Time build_index on synthetic modules: python benchmarks/index_speed.py [lines]."""

import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vulnhound.index import build_index  # noqa: E402

TEMPLATE = '''
import os
import subprocess
from . import helpers as h
from .mod_{prev} import f{prev}_0 as prev_fn


class Svc{i}:
    def __init__(self, db):
        self.db = db

    def run(self, q):
        return self.helper(q)

    def helper(self, q):
        cur = self.db.cursor()
        cur.execute("select " + q)
        return os.path.join(q, "x")
'''
FUNC = '''

def f{i}_{j}(a, b=None):
    """Doc."""
    x = a + 1
    if b:
        subprocess.run(["ls", b])
    h.util(x)
    return prev_fn(x) if x else f{i}_{k}(x)
'''


def main() -> None:
    target = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000
    d = Path(tempfile.mkdtemp())
    try:
        pkg = d / "src" / "bench"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def util(x):\n    return x\n")
        total, i = 0, 0
        while total < target:
            body = TEMPLATE.format(i=i, prev=max(i - 1, 0)) + "".join(
                FUNC.format(i=i, j=j, k=(j + 1) % 20) for j in range(20)
            )
            (pkg / f"mod_{i}.py").write_text(body)
            total += body.count("\n")
            i += 1
        runs = (("cold (no cache)", False), ("cold (writes cache)", True), ("warm", True))
        for label, use_cache in runs:
            t = time.perf_counter()
            idx = build_index(d, use_cache=use_cache)
            dt = time.perf_counter() - t
            print(f"{label:22s} {dt:6.2f}s  {len(idx.functions)} funcs, {total} lines, {i} modules")
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
