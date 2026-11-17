"""Fixture-based quality evaluation: compares findings to ``# VH-EXPECT:`` comments."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .index import build_index
from .models import Finding

_EXPECT = re.compile(r"#\s*VH-EXPECT:\s*([A-Za-z0-9_,\-\s]+)")

Key = tuple[str, int, str]


def load_expectations(root: Path) -> set[Key]:
    """Scan ``*.py`` under root for ``# VH-EXPECT: rule[, rule]`` comments."""
    root = Path(root)
    out: set[Key] = set()
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            m = _EXPECT.search(line)
            if not m:
                continue
            for rule in re.split(r"[,\s]+", m.group(1).strip()):
                if rule:
                    out.add((rel, lineno, rule))
    return out


@dataclass
class EvalResult:
    tp: list[Key] = field(default_factory=list)
    fp: list[Key] = field(default_factory=list)
    fn: list[Key] = field(default_factory=list)

    @property
    def precision(self) -> float:
        n = len(self.tp) + len(self.fp)
        return len(self.tp) / n if n else 1.0

    @property
    def recall(self) -> float:
        n = len(self.tp) + len(self.fn)
        return len(self.tp) / n if n else 1.0

    def format(self) -> str:
        lines = [
            f"tp={len(self.tp)} fp={len(self.fp)} fn={len(self.fn)} "
            f"precision={self.precision:.2f} recall={self.recall:.2f}"
        ]
        for tag, items in (("FN", self.fn), ("FP", self.fp)):
            for path, line, rule in sorted(items):
                lines.append(f"  {tag} {path}:{line} {rule}")
        return "\n".join(lines)


def score(expected: set[Key], findings: list[Finding]) -> EvalResult:
    found = {(f.sink.path, f.sink.line, f.rule) for f in findings}
    return EvalResult(
        tp=sorted(expected & found), fp=sorted(found - expected), fn=sorted(expected - found)
    )


def analyze(index) -> list[Finding]:
    from .taint import engine

    return engine.analyze(index)


def evaluate(root: Path) -> EvalResult:
    root = Path(root)
    index = build_index(root, use_cache=False)
    return score(load_expectations(root), analyze(index))
