"""Group findings that share a sink (or a helper source) so Claude judges each once."""

from __future__ import annotations

from dataclasses import dataclass, field

from vulnhound.models import Finding

_SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Group:
    rep: Finding  # highest severity, then confidence
    members: list[Finding] = field(default_factory=list)  # all findings incl. rep

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def also(self) -> list[str]:
        """Compact ``file:line`` of what differs from the representative.

        Other sources when the sink is shared, else the other sinks.
        """
        seen = {str(self.rep.sink), str(self.rep.source)}
        out: list[str] = []
        for f in self.members:
            if f is self.rep:
                continue
            loc = str(f.source) if f.sink == self.rep.sink else str(f.sink)
            if loc not in seen:
                seen.add(loc)
                out.append(loc)
        return out


def _rank(f: Finding) -> tuple[int, float]:
    return (_SEV[f.severity.value], f.confidence)


def group_findings(findings: list[Finding]) -> list[Group]:
    """Union findings that share (rule, sink path+line), (rule, sink path+function),
    or (rule, source) when the source lives in another file (a helper)."""
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen: dict[tuple, int] = {}
    for i, f in enumerate(findings):
        keys = [
            (f.rule, "sink", f.sink.path, f.sink.line),
            (f.rule, "fn", f.sink.path, f.function),
        ]
        if f.source.path != f.sink.path:
            keys.append((f.rule, "src", f.source.path, f.source.line))
        for k in keys:
            if k in seen:
                parent[find(i)] = find(seen[k])
            else:
                seen[k] = i
    buckets: dict[int, list[Finding]] = {}
    for i, f in enumerate(findings):
        buckets.setdefault(find(i), []).append(f)
    groups = []
    for members in buckets.values():
        rep = max(members, key=_rank)  # first among equals keeps input order
        groups.append(Group(rep, members))
    groups.sort(key=lambda g: (-_SEV[g.rep.severity.value], g.rep.sink.path, g.rep.sink.line))
    return groups
