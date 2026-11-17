"""Name resolution over the whole project (imports, re-exports, methods)."""

from __future__ import annotations

from ..models import FunctionInfo, ModuleInfo


class Resolver:
    def __init__(
        self,
        modules: dict[str, ModuleInfo],
        functions: dict[str, FunctionInfo],
        classes: dict[str, tuple[str, list[str]]],  # class qualname -> (module, raw bases)
    ) -> None:
        self.modules = modules
        self.functions = functions
        self.classes = classes

    def expand(self, module: str, dotted: str) -> str:
        """Expand the head of *dotted* through module-level defs and imports."""
        head, _, rest = dotted.partition(".")
        local = f"{module}.{head}"
        if local in self.functions or local in self.classes:
            full = f"{module}.{dotted}"
        else:
            mi = self.modules.get(module)
            target = mi.imports.get(head) if mi else None
            if target is None:
                return dotted
            full = f"{target}.{rest}" if rest else target
        return self._follow(full)

    def _follow(self, full: str) -> str:
        """Follow package re-exports (``from .sub import f`` in ``__init__``)."""
        for _ in range(6):
            if full in self.functions or full in self.classes:
                return full
            parts = full.split(".")
            for i in range(len(parts) - 1, 0, -1):
                mi = self.modules.get(".".join(parts[:i]))
                if mi is None:
                    continue
                nxt = mi.imports.get(parts[i])
                if nxt and nxt != ".".join(parts[: i + 1]):
                    full = ".".join([nxt, *parts[i + 1 :]])
                    break
                return full
            else:
                return full
        return full

    def method(self, cls: str, name: str, depth: int = 0) -> str | None:
        q = f"{cls}.{name}"
        if q in self.functions:
            return q
        if depth > 5 or cls not in self.classes:
            return None
        mod, bases = self.classes[cls]
        for b in bases:
            full = self.expand(mod, b)
            if full in self.classes and full != cls:
                r = self.method(full, name, depth + 1)
                if r:
                    return r
        return None

    def resolve(
        self, module: str, dotted: str, cls: str | None = None, scope: str | None = None
    ) -> str:
        head, _, rest = dotted.partition(".")
        if not head.isidentifier():
            return dotted
        if head in ("self", "cls") and cls and rest:
            first, _, more = rest.partition(".")
            m = self.method(cls, first)
            return m if m and not more else dotted
        if scope and not rest:
            cur = scope
            while cur:
                cand = f"{cur}.<locals>.{head}"
                if cand in self.functions:
                    return cand
                cur = cur.rpartition(".<locals>.")[0]
        full = self.expand(module, dotted)
        if full in self.classes:
            return self.method(full, "__init__") or full
        return full
