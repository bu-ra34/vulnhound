"""ProjectIndex and build_index."""

from __future__ import annotations

import ast
import hashlib
import tokenize
from pathlib import Path

from ..cache import Cache
from ..models import FunctionInfo, Location, ModuleInfo
from ..project import discover, is_package_file, module_name_for, relative_posix
from . import extract
from .resolve import Resolver


def decode_source(data: bytes) -> str:
    """Decode bytes: utf-8 first, then the declared encoding, then lossy."""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    try:
        enc, _ = tokenize.detect_encoding(iter(data.splitlines(True)).__next__)
        return data.decode(enc, errors="replace")
    except (SyntaxError, LookupError, StopIteration):
        return data.decode("utf-8", errors="replace")


class ProjectIndex:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.modules: dict[str, ModuleInfo] = {}
        self.functions: dict[str, FunctionInfo] = {}
        self._classes: dict[str, tuple[str, list[str]]] = {}
        self._func_cls: dict[str, str | None] = {}
        self._resolver: Resolver | None = None
        self._callers: dict[str, list[str]] | None = None
        self._ast: dict[str, ast.Module] = {}
        self._lines: dict[str, list[str]] = {}

    # -- lazy per-module data -------------------------------------------------
    def _text(self, module_name: str) -> str:
        return decode_source((self.root / self.modules[module_name].path).read_bytes())

    def ast_for(self, module_name: str) -> ast.Module:
        tree = self._ast.get(module_name)
        if tree is None:
            mi = self.modules[module_name]
            tree = ast.parse(self._text(module_name), filename=mi.path)
            self._ast[module_name] = tree
        return tree

    def source_lines(self, module_name: str) -> list[str]:
        lines = self._lines.get(module_name)
        if lines is None:
            lines = self._lines[module_name] = self._text(module_name).splitlines()
        return lines

    # -- call graph -----------------------------------------------------------
    def callees(self, qualname: str) -> list[str]:
        fn = self.functions.get(qualname)
        if fn is None:
            return []
        return [c for c in fn.calls if c in self.functions]

    def callers(self, qualname: str) -> list[str]:
        if self._callers is None:
            rev: dict[str, list[str]] = {}
            for q, fn in self.functions.items():
                for c in fn.calls:
                    if c in self.functions:
                        rev.setdefault(c, []).append(q)
            self._callers = rev
        return list(self._callers.get(qualname, []))

    # -- resolution -----------------------------------------------------------
    def resolve(self, module_name: str, dotted_name: str, function: str | None = None) -> str:
        """Resolve *dotted_name* as seen from *module_name* (optionally inside *function*).

        ``self.x``/``cls.x`` need class context: pass *function* (a qualname), or
        a unique same-named method in the module's classes is used.
        """
        assert self._resolver is not None
        cls = self._func_cls.get(function) if function else None
        head, _, rest = dotted_name.partition(".")
        if head in ("self", "cls") and cls is None and rest and "." not in rest:
            hits = [
                f"{c}.{rest}"
                for c, (m, _b) in self._classes.items()
                if m == module_name and f"{c}.{rest}" in self.functions
            ]
            if len(hits) == 1:
                return hits[0]
        return self._resolver.resolve(module_name, dotted_name, cls, function)


def build_index(root: Path, use_cache: bool = True, include_tests: bool = True) -> ProjectIndex:
    root = Path(root).resolve()
    idx = ProjectIndex(root)
    cache = Cache(root) if use_cache else None
    raw: dict[str, list[str]] = {}
    for path in discover(root, include_tests):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        name = module_name_for(root, path)
        if name in idx.modules:
            continue
        rel = relative_posix(root, path)
        sha = hashlib.sha256(data).hexdigest()
        payload = cache.load(sha, name, rel) if cache else None
        mi = fns = None
        if payload is not None:
            try:
                mi = ModuleInfo(**payload["module"])
                fns = payload["functions"]
            except (TypeError, KeyError):
                payload = mi = fns = None
        if payload is None:
            text = decode_source(data)
            payload = extract.extract_module(name, rel, text, sha, is_package_file(path))
            if cache:
                cache.store(sha, name, rel, payload)
            mi = ModuleInfo(**payload["module"])
            fns = payload["functions"]
        idx.modules[name] = mi
        for q, bases in payload["classes"].items():
            idx._classes[q] = (name, bases)
        for f in fns:
            q = f["qualname"]
            idx.functions[q] = FunctionInfo(
                qualname=q, module=f["module"], name=f["name"],
                location=Location(rel, f["line"], f["col"]), end_line=f["end_line"],
                params=f["params"], decorators=f["decorators"], calls=[],
                is_method=f["is_method"],
            )  # fmt: skip
            idx._func_cls[q] = f["cls"]
            raw[q] = f["calls"]
    if cache:
        cache.prune()
    res = idx._resolver = Resolver(idx.modules, idx.functions, idx._classes)
    for q, calls in raw.items():
        fn = idx.functions[q]
        cls = idx._func_cls[q]
        seen: dict[str, None] = {}
        for c in calls:
            seen[res.resolve(fn.module, c, cls, q)] = None
        fn.calls = list(seen)
    return idx
