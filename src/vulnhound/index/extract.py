"""Single-pass AST extraction for one module. Pure function, JSON-serializable output.

Qualname conventions:
  module code        ``pkg.mod.<module>``
  function           ``pkg.mod.func``
  method             ``pkg.mod.Class.method``
  nested function    ``pkg.mod.outer.<locals>.inner``
  class in function  ``pkg.mod.outer.<locals>.Cls`` (methods: ``...Cls.meth``)

Raw call names: dotted text of the callee. Non-name parts are rendered as
``()`` (call result), ``[]`` (subscript) or ``<expr>``, e.g. ``conn.cursor().execute``.
"""

from __future__ import annotations

import ast


def _callname(n: ast.AST) -> str:
    t = type(n)
    if t is ast.Name:
        return n.id  # type: ignore[attr-defined]
    if t is ast.Attribute:
        return f"{_callname(n.value)}.{n.attr}"  # type: ignore[attr-defined]
    if t is ast.Call:
        return _callname(n.func) + "()"  # type: ignore[attr-defined]
    if t is ast.Subscript:
        return _callname(n.value) + "[]"  # type: ignore[attr-defined]
    return "<expr>"


def _decorator_text(d: ast.expr) -> str:
    if isinstance(d, ast.Call):
        d = d.func
    s = _callname(d)
    return s if "<expr>" not in s and "(" not in s and "[" not in s else ast.unparse(d)


def _params(a: ast.arguments) -> list[str]:
    out = [x.arg for x in a.posonlyargs + a.args]
    if a.vararg:
        out.append(a.vararg.arg)
    out += [x.arg for x in a.kwonlyargs]
    if a.kwarg:
        out.append(a.kwarg.arg)
    return out


class _Scope:
    __slots__ = ("calls", "seen")

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.seen: set[str] = set()

    def add(self, name: str) -> None:
        if name not in self.seen:
            self.seen.add(name)
            self.calls.append(name)


class _Extractor:
    def __init__(self, module: str, path: str, is_package: bool) -> None:
        self.module = module
        self.path = path
        self.pkg = module if is_package else module.rpartition(".")[0]
        self.imports: dict[str, str] = {}
        self.functions: list[dict] = []
        self.classes: dict[str, list[str]] = {}

    def visit(self, node: ast.AST, sc: _Scope, prefix: str, kind: str, cls: str | None) -> None:
        t = type(node)
        if t is ast.Call:
            sc.add(_callname(node.func))  # type: ignore[attr-defined]
        elif t is ast.FunctionDef or t is ast.AsyncFunctionDef:
            self.function(node, sc, prefix, kind, cls)  # type: ignore[arg-type]
            return
        elif t is ast.ClassDef:
            self.klass(node, sc, prefix, cls)  # type: ignore[arg-type]
            return
        elif t is ast.Import:
            for a in node.names:  # type: ignore[attr-defined]
                top = a.name.partition(".")[0]
                self.bind(a.asname or top, a.name if a.asname else top, kind)
            return
        elif t is ast.ImportFrom:
            self.import_from(node, kind)  # type: ignore[arg-type]
            return
        for child in ast.iter_child_nodes(node):
            self.visit(child, sc, prefix, kind, cls)

    def bind(self, alias: str, target: str, kind: str) -> None:
        if kind == "func":  # module-level / class-level imports win
            self.imports.setdefault(alias, target)
        else:
            self.imports[alias] = target

    def import_from(self, node: ast.ImportFrom, kind: str) -> None:
        base = node.module or ""
        if node.level:
            parts = self.pkg.split(".") if self.pkg else []
            up = node.level - 1
            parts = parts[: len(parts) - up] if up <= len(parts) else []
            base = ".".join(parts + ([node.module] if node.module else []))
        for a in node.names:
            if a.name == "*":
                continue
            self.bind(a.asname or a.name, f"{base}.{a.name}" if base else a.name, kind)

    def function(self, node, sc: _Scope, prefix: str, kind: str, cls: str | None) -> None:
        for d in node.decorator_list:
            self.visit(d, sc, prefix, kind, cls)
        args = node.args
        for d in args.defaults:
            self.visit(d, sc, prefix, kind, cls)
        for d in args.kw_defaults:
            if d is not None:
                self.visit(d, sc, prefix, kind, cls)
        qual = f"{prefix}.{node.name}"
        fs = _Scope()
        self.functions.append(
            {
                "qualname": qual,
                "module": self.module,
                "name": node.name,
                "line": node.lineno,
                "col": node.col_offset,
                "end_line": node.end_lineno or node.lineno,
                "params": _params(args),
                "decorators": [_decorator_text(d) for d in node.decorator_list],
                "calls": fs.calls,
                "is_method": kind == "class",
                "cls": cls,
            }
        )
        for stmt in node.body:
            self.visit(stmt, fs, qual + ".<locals>", "func", cls)

    def klass(self, node: ast.ClassDef, sc: _Scope, prefix: str, cls: str | None) -> None:
        for d in node.decorator_list:
            self.visit(d, sc, prefix, "x", cls)
        for b in node.bases:
            self.visit(b, sc, prefix, "x", cls)
        for k in node.keywords:
            self.visit(k, sc, prefix, "x", cls)
        qual = f"{prefix}.{node.name}"
        names = [_callname(b) for b in node.bases]
        self.classes[qual] = [s for s in names if not any(c in s for c in "<([")]
        for stmt in node.body:
            self.visit(stmt, sc, qual, "class", qual)


def extract_module(name: str, path: str, text: str, sha: str, is_package: bool) -> dict:
    """Extract one module into a JSON-safe payload (``module``, ``functions``, ``classes``)."""
    mod = {
        "name": name, "path": path, "sha256": sha,
        "imports": {}, "functions": [], "parse_error": None,
    }  # fmt: skip
    ex = _Extractor(name, path, is_package)
    try:
        tree = ast.parse(text, filename=path)
        top = _Scope()
        for stmt in tree.body:
            ex.visit(stmt, top, name, "module", None)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
        if isinstance(e, SyntaxError):
            mod["parse_error"] = f"{e.msg} (line {e.lineno})"
        else:
            mod["parse_error"] = f"{type(e).__name__}: {e}"[:200]
        return {"module": mod, "functions": [], "classes": {}}
    end = max(len(text.splitlines()), 1)
    ex.functions.insert(
        0,
        {
            "qualname": f"{name}.<module>", "module": name, "name": "<module>", "line": 1, "col": 0,
            "end_line": end, "params": [], "decorators": [], "calls": top.calls,
            "is_method": False, "cls": None,
        },
    )  # fmt: skip
    mod["imports"] = ex.imports
    mod["functions"] = [f["qualname"] for f in ex.functions]
    return {"module": mod, "functions": ex.functions, "classes": ex.classes}
