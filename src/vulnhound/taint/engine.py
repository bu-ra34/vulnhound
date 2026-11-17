"""Taint engine: intraprocedural dataflow plus function summaries to a fixpoint.

Each function is analysed with its parameters carrying *symbolic* taint. A symbolic
taint that reaches a sink becomes a ``Hit`` in the function's summary
(param -> sink). Callers that pass real (source) taint to such a parameter emit a
finding whose sink is the real sink location. Taint reaching ``return`` produces
param -> return and source -> return summaries.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, replace

from vulnhound.index import ProjectIndex
from vulnhound.models import Finding, Location, Severity, Step
from vulnhound.report import finding_id
from vulnhound.taint.specs import (
    DJANGO_REQUEST_ATTRS,
    FASTAPI_APP_CLASSES,
    FASTAPI_ROUTE_DECORATORS,
    FLASK_ROUTE_DECORATORS,
    RULES,
    SANITIZERS,
    SINKS,
    Sink,
    match_sink,
    match_source,
)

MAX_PATH = 8
MAX_HITS_PER_PARAM = 16
MAX_REANALYSIS = 5
_SEV_DOWN = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,
}
_NO_PROPAGATE = frozenset(
    {"len", "isinstance", "issubclass", "hash", "id", "type", "callable", "print", "ord",
     "hasattr", "any", "all", "sum", "min", "max", "sorted_len", "enumerate_len"}
)  # fmt: skip
_MUTATORS = frozenset({"append", "extend", "add", "insert", "update", "setdefault", "appendleft"})
_PARAM_SRC_KINDS = frozenset({"django-request-param", "fastapi-param"})
_REQ_ATTRS = DJANGO_REQUEST_ATTRS | {
    "query_params", "path_params", "url", "json", "body", "form", "get_json", "values", "args",
}  # fmt: skip
_SCALARS = frozenset(
    {"int", "float", "bool", "UUID", "date", "datetime", "time", "timedelta", "Decimal",
     "Request", "Response", "BackgroundTasks", "HTTPConnection", "WebSocket", "Literal",
     "HttpRequest", "SecretStr"}
)  # fmt: skip
_CONTAINERS = frozenset(
    {"List", "Optional", "Union", "Annotated", "list", "dict", "Dict", "set", "Set", "tuple",
     "Tuple", "Sequence", "None", "Iterable", "FrozenSet", "frozenset"}
)  # fmt: skip
_PROPAGATING_SINK_RULES = frozenset({"path-traversal", "deserialization"})
_SKIP_SINKS = frozenset({"pathlib.Path"})  # constructor only; taint flows to the later read
_CONV_RE = re.compile(r"<(?:(\w+)(?:\([^>]*\))?:)?(\w+)>")
_RECV_SINKS: dict[str, list[Sink]] = {}
for _s in SINKS:
    if not _s.arg_positions and not _s.kwarg_names and not _s.pattern.startswith("*."):
        _RECV_SINKS.setdefault(_s.pattern.rsplit(".", 1)[-1], []).append(_s)
_RECV_TOO = frozenset({"extractall"})  # archive receiver is attacker data, not just the path
_SAN_LAST = frozenset(s.pattern.rsplit(".", 1)[-1] for s in SANITIZERS)
_SAN_BY_NAME: dict[str, frozenset[str]] = {}
_SAN_WILD: dict[str, frozenset[str]] = {}
for _san in SANITIZERS:
    _rules = frozenset(RULES) if "*" in _san.rules else frozenset(_san.rules)
    _d = _SAN_WILD if _san.pattern.startswith("*.") else _SAN_BY_NAME
    _key = _san.pattern[2:] if _san.pattern.startswith("*.") else _san.pattern
    _d[_key] = _d.get(_key, frozenset()) | _rules
_ALL_RULES = frozenset(RULES)


# --------------------------------------------------------------------------- data


@dataclass(frozen=True)
class Src:
    loc: Location
    label: str
    weak: bool = False


@dataclass(frozen=True)
class Taint:
    src: Src | None
    params: frozenset
    san: frozenset
    built: bool
    steps: tuple


@dataclass(frozen=True)
class Hit:
    rule: str
    cwe: str
    severity: Severity
    sink: Location
    label: str  # callee as written at the sink
    conf: float
    steps: tuple  # callee-side steps ending with the sink step
    needs_built: bool = False
    via: str = ""  # first project function hop name, for messages


def _score(t: Taint) -> int:
    if t.src is None:
        return 0
    return 1 if t.src.weak else 2


def tmerge(a: Taint | None, b: Taint | None) -> Taint | None:
    if a is None:
        return b
    if b is None or a is b:
        return a
    prim = b if _score(b) > _score(a) else a
    return Taint(prim.src, a.params | b.params, a.san & b.san, a.built or b.built, prim.steps)


def _chain(n: ast.AST) -> str:
    """Dotted text like the indexer's raw call names (``()``/``[]``/``<expr>`` for others)."""
    t = type(n)
    if t is ast.Name:
        return n.id  # type: ignore[attr-defined]
    if t is ast.Attribute:
        return f"{_chain(n.value)}.{n.attr}"  # type: ignore[attr-defined]
    if t is ast.Call:
        return _chain(n.func) + "()"  # type: ignore[attr-defined]
    if t is ast.Subscript:
        return _chain(n.value) + "[]"  # type: ignore[attr-defined]
    return "<expr>"


def _pure(s: str) -> bool:
    return "(" not in s and "[" not in s and "<" not in s


def _collect_nodes(tree: ast.Module, module: str) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {f"{module}.<module>": tree}

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}.{child.name}"
                out[q] = child
                visit(child, q + ".<locals>")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}.{child.name}")
            else:
                visit(child, prefix)

    visit(tree, module)
    return out


class _Summary:
    __slots__ = ("psinks", "pret", "ret_src", "sig")

    def __init__(self) -> None:
        self.psinks: dict[str, list[Hit]] = {}
        self.pret: dict[str, tuple[frozenset, bool]] = {}
        self.ret_src: Taint | None = None
        self.sig: object = None


# --------------------------------------------------------------------------- engine


class Engine:
    def __init__(self, index: ProjectIndex) -> None:
        self.ix = index
        self.nodes: dict[str, ast.AST] = {}
        self.node_module: dict[str, str] = {}
        self.summ: dict[str, _Summary] = {}
        self.fn_findings: dict[str, list[Finding]] = {}
        self._rcache: dict[tuple, str] = {}
        self._modinfo: dict[str, tuple[dict[str, str], dict[str, str]]] = {}
        self._pos_params: dict[str, list[str]] = {}

    # -- setup --------------------------------------------------------------
    def load(self) -> None:
        for m, mi in self.ix.modules.items():
            if mi.parse_error:
                continue
            try:
                tree = self.ix.ast_for(m)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                continue
            for q, n in _collect_nodes(tree, m).items():
                if q in self.ix.functions:
                    self.nodes[q] = n
                    self.node_module[q] = m

    def resolve(self, module: str, qual: str, dotted: str) -> str:
        key = (module, qual, dotted)
        r = self._rcache.get(key)
        if r is None:
            try:
                r = self.ix.resolve(module, dotted, qual)
            except Exception:  # defensive: resolver must never kill analysis
                r = dotted
            self._rcache[key] = r
        return r

    def modinfo(self, module: str) -> tuple[dict[str, str], dict[str, str]]:
        """(module-level var -> resolved constructor, app var -> 'fastapi'|'flask')."""
        mi = self._modinfo.get(module)
        if mi is not None:
            return mi
        types: dict[str, str] = {}
        kinds: dict[str, str] = {}
        try:
            body = self.ix.ast_for(module).body
        except Exception:
            body = []
        for st in body:
            if isinstance(st, ast.Assign) and isinstance(st.value, ast.Call):
                targets = [t for t in st.targets if isinstance(t, ast.Name)]
                val = st.value
            elif (
                isinstance(st, ast.AnnAssign)
                and isinstance(st.value, ast.Call)
                and isinstance(st.target, ast.Name)
            ):
                targets, val = [st.target], st.value
            else:
                continue
            name = self.resolve(module, f"{module}.<module>", _chain(val.func))
            if name.endswith(".__init__"):
                name = name[: -len(".__init__")]
            for t in targets:
                types[t.id] = name
                if name in FASTAPI_APP_CLASSES or name.endswith(("FastAPI", "APIRouter")):
                    kinds[t.id] = "fastapi"
                elif name.startswith("flask.") or name.endswith(("Flask", "Blueprint")):
                    kinds[t.id] = "flask"
        self._modinfo[module] = (types, kinds)
        return types, kinds

    def pos_params(self, q: str) -> list[str]:
        r = self._pos_params.get(q)
        if r is None:
            n = self.nodes.get(q)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = n.args
                r = [x.arg for x in a.posonlyargs + a.args]
                fi = self.ix.functions[q]
                if fi.is_method and "staticmethod" not in fi.decorators and r:
                    r = r[1:]
            else:
                r = []
            self._pos_params[q] = r
        return r

    # -- driver -------------------------------------------------------------
    def run(self) -> list[Finding]:
        self.load()
        order = list(self.nodes)
        counts: dict[str, int] = {}
        pending = list(order)
        queued = set(pending)
        while pending:
            q = pending.pop(0)
            queued.discard(q)
            counts[q] = counts.get(q, 0) + 1
            changed = self.analyze_function(q)
            if changed:
                for c in self.ix.callers(q):
                    if c in self.nodes and c not in queued and counts.get(c, 0) < MAX_REANALYSIS:
                        queued.add(c)
                        pending.append(c)
        out: dict[str, Finding] = {}
        for fs in self.fn_findings.values():
            for f in fs:
                old = out.get(f.id)
                if old is None or f.confidence > old.confidence:
                    out[f.id] = f
        return sorted(out.values(), key=lambda f: (f.sink.path, f.sink.line, f.rule, f.id))

    def analyze_function(self, q: str) -> bool:
        fa = _FuncAnalyzer(self, q)
        try:
            fa.run()
        except RecursionError:
            self.fn_findings[q] = []
            return False
        self.fn_findings[q] = fa.findings
        s = fa.summary()
        old = self.summ.get(q)
        if old is not None and old.sig == s.sig:
            return False
        self.summ[q] = s
        return old is not None or bool(s.sig)


# --------------------------------------------------------------------------- per function


class _FuncAnalyzer:
    def __init__(self, eng: Engine, qual: str) -> None:
        self.eng = eng
        self.ix = eng.ix
        self.qual = qual
        self.module = eng.node_module[qual]
        self.node = eng.nodes[qual]
        self.path = self.ix.modules[self.module].path
        self.lines = self.ix.source_lines(self.module)
        self.env: dict[str, Taint] = {}
        self.types: dict[str, str] = {}
        self.bound: set[str] = set()
        self.reqnames: set[str] = set()
        self.findings: list[Finding] = []
        self.psinks: dict[str, list[Hit]] = {}
        self.ret: Taint | None = None
        self.mtypes, self.mkinds = eng.modinfo(self.module)

    # -- helpers ------------------------------------------------------------
    def loc(self, n: ast.AST) -> Location:
        return Location(self.path, getattr(n, "lineno", 1), getattr(n, "col_offset", 0))

    def code(self, line: int) -> str:
        return self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""

    def step(self, loc: Location, note: str) -> Step:
        return Step(loc, self.code(loc.line), note)

    def resolve(self, dotted: str) -> str:
        head, _, rest = dotted.partition(".")
        if rest:
            t = self.types.get(head)
            if t is None and head not in self.bound:
                t = self.mtypes.get(head)
            if t is not None:
                return f"{t}.{rest}"
        return self.eng.resolve(self.module, self.qual, dotted)

    def with_step(self, t: Taint, loc: Location, note: str) -> Taint:
        if len(t.steps) >= MAX_PATH - 2:
            return t
        if t.steps and t.steps[-1].location.line == loc.line:
            return t
        return replace(t, steps=(*t.steps, self.step(loc, note)))

    # -- entry --------------------------------------------------------------
    def run(self) -> None:
        node = self.node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.init_params(node)
            self.block(node.body)
        else:
            self.block(node.body)  # type: ignore[attr-defined]

    def summary(self) -> _Summary:
        s = _Summary()
        s.psinks = self.psinks
        if self.ret is not None:
            for p in self.ret.params:
                s.pret[p] = (self.ret.san, self.ret.built)
            if self.ret.src is not None:
                s.ret_src = replace(self.ret, params=frozenset())
        s.sig = (
            frozenset(
                (p, h.rule, h.sink.path, h.sink.line, h.needs_built)
                for p, hs in self.psinks.items()
                for h in hs
            ),
            frozenset((p, tuple(sorted(v[0])), v[1]) for p, v in s.pret.items()),
            None
            if s.ret_src is None
            else (s.ret_src.src.loc, tuple(sorted(s.ret_src.san)), s.ret_src.built),  # type: ignore[union-attr]
        )
        return s

    # -- parameters / sources -------------------------------------------------
    def route_kind(self, fn) -> tuple[str | None, str]:
        """('flask'|'fastapi'|None, url pattern) from the function's decorators."""
        fastapi_imp = any(
            t.startswith(("fastapi", "starlette"))
            for t in self.ix.modules[self.module].imports.values()
        )
        for d in fn.decorator_list:
            call = d if isinstance(d, ast.Call) else None
            f = d.func if call else d
            if not isinstance(f, ast.Attribute):
                continue
            last = f.attr
            if last not in FLASK_ROUTE_DECORATORS and last not in FASTAPI_ROUTE_DECORATORS:
                continue
            head = _chain(f.value).partition(".")[0]
            kind = self.mkinds.get(head)
            if kind is None:
                if fastapi_imp and last in FASTAPI_ROUTE_DECORATORS:
                    kind = "fastapi"
                elif last == "route" or any(
                    t.startswith("flask") for t in self.ix.modules[self.module].imports.values()
                ):
                    kind = "flask"
            if kind is None:
                continue
            url = ""
            if call and call.args and isinstance(call.args[0], ast.Constant):
                url = str(call.args[0].value)
            return kind, url
        return None, ""

    def init_params(self, fn) -> None:
        a = fn.args
        allargs = a.posonlyargs + a.args + a.kwonlyargs
        defaults: dict[str, ast.expr] = {}
        pos = a.posonlyargs + a.args
        for arg, d in zip(pos[len(pos) - len(a.defaults) :], a.defaults, strict=False):
            defaults[arg.arg] = d
        for arg, d in zip(a.kwonlyargs, a.kw_defaults, strict=True):
            if d is not None:
                defaults[arg.arg] = d
        extra = [x for x in (a.vararg, a.kwarg) if x is not None]
        names = [x.arg for x in allargs + extra]
        self.bound.update(names)
        kind, url = self.route_kind(fn)
        fi = self.ix.functions[self.qual]
        skip_first = fi.is_method and "staticmethod" not in fi.decorators and bool(allargs)
        if kind == "flask":
            conv = {m.group(2): (m.group(1) or "") for m in _CONV_RE.finditer(url)}
            for arg in allargs:
                if conv.get(arg.arg, "") in ("int", "float", "uuid"):
                    continue
                self.set_source_param(arg, "flask URL param")
            return
        if kind == "fastapi":
            for arg in allargs:
                ann = arg.annotation
                d = defaults.get(arg.arg)
                if isinstance(d, ast.Call) and _chain(d.func).rpartition(".")[2] in (
                    "Depends", "Security",
                ):  # fmt: skip
                    continue
                if ann is not None:
                    leaves = _ann_leaves(ann)
                    if "Request" in leaves and len(leaves) == 1:
                        self.reqnames.add(arg.arg)
                        continue
                    if leaves and all(x in _SCALARS for x in leaves):
                        continue
                self.set_source_param(arg, "FastAPI param")
            return
        # Django-style view: first real parameter called ``request``
        real = allargs[1:] if skip_first else allargs
        if real and (
            real[0].arg == "request"
            or (real[0].annotation is not None and "HttpRequest" in _ann_leaves(real[0].annotation))
        ):
            self.reqnames.add(real[0].arg)
        for arg in names:
            if arg not in self.reqnames and not (skip_first and arg == allargs[0].arg):
                self.env[arg] = Taint(None, frozenset((arg,)), frozenset(), False, ())

    def set_source_param(self, arg: ast.arg, what: str) -> None:
        loc = self.loc(arg)
        src = Src(loc, f"param {arg.arg}")
        self.env[arg.arg] = Taint(src, frozenset(), frozenset(), False,
                                  (self.step(loc, f"source: {what} '{arg.arg}'"),))  # fmt: skip

    def chain_source(self, node: ast.AST) -> Taint | None:
        s = _chain(node)
        if not _pure(s):
            return None
        head, _, rest = s.partition(".")
        if not rest:
            if head in self.reqnames or head in self.env:
                return None
            full = self.resolve(s)
            src = match_source(full) if full != s or head == "input" else None
            if src is None or src.kind in _PARAM_SRC_KINDS:
                return None
            return self.mk_src(node, src.pattern, src.weak)
        if head in self.reqnames:
            if rest.partition(".")[0] in _REQ_ATTRS:
                return self.mk_src(node, f"request.{rest.partition('.')[0]}", False)
            return None
        if head in self.env and head not in self.mtypes:
            return None
        full = self.resolve(s)
        src = match_source(full)
        if src is None or src.kind in _PARAM_SRC_KINDS:
            return None
        return self.mk_src(node, src.pattern, src.weak)

    def mk_src(self, node: ast.AST, label: str, weak: bool) -> Taint:
        for pre in ("flask.", "django.http.HttpRequest."):
            if label.startswith(pre):
                label = label[len(pre) :]
                if pre.startswith("django"):
                    label = "request." + label
        loc = self.loc(node)
        return Taint(Src(loc, label, weak), frozenset(), frozenset(), False,
                     (self.step(loc, f"source: {label}"),))  # fmt: skip

    # -- statements ---------------------------------------------------------
    def block(self, stmts) -> None:
        for s in stmts:
            self.stmt(s)

    def branch(self, stmts) -> dict[str, Taint]:
        saved = self.env
        self.env = dict(saved)
        self.block(stmts)
        out = self.env
        self.env = saved
        return out

    @staticmethod
    def merge_env(a: dict[str, Taint], b: dict[str, Taint]) -> dict[str, Taint]:
        out = dict(a)
        for k, tb in b.items():
            ta = out.get(k)
            out[k] = tb if ta is None else tmerge(ta, tb)  # type: ignore[assignment]
        return out

    def stmt(self, s: ast.stmt) -> None:
        t = type(s)
        if t is ast.Expr:
            self.ev(s.value)  # type: ignore[attr-defined]
        elif t is ast.Assign:
            self.assign(s)  # type: ignore[arg-type]
        elif t is ast.AnnAssign:
            if s.value is not None:  # type: ignore[attr-defined]
                self.bind(s.target, self.ev(s.value), s.value, s.value)  # type: ignore[attr-defined]
        elif t is ast.AugAssign:
            val = self.ev(s.value)  # type: ignore[attr-defined]
            cur = self.ev(s.target) if isinstance(s.target, (ast.Name, ast.Attribute)) else None  # type: ignore[attr-defined]
            new = tmerge(cur, val)
            if new is not None and isinstance(s.op, (ast.Add, ast.Mod)):  # type: ignore[attr-defined]
                new = replace(new, built=True)
            self.bind(s.target, new, s, s.value)  # type: ignore[attr-defined]
        elif t is ast.Return:
            if s.value is not None:  # type: ignore[attr-defined]
                self.ret = tmerge(self.ret, self.ev(s.value))  # type: ignore[attr-defined]
        elif t is ast.If:
            self.ev(s.test)  # type: ignore[attr-defined]
            e1 = self.branch(s.body)  # type: ignore[attr-defined]
            e2 = self.branch(s.orelse)  # type: ignore[attr-defined]
            self.env = self.merge_env(e1, e2)
        elif t is ast.For or t is ast.AsyncFor:
            it = self.ev(s.iter)  # type: ignore[attr-defined]
            saved = self.env
            self.env = dict(saved)
            self.bind(s.target, it, s.iter, s.iter)  # type: ignore[attr-defined]
            self.block(s.body)  # type: ignore[attr-defined]
            e1 = self.env
            self.env = saved
            self.env = self.merge_env(saved, e1)
            self.block(s.orelse)  # type: ignore[attr-defined]
        elif t is ast.While:
            self.ev(s.test)  # type: ignore[attr-defined]
            e1 = self.branch(s.body)  # type: ignore[attr-defined]
            self.env = self.merge_env(self.env, e1)
            self.block(s.orelse)  # type: ignore[attr-defined]
        elif t is ast.With or t is ast.AsyncWith:
            for item in s.items:  # type: ignore[attr-defined]
                v = self.ev(item.context_expr)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, v, item.context_expr, item.context_expr)
            self.block(s.body)  # type: ignore[attr-defined]
        elif t is ast.Try or t is getattr(ast, "TryStar", ()):
            pre = self.env
            e1 = self.branch(s.body)  # type: ignore[attr-defined]
            self.env = self.merge_env(pre, e1)
            start = self.env
            merged = self.env
            for h in s.handlers:  # type: ignore[attr-defined]
                self.env = dict(start)
                if h.name:
                    self.env.pop(h.name, None)
                self.block(h.body)
                merged = self.merge_env(merged, self.env)
            self.env = merged
            self.block(s.orelse)  # type: ignore[attr-defined]
            self.block(s.finalbody)  # type: ignore[attr-defined]
        elif t is ast.Match:
            self.ev(s.subject)  # type: ignore[attr-defined]
            merged = self.env
            for c in s.cases:  # type: ignore[attr-defined]
                merged = self.merge_env(merged, self.branch(c.body))
            self.env = merged
        elif t is ast.Delete:
            for tg in s.targets:  # type: ignore[attr-defined]
                if isinstance(tg, ast.Name):
                    self.env.pop(tg.id, None)
        elif t is ast.Raise:
            if s.exc is not None:  # type: ignore[attr-defined]
                self.ev(s.exc)  # type: ignore[attr-defined]
        elif t is ast.Assert:
            self.ev(s.test)  # type: ignore[attr-defined]
        elif t is ast.ClassDef:
            if not self.in_function:
                self.block(s.body)  # type: ignore[attr-defined]
        # FunctionDef / Import / Pass / Global ...: nothing (nested defs are own functions)

    @property
    def in_function(self) -> bool:
        return not isinstance(self.node, ast.Module)

    def assign(self, s: ast.Assign) -> None:
        val = s.value
        if (
            len(s.targets) == 1
            and isinstance(s.targets[0], (ast.Tuple, ast.List))
            and isinstance(val, (ast.Tuple, ast.List))
            and len(s.targets[0].elts) == len(val.elts)
            and not any(isinstance(e, ast.Starred) for e in val.elts + s.targets[0].elts)
        ):
            ts = [self.ev(e) for e in val.elts]
            for tg, t, e in zip(s.targets[0].elts, ts, val.elts, strict=True):
                self.bind(tg, t, e, e)
            return
        t = self.ev(val)
        for tg in s.targets:
            self.bind(tg, t, val, val)

    def bind(self, target: ast.AST, t: Taint | None, at: ast.AST, valnode: ast.AST) -> None:
        tt = type(target)
        if tt is ast.Name:
            name = target.id  # type: ignore[attr-defined]
            self.bound.add(name)
            if t is None:
                self.env.pop(name, None)
            else:
                self.env[name] = self.with_step(t, self.loc(at), f"assigned to {name}")
            v = valnode.value if isinstance(valnode, ast.Await) else valnode
            if isinstance(v, ast.Call):
                ty = self.resolve(_chain(v.func))
                if ty.endswith(".__init__"):
                    ty = ty[: -len(".__init__")]
                self.types[name] = ty
            else:
                self.types.pop(name, None)
        elif tt is ast.Tuple or tt is ast.List:
            for e in target.elts:  # type: ignore[attr-defined]
                self.bind(e.value if isinstance(e, ast.Starred) else e, t, at, valnode)
        elif tt is ast.Attribute:
            key = _chain(target)
            if _pure(key):
                if t is None:
                    self.env.pop(key, None)
                else:
                    self.env[key] = self.with_step(t, self.loc(at), f"assigned to {key}")
        elif tt is ast.Subscript:
            base = target.value  # type: ignore[attr-defined]
            if isinstance(base, ast.Name) and t is not None:
                self.env[base.id] = tmerge(self.env.get(base.id), t)  # type: ignore[assignment]
            self.ev(target.slice)  # type: ignore[attr-defined]
        elif tt is ast.Starred:
            self.bind(target.value, t, at, valnode)  # type: ignore[attr-defined]

    # -- expressions --------------------------------------------------------
    def ev(self, n: ast.AST | None) -> Taint | None:
        if n is None:
            return None
        t = type(n)
        if t is ast.Constant:
            return None
        if t is ast.Name:
            r = self.env.get(n.id)  # type: ignore[attr-defined]
            if r is None and n.id not in self.bound and n.id not in self.reqnames:  # type: ignore[attr-defined]
                return self.chain_source(n)
            return r
        if t is ast.Attribute:
            key = _chain(n)
            if _pure(key):
                hit = self.env.get(key)
                if hit is not None:
                    return hit
                src = self.chain_source(n)
                if src is not None:
                    return src
            return self.ev(n.value)  # type: ignore[attr-defined]
        if t is ast.Call:
            return self.call(n)  # type: ignore[arg-type]
        if t is ast.JoinedStr:
            acc = None
            for v in n.values:  # type: ignore[attr-defined]
                acc = tmerge(acc, self.ev(v))
            return replace(acc, built=True) if acc is not None else None
        if t is ast.FormattedValue:
            a = self.ev(n.value)  # type: ignore[attr-defined]
            self.ev(n.format_spec)  # type: ignore[attr-defined]
            return a
        if t is ast.BinOp:
            r = tmerge(self.ev(n.left), self.ev(n.right))  # type: ignore[attr-defined]
            if r is not None and isinstance(n.op, (ast.Add, ast.Mod)):  # type: ignore[attr-defined]
                r = replace(r, built=True)
            return r
        if t is ast.Subscript:
            v = self.ev(n.value)  # type: ignore[attr-defined]
            self.ev(n.slice)  # type: ignore[attr-defined]
            if v is None:
                src = self.chain_source(n.value)  # type: ignore[attr-defined]
                return src
            return v
        if t is ast.Await or t is ast.Starred:
            return self.ev(n.value)  # type: ignore[attr-defined]
        if t is ast.Compare:
            self.ev(n.left)  # type: ignore[attr-defined]
            for c in n.comparators:  # type: ignore[attr-defined]
                self.ev(c)
            return None
        if t is ast.UnaryOp:
            r = self.ev(n.operand)  # type: ignore[attr-defined]
            return None if isinstance(n.op, ast.Not) else r  # type: ignore[attr-defined]
        if t is ast.IfExp:
            self.ev(n.test)  # type: ignore[attr-defined]
            return tmerge(self.ev(n.body), self.ev(n.orelse))  # type: ignore[attr-defined]
        if t is ast.Lambda:
            return None
        if t in (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp):
            return self.comp(n)
        if t is ast.NamedExpr:
            v = self.ev(n.value)  # type: ignore[attr-defined]
            self.bind(n.target, v, n, n.value)  # type: ignore[attr-defined]
            return v
        if t is ast.Yield or t is ast.YieldFrom:
            v = self.ev(n.value)  # type: ignore[attr-defined]
            self.ret = tmerge(self.ret, v)
            return v
        acc = None  # BoolOp, Dict, List, Tuple, Set, Slice, ...
        for c in ast.iter_child_nodes(n):
            if isinstance(c, ast.expr_context):
                continue
            acc = tmerge(acc, self.ev(c))
        return acc

    def comp(self, n) -> Taint | None:
        saved = self.env
        self.env = dict(saved)
        for g in n.generators:
            it = self.ev(g.iter)
            self.bind(g.target, it, g.iter, g.iter)
            for cond in g.ifs:
                self.ev(cond)
        if isinstance(n, ast.DictComp):
            r = tmerge(self.ev(n.key), self.ev(n.value))
        else:
            r = self.ev(n.elt)
        self.env = saved
        return r

    # -- calls ----------------------------------------------------------------
    def call(self, n: ast.Call) -> Taint | None:
        func = n.func
        name = _chain(func)
        arg_nodes = [a.value if isinstance(a, ast.Starred) else a for a in n.args]
        arg_ts = [self.ev(a) for a in arg_nodes]
        kw_ts: dict[str | None, Taint | None] = {}
        for kw in n.keywords:
            v = self.ev(kw.value)
            kw_ts[kw.arg] = tmerge(kw_ts.get(kw.arg), v)
        recv_t = None
        if isinstance(func, ast.Attribute):
            recv_t = self.ev(func.value)
        elif not isinstance(func, ast.Name):
            recv_t = self.ev(func)

        if _pure(name):
            src = self.chain_source(func)
            if src is not None:
                return src

        resolved = self.resolve(name)
        last = resolved.rsplit(".", 1)[-1]

        # sanitizers
        if last in _SAN_LAST:
            rules = _SAN_BY_NAME.get(resolved, frozenset())
            if "." in resolved:
                rules = rules | _SAN_WILD.get(last, frozenset())
            if rules:
                merged = self.merge_all(recv_t, arg_ts, kw_ts)
                if merged is None or rules >= _ALL_RULES:
                    return None
                return replace(merged, san=merged.san | rules)

        # project function: summaries
        if resolved in self.ix.functions:
            return self.project_call(n, resolved, name, arg_ts, kw_ts, recv_t)

        # mutating container methods taint the receiver
        if isinstance(func, ast.Attribute) and func.attr in _MUTATORS:
            allt = self.merge_all(None, arg_ts, kw_ts)
            if allt is not None and isinstance(func.value, ast.Name):
                cur = self.env.get(func.value.id)
                self.env[func.value.id] = tmerge(cur, allt)  # type: ignore[assignment]

        sink_rules = self.check_sinks(n, name, resolved, arg_nodes, arg_ts, kw_ts, recv_t)

        if last in _NO_PROPAGATE and "." not in resolved:
            return None
        if (
            sink_rules
            and not (sink_rules & _PROPAGATING_SINK_RULES)
            and resolved not in _SKIP_SINKS
        ):
            return None
        out = self.merge_all(recv_t, arg_ts, kw_ts)
        if out is not None and last in ("format", "join", "format_map"):
            out = replace(out, built=True)
        return out

    @staticmethod
    def merge_all(recv_t, arg_ts, kw_ts) -> Taint | None:
        acc = recv_t
        for a in arg_ts:
            acc = tmerge(acc, a)
        for a in kw_ts.values():
            acc = tmerge(acc, a)
        return acc

    def check_sinks(self, n, name, resolved, arg_nodes, arg_ts, kw_ts, recv_t) -> set[str]:
        cands = match_sink(resolved)
        recv_only = False
        if not cands and isinstance(n.func, ast.Attribute):
            cands = _RECV_SINKS.get(n.func.attr, [])
            recv_only = bool(cands)
        if not cands or resolved in _SKIP_SINKS:
            return set()
        kws = {k.arg: k.value for k in n.keywords if k.arg}
        good: list[Sink] = []
        for s in cands:
            if s.requires_kwarg and not all(
                isinstance(kws.get(k), ast.Constant) and kws[k].value == v  # type: ignore[attr-defined]
                for k, v in s.requires_kwarg.items()
            ):
                continue
            if s.safe_kwarg_values:
                unsafe = True
                for kwn, safe in s.safe_kwarg_values.items():
                    v = kws.get(kwn)
                    if v is None and len(n.args) > 1:
                        v = n.args[1]
                    if v is not None and self.resolve(_chain(v)) in safe:
                        unsafe = False
                if not unsafe:
                    continue
            good.append(s)
        reqpat = {s.pattern for s in good if s.requires_kwarg}
        good = [s for s in good if s.requires_kwarg or s.pattern not in reqpat]
        rules: set[str] = set()
        for s in good:
            rules.add(s.rule)
            tainted: Taint | None = None
            for pos in s.arg_positions:
                if pos < len(arg_ts) and arg_ts[pos] is not None and self._eff(arg_ts[pos], s):
                    tainted = arg_ts[pos]
                    break
            if tainted is None:
                for kn in s.kwarg_names:
                    v = kw_ts.get(kn)
                    if v is not None and self._eff(v, s):
                        tainted = v
                        break
            last = s.pattern.rsplit(".", 1)[-1]
            if tainted is None and (not s.arg_positions or last in _RECV_TOO):
                if recv_t is not None and self._eff(recv_t, s):
                    tainted = recv_t
            if tainted is None:
                continue
            wild = s.pattern.startswith("*.")
            conf = 0.4 if wild else (0.5 if recv_only else 0.9)
            at = self.loc(n)
            hit = Hit(
                rule=s.rule, cwe=s.cwe, severity=s.severity, sink=at, label=name, conf=conf,
                steps=(self.step(at, f"sink: {name}(...)"),),
                needs_built=s.rule == "sqli",
            )  # fmt: skip
            self.apply_hit(tainted, hit, ())
        return rules

    @staticmethod
    def _eff(t: Taint, s: Sink) -> bool:
        return s.rule not in t.san

    def apply_hit(self, t: Taint, hit: Hit, hop: tuple, interproc: bool = False) -> None:
        if hit.rule in t.san:
            return
        if hit.needs_built and not t.built and not t.params:
            return
        steps = (*t.steps, *hop, *hit.steps)
        if t.src is not None and (not hit.needs_built or t.built):
            self.emit(t.src, hit, steps, interproc)
        if t.params:
            rec = replace(hit, needs_built=hit.needs_built and not t.built, steps=_cap(steps))
            if interproc:
                rec = replace(rec, conf=min(rec.conf, 0.7))
            for p in t.params:
                lst = self.psinks.setdefault(p, [])
                if len(lst) < MAX_HITS_PER_PARAM and all(
                    (h.rule, h.sink) != (rec.rule, rec.sink) for h in lst
                ):
                    lst.append(rec)

    def emit(self, src: Src, hit: Hit, steps: tuple, interproc: bool) -> None:
        sev = hit.severity
        conf = hit.conf
        if interproc:
            conf = min(conf, 0.7)
        if src.weak:
            sev = _SEV_DOWN[sev]
            conf = round(conf * 0.6, 2)
        title = RULES.get(hit.rule, ("", sev, hit.rule))[2]
        via = f" via {hit.via}()" if hit.via else ""
        msg = f"{src.label} → {hit.label}{via} ({title})"
        if len(msg) > 99:
            msg = msg[:96] + "..."
        # source location of the original taint; sink is the real sink
        full = _cap(steps)
        self.findings.append(
            Finding(
                id=finding_id(hit.rule, hit.sink, src.loc),
                rule=hit.rule,
                cwe=hit.cwe,
                severity=sev,
                confidence=conf,
                message=msg,
                source=src.loc,
                sink=hit.sink,
                function=self.qual,
                path=list(full),
            )
        )

    def project_call(self, n, resolved, name, arg_ts, kw_ts, recv_t) -> Taint | None:
        eng = self.eng
        summ = eng.summ.get(resolved)
        if summ is None:
            return None
        pos = eng.pos_params(resolved)
        mapping: list[tuple[str, Taint]] = []
        for i, t in enumerate(arg_ts):
            if t is not None and i < len(pos) and not isinstance(n.args[i], ast.Starred):
                mapping.append((pos[i], t))
        for kn, t in kw_ts.items():
            if t is not None and kn is not None:
                mapping.append((kn, t))
        at = self.loc(n)
        short = resolved.rsplit(".", 1)[-1]
        hop = (self.step(at, f"passed to {short}(...)"),)
        for pname, t in mapping:
            for h in summ.psinks.get(pname, ()):
                if h.needs_built and not t.built:
                    continue
                h2 = replace(h, via=h.via or short)
                self.apply_hit(t, h2, hop, interproc=True)
        out = summ.ret_src
        for pname, t in mapping:
            r = summ.pret.get(pname)
            if r is None:
                continue
            san, built = r
            tt = replace(t, san=t.san | san, built=t.built or built)
            tt = self.with_step(tt, at, f"returned from {short}(...)")
            out = tmerge(out, tt)
        if out is not None and out is summ.ret_src:
            out = self.with_step(out, at, f"returned from {short}(...)")
        return out


def _cap(steps: tuple) -> tuple:
    if len(steps) <= MAX_PATH:
        return steps
    return (steps[0], *steps[-(MAX_PATH - 1) :])


def _ann_leaves(ann: ast.AST) -> set[str]:
    """Type names in an annotation, ignoring containers; Annotated keeps only its first arg."""
    out: set[str] = set()

    def walk(n: ast.AST) -> None:
        if isinstance(n, ast.Name):
            if n.id not in _CONTAINERS:
                out.add(n.id)
        elif isinstance(n, ast.Attribute):
            if n.attr not in _CONTAINERS:
                out.add(n.attr)
        elif isinstance(n, ast.Subscript):
            base = _chain(n.value).rpartition(".")[2]
            if base == "Literal":
                out.add("Literal")
            elif base == "Annotated":
                sl = n.slice
                walk(sl.elts[0] if isinstance(sl, ast.Tuple) and sl.elts else sl)
            else:
                walk(n.value)
                walk(n.slice)
        elif isinstance(n, ast.Tuple):
            for e in n.elts:
                walk(e)
        elif isinstance(n, ast.BinOp):
            walk(n.left)
            walk(n.right)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            try:
                walk(ast.parse(n.value, mode="eval").body)
            except SyntaxError:
                out.add(n.value)

    walk(ann)
    return out


def analyze(index: ProjectIndex) -> list[Finding]:
    """Run the taint analysis over the whole indexed project."""
    return Engine(index).run()
