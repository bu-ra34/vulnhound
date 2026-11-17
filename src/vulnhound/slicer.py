"""Minimal, judge-ready code slices for findings.

``vulnhound slice <id>`` prints only what is needed to decide whether a
finding is real: the def lines, the path-step lines, the assignments feeding
the tainted names, guards (if/assert with early exit) and a little context
around the sink. Never whole files.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .index import ProjectIndex, build_index
from .models import Finding, Location
from .store import load_findings

_MAX_COL = 200
_EXPECT_RE = re.compile(r"\s*#\s*VH-EXPECT:.*$")
_MAX_STMT_LINES = 6
_FUNC = (ast.FunctionDef, ast.AsyncFunctionDef)
_BODY_FIELDS = ("body", "orelse", "finalbody", "handlers", "cases")


@dataclass
class _Group:
    path: str
    qualname: str  # "<module>" for module-level code
    first_step: int
    lines: dict[int, int] = field(default_factory=dict)  # lineno -> priority (0 = mandatory)
    step_lines: set[int] = field(default_factory=set)
    guard_lines: set[int] = field(default_factory=set)


def _sig_last(node: ast.AST) -> int:
    """Last line of a def signature (not comments/blank lines before the body)."""
    assert isinstance(node, _FUNC)
    ends = [node.lineno]
    ends += [getattr(n, "end_lineno", None) or node.lineno for n in ast.walk(node.args)]
    if node.returns is not None:
        ends.append(node.returns.end_lineno or node.lineno)
    last = max(ends)
    if last > node.lineno:  # multi-line signature: closing paren line
        last += 1
    return min(last, node.body[0].lineno - 1 if node.body else last)


def _header_span(node: ast.stmt) -> tuple[int, int]:
    """Lines of a statement; for compound statements only the header."""
    if isinstance(node, ast.match_case):  # no lineno of its own (Python 3.10+)
        return node.pattern.lineno, max(node.pattern.end_lineno or 0, node.pattern.lineno)
    start = node.lineno
    if isinstance(node, _FUNC + (ast.ClassDef,)) and node.decorator_list:
        start = min(d.lineno for d in node.decorator_list)
    end = node.end_lineno or node.lineno
    if isinstance(node, _FUNC):
        return start, max(_sig_last(node), node.lineno)
    for f in _BODY_FIELDS:
        body = getattr(node, f, None)
        if isinstance(body, list) and body:
            end = min(end, (getattr(body[0], "lineno", None) or body[0].pattern.lineno) - 1)
    end = max(end, node.lineno)
    return start, min(end, start + _MAX_STMT_LINES - 1)


def _names(node: ast.stmt) -> set[str]:
    out: set[str] = set()
    if any(hasattr(node, f) and getattr(node, f) for f in _BODY_FIELDS):
        parts = [c for c in ast.iter_child_nodes(node) if not isinstance(c, ast.stmt)]
        parts = [p for p in parts if not isinstance(p, (ast.ExceptHandler, ast.match_case))]
    else:
        parts = [node]
    for p in parts:
        for n in ast.walk(p):
            if isinstance(n, ast.Name):
                out.add(n.id)
    return out


def _targets(node: ast.stmt) -> set[str]:
    tg: list[ast.AST] = []
    if isinstance(node, ast.Assign):
        tg = list(node.targets)
    elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
        tg = [node.target]
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        tg = [node.target]
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        tg = [i.optional_vars for i in node.items if i.optional_vars is not None]
    out: set[str] = set()
    for t in tg:
        for n in ast.walk(t):
            if isinstance(n, ast.Name):
                out.add(n.id)
    return out


_GUARD_CALL_RE = re.compile(
    r"^(validate|check|ensure|verify|is_safe|is_valid|is_allowed|is_trusted|is_local)|"
    r"(^|_)(validate|validator|sanitize|is_safe_url|url_has_allowed_host)",
    re.I,
)


def _call_name(call: ast.Call) -> str:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _guard_parts(node: ast.stmt) -> list[ast.AST]:
    if isinstance(node, (ast.If, ast.While, ast.Assert)):
        return [node.test]
    if isinstance(node, (ast.Expr, ast.Assign, ast.AnnAssign, ast.Return)):
        return [node]
    return []


def _is_guard(node: ast.stmt, names: set[str]) -> bool:
    """A check on a tracked name: validate_*()/check_*()/ensure_*() call, ``.startswith``,
    or ``in ALLOWED_*``, whose arguments/subject mention a tracked name."""
    for part in _guard_parts(node):
        for n in ast.walk(part):
            if isinstance(n, ast.Call):
                nm = _call_name(n)
                if nm == "startswith" or _GUARD_CALL_RE.search(nm):
                    used = {
                        x.id
                        for a in [*n.args, *[k.value for k in n.keywords]]
                        for x in ast.walk(a)
                        if isinstance(x, ast.Name)
                    }
                    if isinstance(n.func, ast.Attribute):
                        used |= {x.id for x in ast.walk(n.func.value) if isinstance(x, ast.Name)}
                    if used & names:
                        return True
            elif isinstance(n, ast.Compare) and any(
                isinstance(o, (ast.In, ast.NotIn)) for o in n.ops
            ):
                comp = [
                    x
                    for c in n.comparators
                    for x in ast.walk(c)
                    if isinstance(x, (ast.Name, ast.Attribute))
                ]
                if any(
                    re.search(
                        r"allow|safe|valid|whitelist|trusted",
                        getattr(c, "id", getattr(c, "attr", "")),
                        re.I,
                    )
                    for c in comp
                ):
                    left = {x.id for x in ast.walk(n.left) if isinstance(x, ast.Name)}
                    if left & names:
                        return True
    return False


def _exits(node: ast.If) -> ast.stmt | None:
    for s in node.body:
        if isinstance(s, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return s
    return None


def _function_node(tree: ast.Module, line: int, end: int) -> ast.AST | None:
    for n in ast.walk(tree):
        if isinstance(n, _FUNC) and n.end_lineno == end:
            start = min([n.lineno] + [d.lineno for d in n.decorator_list])
            if line in (n.lineno, start):
                return n
    return None


def _parents(root: ast.AST) -> dict[ast.AST, ast.AST]:
    return {c: p for p in ast.walk(root) for c in ast.iter_child_nodes(p)}


def _innermost_stmt(root: ast.AST, line: int) -> ast.stmt | None:
    best, size = None, 10**9
    for n in ast.walk(root):
        if not isinstance(n, ast.stmt) or n is root:
            continue
        s, e = _header_span(n)
        if s <= line <= e and (e - s) < size:
            best, size = n, e - s
    return best


def _sig_end(fn: ast.AST) -> int:
    return max(_sig_last(fn), fn.lineno)  # type: ignore[arg-type]


def _flatten(locs: list[Location]) -> list[Location]:
    seen, out = set(), []
    for loc in locs:
        k = (loc.path, loc.line)
        if k not in seen:
            seen.add(k)
            out.append(loc)
    return out


def build_slice(
    index: ProjectIndex, finding: Finding, context: int = 1, max_lines: int = 80
) -> str:
    header = (
        f"{finding.id} {finding.rule} {finding.cwe} "
        f"{finding.severity.value} conf={finding.confidence:g}"
    )
    steps = [s.location for s in finding.path]
    locs = _flatten([finding.source, *steps, finding.sink])
    sink_key = (finding.sink.path, finding.sink.line)
    src_key = (finding.source.path, finding.source.line)
    path_to_mod = {m.path: n for n, m in index.modules.items()}

    warn = False
    for st in finding.path:
        mod = path_to_mod.get(st.location.path)
        try:
            text = index.source_lines(mod)[st.location.line - 1] if mod else None
        except (OSError, IndexError):
            text = None
        want = st.code.strip()
        if text is None or not (want == text.strip() or want in text or text.strip() in want):
            warn = True

    groups: dict[tuple[str, str], _Group] = {}
    fn_nodes: dict[tuple[str, str], ast.AST | None] = {}
    trees: dict[str, ast.Module | None] = {}
    lines_of: dict[str, list[str]] = {}

    def tree_of(path: str) -> ast.Module | None:
        if path not in trees:
            mod = path_to_mod.get(path)
            try:
                trees[path] = index.ast_for(mod) if mod else None
            except (SyntaxError, OSError, ValueError):
                trees[path] = None
            try:
                lines_of[path] = index.source_lines(mod) if mod else []
            except OSError:
                lines_of[path] = []
        return trees[path]

    for i, loc in enumerate(locs):
        tree_of(loc.path)
        cands = [
            f
            for f in index.functions.values()
            if f.location.path == loc.path and f.location.line <= loc.line <= f.end_line
        ]
        fi = max(cands, key=lambda f: (f.location.line, -f.end_line), default=None)
        key = (loc.path, fi.qualname if fi else "<module>")
        g = groups.setdefault(key, _Group(loc.path, key[1], i))
        if key not in fn_nodes:
            t = trees[loc.path]
            fn_nodes[key] = _function_node(t, fi.location.line, fi.end_line) if (fi and t) else None
        g.lines[loc.line] = 0
        g.step_lines.add(loc.line)

    sink_group_key = None
    for key, g in groups.items():
        if finding.sink.path == g.path and finding.sink.line in g.step_lines:
            sink_group_key = key

    for key, g in groups.items():
        tree = trees[g.path]
        fn = fn_nodes[key]
        scope = fn if fn is not None else tree
        if tree is None:
            continue
        is_sink_grp = key == sink_group_key
        sink_line = finding.sink.line if is_sink_grp else max(g.step_lines)
        if fn is not None:
            s = min([fn.lineno] + [d.lineno for d in fn.decorator_list])
            for ln in range(s, _sig_end(fn) + 1):
                g.lines[ln] = 0
        stmts = [n for n in ast.walk(scope) if isinstance(n, ast.stmt) and n is not scope]
        parents = _parents(scope)
        # statements of the steps
        step_stmts = [x for ln in g.step_lines if (x := _innermost_stmt(scope, ln))]
        for st in step_stmts:
            a, b = _header_span(st)
            for ln in range(a, b + 1):
                g.lines[ln] = 0
        names: set[str] = set()
        for st in step_stmts:
            names |= _names(st)
        last = max(g.step_lines)
        # data flow into the tracked names (two rounds)
        for _ in range(2):
            new: set[str] = set()
            for st in stmts:
                if st.lineno <= last and _targets(st) & names:
                    a, b = _header_span(st)
                    for ln in range(a, b + 1):
                        g.lines.setdefault(ln, 1)
                    new |= _names(st)
            names |= new
        # enclosing control-flow headers (guards the sink sits under)
        for st in step_stmts:
            p = parents.get(st)
            while p is not None and p is not scope:
                if isinstance(p, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.With, ast.Try)):
                    a, b = _header_span(p)
                    for ln in range(a, b + 1):
                        g.lines.setdefault(ln, 1)
                p = parents.get(p)
        # guard clauses and asserts earlier in the function
        for st in stmts:
            if st.lineno >= last:
                continue
            if isinstance(st, ast.If) and _exits(st) and _names(st) & names:
                a, b = _header_span(st)
                for ln in range(a, b + 1):
                    g.lines.setdefault(ln, 1)
                g.lines.setdefault(_exits(st).lineno, 1)  # type: ignore[union-attr]
            elif isinstance(st, ast.Assert) and _names(st) & names:
                a, b = _header_span(st)
                for ln in range(a, b + 1):
                    g.lines.setdefault(ln, 1)
        # guards on tracked names between source and sink: never elided, flagged for judging
        for st in stmts:
            if st.lineno <= last and _is_guard(st, names):
                a, b = _header_span(st)
                for ln in range(a, b + 1):
                    g.lines[ln] = 0
                g.guard_lines.add(st.lineno)
        if is_sink_grp:
            lo = fn.lineno if fn is not None else 1
            hi = (fn.end_lineno or sink_line) if fn is not None else len(lines_of[g.path])
            for ln in range(max(lo, sink_line - context), min(hi, sink_line + context) + 1):
                g.lines.setdefault(ln, 1)
            # imports that disambiguate the sink call
            sink_stmt = _innermost_stmt(scope, sink_line)
            if sink_stmt is not None:
                heads = _names(sink_stmt)
                for n in tree.body:
                    if isinstance(n, (ast.Import, ast.ImportFrom)):
                        bound = {(a.asname or a.name).split(".")[0] for a in n.names}
                        if bound & heads:
                            for ln in range(n.lineno, (n.end_lineno or n.lineno) + 1):
                                g.lines.setdefault(ln, 1)

    # ---- render, enforcing the cap -------------------------------------------------
    def render(drop: set[tuple[tuple[str, str], int]]) -> list[str]:
        out: list[str] = []
        ordered = sorted(groups.items(), key=lambda kv: kv[1].first_step)
        # sink group last, as the path ends there
        ordered.sort(key=lambda kv: kv[0] == sink_group_key)
        for key, g in ordered:
            src = lines_of.get(g.path, [])
            out.append(f"# {g.path} :: {g.qualname}")
            prev = None
            kept = sorted(ln for ln in g.lines if (key, ln) not in drop and 1 <= ln <= len(src))
            for ln in kept:
                if prev is not None and ln > prev + 1:
                    if any(src[k - 1].strip() for k in range(prev + 1, ln)):
                        out.append("   …")
                prev = ln
                text = _EXPECT_RE.sub("", src[ln - 1]).rstrip()
                if len(text) > _MAX_COL:
                    text = text[: _MAX_COL - 1] + "…"
                mark = ""
                if (g.path, ln) == src_key:
                    mark += "  ◀ source"
                if (g.path, ln) == sink_key:
                    mark += "  ◀ sink"
                if ln in g.guard_lines:
                    mark += "  ◀ guard?"
                out.append(f"{ln:>4}| {text}{mark}")
        return out

    budget = max(1, max_lines - 1 - (1 if warn else 0))
    drop: set[tuple[tuple[str, str], int]] = set()
    body = render(drop)
    if len(body) > budget:
        sink_ln = finding.sink.line
        optional = [
            (key, ln, g.lines[ln]) for key, g in groups.items() for ln in g.lines if g.lines[ln] > 0
        ]

        def dist(item: tuple[tuple[str, str], int, int]) -> int:
            key, ln, _ = item
            same = key == sink_group_key
            return abs(ln - sink_ln) if same else 10_000 + abs(ln - sink_ln)

        optional.sort(key=dist, reverse=True)
        for key, ln, _ in optional:
            drop.add((key, ln))
            body = render(drop)
            if len(body) <= budget:
                break
    if len(body) > budget:  # mandatory lines alone exceed the cap
        body = body[: budget - 1] + ["   … (truncated)"]

    out = [header]
    if warn:
        out.append("! file changed since analyze; re-run vulnhound analyze")
    return "\n".join(out + body) + "\n"


def run(root: Path, finding_id: str, *, max_lines: int = 80) -> int:
    root = Path(root)
    try:
        findings, _ = load_findings(root)
    except FileNotFoundError:
        print("no analysis found; run `vulnhound analyze` first", file=sys.stderr)
        return 2
    finding = next((f for f in findings if f.id == finding_id), None)
    if finding is None:
        print(f"unknown finding id: {finding_id}", file=sys.stderr)
        return 2
    index = build_index(root)
    sys.stdout.write(build_slice(index, finding, max_lines=max_lines))
    return 0
