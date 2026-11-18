"""Name resolution over the whole project (imports, re-exports, methods)."""

from __future__ import annotations

from ..models import FunctionInfo, ModuleInfo

# Compat-shim module prefixes -> real stdlib names (longest prefix wins).
COMPAT_PREFIXES: dict[str, str] = {
    "six.moves.urllib.request": "urllib.request",
    "six.moves.urllib.parse": "urllib.parse",
    "six.moves.urllib.error": "urllib.error",
    "six.moves.urllib.response": "urllib.response",
    "six.moves.urllib_parse": "urllib.parse",
    "six.moves.urllib_request": "urllib.request",
    "six.moves.urllib_error": "urllib.error",
    "six.moves.urllib": "urllib",
    "six.moves.http_client": "http.client",
    "six.moves.http_cookies": "http.cookies",
    "six.moves.http_cookiejar": "http.cookiejar",
    "six.moves.BaseHTTPServer": "http.server",
    "six.moves.SimpleHTTPServer": "http.server",
    "six.moves.CGIHTTPServer": "http.server",
    "six.moves.cPickle": "pickle",
    "six.moves.configparser": "configparser",
    "six.moves.queue": "queue",
    "six.moves.builtins": "builtins",
    "six.moves.socketserver": "socketserver",
    "six.moves.html_parser": "html.parser",
    "six.moves.html_entities": "html.entities",
    "six.moves.xmlrpc_client": "xmlrpc.client",
    "six.moves.xmlrpc_server": "xmlrpc.server",
    "six.moves.reprlib": "reprlib",
    "six.moves.copyreg": "copyreg",
    "six.moves.shlex_quote": "shlex.quote",
    "six.moves.getcwd": "os.getcwd",
    "six.moves.input": "input",
    "six.moves.zip": "zip",
    "six.moves.map": "map",
    "six.moves.range": "range",
    "future.moves.urllib.request": "urllib.request",
    "future.moves.urllib.parse": "urllib.parse",
    "future.moves.urllib.error": "urllib.error",
    "future.moves.urllib": "urllib",
    "future.moves.http.client": "http.client",
    "future.moves.http.server": "http.server",
    "future.moves.http.cookies": "http.cookies",
    "future.moves.http.cookiejar": "http.cookiejar",
    "future.moves.http": "http",
    "future.moves.pickle": "pickle",
    "future.moves.configparser": "configparser",
    "future.moves.queue": "queue",
    "future.moves.builtins": "builtins",
    "future.moves.socketserver": "socketserver",
    "future.moves.xmlrpc": "xmlrpc",
    "future.builtins": "builtins",
    "past.builtins": "builtins",
}
_COMPAT_SORTED = sorted(COMPAT_PREFIXES.items(), key=lambda kv: -len(kv[0]))


def normalize_compat(name: str) -> str:
    """Map ``six.moves.*`` / ``future.moves.*`` names onto their stdlib equivalents."""
    if not name.startswith(("six.", "future.", "past.")):
        return name
    for pre, real in _COMPAT_SORTED:
        if name == pre:
            return real
        if name.startswith(pre + "."):
            return real + name[len(pre) :]
    return name


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
        return normalize_compat(self._follow(full))

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
