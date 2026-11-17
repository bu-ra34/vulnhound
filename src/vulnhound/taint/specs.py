"""Declarative knowledge base for the taint engine: sources, sinks, sanitizers.

Pure data plus three lookup helpers; no analysis logic lives here.

Matching semantics
------------------
All names are *fully-qualified dotted names after import resolution*, e.g.
``from flask import request`` makes ``request.args.get`` resolve to
``flask.request.args.get``.

* Sinks (``match_sink``): a pattern is either an exact dotted name
  (``os.system``) or a wildcard suffix ``*.name`` that matches any call whose
  final attribute is ``name`` on an unknown receiver (``cursor.execute``,
  ``self.db.execute``). Exact matches win: if any exact pattern matches, only
  exact matches are returned; wildcards are a fallback for unresolved receivers.
* Sources (``match_source``): a pattern matches the name itself or any longer
  attribute chain that extends it (``flask.request.args`` matches
  ``flask.request.args.get``). The longest matching pattern wins.
* Sanitizers (``is_sanitizer``): exact or ``*.name`` wildcard, and the call
  must cover the rule (``"*"`` in ``Sanitizer.rules`` covers every rule).

Sink fields: ``arg_positions`` are 0-based positional indices that are
dangerous; ``kwarg_names`` are dangerous keyword arguments. If
``requires_kwarg`` is non-empty the sink only applies when every listed
keyword is present with that literal value. If ``safe_kwarg_values`` is
non-empty the sink does NOT apply when the keyword's value (dotted name) is in
the listed tuple (e.g. ``yaml.load(..., Loader=yaml.SafeLoader)``); absence of
the keyword means unsafe.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vulnhound.models import Severity


@dataclass(frozen=True)
class Source:
    pattern: str
    kind: str
    note: str = ""
    weak: bool = False  # low-trust input (environment); engine may downgrade severity


@dataclass(frozen=True)
class Sink:
    pattern: str
    rule: str
    cwe: str
    severity: Severity
    arg_positions: tuple[int, ...] = (0,)
    kwarg_names: tuple[str, ...] = ()
    note: str = ""
    requires_kwarg: dict = field(default_factory=dict, hash=False)
    safe_kwarg_values: dict = field(default_factory=dict, hash=False)


@dataclass(frozen=True)
class Sanitizer:
    pattern: str
    rules: tuple[str, ...]
    note: str = ""


# rule id -> (cwe, default severity, short title)
RULES: dict[str, tuple[str, Severity, str]] = {
    "sqli": ("CWE-89", Severity.HIGH, "SQL injection"),
    "cmdi": ("CWE-78", Severity.CRITICAL, "OS command injection"),
    "code-exec": ("CWE-95", Severity.CRITICAL, "Dynamic code evaluation"),
    "ssti": ("CWE-1336", Severity.HIGH, "Server-side template injection"),
    "ssrf": ("CWE-918", Severity.MEDIUM, "Server-side request forgery"),
    "path-traversal": ("CWE-22", Severity.HIGH, "Path traversal"),
    "deserialization": ("CWE-502", Severity.CRITICAL, "Unsafe deserialization"),
    "open-redirect": ("CWE-601", Severity.LOW, "Open redirect"),
    "xss": ("CWE-79", Severity.MEDIUM, "Cross-site scripting"),
}

_C, _H, _M, _L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

# --------------------------------------------------------------------------- sources

SOURCES: tuple[Source, ...] = (
    Source("flask.request.args", "flask-request", "query string"),
    Source("flask.request.form", "flask-request", "form body"),
    Source("flask.request.values", "flask-request", "args + form"),
    Source("flask.request.cookies", "flask-request", "cookies"),
    Source("flask.request.headers", "flask-request", "HTTP headers"),
    Source("flask.request.data", "flask-request", "raw body"),
    Source(
        "flask.request.files", "flask-request", "uploaded files (filename is attacker-controlled)"
    ),
    Source("flask.request.json", "flask-request", "parsed JSON body"),
    Source("flask.request.get_json", "flask-request", "parsed JSON body"),
    Source("flask.request.get_data", "flask-request", "raw body"),
    Source("flask.request.view_args", "flask-request", "URL converters"),
    Source("flask.request.path", "flask-request", "URL path"),
    Source("flask.request.url", "flask-request", "full URL"),
    Source("django.http.HttpRequest.GET", "django-request", "query string"),
    Source("django.http.HttpRequest.POST", "django-request", "form body"),
    Source("django.http.HttpRequest.body", "django-request", "raw body"),
    Source("django.http.HttpRequest.COOKIES", "django-request", "cookies"),
    Source("django.http.HttpRequest.META", "django-request", "headers and environ"),
    Source("django.http.HttpRequest.FILES", "django-request", "uploaded files"),
    Source("django.http.HttpRequest.path", "django-request", "URL path"),
    # Django views receive `request` as first param; engine marks it tainted and uses attrs below.
    Source("rest_framework.request.Request.data", "django-request", "DRF parsed body"),
    Source("rest_framework.request.Request.query_params", "django-request", "DRF query string"),
    Source(
        "werkzeug.datastructures.FileStorage.filename",
        "flask-request",
        "client-supplied upload filename (attacker-controlled)",
    ),
    Source("request", "django-request-param", "first parameter of a Django view function"),
    Source("fastapi.param", "fastapi-param", "route function parameters of fastapi routes"),
    Source("fastapi.Request.query_params", "fastapi-param", "starlette request"),
    Source("fastapi.Request.json", "fastapi-param", "starlette request body"),
    Source("fastapi.Request.body", "fastapi-param", "starlette request body"),
    Source("fastapi.Request.headers", "fastapi-param", "starlette request headers"),
    Source("fastapi.Request.cookies", "fastapi-param", "starlette request cookies"),
    Source("sys.argv", "argv", "command line arguments"),
    Source("input", "stdin", "interactive input"),
    Source("sys.stdin", "stdin", "standard input"),
    Source("os.environ", "env", "environment variable (low trust)", weak=True),
    Source("os.getenv", "env", "environment variable (low trust)", weak=True),
)

# Attributes of a Django request parameter that carry user data.
DJANGO_REQUEST_ATTRS: frozenset[str] = frozenset(
    {
        "GET",
        "POST",
        "body",
        "COOKIES",
        "META",
        "FILES",
        "path",
        "path_info",
        "headers",
        "data",
        "query_params",
    }
)
# Django REST Framework request attributes carrying user data (engine reads via getattr).
DRF_REQUEST_ATTRS: tuple[str, ...] = ("data", "query_params")

# Tornado: handler base classes and methods whose return value is user input.
TORNADO_HANDLER_BASES: tuple[str, ...] = ("tornado.web.RequestHandler",)
TORNADO_ARG_METHODS: tuple[str, ...] = (
    "get_argument",
    "get_arguments",
    "get_query_argument",
    "get_query_arguments",
    "get_body_argument",
    "get_body_arguments",
)

# Decorator suffixes marking FastAPI / Starlette routes (receiver is FastAPI or APIRouter).
FASTAPI_ROUTE_DECORATORS: frozenset[str] = frozenset(
    {"get", "post", "put", "delete", "patch", "api_route", "options", "head"}
)
FASTAPI_APP_CLASSES: frozenset[str] = frozenset(
    {
        "fastapi.FastAPI",
        "fastapi.APIRouter",
        "fastapi.applications.FastAPI",
        "fastapi.routing.APIRouter",
    }
)
# Flask route decorators (suffixes) that make function parameters URL-controlled.
FLASK_ROUTE_DECORATORS: frozenset[str] = frozenset(
    {"route", "get", "post", "put", "delete", "patch"}
)

# --------------------------------------------------------------------------- sinks

_SQL_NOTE = (
    "dangerous only when arg 0 is built by string formatting (f-string, %, +, .format); "
    "parameterized tuple/dict args are safe"
)


def _sql(pattern: str, sev: Severity = _H, note: str = _SQL_NOTE) -> Sink:
    return Sink(pattern, "sqli", "CWE-89", sev, (0,), ("sql", "query", "statement"), note)


_SUBPROC = ("run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput")


def _build_sinks() -> tuple[Sink, ...]:
    s: list[Sink] = []
    # --- sqli
    s += [
        _sql("*.execute"),
        _sql("*.executemany"),
        _sql("*.executescript"),
        _sql("sqlalchemy.text", _H, "raw SQL fragment; dangerous when built by string formatting"),
        _sql(
            "sqlalchemy.sql.text", _H, "raw SQL fragment; dangerous when built by string formatting"
        ),
        _sql(
            "sqlalchemy.sql.expression.text",
            _H,
            "raw SQL fragment; dangerous when built by string formatting",
        ),
        _sql(
            "*.raw",
            _M,
            "Django Manager.raw(); wildcard receiver, many false positives (e.g. non-ORM .raw)",
        ),
        _sql(
            "*.extra",
            _M,
            "Django QuerySet.extra(); dangerous in where=/select=/tables= string args",
        ),
        _sql(
            "django.db.models.expressions.RawSQL",
            _H,
            "RawSQL(sql, params): arg 0 string formatting is unsafe",
        ),
        _sql(
            "django.db.models.RawSQL", _H, "RawSQL(sql, params): arg 0 string formatting is unsafe"
        ),
        _sql("django.db.connection.cursor.execute", _H),
        _sql("pandas.read_sql", _M, "string query built by formatting is unsafe"),
        _sql("pandas.read_sql_query", _M, "string query built by formatting is unsafe"),
    ]
    # --- cmdi
    for fn in ("os.system", "os.popen", "commands.getoutput", "pty.spawn"):
        s.append(Sink(fn, "cmdi", "CWE-78", _C, (0,), ("command", "cmd"), "shell command string"))
    for fn in _SUBPROC:
        p = f"subprocess.{fn}"
        s.append(
            Sink(
                p,
                "cmdi",
                "CWE-78",
                _C,
                (0,),
                ("args", "cmd"),
                "shell=True: tainted command string is injectable",
                requires_kwarg={"shell": True},
            )
        )
        s.append(
            Sink(
                p,
                "cmdi",
                "CWE-78",
                _M,
                (0,),
                ("args",),
                "list argv without shell: argument injection / controlled binary only; medium",
            )
        )
    for fn in (
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.spawnl",
        "os.spawnv",
        "os.spawnlp",
        "os.spawnvp",
    ):
        s.append(
            Sink(
                fn,
                "cmdi",
                "CWE-78",
                _H,
                (0, 1),
                (),
                "process replacement/spawn with tainted path or argv",
            )
        )
    s.append(
        Sink(
            "asyncio.create_subprocess_shell",
            "cmdi",
            "CWE-78",
            _C,
            (0,),
            ("cmd",),
            "shell command string",
        )
    )
    s.append(
        Sink(
            "asyncio.create_subprocess_exec",
            "cmdi",
            "CWE-78",
            _M,
            (0,),
            (),
            "argv without shell; medium",
        )
    )
    # --- code-exec
    for fn in ("eval", "exec", "compile"):
        s.append(
            Sink(fn, "code-exec", "CWE-95", _C, (0,), ("source",), f"{fn}() of tainted string")
        )
    s.append(Sink("builtins.eval", "code-exec", "CWE-95", _C, (0,), (), "eval of tainted string"))
    s.append(Sink("builtins.exec", "code-exec", "CWE-95", _C, (0,), (), "exec of tainted string"))
    s.append(
        Sink(
            "importlib.import_module",
            "code-exec",
            "CWE-94",
            _H,
            (0,),
            ("name",),
            "attacker-chosen module import",
        )
    )
    s.append(
        Sink("__import__", "code-exec", "CWE-94", _H, (0,), (), "attacker-chosen module import")
    )
    # --- ssti
    s += [
        Sink(
            "flask.render_template_string",
            "ssti",
            "CWE-1336",
            _H,
            (0,),
            ("source",),
            "template source must not be tainted",
        ),
        Sink(
            "jinja2.Template",
            "ssti",
            "CWE-1336",
            _H,
            (0,),
            ("source",),
            "template source must not be tainted",
        ),
        Sink(
            "jinja2.Environment.from_string",
            "ssti",
            "CWE-1336",
            _H,
            (0,),
            ("source",),
            "template source must not be tainted",
        ),
        Sink(
            "*.from_string",
            "ssti",
            "CWE-1336",
            _M,
            (0,),
            ("source",),
            "jinja2 Environment.from_string on unresolved receiver",
        ),
        Sink(
            "mako.template.Template",
            "ssti",
            "CWE-1336",
            _H,
            (0,),
            ("text",),
            "template source must not be tainted",
        ),
        Sink(
            "django.template.Template",
            "ssti",
            "CWE-1336",
            _M,
            (0,),
            ("template_string",),
            "template source must not be tainted",
        ),
    ]
    # --- ssrf
    for m in ("get", "post", "put", "delete", "patch", "head", "options", "request"):
        pos = (1,) if m == "request" else (0,)
        s.append(
            Sink(
                f"requests.{m}",
                "ssrf",
                "CWE-918",
                _M,
                pos,
                ("url",),
                "tainted URL (host/scheme control)",
            )
        )
        s.append(
            Sink(
                f"httpx.{m}",
                "ssrf",
                "CWE-918",
                _M,
                pos,
                ("url",),
                "tainted URL (host/scheme control)",
            )
        )
        s.append(Sink(f"requests.Session.{m}", "ssrf", "CWE-918", _M, pos, ("url",), "tainted URL"))
        s.append(Sink(f"httpx.Client.{m}", "ssrf", "CWE-918", _M, pos, ("url",), "tainted URL"))
        s.append(
            Sink(f"httpx.AsyncClient.{m}", "ssrf", "CWE-918", _M, pos, ("url",), "tainted URL")
        )
        s.append(
            Sink(f"aiohttp.ClientSession.{m}", "ssrf", "CWE-918", _M, pos, ("url",), "tainted URL")
        )
    s += [
        Sink(
            "urllib.request.urlopen",
            "ssrf",
            "CWE-918",
            _M,
            (0,),
            ("url",),
            "tainted URL; also file:// scheme",
        ),
        Sink("urllib.request.urlretrieve", "ssrf", "CWE-918", _M, (0,), ("url",), "tainted URL"),
        Sink("urllib.request.Request", "ssrf", "CWE-918", _M, (0,), ("url",), "tainted URL"),
        Sink("urllib3.PoolManager.request", "ssrf", "CWE-918", _M, (1,), ("url",), "tainted URL"),
        Sink("http.client.HTTPConnection", "ssrf", "CWE-918", _M, (0,), ("host",), "tainted host"),
        Sink("http.client.HTTPSConnection", "ssrf", "CWE-918", _M, (0,), ("host",), "tainted host"),
    ]
    # --- path traversal
    s += [
        Sink(
            "open",
            "path-traversal",
            "CWE-22",
            _H,
            (0,),
            ("file",),
            "tainted path; os.path.join(base, tainted) still escapes",
        ),
        Sink("io.open", "path-traversal", "CWE-22", _H, (0,), ("file",), "tainted path"),
        Sink(
            "pathlib.Path",
            "path-traversal",
            "CWE-22",
            _M,
            (0,),
            (),
            "tainted path component; sink when later opened/read",
        ),
        Sink(
            "pathlib.Path.open",
            "path-traversal",
            "CWE-22",
            _H,
            (),
            (),
            "receiver Path built from taint",
        ),
        Sink(
            "pathlib.Path.read_text",
            "path-traversal",
            "CWE-22",
            _H,
            (),
            (),
            "receiver Path built from taint",
        ),
        Sink(
            "pathlib.Path.read_bytes",
            "path-traversal",
            "CWE-22",
            _H,
            (),
            (),
            "receiver Path built from taint",
        ),
        Sink(
            "flask.send_file",
            "path-traversal",
            "CWE-22",
            _H,
            (0,),
            ("path_or_file",),
            "tainted path; arbitrary file read",
        ),
        Sink("shutil.copy", "path-traversal", "CWE-22", _M, (0, 1), (), "tainted src or dst"),
        Sink("shutil.copyfile", "path-traversal", "CWE-22", _M, (0, 1), (), "tainted src or dst"),
        Sink("shutil.copytree", "path-traversal", "CWE-22", _M, (0, 1), (), "tainted src or dst"),
        Sink("shutil.move", "path-traversal", "CWE-22", _M, (0, 1), (), "tainted src or dst"),
        Sink(
            "shutil.rmtree",
            "path-traversal",
            "CWE-22",
            _H,
            (0,),
            ("path",),
            "tainted path deletion",
        ),
        Sink("os.remove", "path-traversal", "CWE-22", _H, (0,), ("path",), "tainted path deletion"),
        Sink("os.unlink", "path-traversal", "CWE-22", _H, (0,), ("path",), "tainted path deletion"),
        Sink("os.rename", "path-traversal", "CWE-22", _M, (0, 1), (), "tainted src or dst"),
        Sink(
            "os.listdir",
            "path-traversal",
            "CWE-22",
            _M,
            (0,),
            ("path",),
            "tainted directory listing",
        ),
        Sink(
            "zipfile.ZipFile.extractall",
            "path-traversal",
            "CWE-22",
            _H,
            (0,),
            ("path",),
            "zip-slip: archive member names escape target dir; receiver archive from taint",
        ),
        Sink(
            "tarfile.TarFile.extractall",
            "path-traversal",
            "CWE-22",
            _H,
            (0,),
            ("path",),
            "tar-slip: archive from taint without filter='data'",
        ),
        Sink(
            "tarfile.open", "path-traversal", "CWE-22", _M, (0,), ("name",), "tainted archive path"
        ),
        Sink(
            "*.extractall",
            "path-traversal",
            "CWE-22",
            _M,
            (0,),
            ("path",),
            "zip/tar extractall on unresolved receiver; archive-slip when archive is untrusted",
        ),
    ]
    # --- deserialization
    for fn in (
        "pickle.loads",
        "pickle.load",
        "cPickle.loads",
        "cPickle.load",
        "_pickle.loads",
        "dill.loads",
        "dill.load",
        "cloudpickle.loads",
        "marshal.loads",
        "marshal.load",
        "jsonpickle.decode",
        "jsonpickle.unpickler.decode",
        "shelve.open",
        "pandas.read_pickle",
        "joblib.load",
        "torch.load",
    ):
        s.append(
            Sink(
                fn,
                "deserialization",
                "CWE-502",
                _C,
                (0,),
                ("data", "file", "filename"),
                "untrusted bytes/file reaches an unpickler",
            )
        )
    for fn in ("load", "load_all", "full_load_all", "unsafe_load", "unsafe_load_all"):
        sev = _C
        s.append(
            Sink(
                f"yaml.{fn}",
                "deserialization",
                "CWE-502",
                sev,
                (0,),
                ("stream",),
                "unsafe unless Loader is SafeLoader/CSafeLoader/BaseLoader",
                safe_kwarg_values={
                    "Loader": (
                        "yaml.SafeLoader",
                        "yaml.CSafeLoader",
                        "yaml.BaseLoader",
                        "yaml.CBaseLoader",
                    )
                }
                if fn in ("load", "load_all")
                else {},
            )
        )
    # --- open redirect
    s += [
        Sink(
            "flask.redirect",
            "open-redirect",
            "CWE-601",
            _L,
            (0,),
            ("location",),
            "tainted redirect target",
        ),
        Sink(
            "django.shortcuts.redirect",
            "open-redirect",
            "CWE-601",
            _L,
            (0,),
            ("to",),
            "tainted redirect target",
        ),
        Sink(
            "django.http.HttpResponseRedirect",
            "open-redirect",
            "CWE-601",
            _L,
            (0,),
            ("redirect_to",),
            "tainted redirect target",
        ),
        Sink(
            "fastapi.responses.RedirectResponse",
            "open-redirect",
            "CWE-601",
            _L,
            (0,),
            ("url",),
            "tainted redirect target",
        ),
        Sink(
            "starlette.responses.RedirectResponse",
            "open-redirect",
            "CWE-601",
            _L,
            (0,),
            ("url",),
            "tainted redirect target",
        ),
    ]
    # --- extra gaps: ssrf
    for cls in ("httpx.Client", "httpx.AsyncClient"):
        s.append(Sink(f"{cls}.build_request", "ssrf", "CWE-918", _M, (1,), ("url",), "tainted URL"))
        s.append(
            Sink(
                f"{cls}.send", "ssrf", "CWE-918", _M, (0,), ("request",), "request built from taint"
            )
        )
        s.append(Sink(f"{cls}.stream", "ssrf", "CWE-918", _M, (1,), ("url",), "tainted URL"))
    s += [
        Sink("httpx.stream", "ssrf", "CWE-918", _M, (1,), ("url",), "tainted URL"),
        Sink("httpx.Request", "ssrf", "CWE-918", _M, (1,), ("url",), "tainted URL"),
        Sink("requests.Request", "ssrf", "CWE-918", _M, (1,), ("url",), "tainted URL"),
        Sink("requests.models.Request", "ssrf", "CWE-918", _M, (1,), ("url",), "tainted URL"),
        Sink(
            "requests.Session.send",
            "ssrf",
            "CWE-918",
            _M,
            (0,),
            ("request",),
            "request built from taint",
        ),
        Sink(
            "requests.Session.prepare_request",
            "ssrf",
            "CWE-918",
            _M,
            (0,),
            ("request",),
            "request built from taint",
        ),
        Sink(
            "requests.PreparedRequest.prepare_url",
            "ssrf",
            "CWE-918",
            _M,
            (0,),
            ("url",),
            "tainted URL",
        ),
        Sink(
            "requests.models.PreparedRequest.prepare_url",
            "ssrf",
            "CWE-918",
            _M,
            (0,),
            ("url",),
            "tainted URL",
        ),
        Sink("urllib3.PoolManager.urlopen", "ssrf", "CWE-918", _M, (1,), ("url",), "tainted URL"),
        Sink("urllib3.request", "ssrf", "CWE-918", _M, (1,), ("url",), "tainted URL"),
        Sink(
            "urllib3.PoolManager.connection_from_url",
            "ssrf",
            "CWE-918",
            _M,
            (0,),
            ("url",),
            "tainted URL",
        ),
        Sink("urllib3.HTTPConnectionPool", "ssrf", "CWE-918", _M, (0,), ("host",), "tainted host"),
        Sink("urllib3.HTTPSConnectionPool", "ssrf", "CWE-918", _M, (0,), ("host",), "tainted host"),
        Sink("aiohttp.request", "ssrf", "CWE-918", _M, (1,), ("url",), "tainted URL"),
        Sink(
            "aiohttp.ClientSession.ws_connect", "ssrf", "CWE-918", _M, (0,), ("url",), "tainted URL"
        ),
        Sink(
            "urllib.request.OpenerDirector.open",
            "ssrf",
            "CWE-918",
            _M,
            (0,),
            ("fullurl",),
            "tainted URL",
        ),
        Sink(
            "http.client.HTTPConnection.putrequest",
            "ssrf",
            "CWE-918",
            _M,
            (1,),
            ("url",),
            "tainted request target",
        ),
    ]
    # --- extra gaps: path traversal
    s += [
        Sink(
            "werkzeug.datastructures.FileStorage.save",
            "path-traversal",
            "CWE-22",
            _H,
            (0,),
            ("dst",),
            "upload destination path built from taint",
        ),
        Sink(
            "flask.request.files[].save",
            "path-traversal",
            "CWE-22",
            _H,
            (0,),
            ("dst",),
            "upload destination path built from taint",
        ),
        Sink(
            "*.save",
            "path-traversal",
            "CWE-22",
            _M,
            (0,),
            ("dst",),
            "FileStorage.save on unresolved receiver; destination path",
        ),
        Sink(
            "starlette.responses.FileResponse",
            "path-traversal",
            "CWE-22",
            _H,
            (0,),
            ("path",),
            "tainted path; arbitrary file read",
        ),
        Sink(
            "fastapi.responses.FileResponse",
            "path-traversal",
            "CWE-22",
            _H,
            (0,),
            ("path",),
            "tainted path; arbitrary file read",
        ),
        Sink(
            "flask.helpers.send_file",
            "path-traversal",
            "CWE-22",
            _H,
            (0,),
            ("path_or_file",),
            "tainted path; arbitrary file read",
        ),
        Sink(
            "shutil.unpack_archive",
            "path-traversal",
            "CWE-22",
            _H,
            (0, 1),
            ("filename", "extract_dir"),
            "zip/tar-slip: untrusted archive or target dir",
        ),
        Sink(
            "zipfile.ZipFile.extract",
            "path-traversal",
            "CWE-22",
            _M,
            (0, 1),
            ("member", "path"),
            "tainted member name or target",
        ),
        Sink(
            "tarfile.TarFile.extract",
            "path-traversal",
            "CWE-22",
            _M,
            (0, 1),
            ("member", "path"),
            "tainted member name or target",
        ),
    ]
    # --- extra gaps: ssti / deserialization / redirect
    s += [
        Sink(
            "jinja2.environment.Template",
            "ssti",
            "CWE-1336",
            _H,
            (0,),
            ("source",),
            "template source must not be tainted",
        ),
        Sink(
            "jinja2.environment.Environment.from_string",
            "ssti",
            "CWE-1336",
            _H,
            (0,),
            ("source",),
            "template source must not be tainted",
        ),
        Sink(
            "tornado.template.Template",
            "ssti",
            "CWE-1336",
            _H,
            (0,),
            ("template_string",),
            "template source must not be tainted",
        ),
        Sink(
            "numpy.load",
            "deserialization",
            "CWE-502",
            _C,
            (0,),
            ("file",),
            "allow_pickle=True unpickles untrusted data",
            requires_kwarg={"allow_pickle": True},
        ),
        Sink(
            "pickle.Unpickler",
            "deserialization",
            "CWE-502",
            _C,
            (0,),
            ("file",),
            "untrusted stream reaches an unpickler",
        ),
        Sink(
            "_pickle.load",
            "deserialization",
            "CWE-502",
            _C,
            (0,),
            ("file",),
            "untrusted stream reaches an unpickler",
        ),
        Sink(
            "cloudpickle.load",
            "deserialization",
            "CWE-502",
            _C,
            (0,),
            ("file",),
            "untrusted stream reaches an unpickler",
        ),
        Sink(
            "joblib.numpy_pickle.load",
            "deserialization",
            "CWE-502",
            _C,
            (0,),
            ("filename",),
            "untrusted file reaches an unpickler",
        ),
        Sink(
            "tornado.web.RequestHandler.redirect",
            "open-redirect",
            "CWE-601",
            _L,
            (0,),
            ("url",),
            "tainted redirect target",
        ),
    ]
    return tuple(s)


SINKS: tuple[Sink, ...] = _build_sinks()

# --------------------------------------------------------------------------- sanitizers

_ALL = ("*",)
SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer("int", _ALL, "numeric coercion"),
    Sanitizer("float", _ALL, "numeric coercion"),
    Sanitizer("bool", _ALL, "boolean coercion"),
    Sanitizer("uuid.UUID", _ALL, "validated UUID"),
    Sanitizer("ipaddress.ip_address", ("ssrf", "cmdi", "sqli"), "validated IP"),
    Sanitizer("shlex.quote", ("cmdi",), "shell quoting"),
    Sanitizer("pipes.quote", ("cmdi",), "shell quoting"),
    Sanitizer("os.path.basename", ("path-traversal",), "strips directories"),
    Sanitizer("werkzeug.utils.secure_filename", ("path-traversal",), "normalizes filename"),
    Sanitizer(
        "flask.send_from_directory", ("path-traversal",), "confines path to a directory (safe-ish)"
    ),
    Sanitizer("markupsafe.escape", ("ssti", "xss"), "HTML escaping"),
    Sanitizer("markupsafe.Markup.escape", ("ssti", "xss"), "HTML escaping"),
    Sanitizer("html.escape", ("ssti", "xss"), "HTML escaping"),
    Sanitizer("flask.escape", ("ssti", "xss"), "HTML escaping"),
    Sanitizer("django.utils.html.escape", ("xss",), "HTML escaping"),
    Sanitizer("bleach.clean", ("xss",), "HTML sanitizer"),
    Sanitizer("ast.literal_eval", ("code-exec",), "literal-only evaluation"),
    Sanitizer("yaml.safe_load", ("deserialization",), "safe loader"),
    Sanitizer("yaml.safe_load_all", ("deserialization",), "safe loader"),
    Sanitizer("json.loads", ("deserialization",), "data-only format"),
    Sanitizer(
        "django.utils.http.url_has_allowed_host_and_scheme",
        ("open-redirect",),
        "host allow-list check",
    ),
    Sanitizer("flask.url_for", ("open-redirect",), "internal endpoint"),
    Sanitizer("django.urls.reverse", ("open-redirect",), "internal endpoint"),
)
# urllib.parse.quote deliberately absent: it does NOT sanitize ssrf, sqli or others.

# --------------------------------------------------------------------------- lookups

_SINK_EXACT: dict[str, list[Sink]] = {}
_SINK_WILD: dict[str, list[Sink]] = {}
for _s in SINKS:
    if _s.pattern.startswith("*."):
        _SINK_WILD.setdefault(_s.pattern[2:], []).append(_s)
    else:
        _SINK_EXACT.setdefault(_s.pattern, []).append(_s)

_SOURCE_BY_PATTERN: dict[str, Source] = {s.pattern: s for s in SOURCES}


def match_sink(qualified_call: str) -> list[Sink]:
    """Sinks for a call's qualified name; exact matches take priority over ``*.name``."""
    exact = _SINK_EXACT.get(qualified_call)
    if exact:
        return list(exact)
    last = qualified_call.rsplit(".", 1)[-1]
    if "." in qualified_call:
        return list(_SINK_WILD.get(last, ()))
    return []


def match_source(dotted: str) -> Source | None:
    """Source whose pattern equals ``dotted`` or is its longest attribute-chain prefix."""
    parts = dotted.split(".")
    for n in range(len(parts), 0, -1):
        src = _SOURCE_BY_PATTERN.get(".".join(parts[:n]))
        if src is not None:
            return src
    return None


def is_sanitizer(qualified_call: str, rule: str) -> bool:
    """True if calling ``qualified_call`` neutralizes taint for ``rule``."""
    last = qualified_call.rsplit(".", 1)[-1]
    for san in SANITIZERS:
        if san.pattern == qualified_call or (
            san.pattern.startswith("*.") and "." in qualified_call and san.pattern[2:] == last
        ):
            if "*" in san.rules or rule in san.rules:
                return True
    return False
