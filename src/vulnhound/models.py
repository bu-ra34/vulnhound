"""Shared data model. Every module exchanges these types; keep them stable.

All types are plain dataclasses with a ``to_dict()`` that produces JSON-safe
output, because the CLI's JSON output is the contract the Claude skill reads.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Location:
    path: str  # POSIX path relative to the project root
    line: int  # 1-based
    col: int = 0  # 0-based, as in ast

    def __str__(self) -> str:
        return f"{self.path}:{self.line}"


@dataclass
class FunctionInfo:
    """One function or method found by the indexer."""

    qualname: str  # "pkg.module.Class.method", unique key in the index
    module: str  # "pkg.module"
    name: str
    location: Location
    end_line: int
    params: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)  # dotted source text, e.g. "app.route"
    # resolved qualnames when known, else raw dotted names
    calls: list[str] = field(default_factory=list)
    is_method: bool = False


@dataclass
class ModuleInfo:
    name: str  # dotted module name
    path: str  # relative POSIX path
    sha256: str
    imports: dict[str, str] = field(default_factory=dict)  # local alias -> fully dotted target
    functions: list[str] = field(default_factory=list)  # qualnames
    parse_error: str | None = None


@dataclass
class Step:
    """One hop of a taint path, from source towards sink."""

    location: Location
    code: str  # the source line, stripped
    note: str  # e.g. "source: request.args", "assigned to q", "passed to run_query(q)"


@dataclass
class Finding:
    id: str  # stable short hash, e.g. "VH-3f9a1c"
    # e.g. "sqli", "cmdi", "ssti", "ssrf", "path-traversal", "deserialization", "code-exec"
    rule: str
    cwe: str  # e.g. "CWE-89"
    severity: Severity
    confidence: float  # 0.0 - 1.0, how sure the static engine is
    message: str
    source: Location
    sink: Location
    function: str  # qualname of the function containing the sink
    path: list[Step] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
