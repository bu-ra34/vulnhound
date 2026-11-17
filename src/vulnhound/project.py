"""Project discovery: which files to index and what module they are."""

from __future__ import annotations

import os
from pathlib import Path

SKIP_DIRS = frozenset(
    {
        "venv", "env", "node_modules", "__pycache__", "build", "dist",
        "site-packages", "__pypackages__",
    }
)  # fmt: skip


def _skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.startswith(".") or name.endswith(".egg-info")


def discover(root: Path) -> list[Path]:
    """Return all ``.py`` files under *root* (sorted), skipping vendored/hidden dirs."""
    root = Path(root)
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not _skip_dir(d))
        base = Path(dirpath)
        found.extend(base / f for f in sorted(filenames) if f.endswith(".py"))
    return found


def relative_posix(root: Path, path: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path.resolve().relative_to(root.resolve())
    return rel.as_posix()


def module_name_for(root: Path, path: Path) -> str:
    """Dotted module name for *path*. Handles ``src/`` layout and ``__init__.py``."""
    root = Path(root)
    parts = list(Path(relative_posix(root, path)).with_suffix("").parts)
    if len(parts) > 1 and parts[0] == "src" and not (root / "src" / "__init__.py").exists():
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts.pop()
    if not parts:
        return root.resolve().name or "root"
    return ".".join(parts)


def is_package_file(path: Path) -> bool:
    return Path(path).name == "__init__.py"
