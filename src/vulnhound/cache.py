"""On-disk JSON cache of per-module extraction results (never pickle)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from . import __version__

SCHEMA_VERSION = 1


class Cache:
    """Cache at ``<root>/.vulnhound/cache/``; entries keyed by content + version + schema."""

    def __init__(self, root: Path) -> None:
        self.dir = Path(root) / ".vulnhound" / "cache"
        self.used: set[str] = set()

    def _key(self, sha: str, module: str, path: str) -> str:
        raw = f"{__version__}|{SCHEMA_VERSION}|{sha}|{module}|{path}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def load(self, sha: str, module: str, path: str) -> dict | None:
        key = self._key(sha, module, path)
        try:
            data = json.loads((self.dir / f"{key}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if (
            not isinstance(data, dict)
            or data.get("schema") != SCHEMA_VERSION
            or data.get("version") != __version__
            or data.get("key") != key
            or not isinstance(data.get("module"), dict)
            or not isinstance(data.get("functions"), list)
            or not isinstance(data.get("classes"), dict)
        ):
            return None
        self.used.add(key)
        return data

    def store(self, sha: str, module: str, path: str, payload: dict) -> None:
        key = self._key(sha, module, path)
        entry = {"schema": SCHEMA_VERSION, "version": __version__, "key": key, **payload}
        tmp = self.dir / f"{key}.{os.getpid()}.tmp"
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            gi = self.dir.parent / ".gitignore"
            if not gi.exists():
                gi.write_text("*\n", encoding="utf-8")
            tmp.write_text(json.dumps(entry, separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, self.dir / f"{key}.json")
            self.used.add(key)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass

    def prune(self) -> None:
        """Drop entries not used in this run (stale files / old versions)."""
        try:
            for p in self.dir.glob("*.json"):
                if p.stem not in self.used:
                    p.unlink()
        except OSError:
            pass
