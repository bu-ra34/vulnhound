"""Helpers for PoC scripts run by `vulnhound prove` (inside the sandbox)."""

from __future__ import annotations

import os

PROVEN_MARKER = "VULNHOUND-PROVEN"
SAFE_MARKER = "VULNHOUND-SAFE"


def proven(detail: str = "") -> None:
    """Report that the exploit observably succeeded."""
    print(f"{PROVEN_MARKER}: {detail}", flush=True)


def safe(detail: str = "") -> None:
    """Report that the attack was blocked."""
    print(f"{SAFE_MARKER}: {detail}", flush=True)


def canary_path() -> str:
    """Path of a secret file outside the project; reading it proves traversal."""
    return os.environ["VULNHOUND_CANARY"]
