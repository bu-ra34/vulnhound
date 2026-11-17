import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(rel):
    return json.loads((ROOT / ".claude-plugin" / rel).read_text())


def test_plugin_json():
    d = _load("plugin.json")
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", d["name"])  # only required key; kebab-case
    assert isinstance(d["author"], dict) and d["author"]["name"]
    assert isinstance(d["keywords"], list)


def test_marketplace_json():
    d = _load("marketplace.json")
    assert d["name"] and d["owner"]["name"]
    assert d["plugins"]
    for p in d["plugins"]:
        assert p["name"] and p["source"]
        assert not isinstance(p["source"], str) or ".." not in p["source"]
    assert _load("plugin.json")["name"] in {p["name"] for p in d["plugins"]}


def test_skill_frontmatter():
    text = (ROOT / "skills" / "vulnhound" / "SKILL.md").read_text()
    assert text.startswith("---\n")
    fm = text.split("---\n", 2)[1]
    keys = dict(ln.split(":", 1) for ln in fm.splitlines() if ":" in ln)
    assert keys["name"].strip() and keys["description"].strip()
    assert len(keys["description"]) <= 1536
    assert len(text.splitlines()) <= 80
