# Fixtures

Small apps the taint engine is measured against. They are parsed, never imported or executed
(pytest ignores them: no `test_` prefix, no `__init__.py`).

- `vuln/`: every sink that should be reported has a trailing comment `# VH-EXPECT: <rule>`
  on the line of the sink call (rule ids as in `vulnhound.taint.specs.RULES`).
- `safe/`: look-alike code that must produce zero findings; no `VH-EXPECT` comments.
- `vuln/` subdirectories (`pkg_*`) hold interprocedural cases: source in one module, sink in another.

Scoring: expected = set of (file, line, rule) from the comments; found findings are matched by sink location.
