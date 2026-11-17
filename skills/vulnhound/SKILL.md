---
name: vulnhound
description: Token-thrifty security review of Python code. Use when the user asks for a security review, vulnerability scan, or audit of a Python project (SQL injection, command injection, SSRF, path traversal, unsafe deserialization, code execution), or asks to verify or fix such a finding.
---

# vulnhound workflow

The `vulnhound` CLI does the static analysis. You are the judge. Never read the whole repo.

## Rules
- Only analyze code the user owns or is authorized to test.
- If `vulnhound` is not installed, tell the user: `pip install vulnhound`. Do not scan by reading files instead.
- Never run a PoC directly on the host. Only via `vulnhound prove`.
- Keep output terse. No long explanations per finding.

## Steps
1. Run `vulnhound analyze . --json` (optionally `--min-severity medium`). Exit code 1 means findings, 0 means none.
2. Take findings highest severity first. For each, run `vulnhound slice <id>` and judge only that slice: is the source attacker-controlled, is there real sanitization, is the sink reachable?
3. If likely real, write a minimal PoC file (small script showing the malicious input reaching the sink) and run `vulnhound prove <id> --poc poc.py`.
4. If proven (or clearly real), make the smallest patch that removes the flaw (parameterized query, argument list instead of shell, allow-list, safe loader). Re-run `vulnhound prove <id> --poc poc.py` to confirm the PoC now fails.
5. If the slice shows the flow is safe, mark it false-positive and move on. Do not write a PoC for it.
6. Do not open files beyond the slice unless the slice is genuinely insufficient; then read only the few lines needed.

## Final output
One terse table, nothing else:

| severity | CWE | file:line | status |
|---|---|---|---|

Status is one of: confirmed, fixed, false-positive, unverified.

`vulnhound estimate .` shows what naively reading the repo would cost, if the user asks.
