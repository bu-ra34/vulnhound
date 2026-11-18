---
name: vulnhound
description: Token-thrifty security review of Python code. Use when the user asks for a security review, vulnerability scan, or audit of a Python project (SQL injection, command injection, SSRF, path traversal, unsafe deserialization, code execution), or asks to verify or fix such a finding.
---

# vulnhound workflow

The `vulnhound` CLI does the static analysis. You are the judge. Never read the whole repo.

## Rules
- Only analyze code the user owns or is authorized to test.
- If `vulnhound` is not installed, tell the user: `pip install vulnhound`. Do not scan by reading files instead.
- Never run a PoC on the host (no `python poc.py`, no exec of target code). Only via `vulnhound prove`, which is sandboxed.
- Keep output terse. No long explanations per finding.

## Steps
1. Run `vulnhound analyze . --json` (optionally `--min-severity medium`). Exit code 1 means findings, 0 means none.
2. Take findings highest severity first. Findings are grouped by default: each entry is one representative; `n` is the group size and `also` lists the other locations (other sources if the sink is shared, else other sinks). Judge the representative's slice once and apply the verdict to the whole group (a shared helper is usually one bug or one fix). Use `--no-group` to see every finding; any member id still works with `slice`.
   Test/example/docs dirs (`tests`, `examples`, `docs`, `benchmarks`, ...) and `test_*.py`/`conftest.py` are skipped by default; add `--include-tests` if the user wants them. `--include-local-sources` also treats local/CLI-style inputs as sources (noisier).
   Slice lines marked `◀ guard?` are validation checks on the tainted value that are never elided: judge whether they really block the attack.
   For each, run `vulnhound slice <id>` and judge only that slice: is the source attacker-controlled, is there real sanitization, is the sink reachable?
3. If likely real, write a minimal self-contained PoC (a standalone Python script) and run `vulnhound prove <id> --poc poc.py [--backend unshare|docker] [--timeout N]`. It runs only in a sandbox (needs docker or unshare; none available = UNVERIFIED, then continue from the slice judgment and never run the PoC another way). The sandbox has no network and limited memory/time: the PoC must not fetch anything.
   PoC contract: import the vulnerable code (the project root is on `PYTHONPATH`, read-only), trigger it with the malicious input, then `from vulnhound.poc import proven, safe`: call `proven("detail")` if the exploit observably worked (prints `VULNHOUND-PROVEN: ...`), `safe("detail")` if blocked (prints `VULNHOUND-SAFE: ...`). For path traversal, `canary_path()` is a secret file outside the project; reading it via the sink proves the bug.
   Verdicts: PROVEN (exit 0), SAFE (exit 1, ran without proof), UNVERIFIED (exit 3: no sandbox, timeout, or PoC error such as a missing import; docker uses a clean python image, so use `--backend unshare` for PoCs importing installed deps).
4. If proven (or clearly real), make the smallest patch that removes the flaw (parameterized query, argument list instead of shell, allow-list, safe loader). Re-run `vulnhound prove <id> --poc poc.py` to confirm it now reports SAFE.
5. If the slice shows the flow is safe, mark it false-positive and move on. Do not write a PoC for it.
6. Do not open files beyond the slice unless the slice is genuinely insufficient; then read only the few lines needed.

## Final output
One terse table, nothing else:

| severity | CWE | file:line | status |
|---|---|---|---|

Status is one of: confirmed, fixed, false-positive, unverified.

`vulnhound estimate .` shows what naively reading the repo would cost, if the user asks.
