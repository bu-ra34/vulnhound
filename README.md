# vulnhound

**Finds real vulnerabilities. Proves them. Fixes them. Without burning your tokens.**

> Status: pre-alpha. Only `estimate` and `version` work today; the rest is on the roadmap.

[Türkçe](README.tr.md)

## Why

Asking an LLM to security-review a codebase usually means feeding it the whole repo.
That is expensive, slow, and most of those tokens are code that has nothing to do with
any vulnerability. vulnhound avoids this: cheap static analysis finds candidate flows
first, so the LLM only reads a short list and a few small code slices.

## How it works

- **The core is the eyes.** A stdlib-only Python program builds an AST index and runs
  taint analysis from untrusted sources to dangerous sinks. It never calls an LLM and
  prints short JSON.
- **Claude is the brain.** Inside Claude Code, the bundled skill tells Claude to run the
  CLI, read only that output plus small slices, judge each finding, write a PoC for the
  likely-real ones, prove it in a sandbox, and patch it.

Zero runtime dependencies. Python 3.10+. MIT licensed.

## Install

As a Claude Code plugin:

```
/plugin marketplace add bu-ra34/vulnhound
/plugin install vulnhound@vulnhound
```

The CLI itself (the skill needs it on your PATH):

```
pip install vulnhound
```

## CLI

| Command | What it does |
|---|---|
| `vulnhound analyze [path] [--json] [--no-cache] [--min-severity S]` | Find candidate vulnerabilities. Exit 1 if any. Findings sharing a sink/helper are grouped (`--no-group` to list all); tests/examples/docs dirs and `test_*.py` are skipped unless `--include-tests`; `--include-local-sources` adds local/CLI inputs as sources. |
| `vulnhound slice <id>` | Minimal code slice for one finding. |
| `vulnhound prove <id> --poc FILE [--root DIR] [--backend auto\|docker\|unshare] [--timeout S] [--json] [--verbose]` | Run a PoC in a sandbox (no network, resource-limited). Prints PROVEN (exit 0), SAFE (1) or UNVERIFIED (3). |
| `vulnhound estimate [path] [--json]` | Rough token cost (bytes/4) of reading the whole repo. |
| `vulnhound report [--format json\|sarif\|markdown] [-o FILE]` | Render findings. |
| `vulnhound version` | Print version. |

Exit codes: 0 ok / no findings, 1 findings found, 2 usage error (e.g. unknown id), 3 UNVERIFIED (prove).

## Proving a finding

`vulnhound prove <id> --poc poc.py` runs a small standalone Python PoC in a sandbox (network off, memory/CPU/time limited, project mounted read-only) and reports a verdict. The PoC triggers the vulnerable code with a malicious input and calls `proven("detail")` from `vulnhound.poc` when the exploit works, or `safe("detail")` when it is blocked. `canary_path()` returns a secret file outside the project, for path-traversal PoCs to read. No marker and exit 0 means SAFE; sandbox missing, timeout or a crashing PoC means UNVERIFIED. The PoC never runs on the host.

Caveat: the sandbox needs docker or unshare. The PoC runs against your project, so third-party imports must be importable inside it: the `unshare` backend sees the host venv read-only, while the `docker` backend uses a clean python image, so PoCs needing framework imports may report UNVERIFIED there. Pick `--backend unshare` when the PoC imports your installed deps.

## Roadmap

- [x] M0: skeleton (CLI, plugin, skill, CI)
- [ ] M1: project index (AST, call graph, cache)
- [ ] M2: taint engine
- [ ] M3: framework support and `slice`
- [ ] M4: sandboxed proof (`prove`)
- [ ] M5: benchmark
- [ ] M6: release

No benchmark results are claimed yet; they will be published after M5.

## Security

Scan only code you own. See [SECURITY.md](SECURITY.md).

## License

MIT
