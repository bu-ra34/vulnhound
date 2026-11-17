# Real-project measurements, hot spots, precision sample

Reproduce: `python benchmarks/real_projects.py ROOT [--json out.json] [--dump dir]`
(ROOT has one extracted sdist per sub-directory; code is only parsed, never imported).
Snapshot of the engine/slicer as of this run (other agents were editing engine.py and
slicer.py concurrently, so finding counts will drift). Python 3.13, one core, tokens = bytes/4.

## Projects (PyPI sdists, `.py` files only)

| project | files | lines | funcs | naive tok | cold idx s | warm idx s | analyze s | findings (C/H/M/L) | json B | slice B | Claude reads tok | touched-files tok | x vs repo | x vs touched |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| httpbin 0.10.4 | 8 | 3,316 | 180 | 24,237 | 0.03 | 0.00 | 0.04 | 0 | 169 | 0 | 42 | 0 | 574 | - |
| fastapi-users 15.0.5 | 89 | 9,247 | 684 | 87,148 | 0.11 | 0.02 | 0.12 | 0 | 181 | 0 | 45 | 0 | 1,926 | - |
| flask-admin 2.2.1 | 115 | 30,741 | 1,471 | 244,048 | 0.31 | 0.03 | 0.51 | 18 (0/1/0/17) | 13,020 | 17,708 | 7,682 | 30,807 | 31.8 | 4.0 |
| flask-appbuilder 5.3.0 | 295 | 45,632 | 2,219 | 387,812 | 0.47 | 0.06 | 0.86 | 11 (0/0/0/11) | 9,792 | 12,235 | 5,506 | 9,476 | 70.4 | 1.7 |
| label-studio 1.23.2 | 669 | 85,594 | 3,816 | 828,225 | 1.28 | 0.18 | 1.53 | 17 (0/11/1/5) | 16,116 | 36,029 | 13,036 | 36,783 | 63.5 | 2.8 |
| apache-superset 6.1.0 | 1,177 | 200,225 | 6,624 | 1,782,886 | 1.89 | 0.23 | 3.78 | 7 (0/1/2/4) | 6,464 | 12,462 | 4,731 | 44,780 | 376.8 | 9.5 |
| wagtail 8.1 | 1,332 | 277,900 | 16,348 | 2,547,854 | 3.35 | 0.44 | 7.13 | 20 (0/0/0/20) | 16,212 | 32,749 | 12,240 | 74,307 | 208.2 | 6.1 |
| mlflow 3.18.0 | 1,315 | 396,534 | 15,611 | 4,049,292 | 3.80 | 0.38 | 9.53 | 104 (6/32/39/27) | 108,614 | 229,747 | 84,590 | 480,751 | 47.9 | 5.7 |

"Claude reads" = `analyze --json` + every finding's slice. "touched-files" = whole files that
contain a finding's source, sink or path step (the realistic naive baseline).
Peak RSS for mlflow analyze: 528 MB. `slice` for all findings is cheap (mlflow 0.77 s total).

Takeaways:
- Versus reading the whole repo the saving is 30x-1,900x, but that baseline is a straw man.
  Versus the files that actually contain findings it is only 1.7x-9.5x, and it **shrinks when
  there are many findings**: mlflow's 104 findings cost 84k tokens (JSON ~1.04 KB + slice ~2.2 KB
  each), which is 3.4 KB per finding that, per the precision sample below, is mostly noise.
  Precision (and de-duplication of findings sharing a sink) matters more for token cost than slicing.
- A project with 0 findings costs ~40 tokens, the best case.
- Cost is dominated by repeated findings: flask-admin has 17 open-redirect findings that are one
  `get_redirect_target()` helper reached from 17 callers; wagtail 12 findings from one helper.
  Group by (rule, source) or (rule, sink) and emit one finding with N call sites.
- Slicer bug: `build_slice` raised `AttributeError: 'match_case' object has no attribute 'lineno'`
  (slicer.py `_header_span`, `match` statements) for VH-f8ada2 in mlflow. The benchmark records
  it in `slice_errors`.

## Scaling

cold index ~ 3.8 s/400k lines, analyze ~ 2.5x the cold index time (analyze 9.5 s on mlflow vs
3.8 s cold index). Linear in code size. 108k functions: ~29 s index / 70 s analyze matches.

## Hot spots (cProfile on mlflow, analyze with warm cache: 14.7 s profiled / 9.5 s real)

1. **Garbage collector: ~40% of analyze wall time.** Same code, `gc.disable()` vs enabled:
   - parse all 1,315 modules (`ProjectIndex.ast_for`): 4.0-4.2 s -> 1.4-1.6 s
   - full `analyze()`: 8.7 / 9.7 s -> 5.1 / 5.8 s
   The engine keeps ~15.6k function ASTs alive, so every young-generation collection walks a
   huge live heap. Fix (one line, in `cmd_analyze` or `engine.analyze`): `gc.disable()` (or
   `gc.freeze()` after the AST load, or `gc.set_threshold(200_000, 20, 20)`) for the run.
   Cold `build_index` is not affected (trees die immediately): 3.7-4.1 s either way.
2. **Every module is parsed twice per cold run, and once per warm run.** The index cache stores
   only the extraction JSON, so `Engine.load()` calls `ast_for` for all modules: 1,315 x
   `ast.parse` = 4.0 s of 14.7 profiled (27%, `ast.parse` 2.4 s + C `compile` 1.6 s); `Engine.load`
   alone is 2.1 s even with the GC off. Options: (a) text pre-filter: only parse/analyze modules
   whose source text mentions a configured source or sink name (most modules mention none: of
   15.6k functions only 17,960 analyze_function runs happen anyway, so the saving is parse + walk);
   (b) on a cold run keep the trees from extraction (`extract_module` already parsed them) instead
   of re-parsing: saves ~1.5 s on mlflow at the cost of memory; (c) lazy per-module parse when
   the first function of that module is analyzed.
3. `_collect_nodes` (engine.py `visit`): 222k recursive calls, 1.65 s cumulative (11%); it walks
   every statement via `ast.iter_child_nodes` just to find def/class nodes. The extractor already
   knows each function's `line`; map `(module, line)` -> node with one pass over `ast.walk` only
   statement-bearing containers, or skip subtrees of simple statements.
4. `Analyzer.ev`/`call` (taint transfer): 646k `ev` calls (7.4 s cumulative, 0.9 s self) and
   114k `call`; `chain_source` 222k calls = 3.0 s cumulative (20%), of which `specs.match_source`
   144k calls = 0.9 s and `Engine.resolve` 340k calls = 1.8 s (12%). `chain_source` is recomputed for
   the same attribute chains over and over (e.g. `request.args.get`); memoize on the AST node id
   or on `(module, chain_string)` per module. `_chain` is called 785k times for the same reason.
5. Reanalysis: 17,960 `analyze_function` runs for 15,611 functions (15% re-analysis via the
   field/summary worklist); small, fine.
6. Index (cold, profile 8.5 s / 3.8 s real): `_Extractor.visit` 1.28M recursive calls, 4.8 s of
   6.5 s extraction cumulative (50%+ of it is `ast.iter_child_nodes` generator overhead), C parse
   1.5 s, cache JSON write 0.86 s (1,315 `write_text`, 1 file per module; ~0.3 s real).
   I tried inlining `iter_child_nodes` in `_Extractor.visit` (same order): only ~7% faster on
   extraction (2.89 s -> 2.68 s best-of-3) so I reverted it; not worth the code. Real gains need
   fewer nodes visited (skip Name/Constant/expr leaves by checking `type(node)` against a
   precomputed skip set) or multiprocessing across files for cold runs.
7. Warm index (0.4 s on mlflow) is fine: read + sha256 of every file + JSON load.
   Could use mtime+size to skip hashing, but the gain is a few hundred ms.

No engine/index/cache code was changed (index change attempted and reverted; tests: 68 pass).
Highest-value single change: item 1 (disable GC during analyze), ~3.5 s of 9.5 s on mlflow.

## Precision sample (15 findings, read from their slices)

Sampled across mlflow (7), label-studio (3), flask-admin (2), wagtail, superset.
Result: **0 true positives, 15 false positives, 0 unclear** (with the caveat that I judged only
from the slice plus a look at the elided lines; none of these is a plausible vulnerability).
This is a first estimate, n=15 and not random (spread across rules and severities), but it
suggests precision on real code is currently far below what the token argument needs.

| # | finding | rule/sev | verdict | why |
|---|---|---|---|---|
| 1 | mlflow VH-15232b gateway_api -> `exec` in `recreate_function` | code-exec critical | FP | the flow is a chain of unrelated call hops; the server explicitly refuses custom-code scorers (`_serialized_scorer_is_custom_code` raises) and `model_validate` returns a non-executing handle (comment in the slice) |
| 2 | mlflow VH-9e1627 stdin_server `open(request["output_file"])` | path-traversal high | FP | a local CLI reading stdin; stdin is not attacker input here |
| 3 | mlflow VH-943ad8 `session_id` -> `read_text` | path-traversal high | FP | `get_session_file` calls `SessionManager.validate_session_id` (hidden by slice elision) |
| 4 | mlflow VH-01d4c4 upload_artifact_handler `open(file_path)` | path-traversal high | FP | `path = validate_path_is_safe(path)` is in the slice; engine does not treat it as a sanitizer (and the slice pads with `_decode`/`escape_char` bodies) |
| 5 | mlflow VH-bd4d0b judges/environment_behavior.py | path-traversal medium | FP | test helper reading env vars |
| 6 | mlflow VH-a45beb scoring_server/app.py | path-traversal medium | FP | env var set by the server operator, not a user |
| 7 | mlflow VH-96a1ac `os.environ` -> `__import__` | code-exec medium | FP | taint travels through `.format()` into a pip-requirements string; `__import__(module or package)` gets a package name from a static table |
| 8 | mlflow VH-ab77d4 `os.environ.copy()` -> `Popen` | cmdi low | FP | env dict passed as `env=`, not as the command line |
| 9 | label-studio VH-c25acd `request.GET['d']` -> `open` | path-traversal high | FP | `safe_join(DOCUMENT_ROOT, path)` plus permission check precede the sink |
| 10 | label-studio VH-d2a298 `sys.argv` -> `io.open` | path-traversal high | FP | server CLI config-file argument |
| 11 | label-studio VH-bf3260 `next` -> `redirect` | open-redirect low | FP | `url_has_allowed_host_and_scheme` check reassigns `next_page` on failure (guard-then-reassign) |
| 12 | flask-admin VH-5b9c8a `request.args['db']` -> `send_file` | path-traversal high | FP | `db` is a Mongo database name; `send_file` gets a GridFS object, not a path |
| 13 | flask-admin VH-3c60c1 `request.values` -> `redirect` | open-redirect low | FP | the source line is inside `get_redirect_target`, which returns only if `is_safe_url(target)` |
| 14 | wagtail VH-1f9c9e `request.POST['next']` -> `redirect` | open-redirect low | FP | `url_has_allowed_host_and_scheme(... allowed_hosts={host})` returns "" otherwise |
| 15 | superset VH-b20faf `request.files` -> `db.session.execute(insert(...))` | sqli high | FP | executes a SQLAlchemy `insert().values()` of integer ids; parametrized |

FP causes (counts of the 15): validators/sanitizers not modelled or not honoured when they live
in a callee or a guard-then-reassign (3, 4, 9, 11, 13, 14, 15 partly, 1): 8; non-attacker
sources (env, argv, stdin) treated as untrusted (2, 5, 6, 10, 7): 5; wrong semantic (value is
not a path / not a command, 8, 12, 15): 3 (overlapping).

Actionable for the engine (not changed here):
- Treat as sanitizers any callee whose name matches `validate_*|is_safe*|safe_*|get_safe_*|
  *_is_safe|url_has_allowed_host_and_scheme|safe_join|secure_filename|is_safe_url|is_safe_redirect_url`,
  and honour guard patterns `if not safe(x): x = default` / `if not safe(x): raise|return`.
- Drop `os.environ`, `sys.argv`, `sys.stdin` as sources by default (or demote to `low` with an
  explicit `--include-local-sources` flag); drop `env=` kwargs as cmdi sink args.
- Skip or demote findings under `tests/`, `test_*.py`, `examples/`: mlflow has 15+ of those.
- Do not report source-in-a-safe-helper findings (flask-admin, wagtail, flask-appbuilder: the
  source line is inside `get_redirect_target`/`get_valid_next_url...`, the helper is the sanitizer).
- Slice elision (`…`) hid the actual guard in #3; keep calls to `validate_*`/`check_*` lines of
  the path function and show `if` guards that dominate the sink.

## Round 2 results (validators/guards, grouping, test exclusion)

Same 8 projects, CLI defaults. Total findings fell from about 200 to 16
(superset 3, flask-admin 2, label-studio 2, mlflow 4, wagtail 5, others 0).

Manual triage of all 16 slices: 0 true positives, 13 false positives, 3 unclear
(label-studio storage-URI redirect, mlflow scorer deserialization, mlflow
skills install `custom_path`; the last is behind a deny-remote-access policy).

Remaining false-positive classes:
1. Open redirect to a same-host URL: `request.path`, `request.url` reduced to
   path+query, or `reverse(...) + "?" + query`. Only attacker control over the
   start of the URL (scheme/host) should count.
2. Taint through database lookups: a request id used to fetch an object
   (`DAO.find_by_id(id)`, `GridFS.get(...)`), whose stored content then reaches
   a sink. Values loaded by id are not attacker-supplied content.
3. Positive-branch guards: `if x and is_safe_url(x): return x` is not yet
   treated as a guard on the returned value.
4. Guards whose result is reassigned (`path = validate_path_is_safe(path)`)
   followed by helper calls still produce a finding in mlflow.

## Precision benchmark (benchmarks/precision.py)

`python benchmarks/precision.py CORPUS_DIR [LABELS.json] [--json OUT] [--strict] [NAME ...]`
runs the engine with CLI defaults (grouped, tests excluded) over every project in
CORPUS_DIR and matches group representatives to `benchmarks/precision_labels.json`
by key `project|rule|sink_path:line|source_path:line`. It prints per project
findings / tp / fp / unclear / UNLABELED, then overall precision = tp/(tp+fp),
and lists unlabeled findings with their keys (triage these and add labels).
`--strict` exits 1 if any finding is unlabeled. Labels no longer reported are
counted as stale. Corpus: the 8 earlier projects plus django-cms 5.1.3, flaskbb
3.0.0, gradio 6.32.0, jupyter-server 2.21.1, nautobot 3.2.9, netbox 4.7.5,
pretalx 2026.2.1, saleor 2.10.1, streamlit 1.67.0 (PyPI sdists, .py only).

Baseline (17 projects, engine as of Round 2): 67 findings; 1 tp, 65 fp, 1 unclear;
precision 1/66 = 0.015. fp categories: same-host-redirect 32, guarded 26,
db-lookup 3, wrong-sink-semantics 2, not-attacker-source 2. The 16 original
findings: 0 tp / 15 fp / 1 unclear (the manager's two other unclear items,
label-studio storage-URI redirect and mlflow scorer deserialization, are fp:
bucket-gated presign redirect; guardrail rejects custom-code scorers and the
server never exec()s). Only tp: one gradio path-traversal finding (details withheld pending responsible disclosure).

Note: true-positive labels for issues not yet publicly disclosed are kept out of
this repository until the maintainers have been notified. `precision.py` reports
such findings as UNLABELED.
