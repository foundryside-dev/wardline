# Wardline Read-Only Codebase Audit

Date: 2026-06-04  
Scope: `/home/john/wardline`  
Mode: Comprehensive read-only audit of source, tests, CLI, MCP, static-analysis logic, integrations, and security boundaries.

## Read-Only Boundary

This audit was conducted as a read-only review of the codebase. No source files, tests, configs, or tracker state were modified as part of the audit. The only write performed was this requested markdown artifact.

Seven specialized subagents were dispatched with explicit read-only instructions:

| Agent | Focus |
| --- | --- |
| Architecture Critic | Package boundaries, cohesion, coupling, structural fragility under `src/` |
| Systems Thinker | Feedback loops, dependency chains, propagation flows, failure modes |
| Python Engineer | Python implementation, typing posture, AST parsing/manipulation, idioms |
| Quality Engineer | Tests, CI, coverage structure, maintainability, validation paths |
| Security Architect | Trust boundaries, external data handling, secure defaults |
| Static Tools Analyst | Static-analysis rules, taint propagation, trust lattice, SCC logic |
| MCP & CLI Specialist | CLI and MCP protocol/server behavior, path confinement, tool parity |

Tooling note: the available subagent spawning interface did not expose literal `enable_write_tools=false` or `enable_mcp_tools=false` switches. The equivalent boundary was enforced in each subagent prompt: no edits, no `apply_patch`, no write commands, no MCP tools, no tracker changes, and no escaped double quotes in tool arguments.

## Executive Summary

No Critical issues were found. The audit identified 5 High, 15 Medium, and 5 Low findings. The highest-risk themes are:

- Warm-cache scan behavior can diverge from cold scans for L2-backed rules.
- A default MCP waiver write path can bypass root confinement through symlinked `wardline.yaml`.
- Project-controlled config can influence autofix code generation and LLM judge suppression behavior.
- Filigree close-on-fixed feedback lacks a clean-file heartbeat, so fixed findings may stay open.
- MCP/CLI hardening has several retry, schema, notification, and confinement gaps.

The codebase also shows several strong foundations: shared CLI/MCP orchestration through `core.run`, generally coherent scanner layering, strict mypy/coverage-oriented CI, safe YAML loading/schema validation, fail-soft external integrations, and explicit trust-lattice modeling in the analyzer.

## Remediation Status

Resolved in the current remediation pass:

- H-01: warm-cache L2 bypass no longer skips flow-sensitive call-site state; the warm/cold cache parity test now uses a sink fixture.
- H-02: MCP `waiver_add` passes the project root into waiver writes, rejecting symlinked default config escapes.
- H-03: `autofix.boundary_exception` is validated as an identifier/dotted identifier, and MCP `fix` requires `apply: true` before modifying files.
- H-04: project judge config no longer controls model or write confidence floor unless `trust_judge_config` is explicitly set.
- H-05: Filigree scan-results payloads now carry `scanned_paths`, allowing clean scanned files to participate in close-on-fixed reconciliation.
- M-01: JSON-RPC notifications no longer invoke registered handlers except for initialization lifecycle notifications.
- M-02: MCP tool schemas are closed with `additionalProperties: false`, and unknown tool arguments return `isError`.
- M-03: retrying `baseline_create` and `waiver_add` is idempotent and returns existing state instead of failing.
- M-04: CLI/core scans reject escaping `source_roots` by default; CLI escape now requires `--allow-source-root-escape`.
- M-05: attestation verification now checks `signature.alg`, `signature.key_id`, and signature value.
- M-06: Filigree dossier reads normalize scan-results URLs to the Filigree API base before querying entity associations.
- M-07: Clarion-backed explanations select the exact stored finding by fingerprint/path/line and fall back to local analysis on mismatch.
- M-08: discovery skip rules apply relative to the configured source root, not absolute parent directories.
- M-09: callgraph receiver type tracking no longer collects assignments from nested scopes.
- M-10: sink discovery no longer descends into lambda bodies.
- M-11: `NoneLeak` fall-through analysis handles all-return `try`/`except` paths.
- M-12: shared dossier identity types live in neutral `core.identity`, with Clarion compatibility re-exports.
- M-13: MCP resource/prompt catalogs and shared tool plumbing were split out of `mcp/server.py`, with advertisement snapshot coverage.
- M-14: CI now exposes scheduled/manual live-oracle jobs for Clarion, Legis, and Filigree e2e markers.
- M-15: Filigree unsafe config URL rejection now has mirrored negative coverage.
- L-01: analyzer cache freshness checks use `SummaryCache.has_current()` instead of private `_entries`.
- L-02: `core.protocols` is wired into scan orchestration and the rule registry seam.
- L-03: pack tests use `monkeypatch.syspath_prepend` instead of direct `sys.path` mutation.
- L-04: LSP `Content-Length` framing has a maximum body size and drains oversized frames deterministically.
- L-05: CLI `scan --fix` preserves `strict_defaults` during the post-fix rescan.

Verification after remediation:

- `uv run pytest` — 2173 passed, 8 live/network tests deselected, 1 expected symlink-skip warning.
- `uv run mypy src tests` — success.
- `uv run ruff check src tests` — success.

## Critical Findings

None found.

## High Findings

### H-01: Warm-cache L2 bypass changes rule behavior

Severity: High  
Areas: Static analysis correctness, scanner cache, taint rules  
Locations:

- [src/wardline/scanner/analyzer.py:518](/home/john/wardline/src/wardline/scanner/analyzer.py:518)-525
- [src/wardline/scanner/rules/_sink_helpers.py:174](/home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py:174)-187
- [src/wardline/scanner/rules/_sink_helpers.py:268](/home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py:268)-270
- [src/wardline/scanner/rules/untrusted_to_trusted_callee.py:117](/home/john/wardline/src/wardline/scanner/rules/untrusted_to_trusted_callee.py:117)-119
- [tests/unit/cli/test_cli.py:191](/home/john/wardline/tests/unit/cli/test_cli.py:191)-218

Finding: cached modules with `bypass_l2` restore only selected summary fields, while L2-derived local variable and callsite taints are not rebuilt. Sink rules then fall back to `UNKNOWN_RAW`, and PY-WL-105 can lose caller/callee evidence. Cold and warm scans can therefore produce different diagnostics for the same code. The existing CLI warm-cache test covers a trivial non-sink fixture, so it does not prove the L2-backed sink/callee invariant.

Impact: false positives and false negatives in the scanner after cache reuse. This is especially risky because cache reuse is a normal operational path, so CI or local dogfooding can disagree with a fresh scan.

Remediation:

1. Persist and reload the L2 artifacts that rules consume, including local variable taints and callsite taints.
2. If full L2 persistence is not desired, recompute L2 for cached modules before running rules.
3. Add a cold-vs-warm invariant test that scans the same fixture twice and asserts identical diagnostics.
4. Include fixtures for a safe literal sink, a raw sink, and PY-WL-105 caller/callee propagation.

### H-02: MCP `waiver_add` can write through an out-of-root symlinked default config path

Severity: High  
Areas: MCP mutating tool, path confinement, waiver persistence  
Locations:

- [src/wardline/mcp/server.py:417](/home/john/wardline/src/wardline/mcp/server.py:417)-429
- [src/wardline/core/waivers.py:88](/home/john/wardline/src/wardline/core/waivers.py:88)-117

Finding: the MCP `_waiver_add` fallback writes to `root / "wardline.yaml"` but calls `add_waiver` without passing `root=root`. `add_waiver` only applies `safe_project_file` when `root` is supplied. A symlinked default config file can therefore redirect writes outside the project root.

Impact: a project can cause the MCP tool to append waiver data to an arbitrary symlink target reachable by the process. This breaks the MCP server's otherwise explicit path-confinement posture.

Remediation:

1. Pass `root=root` from `_waiver_add` to `add_waiver` for the default path.
2. Make `add_waiver` require a root for all writes, or require callers to pass a prevalidated path object.
3. Add symlink escape tests for `waiver_add`, default config reads, default config writes, `resources/read wardline://config`, `scan`, and `fix`.
4. Treat a symlinked config target outside the root as an MCP `isError` response with a clear confinement error.

### H-03: Config-controlled autofix exception name can generate unsafe Python output

Severity: High  
Areas: Autofix, config trust boundary, MCP fix tool  
Locations:

- [src/wardline/core/autofix.py:80](/home/john/wardline/src/wardline/core/autofix.py:80)
- [src/wardline/core/autofix.py:175](/home/john/wardline/src/wardline/core/autofix.py:175)
- [src/wardline/core/config_schema.py:59](/home/john/wardline/src/wardline/core/config_schema.py:59)
- [src/wardline/core/config.py:36](/home/john/wardline/src/wardline/core/config.py:36)-38
- [src/wardline/mcp/server.py:437](/home/john/wardline/src/wardline/mcp/server.py:437)-456

Finding: `autofix.boundary_exception` is accepted as an arbitrary string and later inserted into an AST node as a name before being unparsed. The MCP fix path can apply changes without a confirmation callback.

Impact: untrusted project configuration can steer generated source text. Even if malformed names usually fail at AST construction or unparsing time, this is a codemod trust-boundary violation and creates brittle, surprising behavior.

Remediation:

1. Validate `autofix.boundary_exception` as either a single valid identifier or a dotted qualified name where every segment passes `str.isidentifier()`.
2. Prefer an allowlist for known safe boundary exception names if project policy permits it.
3. Return a config validation error before any fix planning when the value is invalid.
4. Make MCP fix dry-run by default, or require an explicit `apply: true` argument for file mutation.
5. Add negative tests for malformed names, dotted names, keywords, whitespace, and punctuation.

### H-04: Project config can steer LLM judge model and suppression threshold

Severity: High  
Areas: LLM judge integration, suppression policy, untrusted project config  
Locations:

- [src/wardline/core/config_schema.py:37](/home/john/wardline/src/wardline/core/config_schema.py:37)-42
- [src/wardline/core/config.py:324](/home/john/wardline/src/wardline/core/config.py:324)-347
- [src/wardline/cli/judge.py:95](/home/john/wardline/src/wardline/cli/judge.py:95)
- [src/wardline/core/judge_run.py:81](/home/john/wardline/src/wardline/core/judge_run.py:81)-92
- [src/wardline/core/judge_run.py:150](/home/john/wardline/src/wardline/core/judge_run.py:150)
- [src/wardline/core/judge_run.py:200](/home/john/wardline/src/wardline/core/judge_run.py:200)
- [src/wardline/core/judge.py:211](/home/john/wardline/src/wardline/core/judge.py:211)-237
- [src/wardline/core/judge.py:322](/home/john/wardline/src/wardline/core/judge.py:322)

Finding: project config can set judge model and false-positive floor values. In a hostile or low-trust checkout, config can direct analysis to an unintended model or lower suppression thresholds.

Impact: a repository under scan can influence the external judge used to evaluate its own findings and can make suppression easier. This weakens judge-based assurance and creates an operator trust-boundary issue.

Remediation:

1. Treat model selection and suppression threshold as operator-controlled settings by default.
2. Require an explicit CLI flag such as `--trust-judge-config` before project config can influence these values.
3. Do not allow project config to lower the built-in false-positive floor unless an operator override is present.
4. Record effective judge model, threshold source, and override source in output metadata.
5. Add tests showing that project config is ignored without the trust flag and honored only with the flag.

### H-05: Filigree close-on-fixed feedback lacks a clean-file heartbeat

Severity: High  
Areas: Filigree integration, feedback loops, finding lifecycle  
Locations:

- [src/wardline/core/filigree_emit.py:58](/home/john/wardline/src/wardline/core/filigree_emit.py:58)-69
- [src/wardline/scanner/diagnostics.py:39](/home/john/wardline/src/wardline/scanner/diagnostics.py:39)-48

Finding: close-on-fixed appears to rely on emitted findings and a `mark_unseen` behavior, but the emitted payload does not include a complete scanned-file inventory or per-file clean heartbeat. The code comment indicates absent fingerprints are swept only for files still represented in the batch. If a file has no current findings, it may not be represented as a cleaned source file.

Impact: fixing the only finding in a file may fail to close the linked Filigree issue. The external tracker can drift toward stale open issues and reduce trust in scan automation.

Remediation:

1. Extend the Filigree payload with explicit scanned source scopes for every analyzed file.
2. Alternatively, emit a per-file clean/reconciliation fact when a file was scanned and produced no findings.
3. Ensure `mark_unseen` receives enough file-level scope to close findings removed from otherwise-clean files.
4. Add a live or contract e2e test: create a finding, bind or emit it to Filigree, fix it, rescan, and assert the file_finding issue closes.

## Medium Findings

### M-01: JSON-RPC notifications can silently execute side-effecting MCP handlers

Severity: Medium  
Locations:

- [src/wardline/mcp/protocol.py:58](/home/john/wardline/src/wardline/mcp/protocol.py:58)-99

Finding: requests without an `id` are treated as notifications and no response is sent, but the handler is still invoked. A no-id `tools/call` notification can therefore run side-effecting handlers silently.

Remediation:

1. Whitelist legitimate notifications only, such as initialization lifecycle notifications if needed.
2. Reject or ignore no-id calls to `tools/*`, `resources/*`, and `prompts/*`.
3. Add a test proving no-id `tools/call` cannot mutate baseline, waiver, or fix state.

### M-02: MCP tool schemas allow unknown arguments on mutating tools

Severity: Medium  
Locations:

- [src/wardline/mcp/server.py:824](/home/john/wardline/src/wardline/mcp/server.py:824)-835
- [src/wardline/mcp/server.py:922](/home/john/wardline/src/wardline/mcp/server.py:922)-956
- [src/wardline/mcp/server.py:437](/home/john/wardline/src/wardline/mcp/server.py:437)-456

Finding: tool schemas do not consistently set `additionalProperties: false`. Unknown arguments, typoed safety flags, and accidentally ignored user intent can pass through mutating tool calls.

Remediation:

1. Add `additionalProperties: false` to all MCP input schemas.
2. Reject unknown arguments in server-side validation before dispatch.
3. Add negative schema tests for typoed mutating-tool arguments.
4. Require explicit `apply: true` or equivalent for mutating tools that change files.

### M-03: Mutating MCP tools are not retry-safe

Severity: Medium  
Locations:

- [src/wardline/mcp/server.py:401](/home/john/wardline/src/wardline/mcp/server.py:401)-429
- [src/wardline/core/baseline.py:100](/home/john/wardline/src/wardline/core/baseline.py:100)-109
- [src/wardline/core/waivers.py:111](/home/john/wardline/src/wardline/core/waivers.py:111)-117

Finding: repeated identical mutating calls can append duplicates or overwrite state without a stable idempotency story.

Remediation:

1. Make repeated identical calls return structured success such as `already_exists: true`.
2. Deduplicate waiver entries by stable fingerprint/rule/path tuple.
3. Add expected-version or idempotency-key support for baseline writes.
4. Add retry tests that issue the same MCP mutating call twice.

### M-04: CLI/core scans are unconfined by default

Severity: Medium  
Locations:

- [src/wardline/core/run.py:76](/home/john/wardline/src/wardline/core/run.py:76)-93
- [src/wardline/core/discovery.py:17](/home/john/wardline/src/wardline/core/discovery.py:17)-27
- [src/wardline/cli/scan.py:137](/home/john/wardline/src/wardline/cli/scan.py:137)
- [tests/unit/mcp/test_server_security.py:74](/home/john/wardline/tests/unit/mcp/test_server_security.py:74)-99

Finding: MCP has explicit path-escape tests, but CLI/core scanning defaults to unconfined source roots. That creates different trust behavior across entry points.

Remediation:

1. Default `confine_to_root=True` in CLI/core scan paths.
2. Add an explicit `--allow-source-root-escape` CLI option for the less-safe behavior.
3. Include the confinement mode in scan metadata.
4. Add CLI tests matching the MCP path-escape coverage.

### M-05: Attestation signature metadata is mutable

Severity: Medium  
Locations:

- [src/wardline/core/attest.py:126](/home/john/wardline/src/wardline/core/attest.py:126)-135
- [src/wardline/core/attest.py:300](/home/john/wardline/src/wardline/core/attest.py:300)-302

Finding: HMAC verification covers the payload/value, but the outer signature metadata such as algorithm and key id is not itself bound or strictly revalidated.

Remediation:

1. Require `signature.alg == "HMAC-SHA256"` during verification.
2. Require the stored `key_id` to match the verifying key's derived id.
3. Prefer including signature metadata in the signed canonical envelope.
4. Add tamper tests for algorithm, key id, schema tag, and payload.

### M-06: Dossier Filigree read path treats a scan-results URL as an API origin

Severity: Medium  
Locations:

- [src/wardline/filigree/dossier_client.py:78](/home/john/wardline/src/wardline/filigree/dossier_client.py:78)-86
- [src/wardline/loom_dossier.py:108](/home/john/wardline/src/wardline/loom_dossier.py:108)-109
- [tests/unit/core/test_config.py:185](/home/john/wardline/tests/unit/core/test_config.py:185)-193

Finding: configuration examples/tests treat `filigree.url` as a Loom scan-results endpoint, while dossier association reads append `/api/entity-associations` to that value as though it were an API origin.

Remediation:

1. Split configuration into distinct values such as `filigree.scan_results_url` and `filigree.api_base_url`.
2. Or normalize the configured scan-results URL back to an origin before appending association routes.
3. Add tests for the documented URL shape and the dossier association lookup URL.

### M-07: Clarion-backed explain can pair a requested fingerprint with the wrong stored finding

Severity: Medium  
Locations:

- [src/wardline/core/explain.py:152](/home/john/wardline/src/wardline/core/explain.py:152)-177
- [src/wardline/core/explain.py:273](/home/john/wardline/src/wardline/core/explain.py:273)-280
- [src/wardline/clarion/facts.py:59](/home/john/wardline/src/wardline/clarion/facts.py:59)-91

Finding: the Clarion-backed explanation path can collapse an entity query to the first finding in a stored blob instead of selecting the finding matching the requested fingerprint/path/line.

Remediation:

1. Pass requested fingerprint, path, line, and rule id into the blob extraction function.
2. Select the exact matching finding when present.
3. Fall back to local explanation when no matching entry exists.
4. Add tests with multiple findings bound to one entity.

### M-08: Absolute-path skip filter can false-green scans based on checkout location

Severity: Medium  
Locations:

- [src/wardline/core/discovery.py:17](/home/john/wardline/src/wardline/core/discovery.py:17)-34
- [src/wardline/core/run.py:209](/home/john/wardline/src/wardline/core/run.py:209)-223

Finding: skip logic checks path components directly. If an absolute parent directory contains a skipped component such as `.venv`, `venv`, `.git`, or `.mypy_cache`, an otherwise valid checkout can be skipped entirely.

Remediation:

1. Apply skip logic to components relative to the project or source root.
2. Emit a structured diagnostic or run metadata flag when all candidate files are skipped.
3. Add tests for checkouts under paths containing skipped directory names.

### M-09: Callgraph receiver type inference is polluted by nested-scope assignments

Severity: Medium  
Locations:

- [src/wardline/scanner/taint/callgraph.py:91](/home/john/wardline/src/wardline/scanner/taint/callgraph.py:91)-114
- [src/wardline/scanner/taint/callgraph.py:145](/home/john/wardline/src/wardline/scanner/taint/callgraph.py:145)-154

Finding: `ast.walk` traverses nested functions, lambdas, and classes while collecting local assignment type information. Inner-scope assignments can pollute outer-scope receiver inference.

Remediation:

1. Replace broad `ast.walk` collection with an own-scope visitor.
2. Stop recursion at nested `FunctionDef`, `AsyncFunctionDef`, `ClassDef`, and `Lambda` boundaries.
3. Add tests where nested-scope assignments use the same variable name as the outer scope.

### M-10: Sink discovery enters lambda bodies without matching taint snapshots

Severity: Medium  
Locations:

- [src/wardline/scanner/rules/_sink_helpers.py:81](/home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py:81)-97
- [src/wardline/scanner/rules/_sink_helpers.py:191](/home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py:191)-205
- [src/wardline/scanner/ast_primitives.py:122](/home/john/wardline/src/wardline/scanner/ast_primitives.py:122)-124

Finding: sink discovery can traverse lambda bodies, but the taint state associated with those expressions does not have a matching scope snapshot. This can misattribute trust state in nested expression scopes.

Remediation:

1. Apply the same scope-boundary policy used by callgraph/L2 analysis.
2. Or model lambdas as first-class scopes with their own taint snapshots.
3. Add lambda sink tests for trusted and untrusted captures.

### M-11: PY-WL-109 NoneLeak fall-through analysis is too shallow

Severity: Medium  
Locations:

- [src/wardline/scanner/rules/none_leak.py:138](/home/john/wardline/src/wardline/scanner/rules/none_leak.py:138)-154
- [src/wardline/scanner/rules/none_leak.py:183](/home/john/wardline/src/wardline/scanner/rules/none_leak.py:183)-190
- [tests/unit/scanner/rules/test_none_leak.py:106](/home/john/wardline/tests/unit/scanner/rules/test_none_leak.py:106)-229

Finding: fall-through detection handles simple terminal statements but does not robustly model `try`, `match`, and common loop terminal forms. This can over-report missing returns.

Remediation:

1. Expand terminal-path analysis for `try`/`except`/`finally`, `match`, and loops whose bodies unconditionally return/raise.
2. When full certainty is not available, prefer a conservative unknown path instead of a confident diagnostic.
3. Add positive and negative tests for `try`, `match`, loop, and nested branch cases.

### M-12: Dossier identity model depends on Clarion-owned types

Severity: Medium  
Locations:

- [src/wardline/core/dossier.py:39](/home/john/wardline/src/wardline/core/dossier.py:39)
- [src/wardline/core/dossier.py:428](/home/john/wardline/src/wardline/core/dossier.py:428)-442
- [src/wardline/filigree/dossier_client.py:27](/home/john/wardline/src/wardline/filigree/dossier_client.py:27)
- [src/wardline/loom_dossier.py:5](/home/john/wardline/src/wardline/loom_dossier.py:5)-8

Finding: core dossier and Filigree dossier paths depend on identity/status types owned by the Clarion integration. This weakens package boundaries and makes a product-neutral dossier model depend on one provider.

Remediation:

1. Move shared identity types such as `IdentityStatus`, `ContentStatus`, `EntityBinding`, and `content_status` into a neutral module such as `core.identity`.
2. Re-export from Clarion only for compatibility.
3. Update core, Clarion, Filigree, and Loom import paths.
4. Add a small dependency-direction test or import-lint check if the project already uses such tooling.

### M-13: MCP server is over-concentrated

Severity: Medium  
Locations:

- [src/wardline/mcp/server.py:132](/home/john/wardline/src/wardline/mcp/server.py:132)
- [src/wardline/mcp/server.py:401](/home/john/wardline/src/wardline/mcp/server.py:401)
- [src/wardline/mcp/server.py:469](/home/john/wardline/src/wardline/mcp/server.py:469)
- [src/wardline/mcp/server.py:551](/home/john/wardline/src/wardline/mcp/server.py:551)
- [src/wardline/mcp/server.py:854](/home/john/wardline/src/wardline/mcp/server.py:854)
- [src/wardline/mcp/server.py:913](/home/john/wardline/src/wardline/mcp/server.py:913)

Finding: MCP protocol, dependency construction, tool handlers, resource handlers, prompts, and schema advertisement are concentrated in one large server module.

Impact: local changes to one tool can accidentally affect unrelated MCP surfaces, and security validation rules are harder to enforce consistently.

Remediation:

1. Split handlers into modules such as `mcp/tools/scan.py`, `mcp/tools/fix.py`, `mcp/resources.py`, `mcp/prompts.py`, and `mcp/schemas.py`.
2. Keep the top-level server as a dispatcher and registry assembler.
3. Centralize common argument validation, root confinement, and error mapping.
4. Preserve public tool names and add advertisement snapshot tests during the split.

### M-14: Live Clarion/Legis/Filigree e2e oracles are not CI-gated

Severity: Medium  
Locations:

- [pyproject.toml:105](/home/john/wardline/pyproject.toml:105)-112
- [.github/workflows/ci.yml:47](/home/john/wardline/.github/workflows/ci.yml:47)-95
- [tests/e2e/test_clarion_live.py:1](/home/john/wardline/tests/e2e/test_clarion_live.py:1)-12

Finding: important live integration tests are marked as opt-in and are not represented as scheduled or manually triggered CI jobs.

Remediation:

1. Add scheduled or workflow-dispatch jobs for `clarion_e2e`, `legis_e2e`, and `filigree_e2e`.
2. Gate those jobs on required service secrets or local service availability.
3. Publish skipped/live status clearly in CI summaries.
4. Keep normal PR CI dependency-free, but run live oracles often enough to catch drift.

### M-15: Filigree unsafe-config URL guard lacks mirrored negative tests

Severity: Medium  
Locations:

- [src/wardline/core/config.py:257](/home/john/wardline/src/wardline/core/config.py:257)-285
- [tests/unit/core/test_config.py:217](/home/john/wardline/tests/unit/core/test_config.py:217)-233

Finding: Clarion unsafe URL configuration has negative test coverage, but Filigree's equivalent unsafe-config guard does not have mirrored tests.

Remediation:

1. Add Filigree tests that reject unsafe scheme/host combinations under unsafe config.
2. Mirror the Clarion test shape to make the two trust-boundary policies easy to compare.
3. Include a positive test for an explicitly permitted safe Filigree URL.

## Low Findings

### L-01: Analyzer reaches into `SummaryCache` private state

Severity: Low  
Locations:

- [src/wardline/scanner/analyzer.py:173](/home/john/wardline/src/wardline/scanner/analyzer.py:173)
- [src/wardline/scanner/taint/summary_cache.py:88](/home/john/wardline/src/wardline/scanner/taint/summary_cache.py:88)-97
- [src/wardline/scanner/taint/summary_cache.py:125](/home/john/wardline/src/wardline/scanner/taint/summary_cache.py:125)-134

Finding: analyzer logic reaches into `SummaryCache._entries`, which couples orchestration code to cache internals.

Remediation:

1. Add a public cache API such as `has_current(path, digest)` or `lookup_current(path, digest)`.
2. Move freshness checks into `SummaryCache`.
3. Update analyzer tests to assert behavior through the public API.

### L-02: `core.protocols` abstractions are declared but not wired

Severity: Low  
Locations:

- [src/wardline/core/protocols.py:14](/home/john/wardline/src/wardline/core/protocols.py:14)
- [src/wardline/core/protocols.py:18](/home/john/wardline/src/wardline/core/protocols.py:18)
- [src/wardline/core/run.py:96](/home/john/wardline/src/wardline/core/run.py:96)

Finding: protocol abstractions exist but are not meaningfully used by the orchestration surface.

Remediation:

1. Wire the protocols into `run_scan`/dependency construction if they represent intended extension seams.
2. Otherwise remove or deprecate them to reduce design noise.
3. Add tests only if the protocols are kept as supported extension points.

### L-03: Some tests mutate `sys.path` without cleanup

Severity: Low  
Locations:

- [tests/unit/core/test_packs.py:11](/home/john/wardline/tests/unit/core/test_packs.py:11)-14
- [tests/unit/core/test_judge_run.py:96](/home/john/wardline/tests/unit/core/test_judge_run.py:96)-105
- [tests/unit/cli/test_cli.py:114](/home/john/wardline/tests/unit/cli/test_cli.py:114)-143

Finding: some tests insert paths into `sys.path` directly. This can leak import state across tests.

Remediation:

1. Use `monkeypatch.syspath_prepend`.
2. Add fixtures that clean up import/module state after each test.
3. Keep dynamically created modules isolated per test.

### L-04: LSP input framing lacks a maximum `Content-Length`

Severity: Low  
Locations:

- [src/wardline/mcp/protocol.py:122](/home/john/wardline/src/wardline/mcp/protocol.py:122)-129
- [src/wardline/mcp/lsp.py:78](/home/john/wardline/src/wardline/mcp/lsp.py:78)
- [src/wardline/mcp/lsp.py:83](/home/john/wardline/src/wardline/mcp/lsp.py:83)-91

Finding: MCP line input has a 10 MB guard, but LSP-style `Content-Length` framing does not appear to enforce a comparable maximum body size.

Remediation:

1. Add a maximum LSP body size.
2. Reject or drain oversized frames deterministically.
3. Add tests for exactly-at-limit, over-limit, malformed, and missing-length frames.

### L-05: CLI `scan --fix` drops `strict_defaults` on post-fix rescan

Severity: Low  
Locations:

- [src/wardline/cli/scan.py:137](/home/john/wardline/src/wardline/cli/scan.py:137)-178

Finding: the first scan honors `strict_defaults`, but the post-fix rescan does not pass that setting through.

Remediation:

1. Pass `strict_defaults=strict_defaults` to the post-fix `run_scan` call.
2. Add a CLI regression test where strict defaults affect diagnostics before and after `--fix`.

## Prioritized Remediation Plan

1. Close direct trust-boundary vulnerabilities first: fix MCP waiver symlink confinement, validate autofix config values, and prevent untrusted project config from lowering judge assurance.
2. Restore scanner determinism next: make cold and warm scans produce identical L2-backed rule behavior, then add invariant tests.
3. Repair feedback loops: add Filigree clean-file heartbeat/reconciliation and validate close-on-fixed with live or contract e2e coverage.
4. Harden MCP contracts: block side-effecting notifications, reject unknown schema arguments, and make mutating tools idempotent.
5. Improve structural maintainability: split the MCP server, move identity types into a neutral module, and replace private cache access with public APIs.
6. Expand CI and tests: schedule live integration oracles, add Filigree unsafe-config tests, add nested-scope static-analysis fixtures, and clean `sys.path` mutation patterns.

## Suggested Acceptance Tests

- Cold scan and warm cached scan of the same fixture produce byte-for-byte equivalent diagnostics for L2-backed sink and PY-WL-105 cases.
- MCP `waiver_add` rejects an out-of-root symlinked `wardline.yaml`.
- Invalid `autofix.boundary_exception` values fail config validation before any AST edit is planned.
- Judge config cannot lower suppression threshold unless an explicit trust flag is supplied.
- A file with one Filigree-backed finding is fixed, rescanned clean, and the associated issue closes.
- No-id JSON-RPC `tools/call` notifications cannot mutate project state.
- MCP mutating tool calls with unknown keys return `isError`.
- CLI scans reject out-of-root source paths by default and allow them only with an explicit escape flag.

## Audit Limitations

- This was a static read-only audit. No source edits or test runs were performed as part of remediation.
- Live Clarion, Legis, Filigree, and external LLM judge services were not exercised.
- Findings were synthesized from code inspection and seven specialized read-only reviewer reports.
- The report should be treated as a remediation backlog plus a verification guide, not as proof that every listed bug is currently reproducible under all runtime configurations.
