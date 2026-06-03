# Wardline Read-Only Audit Report

Date: 2026-06-04  
Scope: `/home/john/wardline`  
Mode: Strictly read-only code audit, except for this requested markdown artifact.  
Review structure: 7 specialized subagents: Architecture Critic, Systems Thinker, Python Engineer, Quality Engineer, Security Architect, Static Tools Analyst, and MCP & CLI Specialist. Each subagent was instructed to operate with `enable_write_tools=false`, `enable_mcp_tools=false`, and to avoid escaped double quotes in tool arguments.

No tests or linters were run. The audit used code reading and line-level verification only, to preserve the read-only boundary.

## Executive Summary

The strongest risk is an engine soundness failure: unresolved calls can inherit a trusted producer's taint instead of degrading to unknown/raw, allowing false-green results for `PY-WL-101`. Several high-severity issues then cluster around false negatives in sink detection, LSP path confinement, trust-policy weakening through project config, duplicate-definition handling, bound method argument binding, and silent fixed-point truncation.

Severity counts:

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 8 |
| Medium | 13 |
| Low | 8 |

## Critical

### C-01: Unresolved calls can retain the trusted caller taint

Locations:
- [src/wardline/scanner/taint/variable_level.py:488-510](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:488)
- [src/wardline/scanner/taint/callgraph.py:58-76](/home/john/wardline/src/wardline/scanner/taint/callgraph.py:58)
- [src/wardline/scanner/taint/propagation.py:557-568](/home/john/wardline/src/wardline/scanner/taint/propagation.py:557)

Impact: A `@trusted` function can return an unmodeled external call and still appear to return trusted data. This is a direct false-green risk for `PY-WL-101` and cuts against Wardline's fail-closed design.

Evidence: `_resolve_call` falls through to `return function_taint` after failing to resolve a call. In a trusted producer, that makes an unresolved call result inherit the producer seed. The call graph records unresolved calls, but the propagated diagnostic is low-resolution telemetry rather than a pessimistic taint.

Remediation:
- Change unresolved call expressions to produce `UNKNOWN_RAW` by default, or apply a pessimistic unresolved-call floor before return taint is evaluated by `PY-WL-101`.
- Keep the low-resolution diagnostic, but make it observable enough to prevent a false clean result where the returned value is part of a trust declaration.
- Add a regression fixture where a trusted producer returns an unresolved imported call, for example `@trusted(level=ASSURED) def f(x): return vendor.clean(x)`, and assert that it does not pass as `ASSURED`.

## High

### H-01: Dangerous sink rules miss aliased imports

Locations:
- [src/wardline/scanner/rules/_sink_helpers.py:51-82](/home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py:51)
- [src/wardline/scanner/context.py:78-105](/home/john/wardline/src/wardline/scanner/context.py:78)
- [src/wardline/scanner/rules/untrusted_to_deserialization.py:17-29](/home/john/wardline/src/wardline/scanner/rules/untrusted_to_deserialization.py:17)

Impact: Aliased sinks such as `import pickle as p; p.loads(raw)`, `import builtins as b; b.eval(raw)`, or `import subprocess as sp; sp.run(raw, shell=True)` can evade `PY-WL-106`, `PY-WL-107`, `PY-WL-108`, and related sink rules.

Evidence: `sink_calls()` reconstructs the raw dotted spelling from the AST and checks direct membership in a sink set. It does not canonicalize through `AnalysisContext.alias_maps`, although the alias maps already exist.

Remediation:
- Add a shared resolver that maps a call's dotted spelling through the module alias map before sink matching.
- Prefer storing canonical call FQNs during analysis so all sink rules consume the same resolved call identity.
- Add tests for `import x as y`, `from x import f`, and nested module aliases for each dangerous-sink rule.

### H-02: LSP can be re-rooted outside the launch root

Locations:
- [src/wardline/mcp/lsp.py:98-107](/home/john/wardline/src/wardline/mcp/lsp.py:98)
- [src/wardline/mcp/lsp.py:130-135](/home/john/wardline/src/wardline/mcp/lsp.py:130)
- [src/wardline/mcp/lsp.py:151-154](/home/john/wardline/src/wardline/mcp/lsp.py:151)

Impact: A client can start `wardline lsp --root /safe/project`, then send `initialize.rootUri` or `rootPath` pointing at any existing readable path. The server replaces `self.root`, and later `run_scan(self.root, confine_to_root=True)` confines to the attacker-selected root rather than the launch root.

Evidence: `initialize` trusts client-supplied roots if they exist, `didOpen` triggers a scan, and `run_and_publish()` scans the mutable `self.root`.

Remediation:
- Store an immutable launch root.
- Accept client roots and document URIs only if their resolved path is under the launch root.
- Otherwise ignore the client root, or reject it with an LSP diagnostic/log message.
- Add tests for attempted `rootUri` and `rootPath` escapes.

### H-03: Project config can disable or neutralize policy rules

Locations:
- [src/wardline/core/config.py:139-144](/home/john/wardline/src/wardline/core/config.py:139)
- [src/wardline/scanner/rules/__init__.py:84-90](/home/john/wardline/src/wardline/scanner/rules/__init__.py:84)
- [src/wardline/core/finding.py:51-57](/home/john/wardline/src/wardline/core/finding.py:51)
- [src/wardline/core/suppression.py:76-86](/home/john/wardline/src/wardline/core/suppression.py:76)

Impact: A scanned repository can set `rules.enable` to nonmatching patterns or override severities to `NONE`, producing active defects that do not trip `--fail-on`.

Evidence: Rule IDs are pattern-enabled without rejecting unknown/nonmatching policy. `Severity.NONE` is accepted as an override and is outside the gate ranking.

Remediation:
- Reject unknown rule patterns and empty effective rule sets by default.
- Disallow `NONE` severity overrides for defect rules unless an explicit trusted-policy mode is selected.
- Emit an active, gate-relevant finding when project config weakens the effective policy.
- Add tests for `rules.enable: [NO_SUCH_RULE]` and `rules.severity: {PY-WL-101: NONE}`.

### H-04: Duplicate function qualnames use first-wins semantics

Location:
- [src/wardline/scanner/index.py:68-88](/home/john/wardline/src/wardline/scanner/index.py:68)

Impact: Ordinary Python redefinition makes the later definition runtime-live, but Wardline keeps the first definition. Later trust decorators, raw returns, sinks, or contradictory declarations can be missed.

Evidence: The docstring says the first definition wins and notes that for plain redefinition this keeps the shadowed/dead node. The implementation skips later duplicates with `if qualname not in seen`.

Remediation:
- Use last-wins for normal redefinitions.
- Special-case overloads/properties where first-wins may be intentional.
- Alternatively emit a `WLN-ENGINE-DUPLICATE-QUALNAME` fact and merge/analyze all definitions conservatively.
- Add tests with duplicate `def f` where the second definition contains a trust violation.

### H-05: Bound method calls bind explicit arguments to `self` or `cls`

Locations:
- [src/wardline/scanner/analyzer.py:282-350](/home/john/wardline/src/wardline/scanner/analyzer.py:282)
- [src/wardline/scanner/taint/callgraph.py:59-70](/home/john/wardline/src/wardline/scanner/taint/callgraph.py:59)
- [src/wardline/scanner/taint/variable_level.py:403-420](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:403)

Impact: For calls like `self.helper(raw)`, the L2 argument collector records only explicit arguments, while the parameter binder maps positional argument 0 to the callee's first parameter. For instance methods, that is usually `self`, so the user data can be bound to the wrong parameter and cross-method taint can be lost.

Evidence: The call graph resolves `self.method(...)` to a project callee, but `_bind_call_site_arguments_to_parameters()` has no bound-method metadata and binds from the first parameter in the callee AST.

Remediation:
- Carry call-site metadata indicating whether a call was resolved as a bound instance/class method.
- When binding a bound method call, skip the implicit `self` or `cls` parameter before mapping explicit arguments.
- Add regressions for `self.helper(raw)` and `Cls.helper(raw)` where the callee sink or return depends on the second declared parameter.

### H-06: L2 fixed-point iteration silently truncates after 10 passes

Locations:
- [src/wardline/scanner/analyzer.py:495-559](/home/john/wardline/src/wardline/scanner/analyzer.py:495)
- [src/wardline/scanner/taint/variable_level.py:167-181](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:167)

Impact: Long parameter and attribute dependency chains can require more than ten propagation passes. If convergence is not reached, the loop exits silently after `range(10)`, leaving stale taint summaries and possible false negatives.

Evidence: The loop breaks only on equality of class-attribute taints and project parameter meets. There is no `else` branch after the loop to report non-convergence or pessimistically degrade affected values.

Remediation:
- Replace the fixed constant with a lattice-derived bound or a worklist algorithm.
- If convergence is not reached, emit a `WLN-ENGINE-L2-CONVERGENCE-BOUND` finding/fact and pessimistically degrade affected returns or call arguments.
- Add a long-chain regression that requires more than ten passes and asserts a visible diagnostic or correct convergence.

### H-07: `wardline judge` bypasses the canonical scan pipeline

Locations:
- [src/wardline/core/judge_run.py:160-165](/home/john/wardline/src/wardline/core/judge_run.py:160)
- [src/wardline/core/run.py:128-144](/home/john/wardline/src/wardline/core/run.py:128)
- [src/wardline/core/run.py:160-180](/home/john/wardline/src/wardline/core/run.py:160)

Impact: `wardline judge` and MCP `judge` can triage a different finding set than `wardline scan`. This violates the design rule that CLI and MCP behavior should be identical by construction and can miss pack grammar or run-scan engine facts.

Evidence: `run_judge()` directly calls `discover()` and `WardlineAnalyzer().analyze()`, while `run_scan()` loads trust grammar packs, adds source-root engine facts, saves cache, and applies the shared pipeline.

Remediation:
- Rework `run_judge()` to call `run_scan()` and then filter/triage the resulting active defects.
- Keep judge-specific options separate, but do not duplicate scan orchestration.
- Add parity tests asserting `judge` sees the same candidate defect fingerprints as `scan`.

### H-08: Optional dependency boundaries are leaky

Locations:
- [pyproject.toml:13-24](/home/john/wardline/pyproject.toml:13)
- [src/wardline/cli/main.py:9-24](/home/john/wardline/src/wardline/cli/main.py:9)
- [src/wardline/core/baseline.py:18](/home/john/wardline/src/wardline/core/baseline.py:18)
- [src/wardline/core/descriptor.py:27](/home/john/wardline/src/wardline/core/descriptor.py:27)
- [src/wardline/core/judged.py:19](/home/john/wardline/src/wardline/core/judged.py:19)
- [src/wardline/core/waivers.py:18](/home/john/wardline/src/wardline/core/waivers.py:18)
- [src/wardline/scanner/taint/stdlib_taint.py:19](/home/john/wardline/src/wardline/scanner/taint/stdlib_taint.py:19)

Impact: The project advertises a zero-dependency base package, but base/core/scanner modules import `yaml`, and the console entrypoint imports `click`. A base install without the `scanner` extra can fail at import time in ordinary command paths.

Evidence: `pyproject.toml` keeps `dependencies = []` while the `scanner` extra contains `pyyaml`, `jsonschema`, and `click`. Multiple core/scanner modules import `yaml` at module import time.

Remediation:
- Either make the CLI/scanner extra mandatory for the console script, or split entrypoints so base import paths remain dependency-free.
- Move YAML-dependent helpers behind lazy imports with clear `WardlineError` messages when extras are missing.
- Add packaging tests that install the base distribution without extras and import the intended base modules.

## Medium

### M-01: LSP scan failures and engine facts can become editor false-greens

Locations:
- [src/wardline/mcp/lsp.py:151-161](/home/john/wardline/src/wardline/mcp/lsp.py:151)
- [src/wardline/cli/scan.py:148-150](/home/john/wardline/src/wardline/cli/scan.py:148)
- [src/wardline/mcp/server.py:840-843](/home/john/wardline/src/wardline/mcp/server.py:840)

Impact: Bad config, unreadable paths, or engine failures produce no LSP error and no diagnostics. The LSP also publishes only active defects, so `WLN-ENGINE-*` facts can be invisible in the editor even though they matter to fail-closed observability.

Evidence: `run_and_publish()` catches `Exception` and returns. CLI and MCP surfaces map `WardlineError` to explicit failure payloads.

Remediation:
- Catch `WardlineError` separately and publish a workspace diagnostic or `window/showMessage`/`window/logMessage`.
- Do not catch all exceptions without surfacing an error.
- Decide whether engine facts should appear as informational diagnostics in LSP; if not, publish a summary diagnostic for under-scan states.

### M-02: LSP advertises full document sync but ignores `didChange`

Locations:
- [src/wardline/mcp/lsp.py:114-119](/home/john/wardline/src/wardline/mcp/lsp.py:114)
- [src/wardline/mcp/lsp.py:124-149](/home/john/wardline/src/wardline/mcp/lsp.py:124)
- [src/wardline/mcp/lsp.py:153-154](/home/john/wardline/src/wardline/mcp/lsp.py:153)

Impact: Clients are told to send full text changes, but the server does not handle `textDocument/didChange` and scans disk. Diagnostics can be stale until save.

Evidence: `textDocumentSync.change` is set to `1`, while handled text-document methods omit `didChange`; scans call `run_scan(self.root, confine_to_root=True)`.

Remediation:
- Advertise save-only synchronization, or maintain open-document buffers and analyze the current buffer state.
- Add LSP tests for unsaved changes and save events.

### M-03: LLM judge places project-supplied policy in the system message

Locations:
- [src/wardline/core/judge_run.py:82-95](/home/john/wardline/src/wardline/core/judge_run.py:82)
- [src/wardline/core/judge.py:230-244](/home/john/wardline/src/wardline/core/judge.py:230)

Impact: `judge.policy_file` comes from the scanned project but is appended to the policy block sent as a system message. A malicious or careless project can steer the judge toward `FALSE_POSITIVE`, especially when `--write` persists judgments.

Evidence: `resolve_policy_block()` labels project policy as untrusted but returns it inside the block consumed by `build_messages()` as `role: system`.

Remediation:
- Do not put project policy in a system message.
- Send project policy as quoted untrusted user data, or restrict it to an allow-listed data format.
- Require an explicit trusted-config flag before loading project-supplied judge policy.

### M-04: `new_since` is passed to Git without option hardening

Locations:
- [src/wardline/core/delta.py:35-47](/home/john/wardline/src/wardline/core/delta.py:35)
- [src/wardline/core/run.py:182-184](/home/john/wardline/src/wardline/core/run.py:182)
- [src/wardline/cli/scan.py:63-67](/home/john/wardline/src/wardline/cli/scan.py:63)
- [src/wardline/mcp/server.py:143-146](/home/john/wardline/src/wardline/mcp/server.py:143)

Impact: CLI and MCP callers can pass a string beginning with `-` as `new_since`. Git may parse it as an option rather than a revision.

Evidence: `get_changed_files_since()` runs `git diff --name-only ref` without validating the ref or inserting `--end-of-options`/`--`.

Remediation:
- Reject refs beginning with `-`.
- Validate with `git rev-parse --verify --end-of-options <ref>`.
- Pass a verified object ID to `git diff`, and use `--` before pathspecs if pathspecs are added later.
- Add CLI and MCP tests for option-like refs.

### M-05: Installer and write helpers follow symlinks

Locations:
- [src/wardline/install/block.py:40-57](/home/john/wardline/src/wardline/install/block.py:40)
- [src/wardline/install/mcp_json.py:15-35](/home/john/wardline/src/wardline/install/mcp_json.py:15)
- [src/wardline/install/detect.py:57-80](/home/john/wardline/src/wardline/install/detect.py:57)
- [src/wardline/core/attest_key.py:55-79](/home/john/wardline/src/wardline/core/attest_key.py:55)

Impact: Running `wardline install --root` on an untrusted checkout can write through symlinked fixed targets such as `AGENTS.md`, `CLAUDE.md`, `.mcp.json`, `.env`, `.gitignore`, or `wardline.yaml`.

Evidence: These helpers use `Path.read_text()` and `Path.write_text()` on project-relative paths without resolving the final target and checking it remains under root.

Remediation:
- Resolve every target before writing and require it to remain under the selected root.
- Reject symlinks for fixed install targets, or use no-follow/openat-style safe writes.
- Add tests with symlinked `AGENTS.md`, `.mcp.json`, `.env`, and `wardline.yaml`.

### M-06: Trust-grammar packs are imported from project config during scans

Locations:
- [src/wardline/core/config.py:107-132](/home/john/wardline/src/wardline/core/config.py:107)
- [src/wardline/core/run.py:128-141](/home/john/wardline/src/wardline/core/run.py:128)

Impact: Safe YAML parsing is followed by Python imports named by `packs:`. Local project packs are blocked by default, but any importable installed package still executes import-time code when an untrusted repo requests it.

Evidence: `load()` imports each `pack_name` with `importlib.import_module(pack_name)`, and `run_scan()` imports packs again to load `trust_grammar`.

Remediation:
- Treat packs as trusted extensions, not untrusted project data.
- Require an explicit allow-list or command-line flag such as `--trust-pack NAME`.
- Default untrusted scans should fail on or ignore `packs:` with a visible diagnostic.
- Avoid double imports by carrying loaded pack metadata from config loading into scan execution.

### M-07: Baseline creation bypasses `run_scan`

Location:
- [src/wardline/core/baseline.py:94-106](/home/john/wardline/src/wardline/core/baseline.py:94)

Impact: Baselines can be built from a finding set that differs from ordinary scans. Pack grammar, run-level engine facts, cache behavior, and future `run_scan` logic can drift from baseline creation.

Evidence: `collect_and_write_baseline()` directly calls discovery and `WardlineAnalyzer().analyze()` instead of `run_scan()`.

Remediation:
- Make baseline creation call `run_scan()` and filter the resulting findings according to the baseline command's intent.
- Add a parity test where a config pack or missing source root affects `run_scan()` and ensure baseline creation sees the same finding fingerprints.

### M-08: L3 invariant failures and convergence bound handling are too quiet

Locations:
- [src/wardline/scanner/taint/propagation.py:430-451](/home/john/wardline/src/wardline/scanner/taint/propagation.py:430)
- [src/wardline/scanner/taint/propagation.py:506-548](/home/john/wardline/src/wardline/scanner/taint/propagation.py:506)
- [src/wardline/scanner/diagnostics.py:25-30](/home/john/wardline/src/wardline/scanner/diagnostics.py:25)
- [src/wardline/core/suppression.py:76-84](/home/john/wardline/src/wardline/core/suppression.py:76)

Impact: If L3 hits a convergence bound or post-fixed-point invariant failure, users may not see a gate-relevant indication that the project was under-analyzed.

Evidence: The convergence bound becomes `WLN-L3-CONVERGENCE-BOUND` with `Kind.METRIC`, which does not trip gates. Post-fixed-point assertion failures log and return seed-only provenance.

Remediation:
- Promote unexpected L3 invariant failures to active `Kind.DEFECT` engine findings.
- For convergence bounds, either prove the branch unreachable and keep it internal, or surface it as a gate-relevant under-scan fact.
- Add tests asserting that each fail-closed L3 escape path reaches CLI and MCP output.

### M-09: Package `__init__.py` relative imports resolve incorrectly

Locations:
- [src/wardline/scanner/analyzer.py:145](/home/john/wardline/src/wardline/scanner/analyzer.py:145)
- [src/wardline/scanner/ast_primitives.py:21-27](/home/john/wardline/src/wardline/scanner/ast_primitives.py:21)
- [src/wardline/scanner/ast_primitives.py:70-72](/home/john/wardline/src/wardline/scanner/ast_primitives.py:70)
- [src/wardline/core/qualname.py:56-60](/home/john/wardline/src/wardline/core/qualname.py:56)

Impact: Relative imports in package `__init__.py` can be resolved as if the module were not a package, which can break cross-module call and sink resolution for package-level exports.

Evidence: `build_import_alias_map()` supports `is_package`, and `qualname` collapses `pkg.__init__` to `pkg`, but the analyzer call does not pass `is_package=True` for `__init__.py`.

Remediation:
- Detect package `__init__.py` in the analyzer and pass `is_package=True`.
- Add regression tests for `from .mod import f` inside `pkg/__init__.py`.

### M-10: Unknown-import diagnostics ignore plain `import X`

Locations:
- [src/wardline/scanner/diagnostics.py:176-206](/home/john/wardline/src/wardline/scanner/diagnostics.py:176)
- [src/wardline/scanner/ast_primitives.py:50-53](/home/john/wardline/src/wardline/scanner/ast_primitives.py:50)

Impact: Unresolved external packages imported with `import pkg` are not observable as `WLN-ENGINE-UNKNOWN-IMPORT`, even though they can later produce unresolved calls.

Evidence: `diagnose_unknown_imports()` walks the tree but immediately continues unless the node is `ast.ImportFrom`; `build_import_alias_map()` handles `ast.Import`.

Remediation:
- Add an `ast.Import` branch to `diagnose_unknown_imports()`.
- Apply the same project/stdlib/type-checking exclusions and stable fingerprint logic used for `ImportFrom`.
- Add tests for `import vendor` and `import vendor as v`.

### M-11: MCP schema validation silently disables itself without `jsonschema`

Location:
- [src/wardline/mcp/server.py:826-832](/home/john/wardline/src/wardline/mcp/server.py:826)

Impact: If `jsonschema` is unavailable, MCP tool argument validation is skipped. Invalid payloads then reach handlers, increasing inconsistent error mapping and unexpected behavior.

Evidence: `_tools_call()` imports `jsonschema` inside the validation block and `except ImportError: pass`.

Remediation:
- Use a tiny internal validator for the limited tool schemas, or make `jsonschema` part of the MCP runtime dependency contract.
- If validation cannot run, return a clear `isError` tool result rather than silently continuing.

### M-12: Warm-cache parity test is vacuous

Location:
- [tests/unit/cli/test_cli.py:123-149](/home/john/wardline/tests/unit/cli/test_cli.py:123)

Impact: A core invariant says warm cache and cold cache must produce byte-identical non-metric findings. The current test fixture emits no non-metric findings, so the equality assertion can pass even if warm-cache analysis is wrong.

Evidence: The fixture is `def f(p): return p`, and `_non_metric(f1) == _non_metric(f2)` effectively compares empty lists.

Remediation:
- Use a fixture that produces at least one stable non-metric finding, such as a leaky trusted producer.
- Assert the exact fingerprint set and compare serialized non-metric findings between cold and warm runs.
- Include a cache-hit metric assertion separately.

### M-13: `new_since` CLI and MCP wiring lacks coverage

Locations:
- [src/wardline/cli/scan.py:63-67](/home/john/wardline/src/wardline/cli/scan.py:63)
- [src/wardline/mcp/server.py:143-146](/home/john/wardline/src/wardline/mcp/server.py:143)
- [src/wardline/mcp/server.py:528-532](/home/john/wardline/src/wardline/mcp/server.py:528)
- [tests/unit/core/test_scan_delta.py:13-90](/home/john/wardline/tests/unit/core/test_scan_delta.py:13)

Impact: Core delta behavior has tests, but the CLI option and MCP schema/handler wiring can drift without detection.

Evidence: Tests exercise `run_scan(new_since=...)`; coverage of `wardline scan --new-since` and MCP `scan` with `new_since` is absent from the cited paths.

Remediation:
- Add CLI tests using `CliRunner` for `--new-since`.
- Add MCP `tools/call scan` tests verifying `new_since` reaches `run_scan()` and invalid refs surface as tool errors.

## Low

### L-01: Direct `config.untrusted_sources` entity matches are not marked used

Locations:
- [src/wardline/scanner/analyzer.py:152-166](/home/john/wardline/src/wardline/scanner/analyzer.py:152)
- [src/wardline/scanner/analyzer.py:591-603](/home/john/wardline/src/wardline/scanner/analyzer.py:591)
- [src/wardline/scanner/taint/call_taint_map.py:148-154](/home/john/wardline/src/wardline/scanner/taint/call_taint_map.py:148)

Impact: A configured source that directly matches an entity qualname is seeded as `EXTERNAL_RAW`, but can still produce a misleading `WLN-CONFIG-UNUSED-SOURCE` fact.

Evidence: Analyzer seeding handles direct entity matches, while `matched_sources` is updated only in `build_call_taint_map()`.

Remediation:
- Add `matched_sources.add(ent.qualname)` when direct entity source matching applies.
- Add a test where an entity source is used directly and no unused-source fact is emitted.

### L-02: Non-object JSON-RPC params can become internal errors

Locations:
- [src/wardline/mcp/protocol.py:66-90](/home/john/wardline/src/wardline/mcp/protocol.py:66)
- [src/wardline/mcp/server.py:817-824](/home/john/wardline/src/wardline/mcp/server.py:817)

Impact: A malformed request with non-object `params` can reach handlers and fail as an internal error instead of an invalid-params fault.

Evidence: `dispatch()` uses `params = message.get("params") or {}` without type validation, and `_tools_call()` assumes `params.get`.

Remediation:
- Validate that top-level `params` is an object for methods that require object params.
- Return `McpError(..., code=-32602)` for protocol shape violations.
- Add protocol tests for list/string/null params.

### L-03: LSP diagnostics copy Python AST offsets as LSP character offsets

Locations:
- [src/wardline/scanner/index.py:93-99](/home/john/wardline/src/wardline/scanner/index.py:93)
- [src/wardline/mcp/lsp.py:173-190](/home/john/wardline/src/wardline/mcp/lsp.py:173)

Impact: Diagnostic columns can point at the wrong character on lines containing non-ASCII text. Python AST columns are byte offsets; LSP positions are UTF-16 code units.

Evidence: Scanner locations are populated from `child.col_offset` and `child.end_col_offset`; LSP copies those values directly into diagnostic ranges.

Remediation:
- Convert stored offsets to UTF-16 positions using source line text when rendering LSP diagnostics.
- Alternatively store location units explicitly and convert at every protocol boundary.
- Add a non-ASCII source fixture with asserted LSP ranges.

### L-04: Filigree dossier reader lacks scheme validation

Locations:
- [src/wardline/filigree/dossier_client.py:41-56](/home/john/wardline/src/wardline/filigree/dossier_client.py:41)
- [src/wardline/core/config.py:174-186](/home/john/wardline/src/wardline/core/config.py:174)

Impact: Other HTTP clients restrict schemes, but the dossier reader calls `urlopen()` directly. `_is_safe_url()` checks localhost hostnames but does not enforce `http` or `https`.

Evidence: `UrllibTransport.get()` passes the URL directly into `urllib.request.Request`; config URL safety only checks hostname.

Remediation:
- Apply the same `http`/`https` allow-list used by the other integration clients.
- Add config tests for non-HTTP schemes and localhost hostnames.

### L-05: Protocol and parsing paths lack size limits

Locations:
- [src/wardline/mcp/protocol.py:115-120](/home/john/wardline/src/wardline/mcp/protocol.py:115)
- [src/wardline/mcp/lsp.py:76-87](/home/john/wardline/src/wardline/mcp/lsp.py:76)
- [src/wardline/scanner/analyzer.py:140-142](/home/john/wardline/src/wardline/scanner/analyzer.py:140)

Impact: Very large JSON-RPC/LSP messages or Python files can consume local process memory and CPU.

Evidence: Protocol readers allocate based on `Content-Length`, and analyzer reads source text before AST parsing without a visible default size cap.

Remediation:
- Add maximum JSON-RPC and LSP message sizes.
- Add a maximum source file size default that emits an observable `WLN-ENGINE-*` fact when exceeded.
- Add tests for bounded reads and oversized source files.

### L-06: `own_nodes()` yields nested scope boundary nodes despite its own-scope contract

Location:
- [src/wardline/scanner/rules/_ast_helpers.py:146-158](/home/john/wardline/src/wardline/scanner/rules/_ast_helpers.py:146)

Impact: The helper says it yields nodes in the current scope while skipping nested scopes, but `_walk_own()` still yields nested `FunctionDef`, `AsyncFunctionDef`, `ClassDef`, and `Lambda` boundary nodes. This is a maintainability risk for future rules.

Evidence: Nested scope nodes are yielded and only their descendants are skipped.

Remediation:
- Clarify the docstring if boundary nodes are intentionally yielded.
- Otherwise skip yielding nested boundary nodes entirely.
- Add tests that define exactly which nodes a rule helper may see.

### L-07: Dogfood CI self-scan can upload SARIF findings without failing

Locations:
- [.github/workflows/ci.yml:74-75](/home/john/wardline/.github/workflows/ci.yml:74)
- [tests/test_self_hosting.py:10-22](/home/john/wardline/tests/test_self_hosting.py:10)

Impact: The workflow runs a SARIF self-scan but does not pass `--fail-on`. The Python self-hosting test bypasses CLI, config loading, SARIF emission, suppression, and `run_scan()`.

Evidence: CI runs `uv run wardline scan src/ --format sarif --output results.sarif`. The test directly constructs `WardlineAnalyzer()` with default config.

Remediation:
- Add `--fail-on ERROR` or the intended threshold to the CI self-scan.
- Replace or supplement the direct analyzer test with a `run_scan()` or CLI-level test.

### L-08: `find_spec()` local-pack preflight can import parent packages

Locations:
- [src/wardline/core/config.py:64-91](/home/john/wardline/src/wardline/core/config.py:64)
- [src/wardline/core/config.py:107-132](/home/john/wardline/src/wardline/core/config.py:107)

Impact: `_is_local_pack()` uses `importlib.util.find_spec(pack_name)` before deciding whether a pack is local. For dotted pack names, `find_spec()` can import the parent package, so preflight may execute import-time code before local-pack rejection.

Evidence: The preflight is meant to avoid loading project-local packs unless trusted, but it still asks importlib to resolve the name.

Remediation:
- Avoid `find_spec()` on untrusted dotted names before policy is decided.
- Resolve project-local candidates by filesystem inspection under the scan root first.
- Require explicit trusted-pack mode before importlib is allowed to import any pack named by project config.

