# Wardline Read-Only Audit Synthesis

Date: 2026-06-04  
Repository: `/home/john/wardline`  
Mode: strictly read-only code review and research. The only workspace write was this requested report artifact.

## Scope And Method

Seven specialized read-only subagents reviewed the codebase with `enable_write_tools=false` and `enable_mcp_tools=false` in their task contracts: Architecture Critic, Systems Thinker, Python Engineer, Quality Engineer, Security Architect, Static Tools Analyst, and MCP & CLI Specialist. I then verified and de-duplicated the strongest claims against the live tree using read-only inspection commands.

No tests were run because even normal pytest/mypy runs can write caches or coverage state. Existing `AUDIT.md` and `wardline-readonly-audit-2026-06-04.md` were left untouched.

## Executive Summary

No Critical findings were confirmed.

The highest-risk issues cluster around four themes:

- Several public non-scan CLI/core flows do not enforce the source-root confinement that `scan` and MCP now enforce.
- Scanner soundness has false-negative gaps around modern Python constructs and call argument unpacking.
- Trust/evidence artifacts can diverge from the effective scan policy, especially baseline generation and attestation policy identity.
- Live CI oracles can pass as skipped, so external integration drift can be missed.

## Critical

No Critical findings confirmed.

## High

### H1. Non-scan trust/evidence entrypoints can scan outside the selected project root

Locations:
- [src/wardline/core/discovery.py:17-48](/home/john/wardline/src/wardline/core/discovery.py:17)
- [src/wardline/cli/scan.py:99-153](/home/john/wardline/src/wardline/cli/scan.py:99)
- [src/wardline/cli/assure.py:35-40](/home/john/wardline/src/wardline/cli/assure.py:35)
- [src/wardline/core/assure.py:233-251](/home/john/wardline/src/wardline/core/assure.py:233)
- [src/wardline/cli/attest.py:90-119](/home/john/wardline/src/wardline/cli/attest.py:90)
- [src/wardline/core/attest.py:173-193](/home/john/wardline/src/wardline/core/attest.py:173), [src/wardline/core/attest.py:226-255](/home/john/wardline/src/wardline/core/attest.py:226)
- [src/wardline/cli/dossier.py:66-72](/home/john/wardline/src/wardline/cli/dossier.py:66)
- [src/wardline/loom_dossier.py:60-69](/home/john/wardline/src/wardline/loom_dossier.py:60)
- [src/wardline/core/dossier.py:628-650](/home/john/wardline/src/wardline/core/dossier.py:628)
- [src/wardline/cli/judge.py:116-129](/home/john/wardline/src/wardline/cli/judge.py:116)
- [src/wardline/core/judge_run.py:128-182](/home/john/wardline/src/wardline/core/judge_run.py:128)
- [src/wardline/core/baseline.py:77-131](/home/john/wardline/src/wardline/core/baseline.py:77)
- MCP contrast: [src/wardline/mcp/server.py:240-323](/home/john/wardline/src/wardline/mcp/server.py:240)

Evidence: `discover()` only rejects escaping `source_roots` and symlinked Python files when `confine_to_root=True`. The canonical `scan` CLI passes `confine_to_root=not allow_source_root_escape`, and tests pin that default. MCP wrappers also pass `confine_to_root=True` for dossier, assure, attest, verify, and judge. The CLI/core paths for assure, attest, dossier, judge, and baseline use defaults or calls that leave confinement off.

Impact: A poisoned in-repo `wardline.yaml` can point `source_roots` outside the selected project. That can make assurance posture, attestations, judge excerpts, dossiers, or baselines incorporate out-of-root files while the canonical scan/MCP surfaces would reject the same scope. The judge path is especially sensitive because excerpts may be sent to OpenRouter.

Remediation: Make public builder defaults `confine_to_root=True`. Pass `confine_to_root=True` from all CLI entrypoints. Add explicit opt-out flags only where intentionally supported, mirroring `scan --allow-source-root-escape`. Add regression tests for escaping `source_roots` across `assure`, `attest --reproduce`, `dossier`, `judge`, and baseline create/update.

### H2. Persistent taint summary cache can be poisoned into false-green scans

Locations:
- [src/wardline/scanner/taint/summary_cache.py:217-270](/home/john/wardline/src/wardline/scanner/taint/summary_cache.py:217)
- [src/wardline/scanner/taint/project_resolver.py:113-143](/home/john/wardline/src/wardline/scanner/taint/project_resolver.py:113)

Evidence: `SummaryCache.load()` accepts any syntactically valid `<cache_dir>/<hex>.json` payload and deserializes `FunctionSummary.cache_key` from the body, but does not verify that every loaded summary's `cache_key` matches the filename key. The resolver then trusts `summary_cache.get(cache_key)` directly for clean modules.

Impact: If a CI cache or project cache directory is attacker-controlled or stale in a malicious way, forged summaries can replace fresh analysis and suppress real findings.

Remediation: Treat persistent cache files as untrusted. On load, require `summary.cache_key == path.stem` for every summary and reject mixed-FQN or mismatched records. Consider authenticated cache records or disabling persistent cache for security gates. Add tests where a valid JSON cache file has a mismatched internal key and must fall back to fresh summarization.

### H3. Attestation `ruleset_hash` omits effective scan policy inputs

Locations:
- [src/wardline/core/attest.py:100-114](/home/john/wardline/src/wardline/core/attest.py:100)
- [src/wardline/core/attest.py:188-223](/home/john/wardline/src/wardline/core/attest.py:188)
- [src/wardline/core/config.py:31-49](/home/john/wardline/src/wardline/core/config.py:31)
- [src/wardline/core/config.py:197-214](/home/john/wardline/src/wardline/core/config.py:197)

Evidence: `ruleset_hash()` hashes only sorted `rules_enable`, sorted `rules_severity`, and Wardline version. It omits fields that materially change scan results, including `source_roots`, `exclude`, `untrusted_sources`, `sanitisers`, `provenance_clash`, custom packs, and pack grammar/config effects.

Impact: Two attestations can share the same policy identity while scanning different files or using different trust semantics. Downstream governance consumers may treat non-equivalent evidence bundles as comparable.

Remediation: Replace `ruleset_hash()` with a canonical effective-scan-policy hash. Include source scope, excludes, rules, severity, provenance policy, custom sources/sanitisers, trusted pack names and versions/hashes, and grammar-affecting pack data. Add tests proving each policy-affecting field changes the signed policy identity.

### H4. Baseline generation bypasses the shared scan pipeline

Locations:
- [src/wardline/core/run.py:78-152](/home/john/wardline/src/wardline/core/run.py:78)
- [src/wardline/core/baseline.py:77-108](/home/john/wardline/src/wardline/core/baseline.py:77)
- [src/wardline/cli/main.py:59-105](/home/john/wardline/src/wardline/cli/main.py:59)
- [src/wardline/mcp/server.py:348-367](/home/john/wardline/src/wardline/mcp/server.py:348)

Evidence: `run_scan()` constructs the configured grammar, summary cache, trust-pack behavior, strict defaults, and analyzer. `collect_and_write_baseline()` loads config with default trust flags, calls `discover()` directly, and constructs `WardlineAnalyzer()` directly.

Impact: A baseline can differ from the scan/gate population. Custom grammar findings can be omitted or baseline generation can fail/differ where scan succeeds with explicit trust options. That weakens baseline suppression as an auditable snapshot of the actual gate.

Remediation: Generate baselines from `run_scan()` or a shared `ScanOptions` pipeline. Thread `trust_local_packs`, `trusted_packs`, `strict_defaults`, cache options, and confinement through baseline CLI/MCP APIs. Add a regression test where a trusted pack emits a custom finding and baseline creation captures the same finding as `scan`.

### H5. Multiple `**kwargs` unpackings overwrite earlier taints

Locations:
- [src/wardline/scanner/taint/variable_level.py:430-447](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:430)
- [src/wardline/scanner/analyzer.py:380-388](/home/john/wardline/src/wardline/scanner/analyzer.py:380)
- [src/wardline/scanner/rules/_sink_helpers.py:172-179](/home/john/wardline/src/wardline/scanner/rules/_sink_helpers.py:172)

Evidence: Every keyword unpack records `resolved_args[kw.arg] = t`. For `**kwargs`, `kw.arg is None`, so `callee(**raw_kwargs, **clean_kwargs)` records only the last unpack. Interprocedural binding and sink helpers consume the single `None` value.

Impact: Raw keyword flows can disappear from PY-WL-105, sink rules, and callee parameter propagation. This is a scanner false negative.

Remediation: Store each `**` unpack separately or combine duplicate `None` entries with `combine()`. Update `_bind_call_site_arguments_to_parameters()` and `worst_arg_taint()` to aggregate all unpack taints. Add regression tests where raw unpack appears before a clean unpack.

### H6. Starred unpack targets can lose raw taint

Locations:
- [src/wardline/scanner/taint/variable_level.py:228-237](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:228)
- [src/wardline/scanner/taint/variable_level.py:724-744](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:724)
- [tests/unit/scanner/taint/test_variable_level.py:1089-1097](/home/john/wardline/tests/unit/scanner/taint/test_variable_level.py:1089)

Evidence: Element-wise unpack handles `ast.Name` and nested tuple/list targets, but skips `ast.Starred`. Later reads of the starred target fall back to function-level taint if no binding exists. The existing test documents that the middle starred target is skipped and does not assert `b`.

Impact: `(a, *rest, c) = (clean, raw, clean); return rest` inside a trusted producer can suppress PY-WL-101 and downstream sink findings.

Remediation: Bind starred targets to the captured RHS slice when statically available, or conservatively bind to the whole RHS taint. Add PY-WL-101 and variable-level regression tests for starred unpack targets.

### H7. `AsyncFor`, `TryStar`, and `except*` handlers are skipped by taint/rule traversal

Locations:
- [src/wardline/scanner/taint/variable_level.py:602-619](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:602)
- [src/wardline/scanner/taint/variable_level.py:627-629](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:627)
- [src/wardline/scanner/taint/variable_level.py:1226-1251](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:1226)
- [src/wardline/scanner/rules/_ast_helpers.py:32-37](/home/john/wardline/src/wardline/scanner/rules/_ast_helpers.py:32)
- [src/wardline/scanner/rules/broad_exception.py:49-56](/home/john/wardline/src/wardline/scanner/rules/broad_exception.py:49)
- [src/wardline/scanner/rules/silent_exception.py:49-56](/home/john/wardline/src/wardline/scanner/rules/silent_exception.py:49)

Evidence: L2 statement dispatch handles `For`, `Try`, `With`, `AsyncWith`, and `Match`, but not `AsyncFor` or `TryStar`; unhandled statements only get walrus scanning. `own_except_handlers()` only yields handlers from `ast.Try`, so PY-WL-103/PY-WL-104 miss `except*`.

Impact: Raw assignments inside `async for` or `except*` paths can be missed, and trusted-tier `except* Exception: pass` can evade broad/silent exception rules.

Remediation: Route `ast.AsyncFor` through loop handling and `ast.TryStar` through try handling. Update `_ast_helpers.own_except_handlers()` to include `ast.TryStar`. Add fixtures for `async for` taint propagation and `except*` PY-WL-103/PY-WL-104 findings.

### H8. Comprehension walrus writeback ignores existing outer variables

Location:
- [src/wardline/scanner/taint/variable_level.py:361-404](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:361)

Evidence: The PEP 572 writeback loop only writes `var_taints[name] = taint` when `name not in var_taints`. That handles new walrus targets but skips rebinding an existing outer variable.

Impact: If `x` starts trusted and a comprehension executes `(x := read_raw(p))`, `x` can remain trusted in the outer taint map. Later trusted returns or sinks using `x` can be missed.

Remediation: For names proven by `_name_bound_by_walrus()`, write back the local taint whether the name is new or existing. Add tests for existing clean variables overwritten inside list/set/dict/gen comprehensions.

### H9. Live oracle CI can pass without running the live oracle

Locations:
- [.github/workflows/ci.yml:84-135](/home/john/wardline/.github/workflows/ci.yml:84)
- [tests/e2e/test_judge_live.py:12-38](/home/john/wardline/tests/e2e/test_judge_live.py:12)
- [tests/e2e/test_legis_live.py:55-65](/home/john/wardline/tests/e2e/test_legis_live.py:55)
- [tests/e2e/test_filigree_promote_live.py:44-47](/home/john/wardline/tests/e2e/test_filigree_promote_live.py:44)
- [tests/unit/test_ci_live_oracles.py:6-14](/home/john/wardline/tests/unit/test_ci_live_oracles.py:6)

Evidence: Scheduled/manual jobs run marker-selected live tests, but tests skip when secrets, services, or routes are absent. The workflow summary explicitly says missing local services or secrets are reported as skipped tests. The default workflow guard only asserts some live markers and summary text, not a required no-skip mode.

Impact: Weekly/manual CI can be green when OpenRouter, Clarion, Legis, or Filigree coverage did not actually execute, so integration drift is not caught.

Remediation: Add a required live-oracle mode such as `WARDLINE_LIVE_ORACLE_REQUIRED=1` that turns missing secrets/services/capabilities into failures. Add workflow preflights or pytest no-skip enforcement. Extend `test_ci_live_oracles.py` to assert the network judge job, required secret env, live-oracle matrix, and required-mode behavior.

## Medium

### M1. MCP request validation accepts invalid IDs and maps malformed params to internal errors

Locations:
- [src/wardline/mcp/protocol.py:55-102](/home/john/wardline/src/wardline/mcp/protocol.py:55)
- [src/wardline/mcp/server.py:834-853](/home/john/wardline/src/wardline/mcp/server.py:834)
- [tests/unit/mcp/test_protocol.py:96-105](/home/john/wardline/tests/unit/mcp/test_protocol.py:96)

Evidence: The server treats presence of the `id` key as a request, so `id: null` is accepted and tested as a valid request. It handles `initialize` before the notification gate, so an `initialize` notification can produce a response. It also assigns `params = message.get("params") or {}` without validating that `params` is an object; `_tools_call()` then assumes `.get()`, so array/string params can become `-32603` internal errors.

Protocol reference: the current MCP spec says requests must include a string or integer ID, IDs must not be null, and notifications must not include IDs or receive responses. See [MCP messages](https://modelcontextprotocol.io/specification/2025-06-18/basic/index). MCP tool malformed-request errors should be protocol errors rather than tool execution errors; see [MCP tools error handling](https://modelcontextprotocol.io/specification/draft/server/tools).

Impact: Strict clients can reject the server, and malformed tool envelopes produce opaque internal errors instead of stable `-32602` invalid-params responses.

Remediation: Validate request IDs before method dispatch. Reject `id is None` and non-string/non-integer IDs with `-32600`. Treat messages without `id`, including `initialize`, as notifications with no response or reject them via documented policy. Validate `params`, `name`, and `arguments` shape before handler calls and return `McpError(..., code=-32602)` for envelope faults. Replace the `id:null` test with conformance rejection tests.

### M2. Filigree dossier URL scheme and network body sizes are not consistently bounded

Locations:
- [src/wardline/core/config.py:237-249](/home/john/wardline/src/wardline/core/config.py:237)
- [src/wardline/filigree/dossier_client.py:41-56](/home/john/wardline/src/wardline/filigree/dossier_client.py:41)
- [src/wardline/core/judge.py:276-286](/home/john/wardline/src/wardline/core/judge.py:276)
- [src/wardline/clarion/client.py:48-59](/home/john/wardline/src/wardline/clarion/client.py:48)
- [src/wardline/core/filigree_emit.py:107-122](/home/john/wardline/src/wardline/core/filigree_emit.py:107)

Evidence: `_is_safe_url()` checks localhost hostnames but not scheme. The Filigree dossier client does not enforce `http`/`https` before `urllib.request.urlopen()`. Several network transports read response and error bodies with unbounded `resp.read()` or `exc.read()`.

Impact: Config URLs like `file://localhost/...` can pass the localhost check in some paths, and compromised or misconfigured endpoints can return oversized bodies that exhaust memory or produce excessive exception text.

Remediation: Require `http`/`https` in `_is_safe_url()` and in `FiligreeWorkProvider` transport. Add a shared bounded-read helper for normal and error bodies. Truncate logged/raised response text. Add tests for `file://`, `ftp://`, schemeless URLs, and oversized response bodies.

### M3. Autofix can report success when the write failed

Location:
- [src/wardline/core/autofix.py:152-220](/home/john/wardline/src/wardline/core/autofix.py:152)

Evidence: `applied[rel_path].append(...)` happens before the file write, and the write is wrapped in `contextlib.suppress(Exception)`.

Impact: `wardline fix` or MCP autofix can tell automation a fix was applied even when the file was not changed, leaving the finding in place and making follow-up scan state confusing.

Remediation: Write first and handle `OSError` explicitly. Only append/report applied fixes after a successful write. Return structured failures or raise `WardlineError` when a requested write fails.

### M4. MCP Filigree emission softens protocol rejection into a nested warning

Locations:
- [src/wardline/core/filigree_emit.py:141-148](/home/john/wardline/src/wardline/core/filigree_emit.py:141)
- [src/wardline/cli/scan.py:196-216](/home/john/wardline/src/wardline/cli/scan.py:196)
- [src/wardline/mcp/server.py:44-58](/home/john/wardline/src/wardline/mcp/server.py:44)
- [src/wardline/mcp/server.py:141-180](/home/john/wardline/src/wardline/mcp/server.py:141)

Evidence: Core/CLI treat Filigree 3xx/4xx rejection as loud `FiligreeEmitError`. MCP `_emit_filigree()` catches `FiligreeEmitError` and returns `filigree.reachable=false` inside an otherwise successful scan payload.

Impact: Agents can consume a successful MCP scan summary/gate while tracker emission or reconciliation was rejected, creating drift between local scan state and work-tracker state.

Remediation: Preserve loud failure semantics for Filigree protocol/client errors in MCP, or expose a top-level `tracker_reconciled=false` / `emission_error` contract that consumers must handle. Align docs and tests with the chosen behavior.

### M5. Interprocedural call binding over-taints impossible parameters

Locations:
- [src/wardline/scanner/analyzer.py:334-388](/home/john/wardline/src/wardline/scanner/analyzer.py:334)
- [tests/unit/scanner/rules/test_wave2_engine_precision.py:70-99](/home/john/wardline/tests/unit/scanner/rules/test_wave2_engine_precision.py:70)

Evidence: Starred taint is appended to every positional parameter, and `**kwargs` taint is appended to positional-only, already-filled, vararg, kw-only, and kwargs slots. The existing test explicitly expects all positional parameters to become contaminated from `*args`.

Impact: PY-WL-105 and sink rules can report raw flow into parameters that Python call binding could not actually populate. This is a precision regression and can inflate false positives.

Remediation: Model `inspect.Signature` binding more closely: explicit positional args first, star args only remaining positional/vararg slots, kwargs only unfilled keyword-capable slots. Keep conservative fallback only when static binding cannot determine a safe subset.

### M6. `AnalysisContext` read-only contract is shallow

Locations:
- [src/wardline/scanner/context.py:28-45](/home/john/wardline/src/wardline/scanner/context.py:28)
- [src/wardline/scanner/context.py:85-115](/home/john/wardline/src/wardline/scanner/context.py:85)

Evidence: The docstring says inner mappings are wrapped read-only, but also notes `function_var_taints` inner dicts are left by convention. `__post_init__()` wraps several outer mappings only; nested maps remain mutable for some fields.

Impact: A rule can mutate nested context state and affect later rules, making rule ordering a hidden input.

Remediation: Deep-freeze nested mappings or provide isolated per-rule views. Add a test rule that attempts to mutate nested context and assert later rules are unaffected.

### M7. SARIF serialization reaches into scanner internals

Locations:
- [src/wardline/core/sarif.py:66-93](/home/john/wardline/src/wardline/core/sarif.py:66)
- [src/wardline/core/sarif.py:117-125](/home/john/wardline/src/wardline/core/sarif.py:117)

Evidence: `core.sarif` imports private scanner/rule helpers and re-derives sink provenance from `AnalysisContext` internals.

Impact: `core` is not a pure shared contract layer for SARIF; scanner refactors can silently break SARIF code-flow/provenance output.

Remediation: Move code-flow/provenance projection to a public scanner explain API or stable DTO, and let SARIF serialize that public contract.

## Low

### L1. PY-WL-109 treats `Any` as a non-None promise

Location:
- [src/wardline/scanner/rules/none_leak.py:66-124](/home/john/wardline/src/wardline/scanner/rules/none_leak.py:66)

Evidence: `_annotation_allows_none()` recognizes `None`, `Optional`, `Union`, and `| None`, but not `Any` or `typing.Any`. Any other explicit annotation is treated as a non-None promise.

Impact: Functions annotated `-> Any` can get false-positive None-leak findings.

Remediation: Treat `Any` and `typing.Any` as not promising non-None. Add direct and string-annotation tests.

### L2. Live judge cache oracle is tautological and CI guard misses the network job

Locations:
- [tests/e2e/test_judge_live.py:14-38](/home/john/wardline/tests/e2e/test_judge_live.py:14)
- [tests/unit/test_ci_live_oracles.py:6-14](/home/john/wardline/tests/unit/test_ci_live_oracles.py:6)
- [.github/workflows/ci.yml:84-98](/home/john/wardline/.github/workflows/ci.yml:84)

Evidence: The live judge test docstring says the second call hits cache, but the assertion allows `prompt_tokens_cached is None` or `>= 0`, including zero. The CI guard checks the live-oracle matrix markers but not the scheduled `network` job.

Impact: Prompt-cache telemetry or network-job workflow drift can pass unnoticed.

Remediation: Either require a positive cached-token signal where provider cache is contractual, or remove the cache-hit claim and assert only schema-critical fields. Extend the workflow guard to include the `network` job, marker, schedule condition, and API-key environment.

### L3. Clarion live oracle setup is fragile

Locations:
- [tests/e2e/test_clarion_live.py:39-69](/home/john/wardline/tests/e2e/test_clarion_live.py:39)
- [tests/e2e/test_clarion_live.py:142-164](/home/john/wardline/tests/e2e/test_clarion_live.py:142)

Evidence: Route support is inferred by running `strings` over the binary and searching for a literal route. `_free_port()` binds port `0`, releases it, then the subprocess later tries to bind the chosen port.

Impact: Valid Clarion builds can be skipped falsely, and port reuse races can make the live oracle flaky.

Remediation: Prefer runtime capability probing after launch. Let explicit `WARDLINE_CLARION_BIN` proceed to runtime probing. Use a bind-to-port-0 server mode if Clarion supports it, or otherwise remove the open-port race.

### L4. Protocol/package boundaries need clearer ownership

Locations:
- [src/wardline/mcp/lsp.py:1-2](/home/john/wardline/src/wardline/mcp/lsp.py:1)
- [src/wardline/cli/lsp.py:1-10](/home/john/wardline/src/wardline/cli/lsp.py:1)
- [src/wardline/mcp/server.py:517-807](/home/john/wardline/src/wardline/mcp/server.py:517)
- [src/wardline/mcp/server.py:834-877](/home/john/wardline/src/wardline/mcp/server.py:834)

Evidence: LSP lives under the MCP package, and the MCP registry mixes read-only, mutating, and network tools in one registration/dispatch path without central capability enforcement despite tool metadata such as `network=True`.

Impact: Future read-only/no-network MCP modes have no central enforcement point, and package ownership is muddy.

Remediation: Move LSP to `wardline.lsp` or `wardline.protocols.lsp` with a compatibility re-export. Add tool capability classes and enforce read/write/network policy at dispatch.

### L5. Scanner orchestration has hidden global seams

Locations:
- [src/wardline/scanner/analyzer.py:76-152](/home/john/wardline/src/wardline/scanner/analyzer.py:76)
- [src/wardline/scanner/analyzer.py:319-485](/home/john/wardline/src/wardline/scanner/analyzer.py:319)
- [src/wardline/scanner/analyzer.py:504-778](/home/john/wardline/src/wardline/scanner/analyzer.py:504)
- [src/wardline/scanner/taint/variable_level.py:78-92](/home/john/wardline/src/wardline/scanner/taint/variable_level.py:78)

Evidence: Analyzer orchestration combines parsing, cache, L1/L2/L3 flow, diagnostics, and rule dispatch. It mutates private contextvars from `variable_level.py` to pass call-site state.

Impact: Stage boundaries are hard to test independently, and private global/contextvar state increases refactor risk.

Remediation: Split the scanner into explicit pipeline stages with typed inputs/outputs, and pass taint-analysis context explicitly instead of mutating private globals.

## Suggested Remediation Order

1. Fix H1 root confinement first because it is a trust-boundary and possible data-exfiltration issue, especially for `judge`.
2. Fix scanner false negatives next: H5, H6, H7, H8. Add focused failing tests before implementation.
3. Fix evidence identity drift: H3 and H4, then add parity tests between scan, baseline, attest, CLI, and MCP.
4. Harden cache trust (H2) and network/MCP protocol behavior (M1, M2, M4).
5. Tighten CI live-oracle required mode (H9) so future integrations fail loudly when not actually exercised.

## Verification Notes

- Verified current tree with read-only commands only.
- No source files were modified.
- No tests were run to avoid cache/coverage writes.
- External protocol references used only official Model Context Protocol documentation:
  - [MCP current basic messages](https://modelcontextprotocol.io/specification/2025-06-18/basic/index)
  - [MCP tools error handling](https://modelcontextprotocol.io/specification/draft/server/tools)
