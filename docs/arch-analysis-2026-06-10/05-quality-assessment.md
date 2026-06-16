# Architecture Quality Assessment — High-Risk Areas

**Source:** Four-lens parallel specialist review (security / engine soundness / architecture / verification), each grounded in direct file reads of the working tree at `rc5` @ `21aeffaa`.
**Assessed:** 2026-06-10
**Assessor:** architecture-critic synthesis (panel: threat-analyst, python-code-reviewer, architecture-critic, coverage-gap-analyst)

## Executive Summary

The codebase's security architecture is strong — THREAT-001 path confinement holds across every new MCP tool, the secure-by-default gate population is structurally enforced, and rekey cannot launder verdicts. The highest risks are elsewhere: **the CI self-hosting scan has no gate** (wardline does not fail its own build on its own findings), **active false-negative soundness gaps in the taint engine's chokepoint** (`_resolve_expr`/`_resolve_call` and loop merging), and **a structural drift seam** (un-layered `core/` held together by 158 deferred imports; the Rust frontend bolted alongside Python with no frontend abstraction). 2 Critical, 8 High findings.

## Findings by Severity

### Critical

1. **CI self-hosting scan is SARIF-upload only — no gate** — verified: `.github/workflows/ci.yml:76` runs `wardline scan src/ --format sarif` with no `--fail-on`; the step succeeds regardless of findings. `tests/test_self_hosting.py` is additionally vacuous by construction (no decorators in own source → tier-gated rules never fire).
   - **Impact:** wardline can ship a trust-boundary violation in itself with a green build — direct credibility risk for a trust-boundary gate product.
   - **Fix:** add `--fail-on ERROR` to the CI step; add an annotated fixture module so self-scan exercises the real pipeline. Effort: S.

2. **All live wire-contract oracles are weekly/manual only** — verified: `pyproject.toml:121` addopts excludes `loomweave_e2e`/`legis_e2e`/`filigree_e2e`/`rust_e2e`; the live job is `schedule`/`workflow_dispatch`-gated. Hermetic pins (legis key-set freeze, loomweave HMAC golden vector) do run in PR CI, but a sibling-side wire change surfaces only at the next weekly run. Known ticket `wardline-79ba05f464` (G6) covers the SEI-oracle half.
   - **Impact:** wire-breaking drift across the federation seams merges green and fails up to a week later.
   - **Fix:** fail-closed weekly job + a required `WARDLINE_LIVE_ORACLE_REQUIRED=1` escape hatch; land G6. Effort: M.

### High — Engine soundness (the product's core value)

3. **Zero-trip loop FN is real and the merge structure confirms it** (`scanner/taint/variable_level.py:1350–1394`): the post-loop state never re-merges `pre_loop` as a fallthrough arm, so a loop that *cleans* a RAW variable hides the zero-iteration path where it stayed RAW. Matches open bug `wardline-d6af917bde` (currently P3 — under-prioritized for a soundness FN). Fix is localized: combine post-loop state with `pre_loop`. Effort: S.

4. **Raw-receiver `taint_map` bypass** (`variable_level.py:740–828`): for attribute calls, the `taint_map` hit returns early *before* the RAW_ZONE receiver guard, so `raw_obj.trusted_method()` can launder taint when the receiver's type isn't tracked. Same family as the scrub's PY-WL-105/stale-var_types cluster. Fix: apply/combine the receiver guard before the `taint_map` lookup. Effort: S–M. *(Confidence: Moderate — trigger needs an untyped raw receiver; confirm with a unit test first.)*

5. **`collect_attribute_writes` is flow-insensitive with its own uncoordinated `var_types`** (`variable_level.py:1617–1703`): resolves RHS taint against final-state `var_taints`, not per-statement snapshots; branch-stale types can dispatch to `@trusted` summaries for now-raw receivers. *(Confidence: Moderate — the L2 fixed-point re-run in `analyzer.py:476` may partially compensate; verify empirically.)*

### High — Structure

6. **`core/` is un-layered: real import cycles + an engine→policy inversion, masked by 158 function-local deferred imports.** Verified cycles include `core.run → scanner.analyzer → … → core.attest → core.assure → core.run`; the inversion is `scanner/taint/project_resolver.py:143` importing `core.attest.ruleset_hash` (taint engine depending on the attestation layer). Every refactor near these modules risks surfacing masked breakage. Fix: `import-linter` contracts in report-only mode, then move `ruleset_hash` down a tier. Effort: M.

7. **Rust frontend is a parallel vertical, not a plugged-in frontend.** Only `Finding`/`TaintState` are shared (`core/protocols.py:17`); context, rules, vocabulary, dataflow, qualname, and Finding-assembly are all reimplemented under `rust/`. A third language costs a third full vertical, and rule/severity/identity semantics will drift between the two rule trees. Fix: lift a `LanguageFrontend` interface before any third language. Effort: L.

8. **MCP-vs-CLI surface drift seam is structural.** The `run_scan` spine is genuinely shared (strength), but the federation-status envelope is duplicated (`mcp/server.py:73,94` vs `cli/scan.py:450,480`) — exactly where the two dogfood drift incidents occurred — and `_register_tools` (`server.py:822–1271`) is a 450-line change-magnet. Fix: one shared status projector + per-tool schema declarations. Effort: M.

### High — Verification gaps in trust-critical paths

9. **Rekey adversarial scenarios untested**: mixed-scheme partial-migration state (one leg done, source changed before resume) and multi-store rollback (only single-store restore is tested, `tests/unit/core/test_rekey_rollback.py` has 2 tests). Rekey moves user trust decisions; rollback is the recovery path. Effort: S–M.

10. **Tier-suppression negative tests absent**: no unit tests assert rules do NOT fire below the tier gate (e.g. `UNKNOWN_RAW` context); a silently loosened gate would only be caught if the pattern happens to exist in the labeled corpus. Effort: S.

### Medium

- **Symlinked `.env`/federation-token reads bypass `safe_project_file`** (`filigree/config.py:49,68`, `core/judge_run.py:67` — vs `attest_key.py:28`/`legis.py:143` which do it right): an attacker-authored repo can symlink `.env` out of root and wardline sends the first matching line as a bearer token to the configured sibling URL. The one security finding warranting a code change. Effort: S.
- **Judge prompt-injection surface is structural but contained**: attacker-authored source reaches the LLM; an injected FALSE_POSITIVE verdict feeds `judged.yaml` — but the secure-default gate ignores judged without `--trust-suppressions`, so no silent gate clear. Keep that invariant; document advisory status.
- **Rust qualname corpus has no drift alarm**: vendored byte-pinned at a loomweave blob; ADR-049 has already moved three times, each needing a manual re-vendor with no CI cross-check. Plus the known reserved-colon locator bug (`wardline-be5ee9cc34`) emits invalid locators with no degrade gate → fingerprint churn on the eventual fix.
- **Rust `write!`/`writeln!`/`format_args!` not modelled** in `rust/dataflow.py:202–214` (`format!` only) — tainted format strings through writers don't fire.
- **Three federation clients hand-roll the urllib transport independently** (`core/filigree_emit.py:229`, `filigree/dossier_client.py:50`, `loomweave/client.py`); only `read_response_text` is shared. Auth ladders should stay separate; the transport should not.
- **Corpus FP-rate gate has zero FALSE_POSITIVE-labeled entries** — the 5% budget math is never exercised against real corpus data.

### Low (selected)

- `resolve_under_root` is escape-rejecting but not symlink-refusing (unlike `safe_project_file`) — fine for today's read-only consumers; document the contract before any write path uses it.
- `attest`/`verify_attestation` is sound (timing-safe compare, schema/key_id binding); missing-`schema`-key and non-dict-payload edges untested.
- L2 loop-convergence backstop truncates silently (`variable_level.py:1362,1393`) with no `WLN-ENGINE-*` diagnostic, unlike the L3 bound.
- `time.sleep(0.1)` polling in `tests/e2e/test_loomweave_live.py:108,121`.

## Cross-Cutting Concerns

**Security:** Strong posture. Path confinement uniform across all MCP tools (including args never opened); secure-by-default gate population architecturally enforced (`run.py:87,298–301`); rekey carry keyed on finding-derived fingerprints (no laundering primitive); `install/block.py` injector hardened; secrets never read from `weft.toml`. The residual real item is the symlink token-read inconsistency.

**Correctness:** The lattice discipline (`combine` vs `taint_join`) is rigorous and the L3 kernel monotone-guarded, but FN risk concentrates in `_resolve_expr`/`_resolve_call` (`variable_level.py:449,647`) — the shared chokepoint where the historical bug record also clusters. That chokepoint, not the file's 1,885-line length, is the real change-magnet; don't split the file for size's sake, invest in differential/property tests around the chokepoint.

**Maintainability:** `core/paths.py` is a genuinely clean single source of truth for stores/config; the zero-dep constraint is well-contained. The debts are the un-layered `core/`, the duplicated Rust vertical, and the duplicated surface envelopes.

## Priority Recommendations

1. **Gate the CI self-scan** (`--fail-on ERROR` + non-vacuous fixture) — Critical, Effort S. A trust-gate product that doesn't gate itself is the cheapest, highest-credibility fix available.
2. **Fix the zero-trip loop FN** (re-merge `pre_loop`) and **confirm/fix the raw-receiver `taint_map` bypass** — Critical-class soundness in the core engine, Effort S each. Re-prioritize `wardline-d6af917bde` above P3.
3. **Close the symlinked token-read gap** (route filigree/judge `.env`+token reads through `safe_project_file` + regression test) — Medium severity, Effort S, restores the codebase's own established discipline.
4. **Land `import-linter` contracts (report-only) + fix the `project_resolver → core.attest` inversion** — High, Effort M; unblocks all future structural work.
5. **Rekey adversarial tests** (mixed-scheme partial, multi-store rollback) + **tier-suppression negative tests** — High, Effort S–M; protects user trust decisions.
6. **Before a third language: `LanguageFrontend` interface** — High, Effort L; the one item that caps the product ceiling.

## Limitations

- High-level risk review, not an exhaustive audit. Not reviewed: `core/triage.py`, `core/source_excerpt.py`, full `install/*`, `loomweave/client.py` send-side internals, LSP beyond delegation check.
- Engine findings 4–5 are structurally verified but not empirically reproduced — write the confirming unit tests before fixing (`wardline-d6af917bde`'s pattern: naive fixes here have regressed before).
- Loomweave index was empty (`never_analyzed`); the import-cycle graph was hand-built via AST and should be cross-checked after `loomweave analyze .`.
- No tests were executed; severity ratings assume the documented threat model (attacker authors repo content scanned by wardline).
