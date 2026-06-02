# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Track 3 — SEI-client groundwork (T3.1–T3.3).** An opt-in `wardline[clarion]`
  SEI abstraction (`wardline.clarion.identity`) carries Clarion's Stable Entity
  Identity as the **opaque, preferred** cross-tool binding handle, with an honest
  **two-axis** status (identity alive/orphaned/unavailable × content fresh/stale/unknown,
  never collapsed). `SeiResolver` reads Clarion's `_capabilities` and **degrades
  gracefully** — when no `sei` capability is advertised it reports "identity
  unavailable" and keeps working on the locator, never guessing or crashing. The SEI
  is **never parsed** and **never enters Wardline finding fingerprints** (a golden-digest
  guard locks the fingerprint input set; the warm/cold byte-identical guarantee holds).
  Built against the spec'd wire contract (SEI standard §4 + Clarion ADR-038, pinned
  `/api/v1/identity/*` routes) and verified live against a real SEI-serving `clarion
  serve`. The base package stays zero-dependency (the module is stdlib-only). The
  locator→SEI fact re-key (T3.4) is gated on the coordinated suite SEI cutover.
- **Track 2 — extensible trust grammar.** The three trust decorators and four
  rules are no longer hardcoded: a project can declare custom **boundary types**
  (a trust transition + its L1 seed) and **rules** and register them via
  `wardline.scanner.grammar` — `default_grammar().extend(boundary_types=…, rules=…)`,
  run through `build_analyzer(grammar=…)`. The builtins are preloaded defaults and
  produce **byte-identical** findings to before (a corpus-wide golden enforces it);
  the released `wardline.core.registry` import surface is unchanged. The extension
  plane is a zero-dependency *code* seam (the same shape as `TaintSourceProvider`),
  not a config DSL.
- **`WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT** — a *custom* boundary type the engine
  cannot prove statically (an unreadable required level) seeds the fail-closed
  `UNKNOWN_RAW` **and** emits this observable FACT, so the extension plane inherits
  Wardline's no-false-green guarantee. Builtins stay silently fail-closed (oracle-
  preserving). A custom boundary stacked on a provable decorator is dragged to the
  fail-closed meet rather than silently over-trusted.

- **Track 1 — engine-quality floor.** A labeled false-positive corpus
  (`tests/corpus/`) with a manifest-driven FP-rate gate (≤5%; currently 0% over 21
  true-positive fixtures spanning control-flow joins, match arms, validators,
  broad/silent exceptions, aliased-stdlib sinks, and return indirection) plus
  waiver discipline (every waiver carries a reason; waiver count ≤ rule count).

### Fixed

- **Star-import false-negative** — `from wardline.decorators import *` now resolves
  the trust decorators statically (materialised from the in-process registry, never
  by importing/executing the target), so a `@trust_boundary`/`@trusted`/
  `@external_boundary` reached via star-import is seeded. Every other star import
  stays unresolved and keeps emitting the honest `WLN-ENGINE-UNKNOWN-IMPORT` FACT.
- **Explain provenance** — `compute_return_callee` resolves single-hop return
  indirection (`x = read_raw(p); return x`), so `explain`/PY-WL-101 names the
  contributing callee instead of `None`. Provenance only — taint values unchanged.

## [0.3.0] - 2026-05-31

### Added

- **`wardline install`** — one-command agent enablement. Injects a hash-fenced
  instruction block into `CLAUDE.md`/`AGENTS.md`, installs the `wardline-gate`
  skill into `.claude/`/`.agents/`, merges a `wardline` entry into `.mcp.json`,
  and detects Clarion/Filigree to record bindings in `wardline.yaml`.
  `clarion.url`/`filigree.url` are now runtime-read config fields (precedence:
  CLI flag > env var > `wardline.yaml`). Opt-out flags `--no-claude-md`,
  `--no-agents-md`, `--no-skill`, `--no-mcp`, `--no-bindings`; no SessionStart
  hook (re-run to refresh).

## [0.2.1] - 2026-05-31

### Added

- **Taint algebra concepts page + lattice-retention ADR** — a new
  `docs/concepts/taint-algebra.md` consolidates the taint-combination
  rationale (which operator runs where and why, the reachable-state set and its
  invariants, the per-rule consumption map, and the accepted "wrong-predicate
  validator" boundary) into one authoritative spec, and
  `docs/decisions/2026-05-31-wardline-taint-lattice-retain.md` records the
  decision to retain the 8-state lattice and the `taint_join` operator as the
  documented contrast operator (no production call site). Resolves the
  taint-combination audit findings F1, F3, F4, and F5.

### Changed

- **Reachable-state invariant now enforced at the taint parsers** — the two
  dynamic `TaintState` construction sites that previously accepted any canonical
  state are now constrained to their legal subsets: the bundled stdlib taint
  table accepts only `{ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}`, and the
  disk-persistent summary cache's deserialiser accepts the full reachable set
  `{INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}`. Both reject the
  never-produced trio (`MIXED_RAW`, `UNKNOWN_GUARDED`, `UNKNOWN_ASSURED`), so a
  corrupt/tampered cache file or a future stdlib-table entry carrying one is
  rejected (the cache file is dropped as cold-cache fallback) rather than
  silently injecting an otherwise-unreachable state. No behaviour change for
  valid inputs. Resolves audit finding F5.
- **Removed dead code in the L3 propagation kernel** — the unreachable inner
  unresolved-clamp in the per-SCC refinement round (subsumed by the preceding
  floor) was deleted, along with the now-orphaned `unresolved_counts` parameter
  of the internal `_compute_scc_round` helper. Behaviour-preserving. Resolves
  audit finding F2.
- **Corrected stale taint-combiner comments in the test suite** — the
  `test_variable_level.py` comments claiming control-flow merges "keep
  `taint_join`" predated the merge migration and misdescribed current behaviour;
  they now state those merges use `least_trusted` (wardline-4d9f840c24). Test
  comments only. Resolves audit finding F6.

### Fixed

- **Control-flow merge over-tainting (false positives)** — the statement-level
  control-flow merges (`if`/`else`, `for`/`while` back-edges, `try`/`except`
  handlers, `match` arms) combined per-variable taint via the provenance-clash
  join, so two clean-but-different-family branches (e.g.
  `if c: x = validate(p) else: x = guard(p)`) spuriously became `MIXED_RAW` and
  fired `PY-WL-101` on validated data. At a merge a variable holds the value of
  exactly one branch, so they now combine via the rank-meet weakest-link
  (`least_trusted`), matching the expression combiners; a raw branch still
  propagates and fires. This completes the `taint_join` → `least_trusted`
  migration for the L2 either-or paths.
- **L3 callee-combination over-tainting (false positives)** — the four
  callee-combination joins in the call-graph propagation engine
  (`minimum_scope.py`, plus `propagation.py`'s external-influence, Phase 1b
  seed-join, and per-round SCC refinement) combined the taints of a function's
  *set* of callees via the provenance-clash join. That is a function-summary
  aggregation of callee influence, not a single value built by merging two
  provenances, so a non-anchored function calling two clean-but-different-family
  callees (e.g. an `ASSURED` validator and an `INTEGRAL` helper) spuriously
  became `MIXED_RAW` (rank 7, in the firing raw zone) — an over-taint that,
  propagated up, fired `PY-WL-101` on clean data. All four sites now aggregate
  via the rank-meet weakest-link (`least_trusted`); a raw callee still
  propagates at its precise rank and fires. Completes the `taint_join` →
  `least_trusted` migration; the `taint_join` operator itself remains in
  `core/taints.py`.

## [0.2.0] - 2026-05-31

Adds a first-class MCP server and an opt-in persistent taint store, ships a
documentation site, and closes a taint soundness hole plus a batch of
hardening fixes. The base package stays zero-dependency.

### Added

- **MCP server** — a dependency-free, stdlib-only MCP-over-stdio server
  (`wardline mcp`, JSON-RPC 2.0, no SDK). Tools: `scan`, `explain_taint`,
  `judge` (network-fenced), `baseline_create`, `baseline_update`, `waiver_add`;
  resources `wardline://vocab|rules|config|config-schema` (findings are never a
  resource); one `wardline:loop` prompt. Tool-execution errors surface as
  `isError` results; protocol faults are JSON-RPC errors.
- **`explain_taint` provenance** — projects the real contributing return-taint
  callee for an anchored `PY-WL-101`, and (with the Clarion store) walks the
  full N-hop taint chain (`chain: true`, explicit truncation via `max_hops`).
- **Clarion taint store** — opt-in Clarion-backed persistent taint store
  (`wardline[clarion]` extra). `wardline scan --clarion-url` persists per-entity
  taint facts; `explain_taint` serves a fresh fact from the store behind a
  never-serve-stale `blake3` freshness gate, falling back to a local re-scan.
  HMAC auth is stdlib; `blake3` is the sole (lazy) extra dependency.
- **Documentation site** — a Material for MkDocs site (home, getting-started,
  concepts, guides, CLI + vocabulary reference, agent-integration), built
  `--strict` in CI and deployed to GitHub Pages. New `docs` extra; the base
  package stays zero-dependency.

### Fixed

- **Taint soundness (fail-open)** — the L2 resolver (`_resolve_expr`) fell
  through to the function taint for unmodelled AST shapes, which in a `@trusted`
  producer reset untrusted data to the trusted tier and emitted a clean report.
  f-strings, `str()`/`.format()`/`.join()`, `.get()`/subscript, BoolOp,
  attribute reads, `await`, comprehensions, container-writes, `self`-method
  calls, and aliased serialization sinks now propagate taint correctly.
- **Expression-combiner over-tainting (false positives)** — value-building /
  either-or / container-summary combiners (BinOp, IfExp, BoolOp, list/dict
  literals, comprehensions, `.get`/`.pop` defaults, `+=`, container writes)
  combined via the provenance-clash join, so a benign literal + validated data
  spuriously became `MIXED_RAW`. They now combine via the rank-meet
  weakest-link, matching the f-string/`.format`/`.join` paths; raw still
  propagates. Control-flow merges deliberately retain the provenance join.
- **Scan observability** — parse-error, unreadable, recursion-skipped, and
  missing-source-root files are now counted (`ScanSummary.unanalyzed`) and
  surfaced, with an opt-in `--fail-on-unanalyzed` gate.
- An explicit `--config` path that does not exist now errors instead of
  silently falling back to the default policy.
- Line-less engine-diagnostic findings no longer crash the scan.
- The MCP server returns an `isError` result (which clients reliably surface)
  for unexpected tool-handler exceptions instead of a dropped `-32603`.

### Security

- **Path confinement (THREAT-001 residual)** — a symlinked `.py` inside a
  source-root could escape the project root and be read out-of-tree via the MCP
  `scan` tool. Each discovered file is now resolved under the root when
  confinement is requested (MCP path); CLI default behavior is unchanged.

### Removed

- Dropped the unused `loom` optional-dependency extra (`httpx`). The Filigree
  emitter and Clarion producer-conformance support ship in `scanner` and use
  only the standard library (`urllib`), so the extra pulled in a dependency
  nothing imported.

## [0.1.0] - 2026-05-30

First public release. A generic, lightweight semantic-tainting static analyzer
for Python — enterprise-class trust-boundary analysis at small-team weight.

### Added

- **Taint engine** — AST-based semantic taint analysis with a trust lattice,
  call-graph propagation, function-summary caching, and `match`-statement
  handling. Zero runtime dependencies in the base package.
- **Trust vocabulary** — decorator-based trust markers (`@trusted`,
  `@boundary`, validators) resolved through a configurable vocabulary
  descriptor.
- **Rules** — `PY-WL-101` (untrusted-reaches-trusted), `PY-WL-102`
  (boundary-without-rejection), `PY-WL-103` (broad-except), `PY-WL-104`
  (silent-except), with per-rule severity overrides.
- **Outputs** — `wardline scan` emits findings as JSONL or SARIF, with a native
  Filigree emitter and Clarion producer-conformance support for Loom
  integration.
- **Suppression model** — baseline files and waivers (with expiry), plus an
  opt-in LLM triage layer.
- **LLM triage judge** — opt-in `wardline judge` reads each active finding cold
  and labels it true/false positive with a rationale, writing confirmed
  false positives to `.wardline/judged.yaml`. Dependency-free transport
  (stdlib `urllib` → OpenRouter); requires `WARDLINE_OPENROUTER_API_KEY`.
- **Configuration** — `wardline.yaml`, validated fail-loud against a JSON
  Schema (unknown or mistyped keys are hard errors).
- **Packaging** — MIT-licensed; optional extras `scanner` (config + CLI) and
  `loom` (HTTP integrations).

[Unreleased]: https://github.com/foundryside-dev/wardline/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/foundryside-dev/wardline/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/foundryside-dev/wardline/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/foundryside-dev/wardline/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/foundryside-dev/wardline/releases/tag/v0.1.0
