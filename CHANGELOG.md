# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- MCP `scan` now emits findings to Filigree when a `--filigree-url` is configured, at
  parity with the CLI (a `filigree` block in the scan result; fail-soft — an unreachable
  sibling or rejected payload is reported, never fails the scan). Closes the CLI/MCP
  finding-emission asymmetry. (WS-A1)
- MCP `scan` gains a server-side `where` filter (rule_id/qualname/severity/suppression/kind/
  path_glob/sink/tier) and an `explain: true` mode that inlines each active defect's taint
  provenance — killing the scan-then-N-explains round-trips. New read-only `wardline findings`
  CLI verb shares the same filter core. (WS-B1, WS-B2)

## [1.0.0rc1] - 2026-06-02

### Changed

- **Cross-method class-attribute taint (soundness closure A).** Raw assigned to
  `self.<attr>` in one method and returned from (or passed to a sink in) ANOTHER
  method used to escape — the engine was function-level. A per-class attribute
  summary (the least-trusted value written to each `self.<attr>` across all methods)
  now seeds reads of that attribute, so `PY-WL-101`/`105` and the sink rules see raw
  data surfaced via instance state. This does NOT over-fire on the common OO shapes
  (validated setter + trusted getter, lazy-init): a `@trust_boundary`-validated write
  is trusted, so the summary stays trusted — measured FP=0 on hand-built patterns and
  on the dogfood + corpus trees. Two bounded residual FNs (never over-fires): a deep
  `self.y = self.x` attribute-to-attribute chain may under-resolve, and the attribute
  summary does not feed back into the L3 fixed point (attr-derived taint surfaced
  through a non-anchored method's return won't propagate to that method's callers).
- **Flow-sensitive sink-arg taint (soundness closure E).** The sink rules
  (`PY-WL-106`/`107`/`108`) and `PY-WL-105` now resolve a call argument's taint AT
  the sink statement, not from the function's final per-variable map. This closes a
  documented two-way imprecision: a variable trusted at the sink but reassigned raw
  *after* it no longer over-fires (a false positive), and one raw at the sink but
  sanitised *after* it now correctly fires (a fail-open it previously missed). The
  L2 walker captures a per-statement var-taint snapshot (`function_call_site_taints`
  on the analysis context); the expression combinators are unchanged.

### Internal

- **Soundness-regression locks for closures B / C / D.** Probing the Track-1.6
  candidate FN closures found three already sound — `*args`/`**kwargs` at call
  sites, comprehension/walrus targets, and decorator-wrapped (`functools.wraps`)
  callees all propagate taint correctly. Pinned with regression tests so a future
  refactor cannot silently reopen them. (No engine change for B/C/D.)

### Added

- **`PY-WL-111` — trust boundary whose only rejection path is `assert` (CWE-617).**
  A `@trust_boundary` that rejects bad input only via `assert` validates in
  development but is stripped under `python -O`, so the rejection silently
  vanishes in production. The one genuinely-generic, FP-safe builtin still worth
  adding (framework-specific sinks belong in opt-in trust-grammar packs).
  Declaration-gated, `ERROR`, partitions cleanly with `PY-WL-102`: 102 fires when
  a boundary cannot reject at all, 111 when it appears to reject but only via an
  `-O`-stripped guard. The shared `has_rejection_path` helper now counts `assert`
  so the two never double-fire.
- **Test guards (no behavior change):** a rule-examples meta-test asserting every
  builtin rule's `examples_violation`/`examples_clean` actually fire / stay clean
  (caught and fixed rotted `PY-WL-101` examples that referenced an undefined
  helper); a `RAW_ZONE` ↔ `TRUST_RANK` consistency pin; `least_trusted`
  idempotence + associativity (exhaustive); a fingerprint-stability test pinning
  the real anchor-line contract (anchor-preserving edits stay byte-identical, a
  line-shifting edit changes it by design); and a CLI ↔ MCP finding-parity
  differential guarding the "identical by construction" tenet.

- **Track 5 — trust-vocabulary convergence + legis CI (T5.1–T5.3).** The final
  Wardline track: one trust vocabulary, one judge, proven against legis. All
  Wardline-repo-only (legis is a fixed external contract; elspeth is inspiration
  only — no import, no linkage). The convergence was found to be *already
  substantially true*, so this track is proof + documentation that locks it in.
  - **T5.1 — vocabulary convergence (gap-check):** `docs/concepts/trust-vocabulary-convergence.md`
    records a keep/adopt/drop sweep of the trust effects elspeth pioneered against
    the Loom mechanisms that already deliver them — fabrication test ≈ PY-WL-102,
    custody ≈ the lattice + `taint_provenance`, fail-closed ≈ `UNKNOWN_*` +
    `WLN-ENGINE-*` FACTs (incl. `WLN-ENGINE-UNPROVABLE-BOUNDARY`), tiered boundary ≈
    `@trust_boundary(to_level=…)`, one-judge ≈ legis carrying Wardline's 8 tiers
    verbatim. All Covered; a `tier=` alias and a duplicate worked example are
    explicitly Dropped (the T2 extension-plane fixture `custom_grammar.py` already
    demonstrates an elspeth-style tiered boundary). No engine/decorator change.
  - **T5.2 — legis intake conformance:** Wardline's emitted findings/gate already
    match legis's `from_wire` ingest contract (verified: `severity` name, `kind`,
    `suppressed` values all align). A hermetic always-on contract test
    (`tests/conformance/test_legis_intake_contract.py`) vendors legis's contract and
    proves a real scan ingests cleanly and that legis's active-defect selection
    reproduces Wardline's own `summary.active` gate population (one judge: legis
    reads the verdict, never re-derives it). A new opt-in `legis_e2e` marker drives a
    live round-trip oracle (`tests/e2e/test_legis_live.py`) against a running legis's
    `POST /wardline/scan-results`, auto-skipping when absent.
  - **T5.3 — hash-granularity harmonisation:** an ADR
    (`docs/decisions/2026-06-02-wardline-hash-granularity-two-model.md`) formalizes
    the two-granularity model — whole-file (taint-store freshness,
    `content_hash_at_compute` ↔ Clarion `current_file_hash`) vs entity-body
    (identity/association drift, Clarion resolve `content_hash` ↔ Filigree
    `content_hash_at_attach`) — and the never-cross-compare rule. Discipline tests
    (`tests/conformance/test_hash_granularity.py`) lock the false-STALE-never
    property and guard that `content_status` is only called from the entity-body
    surface. No new hashing, no store change.
- **Track 4 — the Loom entity dossier (assembler + live wiring, T4.1–T4.3).** One
  freshness-honest call returns everything an agent needs to reason about a function
  without reading its source. Wardline is the **assembler** (composes each tool's
  slice; it does not become the store).
  - `core/dossier.py` — the `EntityDossier` envelope: frozen, JSON-serialisable, keyed
    on the **opaque SEI**, freshness-stamped on **both orthogonal axes** (identity
    alive/orphaned/unavailable × content fresh/stale/unknown, never collapsed). The
    default envelope is **token-bounded ≤2k** via a conservative deterministic estimator;
    over-budget content is trimmed with an explicit, elision-honest truncation marker
    (shown-of-total), and an untrimmable core is reported as EXCEEDS-budget — never a
    silent cap. `build_dossier` composes Wardline's OWN trust posture for real (re-scan
    → FRESH) with a **three-valued honest verdict** (defect / clean / **unknown** — an
    undeclared or under-scanned entity is never reported "clean"), and reads Clarion
    linkages + Filigree work through injected `LinkageProvider`/`WorkProvider` seams.
    An absent / no-opinion / unreachable source degrades to an honest `unavailable`
    section — never fabricated, never a crash.
  - `clarion/client.py` — `get_callers`/`get_callees` (HMAC-gated call-graph reads,
    fail-soft); `clarion/dossier_sources.py` — `ClarionLinkageProvider` (live linkages,
    SEI identity axis + FRESH live-read content axis, one-sided outages named) and
    `resolve_entity_binding` (qualname → locator → opaque SEI binding via the Track-3
    `SeiResolver`; never mints or parses the SEI).
  - `filigree/dossier_client.py` — a dep-free urllib `FiligreeWorkProvider` reading
    ADR-029 entity-associations keyed on the SEI; compares `content_hash_at_attach`
    (same entity-body granularity as Clarion's resolve) to set per-ticket **DRIFT** and
    a three-valued section content axis (STALE / UNKNOWN / FRESH — never guesses FRESH).
  - `loom_dossier.py` — `build_loom_dossier`, the orchestrator: probe Clarion
    capabilities once, resolve the SEI binding, wire both providers, call the
    source-agnostic core assembler. Degrades honestly with whatever sources are present.
  - **Surface:** `wardline dossier <qualname>` (CLI) and a `dossier` MCP tool, both thin
    delegators to `build_loom_dossier` (CLI and MCP identical by construction — a parity
    test asserts byte-identical envelopes). `wardline mcp` gains `--filigree-url`.
  - The base package stays **zero-dependency** (the Filigree reader is stdlib urllib;
    Clarion-consuming code lives behind the existing `wardline[clarion]` extra). Verified
    by a live `clarion_e2e` one-call dossier round-trip against a real `clarion serve`.
- **Track 1.5 — rule-set breadth (4 → 10 curated rules).** Six new trust-taint rules,
  authored on the Track 2 grammar, each fail-closed/opt-in with violation+clean examples
  and labeled corpus fixtures (corpus FP rate stays 0%):
  - **PY-WL-105** — untrusted data passed to a trusted callee at a call site (CWE-501);
    the call-site analogue of PY-WL-101. Fires only on provably-untrusted args.
  - **PY-WL-106** — untrusted data reaches a deserialization sink (pickle/marshal/yaml.load, CWE-502).
  - **PY-WL-107** — untrusted data reaches a dynamic-code-execution sink (eval/exec/compile, CWE-95).
  - **PY-WL-108** — untrusted data reaches an OS-command sink (os.system/subprocess.*, CWE-78).
  - **PY-WL-109** — None leaks from a trusted producer (mixed value + bare/None return, CWE-394).
  - **PY-WL-110** — contradictory trust declaration (≥2 distinct trust markers on one entity).
  105–108 are call-site rules; 106/107/108 are tier-modulated (silent in the developer-freedom
  zone). All toggle via `wardline.yaml` `rules.enable`/`rules.severity` like the existing four.
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
  serve`. The base package stays zero-dependency (the module is stdlib-only).
- **Track 3 — rename-stable taint read-by-SEI (T3.4).** Consumes Clarion's additive
  migration 0006 (a nullable `sei` column + `POST /api/wardline/taint-facts/by-sei`
  route + discrete `taint_store.read_by_sei` capability). `TaintStoreCapability`
  detects the route **gated separately from `sei.supported`** (an older SEI-capable
  Clarion predates the route), fail-closed. `ClarionClient.batch_get_by_sei` reads
  taint facts by their stable **opaque SEI** — the surface by which a fact written
  under a former locator survives a rename — fail-soft like `batch_get` (outage/403 →
  None; route-absent 404 → loud read-skew). The write path is unchanged: Clarion
  **stamps each fact's SEI server-side** from its alive `sei_bindings` row, so facts
  become SEI-tagged with no Wardline change. Verified live (write → resolve →
  read-by-SEI round-trip + bogus-SEI honest miss) and at the unit level (the
  deterministic rename model: by-new-locator misses, by-SEI hits). There is
  **no in-repo serve consumer** — by-SEI is the cross-tool rename-stable read surface
  for Track 5/legis and dossier-over-time (an explain fast-path consumer would be dead
  code: a renamed entity's fact is anchored to its old `source_file_path`, so a qualname
  change implies a content/path change and the fact reads stale). Base stays zero-dep.
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
