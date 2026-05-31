# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/foundryside-dev/wardline/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/foundryside-dev/wardline/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/foundryside-dev/wardline/releases/tag/v0.1.0
