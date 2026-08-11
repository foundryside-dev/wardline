# Roadmap — Wardline

> **Routing banner.** This roadmap is **intent only** — Now / Next / Later
> horizons, no dates, no WSJF scores, no sequencing. Turning a committed bet
> into a dated, sequenced, capacity-checked plan is `/axiom-program-management`;
> turning one bet into an implementation plan is `/axiom-planning`. Do not add
> dates or scores here.

`Updated: 2026-08-11 (PDR-0020)` — Now bet **re-baselined** on a fourth hole of the
same class; horizon unchanged. Also applies PDR-0017's stated consequence, which was
declared but never written: the Now entry's contract anchors were still PDR-0012's.
Prior: `2026-08-09 (PDR-0012)` rotated S0 hardening to Now and moved seam-conformance
to Next as residual closeout; `2026-06-29 (PDR-0009)` added framework-boundary
enforcement to Later as PARKED+gated; `2026-06-27 (PDR-0002)` rotated
weft-seam-conformance to Now.

## Now — the current bet

**Return G2 to zero known false-green holes, and prove consumer-first local readiness
without emitting new vocabulary.** A trust annotation can be silently discarded — the
marker is written, the engine cannot read it, the function falls out of the declared
set, every tier-modulated rule goes quiet, and the gate exits 0. That contradicts the
promise the product is built on: uncertainty is made *explicit* rather than converted
into a green gate. The bet restores it, hardens the QE evidence later declaration
kinds depend on, and proves each consumer can dual-read the future contracts before
Wardline changes what it emits.

- *Strategic trace:* primary coding-agent gate; win on deterministic, actionable
  boundary truth without enterprise process weight.
- *Metric it moves:* **G2** to 0 known false-green/fail-open holes while holding
  **G1** FP rate ≤ 0.05; **G2-seam** remains honest during consumer staging.
- *Contract and delivery anchors:* PRD-0003; declaration-surface-v2 spec **rev 10**
  (`aa10dd3d`, blob `f4ba87c4…`); S0 plan **rev 3.8** (`0308b4e9`).
- *Tracker:* `wardline-5a795253f1` (the S0 receipt, in progress, Tasks 9–23) plus the
  open holes below. Closed and verified: `wardline-4928b75782`, `wardline-2b2a6cddfa`.
- *Still open against this bet:* `wardline-b857b50b54` (Rust marker shape — owns
  PRD-0003 criterion 6), `wardline-69a58cb05f` (re-export drops the seed with zero
  channels), `wardline-70a8bb3875` (`--fail-on-inert` no-ops on Rust scans).
- *Outcome boundary:* a complete isolated local receipt closes S0 with
  `published_emission_ready=false`; public generic-3/attest-3 emission is a separate
  release gate and owner decision.

## Next — proposed, not committed

- **Residual weft-seam-conformance closeout.** Keep the six at-bar core seams honest
  while closing or durably transferring the two non-gating P4 Wardline follow-ons.
  Program tracker `wardline-c66f62894b`; product contract PRD-0002 / PDR-0002.
  - *Metric it protects:* **G2-seam** — 0 confident-empty Wardline-owned seam
    surfaces, held continuously.

- **MCP-primary surface program.** Make MCP the first-class agent surface, at
  parity with or ahead of the CLI: structured output, where-filters +
  pagination on inventory tools (the `decorator_coverage` unbounded-output
  class), de-duplicated federation-status envelope, agent-first guidance docs.
  Tracked under `mcp-primary-2026-06-11` (×16) and the gap tracker
  `wardline-8528e67192`.
  - *Metric it moves:* agent-fix success rate (north star) — a richer,
    bounded, structured MCP surface is what an agent actually drives.

- **Frictionless-surface completion (WS-C/E/F/G).** The remaining workstreams
  from the frictionless-agent-surface program: delta gate, SEI-native
  addressing, activation hardening / rule packs, collapse of overlapping
  baseline tools. Tracked under `frictionless-surface` (×8).
  - *Metric it moves:* zero-config activation guardrail + agent-fix success.

- **Coverage expansion, as an attributed backlog.** The reviewer-named
  dangerous-but-unmodelled sinks and false-negative gaps (`expansion` ×9,
  `false-negative` ×9) are the roadmap for engine power — kept separate from
  defect bugs.
  - *Metric it moves:* north star (more real defects caught) **without**
    breaching the false-positive guardrail.

## Later — direction, not plan

- **Framework-boundary enforcement for truly-unannotated apps (option B) —
  PARKED, gated.** Per-parameter seed granularity + framework boundary inference
  so an unannotated FastAPI/Flask app gets real enforcement. A vision change (it
  revises "silent until opted in") *and* an engine-model change. Held by owner
  decision (PDR-0009); reopens only when *reliance-gated inert* framework apps
  reach ≥ 5 across measured corpora (baseline 2026-06-29 = 1). The cheap in-thesis
  floor (raw-`Request.*` source seeding) already shipped as Part C.
- Generative agent-extension plane: agent-authored boundary types and rules in
  the shared trust grammar, inheriting the soundness invariants (the invariant-2
  "most powerful version" ceiling).
- Deeper Weft federation: dossier / SEI-native cross-tool identity once sibling
  tools' contracts stabilize.
- Rust frontend beyond the command-injection preview — only if the precision bar
  the Python core holds can be met.

## Explicitly parked (see anti-goals in vision.md)

Broad multi-language SAST, whole-program path-sensitive proving, and any
hosted/cloud service are out of scope by design, not by sequencing.
