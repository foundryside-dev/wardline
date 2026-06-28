# Roadmap — Wardline

> **Routing banner.** This roadmap is **intent only** — Now / Next / Later
> horizons, no dates, no WSJF scores, no sequencing. Turning a committed bet
> into a dated, sequenced, capacity-checked plan is `/axiom-program-management`;
> turning one bet into an implementation plan is `/axiom-planning`. Do not add
> dates or scores here.

`Updated: 2026-06-29 (PDR-0009)` — added option B (framework-boundary enforcement
for unannotated apps) to Later as PARKED+gated; **Now is unchanged** (seam-health
probe). Prior: `2026-06-27 (PDR-0002)` rotated Now Later→Now to
weft-seam-conformance; the Codex hardening campaign paid off (batch 0 open, G2 at
target) and moved to ACCEPT. Originally seeded on bootstrap (2026-06-22) from
observed direction (git history, the dominant `codex-security` labels, the
in-progress item, and the recorded MCP-primary / frictionless-surface programs).

## Now — the current bet

**Close out the Wardline residency of the weft-seam-conformance program — give
every Wardline-owned seam back its ability to say "I don't know."** The federation
*is* the product (PDR-0023); the seams are the crown jewels. A silent join-miss
(scheme drift, unresolved SEI, stale snapshot, dropped signature, absent artifact
key) returns a confident, well-formed answer (`affected:[]`, `failed:[]`,
`freshness:"unknown"`) that is **byte-indistinguishable from a true-negative** —
and the agent commits the lie as the premise of its next decision. **Intent: every
Wardline seam surface reports emptiness/staleness with a machine-readable
`reason`, and every consumer read is round-trip-verified under the agreed identity
scheme — never by trusting a self-reported status field.** Spec: PRD-0002 /
`~/weft/pm/2026-06-15-seam-health-map.md`. Program tracker: `wardline-c66f62894b`.

- *Metric it moves:* **G2-seam — cross-repo seam honesty** (`metrics.md`): 0 of 6
  Wardline-owned seam surfaces can return a true-negative-indistinguishable answer.

> *Just completed (→ ACCEPT, not Now):* the **Codex security-review hardening
> close-out** (PDR-0001 / PRD-0001). Both P1s closed + regression-pinned, the
> `codex-security-2026-06-20` batch is 0 open, and guardrail **G2 is at target**.
> Awaiting a formal ACCEPT pass against PRD-0001's criteria (incl. the
> byte-identical active-finding check).

## Next — proposed, not committed

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
