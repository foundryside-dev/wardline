# Roadmap — Wardline

> **Routing banner.** This roadmap is **intent only** — Now / Next / Later
> horizons, no dates, no WSJF scores, no sequencing. Turning a committed bet
> into a dated, sequenced, capacity-checked plan is `/axiom-program-management`;
> turning one bet into an implementation plan is `/axiom-planning`. Do not add
> dates or scores here.

Seeded on bootstrap (2026-06-22) from observed direction: recent git history
(26 of the last 50 commits are `fix:`), the dominant tracker labels
(`codex-security` ×89, `codex-security-2026-06-20` ×44, `security-finding` ×47),
the in-progress item, and the recorded MCP-primary and frictionless-surface
programs. Treat horizon placement as a proposal for the human to confirm in
`DECIDE`.

## Now — the current bet

**Close out the Codex security-review hardening campaign on the shipped 1.0.x
agent surface.** A large external (Codex) security review produced ~89 findings
against the agent-facing MCP / CLI / federation surfaces (sibling-URL trust,
network-policy bypasses, rekey/provenance, fingerprint-suppression misapply,
Rust-frontend crashes). The last ~25 commits and the single in-progress ticket
(`wardline-14359d070b`) are all part of this. **Intent: drive the
`codex-security-2026-06-20` batch to zero, with each fix verified at the
boundary, before opening a new capability front.**

- *Metric it moves:* the **soundness / surface-integrity guardrail** (no known
  fail-open or policy-bypass holes on the agent surface).

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
