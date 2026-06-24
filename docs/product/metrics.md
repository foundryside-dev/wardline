# Metrics — Wardline

> The scoreboard the product is judged against. Every target is **falsifiable**:
> a number and a date against a `BASELINE → TARGET by <date>` placeholder. A
> directional word ("improve precision") is not a metric. Seeded on bootstrap
> 2026-06-22 — the human owner sets the real BASELINE/TARGET numbers; the
> placeholders mark *what* to measure and *which way is good*, not confirmed
> goals.

## North star

**Agent-fix success rate** — of the ERROR-severity findings Wardline surfaces in
an agent's edit-verify loop, the share the agent resolves *at the boundary* such
that a rescan confirms the finding cleared, within one fix-verify cycle and
without human help.

This is the thesis ("tools that work first time, every time") made measurable:
an analyzer the agent can actually act on, not just one that flags. It rises
only when findings are both *real* (precision) and *actionable* (explanation
points at the boundary, not the sink).

- `BASELINE → TARGET`: `BASELINE: TBD (instrument on a dogfood corpus) → TARGET:
  ≥ 0.90 by 2026-09-30`
- *Instrumentation gap:* requires a labeled corpus of findings + agent-fix
  outcomes. Not yet measured. **Open question for the human owner.**

## Guardrails (must-not-degrade)

### G1 — False-positive rate (precision)
An analyzer that cries wolf gets turned off. The unsuppressed ERROR/HIGH
population must stay true-positive-dominant.
- `BASELINE → TARGET`: `BASELINE: TBD → keep FP rate ≤ 0.05 of active findings,
  measured 2026-09-30`
- Proxy already in the repo: suppression/waiver growth vs. rule growth (a single
  rule accruing disproportionate waivers signals lattice mis-design).

### G2 — Soundness / surface integrity (no false green, no policy bypass)
Zero known fail-open taint holes (untrusted→trusted laundering) **and** zero
known agent-surface policy bypasses (MCP network/write-policy escapes, sibling
URL trust, fingerprint-suppression misapply). This is the guardrail the **Now**
bet directly serves.
- `BASELINE → TARGET`: `BASELINE: open codex-security-2026-06-20 batch (≈44
  open) → TARGET: 0 open in that batch by 2026-07-31; thereafter 0 known
  fail-open/bypass holes, held continuously`
- Enforced by: the soundness oracle + the security regression suite. A new
  fail-open hole is a P0.

### G3 — Zero-config activation
`wardline scan .` runs and gates on an unconfigured repository with no required
human configuration — power arrives as activation, never as a form.
- `BASELINE → TARGET`: `BASELINE: holds at 1.0.6 (base package zero runtime
  deps; scanner via one extra) → TARGET: still holds, 0 required-config steps,
  re-checked each release`

### G4 — Weight discipline (anti-enterprise-creep)
The base package stays zero-runtime-dependency; capability stays behind opt-in
extras; no enterprise-process machinery (governance boards, formal V&V, corpus
gates) enters the tool.
- `BASELINE → TARGET`: `BASELINE: base = 0 runtime deps at 1.0.6 → TARGET: base
  stays 0 runtime deps; new deps only behind a named extra, re-checked each
  release`

## Notes

- All BASELINE values marked TBD need a measurement pass before they are real
  targets — flagged as open questions in `current-state.md`.
- A metric reading that crosses a guardrail is a reversal trigger for the bet
  that touches it; `/product-checkpoint` flags any such crossing.
