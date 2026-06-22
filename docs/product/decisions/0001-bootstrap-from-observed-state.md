# PDR 0001 — Bootstrap the product workspace from observed state

`Date: 2026-06-22` · `Status: Accepted` · `Decider: product-owner agent
(confirmed with john@foundryside.dev)`

## Context

No `docs/product/` workspace existed. The `/own-product` command branched to
BOOTSTRAP. There was no remembered product history to resume; the workspace had
to be constructed from observed reality rather than fabricated from memory.

## What was observed

- **Repo:** README, ROADMAP, docs/index.md — Wardline is a lightweight, opt-in,
  agent-first semantic-tainting trust-boundary analyzer (Python core, Rust
  preview). 1.0.6 shipped, live on PyPI, base package zero runtime deps.
- **Recorded thesis** (product memory, 2026-05-30 / 2026-06-01): enterprise-class
  capability for a 1–2 dev agent-enabled team without enterprise weight; two
  invariants (zero-human-config guardrail; most-powerful-version-within-it).
- **Git history:** 26 of the last 50 commits are `fix:` — a hardening campaign,
  not a feature push.
- **Tracker:** dominant labels `codex-security` (×89),
  `codex-security-2026-06-20` (×44), `security-finding` (×47); the single
  in-progress item is a Codex security bug; 52 ready / 0 blocked.

## The call

Seed all five workspace artifacts from this evidence. Set the **Now** bet to
"close out the Codex security-review hardening campaign," with MCP-primary and
frictionless-surface completion as **Next**. Seed metrics with an agent-fix
success-rate north star and four guardrails (precision, soundness/surface
integrity, zero-config activation, weight discipline), all as falsifiable
`BASELINE → TARGET` placeholders pending a human-set measurement.

The authority grant was proposed and **confirmed standard** by the human owner
in this session (autonomous within strategy; escalate releases incl. PyPI,
vision/grant changes, deprecations, pricing, data deletion, external parties).

## Reversal trigger

Revisit once the human confirms the vision framing and the Now-bet scope —
specifically if (a) the Now bet is not actually the Codex hardening campaign, (b)
the agent-fix-success north star is rejected in favor of precision as the
headline metric, or (c) the thesis has moved from the recorded 2026-06-01
statement.
