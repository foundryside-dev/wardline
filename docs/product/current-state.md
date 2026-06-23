# Current State — Wardline

> The resume brief: the fastest path back to the running picture. Read this
> first next session. Bootstrapped 2026-06-22 from observed reality (no prior
> workspace existed).

## The bet right now

**Close out the Codex security-review hardening campaign on the shipped 1.0.x
agent surface** (see `roadmap.md` → Now). Wardline 1.0.6 is shipped and live on
PyPI; the active work is hardening the agent-facing MCP / CLI / federation
surfaces against an external (Codex) security review, not building a new
capability front.

**Dispatchable top of the bet: `PRD-0001` (Codex P1 close-out)** — awaiting
planning/acceptance. The 2026-06-22 deep triage (52 agents, adversarially
verified; full record in `codex-triage-2026-06-22.md`) re-graded the 26 open
Codex bugs: **2 already-fixed → closed**, **2 P1**, **1 P2**, **21 P3**. Nothing
is P0; the default `wardline scan --fail-on` gate is clean. The two P1s
(`wardline-c797baf28b` default-gate DoS, `wardline-d96b94d4e9` doctor token leak)
are the entire `PRD-0001` acceptance core.

## In flight (by tracker ID)

- **`wardline-14359d070b`** (P2, bug, *in progress*) — "waiver_add bypasses MCP
  network policy for entity_symbol." The single claimed item; representative of
  the Now bet.
- **`wardline-bf004e2aea`** (P1, task) — "Holistic risk review 2026-06-10 —
  findings tracker." Parent tracker; triage on 2026-06-20 narrowed it to 4 live
  children (`wardline-80e457bc41` federation-status envelope dup;
  `wardline-18499aaa2d` shared transport extract; `wardline-d59f35c626`
  verify_attestation edge tests; `wardline-bf93236656` confinement sweep).
- **Codex security batch** — `codex-security-2026-06-20` label carries ~44
  findings; `codex-security` ~89 total. Many are the P2 bugs in the ready queue
  (rekey probe write-policy, doctor token leak via planted port file, scan
  advertised read-only despite effects, Rust mount-overlay crash, move-stable
  fingerprint misapply, etc.). **This batch is the operational heart of the Now
  bet.**
- **MCP-primary program** — `wardline-8528e67192` (gap tracker), label
  `mcp-primary-2026-06-11` (~16). Queued as **Next**.

Tracker scale: 52 ready, 0 blocked at bootstrap. Recent git history is almost
entirely `fix:` commits — consistent with a hardening campaign, not a feature
push.

## Open questions (bootstrap could not resolve)

1. **North-star instrumentation.** Agent-fix success rate (metrics.md) has no
   baseline — there is no labeled findings+outcome corpus yet. How should this
   be measured, and is it the right north star, or is precision (G1) the truer
   headline metric for an analyzer?
2. **Horizon confirmation.** Is finishing the Codex batch genuinely the *whole*
   Now bet, or should the MCP-primary program run concurrently rather than as
   Next?
3. **"Done" definition for the campaign.** Is the bet complete when the
   `codex-security-2026-06-20` batch hits zero open, or when a clean re-review
   confirms no residual class? (Proposed: the latter — re-review, not just
   count-to-zero.)
4. **Guardrail baselines.** G1 (FP rate) and the north star need a measurement
   pass to turn TBD placeholders into real targets.

## Where the next session starts

1. Confirm the authority grant still holds (it was confirmed standard on
   2026-06-22).
2. Confirm the Now/Next horizon split in `roadmap.md` — especially open
   question 2.
3. `DECIDE` on the Codex-batch "done" definition (open question 3), then
   `DISPATCH`: the top dispatchable bet is driving `codex-security-2026-06-20`
   to zero — candidate for `/write-prd` to pin its falsifiable acceptance
   criterion (batch → 0 open + clean re-review, no FP-rate regression).
4. Schedule the north-star instrumentation question (open question 1) as a
   discovery task before committing the metric.

## Provenance

This workspace was inferred from observed state, not a remembered history — see
`decisions/0001-bootstrap-from-observed-state.md`. Reversal trigger: revisit
once the human confirms the vision and the Now-bet framing.
