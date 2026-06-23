# Vision — Wardline

> Standing product vision. The authority grant at the bottom governs what the
> product-owner agent may do autonomously versus what it must escalate. This
> file is never rewritten silently — a change here is a vision change and is
> escalated to the human owner.

## Purpose

Wardline is a **lightweight, opt-in semantic-tainting static analyzer for trust
boundaries**. It reads code statically (never runs it) and asks one question of
every trust-annotated boundary: *is the data this function works with as trusted
as it claims?* For Python it tracks a trust level (taint) through function
bodies and the project call graph and flags where untrusted data reaches a
trusted producer with no validation between. For Rust it ships a
command-injection preview around `std::process::Command`.

Wardline gives a coding agent and CI a **deterministic gate** for untrusted data
reaching trusted code — and surfaces each finding in terms an agent can act on
and fix *at the boundary*, not at the sink.

## Who it serves

- **Primary: the coding agent.** Wardline is agent-first — "humans on the loop,
  not in the loop." The agent runs the scan in its edit-verify loop, reads the
  explanation, and fixes the boundary. A human rarely reads the findings file by
  hand.
- **The 1–2 developer team that arms that agent.** They want enterprise-class
  trust-boundary analysis without enterprise-class process weight (no governance
  boards, no formal V&V apparatus, no corpus-benchmark gates).
- **Their CI**, as the gate of record on the unsuppressed finding population.

Wardline is one tool in the **Weft** suite (federation hub at `~/weft`); it
composes with Filigree (issues), Loomweave (code archaeology), and legis
(governance) under an enrich-only axiom.

## The thesis (the filter for every decision)

**Enterprise-class capability for a 1–2 dev agent-enabled team, without
enterprise-class weight.** Two governing invariants, as a constrained
optimization:

1. **Plug-and-play, zero-*human*-config is the hard guardrail.** You don't
   configure Wardline — you install it and it stands itself up. The
   agent-calibrated instruction layer (`wardline install`) *is* the
   zero-config mechanism: the tool ships pre-instructed for the agent to drive
   it; the human never fills in a form. Power reaches the human as opt-in
   **activation** (a switch + sane preloaded defaults), never opt-in
   **configuration**.
2. **Within that guardrail, build the most powerful version of the idea.** Zero
   *human* config ≠ zero config: the agent may configure — and generatively
   *extend* — the environment, defining new boundary types and the rules
   enforced at them, expressed in the one shared trust grammar. The human's
   ceiling is a switch; the agent's ceiling is "define new abstractions."
   Extensions still inherit the soundness invariants — an agent-defined boundary
   the engine cannot prove yields an honest `UNKNOWN_*`, never a false green.

> Assumption to confirm: purpose and audience above are drawn from README,
> ROADMAP, docs/index.md, and the recorded product thesis (2026-05-30 /
> 2026-06-01). They match the shipped 1.0.6 reality. Flag if the thesis has
> moved.

## Anti-goals (what Wardline deliberately is NOT)

- **Not a broad multi-language SAST suite.** Python-first, Rust preview only. A
  small, precise, opt-in rule set beats dozens-of-rules coverage.
- **Not an exhaustive whole-program path-sensitive prover.** Deliberately L1–L2
  with an L3 project fixed point.
- **Not a hosted/cloud service.** Local-first, stays that way.
- **Not enterprise process.** No governance boards, formal V&V apparatus, or
  benchmark-corpus CI gates baked into the tool. (Governance lives in legis, as
  an opt-in sibling — flip it on, don't map your controls.)
- **Not noisy.** Silent until opted in; undecorated code produces no findings.
  An analyzer that cries wolf gets turned off.

## Authority grant

`Status: CONFIRMED` · `Granted by: john@foundryside.dev` · `Last reviewed:
2026-06-22` · `Review cadence: 90 days`

The product-owner agent acts **autonomously within strategy**:
- prioritize and reprioritize the backlog,
- write PRDs and shape bets,
- dispatch delivery work,
- accept work against its stated acceptance criteria,
- kill a failing bet.

The agent **escalates to the human owner before** anything irreversible or
outward-facing:
- changing the vision, strategy, or this authority grant,
- a public release (including any PyPI publish) or public announcement,
- deprecating a feature users depend on,
- a pricing or commercial change,
- data deletion,
- anything touching an external party.

A widened or narrowed grant is itself a vision change — escalate it, never edit
it silently.
