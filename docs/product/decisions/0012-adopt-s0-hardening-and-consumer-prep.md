# PDR-0012: Adopt S0 hardening and consumer-first preparation as the Now bet

Date: 2026-08-09
Status: accepted
Author: Codex product-owner checkpoint
Owner sign-off: checkpoint requested by the owner. The priority and local-plan
call is reversible, inward-facing work within the standing grant. Any public
release, tag, publication, or producer emission remains owner-gated.
Related: `roadmap.md` (Now), `metrics.md` (G1, G2, G2-seam),
`wardline-4928b75782`, `wardline-5a795253f1`, declaration-surface-v2 spec commit
`ed7bfe86` (blob `0f04eeb172e4479c330a806b37ff9b2132917f20`), S0 plan rev 3 commit
`5252e3f5` (blob `b5cd4b53f9c23b3c4519a91a963370910241a45e`).

## Context

The declaration-surface-v2 design exposed a live G2 false green:
`@trusted(level="INTEGRAL", audit=True)` and other malformed builtin marker calls
silently drop their seed, which suppresses every tier-modulated rule and makes the
scan greener without a diagnostic (`wardline-4928b75782`). The design also makes
consumer-first dual-read a prerequisite for any future generic-3 or attest-3
emission.

The governing design spec is committed, and its S0 implementation plan has now
received adversarial core/API, quality-engineering, consumer-systems, and technical
editor review. Rev 3 is a 21-task, code-grounded plan with a GO verdict for local S0
after clean-target preflight and an explicit NO-GO for published v3 emission. The plan
also records a deliberate Task-1 correction to spec section 4.2 and P11; the resulting
post-Task-1 spec blob, not an inferred or hand-edited preview, becomes the downstream
consumer pin.

The prior Now bet is no longer described truthfully by the June checkpoint: live
Filigree state says its six core Wardline seam surfaces are at-bar and only two P4,
non-gating follow-ons remain under `wardline-c66f62894b`. Meanwhile the new S0 bug is
P1, is on the current critical path, and blocks `wardline-5a795253f1` and every later
declaration-surface stage.

## Options considered

1. **Keep seam-conformance as Now and leave S0 as an uncheckpointed delivery plan.**
   Rejected: the roadmap would continue to present residual P4 cleanup as the primary
   outcome while a known P1 false green remains live and blocks the next product stage.
2. **Move the whole declaration-surface-v2 program to Now.** Rejected: this collapses a
   deliberately staged program into a feature list and would blur S0 consumer
   preparation into authorization to emit new vocabulary.
3. **Move S0 only to Now; retain the residual seam closeout in Next; treat the spec and
   rev-3 plan as a paired contract.** Chosen: it closes the known soundness breach first,
   makes the downstream stage boundary explicit, and keeps public emission behind a
   separate owner-controlled gate.

## The call

Adopt **S0 hardening plus consumer-first preparation** as Wardline's Now bet. The
declaration-surface-v2 spec defines the product contract; the rev-3 plan is the
codebase-validated delivery plan for S0 and owns the Task-1 contract correction and
post-correction blob receipt. Dispatch remains represented by the two Filigree IDs,
not copied into the product workspace:

- claim and close `wardline-4928b75782` first for the false-green slice;
- then claim and close `wardline-5a795253f1` only after the full local S0 receipt exists.

Local S0 is accepted only when all of these falsifiable outcomes hold:

1. The ticket's malformed-builtin repro emits `PY-WL-130`, trips
   `--fail-on ERROR`, and cannot seed the malformed declaration; forward marker skew is
   observable through `WLN-ENGINE-UNKNOWN-MARKER` and `decorator_coverage`, never a
   crash or a false clean.
2. Existing valid-marker descriptor and attestation bytes remain unchanged in S0;
   the resolver cache epoch changes, but Wardline emits neither generic-3 nor attest-3.
3. The QE harness counts preview findings, enforces the specified per-kind floors and
   two-run determinism, and holds the reviewed waiver ceiling at **5** with actual
   committed waiver usage **0**.
4. Loomweave, Wardline's key-holding verifier, Warpline's keyless relay, and Legis each
   pass their committed dual-read/tolerance contract, and the isolated four-repository
   local-install receipt names the exact consumer commits.
5. The S0 receipt closes with `published_emission_ready=false`. Published v3 emission
   remains NO-GO until consumer releases containing those commits are independently
   proven from release tags and installed distributions and the owner authorizes the
   release train.

## Rationale

This is the smallest stage that restores the core promise—an invalid trust declaration
cannot make the gate more confident—while protecting G1 precision and the byte-frozen
no-declaration path. Consumer-first preparation retires the cross-product compatibility
risk before producers change, but separating local readiness from published readiness
prevents a green local workspace from being misrepresented as ecosystem availability.
The call advances the product thesis without widening the vision or authorizing an
outward-facing action.

## Reversal trigger

Stop and reopen this call before accepting S0 if any previously valid builtin marker
changes seeding semantics or frozen bytes, if the ticket repro can still pass green, if
the local consumer receipt cannot prove all four exact commits, if committed waiver usage
exceeds **5**, or if the S0 rule population pushes G1 false-positive rate above **0.05**.
Any attempt to set `published_emission_ready=true` without the published-release evidence
and explicit owner authorization is not a reversal—it is a prohibited boundary crossing.
