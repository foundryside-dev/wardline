# PRD-0002 — weft-seam-conformance (wardline residency, scope B)   Status: ready-for-planning
Decision: PDR-0002 (pending `/product-checkpoint`)   Bet (roadmap.md): Now   Target metric (metrics.md): G2-seam — cross-repo seam honesty

## Problem

**Who** — the coding agent (and the 1–2 dev team behind it) that trusts a Weft seam's
answer *without re-deriving it* — and the operator who runs `wardline doctor` to keep
the integrations honest. A seam is a syscall the agent trusts blind.

**The problem (their pain)** — every Weft seam has lost its ability to say *"I don't
know."* When a join silently misses — scheme drift, an unresolved SEI, a stale
snapshot, a dropped signature, an absent artifact key — the result is **not an
error**. It is a confident, well-formed answer (`affected:[]`, `findings_created:0`,
`freshness:"unknown"`, `failed:[]`) that is **byte-indistinguishable from a
legitimate true-negative**. The agent commits the lie as the premise of its next
decision: it ships a change warpline said breaks nothing, or closes a loop loomweave
said was clean. Wardline sits on both sides of this — it **consumes** seams (SEI
identity from Loomweave, the warpline reverify worklist) and **produces** them
(findings emit, taint facts, delta scope, vocab descriptor, attest). Today Wardline
still owns ≥2 structurally-confident-empty surfaces and has **no live round-trip
check** that the data it consumes survives scheme/key/freshness drift — it reads a
self-reported status field, which is exactly the thing that lies.

**Desired outcome** — every Wardline seam surface can honestly report
emptiness/staleness with a *machine-readable reason* (clean vs disabled vs
unreachable vs dead vs scheme-drifted), and Wardline can prove **by round-trip — not
by trusting a status field** — that the data it consumes is retrievable under the
agreed identity scheme. The seam can say "I don't know" out loud.

**Why now** — the federation *is* the product (PDR-0023); the seams are the crown
jewels. The dead loomweave→filigree seam ran dead for weeks and was caught once by
luck — it was this pattern caught once, not an outlier. Reality has already pulled
this work into Now (6 seams reached `at_bar` this cycle, plus the P0 enforceable seam
registry + fail-closed gate). An untrustworthy seam silently corrupts every
downstream agent decision; closing the silent-failure class is what makes the moat
real.

## Success metric (the signal the bet paid off)

**G2-seam — cross-repo seam honesty** (`metrics.md`, added 2026-06-27). The pure
outcome: **no Wardline-owned seam surface can return an answer indistinguishable
from a legitimate true-negative** — every one emits a machine-readable `reason`
for empty/partial/stale, and every consumer read is round-trip-verifiable under the
agreed identity scheme. (The probe is *how* this is measured — criteria 1–2 — not
the metric itself.)
- **Closed surface set (6):** (1) wardline→filigree emit, (2) wardline→legis attest,
  (3) SEI loomweave→wardline consumer read, (4) warpline worklist consumer read,
  (5) wardline delta-scope producer artifact, (6) SEI-oracle producer-source CI
  drift. (Source: `~/weft/pm/2026-06-15-seam-health-map.md` + the shipped `at_bar`
  set.)
- BASELINE (2026-06-15): of the 6, **3 lie or cannot self-report** — (1) hardwired
  `failed:[]`, (2) attest key-absent fail-open with no amber/`key_id`, (3)
  SEI-wire-transport `gap` with no round-trip — and **0** consumer round-trip probes
  exist.
- TARGET: **0 of 6** can return a true-negative-indistinguishable answer (all 6 emit
  a machine-readable reason and/or are round-trip/drift-verified), by **2026-07-31**.
- Falsification: any of the 6 still returns empty/stale with no `reason`, or any
  consumer seam still lacks round-trip verification, at the window close → not paid
  off.

## Acceptance criteria (falsifiable)

1. **SUCCESS — Layer-1 self-check.** `wardline doctor --seams` (and the MCP
   self-check tool) returns a per-seam posture carrying a **mandatory
   machine-readable `reason`** for every Wardline-owned seam, echoing the non-secret
   artifact `key_id` where one applies; a planted missing/mismatched key yields a
   *distinct amber reason*, not a bare `ok:false`. A test proves the distinct
   reasons. Merged by 2026-07-31.
   *Reject:* any seam returns a bare boolean / no reason, or a missing key reads as
   healthy → unmet.
2. **SUCCESS — Layer-2 consumer round-trip.** For each seam where Wardline is the
   consumer (SEI identity from Loomweave; warpline reverify worklist), a probe
   round-trips a producer-minted reserved-prefix sentinel through the **real wire**
   and queries Wardline's **own read surface**, asserting (a) retrievability under
   the agreed identity scheme, (b) producer-emitted vs consumer-accepted **key-set
   conformance**, (c) freshness vs the live anchor. It writes nothing durable and
   never gates. A scheme-drifted sentinel (e.g. wlfp2 vs wlfp3) **fails** the probe;
   a test proves the drift is caught. Merged by 2026-07-31.
   *Reject:* a drifted/absent sentinel reads back as a clean hit, or the probe
   writes/gates → unmet.
3. **SUCCESS — producer artifacts peers can verify against.** (a) Wardline publishes
   a versioned `wardline.delta_scope.v1` artifact consumed by a drift-check in CI
   (`c0563eee74`); (b) the SEI-oracle producer-source drift check runs **required &
   fail-closed** in CI with no skip-when-absent (`79ba05f464`). Each lands with a
   test that fails pre-fix. Merged by 2026-07-31. (The Wardline-side qualname corpus
   is already published + tested — `tests/conformance/qualnames.json` — so it needs
   no new work here.)
   *Reject (per item):* artifact still vendored-only / CI still skips → that item
   unmet.
4. **GUARDRAIL — honesty invariant, no confident-empty.** Wardline's hardwired
   `failed:[]` (and any sibling structurally-confident-empty surface it owns) is
   replaced by real per-item failure tracking; a partial emit no longer reads as
   total success. Verified over the same window.
   *Reject:* any Wardline-owned seam result still reports success/empty when it
   actually failed/partial → bet rejected **even if 1–3 pass**.
5. **GUARDRAIL — G1 precision + G3 zero-config + G4 weight must not degrade.** The
   probe and self-check add **zero** false findings (full suite **and** a dogfood
   self-scan yield a byte-identical active-finding set before vs. after), require
   **no** new human configuration (`doctor --seams` activates by default), and add
   **no** base-package runtime dependency (probe lives behind existing extras /
   stdlib). Verified over the same window.
   *Reject:* any active finding lost/gained, a required-config step introduced, or a
   new base dep → rejected.
6. **SCOPE — wardline-residency, not peer-gated.** Every criterion above is
   achievable by Wardline alone; cross-repo green is asserted only where the peer
   *already* conforms, and a non-conforming peer yields an honest probe `reason`
   (not a failure of this bet).
   *Reject:* acceptance made contingent on warpline/loomweave/legis landing
   unshipped work → scope breach (that is scope C, a different bet).

**Secondary (non-gating).** `23c8e4bef4` (G19 — Loomweave `ErrorCode` soft/loud
classification) *supports* the honesty `reason` taxonomy but is consumer hygiene, not
the probe; `da883a2d07` (G25 — Loomweave's consumer leg) is cross-repo. Both may ride
the same PRs if they fit without scope growth; **neither gates this bet's
acceptance**, and they fall back to their own queue otherwise.

## Non-goals (this bet)

- The **peer-repo-owned strikes** from the seam-health-map roadmap: warpline's P0
  quiet-segfault loudening, the loomweave→filigree misroute, the legis closure-gate
  `content_hash` join, the SEI rename-feed producer fix. They live in their repos /
  the `~/weft` hub.
- **Layer-3 federation roll-up** (the single legis-owned matrix tool) — legis holds
  the identity + audit spine; out for Wardline.
- **G25's Loomweave consumer leg** (`da883a2d07`) — Wardline publishes the qualname
  corpus *consumably*; Loomweave actually consuming it is the cross-repo leg, tracked
  but not part of Wardline's acceptance.
- Any **new analyzer rule, boundary type, or capability** — this is seam-conformance,
  not engine expansion.
- The `bf004e2aea` structural items (`80e457bc41`, `18499aaa2d`) — code-landed; a
  separate ACCEPT pass, not this bet.

## Constraints & guardrails

- **Enrich-only axiom.** Wardline analyzes; it must not become a second authority.
  The probe *reads*; legis owns the roll-up + audit.
- **Never trust a self-reported status field** (the core seam-health-map principle) —
  assert by round-trip, not by reading `freshness_status` / `artifact_status`.
- **The probe writes nothing durable and never gates a scan** — it is diagnostic,
  like the delta advisory.
- **G1 / G3 / G4 are hard** (criterion 5). Fix at the boundary, per the
  `wardline-gate` discipline.
- **Per-sibling auth/signing layers stay byte-pinned** to each verifier — do not
  unify them (the `18499aaa2d` transport extract already drew that line).

## Open questions / assumptions

- **PDR-0002** (federation Later→Now) is decided but not yet durable —
  `/product-checkpoint` writes it. Until then this PRD's provenance is a *session*
  decision, not a recorded one.
- **`metrics.md` G2-seam axis was added 2026-06-27** (closed 6-surface set +
  BASELINE/TARGET), so the success metric is anchored on the scoreboard. The only
  remaining ACCEPT dependency is that **PDR-0002 is recorded at `/product-checkpoint`**
  — until then the bet's provenance is a session decision, not a durable one.
- **The round-trip probe protocol** (sentinel prefix, wire path, scheme-version
  negotiation) is a DESIGN choice → `/axiom-solution-architect`. *Assumption:*
  Wardline can mint/round-trip a sentinel on its consumer seams without a peer-side
  code change (true for SEI resolve + warpline worklist read; if a peer needs a new
  endpoint, that leg slips to scope C).
- *Assumption:* the seam-health-map's Wardline-owned confident-empty surfaces
  (hardwired `failed:[]`, SEI-wire gap) are still present at HEAD `29170e56` — verify
  at planning.

## Handoff

- **Top item → `/axiom-planning`:** criteria 1 + 2 (the Layer-1 `doctor --seams`
  self-check + the consumer-side Layer-2 round-trip probe) — the highest-blast-radius,
  unilaterally-buildable core. Turn into an executable, codebase-validated
  implementation plan first.
- **Solution shape → `/axiom-solution-architect`:** the seam-health probe protocol
  (sentinel scheme, key-set conformance diff, freshness anchor) and the
  honesty-invariant refactor (kill the confident-empty `failed:[]`). The PRD names
  the constraints; the design is theirs.
- **Tracker IDs:** program `wardline-c66f62894b`; children `c0563eee74` (P2),
  `79ba05f464` (P2), `23c8e4bef4` (P4), `da883a2d07` (P4). Decision: PDR-0002
  (pending). Authoritative spec: `~/weft/pm/2026-06-15-seam-health-map.md`.
- **Forecast/sequencing → `/axiom-program-management`.** No delivery date is set
  here; the dated commitment comes from its forecast.
