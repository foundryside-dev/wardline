# Wardline — first-class program PROGRESS TRACKER

**Date started:** 2026-06-02
**Purpose:** The single resume surface for Wardline's path to first-class. If
context is lost, **read this first** — it overlays live status onto the program
spec, names every gate's current state, and says what to do next. Update the status
columns as work lands.

**Source-of-truth docs (this tracker overlays status onto them):**
- Program spec: `2026-06-02-wardline-first-class-body-of-work-design.md` (the 5 tracks, quantified DoD)
- Track specs: `2026-06-02-wardline-track1-engine-floor-design.md` (others written as reached)
- Roadmap (vision): `2026-06-01-wardline-roadmap-to-first-class.md`
- SEI standard + reconciliation/lock state: `2026-06-01-loom-stable-entity-identity-conformance.md` §0.5
- Suite umbrella: `2026-06-01-loom-goal-state-case-study.md`

**Status legend:** ☐ not started · ◐ in progress · ☑ done · ⛔ blocked (gate named)

---

## Current position (update this line)

**As of 2026-06-02:** **Track 2 (extensible trust grammar) IN PROGRESS** on branch
`loom-step-up` (Track 1 merged here). Design spec + implementation plan written and
reviewed (advisor-pressure-tested): the grammar is a *code* seam (`scanner/grammar.py`:
`BoundaryType`/`TrustGrammar`/`default_grammar()`), the same shape as `TaintSourceProvider`
— NOT a DSL. Builtins re-expressed on the seam must stay byte-identical (a Task 0
full-stream golden over dogfood+corpus is the oracle); the released `core.registry`
contract (Clarion-consumed) stays frozen; the unprovable-boundary FACT is custom-only
(builtins never emit it). Spec:
`2026-06-02-wardline-track2-extensible-trust-grammar-design.md`; plan:
`docs/superpowers/plans/2026-06-02-wardline-track2-extensible-trust-grammar.md`.
Next: execute the plan (Task 0 golden → T2.1 model → T2.2 seam → T2.4 plumbing+FACT →
acceptance fixture → close-out panel). **Track 1 remains complete** (below).

**Track 1 recap —** **Track 1 (engine-quality floor) COMPLETE**, merged onto
`loom-step-up` (was branch `feat/track1-engine-floor`; plan:
`docs/superpowers/plans/2026-06-02-wardline-track1-engine-floor.md`).
All four units done with every DoD gate green: T1.4 labeled FP corpus + FP-rate gate
(0% ≤ 5%, 21 TRUE_POSITIVE active DEFECTs across the FP-prone shapes) + waiver
discipline; T1.2 star-import resolution (`from wardline.decorators import *` seeded
statically, fail-closed for all else); T1.3 single-hop return-indirection in
`compute_return_callee` (explain-only, taint values pinned unchanged); T1.1
verify-and-close of the hardening epic (audit findings F1–F6 confirmed
enforced/dispositioned). Suite 1063 passing; `scanner/taint/` coverage 100% (≥95%
gate); warm/cold byte-identical green; dogfood clean; mypy/ruff clean. Default
code-review panel run (static-analysis/Python/test/security) → SHIP / SHIP-WITH-FIXES,
convergent must-fixes applied. **Branch not yet merged — awaiting merge-target
decision.** Next action: **Track 2 (extensible trust grammar)** — the next thing to
spec (its own brainstorm); the FP corpus is the substrate it and T1.5 reuse.

---

## The end-to-end plan (all five tracks)

### Track 1 — Engine-quality floor  ·  gate: none (autonomous)  ·  **☑ done (branch `feat/track1-engine-floor`, unmerged)**

| Unit | Work | Filigree | Status |
|---|---|---|---|
| T1.1 | Taint-combination engine hardening (2026-05-31 audit) | `wardline-2b138b3662` (epic, P2) | ☑ |
| T1.2 | Star-import FN resolution | `wardline-2b427a9579` (P3) | ☑ |
| T1.3 | Return-indirection in `compute_return_callee` | `wardline-82f49ec3c3` (P3) | ☑ |
| T1.4 | FP economics: labeled corpus + FP-rate ≤5% + waiver discipline | `wardline-41f4a42a43` (P2) | ☑ |

**DoD gates:** FP ≤5% on labeled corpus · coverage 90% global / 95% on `taint/` · warm/cold byte-identical green · dogfood finding-clean · every closed hole has a RED-first regression test.
**Deferred out of Track 1:** T1.5 rule-set breadth (4 → ≥10) → after Track 2.

### Track 2 — Extensible trust grammar  ·  gate: none (autonomous; sequence after T1)  ·  **◐ in progress (spec+plan written; executing)**

| Unit | Work | Status |
|---|---|---|
| T0 | Byte-identity golden over dogfood+corpus (oracle, RED-first) | ◐ |
| T2.1 | Define the grammar (`scanner/grammar.py`: `BoundaryType`/`LevelArg`/`TrustGrammar`/`default_grammar`) | ◐ |
| T2.2 | Boundary-type loop replaces `_match` if-ladder; rules from grammar; `build_analyzer` (builtins as defaults) | ◐ |
| T2.3 | Re-express the 4 builtins + 3 decorators on the grammar (golden held byte-for-byte) | ◐ |
| T2.4 | Soundness inheritance (unprovable **custom** boundary → `UNKNOWN_*` + `WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT; builtins never) | ◐ |

**DoD:** agent defines a new boundary+rule end-to-end (acceptance fixture, litmus = zero edits to `_match`/`_ALL_RULE_CLASSES`/`_ENTRIES`) · unprovable→UNKNOWN+FACT test · the 4 builtins re-expressed produce **byte-identical findings** to today (oracle held).
**Note:** the hinge between "best analyzer" and "Loom citizen". Design spec: `2026-06-02-wardline-track2-extensible-trust-grammar-design.md`; plan: `…/plans/2026-06-02-wardline-track2-extensible-trust-grammar.md`. T1.5 (rule breadth) lands here, on the grammar. **Blockers baked into the plan:** released `core.registry` contract frozen (Clarion-consumed); summary-cache fingerprint must carry grammar identity (builtin = legacy string); `vocabulary.yaml`/`descriptor.py` unchanged (REGISTRY frozen).

### Track 3 — SEI-client  ·  groundwork: none · wiring: ⛔ Clarion SEI  ·  **☐ not started**

| Unit | Work | Gate | Status |
|---|---|---|---|
| T3.1 | SEI-client abstraction (carry SEI as explain/dossier handle, opaque) | none | ☐ |
| T3.2 | Capability detection + graceful degrade (no `sei` cap → honest fallback) | none | ☐ |
| T3.3 | Fingerprint-isolation test (SEI must NOT enter finding fingerprints) | none | ☐ |
| T3.4 | Re-key taint facts locator→SEI in the hard cutover (idempotent/resumable) | ⛔ Clarion SEI | ☐ |

**DoD:** fingerprint byte-identical across SEI introduction · graceful-degrade test · opaque round-trip · (post-cutover) a fact survives a rename.

### Track 4 — Dossier assembler  ·  groundwork: none · wiring: ⛔ Clarion SEI + HTTP linkages  ·  **☐ not started**

| Unit | Work | Gate | Status |
|---|---|---|---|
| T4.1 | Envelope schema (typed, ≤2k tokens, two-axis freshness, SEI-keyed) | none | ☐ |
| T4.2 | Assembler skeleton (compose taint + stubbed Clarion + Filigree; honest partial) | none | ☐ |
| T4.3 | Wire Clarion HTTP linkages + SEI + Filigree associations | ⛔ Clarion SEI + HTTP linkages | ☐ |

**DoD:** envelope ≤2k tokens · freshness both axes · SEI-keyed · honest partial when sources absent · (post-wiring) one-call dossier on a real dogfood entity.

### Track 5 — Trust-vocab convergence + legis CI  ·  gate: ⛔ legis existing (+ T2 done)  ·  **☐ not started**

| Unit | Work | Status |
|---|---|---|
| T5.1 | Converge suite trust vocabulary (Wardline grammar delivers elspeth effects; builtins unchanged) | ☐ |
| T5.2 | legis intake surface (findings/gate as inputs; one judge, not two) | ☐ |
| T5.3 | Hash-granularity harmonisation (entity-body vs whole-file) | ☐ |

---

## Sequencing (critical path + parallelism)

- **Autonomous critical path:** T1 → T2 (→ T1.5 on the grammar). **Start here.**
- **Parallel autonomous groundwork:** T3.1–T3.3 and T4.1–T4.2 (can run alongside T1→T2).
- **Gated finishes:** T3.4 (Clarion SEI) · T4.3 (Clarion SEI + HTTP linkages) · T5 (legis).

**Program exit (first-class done):** all track DoDs green + Wardline's goal-state-checklist items + a dogfood proof of a one-call mastery read that survives a rename.

---

## Cross-track / sibling gate states (update as siblings ship)

| Gate | Current state (2026-06-02) | Owner |
|---|---|---|
| **SEI lock** | REQ-C-01/C-02 **RESOLVED** (Clarion ADR-038); all four subsystems reported. Lock waits ONLY on the §8 conformance oracle (+ ADR-038 authored). | suite (Clarion authority) |
| **Clarion HTTP linkages** | ☐ not shipped — Clarion P0, autonomous (their roadmap M4) | Clarion |
| **Clarion prior-index retention** | ☐ not shipped — Clarion P0, autonomous (M3); prerequisite for SEI matcher + incremental | Clarion |
| **Clarion SEI authority** | ⛔ gated on SEI lock; then minting/matcher/lineage/wire (M5) | Clarion |
| **legis runtime** | ☐ design-ready, NOT implemented (repo `/home/john/legis`) | legis |

The Wardline halves of the gated tracks (T3.4, T4.3, T5) are **thin and ready** — they
become wiring steps, not builds, the moment the sibling gate opens.

---

## How to resume

1. Read this tracker's **Current position** line and the status columns.
2. For Wardline's own next step: the autonomous critical path is **T1 → T2**. If T1
   isn't done, dispatch/continue it (Track 1 spec + dispatch prompt). If T1 is done,
   the next thing to *spec* is **Track 2 (extensible grammar)** — its own brainstorm.
3. For suite/gate status, read SEI spec §0.5 (lock state) and the sibling roadmaps in
   `/home/john/{clarion,filigree,legis}/docs/superpowers/specs/`.
4. Update the status columns and the Current-position line as work lands.
