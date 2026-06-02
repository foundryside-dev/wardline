# Wardline — the first-class body of work (program spec)

**Date:** 2026-06-02
**Status:** Program / work-breakdown spec — the detailed sequence beneath
`2026-06-01-wardline-roadmap-to-first-class.md` (vision) and above the per-track
design→plan documents. Companion to the SEI standard
(`2026-06-01-loom-stable-entity-identity-conformance.md`) and the goal-state case
study.
**Altitude:** This spec designs the *architecture of the work* — what ships, in
what order, gated on what, and the quantified bar each piece must clear. It does
**not** design the *how* of each track; each track gets its own focused design spec
when reached (the extensible grammar, T2, is the immediate next one).

> **Thesis filter (governs every line).** Enterprise *capability* via opt-in
> layers, never enterprise *weight* in the base. The zero-dependency base stays
> zero-dependency; governance/V&V/audit live in `legis`, not Wardline. Every gate
> below is a capability bar, not a process tax.

> **Quantified gates are the proposed bar (user-approved 2026-06-02), reviewed
> before start and adjusted as we go.** Numbers most worth re-checking in flight:
> FP ≤5%, rule-count floor 10, coverage 90%/95%, dossier ≤2k tokens.

---

## 1. Goal & the definition of first-class

Wardline is first-class when it is, at once, **the best Python trust-taint analyzer
there is** *and* **a first-class Loom citizen**. The bar has two co-equal halves:

- **Half 1 — the analyzer itself** (Tracks 1–2): sound, precise, broad-ruled,
  agent-programmable. Entirely Wardline's own work; no sibling gate.
- **Half 2 — the Loom citizen** (Tracks 3–5): SEI-keyed facts that survive
  refactors, the one-call dossier, and governed CI. Mostly thin client work; the
  groundwork is autonomous, the finish is sibling-gated.

**Program exit criterion** (§4): every track's quantified DoD is green, Wardline's
own goal-state-checklist items are checked, and a dogfood proves the one-call
mastery read on a real entity that survives a rename.

---

## 2. The five tracks

Convention: each track lists **work units → quantified DoD → gate**. Sibling-gated
tracks split into **groundwork (own now)** and **wiring (gated)** so the whole
program is actionable today.

### Track 1 — Engine-quality floor *(autonomous)*

The analyzer-itself bar. This is where first-class starts.

**Work units**
- **T1.1** Taint-combination engine hardening — `wardline-2b138b3662` (P2, "first-class
  hardening" epic): close the `least_trusted` / `taint_join` / control-flow-join edge
  cases from the 2026-05-31 audit.
- **T1.2** Star-import FN — `wardline-2b427a9579`: resolve decorator markers through
  `from x import *` (today observable as `WLN-ENGINE-UNKNOWN-IMPORT`).
- **T1.3** Return-indirection in `compute_return_callee` — `wardline-82f49ec3c3`:
  explain-surface completeness.
- **T1.4** FP economics — stand up a labeled corpus + an FP-rate measurement; enforce
  waiver discipline (every suppression carries a reason; waiver count tracked against
  rule count).
- **T1.5** Rule-set breadth — grow the curated builtin set from 4 toward the floor of
  10, each rule shipping `examples_violation` / `examples_clean` fixtures, toggled via
  `wardline.yaml`. *(Sequencing note: prefer to land after T2.1–T2.3 so new rules are
  authored on the grammar rather than the legacy mechanism — see §3.)*

**Quantified DoD**

| Gate | Bar |
|---|---|
| False-positive rate | **≤5%** of active findings on dogfood + labeled corpus; all suppressions waivered; waivers do not grow faster than rules |
| Coverage | **90%** global floor; **95%** on `src/wardline/scanner/taint/` |
| Determinism | warm/cold **byte-identical findings** test stays green |
| Dogfood | tree stays **finding-clean or baselined** |
| Breadth | **≥10** curated rules, each with violation/clean fixtures |
| Soundness | no known fail-open holes; **every closed hole has a regression test** |

**Gate:** none — fully autonomous.

### Track 2 — Extensible trust grammar *(autonomous; the hinge)*

The most-powerful-version of the trust model, and the substrate for T1.5 (breadth)
and T5 (vocab convergence). The hinge between Half 1 and Half 2.

**Work units**
- **T2.1** Define the grammar (the meta-model): what a *boundary type* is (a declared
  trust transition carrying an enforcement rule), how trust composes (the 8-state
  lattice + rank-meet `least_trusted`), what fail-closed means. The grammar is the
  shared contract; instances are open.
- **T2.2** Boundary-type + rule registry / provider seam — agents declare new boundary
  types and the rules enforced at them; builtins are preloaded defaults. Same seam
  shape as `TaintSourceProvider` / Clarion `Transport` / dossier `HistoryProvider`.
- **T2.3** Re-express the 4 builtins (PY-WL-101–104) and 3 decorators **on** the grammar
  — proving the grammar subsumes today's behavior exactly.
- **T2.4** Soundness inheritance — an agent-defined boundary the engine cannot prove
  emits `UNKNOWN_*` + a `WLN-ENGINE-*` FACT, never a false-green.

**Quantified DoD**

| Gate | Bar |
|---|---|
| Extensibility | acceptance fixture: an agent defines a **new boundary type + rule end-to-end** and it fires correctly |
| Soundness inherited | unprovable custom boundary → `UNKNOWN_*` + `WLN-ENGINE` FACT (test) |
| No regression | the 4 builtins re-expressed on the grammar produce **byte-identical findings** to today (oracle held byte-for-byte) |

**Gate:** none (autonomous). Builds on T1's sound engine; sequence after the T1 floor.

### Track 3 — SEI-client *(groundwork now / wiring gated on Clarion SEI)*

**Groundwork (own now)**
- **T3.1** SEI-client abstraction — carry SEI as the explain/dossier handle; treat opaque.
- **T3.2** Capability detection + graceful degrade — read Clarion `_capabilities`; when
  `sei` is absent, fall back honestly ("identity unavailable"), never guess or crash.
- **T3.3** Fingerprint-isolation — prove the SEI does **not** enter finding fingerprints
  (it is a binding key, not a fingerprint input); the warm/cold byte-identical test holds.

**Wiring (gated on Clarion SEI)**
- **T3.4** Re-key Clarion-stored taint facts locator→SEI as part of the **single hard
  cutover**; idempotent/resumable backfill (relies on Clarion `resolve` rejecting
  SEI-shaped inputs, SEI spec §4/§7.1).

**Quantified DoD**

| Gate | Bar |
|---|---|
| Fingerprint isolation | introducing SEI leaves finding fingerprints **byte-identical** (test) |
| Graceful degrade | `sei` capability absent → honest fallback, no crash (test) |
| Opacity | SEI never parsed (round-trip / never-parse test) |
| Post-cutover | a dogfood fact **survives a rename** of its entity (keyed on SEI) |

**Gate:** groundwork — none; wiring (T3.4) — **Clarion ships SEI**.

### Track 4 — Dossier assembler *(groundwork now / wiring gated on Clarion SEI + HTTP linkages)*

Wardline is the dossier **assembler** (composes; does not become the store).

**Groundwork (own now)**
- **T4.1** Envelope schema — typed, token-bounded, freshness-stamped on **both axes**
  (SEI alive/orphan + content fresh/stale), SEI-keyed.
- **T4.2** Assembler skeleton — compose Wardline taint posture + (stubbed) Clarion
  structure/linkages + Filigree open work; emit an **honest partial** envelope when a
  source is absent.

**Wiring (gated)**
- **T4.3** Wire Clarion HTTP linkages + SEI and Filigree `list_associations_by_entity`
  into the assembler.

**Quantified DoD**

| Gate | Bar |
|---|---|
| Token budget | one-call envelope **≤2k tokens** |
| Freshness | stamped on both axes; SEI-keyed |
| Degradation | honest partial envelope when linkages/SEI absent (no crash) |
| Post-wiring | one-call dossier returns a complete, cited envelope on a **real dogfood entity** |

**Gate:** groundwork — none; wiring (T4.3) — **Clarion SEI + HTTP linkages** (Filigree
half already present).

### Track 5 — Trust-vocabulary convergence + legis CI *(gated on legis)*

**Work units**
- **T5.1** Converge the suite trust vocabulary — Wardline's grammar (T2) delivers
  elspeth's *effects* (custody, the fabrication test, fail-closed boundaries) in Loom's
  own terms, builtins unchanged.
- **T5.2** legis intake surface — expose findings + gate (`--fail-on`, exit codes) as
  clean inputs to legis's policy layer. One judge, not two: Wardline analyses, legis
  governs; Wardline never re-judges.
- **T5.3** Hash-granularity harmonisation — resolve the content-axis granularity
  (entity-body vs whole-file) flagged in SEI spec §2.

**Quantified DoD**

| Gate | Bar |
|---|---|
| One vocabulary | a single `@trust_boundary` grammar across the suite; builtins' behavior unchanged |
| One judge | legis consumes Wardline findings/gate without Wardline re-judging (integration test) |
| Granularity | content-axis hash granularity resolved and tested suite-consistent |

**Gate:** **legis existing** (+ T2 done).

---

## 3. Sequencing — DAG, critical path, parallelism

```
   T1 (engine floor) ──► T2 (grammar) ──► T1.5 (breadth, on the grammar)
        │                    │
        │                    └────────────────► T5.1 (vocab convergence) ─┐
        │                                                                 ├─► T5  [gate: legis]
   (parallel, autonomous groundwork)                                      │
   T3.1–T3.3 (SEI-client groundwork) ──► T3.4 (re-key) ─[gate: Clarion SEI]┘
   T4.1–T4.2 (dossier skeleton) ───────► T4.3 (wire) ──[gate: Clarion SEI + HTTP linkages]
```

- **Critical path (autonomous):** **T1 → T2.** T1 first (the grammar builds on a sound
  engine); T2 is the hinge and the highest-leverage un-gated item.
- **T1.5 (rule breadth)** sequences **after T2.1–T2.3** so breadth is authored *on* the
  grammar rather than built the legacy way and migrated. If T2 slips, T1.5 may proceed
  on the current rule mechanism as a fallback (flagged, not silent).
- **Parallel with T1→T2:** the autonomous groundwork of T3 (T3.1–T3.3) and T4
  (T4.1–T4.2). These are independent and can run alongside the critical path.
- **Gated finishes:** T3.4 (Clarion SEI) → during the hard cutover; T4.3 (Clarion SEI +
  HTTP linkages); T5 (legis existing). Wardline's half of each is thin and ready, so
  these are wiring steps, not builds, when the gate opens.

This is a dependency DAG, not a strict line: at any time the team can be advancing the
critical path **and** pre-building the gated halves in parallel.

---

## 4. Program-level acceptance (first-class "done")

Wardline is first-class when **all** of the following hold:

1. Every track's quantified DoD (§2) is green.
2. Wardline's goal-state-checklist items are checked: facts SEI-keyed and
   refactor-surviving; the dossier returns a complete freshness-stamped envelope;
   trust vocabulary reconciled to one grammar; governance is legis's layer, not
   Wardline's.
3. **Dogfood proof:** on a real annotated entity in Wardline's own tree, an agent gets
   a complete, current, cited one-call dossier — and that answer stays correct after
   the entity is renamed (SEI carried, fact re-keyed, dossier still resolves).

Half 1 (Tracks 1–2) can reach *its* done independently and immediately; it does not
wait on the suite. Full program done additionally requires the sibling gates to open.

---

## 5. Invariants & non-goals

**Invariants (hold across every track):**
- **Opt-in layers, zero-dep base.** Nothing here adds a runtime dependency to the base
  package; SEI/dossier/governance are switches, not weight.
- **Agent-first, humans on the loop.** The extension plane is agent-authored (zero
  *human* config); the human supervises.
- **Fail-closed / no false-green.** Every unprovable state is an observable
  `WLN-ENGINE-*` FACT, in the engine and in the grammar's extension plane alike.
- **SEI opaque; no binding keyed on a locator** on any surface Wardline emits.

**Non-goals (explicitly out of this body of work):**
- **Governance machinery** — judge gates, attestations, audit lineage, sign-offs:
  these are `legis`. Wardline provides findings + the gate primitive; it does not build
  governance.
- **Multi-language engine.** Generality is promised at the *contract* layer (fact
  format, trust vocabulary, SEI); the AST analyzer stays Python. Other languages are
  other producers, not a rewrite.
- **Dossier-as-store.** Wardline assembles the dossier; Clarion remains the fact/identity
  store. No aggregation authority moves into Wardline.
- **Time/effort estimates.** Sequencing is by dependency, not calendar.
