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

**As of 2026-06-02 (latest):** **T1.5 (rule-set breadth) IN PROGRESS — 1 of 6 new rules done, 5/10 total.**
On branch `feat/track3-sei-client` (T1.5 continues here on top of Track 3). The user chose the
"broad-to-10" set (PY-WL-105 untrusted-arg→trusted-callee · 106 deserialization sink · 107
dynamic-exec · 108 OS-command · 109 None-leak · 110 contradictory trust decorators). **DONE:
PY-WL-110** (contradictory trust declaration — anchored entity with ≥2 distinct grammar markers;
ERROR; ships violation/clean examples + `tests/corpus/fixtures/contradictory.py` + MANIFEST;
golden regenerated; corpus FP 0%; dogfood clean; 1125 tests green). **REMAINING (turnkey via the
plan): 105, 106, 107, 108, 109** — 106/107/108 share a new `rules/_sink_helpers.py` (conservative
call-arg taint resolution off `function_var_taints`); 105 is the hardest (callee-trust resolution);
109 is the managed-FP rule (guarded None-leak). Plan:
`docs/superpowers/plans/2026-06-02-wardline-track1.5-rule-breadth.md`. Filigree `wardline-f0a2e9678e`.
**Then:** review panel incl. `false-positive-analyst`, update DoD "≥10 rules", close the issue.

---

**Track 3 SEI-client GROUNDWORK COMPLETE (T3.1–T3.3)** (prior position, retained for context)

**As of 2026-06-02:** **Track 3 SEI-client GROUNDWORK COMPLETE (T3.1–T3.3)**
on branch `feat/track3-sei-client` (branched off `loom-step-up`; nothing pushed). A
stdlib-only, opt-in SEI abstraction (`src/wardline/clarion/identity.py`:
`IdentityStatus`/`ContentStatus`/`SeiCapability`/`EntityBinding`/`content_status`/`SeiResolver`)
carries Clarion's SEI as the **opaque, preferred** binding handle with a **two-axis**
status (identity alive/orphaned/unavailable × content fresh/stale/unknown, never
collapsed), plus three fail-soft `ClarionClient` wire methods for the pinned
`/api/v1/identity/*` + `/api/v1/_capabilities` routes. All three DoD gates green:
**fingerprint isolation** (golden-digest guard on `compute_finding_fingerprint`,
RED-first-proven to bite if an SEI leaks in — SEI never enters fingerprints; warm/cold
byte-identical holds); **graceful degrade** (no `sei` cap → honest UNAVAILABLE, no wire
call, no crash); **opacity / never-parse** (an atypical token round-trips verbatim).
Strictly additive — `build_taint_facts` stays qualname-keyed (T3.4 re-key is gated).
1117 tests pass; coverage 95.81% global / `clarion/identity.py` 100%; ruff/format/mypy
clean; dogfood clean; base stays zero-dependency. **DISCOVERY (live oracle):** the local
`~/clarion/target/release/clarion` build **already serves SEI end-to-end** — `_capabilities`
advertises `sei:{supported,version:1}` and `/api/v1/identity/resolve` returns a real
ADR-038 token (`clarion:eid:<32hex>`, `alive:true`, entity-body `content_hash`). The
SEI client is therefore validated against a **real** SEI-serving Clarion, not only mocks
(the live `clarion_e2e` test exercises the ALIVE + opacity path). This means the SEI lock
/ Clarion-SEI gate may be closer to opening than the docs assume — surfaced, not acted on
(T3.4 is the coordinated suite cutover, still out of scope). Spec basis: program spec §2
Track 3 + SEI standard §4 + Clarion ADR-038; plan:
`docs/superpowers/plans/2026-06-02-wardline-track3-sei-client.md`.
**Next:** the autonomous critical path is **T1.5 (rule-set breadth, 4 → ≥10, on the Track 2
grammar)**; Track 4 groundwork (T4.1–T4.2 dossier skeleton) is also available in parallel.

**As of 2026-06-02:** **Track 2 (extensible trust grammar) COMPLETE** on branch
`loom-step-up` (Track 1 merged here). The grammar is a *code* seam
(`src/wardline/scanner/grammar.py`: `BoundaryType`/`LevelArg`/`TrustGrammar`/`default_grammar()`),
the same shape as `TaintSourceProvider` — NOT a DSL. All DoD gates green: an agent
defines a new boundary type + rule end-to-end and it fires (`tests/grammar/test_acceptance_custom_grammar.py`,
**litmus held** — zero edits to `_match`/`_ALL_RULE_CLASSES`/`_ENTRIES` for the fixture);
unprovable **custom** boundary → `UNKNOWN_*` + `WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT
(builtins never emit it); the 4 builtins + 3 decorators re-expressed on the seam are
**byte-identical** (Task 0 corpus golden held through every task). Released
`core.registry` contract frozen + Clarion probe verified; `vocabulary.yaml`/descriptor
unchanged; summary-cache fingerprint carries grammar identity (builtin = legacy string).
Suite **1087 passing**; coverage 95.74% global / `scanner/taint/` + `grammar.py` 100%;
ruff/format/mypy clean. Default code-review panel run (silent-failure + Python-quality):
found + fixed a HIGH fail-closed hole (stacked provable + unprovable-custom decorators
were silently over-trusted — now dragged to `UNKNOWN_RAW` + FACT) and a plural-reporting
completeness gap. Spec: `2026-06-02-wardline-track2-extensible-trust-grammar-design.md`;
plan: `docs/superpowers/plans/2026-06-02-wardline-track2-extensible-trust-grammar.md`.
**Next:** the autonomous path continues to **T1.5 (rule-set breadth, 4 → ≥10, authored
ON the grammar)**; parallel autonomous groundwork T3.1–T3.3 / T4.1–T4.2 is available.
**Track 1 remains complete** (below).

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

### Track 2 — Extensible trust grammar  ·  gate: none (autonomous; sequence after T1)  ·  **☑ done (branch `loom-step-up`)**

| Unit | Work | Status |
|---|---|---|
| T0 | Byte-identity golden over the T1.4 corpus (oracle, RED-first; dogfood via self-hosting) | ☑ |
| T2.1 | Define the grammar (`scanner/grammar.py`: `BoundaryType`/`LevelArg`/`TrustGrammar`/`default_grammar`) | ☑ |
| T2.2 | Boundary-type loop replaces `_match` if-ladder; rules from grammar; `build_analyzer` (builtins as defaults) | ☑ |
| T2.3 | Re-express the 4 builtins + 3 decorators on the grammar (golden held byte-for-byte) | ☑ |
| T2.4 | Soundness inheritance (unprovable **custom** boundary → `UNKNOWN_*` + `WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT; builtins never) | ☑ |

**DoD:** agent defines a new boundary+rule end-to-end (acceptance fixture, litmus = zero edits to `_match`/`_ALL_RULE_CLASSES`/`_ENTRIES`) · unprovable→UNKNOWN+FACT test · the 4 builtins re-expressed produce **byte-identical findings** to today (oracle held).
**Note:** the hinge between "best analyzer" and "Loom citizen". Design spec: `2026-06-02-wardline-track2-extensible-trust-grammar-design.md`; plan: `…/plans/2026-06-02-wardline-track2-extensible-trust-grammar.md`. T1.5 (rule breadth) lands here, on the grammar. **Blockers baked into the plan:** released `core.registry` contract frozen (Clarion-consumed); summary-cache fingerprint must carry grammar identity (builtin = legacy string); `vocabulary.yaml`/`descriptor.py` unchanged (REGISTRY frozen).

### Track 3 — SEI-client  ·  groundwork: none · wiring: ⛔ Clarion SEI  ·  **◐ groundwork done (T3.1–T3.3); T3.4 ⛔ Clarion SEI**

| Unit | Work | Gate | Status |
|---|---|---|---|
| T3.1 | SEI-client abstraction (carry SEI as explain/dossier handle, opaque) | none | ☑ |
| T3.2 | Capability detection + graceful degrade (no `sei` cap → honest fallback) | none | ☑ |
| T3.3 | Fingerprint-isolation test (SEI must NOT enter finding fingerprints) | none | ☑ |
| T3.4 | Re-key taint facts locator→SEI in the hard cutover (idempotent/resumable) | ⛔ Clarion **SEI-keyed taint-fact store** (not the SEI authority — that ships) + coordinated suite cutover | ☐ |

> **T3.4 gate re-assessed (2026-06-02, cross-repo verified).** Clarion's SEI *authority* is
> done and serving live (resolve/resolve_sei/lineage/_capabilities, oracle-passing) — the
> SEI client (T3.1–T3.3) is proven against it. T3.4 is NOT blocked on "Clarion ships SEI";
> it is blocked on two specific, narrow things: (1) Clarion's `wardline_taint_facts` store is
> still **locator(`entity_id`)-keyed** — a re-key needs an SEI-keyed target that does not yet
> exist (un-scoped in Clarion's plan); (2) the **§7.1 single hard cutover** is a suite-owned
> coordinated release (Filigree's backfill is not built; the cutover needs a freeze window).
> **Recommended next step toward T3.4 (suite-level):** file a Clarion ask for an SEI-keyed
> taint-fact store (or an additive SEI annotation on the existing fact), then sequence the
> coordinated backfill. Wardline's half (resolve locator→SEI via the now-built `SeiResolver`,
> idempotent/resumable, ORPHAN-surfacing) is thin and ready the moment that target exists.

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
| **SEI lock** | **Lock-ready in substance (2026-06-02, cross-repo verified).** All four reported; ADR-038 **accepted**; the §8 conformance oracle **exists and passes all six scenarios in Clarion CI** (`clarion/crates/clarion-storage/tests/sei_conformance_oracle.rs`). Not yet *formally* declared locked; remaining = other subsystems wiring the oracle into their own harnesses + the formal flip. | suite (Clarion authority) |
| **Clarion SEI authority** *(re-assessed)* | **IMPLEMENTED + oracle-passing + serving live** (sei_bindings/sei_lineage migrations, deterministic matcher §3, prior-index retention §3.1, all `/api/v1/identity/*` routes, REQ-F-02 reserved-prefix rejection, `_capabilities.sei`). In Clarion `[Unreleased]` (WS1 merged, not tagged). Wardline's T3.1–T3.3 client verified against it live. | Clarion |
| **Clarion SEI-keyed taint-fact store** | ⛔ **NOT built** — `wardline_taint_facts` is still `entity_id`(locator)-keyed; there is no SEI-keyed taint-fact store. **This is the real blocker for Wardline T3.4** (a re-key needs an SEI-keyed target). Not yet scoped in Clarion's plan. | Clarion |
| **Clarion HTTP linkages** | ☐ not shipped — Clarion P0, autonomous (their roadmap M4) | Clarion |
| **Clarion prior-index retention** | ☐ not shipped — Clarion P0, autonomous (M3); prerequisite for SEI matcher + incremental | Clarion |
| **Clarion SEI authority** | ⛔ gated on SEI lock; then minting/matcher/lineage/wire (M5). **NOTE (2026-06-02, live):** the local `~/clarion/target/release/clarion` build *already* advertises `sei:{supported,version:1}` and resolves a real `clarion:eid:<32hex>` token end-to-end — the wire is further along than "not started." Wardline's T3.1–T3.3 client is verified against it. The remaining gate for T3.4 is the **coordinated suite cutover** (single hard cutover, §7.1) + SEI **lock** (§8 oracle), not the route existing. | Clarion |
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
