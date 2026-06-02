# Wardline — first-class program PROGRESS TRACKER

**Date started:** 2026-06-02
**Purpose:** The single resume surface for Wardline's path to first-class. If
context is lost, **read this first** — it overlays live status onto the program
spec, names every gate's current state, and says what to do next. Update the status
columns as work lands.

**Source-of-truth docs (this tracker overlays status onto them):**
- Program spec: `2026-06-02-wardline-first-class-body-of-work-design.md` (the 5 tracks, quantified DoD)
- Track specs: `archive/2026-06-02-wardline-track1-engine-floor-design.md` (others written as reached)
- Roadmap (vision): `2026-06-01-wardline-roadmap-to-first-class.md`
- SEI standard + reconciliation/lock state: `2026-06-01-loom-stable-entity-identity-conformance.md` §0.5
- Suite umbrella: `2026-06-01-loom-goal-state-case-study.md`

**Status legend:** ☐ not started · ◐ in progress · ☑ done · ⛔ blocked (gate named)

---

## Current position (update this line)

**As of 2026-06-02 (latest):** **TRACK 5 COMPLETE — ALL FIVE WARDLINE TRACKS DONE.** T5.1–T5.3 landed
on `feat/track3-sei-client` (nothing pushed), panel-reviewed. Wardline-repo-only; legis is the sole
integration (fixed contract), **elspeth is inspiration only (no linkage)**. The convergence was
**already substantially true** — legis carries Wardline's 8 tiers verbatim and Wardline's emitted
finding shape already matches legis's `from_wire` — so Track 5 is **proof + documentation that locks it
in**, not new machinery (no engine/decorator/store change). T5.1: keep/adopt/drop gap-check doc
(`docs/concepts/trust-vocabulary-convergence.md`) — all elspeth effects Covered, `tier=` alias + a
duplicate example Dropped (cites the existing T2 fixture `custom_grammar.py`). T5.2: hermetic always-on
contract test (`tests/conformance/test_legis_intake_contract.py`) + opt-in live `legis_e2e` oracle
(`tests/e2e/test_legis_live.py`, `WARDLINE_LEGIS_URL`-driven, auto-skips) — "one judge" proven (legis
reproduces Wardline's `summary.active` from the wire). T5.3: ADR
(`docs/decisions/2026-06-02-wardline-hash-granularity-two-model.md`) formalizing whole-file-vs-entity-body
granularity + discipline tests (`tests/conformance/test_hash_granularity.py`). **`make ci` green** (1241
tests, ruff/format/mypy clean, docs `--strict` exit 0, dogfood exit 0). Filigree `wardline-927cb4cf2e`/
`wardline-680861ec57`/`wardline-d4198c2b44`. **Remaining for full program-exit: nothing in Wardline's
lane** — the dossier "survives a rename" dogfood proof is met on the Clarion axis; the Filigree axis
pends **Filigree's own** SEI conformance (backfill + §8 oracle), which is Filigree's lane.

**Prior position (retained for context):** **TRACK 3 NOW COMPLETE — T3.4 (rename-stable taint read-by-SEI) done & panel-reviewed**,
on branch `feat/track3-sei-client` (nothing pushed). Clarion landed the enabling change **additively** (its
commit `caa2665`, migration 0006: nullable `sei` column on `wardline_taint_facts` + `POST
/api/wardline/taint-facts/by-sei` route + discrete `taint_store.read_by_sei` capability) — so the original
"re-key in a single hard cutover" mechanism collapsed to a property (**a fact survives a rename**) achievable
with **no PK re-key, no backfill, no suite freeze**. Wardline's reciprocal half delivered: `TaintStoreCapability`
(detects the route, **gated separately from `sei.supported`** — an older SEI Clarion lacks it, fail-closed);
`ClarionClient.batch_get_by_sei` + `TaintFactBySeiView` (read facts by their **opaque** stable SEI, fail-soft like
`batch_get`); writes unchanged (Clarion stamps each fact's SEI server-side). **No in-repo serve consumer** — by-SEI
is the cross-tool rename-stable read surface for Track 5/legis + dossier-over-time; an explain fast-path consumer
would be **dead code** (a renamed entity's fact stays anchored to its old `source_file_path` ⇒ stale ⇒ serve-fresh
never fires), so it was deliberately not built. Rename-survival proven as a **split oracle**: Wardline unit test
(by-new-locator misses, by-SEI hits) + live `clarion_e2e` (write → resolve → read-by-SEI round-trip + bogus-SEI
honest miss) + Clarion's own binding-flip oracle. **`make ci` green** (1235 tests; ruff/format/mypy clean; cov
96%, `clarion/identity.py` 100% + new by-sei method 100%; dogfood exit 0); **4 live `clarion_e2e` PASS**. Filigree
`wardline-51a8408618`. **Next + ONLY remaining Wardline track: Track 5** (trust-vocab convergence + legis CI) —
the legis gate is **OPEN** (legis built through Sprint 6 with a live `/wardline/scan-results` intake).

**Prior position (retained for context):** **TRACK 4 (dossier assembler) COMPLETE — T4.1 + T4.2 + T4.3 done & panel-reviewed**,
on branch `feat/track3-sei-client` (Track 4 stacked on Track 3 + T1.5, NOT off `loom-step-up` as the
original prompt said — building on `loom-step-up` would have lost Track 3's two-axis SEI types
(`clarion/identity.py`: `IdentityStatus`×`ContentStatus`), which the dossier envelope KEYS ON; the prompt
predated Track 3 landing, so this deviation was forced and is surfaced here). **The SEI gate is OPEN:** the
local `~/clarion/target/release/clarion` build serves SEI **and** call-graph linkages over HTTP
(`/api/v1/identity/*` + `/api/v1/entities/{id}/callers|callees`; `_capabilities` advertises `sei` +
`linkages.http`) — so T4.3 was unblocked and wired, not just grounded. Delivered: `core/dossier.py`
(`EntityDossier` envelope — typed, JSON-serialisable, keyed on the **opaque SEI**, freshness-stamped on
**both orthogonal axes** identity×content, token-bounded **≤2k** with explicit elision-honest truncation +
EXCEEDS-budget honesty; `build_dossier` composes Wardline's OWN trust posture for real with a **3-valued
honest verdict** defect/clean/**unknown** — no false-green on undeclared/under-scanned entities — and
Clarion/Filigree via typed `LinkageProvider`/`WorkProvider` seams, honest-partial on every absent/unreachable
source); `clarion/dossier_sources.py` (`ClarionLinkageProvider` + `resolve_entity_binding`);
`filigree/dossier_client.py` (dep-free urllib `FiligreeWorkProvider` reading ADR-029 entity-associations,
content_hash_at_attach → per-ticket DRIFT + 3-valued section content axis); `loom_dossier.py`
(`build_loom_dossier` orchestrator — probe caps once, resolve SEI binding via Track-3 `SeiResolver`, wire both
providers). **Callable surface:** `wardline dossier <qualname>` (CLI) + a `dossier` MCP tool, both thin
delegators to `build_loom_dossier` — **CLI≡MCP parity test asserts byte-identical envelopes** (the
"identical by construction" tenet); `wardline mcp` gains `--filigree-url`. Filigree's entity-association
contract verified against `~/filigree` source (`GET /api/entity-associations?entity_id=…` →
`{"associations":[…]}`, rows carry entity-body-granular `content_hash_at_attach`). Two code-review panels run (silent-failure-hunter + python-code-reviewer ×2): fixed the
false-green verdict, budget-marker honesty, two content-axis UNKNOWN→FRESH false-greens, one-sided-linkage
masquerade, typed seams. **DoD green:** ≤2k token budget (tested incl. truncation + untrimmable-core paths) ·
both freshness axes, SEI-keyed · honest-partial (no crash) · base stays **zero-dependency** · `make ci` green
(**1216 tests, 96.17%**, all new dossier modules 100%) · dogfood exit 0 · **LIVE `clarion_e2e` one-call
dossier round-trip PASSED** against a real `clarion serve` (resolve SEI + read linkages, leaky→read_raw edge
asserted). Filigree: `wardline-730d3efa6b` (T4.1), `wardline-d5c366102f` (T4.2), `wardline-4e3bcf3e49` (T4.3).
**Next:** Track 5 (trust-vocab convergence + legis CI) — gated on `legis` existing.

**Prior position (retained for context):** **T1.5 (rule-set breadth) — ALL 10 RULES IMPLEMENTED (review pending).**
On branch `feat/track3-sei-client` (T1.5 built on top of Track 3). The user chose the "broad-to-10"
set; all six new rules are landed, each with violation/clean examples + a labeled corpus fixture:
**PY-WL-110** contradictory trust decorators (ERROR) · **PY-WL-109** None-leak from a trusted
producer (CWE-394, guarded) · **PY-WL-105** untrusted-arg→trusted-callee (CWE-501, ERROR, fires
only on provably-untrusted EXTERNAL_RAW/MIXED_RAW) · **PY-WL-106** deserialization sink (CWE-502) ·
**PY-WL-107** dynamic-exec sink (CWE-95) · **PY-WL-108** OS-command sink (CWE-78). 106/107/108 share
`rules/_sink_helpers.py` (a `TaintedSinkRule` base + conservative, flow-insensitive call-arg taint
resolution off `function_var_taints` — Name + same-module bare-call, under-fire otherwise; documented).
DoD gates green: **10 curated rules** · corpus **FP 0%** (zero unaccounted) · `make ci` green
(1143 tests, cov ≥90%) · dogfood clean · golden regenerated · warm/cold byte-identical green.
Plan: `docs/superpowers/plans/archive/2026-06-02-wardline-track1.5-rule-breadth.md`; Filigree `wardline-f0a2e9678e`.
**T1.5 COMPLETE & panel-reviewed** (Filigree `wardline-f0a2e9678e` closed). The default panel
(false-positive-analyst + rule-designer + python-quality) found + fixed: the PY-WL-109 Optional-flood
(now requires an explicit non-None return annotation), a `dotted_name` bare-attr FP window, the
PY-WL-108 subprocess argv-list FP (narrowed to always-shell APIs), the flow-insensitivity docstring
(honest about over-fire on trusted→raw reassignment), `RAW_ZONE` triplication (consolidated into
`core.taints`), 110 ERROR→WARN, and misleading examples. **The autonomous critical path
T1→T2→T1.5 is now COMPLETE.** **Next parallel-autonomous item:** Track 4 (dossier assembler)
groundwork T4.1 (envelope schema, ≤2k tokens, two-axis freshness, SEI-keyed) + T4.2 (assembler
skeleton, honest partial). **Open suite-level recommendation (from the Track 3 re-assessment):** file
the Clarion ask for an SEI-keyed taint-fact store to unblock T3.4.

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
`docs/superpowers/plans/archive/2026-06-02-wardline-track3-sei-client.md`.
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
completeness gap. Spec: `archive/2026-06-02-wardline-track2-extensible-trust-grammar-design.md`;
plan: `docs/superpowers/plans/archive/2026-06-02-wardline-track2-extensible-trust-grammar.md`.
**Next:** the autonomous path continues to **T1.5 (rule-set breadth, 4 → ≥10, authored
ON the grammar)**; parallel autonomous groundwork T3.1–T3.3 / T4.1–T4.2 is available.
**Track 1 remains complete** (below).

**Track 1 recap —** **Track 1 (engine-quality floor) COMPLETE**, merged onto
`loom-step-up` (was branch `feat/track1-engine-floor`; plan:
`docs/superpowers/plans/archive/2026-06-02-wardline-track1-engine-floor.md`).
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
| T1.5 | Rule-set breadth 4 → 10 (PY-WL-105–110), authored on the Track 2 grammar | `wardline-f0a2e9678e` (P2) | ☑ (panel-reviewed) |

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
**Note:** the hinge between "best analyzer" and "Loom citizen". Design spec: `archive/2026-06-02-wardline-track2-extensible-trust-grammar-design.md`; plan: `…/plans/archive/2026-06-02-wardline-track2-extensible-trust-grammar.md`. T1.5 (rule breadth) lands here, on the grammar. **Blockers baked into the plan:** released `core.registry` contract frozen (Clarion-consumed); summary-cache fingerprint must carry grammar identity (builtin = legacy string); `vocabulary.yaml`/`descriptor.py` unchanged (REGISTRY frozen).

### Track 3 — SEI-client  ·  groundwork: none · wiring: SEI gate OPEN  ·  **☑ done (T3.1–T3.4, branch `feat/track3-sei-client`)**

| Unit | Work | Gate | Status |
|---|---|---|---|
| T3.1 | SEI-client abstraction (carry SEI as explain/dossier handle, opaque) | none | ☑ |
| T3.2 | Capability detection + graceful degrade (no `sei` cap → honest fallback) | none | ☑ |
| T3.3 | Fingerprint-isolation test (SEI must NOT enter finding fingerprints) | none | ☑ |
| T3.4 | Rename-stable taint **read-by-SEI** (consume Clarion's additive SEI lookup key) | ~~⛔ Clarion SEI-keyed taint store~~ **OPEN — shipped additively (Clarion migration 0006)** | ☑ |

> **T3.4 re-scoped + closed (2026-06-02, cross-repo verified).** The original framing
> ("re-key the store in a single hard cutover") was a *mechanism*; the requirement is a
> *property* — **a fact survives a rename**. Clarion landed that property **additively**
> (migration 0006: a nullable `sei` column on `wardline_taint_facts` + a `POST
> /api/wardline/taint-facts/by-sei` route + a discrete `taint_store.read_by_sei`
> capability), so no primary-key re-key, no backfill, and **no coordinated suite freeze**
> is required — the locator-keyed store stays as-is and gains a second, rename-stable
> lookup key. Wardline's reciprocal half (this commit): `TaintStoreCapability` (gated
> separately from `sei.supported`), `ClarionClient.batch_get_by_sei`, and the rename
> oracle (live + unit). Writes are unchanged — Clarion stamps each fact's SEI server-side.
> **There is no in-repo serve consumer** of by-SEI: it is the cross-tool rename-stable
> read surface for Track 5/legis and dossier-over-time. An explain fast-path consumer
> would be **dead code** (a renamed entity's fact is anchored to its old
> `source_file_path`, so a qualname change implies a content/path change → the fact reads
> stale → the serve-fresh path never fires); it was deliberately not built rather than
> manufactured to look used. The DoD's rename-survival line is met as a split oracle:
> Wardline's unit test (by-new-locator misses, by-SEI hits) + Clarion's own
> binding-flip oracle (Wardline cannot flip Clarion's `sei_bindings` from the client).

**DoD:** fingerprint byte-identical across SEI introduction ✅ · graceful-degrade test ✅ · opaque round-trip ✅ · a fact survives a rename ✅ (split: Wardline unit + Clarion oracle).

### Track 4 — Dossier assembler  ·  groundwork: none · wiring: SEI gate OPEN  ·  **☑ done (T4.1–T4.3, branch `feat/track3-sei-client`)**

| Unit | Work | Gate | Status |
|---|---|---|---|
| T4.1 | Envelope schema (typed, ≤2k tokens, two-axis freshness, SEI-keyed) | none | ☑ |
| T4.2 | Assembler skeleton (compose taint + stubbed Clarion + Filigree; honest partial) | none | ☑ |
| T4.3 | Wire Clarion HTTP linkages + SEI + Filigree associations | ~~⛔ Clarion SEI + HTTP linkages~~ **OPEN — both ship over HTTP** | ☑ |

**DoD:** envelope ≤2k tokens · freshness both axes · SEI-keyed · honest partial when sources absent · (post-wiring) one-call dossier on a real dogfood entity.

### Track 5 — Trust-vocab convergence + legis CI  ·  gate: **legis OPEN** ✓ + T2 done ✓  ·  **☑ done (T5.1–T5.3, branch `feat/track3-sei-client`)**

| Unit | Work | Status |
|---|---|---|
| T5.1 | Converge suite trust vocabulary — keep/adopt/drop gap-check vs elspeth effects; builtins unchanged | ☑ |
| T5.2 | legis intake conformance — hermetic contract test (always-on) + opt-in live `legis_e2e` oracle; one judge | ☑ |
| T5.3 | Hash-granularity harmonisation — ADR (whole-file vs entity-body) + discipline tests; no new hashing | ☑ |

> **Track 5 done (2026-06-02).** Wardline-repo-only; legis is the sole integration
> (fixed contract), **elspeth is inspiration only — no import, no linkage.** The
> defining finding: the convergence was **already substantially true** (legis carries
> Wardline's 8 tiers verbatim; Wardline's emitted finding shape already matches legis's
> `from_wire`, values and all), so this track is **proof + documentation that locks it
> in**, not new machinery — no engine/decorator/store change. T5.1: a keep/adopt/drop
> sweep doc (`docs/concepts/trust-vocabulary-convergence.md`) — all elspeth effects
> Covered, a `tier=` alias + a duplicate worked example Dropped (the T2 fixture
> `custom_grammar.py` already shows an elspeth-style tiered boundary). T5.2: a hermetic
> always-on contract test + an opt-in `legis_e2e` live oracle; the "one judge" property
> is proven (legis reproduces Wardline's `summary.active` gate population from the wire,
> never re-derives). T5.3: an ADR formalizing the two-granularity model (whole-file
> taint freshness vs entity-body identity drift) + discipline tests (false-STALE-never +
> a content_status call-site guard). Panel-reviewed (silent-failure-hunter + QA): fixed
> the qualname round-trip gap, the `/health` probe path, placeholder doc links.
> Filigree `wardline-927cb4cf2e` (T5.2), `wardline-680861ec57` (T5.1), `wardline-d4198c2b44` (T5.3).
>
> **ALL FIVE TRACKS NOW DONE.** Program-exit "dogfood proof" (one-call dossier surviving
> a rename) is fully met on the Clarion axis; the Filigree axis of that proof remains
> pending **Filigree's own** SEI conformance (its locator→SEI backfill + §8 oracle pass —
> out of Wardline's lane; see the sibling-gate table).

---

## Sequencing (critical path + parallelism)

- **Autonomous critical path:** T1 → T2 (→ T1.5 on the grammar). **Start here.**
- **Parallel autonomous groundwork:** T3.1–T3.3 and T4.1–T4.2 (can run alongside T1→T2).
- **Gated finishes:** ~~T3.4 (Clarion SEI)~~ **done** · ~~T4.3 (Clarion SEI + HTTP linkages)~~ **done** · T5 (legis).

**Program exit (first-class done):** all track DoDs green + Wardline's goal-state-checklist items + a dogfood proof of a one-call mastery read that survives a rename.

---

## Cross-track / sibling gate states (update as siblings ship)

| Gate | Current state (2026-06-02) | Owner |
|---|---|---|
| **SEI lock** | **Lock-ready in substance (2026-06-02, cross-repo verified).** All four reported; ADR-038 **accepted**; the §8 conformance oracle **exists and passes all six scenarios in Clarion CI** (`clarion/crates/clarion-storage/tests/sei_conformance_oracle.rs`). Not yet *formally* declared locked; remaining = other subsystems wiring the oracle into their own harnesses + the formal flip. | suite (Clarion authority) |
| **Clarion SEI authority** *(re-assessed)* | **IMPLEMENTED + oracle-passing + serving live** (sei_bindings/sei_lineage migrations, deterministic matcher §3, prior-index retention §3.1, all `/api/v1/identity/*` routes, REQ-F-02 reserved-prefix rejection, `_capabilities.sei`). In Clarion `[Unreleased]` (WS1 merged, not tagged). Wardline's T3.1–T3.3 client verified against it live. | Clarion |
| **Clarion SEI-keyed taint-fact store** | **SHIPPED additively** (Clarion `caa2665`, migration 0006, verified 2026-06-02) — `wardline_taint_facts` keeps its `entity_id` PK and gains a nullable `sei` column + partial index, a `POST /api/wardline/taint-facts/by-sei` route, and a discrete `taint_store.read_by_sei` capability. Writes stamp the SEI server-side from the alive `sei_bindings` row. No PK re-key, no backfill, no suite freeze. **Unblocked + closed Wardline T3.4.** | Clarion |
| **Clarion HTTP linkages** | **SHIPPED** (verified 2026-06-02) — `/api/v1/entities/{id}/callers|callees` (+ batch) live over the HTTP read API (`clarion-cli/src/http_read.rs`); `_capabilities.linkages.http`. Wired live into the Track 4 dossier. | Clarion |
| **Clarion prior-index retention** | **BUILT** — migration `0004_sei_prior_index` (the side table the matcher diffs against). | Clarion |
| **legis runtime** | **IMPLEMENTED through Sprint 6** (verified in source 2026-06-02; `/home/john/legis`, branch `sprint-6-suite-combinations`): the 2×2 enforcement engine, the API incl. **`POST /wardline/scan-results` → 2×2 cell**, SEI-consumer **passing the §8 oracle** (`tests/conformance/test_sei_oracle.py`), SEI-keyed Filigree sign-off, and the git-rename surface. **NOT design-ready — built. The legis gate for Track 5 is OPEN.** | legis |
| **Filigree SEI conformance** | **CONFORMANT — proven 2026-06-02 (uncommitted in its working tree, pending commit).** No longer the laggard. Both sufficiency conditions met: the locator→SEI backfill (`src/filigree/sei_backfill.py` + `filigree sei-backfill` CLI + migration v22) AND the §8 oracle. Verified by RUNNING it: hermetic `tests/federation/test_sei_conformance_oracle.py` **17 passed** (all six §8 scenarios covered + backfill branches; vendors Clarion's shared fixture with a drift-guard), and the faithful `test_sei_oracle_live_clarion.py` **passes** against a real SEI-serving `clarion serve`. Locks once committed/pushed + backfill run on real data. | Filigree |

T3.4 and T4.3 are now **done** (their Clarion gates opened and Wardline's halves landed).
The remaining gated track is **T5 (legis)** — and the legis gate is **OPEN** (legis is
built through Sprint 6 with a live `/wardline/scan-results` intake), so T5 is now a wiring
step, not a build.

---

## How to resume

1. Read this tracker's **Current position** line and the status columns.
2. For Wardline's own next step: the autonomous critical path is **T1 → T2**. If T1
   isn't done, dispatch/continue it (Track 1 spec + dispatch prompt). If T1 is done,
   the next thing to *spec* is **Track 2 (extensible grammar)** — its own brainstorm.
3. For suite/gate status, read SEI spec §0.5 (lock state) and the sibling roadmaps in
   `/home/john/{clarion,filigree,legis}/docs/superpowers/specs/`.
4. Update the status columns and the Current-position line as work lands.
