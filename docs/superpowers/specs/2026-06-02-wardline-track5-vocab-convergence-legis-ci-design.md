# Track 5 — Trust-vocabulary convergence + legis CI — DESIGN

**Date:** 2026-06-02
**Status:** design, pending user review
**Branch:** `feat/track3-sei-client` (Track 5 stacks on Tracks 1–4)
**Program spec:** `2026-06-02-wardline-first-class-body-of-work-design.md` §Track 5
**Tracker:** `2026-06-02-wardline-first-class-progress-tracker.md`

---

## 1. Summary

Track 5 is the last Wardline track. It closes the loop between Wardline (the
*analyzer*) and legis (the Loom *governance* plugin), and reconciles the suite's
trust vocabulary to one grammar. The defining discovery of the design phase:
**the convergence is already substantially true** — legis already carries
Wardline's 8-tier vocabulary verbatim, and Wardline's emitted finding shape is
already byte-compatible with legis's ingest contract. So Track 5 is mostly
**proof + documentation that locks in** convergence, not new machinery. This
matches the program theme — "Wardline's half of each gated track is thin and
ready."

It is **Wardline-repo-only**. legis is the sole integration and is treated as a
**fixed external contract** (the way Clarion was for T3.4/T4.3). **elspeth is
inspiration only** — no import, no linkage, no runtime relationship; it is where
the trust-boundary *ideas* came from, nothing more.

## 2. Lane & invariants

- **Wardline-repo-only.** No changes to legis, elspeth, or Clarion.
- **elspeth = inspiration, not a provider.** Track 5 must add no import of or
  network call to elspeth. References to elspeth are conceptual (in docs), to
  explain the lineage of the trust effects.
- **One judge.** Wardline analyses; legis governs. Wardline never re-judges, and
  legis never re-analyzes. The integration is one-directional data flow:
  Wardline's scan output → (the agent hands it to) legis's policy layer.
- **Zero new base dependencies.** The hermetic tests are stdlib-only; the live
  legis oracle is opt-in behind a deselected-by-default marker.
- **Fail-closed / no false-green** holds, as everywhere.
- **Builtins unchanged.** No change to the four/ten rules, the decorators, the
  lattice, or the emitted finding shape. Track 5 ships docs + tests, not engine
  edits. (If a conformance test surfaces a genuine wire-shape gap, that becomes
  scoped work, flagged — not silently absorbed.)

## 3. Verified ground truth (design-phase findings)

These were confirmed against source before the design was fixed:

1. **legis already carries the vocabulary.** `legis/src/legis/wardline/ingest.py`
   defines `TRUST_TIERS` = Wardline's eight taints (`INTEGRAL`, `ASSURED`,
   `GUARDED`, `EXTERNAL_RAW`, `UNKNOWN_RAW`, `UNKNOWN_GUARDED`, `UNKNOWN_ASSURED`,
   `MIXED_RAW`), commented "carried, never re-derived."

2. **The finding wire shape already matches.** legis's
   `WardlineFinding.from_wire` requires `rule_id`, `message`, `severity` (as a
   `WardlineSeverity[...]` *name* subscript), `kind`, `fingerprint`, `qualname`
   (optional), `properties` (optional), `suppressed` (default `"active"`).
   Wardline's `Finding.to_jsonl` (`core/finding.py`) emits all of these, and the
   **values align**: `Severity` is a `StrEnum` whose values are the uppercase
   names (`"ERROR"` etc., so the name-subscript resolves), `Kind.DEFECT.value ==
   "defect"`, `SuppressionState.ACTIVE.value == "active"`. legis's gate
   population (`active_defects`) selects `kind == "defect" and suppressed ==
   "active"` — exactly Wardline's active-DEFECT set.

3. **The legis intake contract.** `POST /wardline/scan-results` with body
   `{cell, scan, agent_id}` where `scan` is the Wardline scan response (carrying
   `findings: [...]`). legis selects `active_defects(scan)` and routes them into
   the named 2×2 `cell` (`WardlineCellPolicy`). legis does not call Wardline
   ("Wardline has no HTTP; the agent hands legis the MCP scan response").

4. **The trust-decorator collision (T5.1's subject).** Wardline:
   `@trust_boundary(*, to_level=GUARDED|ASSURED)` (named levels). elspeth:
   `@trust_boundary(tier=3, source_param=…)` (integer tiers; only tier 3 valid —
   "Tier-1 and Tier-2 must crash, not suppress"). Different signatures, different
   semantics. Loom's vocabulary is **Wardline's**; elspeth's tier model *maps
   onto* it but is not adopted.

5. **The two hash granularities (T5.3's subject).** Whole-file
   (`content_hash_at_compute` ↔ Clarion `current_file_hash`, the taint-store
   freshness gate) and entity-body (Clarion resolve `content_hash` ↔ Filigree
   `content_hash_at_attach`, identity/association drift). Wardline's
   `content_status` already refuses to cross-compare (returns `UNKNOWN`, never a
   false-`STALE`).

## 4. Work units

### T5.1 — Trust-vocabulary convergence *(a common-sense gap-check, not a build)*

**Goal:** a sanity sweep — walk elspeth's trust ideas as a checklist against what
Wardline + legis already deliver, **keep what's useful, drop what isn't.** This is
a review to make sure we're not forgetting anything, *not* an obligation to import
or re-express elspeth's whole model. The expected outcome (per the design-phase
findings) is that the useful effects are already covered; T5.1 confirms that and
records the verdict, adopting a gap only if the check surfaces one that is both
useful and genuinely missing.

**Method:** for each elspeth trust idea, assign a verdict —
- **Covered** — Loom already delivers the effect (record where);
- **Adopt** — useful *and* genuinely missing → becomes a small scoped item
  (flagged, not silently absorbed);
- **Drop** — not useful for Wardline/Loom → explicitly declined, with a one-line
  reason (so the decision is durable, not re-litigated).

**Starting checklist (verdicts to confirm):**

| elspeth idea | Expected verdict | Loom mechanism / reason |
|---|---|---|
| **Fabrication test** — a boundary must be able to say *no* | Covered | **PY-WL-102** (trust boundary with no rejection path = "can't say no") |
| **Custody / provenance** — trust is earned, tracked | Covered | the trust **lattice** (least-trusted-source wins) + `taint_provenance` |
| **Fail-closed boundaries** — unprovable ⇒ not trusted | Covered | `UNKNOWN_*` states + `WLN-ENGINE-*` FACTs, incl. T2.4's `WLN-ENGINE-UNPROVABLE-BOUNDARY` |
| **Tiered boundaries** (`tier=3`; only tier 3 valid) | Covered | named levels (`to_level=GUARDED|ASSURED`) — same "raise trust at a validated boundary" effect, in Loom's lattice |
| **One judge** | Covered | Wardline analyses (8-tier vocab legis carries verbatim); legis governs |
| *(anything else found in the sweep)* | Covered / Adopt / Drop | recorded with reason |

**Deliverable:** a short convergence note (a section in an existing concepts doc,
or a brief standalone) recording the verdict per idea — the durable "we checked;
here's what we keep and what we drop." A **worked grammar example** (a custom
elspeth-style boundary via the T2 extension plane, builtins byte-identical) is
included **only if** the sweep finds it adds real value — otherwise it is
explicitly dropped as YAGNI. No engine/decorator/builtin change either way.

**Out of scope:** adding a `tier=` alias, importing elspeth, changing legis, or
taking on any elspeth idea that the sweep judges not useful.

### T5.2 — legis intake conformance

**Goal:** prove Wardline's findings/gate are clean inputs to legis's policy
layer, and that the one-judge boundary holds. The contract already matches
(§3.2), so this unit is **proof, not plumbing**.

**Deliverables:**
1. A **hermetic contract test** (always runs, stdlib-only,
   `tests/conformance/test_legis_intake_contract.py`):
   - run a real `run_scan` over a small fixture with an active DEFECT (the
     `svc.leaky` shape) and at least one suppressed finding and one FACT;
   - serialize findings as the scan response does;
   - assert every finding dict carries legis's `from_wire` required keys with
     the right types, and that the **active-defect selection** (`kind ==
     "defect" and suppressed == "active"`) yields exactly Wardline's active
     DEFECT set (FACTs and suppressed findings excluded);
   - the legis contract is captured as a **local vendored spec** (the required
     field set + selection rule, as a small constant/fixture in the test), with
     a comment citing `legis/src/legis/wardline/ingest.py` — no legis import.
2. A **live `legis_e2e` oracle** (deselected by default via a new `legis_e2e`
   pytest marker, mirroring `clarion_e2e`):
   - discover/launch a legis server from `~/legis` (env override
     `WARDLINE_LEGIS_BIN`/URL; auto-skip clean if unavailable);
   - `run_scan` → build the scan response → `POST /wardline/scan-results`
     `{cell, scan, agent_id}` with a representative cell;
   - assert legis responds `{routed: …}` and that the routed population matches
     Wardline's active-defect count. A bogus/empty scan routes nothing.
3. A **one-judge assertion**: the conformance path performs **no** judge call —
   Wardline emits, legis governs. (Structural: assert the test exercises
   `run_scan`/emit only, never `run_judge`.)

**Open implementation question for the plan:** how legis is launched in the
oracle (its CLI/entrypoint + auth, if any). The plan step resolves this against
`~/legis` before writing the oracle; until then the oracle is written to
auto-skip, so CI stays green regardless.

### T5.3 — hash-granularity harmonisation

**Goal:** resolve the content-axis granularity so the suite is consistent and a
future consumer cannot trip on it. Given the Wardline-only lane and the shipped
SP9 store (whose whole-file freshness must not break), "resolved" means
**formalized + tested**, not unified into one value.

**Deliverables:**
1. An **ADR** (`docs/architecture/decisions/` or the repo's ADR home;
   `docs/concepts/taint-algebra.md` cross-link) stating the two-granularity
   model explicitly:
   - **whole-file** — taint-store freshness; `content_hash_at_compute` (Wardline,
     blake3 whole-file raw bytes) ↔ Clarion `current_file_hash`. Why: the
     taint-fact freshness gate must match Clarion's live file hash byte-for-byte
     (the SP9 contract).
   - **entity-body** — identity & association drift; Clarion resolve
     `content_hash` ↔ Filigree `content_hash_at_attach`. Why: identity drift is
     about whether *this entity's body* changed, independent of unrelated edits
     elsewhere in the file.
   - the rule: **never compare across granularities**; a cross-granularity
     compare is a permanent false-`STALE` and is forbidden. `content_status` is
     the single chokepoint that enforces honest `UNKNOWN` on a granularity
     mismatch.
2. **Discipline tests** (`tests/conformance/test_hash_granularity.py`):
   - assert each Wardline surface uses the correct granularity (taint facts =
     whole-file; the dossier's Clarion/Filigree compares = entity-body vs
     entity-body);
   - assert `content_status` returns `UNKNOWN` (never `STALE`) when either side
     is absent, and is only ever called with same-granularity inputs in the
     codebase (a guard test over the call sites / a documented invariant test).

**Out of scope:** adding an entity-body hash to Wardline, changing the SP9 store,
or any sibling change. (The additive-entity-body option was considered and
declined as YAGNI — nothing consumes it today.)

## 5. Testing strategy

- **Hermetic, always-on:** T5.1 grammar example + byte-identity guard; T5.2
  contract test; T5.3 discipline tests. All stdlib-only, no network, run in the
  default suite.
- **Opt-in oracle:** T5.2 `legis_e2e` (new marker, deselected by default in
  `pyproject` addopts, mirroring `clarion_e2e`/`network`). Auto-skips when legis
  is absent so it never reds CI.
- **TDD throughout** (RED → GREEN → REFACTOR), `pytest-randomly`-safe.
- **Coverage:** new modules/tests to 100% where they are the unit under test;
  global floor 90% holds.
- **No false-green:** the hermetic contract test must be written so it would
  *fail* if a finding field were dropped or a value drifted (e.g. severity
  emitted lowercase) — proven RED-first.

## 6. Acceptance (Track 5 DoD)

| Gate | Bar |
|---|---|
| One vocabulary | the gap-check sweep is done and recorded (keep/adopt/drop verdict per elspeth idea); a single `@trust_boundary` grammar confirmed across the suite; builtins byte-identical; a worked grammar example only if the sweep judges it useful |
| One judge | legis consumes Wardline findings/gate without Wardline re-judging — proven by the hermetic contract test **and** the live `legis_e2e` oracle |
| Granularity | the two-granularity model is documented (ADR) and tested suite-consistent; `content_status` never cross-compares |
| Hygiene | `make ci` green; ruff/format/mypy clean; dogfood exit 0; tracker + CHANGELOG updated; a Filigree issue per unit, panel-reviewed before close |

**Program exit note:** with Track 5 done, all five tracks' DoDs are green. The
program-level "dogfood proof" (an agent gets a complete one-call dossier on a
real annotated entity that stays correct after a rename) is the final
program-exit check; the SEI-axis half on Filigree's side remains pending
Filigree's own conformance (out of Wardline's lane), which the tracker records.

## 7. Risks & mitigations

- **legis launch unknowns** (oracle): mitigated by auto-skip + resolving the
  entrypoint during planning; the hermetic test guarantees coverage regardless.
- **Wire drift over time**: the hermetic contract test is the always-on guard; a
  future legis field change surfaces as a RED here, not a silent break.
- **Scope creep into siblings**: the lane invariant (§2) is explicit; any
  temptation to "just fix it in legis" is out of scope and flagged instead.

## 8. Filigree issues

One per unit (created at plan/execute time): T5.1 (vocab convergence), T5.2
(legis intake conformance), T5.3 (hash-granularity harmonisation).
