# Wardline v1.0 — Roadmap to ship

**Date**: 2026-04-12
**Author**: johnm-dta + Claude Code (session artefact)
**Status**: Working document — reflects the ledger state as of this session
**Ledger snapshot**: `wardline.compliance.json` at commit `b4f251a1-dirty`

## The v1.0 ship condition

Every applicable obligation in the compliance ledger MUST be in one of
exactly two states:

1. **`verified`** — requirement, evidence, freshness binding, and reviewer
   checks all align (§15.6 states table)
2. **`not_applicable`** — out of scope for the declared profile by design

**Everything else blocks release.** §15.7 is explicit: *"A tool or regime
is partially conformant when one or more applicable obligations are
`unassessed`, `implemented_no_evidence`, `evidenced`, `non_compliant`,
`waived`, or `stale`."* Note that `evidenced` is on the partial-
conformance list — it is not shippable.

Additionally:

- `catalog_status` MUST be `"complete"` for the claimed surface
- The six release-critical gates in §15.6 MUST all pass
- The release-signoff run MUST report `wardline.controlLaw: "normal"`

## Why `evidenced` is not enough

The difference between `evidenced` and `verified` is the review:

| State | What it means |
|---|---|
| `evidenced` | Someone *could* check this and it *looks* assessor-runnable |
| `verified` | Someone *actually did* check it, the check came back clean, and the reviewer identity + date + independence are captured in the record |

Under BAR (§15.3.4), "someone" is the wardline-bar-panel pipeline with
`bootstrap_attested` independence. Under default Assurance, "someone" is
an independent human reviewer.

## How an obligation transitions to `verified` under BAR

For any obligation currently blocking release:

1. **Evidence must exist and be captured** — not described, not
   aspirational, not "the code is probably fine." A concrete
   assessor-runnable artefact (test output, SARIF file, corpus verdict,
   coherence report) must be bound to the obligation's `evidence_classes`
   entries.
2. **Review must be performed** with non-null `primary_reviewer` and
   `review_date` in `reviewer_metadata`.
3. **Independence must be non-pending.** Under BAR, this means:
   - The BAR pipeline runs against the obligation exactly **three times**
     (§5 of `docs/governance/bar-review-pipeline.md` — the
     `check_stability()` function in the policy tree)
   - All three runs produce the **same aggregate verdict** (stability
     condition 1)
   - When the aggregate is `pass`, all three runs have the **same
     7-reviewer per-role votes** (stability condition 2)
   - The aggregate verdict is **unanimous `pass`** (all 7 reviewer
     roles — no fail, insufficient_evidence, or refer)
   - Evidence artefacts are captured at
     `docs/verification/bar-pipeline-runs/<date>/<obligation-id>.json`
4. **State transitions to `verified`.** The schema's conditional `allOf`
   enforces: `state ∈ {verified, waived}` requires
   `independence ∈ {independent, bootstrap_attested}` and non-null
   reviewer identity + date.

For a `non_compliant` obligation, step 1 is substantial — it means
fixing the underlying bug, generating real evidence, *then* going through
the BAR pipeline.

## Current ledger state (23 obligations)

| State | Count | Shippable? |
|---|---|---|
| `verified` | 0 | Yes |
| `not_applicable` | 2 | Yes |
| `evidenced` | 5 | **No** — needs BAR pipeline review to reach `verified` |
| `implemented_no_evidence` | 7 | **No** — needs evidence capture, then BAR pipeline review |
| `non_compliant` | 9 | **No** — needs bug fix + evidence + BAR pipeline review |
| **Total blocking** | **21** | |
| **Total shippable** | **2** | |

## The 21 blocking obligations, grouped by work type

### Needs code/governance fix + evidence + BAR review (9 non_compliant)

| Obligation | Gap | Tracker |
|---|---|---|
| `C-CRIT-5-PER-CELL-MEASUREMENT` | 17 failing cells; floor semantics drift between prose and verifier | `wardline-735e7f15fe` |
| `C-CRIT-6-GOLDEN-CORPUS` | Schema, verdict vocabulary, and known_false_negative handling drift from §11 | `wardline-735e7f15fe` |
| `C-CRIT-7-SELF-HOSTING` | Self-hosting gate only blocks on unexcepted errors; full gate definition unsatisfied | `wardline-625c233fde` |
| `P1-S6-TAINT-JOIN-ABSORBING` | L3 callgraph propagation uses `TRUST_RANK` and `max()` instead of `taint_join()` | `wardline-cf49edcde8` |
| `P2A-A3-L1-MINIMUM-CONFORMANCE` | Binding says L1 includes two-hop scope; callgraph propagation only runs at L3 | `wardline-dac6c4195a` |
| `R-CATALOG-COMPLETENESS` | Catalog is seeded (23 obligations), not complete for claimed surface | `wardline-fae28f1be3` |
| `R-REGIME-COVERAGE-COMPLETE` | Cannot claim "no unexplained gaps" while catalog is partial | `wardline-fae28f1be3` |
| `G-ASSURANCE-ADVERSARIAL-CORPUS-MINIMA` | Corpus doesn't meet per-rule adversarial minima (§15.6 step 3) | — |
| `G-ASSURANCE-EXPEDITED-RATIO` | Ratio not declared in root manifest per §15.3.2 MUST | — |

### Needs evidence capture + BAR review (7 implemented_no_evidence)

| Obligation | What's missing | Tracker |
|---|---|---|
| `C-CRIT-8-DETERMINISTIC-SARIF` | End-to-end re-verification of deterministic SARIF against unsorted file discovery (*note: currently `evidenced` but will need the BAR pipeline to reach `verified`*) | `wardline-29bd1003e7` |
| `G-CONTROL-LAW-NORMAL-FOR-RELEASE` | No current release-signoff SARIF run bound to the ledger | `wardline-fae28f1be3` |
| `G-RETROSCAN-AFTER-DEGRADED-LAW` | Release evidence doesn't bind recent history to a retrospective-scan closure | `wardline-fae28f1be3` |
| `P1-S11-CORPUS-INDEPENDENCE` | Corpus hash manifest exists; publication + review model evidence incomplete | `wardline-8cd5d3fb73` |
| `G-ASSURANCE-CHECKLIST-VERIFIABLE` | §15.3.2 Assurance table exists; no bound static review captured | — |
| `G-ASSURANCE-COHERENCE-GATE` | Coherence module exists; CI release-blocking gate not wired | — |
| `G-ASSURANCE-TEMPORAL-SEPARATION` | Mechanism authorised by §15.3.4; no bound commit-history audit | — |

### Needs BAR review only (5 evidenced)

These have evidence already. They need the BAR pipeline's three
stability runs + unanimous pass to transition to `verified`:

| Obligation | Current evidence |
|---|---|
| `C-CRIT-8-DETERMINISTIC-SARIF` | Unit tests cover ordering invariants; E2E gap noted |
| `C-CRIT-9-GOVERNANCE-MINIMUMS` | Manifest, CODEOWNERS, exception register present |
| `C-CRIT-10-MANIFEST-CONSUMPTION` | Manifest loader, schema validation, coherence check present |
| `G-ASSURANCE-FINGERPRINT-BASELINE` | `wardline.fingerprint.json` exists, regime verify passes |
| `R-RELEASE-PROJECTION-RUNNABLE` | Certification matrix carries required runnable fields |

### Already shippable (2 not_applicable)

| Obligation | Why |
|---|---|
| `G-LITE-CHECKLIST-VERIFIABLE` | Out of scope: Assurance-only BAR ledger |
| `G-ASSURANCE-SIEM-EXPORT` | SHOULD (not MUST) under non-accredited BAR; mutual exclusion with accreditation |

## The roadmap to 1.0

Working backward from what needs to be true at sign-off:

| Stage | Work | Status |
|---|---|---|
| **0. Ledger accuracy locked** | All adversarial review groups come back clean | ← current stage, iterating |
| **1. Build the BAR runner** | Implement the pipeline that reads the policy tree and dispatches 7 roles × 3 stability runs × N obligations. Today the policy tree is a specification; there is no runner. | Not started |
| **2. Fix the 9 non_compliant obligations** | Each has a real gap (taint join, L1 scope, corpus adversarial minima, expedited ratio, catalog completeness, etc.). Real code/corpus/governance work. | Not started |
| **3. Capture evidence for the 7 implemented_no_evidence** | Run the relevant checks, bind the outputs to ledger records as concrete artefacts. | Not started |
| **4. Run BAR pipeline over all 21 applicable obligations** | Three stability runs per obligation, unanimous pass, captured artefacts → state `verified`, independence `bootstrap_attested`. | Not started |
| **5. Verify release-critical gates (§15.6)** | Claim surface explicit, release projection runnable, corpus floors met, control law normal, retrospective scan closure, governance checklist verified. | Partially satisfied |
| **6. Catalog completeness for claimed surface** | Current `catalog_status` is `"partial"`. Either enumerate all remaining Part I / Part II-A obligations (option 1) or narrow the claim (option 2). See decision below. | Needs decision |
| **7. Sign off** | R-CATALOG-COMPLETENESS and R-REGIME-COVERAGE-COMPLETE transition to `verified`; release projection goes green; sign-off under normal law. | Blocked on 1–6 |

## The catalog-completeness decision

The ledger's `catalog_status` is `"partial"` and `R-CATALOG-COMPLETENESS`
is honestly `non_compliant` to reflect that. The 23 catalogued obligations
cover §15.2 criteria + a few Part I / Part II-A samples + the §15.3.2
Assurance governance MUSTs. That is **not** the full Python binding
surface.

§15.7 allows two paths, but requires the choice to be explicit:

### Option 1 — Enumerate the rest

Create obligations for PY-WL-001 through PY-WL-010 (10 rule-level
obligations), every additional §6 / §7 / §8 / §9 / §11 property the
Python binding claims, and every §10 governance mechanism. Probably
50–100 more obligations. Then run the BAR pipeline over all of them.

**Pro**: The reference-implementation-ambitious path. Consistent with the
"reference" framing — a reference implementation should catalogue the
full surface.

**Con**: Substantially more work. The BAR pipeline runs 7 roles × 3
stability runs per obligation; 100 obligations = 2,100 reviewer
invocations.

### Option 2 — Narrow the claimed surface

Tighten `claim_scope.claimed_profiles` and
`required_framework_rule_surface` to only what's actually ready. Move the
rest to `not_claimed_profiles` / `optional_supplementary_not_claimed`.
Make the claim smaller but keep the catalog complete for what remains.

**Pro**: Faster path to a defensible 1.0. Honest partial conformance is
explicitly permitted by §15.7.

**Con**: The reference implementation ships with a narrower claim than
expected. Future work expands the claim as the catalog grows.

**Recommendation**: This decision deserves an ADR. Both options are
legitimate under §15.7, and the choice shapes the project's credibility
and the amount of work between now and the 2026-06-12 graduation target.

## The BAR graduation constraint

The `bootstrap_reference_declaration` declares:

- `graduation_target_date`: **2026-06-12** (two months from declaration)
- `graduation_mechanism`: `external_audit` (by `dta-security`)
- `slip_count`: **0** of maximum **2**

Per §15.3.4 "Graduation date changes," each slip requires a manifest
ratification event, a reason-for-slip entry in the graduation plan
(ADR-005), and an increment of `slip_count`. A third slip is refused by
schema validation and forces either graduation or a downgrade to Lite.

Every BAR-attested obligation automatically transitions to `stale` the
day after `graduation_target_date` passes without re-review. That makes
2026-06-12 a hard deadline, not a soft target.

## What this document is NOT

This is not the compliance ledger (that's `wardline.compliance.json`).
This is not a release projection (that's derived from the ledger's
`projections` block). This is a working-document summary of the
roadmap from the current ledger state to a shippable 1.0, written to
make the remaining work visible and the decisions explicit.

When the ledger reaches full conformance, this document becomes
historical context, not a governance artefact.
