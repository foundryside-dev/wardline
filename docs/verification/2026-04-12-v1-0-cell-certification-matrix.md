# Wardline v1.0.0 Release Projection Matrix

## Purpose

This document is the release-authorizing projection derived from:

- `docs/verification/2026-04-12-v1-0-compliance-ledger.md`
- `wardline.compliance.json`

It is not the source of truth for compliance. Its narrower job is to answer a
release question from current obligation records: can the current `1.0`
recertification advance?

## Claimed Surface

- Binding: `Python`
- Claimed conformance profiles for this recertification: `Wardline-Core`,
  `Wardline-Governance`
- Declared governance profile: `lite`
- Explicitly not claimed in this recertification: `Wardline-Type`
- Required framework rule surface in scope: `PY-WL-001` through `PY-WL-010`
  mapped to framework `WL-001` through `WL-009`
- Active binding-specific rows tracked for documentation honesty, but not
  required for framework conformance: `SCN-021`, `SUP-001`
- Optional supplementary rows not claimed for this release: `SUP-010`,
  `SUP-011`

## Working Rules

1. Treat this matrix as a view over obligation records, not as the truth store.
2. A green row requires every backing obligation to be `verified` or
   `not_applicable`.
3. `waived`, `non_compliant`, `stale`, `evidenced`, and
   `implemented_no_evidence` are all release-blocking states unless the claimed
   surface is explicitly narrowed.
4. Any evidence drift reopens the affected obligations first, then the derived
   row.
5. Release sign-off must be taken from a `wardline.controlLaw: "normal"` run,
   and any degraded window must already be closed by a verifiable retrospective
   scan.

## Release-Authorizing Rows

| Row | Release surface | Backing obligations | Current state | Disposition / next action | Reviewer status |
|---|---|---|---|---|---|
| C01 | Claimed regime map and profile claim | `R-REGIME-COVERAGE-COMPLETE`, `R-CATALOG-COMPLETENESS`, `R-RELEASE-PROJECTION-RUNNABLE` | blocked | Finish the obligation catalog expansion and keep the projection aligned with the narrowed `Wardline-Core + Wardline-Governance` claim | review pending |
| C02 | Core tier model and runtime constructs | `P1-S6-TAINT-JOIN-ABSORBING` plus remaining core/runtime obligations as the catalog expands | blocked | Fix L3 taint propagation to use the normative join algebra, then finish core/runtime obligation population | review pending |
| C03 | Decorator vocabulary and discovery | pending catalog population for the declared Python regime | blocked | Add the remaining Part I and Part II-A decorator/discovery obligations to the ledger before sign-off | review pending |
| C04 | Manifest, schema, and governance | `C-CRIT-9-GOVERNANCE-MINIMUMS`, `C-CRIT-10-MANIFEST-CONSUMPTION`, `G-LITE-CHECKLIST-VERIFIABLE`, `G-CONTROL-LAW-NORMAL-FOR-RELEASE`, `G-RETROSCAN-AFTER-DEGRADED-LAW` | at risk | Re-run governance evidence review, confirm the seven-point Lite checklist, and bind sign-off to a normal-law run plus any required retrospective-scan closure | review pending |
| C05 | Scanner engine and rule registration | `P1-S6-TAINT-JOIN-ABSORBING`, `P2A-A3-L1-MINIMUM-CONFORMANCE` | blocked | Fix the taint-join defect and reconcile the level-1 minimum-conformance claim with the actual analysis surface | review pending |
| C06 | CLI, SARIF, explainability, and self-hosting gate | `C-CRIT-7-SELF-HOSTING`, `C-CRIT-8-DETERMINISTIC-SARIF` | blocked | Tighten self-hosting pass/fail semantics and re-verify deterministic SARIF end to end | review pending |
| C07 | Corpus integrity and measurement pipeline | `C-CRIT-5-PER-CELL-MEASUREMENT`, `C-CRIT-6-GOLDEN-CORPUS`, `P1-S11-CORPUS-INDEPENDENCE` | blocked | Reconcile schema/floor drift, restore assessor-runnable corpus integrity checks, and close adversarial-coverage gaps | review pending |
| C08 | Final release evidence bundle | all release-scoped obligations above | blocked | Re-run the full evidence bundle only after all reopened rows return green | review pending |
| C09 | Wardline-Type layer (`wardline-mypy`) | claim-scope metadata only | not_applicable | Not claimed for this recertification; create a dedicated release row only when the type layer is actually claimed | n/a for this release |

## Rule-Surface Traceability

These rows keep the release claim honest about which Python rules are required,
active-but-non-blocking, or intentionally out of scope.

| Row | Python rule | Framework mapping | Release scope | Backing criteria | Current state | Primary evidence |
|---|---|---|---|---|---|---|
| R01 | `PY-WL-001` | `WL-001` (split) | required framework rule | criterion 2 | blocked | corpus verify, SARIF rule output, self-hosting coverage |
| R02 | `PY-WL-002` | `WL-001` (split) | required framework rule | criterion 2 | blocked | corpus verify, SARIF rule output, self-hosting coverage |
| R03 | `PY-WL-003` | `WL-002` | required framework rule | criterion 2 | blocked | corpus verify, SARIF rule output, regression tests |
| R04 | `PY-WL-004` | `WL-003` | required framework rule | criterion 2 | blocked | corpus verify, SARIF rule output, regression tests |
| R05 | `PY-WL-005` | `WL-004` | required framework rule | criterion 2 | blocked | per-cell corpus report and regression tests |
| R06 | `PY-WL-006` | `WL-005` | required framework rule | criteria 2, 4 | blocked | taint-aware corpus report and regression tests |
| R07 | `PY-WL-007` | `WL-006` | required framework rule | criterion 2 | blocked | runtime-type-check corpus cells, rule mapping review, self-hosting coverage |
| R08 | `PY-WL-008` | `WL-007` | required framework rule | criterion 3 | blocked | structural-verification corpus cells, delegation coverage, adversarial specimens |
| R09 | `PY-WL-009` | `WL-008` | required framework rule | criterion 3 | blocked | ordering corpus cells, adversarial specimens |
| R10 | `PY-WL-010` | `WL-009` | required framework rule | criterion 3 | blocked | restoration corpus cells, serialization-boundary coverage |
| R11 | `SCN-021` | no framework counterpart | active binding-specific, non-framework-blocking | binding-specific | at risk | explicit corpus evidence and declared-scope documentation |
| R12 | `SUP-001` | no framework counterpart | active binding-specific, non-framework-blocking | binding-specific | at risk | explicit corpus evidence and declared-scope documentation |
| R13 | `SUP-010` | no framework counterpart | not claimed | supplementary opt-in | not_applicable | no release evidence required while unclaimed |
| R14 | `SUP-011` | no framework counterpart | not claimed | supplementary opt-in | not_applicable | no release evidence required while unclaimed |

## Current Open Blockers

These open tracker items still block the release projection:

- `wardline-01a36526c7` — identical fragments across taint states inflate specimen count
- `wardline-249164090d` — orphaned `.py` files in `PY-WL-006` and `PY-WL-007`
- `wardline-31c5cc907c` — orphaned `.py` files alongside `PY-WL-001` YAML specimens
- `wardline-250e191c9c` — `PY-WL-008/009` standard specimens are taint-independent clones
- `wardline-9c7663a0d8` — `SCN-021` and `SUP-001` only have `EXTERNAL_RAW` specimens
- `wardline-ba8c82eb16` — no adversarial specimens for `PY-WL-008` or `PY-WL-009`
- `wardline-36f5768bdf` — TN specimens inconsistently lack `expected_match: false`
- `wardline-41ce9bbf7d` — unresolved question on whether single finding per specimen is normative
- `wardline-735e7f15fe` — §11 / §15 / live corpus schema and floor drift
- `wardline-cf49edcde8` — taint propagation does not preserve normative `taint_join`
- `wardline-dac6c4195a` — criterion 4 / analysis-level contract ambiguity
- `wardline-625c233fde` — self-hosting semantics are underdefined
- `wardline-29bd1003e7` — restored Lite governance checklist still needs a bound repo review
- `wardline-8cd5d3fb73` — release sign-off still needs normal-law SARIF and retrospective-scan closure evidence
- `wardline-fae28f1be3` — obligation-ledger compliance model still in progress
- `wardline-75a774e144` — full Part I and Part II-A obligation catalog not yet populated

## Release Gate

Do not push `1.0` until all of the following are true:

- `C01` through `C08` are green and `C09` remains `not_applicable` unless the
  release claim is expanded
- all required framework rule rows `R01` through `R10` are green
- active binding-specific rows `R11` and `R12` are either green or explicitly
  retained as non-framework-blocking in the narrowed claim
- no release-authorizing row remains in `review pending`
- the release-signoff SARIF run reports `wardline.controlLaw: "normal"`
- any alternate-law or direct-law window since the last accepted normal-law run
  is closed by the required retrospective scan
- the final evidence bundle is rerun after the last reopened row returns green

Minimum evidence bundle:

- `uv run ruff check src/ tests/`
- `uv run mypy src/`
- `uv run pytest`
- `wardline corpus verify`
- self-hosting SARIF run
- published `wardline.conformance.json`
- published `wardline.compliance.json`

## Filigree Mapping

Active release structure:

- Release `wardline-d72a66711c`: `Wardline v1.0.0 - Recertification`
- Release item `wardline-cf78d0d12f`: `C01-C02` regime/core/runtime
- Release item `wardline-a1383c4302`: `C03` decorator surface
- Release item `wardline-ea2ad585f6`: `C04` manifest and governance
- Release item `wardline-edd6045865`: `C05` scanner engine
- Release item `wardline-5f45af2b61`: `C06` CLI and SARIF
- Release item `wardline-829776394a`: `C07` corpus and self-hosting
- Release item `wardline-014c968f6b`: `C08` final evidence and ship decision

No release item exists for `C09` because `Wardline-Type` is not claimed in this
recertification.

The source-of-truth obligation ledger for this release is:

- `docs/verification/2026-04-12-v1-0-compliance-ledger.md`
- `wardline.compliance.json`
