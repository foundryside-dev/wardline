# Wardline v1.0.0 Compliance Ledger

## Purpose

This document is the human-readable source of truth for the repository's
compliance state. It replaces the release-only reading of the conformance matrix
with an obligation ledger.

The ledger answers:

- what obligations are in scope
- whether the catalog itself is complete
- which obligations are verified, stale, non-compliant, or waived
- which evidence artefacts bind each claim to repository state
- which release rows are blocked by those obligations

The release projection remains useful, but it is derived from this ledger rather
than acting as the primary truth store.

## Requirement ID Schema

Obligation IDs are stable repo-level identifiers, not line numbers.

| Prefix | Meaning | Example |
|---|---|---|
| `P1-S<chapter>` | Part I framework obligation | `P1-S6-TAINT-JOIN-ABSORBING` |
| `P2A-A<section>` | Python binding obligation | `P2A-A3-L1-MINIMUM-CONFORMANCE` |
| `C-CRIT-<n>` | Conformance criterion from §15.2 | `C-CRIT-7-SELF-HOSTING` |
| `G-LITE-*` / `G-ASSURANCE-*` | Governance profile obligation | `G-LITE-CHECKLIST-VERIFIABLE` |
| `R-*` | Regime or release projection obligation | `R-RELEASE-PROJECTION-RUNNABLE` |

IDs remain stable even when the evidence package or release view changes. If a
chapter is renumbered, the `source_ref` changes; the obligation ID does not.

## Compliance States

| State | Meaning |
|---|---|
| `unassessed` | No assessment has been completed yet |
| `implemented_no_evidence` | Claimed implementation exists, but assessor-runnable evidence is missing |
| `evidenced` | Evidence exists, but reviewer verification is incomplete or blocked |
| `verified` | Requirement, evidence, freshness binding, and reviewer checks all align |
| `non_compliant` | Evidence contradicts the claim or the implementation does not satisfy the requirement |
| `waived` | Claim is not satisfied, but an explicit waiver with scope, approver, rationale, and expiry exists |
| `not_applicable` | Not in scope for the claimed profile, binding, or regime surface |
| `stale` | Previously evidenced or verified, but drift invalidated the claim |

Remediation plans are separate from state. Examples include `fix-code`,
`fix-spec`, `narrow-claim`, and `seek-waiver`, but none of those turn a failed
obligation into a compliant one.

## Freshness Binding

A `verified`, `waived`, or `stale` record must bind to repository state through
the evidence package it depends on. For this repository that usually means:

- commit reference
- tool version
- manifest hash
- corpus hash
- self-hosting input hash
- evidence artefact path and hash, where available

If any input changes without re-verification, the obligation becomes `stale`.

## Current Release Claim

This recertification currently claims:

- binding: `Python`
- conformance profiles: `Wardline-Core`, `Wardline-Governance`
- governance profile: `lite`
- required framework rule surface: `PY-WL-001` through `PY-WL-010`
- active binding-specific, non-framework-blocking rows: `SCN-021`, `SUP-001`

This recertification does not currently claim:

- `Wardline-Type`
- supplementary opt-in rules `SUP-010` and `SUP-011`

The release projection and the machine-readable compliance artifact must keep
that claim surface explicit. If the claim surface changes, the ledger changes
first.

## Catalog Completeness

Current status: `partial`

This ledger now covers:

- the ten conformance criteria in §15.2 where they drive the current release
- governance-profile obligations that materially affect the recertification gate
- the cross-chapter obligations surfaced by the adjudicated external reviews
- the release-projection obligations needed to keep the narrowed claim surface
  explicit and assessor-runnable

This ledger does not yet enumerate every normative obligation in Part I and
Part II-A. That missing coverage is itself visible and blocks any claim of
complete compliance visibility.

Primary catalog sources for the next population pass:

- `docs/requirements/spec-fitness/01-framework-core.yaml`
- `docs/requirements/spec-fitness/02-manifest-governance.yaml`
- `docs/requirements/spec-fitness/03-scanner-conformance.yaml`
- `docs/requirements/spec-fitness/05-enforcement-layers.yaml`
- `docs/requirements/spec-fitness/06-governance-operations.yaml`
- `docs/requirements/spec-fitness/07-conformance-profiles.yaml`

## Current Ledger

Evidence binding for the current snapshot:

- commit: `de0d4a67d36526249659cca7bdc73e030b328692`
- conformance artefact: `wardline.conformance.json`
- conformance inputs:
  - `commit_ref`: `5bd9e55e30d9225ae4db6de5bedbd3ad7c47e52d-dirty`
  - `tool_version`: `1.0.0`
  - `manifest_hash`: `sha256:b7e6f1d15e8896601478df483fc8ff3e48366abba60e9c98c1405ca42c59a2a3`
  - `corpus_hash`: `sha256:81e348e223a4c83f12b4e3b617e28855a964c30faa927a32f5780224d74b5950`
  - `self_hosting_input_hash`: `sha256:d08705f2c6e967013eb54fbe07390b1717cc8f8a0162f0692ddac6397585167b`

| Obligation ID | Source refs | Summary | State | Notes | Tracker |
|---|---|---|---|---|---|
| `C-CRIT-5-PER-CELL-MEASUREMENT` | `§15.2(5)`, `§11` | Precision and recall are measured, tracked, and published per cell | `non_compliant` | Live report has 17 failing cells and the floor semantics drift across prose and code | `wardline-735e7f15fe` |
| `C-CRIT-6-GOLDEN-CORPUS` | `§15.2(6)`, `§11` | Golden corpus exists with coherent specimen schema and adversarial coverage | `non_compliant` | Live specimen schema, verdict vocabulary, and KFN handling drift from §11 | `wardline-735e7f15fe` |
| `C-CRIT-7-SELF-HOSTING` | `§15.2(7)`, `§11` | Enforcement tools pass their own rules where applicable | `non_compliant` | Current gate only blocks on unexcepted `error` findings; warnings and suppressed findings remain outside the chapter's pass/fail meaning | `wardline-625c233fde` |
| `C-CRIT-8-DETERMINISTIC-SARIF` | `§15.2(8)`, `§11.1` | Verification-mode SARIF is deterministic and assessor-runnable | `evidenced` | SARIF results are sorted, but unsorted file discovery still leaves a drift risk until re-verified end to end | `wardline-fae28f1be3` |
| `C-CRIT-9-GOVERNANCE-MINIMUMS` | `§15.2(9)`, `§10`, `§15.3.2` | Lite governance minimums are present and reviewable | `evidenced` | Manifest, CODEOWNERS, and exception register exist, but the refreshed seven-point Lite checklist still needs a bound assessment run | `wardline-29bd1003e7` |
| `C-CRIT-10-MANIFEST-CONSUMPTION` | `§15.2(10)`, `§14` | Manifest validation and declared delegation are enforced | `evidenced` | Implemented, but still tied to the broader compliance-ledger redesign for truthful release claims | `wardline-fae28f1be3` |
| `P1-S6-TAINT-JOIN-ABSORBING` | `§6`, `§11 property 6` | Taint propagation preserves the normative join algebra with `MIXED_RAW` absorbing | `non_compliant` | L3 propagation currently uses `TRUST_RANK` and `max()` instead of `taint_join()` | `wardline-cf49edcde8` |
| `P1-S11-CORPUS-INDEPENDENCE` | `§11`, `WL-FIT-SCAN-011` | Corpus release, integrity, and review model support independent assessment | `implemented_no_evidence` | Hash manifest exists, but separate publication and independent review requirements are not yet clearly satisfied at the regime level | `wardline-fae28f1be3` |
| `P2A-A3-L1-MINIMUM-CONFORMANCE` | `A.3`, `§15.2(4)` | Analysis level 1 truthfully represents the minimum conformant scope | `non_compliant` | Binding says level 1 includes required two-hop scope, but general callgraph taint propagation only runs at level 3 | `wardline-dac6c4195a` |
| `G-LITE-CHECKLIST-VERIFIABLE` | `§15.3.2`, `WL-FIT-CONF-010` | The Lite governance checklist remains explicit and assessor-runnable | `evidenced` | The seven-point checklist has been restored in §15, but the current repo still needs a bound review against it | `wardline-29bd1003e7` |
| `G-CONTROL-LAW-NORMAL-FOR-RELEASE` | `§10.5`, `§15.6`, `WL-FIT-GOV-008` | Release sign-off requires a normal-law SARIF run | `implemented_no_evidence` | The rule is now explicit in §15 and the matrix, but no current sign-off run is bound to the ledger yet | `wardline-8cd5d3fb73` |
| `G-RETROSCAN-AFTER-DEGRADED-LAW` | `§10.5`, `§15.6`, `WL-FIT-GOV-009` | Any degraded window is closed by a verifiable retrospective scan before release sign-off | `implemented_no_evidence` | Retrospective-scan semantics exist in SARIF, but the release evidence does not yet bind recent history to a confirmed closure check | `wardline-8cd5d3fb73` |
| `R-REGIME-COVERAGE-COMPLETE` | `§15.4` | Regime documentation covers the narrowed claimed surface with no unexplained gaps | `evidenced` | The release claim now explicitly names `Wardline-Core + Wardline-Governance`, active binding-specific rows, and out-of-scope surfaces | `wardline-fae28f1be3` |
| `R-S15-WORKED-EXAMPLE-CREDIBLE` | `§15.6.1`, `§15.6.2` | Worked examples do not claim passing states contradicted by live evidence | `evidenced` | The generic mixed-state examples no longer present a false pass against the live failing corpus state | `wardline-9243d037e7` |
| `R-CATALOG-COMPLETENESS` | `§15.1`, `§15.6` | The obligation catalog is complete for the claimed surface | `non_compliant` | This is still a seeded ledger, not yet a complete catalog of all Part I and Part II-A obligations | `wardline-75a774e144` |
| `R-RELEASE-PROJECTION-RUNNABLE` | `§15.1`, `§15.6`, release matrix | The derived release projection is assessor-runnable and declares scope, state, next action, reviewer status, and explicit `not_applicable` rows | `evidenced` | The projection now carries runnable release fields, but it still blocks until its backing obligations are green | `wardline-fae28f1be3` |

## Derived Release Projection

The release view is a projection over obligations rather than a separate truth
store.

| Release row | Derived from obligations | Current result |
|---|---|---|
| `C01` Claimed regime map and profile claim | `R-REGIME-COVERAGE-COMPLETE`, `R-CATALOG-COMPLETENESS`, `R-RELEASE-PROJECTION-RUNNABLE` | blocked |
| `C02` Core tier model and runtime constructs | `P1-S6-TAINT-JOIN-ABSORBING` plus pending core/runtime catalog expansion | blocked |
| `C03` Decorator vocabulary and discovery | pending catalog population for decorator/discovery obligations | blocked |
| `C04` Manifest, schema, and governance | `C-CRIT-9-GOVERNANCE-MINIMUMS`, `C-CRIT-10-MANIFEST-CONSUMPTION`, `G-LITE-CHECKLIST-VERIFIABLE`, `G-CONTROL-LAW-NORMAL-FOR-RELEASE`, `G-RETROSCAN-AFTER-DEGRADED-LAW` | at risk |
| `C05` Scanner engine and rule registration | `P1-S6-TAINT-JOIN-ABSORBING`, `P2A-A3-L1-MINIMUM-CONFORMANCE` | blocked |
| `C06` CLI, SARIF, and explainability | `C-CRIT-8-DETERMINISTIC-SARIF`, `C-CRIT-7-SELF-HOSTING` | blocked |
| `C07` Corpus integrity and measurement | `C-CRIT-5-PER-CELL-MEASUREMENT`, `C-CRIT-6-GOLDEN-CORPUS`, `P1-S11-CORPUS-INDEPENDENCE` | blocked |
| `C08` Final release evidence bundle | every release-scoped obligation above | blocked |
| `C09` Wardline-Type layer | claim-scope metadata only | not_applicable |

## Next Expansion

To reach full compliance visibility, the next catalog population pass must add:

- all remaining Part I normative obligations claimed by the Python regime
- the full Part II-A interface contract and binding-specific rule obligations
- the structured requirement sets already maintained under
  `docs/requirements/spec-fitness/`
- waiver records, if any, with approver, rationale, scope, and expiry
- automatic freshness invalidation rules for the machine-readable ledger
