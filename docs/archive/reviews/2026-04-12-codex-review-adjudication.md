# 2026-04-12 Codex Review Adjudication

## Scope

This note records the higher-signal review feedback received after the initial
§15 obligation-ledger rewrite. It exists so the feedback survives the rewrite
itself and so later reviewers can distinguish:

- findings already resolved by the current branch state
- findings accepted as live defects
- findings treated as interpretation differences rather than defects

The reviewed artefacts were:

- `docs/spec/wardline-01-15-conformance.md`
- `docs/verification/2026-04-12-v1-0-cell-certification-matrix.md`
- `docs/verification/2026-04-12-v1-0-compliance-ledger.md`
- `wardline.compliance.json`

## Adjudication Summary

The review correctly identified that the branch had moved in the right
direction, but had not yet restored several assessable obligations that the
prior §15 carried more explicitly. The live defects fall into four buckets:

1. The derived release projection was no longer runnable as a release artefact.
2. Lite governance had been compressed below assessor-runnable form.
3. Control-law and retrospective-scan release gating had been weakened.
4. Claimed release surface and rule/profile traceability were still ambiguous.

## Finding Disposition

| Finding | Disposition | Notes |
|---|---|---|
| Matrix no longer carries state/disposition/sign-off fields | Accepted | The matrix is now a derived view, which is correct, but it still needs explicit row state, release-scope, next-action, and reviewer fields if it is to authorize ship. |
| Explicit release gate for `wardline.controlLaw: normal` was dropped | Accepted | This weakens release gating and must be restored in §15 and the derived release projection. |
| Explicit retrospective-scan check after alternate/direct law was dropped | Accepted | This is still required by §10.5 and by spec-fitness governance baselines. |
| Lite governance checklist was weakened into short labels | Accepted | The seven-point Lite checklist must remain explicit and assessor-runnable. |
| Claimed release profile/regime is unclear; Wardline-Type scope is ambiguous | Accepted | The release projection and ledger must state the claimed profiles and the explicit out-of-scope surfaces. |
| Rule mapping for `R07`-`R10` drifts from the Python binding | Accepted | The derived matrix must use the binding's framework-to-Python mapping, not ad hoc row references. |
| Step 3 corpus requirements are weaker than prior §15 and spec-fitness baselines | Accepted | Corpus integrity, floor semantics, and minimum adversarial/suppression-interaction coverage must be restated explicitly. |
| Supplementary rows are not distinguished as required vs optional | Accepted | The release view must separate required framework rows, active binding-specific rows, and optional supplementary rows not claimed for this release. |
| “Phase 3 deployment” example title is stale | Already resolved | The obligation-ledger rewrite had already removed that adoption-phase wording. |

## Follow-through

The corrective pass after this note should:

- keep the obligation ledger as the source of truth
- restore the dropped assessable obligations in §15
- make the release projection an explicit, runnable derived view
- align the release claim surface with the Python binding and governance profile
- reflect the same claim surface and blocking conditions in
  `wardline.compliance.json`
