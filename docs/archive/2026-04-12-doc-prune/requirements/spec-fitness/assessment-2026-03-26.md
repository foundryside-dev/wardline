# Spec Fitness Assessment — 2026-03-26

This is the first repo fitness assessment against the baseline in this folder.

## Rollup

- Pass: 17 (of 35 assessed)
- Partial: 10
- Fail: 8
- Not assessed: 71 (39 previously in YAML + 32 added in baseline expansion)

Overall judgment: the project has a solid core implementation and test surface, but it is not yet fit to claim clean alignment with the current normative spec. The main issues are concentrated in three areas:

1. Binding-to-spec contract gaps: AST discovery and `schema_default()` handling are solid, but the normative restoration-composition contract and required run-level SARIF properties are not yet met.
2. Manifest and governance drift: `validation_scope` remains incomplete, the self-hosting manifest lacks ratification metadata, and Lite-governance controls are only partially evidenced.
3. Conformance evidence gaps: the scanner is strong on rule logic and two-hop taint behavior, but per-cell metrics, full SARIF property bags, corpus breadth, and substantive self-hosting still lag the spec.

## Verification Run

Targeted tests executed successfully:

```bash
uv run pytest tests/unit/core/test_taints.py \
  tests/unit/core/test_taint_to_tier.py \
  tests/unit/decorators/test_boundaries.py \
  tests/unit/manifest/test_loader.py \
  tests/unit/manifest/test_resolve.py \
  tests/unit/manifest/test_regime.py \
  tests/unit/scanner/test_sarif.py \
  tests/unit/scanner/test_py_wl_001.py \
  tests/unit/scanner/test_py_wl_007.py \
  tests/unit/scanner/test_py_wl_009.py \
  tests/unit/scanner/test_engine_l3.py \
  tests/unit/scanner/test_delegated_rejection.py \
  tests/unit/scanner/test_rejection_path_convergence.py -q
```

Result: `252 passed in 0.38s`

## Assessment Table

| Requirement | Status | Primary evidence | Notes |
|---|---|---|---|
| `WL-FIT-CORE-001` | pass | `src/wardline/core/taints.py`, `tests/unit/core/test_taints.py`, `src/wardline/scanner/sarif.py` | Canonical taint tokens are defined and exercised in tests. |
| `WL-FIT-CORE-002` | pass | `src/wardline/core/taints.py`, `tests/unit/core/test_taints.py` | Join algebra properties are explicitly tested, including exhaustive associativity. |
| `WL-FIT-CORE-003` | pass | `src/wardline/core/taints.py`, `tests/unit/core/test_taints.py` | Known-plus-unknown merges collapse to `MIXED_RAW` as required. |
| `WL-FIT-CORE-004` | pass | `src/wardline/core/tiers.py`, `tests/unit/core/test_taint_to_tier.py` | Tier-to-taint mapping is explicit and complete. |
| `WL-FIT-CORE-005` | pass | `src/wardline/core/matrix.py`, `tests/unit/core/test_matrix.py`, `tests/unit/scanner/test_matrix_cells.py` | Implemented rule/state severity behavior is covered by dedicated tests. |
| `WL-FIT-CORE-006` | fail | `src/wardline/manifest/schemas/overlay.schema.json`, `src/wardline/manifest/loader.py` | Skip-promotions to Tier 1 are not rejected by schema or loader logic. |
| `WL-FIT-CORE-007` | fail | `src/wardline/decorators/__init__.py`, `src/wardline/core/registry.py`, `docs/audits/2026-03-25-rule-conformance/phase-2/f1/evidence-restoration.md` | The Part I restoration contract is not fully realisable in the Python binding because `@restoration_boundary(...)` support is still missing. |
| `WL-FIT-MAN-001` | pass | `src/wardline/manifest/loader.py`, `src/wardline/manifest/schemas/wardline.schema.json`, `tests/unit/manifest/test_schemas.py` | Root manifest schema validation is enforced before model construction. |
| `WL-FIT-MAN-002` | pass | `src/wardline/manifest/resolve.py`, `src/wardline/manifest/scope.py`, `tests/unit/manifest/test_loader.py`, `tests/unit/manifest/test_resolve.py` | Overlay path/scope spoofing is rejected. |
| `WL-FIT-MAN-003` | pass | `src/wardline/manifest/merge.py`, `tests/unit/manifest/test_merge.py`, `tests/unit/manifest/test_resolve.py` | Narrow-only enforcement exists for severity and scoped tier widening. |
| `WL-FIT-MAN-004` | fail | `src/wardline/manifest/models.py`, `src/wardline/manifest/loader.py`, `src/wardline/manifest/schemas/overlay.schema.json`, `docs/audits/2026-03-25-rule-conformance/phase-2/f1/bounded-context.md` | Implementation still uses `bounded_context`; current spec baseline requires `validation_scope`. Presence-check enforcement is also absent. |
| `WL-FIT-MAN-005` | partial | `src/wardline/manifest/models.py`, `src/wardline/manifest/loader.py`, `src/wardline/manifest/resolve.py` | Contract bindings are separate and name-based, but contract declarations remain raw dicts and cross-validation is weak. |
| `WL-FIT-MAN-006` | pass | `src/wardline/scanner/rules/py_wl_001.py`, `tests/unit/scanner/test_py_wl_001.py`, `src/wardline/manifest/resolve.py` | `schema_default()` is tied to overlay optional-field governance and tested. |
| `WL-FIT-MAN-007` | partial | `src/wardline/manifest/models.py`, `src/wardline/manifest/regime.py`, `tests/unit/manifest/test_regime.py`, `wardline.yaml` | Ratification age is computed by the tooling, but the self-hosting root manifest lacks ratification metadata, so the control cannot currently pass on the repo’s own manifest. |
| `WL-FIT-MAN-008` | pass | `src/wardline/manifest/schemas/wardline.schema.json`, `src/wardline/manifest/models.py`, `src/wardline/manifest/loader.py`, `src/wardline/manifest/regime.py`, `src/wardline/scanner/sarif.py` | Governance profile is now modeled in the manifest, consumed by regime reporting, and emitted in SARIF as `wardline.governanceProfile`. |
| `WL-FIT-MAN-009` | partial | `.github/CODEOWNERS`, `wardline.yaml`, `.github/workflows/ci.yml` | Path protection exists for the root manifest, overlays, and corpus, but exception-register and fingerprint-governance paths are not comprehensively covered. |
| `WL-FIT-MAN-010` | partial | `src/wardline/cli/fingerprint_cmd.py`, `src/wardline/scanner/fingerprint.py`, `tests/unit/cli/test_fingerprint_cmd.py` | Fingerprint tooling exists and is tested, but the active self-hosting governance posture is closer to “tools available” than “declared profile fully evidenced.” |
| `WL-FIT-MAN-011` | fail | `wardline.yaml`, `docs/audits/2026-03-25-rule-conformance/phase-2/f3/compliance-surface.md` | No temporal-separation posture or Lite-profile alternative is declared in the self-hosting manifest, so this governance requirement is not assessable. |
| `WL-FIT-SCAN-001` | pass | `src/wardline/scanner/rules/__init__.py`, `src/wardline/scanner/sarif.py`, `tests/unit/scanner/test_sarif.py` | Implemented rules are declared and pseudo-rules are excluded from `implementedRules`. |
| `WL-FIT-SCAN-002` | pass | `tests/unit/scanner/test_py_wl_001.py` through `test_py_wl_009.py`, `tests/unit/scanner/test_scn_021.py` | Implemented rule behavior has substantial unit coverage. |
| `WL-FIT-SCAN-003` | pass | `tests/unit/scanner/test_engine_l3.py`, `tests/unit/scanner/test_delegated_rejection.py`, `tests/unit/scanner/test_rejection_path_convergence.py` | Direct, two-hop, delegated, and convergence paths are explicitly tested. |
| `WL-FIT-SCAN-004` | fail | `src/wardline/scanner/sarif.py`, `tests/unit/scanner/test_sarif.py`, `src/wardline/cli/scan.py` | The scanner emits several required properties, but the full required Part I and A.3 property bag is incomplete, especially at run level (`inputHash`, `inputFiles`, `overlayHashes`, `coverageRatio`, and related fields). |
| `WL-FIT-SCAN-005` | partial | `src/wardline/cli/corpus_cmds.py`, `tests/unit/scanner/test_corpus_runner.py`, `tests/integration/test_corpus_verify.py` | Corpus verification computes and prints metrics, but current reporting is per rule with sample thresholds, not the spec’s required per-cell measured-and-published surface. |
| `WL-FIT-SCAN-006` | partial | `corpus/specimens`, `tests/unit/corpus/test_corpus_skeleton.py`, `tests/unit/scanner/test_corpus_runner.py` | Corpus machinery exists and is runnable, but specimen breadth is still narrower than the full claimed rule surface and adversarial floor. |
| `WL-FIT-SCAN-007` | partial | `tests/integration/test_self_hosting.py`, `tests/integration/test_self_hosting_scan.py`, `docs/audits/2026-03-25-rule-conformance/phase-2/f3/compliance-surface.md` | Self-hosting is exercised, but the current gate is closer to stability checking than a strict “passes its own rules” conformance claim. |
| `WL-FIT-SCAN-008` | partial | `src/wardline/scanner/sarif.py`, `docs/audits/2026-03-25-rule-conformance/phase-2/f3/compliance-surface.md` | The scanner documents and emits implemented rules, but the machine-readable conformance surface still reports no conformance gaps despite tracked gaps. |
| `WL-FIT-PY-001` | pass | `src/wardline/scanner/discovery.py`, `tests/unit/test_wp04_hardening.py` | Decorator discovery is AST-based and explicitly designed around parsed source rather than runtime reflection. |
| `WL-FIT-PY-002` | pass | `src/wardline/decorators/schema.py`, `src/wardline/scanner/rules/py_wl_001.py`, `tests/unit/scanner/test_py_wl_001.py` | `schema_default()` is recognised and tied to overlay-backed governance. |
| `WL-FIT-PY-003` | pass | `src/wardline/scanner/sarif.py`, `tests/unit/scanner/test_sarif.py` | The Python interface contract’s mandatory result-level SARIF fields are emitted. |
| `WL-FIT-PY-004` | fail | `src/wardline/decorators/__init__.py`, `src/wardline/core/registry.py`, `docs/audits/2026-03-25-rule-conformance/phase-2/f1/evidence-restoration.md` | The normative `@int_data` + `@restoration_boundary` composition contract is not satisfied because `@restoration_boundary(...)` is still missing. |
| `WL-FIT-PY-005` | pass | `tests/unit/scanner/test_delegated_rejection.py`, `tests/unit/scanner/test_rejection_path_convergence.py` | Conservative fallback behavior for unresolved delegation is covered by dedicated rejection-path tests. |
| `WL-FIT-PY-006` | partial | `src/wardline/scanner/rules/__init__.py`, `src/wardline/cli/corpus_cmds.py`, `corpus/specimens` | Rule declaration is explicit, but corpus maintenance breadth still lags the claimed conformance surface. |
| `WL-FIT-PY-007` | pass | `src/wardline/cli/scan.py`, `tests/integration/test_determinism.py` | `--verification-mode` exists and deterministic output is tested. |
| `WL-FIT-PY-008` | fail | `src/wardline/scanner/sarif.py`, `src/wardline/cli/scan.py`, `tests/unit/scanner/test_sarif.py` | The Python interface contract’s required run-level properties are incomplete; notably `wardline.inputHash` and `wardline.inputFiles` are absent. |
| `WL-FIT-PY-009` | pass | `src/wardline/cli/scan.py`, `src/wardline/manifest/loader.py`, `tests/integration/test_scan_cmd.py` | The scanner loads and validates the manifest against JSON Schema before producing findings. |

## Requirements Not Yet Assessed

The following requirements were either in the YAML files but not assessed in this initial pass, or were added during the baseline expansion to 106 requirements on 2026-03-26. They require assessment in a subsequent fitness pass.

**Previously in YAML, not assessed (39 requirements):**
CORE-008 through CORE-012, MAN-012 through MAN-013, SCAN-009 through SCAN-014, ENF-001 through ENF-007, GOV-001 through GOV-011, CONF-001 through CONF-008.

**Added in baseline expansion (32 requirements):**
CORE-013 through CORE-017, MAN-014 through MAN-019, SCAN-015 through SCAN-020, PY-010 through PY-012, ENF-008 through ENF-012, GOV-012 through GOV-016, CONF-009 through CONF-010.

## Highest-Value Gaps

1. Finish the restoration contract.
   Add `@restoration_boundary(...)`, register it, and wire scanner behavior so the normative `@int_data` composition rule from A.3 becomes true.

2. Reconcile manifest terminology and validation behavior.
   Replace `bounded_context` with `validation_scope`, add presence checks for Tier 2 semantics, and reject skip-promotions to Tier 1.

3. Complete the required SARIF run-level property bag.
   Add at least `wardline.inputHash`, `wardline.inputFiles`, `wardline.overlayHashes`, `wardline.coverageRatio`, and other missing required run properties.

4. Raise conformance evidence from “tooling exists” to “spec requirement satisfied”.
   This mainly means per-cell corpus metrics, adversarial corpus breadth, and a stricter self-hosting gate.

5. Make Lite governance assessable on the self-hosting repo.
   Add manifest ratification metadata, declare the temporal-separation posture or allowed Lite alternative, and tighten CODEOWNERS coverage for governance artefacts.

## Suggested Next Moves

1. Fix the hard normative blockers first: `WL-FIT-PY-004`, `WL-FIT-CORE-006`, `WL-FIT-MAN-004`, `WL-FIT-SCAN-004`, `WL-FIT-PY-008`.
2. Make the self-hosting governance posture assessable: `WL-FIT-MAN-007`, `WL-FIT-MAN-009`, `WL-FIT-MAN-011`.
3. Then close the evidence-quality gaps: `WL-FIT-SCAN-005`, `WL-FIT-SCAN-006`, `WL-FIT-SCAN-007`, `WL-FIT-SCAN-008`, `WL-FIT-PY-006`.
