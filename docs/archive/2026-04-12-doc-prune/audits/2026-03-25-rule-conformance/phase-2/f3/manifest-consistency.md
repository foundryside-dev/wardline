# F3: Manifest/Overlay Consistency Assessment

**Auditor:** Manifest/Overlay Consistency Agent
**Date:** 2026-03-25
**Scope:** Manifest validation, overlay merge, SARIF descriptions, coherence checks, matrix protection, ratification enforcement

---

## 1. Manifest Validation

**Question:** Does the loader validate wardline.yaml against JSON schema? Is a malformed manifest a hard error?

**Finding: PASS**

`src/wardline/manifest/loader.py` implements a five-step validation pipeline:

1. **File size check** -- 1MB limit (`MAX_FILE_SIZE = 1_048_576`), raises `ManifestLoadError` on breach.
2. **YAML parse with alias-bomb protection** -- Custom SafeLoader subclass counts alias resolutions against a hard-capped limit (`HARD_ALIAS_UPPER_BOUND = 10_000`), raises `WardlineYAMLError` on breach.
3. **$id version check** -- Extracts version from `$id` URL, raises `ManifestLoadError` on mismatch against `EXPECTED_SCHEMA_VERSION`.
4. **JSON Schema validation** -- `_validate_schema()` loads `wardline.schema.json` and calls `jsonschema.validate()`, raising `ManifestLoadError` on failure.
5. **Dataclass construction** -- Builds frozen `WardlineManifest` from validated data.

All validation failures raise exceptions (hard errors). There is no best-effort parsing or fallback behaviour. This conforms to the spec requirement in section 13.1.1: "a malformed manifest is a hard error, not a best-effort parse."

Overlays follow the same pipeline against `overlay.schema.json`.

Schema files confirmed present in `src/wardline/manifest/schemas/`:
- `wardline.schema.json` (root manifest)
- `overlay.schema.json`
- `exceptions.schema.json`
- `fingerprint.schema.json`
- `corpus-specimen.schema.json`

---

## 2. Overlay Merge (Narrowing-Only)

**Question:** Does merge enforce narrowing-only? Are widening overrides rejected as errors?

**Finding: PASS**

`src/wardline/manifest/merge.py` enforces narrowing-only at two levels:

### Severity narrowing
Lines 108-119: When an overlay rule override has lower severity rank than the base, `ManifestWidenError` is raised. The severity ranking is `OFF(0) < INFO(1) < WARNING(2) < ERROR(3) < CRITICAL(4)` -- a lower rank in the overlay triggers the error.

### Boundary-level narrowing
Lines 137-156: Boundary `from_tier` and `to_tier` values are checked against the module's default tier (resolved via longest-prefix match). A boundary that declares a tier number higher than the module tier raises `ManifestWidenError`.

`ManifestWidenError` is a hard exception (not a warning), conforming to the spec: "An enforcement tool that encounters a widening override in an overlay MUST reject the overlay with an error, not a warning."

**Minor note:** The overlay merge does not explicitly check tier-assignment widening (e.g., an overlay cannot relax a tier from 1 to 2). This is not currently a merge concern since overlays do not carry `tiers` sections -- tier definitions live only in the root manifest. The architecture avoids the problem by design.

---

## 3. SARIF _RULE_SHORT_DESCRIPTIONS Audit

**Question:** Audit every entry. Which are correct? Which are stale/wrong?

Cross-referencing `_RULE_SHORT_DESCRIPTIONS` in `src/wardline/scanner/sarif.py` against spec section 7.1:

### Canonical analysis rules

| RuleId | SARIF Description | Spec Description | Verdict |
|--------|-------------------|------------------|---------|
| PY_WL_001 | "Dict key access with fallback default" | WL-001: "Accessing a member (field or attribute) with a fallback default" | **CORRECT** -- PY-WL-001 is the dict-key sub-rule of WL-001 |
| PY_WL_002 | "Attribute access with fallback default" | WL-001 (attribute sub-rule) | **CORRECT** -- PY-WL-002 is the attribute sub-rule of WL-001 |
| PY_WL_003 | "Existence-checking as structural gate" | WL-002: "Using existence-checking as a structural gate" | **CORRECT** |
| PY_WL_004 | "Broad exception handler" | WL-003: "Catching all exceptions broadly" | **CORRECT** -- reasonable shortening |
| PY_WL_005 | "Silent exception handler" | WL-004: "Catching exceptions silently (no action taken)" | **CORRECT** -- reasonable shortening |
| PY_WL_006 | "Audit-critical write in broad exception handler" | WL-005: "Audit-critical writes inside broad exception handlers" | **CORRECT** |
| PY_WL_007 | "Runtime type-checking on internal data" | WL-006: "Type-checking internal data at runtime" | **CORRECT** |
| PY_WL_008 | "Validation boundary with no rejection path" | WL-007: "Boundary with no rejection path" | **CORRECT** |
| PY_WL_009 | "Semantic validation without prior shape validation" | WL-008: "Semantic validation without prior shape validation" | **CORRECT** |
| SCN_021 | "Contradictory or suspicious wardline decorator combination" | N/A (scanner-level rule) | **CORRECT** -- self-describing |
| SUP_001 | "Supplementary decorator contract violation" | N/A (supplementary rule) | **CORRECT** -- self-describing |

### Pseudo-rule-IDs (diagnostic/governance)

| RuleId | Description | Verdict |
|--------|-------------|---------|
| PY_WL_001_GOVERNED_DEFAULT | "Governed default value (diagnostic)" | **CORRECT** |
| PY_WL_001_UNGOVERNED_DEFAULT | "Ungoverned schema_default() -- no overlay boundary (diagnostic)" | **CORRECT** |
| WARDLINE_UNRESOLVED_DECORATOR | "Unresolved decorator (diagnostic)" | **CORRECT** |
| TOOL_ERROR | "Internal tool error" | **CORRECT** |
| GOVERNANCE_REGISTRY_MISMATCH_ALLOWED | "Registry mismatch allowed (diagnostic)" | **CORRECT** |
| GOVERNANCE_RULE_DISABLED | "Rule disabled by configuration (governance)" | **CORRECT** |
| GOVERNANCE_PERMISSIVE_DISTRIBUTION | "Permissive distribution allowed (governance)" | **CORRECT** |
| GOVERNANCE_STALE_EXCEPTION | "Stale exception -- AST fingerprint mismatch (governance)" | **CORRECT** |
| GOVERNANCE_UNKNOWN_PROVENANCE | "Unknown agent provenance on exception (governance)" | **CORRECT** |
| GOVERNANCE_RECURRING_EXCEPTION | "Recurring exception -- multiple renewals (governance)" | **CORRECT** |
| GOVERNANCE_BATCH_REFRESH | "Batch exception refresh performed (governance)" | **CORRECT** |
| GOVERNANCE_NO_EXPIRY_EXCEPTION | "Exception has no expiry date (governance)" | **CORRECT** |
| GOVERNANCE_EXCEPTION_TAINT_DRIFT | "Exception taint state no longer matches function's effective taint" | **CORRECT** |
| GOVERNANCE_EXCEPTION_LEVEL_STALE | "Exception granted at lower analysis level than active scan" | **CORRECT** |
| L3_LOW_RESOLUTION | "L3 call-graph taint based on minority of call edges (>70% unresolved)" | **CORRECT** |
| L3_CONVERGENCE_BOUND | "L3 propagation hit iteration safety bound -- results may be incomplete" | **CORRECT** |

**Summary:** All 27 SARIF rule descriptions are accurate. The Phase 1 report that "6+ rules" had wrong descriptions appears to have been addressed or was incorrect. Every canonical rule description correctly maps to its spec-defined pattern name (accounting for the WL-001 split into PY-WL-001/002 sub-rules).

---

## 4. Coherence Checks (section 9.2 -- Five Conditions)

**Question:** Are all 5 coherence conditions from section 9.2 implemented?

The spec defines five coherence conditions. Assessment against `src/wardline/manifest/coherence.py`:

| # | Condition | Status | Implementation |
|---|-----------|--------|----------------|
| 1 | **Tier-topology consistency** | **NOT IMPLEMENTED** | No function checks tier assignments against data-flow topology. The spec says: "A data source declared at Tier 4 that feeds a consumer declared within a Tier 1 bounded context without an intervening validation boundary is a manifest-level contradiction." No code performs this cross-reference. |
| 2 | **Orphaned annotations** | **IMPLEMENTED** | `check_orphaned_annotations()` (line 43) -- finds decorated functions with no matching boundary declaration. |
| 3 | **Undeclared boundaries** | **IMPLEMENTED** | `check_undeclared_boundaries()` (line 80) -- finds boundary declarations with no matching decorated function in code. |
| 4 | **Unmatched contracts** | **NOT IMPLEMENTED** | No function checks contract declarations against code-level annotations at declared locations. The spec says this "detects contract declarations that have drifted from the code through refactoring." |
| 5 | **Stale contract bindings** | **NOT IMPLEMENTED** | No function verifies that `contract_bindings` function paths resolve to existing functions. The `sup_001.py` file handles contract enforcement at the rule level but does not perform the manifest-level existence check the spec requires. |

Additionally, `coherence.py` implements several governance anomaly checks not in the five-condition list:
- `check_tier_distribution()` -- permissive tier ratio threshold
- `check_tier_downgrades()` -- tier relaxation vs. baseline
- `check_tier_upgrade_without_evidence()` -- tier tightening without boundary evidence
- `check_agent_originated_exceptions()` -- unknown agent provenance
- `check_expired_exceptions()` -- expired and far-future exceptions
- `check_first_scan_perimeter()` -- first-scan detection

**3 of 5 coherence conditions are unimplemented.** Tier-topology consistency, unmatched contracts, and stale contract bindings are missing.

---

## 5. Matrix Structural Protection

**Question:** Is there a mechanism preventing accidental matrix data corruption?

**Finding: PASS**

Multiple layers of protection exist:

1. **Immutable data structure:** `SEVERITY_MATRIX` is a `MappingProxyType` (line 74-76 of `src/wardline/core/matrix.py`). The builder dict is deleted after construction (`del _severity_matrix_builder`). Runtime mutation raises `TypeError`.

2. **Independent fixture test:** `tests/unit/core/test_matrix.py` encodes all 72 cells independently from the spec (not copied from `matrix.py`). The test file enforces this at the AST level -- `test_no_matrix_import_at_module_level()` verifies that the fixture does not import from `wardline.core.matrix` at module level. This is a strong structural protection: a matrix data error requires the same error to be independently introduced in both the matrix and the test fixture.

3. **Well-formedness invariants:**
   - `test_fixture_has_72_cells()` -- exactly 72 cells (9 rules x 8 taint states)
   - `test_every_canonical_pair_has_entry()` -- no missing entries
   - `test_every_cell_has_valid_severity_and_exceptionability()` -- type safety
   - `test_no_duplicate_keys()` -- no key collisions
   - `test_severity_matrix_is_immutable()` -- MappingProxyType assertion

4. **Build-time zip strict:** The matrix builder uses `zip(_TAINT_ORDER, _cells, strict=True)` (line 69), which raises `ValueError` if the row length does not match the column count. This prevents silent truncation or padding.

This is robust structural protection. The independent-fixture pattern is particularly strong.

---

## 6. Ratification Enforcement

**Question:** Does the scanner compute manifest age and flag overdue ratification?

**Finding: CONCERN**

The spec (section 13.1.1) states: "The enforcement tool MUST compute the age of the ratification (current date minus ratification date) and compare it to the declared review interval. When the ratification age exceeds the review interval, the enforcement tool produces a governance-level finding."

**What is implemented:**
- `src/wardline/manifest/regime.py` computes `ratification_age_days` and `ratification_overdue` (lines 195-218).
- `src/wardline/cli/regime_cmd.py` reports overdue ratification as a regime check result (lines 578-594).

**What is missing:**
- The scanner engine (`src/wardline/scanner/engine.py`) does not produce a SARIF finding for overdue ratification.
- There is no `GOVERNANCE_RATIFICATION_OVERDUE` member in `RuleId`.
- The ratification check exists only in the regime CLI command, not in the scan pipeline.

The spec says "the enforcement tool" (the scanner) must produce this finding. Currently it is only surfaced through the `wardline regime` CLI command, not as a SARIF finding in scan output. This is a conformance gap -- the regime command implements the computation correctly, but it is not integrated into the scan pipeline as the spec requires.

---

## Summary of Findings

| Area | Verdict | Detail |
|------|---------|--------|
| Manifest validation | PASS | Full JSON Schema validation, hard errors on all failures |
| Overlay merge narrowing | PASS | Severity and tier widening raise ManifestWidenError |
| SARIF descriptions | PASS | All 27 descriptions are accurate |
| Coherence checks (5 conditions) | FAIL | 3 of 5 missing: tier-topology consistency, unmatched contracts, stale contract bindings |
| Matrix structural protection | PASS | MappingProxyType + independent fixture + well-formedness invariants |
| Ratification enforcement | CONCERN | Computation exists in regime CLI but not surfaced as SARIF finding in scan output |

---

## Verdict: CONCERN

**Evidence:**

The manifest loading, schema validation, and overlay merge semantics are correctly implemented and conform to the spec. SARIF descriptions are all accurate. The severity matrix has strong structural protection.

However, two issues prevent a PASS:

1. **Coherence check gap (3/5 missing).** Tier-topology consistency, unmatched contracts, and stale contract bindings are not implemented. The spec marks these as SHOULD for Lite deployments but MUST for Assurance. At minimum this represents incomplete coverage of section 9.2.

2. **Ratification enforcement not in scan pipeline.** The spec uses MUST language: "the enforcement tool produces a governance-level finding." The computation exists in the regime CLI but does not produce a SARIF finding during scanning. This is a conformance gap against section 13.1.1.

Neither issue introduces incorrect behaviour (no false negatives on what is checked, no wrong results). The concern is about missing coverage, not wrong results.
