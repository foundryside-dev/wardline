# Phase 2 F2: Validation Boundary Assessment

**Auditor role:** Validation Boundary Agent
**Date:** 2026-03-25
**Scope:** Whether validation boundary declarations correctly implement tier transitions and body evaluation context.

---

## 1. Body Evaluation Context

**Spec requirement (A.4.3):** Pattern rules within validation boundary bodies use severity lookups of the INPUT tier:

| Decorator | Input tier | Body evaluation severity |
|-----------|-----------|-------------------------|
| `@validates_shape` | TIER_4 | EXTERNAL_RAW |
| `@validates_semantic` | TIER_3 | SHAPE_VALIDATED |
| `@validates_external` | TIER_4 | EXTERNAL_RAW |

**Implementation (function_level.py lines 41-49):**

```python
DECORATOR_TAINT_MAP: dict[str, TaintState] = {
    "external_boundary": TaintState.EXTERNAL_RAW,
    "validates_shape": TaintState.SHAPE_VALIDATED,
    "validates_semantic": TaintState.PIPELINE,
    "validates_external": TaintState.PIPELINE,
    ...
}
```

**Finding: FAIL.** The taint map assigns the OUTPUT tier, not the INPUT tier:

| Decorator | Spec requires (input) | Implementation assigns (output) | Correct? |
|-----------|----------------------|-------------------------------|----------|
| `@validates_shape` | EXTERNAL_RAW | SHAPE_VALIDATED | NO |
| `@validates_semantic` | SHAPE_VALIDATED | PIPELINE | NO |
| `@validates_external` | EXTERNAL_RAW | PIPELINE | NO |

All three validation boundary decorators are assigned to their output taint state. The spec explicitly states: "the scanner evaluates pattern rules within validation boundary bodies using the severity lookups of the **input tier** -- the tier the validator operates on, not the tier it produces." The implementation does the opposite.

**Impact:** Pattern rules (PY-WL-001 through PY-WL-005) evaluated inside validation boundary bodies receive a less strict severity than intended. For example, `@validates_shape` bodies should evaluate at EXTERNAL_RAW severity (sceptical programming) but instead evaluate at SHAPE_VALIDATED severity (guarded programming). This is a false-negative generator: violations inside validators are graded at a lower severity than the spec mandates.

**Note on design ambiguity:** The DECORATOR_TAINT_MAP serves double duty: (1) it determines the function-level taint for pattern rule severity lookups within the body, and (2) it determines the taint state the scanner assigns to the return value for downstream propagation. The spec requires different values for these two purposes. The current architecture conflates them into a single mapping.

---

## 2. Transition Completeness

**Spec requires 5 transition types (SS5.2):**

1. Shape validation: T4 to T3
2. Semantic validation: T3 to T2
3. Combined validation: T4 to T2
4. Construction: T2 to T1
5. Restoration: raw to T1 (with evidence)

**Decorator-level support (authority.py):**

| Transition | Decorator | `_wardline_transition` | Supported? |
|-----------|-----------|----------------------|------------|
| T4 to T3 | `@validates_shape` | (EXTERNAL_RAW, SHAPE_VALIDATED) | YES |
| T3 to T2 | `@validates_semantic` | (SHAPE_VALIDATED, PIPELINE) | YES |
| T4 to T2 | `@validates_external` | (EXTERNAL_RAW, PIPELINE) | YES |
| T2 to T1 | `@authoritative_construction` | (PIPELINE, AUDIT_TRAIL) | YES |
| Restoration | Not in authority.py | N/A | Declared via Group 17 |

**Overlay schema support (overlay.schema.json):**

```json
"transition": {
  "type": "string",
  "enum": [
    "shape_validation", "semantic_validation",
    "combined_validation", "construction", "restoration"
  ]
}
```

**Finding: PASS.** All five transition types are supported. Decorators cover the first four; restoration is handled by Group 17 (`@restoration_boundary`). The overlay schema enumerates all five valid transitions.

**Note:** PY-WL-008's `_BOUNDARY_TRANSITIONS` set includes both `external_validation` and `combined_validation` as distinct strings. The overlay schema only includes `combined_validation`. The `external_validation` string appears to be a legacy synonym used in code but not in the schema. This is not a conformance failure since it broadens acceptance, but it creates a terminology inconsistency.

---

## 3. Skip-Promotion Rejection

**Spec requirement (SS5.2 invariant 4):** T2 does not automatically upgrade to T1. The spec also states (A.4.2): "Skip-promotions to T1 are schema-invalid."

**Schema-level enforcement:** The overlay schema constrains `transition` to the enum `["shape_validation", "semantic_validation", "combined_validation", "construction", "restoration"]`. There is no `"skip_promotion"` or direct T4-to-T1 / T3-to-T1 transition type. Any attempt to declare such a transition in the manifest would fail schema validation.

**Decorator-level enforcement:** The Group 1 decorators have hardcoded transition tuples:
- `@validates_shape`: (EXTERNAL_RAW, SHAPE_VALIDATED) -- T4 to T3 only
- `@validates_semantic`: (SHAPE_VALIDATED, PIPELINE) -- T3 to T2 only
- `@validates_external`: (EXTERNAL_RAW, PIPELINE) -- T4 to T2 only
- `@authoritative_construction`: (PIPELINE, AUDIT_TRAIL) -- T2 to T1 only

There is no decorator that can express T4-to-T1 or T3-to-T1.

**Group 16 `@trust_boundary`:** The `trust_boundary` decorator in `boundaries.py` only sets `_wardline_trust_boundary=True` as a boolean flag -- it does not carry `from_tier`/`to_tier` parameters in the current implementation. The spec (A.4.2 row 16) describes `@trust_boundary(from_tier=N, to_tier=M)` with the note "Skip-promotions to T1 are schema-invalid." Since the parameterised form is not yet implemented, skip-promotion via Group 16 is structurally impossible in the current codebase.

**Finding: PASS.** Skip-promotion is prevented through:
1. Schema enum constraint on overlay boundary transitions
2. Hardcoded transition tuples in Group 1 decorators
3. Group 16 parameterised form not yet implemented (cannot be misused)

---

## 4. Combined Boundary Semantics

**Spec requirement (SS5.2):** Combined validation boundaries perform both shape and semantic validation (T4 to T2). The scanner must establish that the body performs both structural and semantic checks.

**`@validates_external` declaration (authority.py line 40-44):**

```python
validates_external = wardline_decorator(
    1,
    "validates_external",
    _wardline_transition=(TaintState.EXTERNAL_RAW, TaintState.PIPELINE),
)
```

This correctly models the T4-to-T2 transition as EXTERNAL_RAW to PIPELINE.

**PY-WL-009 combined boundary exemption (py_wl_009.py lines 229-231):**

```python
def visit_function(self, node, *, is_async):
    if self._is_combined_boundary(node):
        return  # exempt from ordering check
```

Combined boundaries are checked first and exempted from PY-WL-009. The `_is_combined_boundary` method checks both manifest transitions (`combined_validation`, `external_validation`) and direct decorators (`validates_external`).

**Spec says (A.4.3):** "A function that performs both checks in a single body satisfies this invariant internally."

**PY-WL-008 coverage:** Combined boundaries ARE checked by PY-WL-008 for rejection paths. The `_BOUNDARY_TRANSITIONS` set in PY-WL-008 includes `external_validation` and `combined_validation`, and `_BOUNDARY_DECORATORS` includes `validates_external`.

**Missing enforcement:** The spec states "The scanner must be able to establish that the boundary performs both structural and semantic checks." PY-WL-008 only checks for a rejection path (WL-007). There is no rule that verifies a combined boundary actually performs BOTH shape AND semantic validation. The combined boundary is trusted to do both, but only the rejection path is verified. This is a gap, though arguably a deferred-scope item rather than a conformance failure, as the spec uses "must be able to establish" which may be interpreted as a capability requirement rather than a mandatory check.

**Finding: CONCERN.** The combined boundary exemption from PY-WL-009 is correct. The rejection path check via PY-WL-008 is present. However, there is no enforcement that combined boundaries actually perform both structural AND semantic checks -- only that they have a rejection path. A `@validates_external` function with only shape checks (no semantic validation) would pass all current rules despite not satisfying the T4-to-T2 contract.

---

## 5. Boundary-to-Taint Mapping

**Question:** After a function passes through `@validates_shape`, does the scanner assign SHAPE_VALIDATED taint to the return value?

**Function-level taint assignment (function_level.py):** The `DECORATOR_TAINT_MAP` assigns `validates_shape` to `TaintState.SHAPE_VALIDATED`. The `assign_function_taints` function assigns this taint to the function's qualname in the taint map. All code within the body of a `@validates_shape` function operates under SHAPE_VALIDATED taint at analysis level 1.

**Runtime tier stamping (_base.py):** The `wardline_decorator` factory computes an `output_tier` from the transition tuple's second element. For `@validates_shape`, the transition is `(EXTERNAL_RAW, SHAPE_VALIDATED)`, so `output_tier` derives from SHAPE_VALIDATED. At runtime (when enforcement is enabled), the return value is stamped with this tier via `_try_stamp_tier`.

**Scanner-level propagation:** The taint map entry for a `@validates_shape` function is SHAPE_VALIDATED. When another function calls a `@validates_shape` function, call-graph propagation (Level 3) or the caller's own taint assignment determines the caller's taint. At Level 1, the return value's taint is not tracked across function boundaries -- only the callee's function-level taint is recorded.

**Finding: PARTIAL PASS.** The taint mapping from `@validates_shape` to SHAPE_VALIDATED is correct for the return value / function-level taint. However, this is the same mapping that creates the body evaluation context issue identified in Finding 1 -- the function's body should evaluate at EXTERNAL_RAW (input tier) but evaluates at SHAPE_VALIDATED (output tier).

---

## Summary of Findings

| # | Assessment Area | Finding | Severity |
|---|----------------|---------|----------|
| 1 | Body evaluation context | FAIL: Taint assigned to validation boundary bodies uses OUTPUT tier, not INPUT tier as spec requires | HIGH |
| 2 | Transition completeness | PASS: All 5 transition types supported | -- |
| 3 | Skip-promotion rejection | PASS: Prevented at schema, decorator, and Group 16 levels | -- |
| 4 | Combined boundary semantics | CONCERN: PY-WL-009 exemption correct, but no enforcement that combined boundaries perform BOTH structural AND semantic validation | MEDIUM |
| 5 | Boundary-to-taint mapping | PASS (for return value); FAIL (for body context, same as #1) | -- |

---

## Verdict: FAIL

**Primary failure:** The body evaluation context for validation boundaries uses the output tier instead of the input tier as mandated by spec SS A.4.3. This is a systematic false-negative generator affecting all pattern rules (PY-WL-001 through PY-WL-005) evaluated inside validation boundary bodies.

**Evidence:**
- `DECORATOR_TAINT_MAP` in `src/wardline/scanner/taint/function_level.py` lines 41-49 assigns `validates_shape` to `SHAPE_VALIDATED` (output), not `EXTERNAL_RAW` (input).
- Spec SS A.4.3 table explicitly requires body evaluation at EXTERNAL_RAW for `@validates_shape`.
- The architecture conflates two distinct concerns (body evaluation taint vs. return value taint) into a single mapping table.

**Secondary concern:** No enforcement that `@validates_external` combined boundaries actually perform both structural and semantic validation. The rejection path check (PY-WL-008) is necessary but not sufficient.
