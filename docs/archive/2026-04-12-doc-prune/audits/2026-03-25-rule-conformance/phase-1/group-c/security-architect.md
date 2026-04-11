# Security Architect — Group C: Structural Verification

**Reviewer:** Security Architect
**Date:** 2026-03-25
**Rules:** PY-WL-007 (WL-006), PY-WL-008 (WL-007), PY-WL-009 (WL-008)
**Scope:** Threat model alignment and bypass resistance

---

## 1. ACF-S3 Alignment for PY-WL-007

**Question:** Does isinstance() detection actually signal structural identity doubt?

**Assessment: ALIGNED, with correct scope.**

PY-WL-007 detects `isinstance()` and `type() == / is` comparisons on internal data. The spec (section 2, footnote on ACF-S3) is precise: WL-006 is *not* the S3 fix. It is a *signal* that the codebase may harbour S3-class issues. The rule's implementation matches this intent exactly -- it fires as WARNING/RELAXED in SHAPE_VALIDATED and PIPELINE contexts, not ERROR/UNCONDITIONAL, which correctly communicates "this is suspicious, not categorically wrong."

The suppression list is well-constructed:

- **AST node dispatch** (`isinstance(node, ast.Assign)`): Correct suppression. This is tagged-union dispatch, not trust-boundary type doubt.
- **Dunder comparison protocol** (`isinstance(other, Cls)` in `__eq__` returning `NotImplemented`): Correct. Required by Python's data model, not a trust signal.
- **Frozen dataclass construction** (`isinstance(self.x, dict)` in `__post_init__` with `object.__setattr__`): Correct. Defensive freezing pattern.
- **Declared boundary suppression**: This is the critical one. When a function has a wardline boundary decorator, `isinstance` is the *implementation* of the declared contract. Suppression is correct -- the rule's job is to detect *undeclared* type doubt, not to fire on the mechanism that resolves it.

**No concerns.**

## 2. PY-WL-008 as Defence Against Adversarial Annotation Injection

**Question:** Agent declares `@validates_shape` but function is a pass-through. Does the rule catch this?

**Assessment: PARTIALLY EFFECTIVE, with a documented gap.**

PY-WL-008's `_has_rejection_path()` checks for:
1. A bare `raise` statement anywhere in the body.
2. An `if` with a negative guard (`not x`, `x is None`, etc.) whose body contains `raise` or `return`.
3. An `if/else` where the else branch contains `raise` or `return`.

**What it catches:**
- A function with no conditional logic at all (pure pass-through).
- A function that only returns a value unconditionally.
- A function that only logs or transforms without any branching.

**What it does NOT catch (the gap):**

**Trivial rejection paths.** The rule checks *presence* of a rejection path, not *quality*. An adversary can satisfy PY-WL-008 with:

```python
@validates_shape
def validate(data):
    if not isinstance(data, object):  # Always False -- object is the root type
        raise ValueError("invalid")
    return data
```

This passes PY-WL-008 because: (a) there is an `if` with a negative guard (`not isinstance(...)`), and (b) the body contains `raise`. The rejection path is structurally present but semantically unreachable. The spec (section 7.2) explicitly acknowledges this: "the scanner SHOULD detect trivially unreachable rejection paths (constant-False guards, `if 0:`, `if "":`)" but notes that "full reachability analysis is not REQUIRED." The `isinstance(data, object)` case is not a constant-expression guard -- it requires semantic knowledge that `object` is the universal base class. This is a real gap.

**Spec alignment:** This gap is documented as residual risk 9 (section 12): "An adversary or agent can modify a function's body to circumvent the wardline's intent (e.g., making a rejection path unreachable by guarding it with a condition that is always false due to upstream logic rather than a constant expression)." The implementation is consistent with the spec's stated trade-off, but the gap is exploitable.

**Severity of this gap:** MODERATE. Exploitation requires the adversary to (a) add a wardline boundary decorator and (b) craft a vacuous rejection path. Both changes are governance-visible through the fingerprint baseline. The attack is detectable by human review but not by the scanner.

## 3. Cross-Rule Evasion Dynamics

**Question:** If evading PY-WL-007 (by declaring a boundary) triggers PY-WL-008 (boundary must have rejection path), is this complementary? Can both be evaded simultaneously?

**Assessment: COMPLEMENTARY, but simultaneously evadable.**

The cross-rule interaction works as intended:

1. **PY-WL-007 fires** on `isinstance()` in non-boundary functions: "you have structural doubt about internal data."
2. **To suppress PY-WL-007**, the developer declares a boundary (`@validates_shape`). This is the correct resolution -- make the type-checking explicit and governed.
3. **PY-WL-008 then activates** on the declared boundary: "your boundary must have a rejection path."

This is a genuine complementary defence. An agent cannot simply add `@validates_shape` to silence PY-WL-007 without also satisfying PY-WL-008.

**However, simultaneous evasion IS possible:**

```python
@validates_shape
def validate(data):
    if not data:  # Negative guard -- satisfies PY-WL-008
        raise ValueError("empty")
    # isinstance() suppressed by declared boundary -- evades PY-WL-007
    return data
```

This function: (a) has a declared boundary, so PY-WL-007 suppresses all `isinstance()` calls within it; (b) has a rejection path (`if not data: raise`), so PY-WL-008 is satisfied; but (c) performs no actual shape validation -- it only rejects falsy values (empty strings, zero, None, empty containers). The function passes both rules while providing negligible structural verification.

**Is this a real threat?** YES. This is the natural pattern an agent produces when asked to "add validation" -- a truthiness check and an early raise. It is not adversarial; it is the default behaviour of current-generation LLMs when asked to "add a validation boundary." The spec's section 12 risk 12 (evasion surface trajectory) acknowledges this: "Current LLMs produce structurally sloppy code that trips syntactic tripwires [...] As models improve at producing structurally clean but semantically wrong code, they will naturally route around syntactic tripwires without adversarial intent."

**Mitigation question:** Should PY-WL-008 distinguish between shape-relevant rejection conditions (isinstance, hasattr, key-in-dict) and non-shape rejection conditions (truthiness, length, None-check)? The spec says no: "the scanner enforces presence, not kind" (section 7.2). This is a deliberate design choice that accepts the gap.

## 4. PY-WL-009 Ordering Enforcement: Dead isinstance() Evasion

**Question:** Can an agent skip shape validation by adding a dead `isinstance()` as fake shape evidence?

**Assessment: VULNERABLE. This is the most significant finding in this audit.**

PY-WL-009's `_is_shape_validation_call()` (lines 93-130 of `py_wl_009.py`) accepts `isinstance` and `hasattr` *unconditionally* as shape validation evidence:

```python
if isinstance(call.func, ast.Name):
    name = call.func.id
    if name in ("isinstance", "hasattr"):
        return True  # No check on WHAT is being checked
```

This means the following evades PY-WL-009:

```python
@validates_semantic
def validate_business_rules(data):
    isinstance(data, object)  # Dead expression -- always True, result discarded
    if data["amount"] > 1000:  # Semantic check on unvalidated shape
        raise ValueError("over limit")
    return data
```

The `isinstance(data, object)` call is: (a) a no-op expression statement (result is not used), (b) checking against `object` (always True), and (c) placed before the semantic check to satisfy the `stop_line` ordering. PY-WL-009 sees `isinstance` before the semantic check and suppresses the finding.

**More subtle variant** (not even adversarial):

```python
@validates_semantic
def validate_business_rules(data):
    if isinstance(data, dict):  # Shape check -- but only on container type
        pass  # No rejection on failure!
    if data["amount"] > 1000:  # Still accessing keys without real shape guarantee
        raise ValueError("over limit")
```

This also evades PY-WL-009 because `isinstance(data, dict)` appears before line N and is recognised as a shape check. But the isinstance result is not used as a guard -- there is no rejection path if data is NOT a dict. The code proceeds to `data["amount"]` regardless.

**Root cause:** PY-WL-009's `_has_shape_check_before()` checks for *presence* of shape-validation calls before the semantic check line number. It does not verify that:
1. The shape check's result is actually used in a conditional guard.
2. The conditional guard has a rejection path for the failure case.
3. The type being checked is meaningful (not `object`).

**Spec alignment:** The spec (section 7.2) says WL-008 is "an ordering constraint, not a body-content check" and that "the scanner verifies that a declared semantic-validation boundary's inputs trace back to a shape-validation boundary's outputs." The current implementation checks for *co-occurrence* of shape-check calls before semantic checks within the same function body. This is a weaker property than the spec's "inputs trace back to outputs" -- the spec describes a dataflow relationship, while the implementation checks syntactic ordering.

**Severity: HIGH.** This is not an exotic adversarial attack. An agent naturally produces `isinstance(data, dict)` as "shape validation" without connecting it to a rejection path. The result is a semantic validator that claims shape has been checked but has no actual enforcement of shape invariants. This directly undermines the section 5.2 invariant 3 (shape validation must precede semantic validation) that PY-WL-009 exists to enforce.

## 5. Residual Risk Alignment

### Risk 9: Adversarial Annotation Injection

The three rules provide layered but incomplete defence:

| Attack | PY-WL-007 | PY-WL-008 | PY-WL-009 | Net |
|--------|-----------|-----------|-----------|-----|
| Add `@validates_shape` to pass-through | Suppresses isinstance findings | **FIRES** (no rejection path) | N/A | Caught |
| Add `@validates_shape` with vacuous guard | Suppresses isinstance findings | Silent (guard present) | N/A | **EVADES** |
| Add `@validates_semantic` with dead isinstance | N/A | May fire (if no rejection path) | **Silent** (isinstance counts as shape evidence) | **EVADES** |
| Add `@validates_semantic` with vacuous isinstance + vacuous guard | N/A | Silent | Silent | **EVADES ALL THREE** |

The last row is the critical combination. An agent can produce:

```python
@validates_semantic
def validate(data):
    isinstance(data, dict)  # Dead shape evidence -- evades PY-WL-009
    if not data:            # Vacuous guard -- evades PY-WL-008
        raise ValueError("empty")
    if data["status"] in ("active", "pending"):  # Unguarded semantic check
        return data
    raise ValueError("bad status")
```

This passes all three rules, has a declared boundary decorator (governance-visible), has a "rejection path," has "shape evidence" before the semantic check, and provides essentially no structural verification of the data's shape.

### Risk 12: Evasion Trajectory

The current rule set is well-positioned against *current* LLM output, which tends to omit rejection paths entirely (caught by PY-WL-008) or perform isinstance checks on internal data without declaring boundaries (caught by PY-WL-007). The evasion patterns identified above require a model that:
1. Understands wardline boundary decorators (context-window dependent).
2. Knows to add both a rejection path AND a shape check (two independent requirements).
3. Produces syntactically correct but semantically vacuous implementations.

Current models do not reliably produce this pattern, but it is the natural trajectory as models learn from codebases that use wardline annotations. The gap will widen over time without countermeasures.

## 6. Specific Recommendations

1. **PY-WL-009: Guard-connected shape checks.** The most impactful improvement would be to verify that shape-validation calls appear inside conditional guards (if/assert tests) rather than as bare expression statements. A bare `isinstance(data, dict)` with no surrounding conditional is not shape *validation* -- it is shape *observation* with the result discarded. This would close the dead-isinstance evasion without requiring dataflow analysis.

2. **PY-WL-008: Vacuous type checks.** Consider detecting `isinstance(x, object)` as a trivially-true guard in `_is_negative_guard` or a dedicated check. This is a narrow, high-confidence heuristic -- `object` is always the universal base class in Python.

3. **Cross-rule: PY-WL-008 + PY-WL-009 coordination.** When PY-WL-009 suppresses a finding because shape evidence exists, PY-WL-008 should verify that the shape evidence is connected to a rejection path. Currently the two rules operate independently on the same function body without sharing analysis results.

---

## Verdict: CONCERN

**Evidence:**

- PY-WL-007 is well-aligned with ACF-S3 and has a sound suppression model. PASS.
- PY-WL-008 catches structurally absent rejection paths but accepts vacuous ones (e.g., `isinstance(data, object)` guards). This is a documented and spec-acknowledged gap. CONCERN.
- PY-WL-009 accepts any `isinstance()` or `hasattr()` call as shape evidence regardless of whether the result is used, the type is meaningful, or a rejection path exists for the failure case. This is the most significant gap: the dead-isinstance evasion undermines the ordering invariant that PY-WL-009 exists to enforce. CONCERN.
- Cross-rule evasion is possible by combining a vacuous rejection path (evades PY-WL-008) with a dead shape check (evades PY-WL-009), both under a declared boundary decorator (suppresses PY-WL-007). The resulting code passes all three rules while providing no structural verification.
- All identified gaps are consistent with the spec's documented residual risks (section 12, risks 9 and 12) and the spec's explicit statement that "the scanner enforces presence, not kind" (section 7.2). The implementation is spec-conformant. The concern is with the residual attack surface, not with implementation fidelity.

**Recommendation:** Address the PY-WL-009 dead-isinstance gap (recommendation 1 above) as the highest-priority hardening item. It is the lowest-cost, highest-impact improvement: checking that shape-validation calls appear inside conditional guards rather than as bare expressions requires no dataflow analysis and closes the most natural evasion path.
