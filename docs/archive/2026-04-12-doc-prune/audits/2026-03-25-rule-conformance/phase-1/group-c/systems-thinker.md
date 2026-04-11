# Group C: Structural Verification -- Systems Thinker Audit

**Auditor role:** Systems Thinker
**Date:** 2026-03-25
**Rules under audit:** PY-WL-007 (WL-006), PY-WL-008 (WL-007), PY-WL-009 (WL-008)

---

## 1. The Structural Verification Chain

PY-WL-007, PY-WL-008, and PY-WL-009 form a three-stage verification chain that enforces progressively deeper trust properties on boundary functions:

| Stage | Rule | Question Answered | Scope |
|-------|------|-------------------|-------|
| Type trust | PY-WL-007 | Is runtime type-checking happening on data whose types should already be known? | Any function body |
| Boundary integrity | PY-WL-008 | Does a declared boundary actually reject anything? | Declared boundary functions |
| Boundary ordering | PY-WL-009 | Does semantic validation presume shape validation has already occurred? | Declared semantic-validation boundaries |

The chain narrows scope at each stage: PY-WL-007 applies broadly (any annotated function), PY-WL-008 applies only to declared boundaries, and PY-WL-009 applies only to the semantic-validation subset of those boundaries. This narrowing is architecturally sound -- each rule's precondition is a subset of the previous rule's scope, preventing combinatorial blowup.

**Dependency direction is correct.** PY-WL-009 depends on PY-WL-008's guarantee (a boundary with a rejection path exists) as an implicit precondition: checking whether shape validation precedes semantic validation is meaningless if the semantic boundary accepts all input. PY-WL-008 depends on the declaration infrastructure that PY-WL-007's suppression logic consults. The chain flows from broad (type trust) to narrow (ordering), which means a failure at a lower stage does not invalidate findings at a higher stage.

## 2. PY-WL-007's Declared-Boundary Suppression and PY-WL-008 Exposure

### The Mechanism

PY-WL-007 suppresses `isinstance()` findings inside functions that have a declared boundary transition (`_has_declared_boundary()`, line 107-120 of `py_wl_007.py`). The rationale is explicit in the docstring: "isinstance is the *implementation* of the declared contract."

### The Interaction

When a developer declares a function as a boundary to suppress PY-WL-007, that function becomes subject to PY-WL-008 (boundary must have a rejection path). This creates a deliberate feedback loop:

```
Developer adds isinstance() in function
  -> PY-WL-007 fires (type-checking internal data)
  -> Developer declares function as boundary (to suppress PY-WL-007)
  -> PY-WL-008 now applies (boundary must have rejection path)
  -> If isinstance() is present but no rejection path -> PY-WL-008 fires
```

### Assessment: This Dynamic Is Healthy

This is a **balancing loop**, not a reinforcing one. The suppression is not free -- it transfers enforcement from one rule to another. Specifically:

1. **The transfer is severity-escalating.** PY-WL-007 is W/R (WARNING/RELAXED) in most taint states. PY-WL-008 is E/U (ERROR/UNCONDITIONAL) in ALL taint states. Declaring a boundary to suppress a WARNING subjects the function to an UNCONDITIONAL ERROR. This is the correct incentive structure: if you claim to be a boundary, you must actually validate.

2. **The transfer prevents declaration gaming.** A developer cannot add `@validates_shape` to suppress PY-WL-007 and then write a pass-through function. PY-WL-008 catches exactly this evasion pattern.

3. **PY-WL-009 provides the third backstop.** If the declared boundary is a semantic validator, PY-WL-009 additionally requires that shape validation evidence precede the semantic checks. This prevents the subtler evasion of declaring a semantic boundary that has a rejection path (satisfying PY-WL-008) but operates on structurally unvalidated data.

**No coverage gap exists.** The suppression in PY-WL-007 checks `self._context.boundaries` (the same source PY-WL-008 consults). Any function visible to PY-WL-007's suppression is visible to PY-WL-008's enforcement.

## 3. PY-WL-008's Unconditional Severity and False-Positive Pressure

### The Problem

PY-WL-008 is E/U across all 8 taint states. Per the governance model (S9.1), UNCONDITIONAL means "no exception permitted -- project invariant -- changing an UNCONDITIONAL cell requires modifying the wardline specification itself."

This creates a structural rigidity: if PY-WL-008 produces a false positive, the only remediation is to modify the specification or the rule implementation. There is no governance escape valve.

### False-Positive Scenarios

The spec (S7.2) defines rejection paths to include "a call to a function that unconditionally raises, if the called function is resolvable via two-hop call-graph analysis." The current implementation (`_has_rejection_path` in `py_wl_008.py`) checks for:

- Direct `raise` statements
- Negative-guard `if` with rejection terminator in body
- `if` with rejection terminator in `else` branch

It does NOT implement two-hop call-graph resolution. This means:

1. **Schema library delegation** -- `jsonschema.validate(instance, schema)` raises `ValidationError` on invalid input, but the call is not recognized as a rejection path. A boundary that delegates entirely to a schema library will fire PY-WL-008 as a false positive.

2. **Thin wrapper delegation** -- `self._validate_fields(data)` where the helper raises is not recognized. This is the "two layers" case the spec explicitly calls out.

3. **Context manager patterns** -- validation via context managers (`with validator(data): ...`) where the `__exit__` handles rejection.

### Governance Pressure Analysis

Because UNCONDITIONAL findings cannot be excepted, false positives from PY-WL-008 create one of three pressures:

1. **Code distortion** -- developers add a dummy `raise` or `if False: raise` to satisfy the structural check. The spec explicitly says unreachable rejection paths should be detected, but the implementation does not currently check for this.

2. **Declaration avoidance** -- developers avoid declaring boundaries to avoid PY-WL-008 scrutiny. This is the most dangerous pressure because it reduces the annotation surface, making all other rules less effective. It is a reinforcing loop: fewer declarations -> less enforcement -> less incentive to declare.

3. **Specification amendment pressure** -- teams push to change UNCONDITIONAL to STANDARD for PY-WL-008. This would weaken the framework invariant.

### Severity of Concern

The missing two-hop call-graph analysis is a **known gap** (the spec requires it at S7.2 but the L1 implementation is not expected to have it). However, the E/U severity means this gap has disproportionate impact. At L1 analysis level, the practical false-positive rate on delegating validators is likely above the 80% precision floor for this specific pattern.

**Mitigating factor:** PY-WL-008's `_has_rejection_path` does walk the entire function body, so any function that wraps a schema library call AND has its own guard logic (which is common) will not false-positive. The pressure applies specifically to pure-delegation boundaries.

**Recommendation:** This is the most significant systemic risk in Group C. The two-hop call-graph analysis should be prioritized, or PY-WL-008 should recognize known schema-library calls (analogous to PY-WL-009's `_SCHEMA_QUALIFIED_METHODS`) as implicit rejection paths. Until then, pure-delegation validators will generate UNCONDITIONAL false positives with no governance escape.

## 4. Cross-Group Interactions

### 4.1 Group A: PY-WL-003 (Existence Checking) and PY-WL-009 (Shape Evidence)

PY-WL-003 detects existence-checking as a structural gate. PY-WL-009 looks for shape-validation evidence (which includes existence checks like `isinstance`, `hasattr`, `"key" in data`) before semantic checks.

**Interaction:** PY-WL-003 suppresses inside shape-validation boundaries (`_SUPPRESSED_BOUNDARY_TRANSITIONS` includes `shape_validation` and `combined_validation`). PY-WL-009 looks for shape evidence *within* semantic-validation boundaries. These scopes are complementary:

- Shape boundaries: PY-WL-003 suppressed (existence-checking is the purpose), PY-WL-009 does not apply (not a semantic boundary)
- Semantic boundaries: PY-WL-003 active (existence-checking is suspicious in semantic context), PY-WL-009 active (checking for prior shape evidence)

**The complementarity is clean.** A function annotated as a semantic boundary that contains `"key" in data` before a domain check will:
- Have PY-WL-003 fire on the `"key" in data` (existence check in a context where shape should be guaranteed)
- Have PY-WL-009 NOT fire because it recognizes the membership test as shape evidence

This creates a tension: PY-WL-003 says the existence check is wrong here, while PY-WL-009 counts it as evidence that shape validation is happening. This is **not a contradiction** -- it is the correct signal. PY-WL-003 is saying "you should not need this check because shape validation should have happened earlier." PY-WL-009 is saying "at least you have some shape evidence before your semantic check." Both signals are informative; they diagnose the same underlying problem (missing prior shape validation) from different angles.

**Matrix alignment:** PY-WL-003 is E/U in SHAPE_VALIDATED and UNKNOWN_SHAPE_VALIDATED (where shape IS guaranteed), but E/St in EXTERNAL_RAW and UNKNOWN_RAW (where it may be legitimate). PY-WL-009 is E/U everywhere. The governance paths are consistent -- there is no scenario where PY-WL-003 permits an exception that would mask a PY-WL-009 violation.

### 4.2 Group D: SCN-021 (Contradictory Decorators) as Dependency

SCN-021 detects contradictory decorator combinations. Several combinations directly prevent invalid inputs to Group C rules:

| SCN-021 Combination | Group C Impact |
|---------------------|---------------|
| `validates_shape` + `validates_semantic` (CONTRADICTORY) | Prevents a function from being simultaneously subject to PY-WL-008 shape-boundary checks AND PY-WL-009 semantic-ordering checks with conflicting expectations |
| `validates_external` + `validates_shape` (CONTRADICTORY) | Prevents double-counting: `validates_external` already encompasses shape validation |
| `validates_external` + `validates_semantic` (CONTRADICTORY) | Same: prevents double-counting |
| `int_data` + `validates_shape` (CONTRADICTORY) | Prevents declaring internal data needs shape validation -- the type system already guarantees it |
| `validates_semantic` + `external_boundary` (CONTRADICTORY) | Prevents declaring T3-input semantic validation on T4 data -- would create an impossible precondition for PY-WL-009 |

**SCN-021 acts as a precondition validator for Group C.** If contradictory decorators were permitted, Group C rules would face logically impossible scenarios (e.g., a function that is both a shape boundary and a semantic boundary would need to satisfy PY-WL-008 twice with different expected rejection types, and PY-WL-009 would need to check itself for prior shape evidence).

**The dependency is one-directional and healthy.** SCN-021 runs independently (no severity matrix lookup, always UNCONDITIONAL), and its findings are strictly upstream of Group C. SCN-021 does not depend on Group C outputs. This prevents circular dependencies in the rule evaluation order.

## 5. Systemic Risk: Reinforcing and Balancing Loops

### Balancing Loop 1: Declaration-Enforcement Transfer (Healthy)

```
More boundary declarations
  -> More PY-WL-008 enforcement surface
  -> More rejection-path requirements
  -> Higher code quality at boundaries
  -> More trust in boundary guarantees
  -> More rules can rely on boundary guarantees (PY-WL-003 suppression, PY-WL-009 ordering)
  -> Stabilizes
```

This is the intended steady state. The loop balances because each additional boundary declaration carries enforcement cost (PY-WL-008 + potentially PY-WL-009), preventing over-declaration.

### Reinforcing Loop 2: Declaration Avoidance (Unhealthy, Latent)

```
PY-WL-008 false positive on delegating validator
  -> Developer removes boundary declaration (to avoid UNCONDITIONAL finding)
  -> PY-WL-007 fires on isinstance() in the same function (no longer suppressed)
  -> PY-WL-007 is only W/R -> developer ignores or gets RELAXED exception
  -> Function is undeclared boundary with no enforcement
  -> Reduced annotation surface
  -> Other rules lose context
  -> More patterns escape detection
```

This loop is **latent** -- it requires PY-WL-008 false positives on pure-delegation validators to activate. The severity gap (PY-WL-008 at E/U vs PY-WL-007 at W/R) means the rational developer response to a false positive is to undeclare. The missing two-hop analysis is the trigger condition.

**Likelihood:** Medium. Delegating validators that wrap schema libraries are common in real codebases. The loop activates when adoption reaches the point where non-trivial validation patterns are annotated.

### Reinforcing Loop 3: Combined-Boundary Preference (Neutral)

```
PY-WL-009 fires on semantic boundary without prior shape evidence
  -> Developer switches to @validates_external (combined T4->T2)
  -> PY-WL-009 excludes combined boundaries by design
  -> PY-WL-008 still applies (combined is in _BOUNDARY_TRANSITIONS)
  -> Net effect: fewer separate boundaries, more monolithic validators
```

This loop drives toward monolithic combined validators rather than separated shape+semantic stages. This is **architecturally neutral** -- the spec explicitly supports combined boundaries, and PY-WL-008 still enforces rejection-path presence. However, it works against the architectural preference for separation of concerns described in the tier model. The pressure is mild because `validates_external` is only appropriate for T4->T2 transitions, not for all validation scenarios.

## 6. Summary of Findings

| Finding | Severity | Evidence |
|---------|----------|----------|
| PY-WL-007 -> PY-WL-008 suppression transfer is severity-escalating and well-designed | Positive | Suppression at W/R transfers to enforcement at E/U; no coverage gap |
| PY-WL-008 E/U without two-hop call-graph creates declaration-avoidance pressure | CONCERN | Missing `_has_rejection_path` recognition of delegation calls; E/U means no governance escape for false positives |
| PY-WL-003 and PY-WL-009 have complementary scopes with coherent signals | Positive | Suppression boundaries are disjoint; both rules diagnose the same underlying problem from different angles |
| SCN-021 acts as a clean upstream precondition validator | Positive | One-directional dependency; prevents logically impossible decorator combinations that would confuse Group C |
| Combined-boundary preference loop is architecturally neutral | Neutral | Spec supports combined boundaries; PY-WL-008 still enforces |
| Declaration-avoidance reinforcing loop is latent | CONCERN | Triggered by PY-WL-008 false positives on pure-delegation validators; severity gap (E/U vs W/R) makes undeclaration the rational response |

---

## Verdict: CONCERN

The structural verification chain is well-designed in its architecture: the scope narrowing is correct, the suppression transfer is severity-escalating, cross-group interactions are coherent, and SCN-021 provides a clean upstream dependency. However, PY-WL-008's E/U severity across all taint states, combined with the missing two-hop call-graph analysis, creates a latent reinforcing loop where false positives on pure-delegation validators incentivize declaration avoidance -- the single most damaging systemic outcome for the framework, because it reduces the annotation surface that all other rules depend on. The concern is not with the specification (which correctly requires E/U for boundary integrity) but with the implementation gap between the spec's two-hop analysis requirement and the L1 implementation's body-only rejection-path detection. Until that gap is closed, the UNCONDITIONAL severity acts as a governance pressure amplifier on a known detection limitation.
