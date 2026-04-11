# Systems Thinker Audit: SCN-021 (Contradictory Decorator Combinations)

**Auditor role:** Systems Thinker
**Rule:** SCN-021 — Contradictory and suspicious decorator-combination detection
**Date:** 2026-03-25

---

## 1. SCN-021 as a Foundation Rule: Cascade Analysis

SCN-021 is a structural integrity gate. Every other rule that reasons about decorator semantics implicitly assumes decorator declarations are non-contradictory. If SCN-021 has gaps, the consequences propagate silently.

**PY-WL-008 (boundary rejection path) cascade.** PY-WL-008 checks that boundary declarations (`validates_shape`, `validates_semantic`, `validates_external`, `restoration_boundary`) contain rejection paths. If a function carries `@validates_shape` + `@validates_semantic` (contradictory per spec entry #9), PY-WL-008 would evaluate the body against *both* boundary contracts simultaneously. The function would need to satisfy both shape and semantic rejection requirements independently, but the spec says this combination is semantically meaningless ("Use `@validates_external` for combined T4->T2 validation"). PY-WL-008 would fire on a valid `@validates_external` body that happens to carry the wrong decorator pair, producing findings with no actionable fix.

**Severity matrix cascade.** The severity matrix (Part I S7.3) resolves rule severity based on tier context and decorator declarations. Contradictory tier declarations (e.g., `@external_boundary` + `@tier1_read`) create ambiguous tier context. The severity lookup would resolve against whichever decorator the engine encounters first, producing non-deterministic severity for downstream rules. This is not observable in the current engine (which does not yet compose tier contexts from multiple decorators), but becomes a latent defect once tier-context composition is implemented.

**Assessment:** SCN-021 is correctly positioned as an early-pass, UNCONDITIONAL rule. Its function as a foundation gate is architecturally sound. The cascade risk is real but currently bounded by implementation sequencing.

## 2. Registry Synchronisation

**Current state.** The registry (`REGISTRY` in `src/wardline/core/registry.py`) contains 35 decorators across Groups 1-15. The decorator `__init__.py` exports 36 names (including `schema_default`, which is not in the registry). SCN-021's combination table references 29 entries involving 17 unique decorator names.

**Divergence finding: forward references in SCN-021.** Two decorators in SCN-021's combination table are not present in the registry:

- `restoration_boundary` (Group 17) -- referenced in spec entries #16 and #17
- `data_flow` (Group 16) -- referenced in spec entry #25

These are Groups 16/17, which are defined in the spec (Part II-A, S A.4.2) but not yet implemented. SCN-021 includes their contradictions proactively. This means SCN-021 contains dead rules: the `_decorator_name()` resolver will never match `restoration_boundary` or `data_flow` because no decorator implementation exists to produce them. The dead rules are harmless (they simply never fire), but they represent a spec-to-implementation gap that should be tracked.

**Divergence finding: `schema_default` decorator.** The decorator `__init__.py` exports `schema_default`, which has no corresponding registry entry. If `schema_default` participates in any contradictory combination (it currently does not appear in SCN-021's table), the gap would be invisible.

**Divergence finding: no registry-driven validation.** SCN-021's combination table is a manually maintained tuple of `_CombinationSpec` entries. The registry is a separate manually maintained dict. There is no automated check that the two are consistent -- no test verifies that every decorator name in `_COMBINATIONS` exists in the registry, and no test verifies that the combination table was reviewed when the registry changes.

**Assessment:** The registry and SCN-021 are currently in sync for all implemented decorators. The forward references are intentional but create a maintenance coupling that is entirely manual.

## 3. Adding New Combinations: Process Analysis

**Current process.** When a new decorator is added:
1. Add `RegistryEntry` to `REGISTRY` in `registry.py`
2. Implement the decorator function in the appropriate module
3. Export from `decorators/__init__.py`
4. Manually review SCN-021's `_COMBINATIONS` for new contradictions
5. Update the spec table (Part II-A, S A.4.3) with new entries

Steps 4 and 5 are entirely manual and have no enforcement mechanism. The combination table is O(n^2) in the number of decorators -- with 35 decorators, there are 595 possible pairs. Currently 29 are flagged. There is no tooling to prompt a developer to consider new pairs when adding decorator #36.

**Systemic risk: Groups 16/17 integration.** When `restoration_boundary` and `data_flow` are implemented, the existing SCN-021 entries (#16, #17, #25) will activate automatically -- this is a well-designed forward reference. However, any *new* contradictions involving these decorators (e.g., `restoration_boundary` + `compensatable`, which would be semantically dubious) would need manual identification.

**Missing feedback loop.** There is no test that enumerates all registry entries and asserts that the combination table was reviewed for each pair. A `test_registry_sync.py` exists but it validates decorator-to-registry alignment, not combination-table completeness. A lightweight check could assert that every canonical name in `_COMBINATIONS` is either in `REGISTRY` or in a documented "pending" set, and that the combination table's review date is tracked.

**Assessment:** The manual process works at current scale (35 decorators) but has no structural guarantee of completeness. The O(n^2) nature of the combination space means omissions become more likely as the decorator set grows.

## 4. Governance Dynamics: UNCONDITIONAL Exceptionability

**All 29 SCN-021 findings are UNCONDITIONAL** (line 169 of `scn_021.py`). Per S9.1, this means "No exception permitted. Project invariant. Changing an UNCONDITIONAL cell requires modifying the wardline specification itself."

**Pressure analysis: appropriate or excessive?**

For the 26 CONTRADICTORY entries: UNCONDITIONAL is correct. These are logical contradictions -- `@fail_open` + `@fail_closed` is structurally meaningless. There is no legitimate edge case where a function is simultaneously fail-open and fail-closed. The finding is always a bug. UNCONDITIONAL creates appropriate pressure to fix the declaration.

For the 3 SUSPICIOUS entries (#27-#29): UNCONDITIONAL is debatable. These are not contradictions but tensions:
- `@fail_open` + `@deterministic` -- a function could legitimately be fail-open with deterministic fallback defaults
- `@compensatable` + `@deterministic` -- a function could be deterministic in its primary path with a well-defined compensation path
- `@time_dependent` + `@idempotent` -- a function could be idempotent within a time window

However, these are WARNING-severity findings, not ERROR. The combination of WARNING severity with UNCONDITIONAL exceptionability means: "This is always flagged, always visible, never suppressible, but it's a warning not an error." This creates an interesting governance dynamic -- the finding cannot be silenced, but it does not block CI. This is a reasonable "forced acknowledgment" posture for suspicious-but-not-impossible combinations. The risk is governance fatigue: if a codebase legitimately has many `@time_dependent` + `@idempotent` functions, the persistent warnings become noise.

**Assessment:** UNCONDITIONAL for CONTRADICTORY entries is correct. UNCONDITIONAL for SUSPICIOUS entries is defensible but creates a governance fatigue risk if legitimate uses accumulate. The spec does not provide a mechanism for a project to declare "we have reviewed this suspicious combination and accept it" without modifying the spec itself.

## 5. Interaction with Annotation Fingerprint Baseline (S9.2)

**Are contradictory combinations tracked as annotation changes?** The fingerprint baseline (S9.2) records "which of the 17 annotation groups are declared on [a function]" and "a cryptographic hash of the annotation declarations." If a developer adds a contradictory pair (e.g., `@fail_open` + `@fail_closed`), the fingerprint baseline would record both annotations. The baseline diff would show two annotations added. But the baseline does not flag the combination as contradictory -- it records what is declared, not whether the declaration is valid.

**Gap: no cross-reference between SCN-021 and baseline.** SCN-021 fires at scan time and produces SARIF findings. The fingerprint baseline tracks annotation surface changes. These are parallel systems with no cross-reference. A contradictory combination that persists across baseline updates (because it was introduced and never fixed) would appear as a stable entry in the baseline -- "these decorators have been here since date X." The baseline's change-detection mechanism only fires on changes, not on persistent violations. A contradictory combination introduced before baseline tracking was enabled would be invisible to the baseline entirely.

**Compensating control.** SCN-021 fires on every scan, not just on changes. This means contradictory combinations are detected regardless of baseline state. The baseline gap is therefore a governance-visibility gap, not a detection gap: the combination is always caught, but governance reviewers looking at baseline diffs would not see it flagged distinctly from normal annotation additions.

**Assessment:** The detection mechanism is sound (SCN-021 fires unconditionally on every scan). The governance integration is incomplete -- the fingerprint baseline does not distinguish contradictory declarations from valid ones, but this is compensated by SCN-021's persistent detection.

---

## Summary of Findings

| # | Finding | Severity | Category |
|---|---------|----------|----------|
| 1 | `restoration_boundary` and `data_flow` referenced in SCN-021 but not in registry or decorator exports (Groups 16/17 not yet implemented) | Low | Forward reference -- harmless dead rules |
| 2 | `schema_default` exported from decorators but absent from registry | Low | Registry completeness gap |
| 3 | No automated check that `_COMBINATIONS` names align with `REGISTRY` | Medium | Maintenance coupling |
| 4 | No structural mechanism to prompt combination review when new decorators are added | Medium | Process gap |
| 5 | SUSPICIOUS entries (#27-#29) are UNCONDITIONAL with no project-level acknowledgment mechanism | Low | Governance fatigue risk |
| 6 | Fingerprint baseline does not distinguish contradictory annotation pairs from valid ones | Low | Governance visibility gap (compensated by persistent SCN-021 detection) |

---

## Verdict: CONCERN

**Evidence:** SCN-021 is architecturally sound as a foundation rule. Its combination table matches the spec (29 entries, matching Part II-A S A.4.3 table exactly). All implemented decorators are correctly covered. The UNCONDITIONAL exceptionability is appropriate for contradictions and defensible for suspicious combinations.

The concerns are systemic, not correctness defects:

1. **Manual coupling between registry and combination table** (finding #3-#4). There is no automated feedback loop ensuring that registry growth triggers combination table review. At 35 decorators this is manageable; at 50+ it becomes a real gap. The O(n^2) pair space means the probability of missed combinations grows quadratically.

2. **Forward references create invisible dead rules** (finding #1). Three combination entries reference unimplemented decorators. These are intentional and spec-conformant, but there is no marker distinguishing "intentionally forward-referencing" from "accidentally referencing a typo." A registry-aware validation test would catch the latter.

Neither concern represents a current correctness failure. Both represent structural fragility that will manifest as the decorator vocabulary grows with Groups 16/17 implementation.
