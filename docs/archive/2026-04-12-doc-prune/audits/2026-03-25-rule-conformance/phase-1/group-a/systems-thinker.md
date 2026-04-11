# Group A — Systems Thinker Assessment

**Rules:** PY-WL-001 (dict key access with fallback default), PY-WL-002 (attribute access with fallback default), PY-WL-003 (existence-checking as structural gate)

**Date:** 2026-03-25

---

## Inter-Rule Interaction

### Detection Surface Overlap

The three rules have **cleanly partitioned detection surfaces** with no syntactic overlap:

- **PY-WL-001** fires on `d.get(key, default)`, `d.setdefault(key, default)`, `defaultdict(factory)`, and `schema_default(d.get(...))`.
- **PY-WL-002** fires on `getattr(obj, name, default)` (3-arg form) and `obj.attr or default` (boolean-or fallback).
- **PY-WL-003** fires on `key in d`, `key not in d`, `hasattr(obj, name)`, `match/case` with `MatchMapping`, and `match/case` with `MatchClass`.

No single AST node can match more than one rule. This is structurally sound — the rules partition the "fallback/existence" problem space along the dict-vs-attribute axis (PY-WL-001 vs PY-WL-002) and the fabrication-vs-gating axis (PY-WL-001/002 vs PY-WL-003).

### Evasion Dynamics

The evasion dynamics are **healthy with one gap**:

1. **Evading PY-WL-001 via existence check triggers PY-WL-003.** An agent that replaces `d.get("key", default)` with `if "key" in d: ... else: fabricate_default()` evades PY-WL-001 but triggers PY-WL-003 on the `in` check. This is a well-designed complementary pair — the evasion route is covered.

2. **Evading PY-WL-002 via hasattr triggers PY-WL-003.** An agent that replaces `getattr(obj, "attr", default)` with `if hasattr(obj, "attr"): ... else: default` evades PY-WL-002 but triggers PY-WL-003. Same complementary dynamic.

3. **Evading PY-WL-003 via try/except triggers PY-WL-004.** An agent that replaces `if "key" in d:` with `try: val = d["key"] except KeyError: val = default` evades PY-WL-003 but enters the exception-handling rule group (PY-WL-004/005). This is a healthy cross-group handoff.

4. **Gap: PY-WL-002 does not cover `getattr(obj, name)` (2-arg) followed by conditional assignment.** The 2-arg form raises `AttributeError`, so it is not a silent fabrication — this is correctly excluded. However, `getattr(obj, name)` inside a try/except block that catches `AttributeError` and substitutes a default is a semantic equivalent that requires PY-WL-004 to catch the broad handler. If the except clause is narrowly typed (`except AttributeError`), PY-WL-004 may not fire (it targets broad catches). This is a potential evasion seam between PY-WL-002 and PY-WL-004 — narrow except + default substitution may escape all rules. **This is noted as a gap but is outside Group A's direct scope.**

5. **PY-WL-001's `schema_default()` suppression and PY-WL-003's boundary suppression share the same boundary set** (`shape_validation`, `external_validation`, `combined_validation`, `validates_shape`, `validates_external`). This is coherent: both suppressions activate within declared validation boundaries where the pattern is expected. There is no unexpected interaction — `schema_default()` suppresses the *fabrication* finding inside a boundary, while the boundary suppresses the *existence check* finding. These target different AST patterns, so a function using `schema_default(d.get("key", default))` inside a validation boundary gets PY-WL-001 suppressed (governed default) and any `if "key" in d` checks in the same function also suppressed (PY-WL-003 boundary suppression). This is the correct behavior — validation boundary code legitimately does both.

### Asymmetry Between PY-WL-001 and PY-WL-002

PY-WL-001 has a governed-default mechanism (`schema_default()` + overlay declaration) that PY-WL-002 lacks. This asymmetry is **intentional and correct**: dict key access on external data schemas has a legitimate optional-field use case (spec 7.2.1), while attribute access on objects does not have the same structural justification — objects have defined interfaces, not optional members by contract. If this assumption changes (e.g., protocol-style optional attributes become common), PY-WL-002 would need an equivalent governed path.

---

## Feedback Dynamics

### Governance Load Distribution

**PY-WL-001 matrix row:** 1 UNCONDITIONAL (AUDIT_TRAIL) + 7 STANDARD = 12.5% unconditional load. This means 87.5% of findings are governable. For most codebases (predominantly PIPELINE, SHAPE_VALIDATED, EXTERNAL_RAW contexts), PY-WL-001 findings will be STANDARD — requiring exception management if the pattern is justified.

**PY-WL-002 matrix row:** Identical to PY-WL-001: 1 UNCONDITIONAL + 7 STANDARD. Same governance load profile.

**PY-WL-003 matrix row:** 5 UNCONDITIONAL (AUDIT_TRAIL, PIPELINE, SHAPE_VALIDATED, UNKNOWN_SHAPE_VALIDATED, UNKNOWN_SEM_VALIDATED) + 3 STANDARD (EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW) = 62.5% unconditional load. This is significantly heavier than PY-WL-001/002 — existence-checking is ungovernable in most contexts.

**Aggregate Group A load:** Across the three rules and eight taint states (24 cells), 7 are UNCONDITIONAL (29%), 17 are STANDARD (71%), 0 are RELAXED or TRANSPARENT. There is no governance "free pass" anywhere in Group A — every finding requires either acceptance as an invariant violation or a formal exception. This is intentionally heavy for a rule group targeting value fabrication, which is the spec's flagship risk.

### False-Positive Pressure and Governance Fatigue

**PY-WL-003 carries the highest false-positive risk in Group A.** The `in` operator is pervasive in Python — it appears in iteration (`for x in collection`), set membership tests, string containment checks, and many contexts unrelated to structural gating. While the rule targets `ast.Compare` nodes (not `for` loops), the `in` operator in comparisons still has many legitimate non-structural-gate uses (e.g., `if user_id in allowed_ids`). At 62.5% UNCONDITIONAL, false positives on PY-WL-003 in PIPELINE or SHAPE_VALIDATED contexts cannot be excepted — they generate noise that is irresolvable through the governance model.

**Mitigation:** PY-WL-003's boundary suppression mechanism (suppressing all findings inside declared validation boundaries) reduces volume where existence-checking is most common. However, code outside boundaries that uses `in` for legitimate non-structural-gate purposes (set membership, string containment) will generate UNCONDITIONAL findings in five taint states. This is the primary governance fatigue vector for Group A.

**PY-WL-001's `schema_default()` mechanism is a well-designed pressure valve.** Without it, every optional-field access on external data would generate STANDARD exceptions — exactly the governance fatigue exploitation vector described in spec 9.3.2. The governed-default path converts legitimate optional-field handling from exception noise to SUPPRESS/TRANSPARENT, preserving governance capacity for genuine violations. The three conditions (declared field + matching default + within boundary) prevent abuse.

**PY-WL-002's `obj.attr or default` pattern may generate false positives** on boolean-or expressions where the left side is an attribute access but the intent is not fallback-default behavior (e.g., `config.verbose or os.environ.get("VERBOSE")`). The severity is STANDARD in most contexts, so these are governable, but they add to the exception volume.

### Perverse Incentive Analysis: Boundary Declaration as Suppression Mechanism

PY-WL-003 suppresses all findings inside declared validation boundaries. **Could an agent declare everything as a boundary to suppress findings?**

The boundary declaration is governed by:
1. **PY-WL-008** (WL-008): Structural verification that semantic validation follows shape validation. A bogus boundary that doesn't actually validate would fire PY-WL-008 (UNCONDITIONAL in all 8 states).
2. **PY-WL-007** (WL-007): Boundary must contain a rejection path. A function declared as a boundary with no conditional/raise/early-return fires PY-WL-007 (UNCONDITIONAL in all 8 states).
3. **Manifest governance (spec 9.2):** Boundary declarations are policy artefacts requiring protected-file review.

These three controls create a **balancing loop** that prevents boundary-declaration abuse: declaring a bogus boundary to suppress PY-WL-003 triggers PY-WL-007/008 with UNCONDITIONAL severity. The cost of the evasion (two UNCONDITIONAL violations) exceeds the benefit (suppressing STANDARD or UNCONDITIONAL PY-WL-003 findings). This is a healthy systemic design.

However, a more subtle perverse incentive exists: an agent could write a **minimal but legitimate** validation boundary (one that has a real rejection path and passes WL-007/008) purely to obtain PY-WL-003 suppression, even if the function's primary purpose is not validation. This is harder to detect automatically. The balancing control here is code review and the manifest governance layer — boundary declarations are visible in the fingerprint baseline and require reviewer approval. **This is a residual risk, not a systemic failure.**

---

## Cross-Group Interaction

### Interaction with Exception Handling Rules (PY-WL-004/005/006)

The evasion dynamics create a well-structured **enforcement cascade**:

- **Group A evasion into Group B:** Replacing fallback defaults with try/except patterns enters PY-WL-004 (broad catch) or PY-WL-005 (silent catch) territory. The severity gradient is maintained: PY-WL-004 in EXTERNAL_RAW is W/R (weaker than PY-WL-001's E/St), so there is a severity **downgrade** available through this evasion path in EXTERNAL_RAW context. In PIPELINE and AUDIT_TRAIL contexts, PY-WL-004 is E/St and E/U respectively, so no severity benefit from evasion.

- **Severity gap in EXTERNAL_RAW:** An agent can convert a PY-WL-001 finding (E/St in EXTERNAL_RAW) into a PY-WL-004 finding (W/R in EXTERNAL_RAW) by wrapping the access in a try/except with a default in the except clause. This is a severity downgrade from ERROR to WARNING and from STANDARD to RELAXED governance. This is arguably correct from the spec's perspective — a try/except with a default on external data is less dangerous than a silent `.get()` default because the exception makes the failure mode explicit — but it is an exploitable gradient. The spec's rationale in 7.4(a) vs 7.4(c) supports this distinction, so this is intentional, not a gap.

### Interaction with Structural Verification Rules (PY-WL-007/008/009)

- **PY-WL-007/008 act as boundary-integrity guards** that prevent the PY-WL-003 suppression mechanism from being exploited (as analyzed above).
- **PY-WL-009** (semantic validation without shape validation) creates a prerequisite chain: you cannot get to SHAPE_VALIDATED context (where PY-WL-003 is UNCONDITIONAL and PY-WL-001 is STANDARD) without passing through a shape validation boundary, and that boundary must have a rejection path (PY-WL-007) and must precede semantic validation (PY-WL-008/009). This creates a **coherent pipeline** where the severity of Group A rules reflects real structural guarantees, not just declarations.

### Severity Gradient Coherence

Reading across the taint states for Group A:

| Context | PY-WL-001 | PY-WL-002 | PY-WL-003 |
|---------|-----------|-----------|-----------|
| AUDIT_TRAIL | E/U | E/U | E/U |
| PIPELINE | E/St | E/St | E/U |
| SHAPE_VALIDATED | E/St | E/St | E/U |
| EXTERNAL_RAW | E/St | E/St | E/St |
| UNKNOWN_RAW | E/St | E/St | E/St |

PY-WL-003 is **harder** than PY-WL-001/002 in PIPELINE and SHAPE_VALIDATED (UNCONDITIONAL vs STANDARD). This creates coherent pressure: in contexts with structural guarantees, existence-checking is a harder violation than fallback defaults. Fallback defaults are wrong but potentially governable (maybe there is a legitimate domain reason); existence-checking where structure is guaranteed is categorically redundant or masking a defect. The gradient is correct.

In EXTERNAL_RAW, all three are E/St — equal governance weight. This makes sense: on raw external data, both fabrication and gating patterns carry the same risk class.

There are no gaps where an agent can operate with minimal constraint. Every taint state produces ERROR severity for all three rules. The only variation is in governability (UNCONDITIONAL vs STANDARD), which correctly reflects how much institutional override is appropriate per context.

---

## Systemic Risk

### Reinforcing Loops

1. **Exception accumulation loop (spec 9.4).** PY-WL-001 and PY-WL-002 generate STANDARD exceptions across 7 of 8 taint states. In a large codebase with many dict/attribute accesses, exception volume could grow, leading to governance fatigue, leading to less scrutiny per exception, leading to more exceptions being granted, leading to the exception register becoming noise. **The spec addresses this** with exception recurrence tracking, age-based expiry, and the expedited governance ratio. These are adequate balancing mechanisms if implemented.

2. **Annotation avoidance loop.** Since unannotated code produces no findings (spec 9.4: "finding rate scales with annotation coverage"), there is a systemic incentive to leave code unannotated. Group A rules only fire on annotated functions. An agent could avoid all Group A findings by not annotating functions. **The spec addresses this** with coverage reporting in the fingerprint baseline (spec 9.2) and the annotation-removal detection mechanism. However, the incentive is real and coverage gaps in non-Tier-1 modules may persist. This is a known residual risk (spec 12, residual risk 4).

### Balancing Loops

1. **Boundary-integrity loop** (analyzed in Feedback Dynamics). PY-WL-007/008 prevent boundary declaration abuse for PY-WL-003 suppression. This is the strongest balancing loop in Group A.

2. **Governed-default loop.** PY-WL-001's `schema_default()` mechanism converts legitimate optional-field handling from exception noise to governed suppressions, preserving governance capacity. The three-condition gate (declared field + matching default + within boundary) prevents the governed path from becoming a blanket suppression. This is a well-calibrated pressure valve.

3. **Evasion-cascade loop.** Evading one Group A rule pushes the agent into adjacent rule groups (Group B for exception handling, PY-WL-003 for existence checking). There is no clean evasion path that exits all rule coverage simultaneously — every transformation of a flagged pattern either triggers another rule or requires a genuine architectural change (proper validation boundaries, explicit error handling). This is the hallmark of a well-designed enforcement surface.

### Steady-State Behavior

Under sustained enforcement, a codebase will converge toward:

1. **Validation boundaries as the primary structural pattern.** Code that processes external or unknown data will be routed through declared validation boundaries where existence-checking and optional-field handling are suppressed. Business logic outside boundaries will avoid fallback defaults and existence checks, relying on the structural guarantees provided by upstream validation. This is the intended architecture.

2. **Exception register containing domain-specific overrides.** Legitimate domain cases (optional fields with no `schema_default()` equivalent, necessary existence checks in non-boundary code) will populate the exception register at STANDARD governance. The volume of these exceptions is the primary metric of how well the `schema_default()` and boundary-suppression mechanisms cover real-world patterns.

3. **PY-WL-003 as the highest-volume rule.** Due to the pervasiveness of `in` in Python and the high UNCONDITIONAL rate, PY-WL-003 will likely generate the most findings in annotation-dense codebases. The boundary suppression mechanism is the critical volume control — if boundaries are not declared comprehensively, PY-WL-003 findings dominate the finding output.

---

## Verdict: PASS

**Group A's three rules form a coherent, well-partitioned enforcement surface with healthy evasion dynamics, adequate balancing loops, and no systemic design flaws.**

Key strengths:
- Clean detection surface partitioning with no overlap.
- Complementary evasion coverage (PY-WL-001/002 evasion triggers PY-WL-003; PY-WL-003 evasion triggers PY-WL-004/005).
- The `schema_default()` governed-default mechanism on PY-WL-001 is a well-designed governance load relief valve.
- PY-WL-007/008 act as boundary-integrity guards preventing PY-WL-003 suppression abuse.
- Severity gradient across taint states is coherent and creates consistent enforcement pressure.

Residual concerns (not sufficient for CONCERN or FAIL):
- **PY-WL-003 false-positive volume on `in` operator.** The `in` operator has many non-structural-gate uses in Python. At 62.5% UNCONDITIONAL, false positives in high-guarantee contexts are irresolvable through governance. This is a precision concern (for the precision specialist), but systemically it creates governance fatigue pressure that the boundary-suppression mechanism must absorb. If boundary declarations are incomplete, PY-WL-003 becomes the dominant noise source.
- **Narrow-except evasion seam.** The path from PY-WL-002 through `try: getattr(obj, name) except AttributeError: default` may escape both PY-WL-002 and PY-WL-004 (which targets broad catches). This is a detection gap, not a systemic design flaw — it can be addressed by extending PY-WL-004 or adding an equivalent-pattern entry to PY-WL-002.
- **EXTERNAL_RAW severity downgrade via evasion.** Converting PY-WL-001 (E/St) patterns to try/except equivalents yields PY-WL-004 (W/R) in EXTERNAL_RAW. The severity downgrade is intentional per spec rationale but represents a path of least resistance for agents optimizing against the scanner.
