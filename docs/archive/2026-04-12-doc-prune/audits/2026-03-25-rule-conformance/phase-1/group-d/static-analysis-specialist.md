# SCN-021 Precision and Recall Audit

**Rule:** SCN-021 -- Contradictory decorator combination detection
**Spec reference:** wardline-02-A-python-binding.md, Section A.4.3
**Implementation:** `src/wardline/scanner/rules/scn_021.py`
**Date:** 2026-03-25
**Auditor role:** Static Analysis Specialist

---

## 1. Completeness: Combination Table Coverage

### 1.1 Spec-to-implementation match

The spec (Section A.4.3) defines exactly 29 combinations: 26 contradictory (ERROR) and 3 suspicious (WARNING). The `_COMBINATIONS` tuple in `scn_021.py` contains exactly 29 `_CombinationSpec` entries. Each spec entry was matched 1:1 against the implementation entries by (left, right, severity, rationale). All 29 match.

### 1.2 Phantom decorators

Two decorator names appear in `_COMBINATIONS` but are **not in the canonical registry** (`src/wardline/core/registry.py`):

| Decorator | Used in combination(s) | Registry status |
|---|---|---|
| `restoration_boundary` | #16, #17 | **Not registered** -- Group 17 per spec A.4.2 but absent from `REGISTRY` |
| `data_flow` | #25 | **Not registered** -- Group 16 per spec A.4.2 but absent from `REGISTRY` |

**Impact on detection:** When the annotations_map path is used (the primary path), decorator resolution depends on the annotations_map populated by the scanner engine. If `restoration_boundary` and `data_flow` are not discovered and mapped to their canonical names, combinations #16, #17, and #25 cannot fire via annotations_map. They can only fire via the AST fallback path, which resolves bare decorator names from syntax. This means:

- `@restoration_boundary` (bare name) -- detectable via AST fallback
- `@wardline.decorators.restoration_boundary` (qualified) -- detectable via AST fallback (`_decorator_name` extracts `.attr`)
- Aliased imports (`from wardline... import restoration_boundary as rb`) -- **NOT detectable** because the AST fallback sees the alias name, and annotations_map has no entry for unregistered decorators

**Assessment:** LOW CONCERN. The decorators exist in the spec but are not yet implemented in the library (no decorator function, no registry entry). The combinations are forward-compatible placeholders. Once these decorators are added to the registry, the annotations_map path will resolve them correctly. Current risk is limited to aliased imports of unimplemented decorators, which is an implausible scenario.

### 1.3 Potentially missing combinations

The user-suggested combinations were evaluated against the spec's semantic model:

| Candidate | Assessment |
|---|---|
| `@fail_open` + `@must_propagate` | **Genuinely missing.** `@fail_open` degrades silently; `@must_propagate` requires exceptions to be forwarded. These are semantically contradictory for the same reason as `@exception_boundary` + `@must_propagate` (#12). `@fail_open` swallows exceptions; `@must_propagate` demands they propagate. |
| `@handles_secrets` + `@fail_open` | BORDERLINE. Fail-open on a secrets-handling function could leak partial secret state. However, the spec does not include this -- secrets handling is about data classification, not failure mode. The spec's philosophy is that `@fail_open` contradictions are scoped to authority/audit paths, not data sensitivity. Not a gap per the spec's intent. |
| `@test_only` + `@audit_critical` | BORDERLINE. A test-only function marked audit-critical is logically suspicious, but `@test_only` is a lifecycle annotation (Group 15) and `@audit_critical` is a runtime property (Group 2). The spec does not cross these concerns. Could be a useful future addition as SUSPICIOUS but is not a spec gap. |
| `@handles_pii` + `@external_boundary` | NOT contradictory. External boundary functions frequently handle PII (e.g., form submissions). These are complementary, not contradictory. |

**Finding: `@fail_open` + `@must_propagate` is a genuine semantic contradiction absent from the 29-entry table.** The rationale parallels entry #12 (`@exception_boundary` + `@must_propagate`). However, since this is absent from the normative spec table, the implementation correctly omits it -- adding it would be a spec change, not a bug fix.

---

## 2. False Positives

### 2.1 Alias pairs producing double findings

The spec explicitly documents two alias pairs:

- **#5 / #19:** `@fail_open` + `@audit_critical` and `@audit_critical` + `@fail_open`
- **#12 / #23:** `@exception_boundary` + `@must_propagate` and `@preserve_cause` + `@exception_boundary`

**Critical distinction:** Entry #23 is NOT a true alias of #12. Entry #12 matches `{exception_boundary, must_propagate}`. Entry #23 matches `{preserve_cause, exception_boundary}`. These are different pairs that share one element (`exception_boundary`). The spec's "(Alias of #12)" note means the *rationale* is related, not that the pair is identical.

Entry #5 and #19 ARE the same pair with reversed order: `{fail_open, audit_critical}`. Since the detection uses set membership (`spec.left in names and spec.right in names`), **both entries will fire if a function has both `@fail_open` and `@audit_critical`**, producing **2 findings for the same semantic contradiction**.

**Evidence:** Given a function with `@fail_open` and `@audit_critical`:
- Entry #5: `left="fail_open"`, `right="audit_critical"` -- both in names -- FIRES
- Entry #19: `left="audit_critical"`, `right="fail_open"` -- both in names -- FIRES
- Result: 2 findings emitted for 1 contradiction

**This is a confirmed finding-count inflation bug for the #5/#19 alias pair.** Entry #19 should be removed from the implementation, or deduplication logic should be added.

### 2.2 Entry #24 vs #3 overlap

Entry #3: `@fail_open` + `@audit_writer` (contradictory)
Entry #24: `@compensatable` + `@audit_writer` (contradictory)

These are distinct pairs (different left operands). No overlap issue.

### 2.3 Legitimate decorator stacking

No false positive risk identified for the remaining 27 non-alias entries. Each pair represents a genuine semantic contradiction or suspicious combination per the spec's rationale.

---

## 3. Detection Mechanism Accuracy

### 3.1 Annotations map path (primary)

The primary path at lines 140-144 resolves canonical names from `self._context.annotations_map`. This correctly handles:
- Aliased imports (`from wardline.decorators import fail_open as fo`)
- Qualified access (`wardline.decorators.fail_open`)
- Parameterized decorators (`@compensatable(rollback=fn)`)

The lookup key is `self._current_qualname`, which is set by `RuleBase._dispatch()` before `visit_function` is called. This is correct.

**Concern:** If `annotations_map` contains entries for the qualname, the AST fallback is skipped entirely (line 143: `if names: return frozenset(names)`). This means the primary path is all-or-nothing per function. If a function has some wardline decorators in the map and some non-wardline decorators, only the mapped ones are checked. This is correct behavior -- non-wardline decorators should not be checked.

### 3.2 AST fallback path

The `_decorator_name` function (lines 102-109) handles three forms:
- `@name` (ast.Name) -- returns `target.id`
- `@name(args)` (ast.Call wrapping ast.Name) -- returns `target.id`
- `@pkg.name` / `@pkg.name(args)` (ast.Attribute) -- returns `target.attr`

**Missing form:** `@pkg.sub.name` (chained attribute access) is handled correctly because `ast.Attribute.attr` returns the terminal attribute regardless of chain depth.

**Missing form:** `@pkg.sub.name(args)` -- handled correctly: `ast.Call` unwraps to `ast.Attribute`, which returns `.attr`.

**Edge case:** A decorator that is a bare subscript (`@decorators["fail_open"]`) returns `None` and is silently skipped. This is correct -- such exotic forms should not be matched.

### 3.3 Correctness of set membership test

Line 132: `if spec.left in names and spec.right in names`

This uses `frozenset` membership, which is O(1) and commutative with respect to decorator declaration order. A function decorated with `@B` then `@A` will match a spec with `left="A", right="B"` just as readily as one with `left="B", right="A"`.

---

## 4. Ordering Sensitivity

### 4.1 Decorator declaration order

The `frozenset` construction (line 144 and line 145-149) discards ordering. Detection is **fully commutative** -- decorator order on the function does not affect detection.

### 4.2 Combination table order

The `_COMBINATIONS` tuple is iterated sequentially. For the #5/#19 duplicate pair, both entries fire. For all other entries, table ordering does not affect correctness because each entry matches a unique pair (with the one exception noted).

---

## 5. Finding Count Consistency

### 5.1 Confirmed inflation

As analyzed in Section 2.1, the pair `{fail_open, audit_critical}` produces **2 findings** due to entries #5 and #19 both matching. This is the only confirmed inflation case.

### 5.2 Triple-decorator scenarios

A function with three decorators that form multiple contradictory pairs will correctly emit one finding per matching pair. For example, `@fail_open` + `@fail_closed` + `@audit_critical` will fire:
- #1 (fail_open + fail_closed)
- #5 (fail_open + audit_critical)
- #19 (audit_critical + fail_open) -- **duplicate of #5**

This produces 3 findings where 2 are expected. The inflation is exclusively caused by the #5/#19 duplicate.

### 5.3 Test coverage gap

The test suite (`tests/unit/scanner/test_scn_021.py`) has 5 tests covering:
- Contradictory pair detection (fail_open + fail_closed)
- A different contradictory pair (exception_boundary + must_propagate)
- The non-alias pair #23 (preserve_cause + exception_boundary) -- correctly produces 1 finding
- Suspicious combination (fail_open + deterministic)
- Alias import resolution via annotations_map

**Missing test:** No test covers the `@fail_open` + `@audit_critical` pair, which would expose the double-finding bug. No test covers triple-decorator scenarios.

---

## Summary of Findings

| # | Category | Severity | Description |
|---|---|---|---|
| F1 | Finding inflation | MEDIUM | Entries #5 and #19 are the same pair (`fail_open`, `audit_critical`) in reversed order. Both fire, producing 2 findings for 1 contradiction. |
| F2 | Phantom decorators | LOW | `restoration_boundary` and `data_flow` are referenced in combinations #16, #17, #25 but are not in the registry. Detection depends on AST fallback for these; aliased imports will be missed. |
| F3 | Missing combination | INFO | `@fail_open` + `@must_propagate` is a genuine semantic contradiction not in the spec table. This is a spec gap, not an implementation bug. |
| F4 | Test gap | LOW | No test exercises the #5/#19 alias pair or triple-decorator scenarios. |

---

## Verdict: CONCERN

The rule correctly implements all 29 spec entries with accurate AST resolution, commutative matching, and proper severity assignment. However, the confirmed double-finding on the `{fail_open, audit_critical}` pair (F1) is a precision defect that inflates finding counts. Two phantom decorator references (F2) create a forward-compatibility dependency on unimplemented registry entries. Neither issue affects safety (no false negatives for implemented decorators, no spurious findings on legitimate stacking outside the alias pair), but F1 should be addressed before the rule is considered production-grade.
