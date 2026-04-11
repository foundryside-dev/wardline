# PY-WL-001 schema_default Governance Scope — Regression Recovery Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore PY-WL-001 `schema_default()` governance to the spec-required function-level semantics (§A.3 clause 3, §A.4 row 5), repair the corpus specimens and unit tests that locked in the regression, close the observability gap that allowed the regression to persist, and install structural controls preventing recurrence.

**Status:** Draft for review.

**Severity:** CRITICAL — non-conformant for the `schema_default` cell of PY-WL-001. Blocks any v1.0 conformance claim touching that cell. Follow-on audit required for other rules.

**Spec authority:** `docs/spec/wardline-02-A-python-binding.md` §A.3 clause 3 (line 76), §A.4 row 5 (line 172), canonical example lines 461-496.

**Panel review:** 7-specialist panel (SA, ST, PE, QE, SecArch, SAD, IRAP) convened 2026-04-11. Consensus: remove file-level governance. Non-consensus resolved in favor of SAD's architectural finding (decorator → boundary wiring gap).

---

## 1. Executive Summary

On 2026-04-09, commit `7caf751` ("feat: v1.0 release push — close all spec gaps, fix 8 bugs, add 6 features") introduced a silent loosening of PY-WL-001 `schema_default()` governance. A new method `_is_governed_by_optional_field` was added as an `or`-branch fallback to the existing function-level `_is_governed_by_boundary` check. The new method treats any call to `schema_default(x.get("key", ...))` anywhere in an `optional_fields` overlay scope as governed, regardless of whether the enclosing function carries a validation-boundary decorator.

This directly contradicts spec §A.3 clause 3 and §A.4 row 5, both of which require "validation boundary context" as a necessary condition for suppression. The regression:

- **Contradicts a MUST clause** in a normative spec chapter that predates the code change by 15 days.
- **Breaks** the pre-existing integration test `tests/integration/test_preview_phase2.py` (added 2026-03-24), which was silently excluded from local test runs by `pyproject.toml:65`.
- **Locked itself in** via three new unit tests added in the same commit with docstrings declaring "optional_fields is the primary governance mechanism" — language that has no spec basis.
- **Corrupted the golden corpus**: specimen `PY-WL-001-TN-schema-default-governed.yaml` declares `boundaries: function: "process"` but the Python fragment defines `def governed_schema_default` — the boundary qualname is wrong. The specimen only "passes" because the file-level fallback ignores qualname mismatches.
- **Persisted for 16 days** before being surfaced during unrelated test-failure triage.
- **Landed with no ADR, no spec update, and no human reviewer distinct from the Claude co-author** on the commit.

The 7-specialist panel (SA, ST, PE, QE, SecArch, SAD, IRAP) unanimously recommends reversing the regression. SAD's architectural review surfaced that a pure revert is insufficient: the spec's own canonical example (a function decorated with `@validates_shape` containing `schema_default(...)`) does not work with the current boundary-discovery code because no code path converts decorators into implicit `BoundaryEntry` objects. The correct fix is to wire decorator detection into `_is_governed_by_boundary` at the same time as removing the file-level fallback.

## 2. Background: The Regression

### 2.1 Spec text (authoritative)

**`docs/spec/wardline-02-A-python-binding.md:76`** (§A.3 clause 3 — Wardline-Core interface contract):

> "The tool MUST recognise `schema_default()` as a PY-WL-001 suppression marker. Calls wrapped in `schema_default()` where the default value matches the overlay's declared approved default are governed by the overlay declaration, not by PY-WL-001."

**`docs/spec/wardline-02-A-python-binding.md:172`** (§A.4 decorator table, row 5):

> "Scanner verifies overlay declaration, default value match, and validation boundary context."

Three conjunctive MUSTs: (1) overlay declaration, (2) default value match, (3) validation boundary context. "Validation boundary context" is function-level — the enclosing function must carry a validation-boundary decorator (`@validates_shape`, `@validates_external`, or a combined constructor).

**Canonical example (lines 461-496):**

```python
@validates_shape
def parse_partner_response(raw: dict) -> PartnerDTO:
    ...
    indicators = schema_default(raw.get("risk_indicators", []))
    ...
```

> "Note: `risk_indicators` is optional-by-contract — the external API may omit it. The `schema_default()` wrapper links this `.get()` to the overlay declaration for this data source, which declares the field as optional with an approved default of `[]`. Without `schema_default()`, the `.get()` would fire PY-WL-001 at ERROR/STANDARD severity."

The spec's worked example uses `@validates_shape` on the enclosing function. The overlay's `optional_fields` entry provides the *declaration*; the decorator provides the *validation-boundary context*. Both are required.

### 2.2 The regression (commit `7caf751`, 2026-04-09)

Added to `src/wardline/scanner/rules/py_wl_001.py`:

```python
# Lines 215-222 — was a simple AND condition, became OR:
if (
    optional_field is not None
    and default_value == optional_field.approved_default
    and (
        self._is_governed_by_boundary(optional_field.overlay_scope)
        or self._is_governed_by_optional_field(optional_field)   # NEW — spec-violating
    )
):
```

```python
# Lines 300-310 — new method:
def _is_governed_by_optional_field(self, optional_field: OptionalFieldEntry) -> bool:
    """Check if the optional_field declaration itself constitutes governance.

    An optional_field entry with a non-empty overlay_scope that covers
    the current file is sufficient governance for schema_default() —
    the optional_fields list is the primary governance mechanism.
    """
    return bool(
        optional_field.overlay_scope
        and path_within_scope(self._file_path, optional_field.overlay_scope)
    )
```

The docstring's claim that "optional_fields is the primary governance mechanism" has **no spec basis**. §A.3 and §A.4 require validation boundary context as a conjunct, not an alternative.

### 2.3 Contradictory unit tests added in the same commit

`tests/unit/scanner/test_py_wl_001.py`:

- **`test_optional_field_only_no_boundary_suppresses`** (lines 289-304) — docstring: *"optional_fields is the primary governance mechanism — no boundary needed"*. Fixture has no `BoundaryEntry`. Asserts `GOVERNED_DEFAULT`.
- **`test_wrong_function_boundary_still_governed_by_optional_field`** (lines 339-360) — boundary exists but qualname mismatches. Asserts `GOVERNED_DEFAULT`. **Misplaced**: lives in `TestSchemaDefaultUngoverned` whose class docstring says "schema_default() without matching boundary -> ERROR".
- **`test_wrong_transition_boundary_still_governed_by_optional_field`** (lines 362-382) — boundary has wrong transition type (`semantic_validation`, not a governance-relevant transition). Asserts `GOVERNED_DEFAULT`. Also misplaced in `TestSchemaDefaultUngoverned`.
- **`test_case_sensitive_qualname_boundary_still_governed_by_optional_field`** (lines 438-458) — case-mismatched qualname. Asserts `GOVERNED_DEFAULT`. Also misplaced. (Found by PE during panel review.)

All four tests assert behavior that the spec explicitly forbids. Deleting them does not reduce coverage — the scenarios they cover should all emit `UNGOVERNED_DEFAULT`.

### 2.4 Corpus corruption

Found by SAD during panel review:

- **`corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-TN-schema-default-governed.yaml`**: declares `boundaries: function: "process"` but the Python file defines `def governed_schema_default`. The boundary entry's `function` field does not match any function in the specimen. The specimen only passes corpus verify because the file-level fallback ignores qualname mismatches. This is a false-negative specimen — "passing" for the wrong reason.
- **`corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-TN-TF-governed-overlay.yaml`**: function `validate_and_default` has no `@validates_shape` decorator. Relies on file-level governance.

The golden corpus was written to match the broken rule, not to match the spec. Repairing these specimens is a prerequisite for any conformance claim.

### 2.5 Observability gap (QE finding)

`pyproject.toml:65`:

```toml
addopts = "-m 'not integration and not network'"
```

Every local `uv run pytest` invocation silently excludes integration tests by default. The broken `test_preview_phase2.py` was invisible to developers running tests locally. Integration tests run only in CI, only on PRs to `main`. This is the proximate reason the regression persisted for 16 days.

### 2.6 Architectural gap (SAD finding)

`BoundaryEntry` objects are constructed in exactly three places: `src/wardline/cli/corpus_cmds.py:135`, `src/wardline/manifest/loader.py:361`, `src/wardline/cli/scan.py:1531`. All three parse YAML. `resolve_boundaries()` in `src/wardline/manifest/resolve.py:31-89` only reads `resolved.boundaries` from the merged overlay model.

**No code path synthesizes a `BoundaryEntry` from a `@validates_shape` decorator.**

This means the spec's canonical example cannot work with `_is_governed_by_boundary` alone — the spec shows decorator-based governance, but the scanner requires a redundant `boundaries:` YAML entry with a matching qualname. The `_is_governed_by_optional_field` fallback was papering over this architectural hole. A pure revert would re-expose it.

## 3. Fix Plan

### Phase 0 (gate): Verify SAD's architectural claim

**Status: Precondition.** Before starting Phase 1, confirm that no code path converts `@validates_shape` / `@validates_external` decoration into an implicit `BoundaryEntry` or equivalent data structure.

- [ ] **Step 0.1**: Grep `src/wardline/` for all `BoundaryEntry(` construction sites. Confirm all come from YAML parsers.
- [ ] **Step 0.2**: Read `src/wardline/scanner/context.py` to confirm `ScanContext.annotations_map` exists and holds per-function decorator metadata.
- [ ] **Step 0.3**: Read `src/wardline/manifest/resolve.py::resolve_boundaries` and confirm it does not synthesize boundaries from decorators.
- [ ] **Step 0.4**: Trace how a function's annotations are discovered during scan (`scanner/engine.py` and `cli/_helpers.py::discover_all_annotations`).

**Gate**: If Phase 0 confirms SAD's finding, proceed with Option B (wire decorator → boundary). If Phase 0 finds a decorator → boundary code path that SAD missed, the fix simplifies to Option A (pure revert). The rest of this plan assumes Option B.

### Phase 1: Rule code fix (py_wl_001.py)

**Files:** `src/wardline/scanner/rules/py_wl_001.py`

- [ ] **Step 1.1: Remove the file-level fallback method.** Delete `_is_governed_by_optional_field` (lines 300-310) in its entirety. No other callers exist (verified by PE during panel review).

- [ ] **Step 1.2: Remove the `or` branch.** Change lines 215-222 from:

  ```python
  if (
      optional_field is not None
      and default_value == optional_field.approved_default
      and (
          self._is_governed_by_boundary(optional_field.overlay_scope)
          or self._is_governed_by_optional_field(optional_field)
      )
  ):
  ```

  to:

  ```python
  if (
      optional_field is not None
      and default_value == optional_field.approved_default
      and self._is_governed_by_validation_context(optional_field.overlay_scope)
  ):
  ```

- [ ] **Step 1.3: Add validation-context check.** Add a new method `_is_governed_by_validation_context` that returns True under *either* of two conditions (both function-level, both spec-aligned):

  1. The current function appears in `self._context.boundaries` with a matching qualname, governance-relevant transition, non-empty `overlay_scope`, and file within scope. (This is the existing `_is_governed_by_boundary` logic — call it as a helper.)
  2. The current function is decorated with `@validates_shape`, `@validates_external`, or `@validates_combined` (any `_GOVERNED_TRANSITIONS` decorator) in `self._context.annotations_map`, AND the decorator's effective scope covers the file.

  Exact implementation (pseudocode, adjust to match actual `annotations_map` shape discovered in Phase 0):

  ```python
  def _is_governed_by_validation_context(self, overlay_scope: str) -> bool:
      """Spec §A.3 clause 3 / §A.4 row 5: validation boundary context is
      satisfied by either an explicit overlay boundary entry OR a
      validation-boundary decorator on the enclosing function.
      """
      if self._is_governed_by_boundary(overlay_scope):
          return True
      return self._has_validation_decorator_on_current_function()

  def _has_validation_decorator_on_current_function(self) -> bool:
      """True iff the enclosing function carries @validates_shape,
      @validates_external, or a combined validator decorator.
      """
      if self._context is None or self._current_qualname is None:
          return False
      annotations = self._context.annotations_map.get(
          (self._file_path, self._current_qualname), ()
      )
      return any(
          ann.name in {"validates_shape", "validates_external", "validates_combined"}
          for ann in annotations
      )
  ```

  **Note**: Exact attribute names (`annotations_map`, `ann.name`) must match the real structures found in Phase 0. The decorator name set must match the keys `_GOVERNED_TRANSITIONS` expects.

- [ ] **Step 1.4: Rename or retire `_is_governed_by_boundary`.** Keep the method as a private helper for explicit-boundary-entry matching, called from `_is_governed_by_validation_context`. Update its docstring to clarify it is one of two paths, not the only one.

- [ ] **Step 1.5: Run `uv run ruff check src/wardline/scanner/rules/py_wl_001.py` and `uv run mypy src/wardline/scanner/rules/py_wl_001.py`. Both must pass clean.

### Phase 2: Unit tests (test_py_wl_001.py)

**Files:** `tests/unit/scanner/test_py_wl_001.py`

- [ ] **Step 2.1: Delete the 4 spec-violating tests:**
  - `test_optional_field_only_no_boundary_suppresses` (lines 289-304)
  - `test_wrong_function_boundary_still_governed_by_optional_field` (lines 339-360)
  - `test_wrong_transition_boundary_still_governed_by_optional_field` (lines 362-382)
  - `test_case_sensitive_qualname_boundary_still_governed_by_optional_field` (lines 438-458)

- [ ] **Step 2.2: Add inverted tests asserting the correct behavior.** Each deleted scenario corresponds to a case that must now emit `UNGOVERNED_DEFAULT`. Add (in `TestSchemaDefaultUngoverned`):
  - `test_optional_field_without_boundary_or_decorator_is_ungoverned` — optional_field matches, no boundary, no decorator → `PY_WL_001_UNGOVERNED_DEFAULT`
  - `test_wrong_function_boundary_is_ungoverned` — boundary exists but qualname mismatches → ungoverned
  - `test_wrong_transition_boundary_is_ungoverned` — boundary exists but transition is not governance-relevant → ungoverned
  - `test_case_sensitive_qualname_mismatch_is_ungoverned` — case differs → ungoverned

- [ ] **Step 2.3: Add new tests for decorator-based governance** (SAD's list). These tests require the Phase 1 implementation to wire `annotations_map` into the rule:
  - `test_schema_default_with_validates_shape_decorator_is_governed` — spec canonical example (decorator + optional_field, no explicit boundary entry) → GOVERNED
  - `test_schema_default_with_validates_external_decorator_is_governed` — combined T4→T2 validator
  - `test_schema_default_in_undecorated_helper_is_ungoverned` — decorator on a sibling function, not the enclosing one → UNGOVERNED (regression lock)
  - `test_schema_default_in_class_method_without_decorator_is_ungoverned` — class-qualname variant
  - `test_schema_default_decorator_on_outer_not_inner` — nested function; outer has `@validates_shape`, inner helper does not → inner call is UNGOVERNED

- [ ] **Step 2.4: Add `SPEC_REF` class constant** to `TestSchemaDefaultGoverned` and `TestSchemaDefaultUngoverned` (ST's recommendation):
  ```python
  class TestSchemaDefaultGoverned:
      """schema_default() with validation boundary context -> SUPPRESS."""
      SPEC_REF = (
          "docs/spec/wardline-02-A-python-binding.md §A.3 clause 3 (line 76); "
          "§A.4 row 5 (line 172); canonical example lines 461-496"
      )
  ```

- [ ] **Step 2.5: Verify class-docstring consistency.** The `TestSchemaDefaultUngoverned` class docstring says "schema_default() without matching boundary -> ERROR". After Phase 2, every test in this class must conform to that contract. No test in this class may assert `GOVERNED_DEFAULT`.

### Phase 3: Integration test fixture (test_preview_phase2.py)

**Files:** `tests/integration/test_preview_phase2.py`

- [ ] **Step 3.1: Add `@validates_shape` to `governed_fn`.** Update `_write_source_file` (lines 43-67) so `governed_fn` carries `@validates_shape`:

  ```python
  'from wardline import schema_default, validates_shape\n'
  '\n'
  'def ungoverned_fn(data):\n'
  '    """schema_default() with no decorator → PY-WL-001-UNGOVERNED-DEFAULT."""\n'
  '    return schema_default(data.get("key", ""))\n'
  '\n'
  '\n'
  '@validates_shape\n'
  'def governed_fn(data):\n'
  '    """schema_default() in validation boundary → PY-WL-001-GOVERNED-DEFAULT (SUPPRESS)."""\n'
  '    return schema_default(data.get("key", ""))\n'
  ```

- [ ] **Step 3.2: Reconsider the overlay `boundaries:` entry.** With decorator-based governance wired in Phase 1, the overlay's `boundaries:` entry for `governed_fn` may be redundant. Two options:
  - (A) Keep the overlay entry so the test exercises the explicit-boundary path *and* the decorator path redundantly. Simpler.
  - (B) Remove the overlay entry so the test is a true discriminator of the decorator path only. ST's recommendation.

  Preferred: **Option B**. Make the fixture prove that the decorator alone governs. This catches any future regression that removes decorator-path support.

- [ ] **Step 3.3: Address the `overlay_scope` gap that PE found.** The current overlay YAML has no `overlay_scope` field. Add `overlay_scope: src` to the optional_field entry, and verify whether the decorator-path helper requires a scope or not. Document the resolution in the fixture.

- [ ] **Step 3.4: Verify test assertions still match.** After the fixture update, re-run `test_unverified_default_count_is_one`, `test_unverified_defaults_contains_ungoverned_fn`, `test_governed_fn_not_in_unverified_defaults`, `test_get_fn_not_in_unverified_defaults`, and `test_output_flag_writes_to_file`. All must pass.

### Phase 4: Corpus repair and extension

**Files:** `corpus/specimens/PY-WL-001/`

- [ ] **Step 4.1: Repair `PY-WL-001-TN-schema-default-governed`**. Either (a) add `@validates_shape` to the function in the `.py` fragment and align the `boundaries.function` field in the YAML, or (b) rename the function to match the existing `boundaries` entry. Option (a) is preferred — it matches the spec canonical example.

- [ ] **Step 4.2: Repair `PY-WL-001-TN-TF-governed-overlay`**. Add `@validates_shape` to `validate_and_default`.

- [ ] **Step 4.3: Add `PY-WL-001-TN-schema-default-validates-shape`**. A true-negative specimen derived verbatim from the spec canonical example at `wardline-02-A-python-binding.md:461-475`. The specimen should contain `@validates_shape def parse_partner_response` calling `schema_default(raw.get("risk_indicators", []))`. Overlay declares only `optional_fields` for `risk_indicators` — no boundary entry needed. Expected verdict: GOVERNED/SUPPRESS.

  This specimen **locks the spec canonical example into the golden corpus**. Any future change that breaks it will fail corpus verify immediately.

- [ ] **Step 4.4: Add `PY-WL-001-TP-schema-default-undecorated-helper`**. A true-positive specimen: a helper function without any validation decorator, under an `optional_fields` overlay scope, calls `schema_default(x.get("key", default))`. Expected verdict: UNGOVERNED/ERROR.

  This specimen **locks the regression out**. Any future change that re-introduces file-level governance will fail this specimen.

- [ ] **Step 4.5: Add `PY-WL-001-TP-schema-default-wrong-transition`**. Boundary entry exists with wrong transition type (e.g., `semantic_validation`). Expected: UNGOVERNED/ERROR.

- [ ] **Step 4.6: Run `uv run wardline corpus verify --json`**. All PY-WL-001 cells must meet precision ≥ 80% and recall ≥ 90%. No specimen may be "passing for the wrong reason."

### Phase 5: Documentation

- [ ] **Step 5.1: Write ADR-004.** Create `docs/adr/ADR-004-schema-default-governance-function-level.md`. Use IRAP's draft as a starting point:

  - **Title**: ADR-004 — schema_default() governance is function-level, not file-level
  - **Status**: Accepted
  - **Date**: 2026-04-11 (or the date the fix lands)
  - **Context**: spec §A.3 clause 3 requires three conjunctive conditions. An interim implementation (`7caf751`, 2026-04-09) collapsed (c) validation boundary context into a file-scope predicate, contradicting the spec.
  - **Decision**: Governance is anchored at the function boundary. Validation boundary context is satisfied by either (i) an explicit overlay `boundaries` entry with matching qualname and governance-relevant transition, or (ii) a validation-boundary decorator on the enclosing function. The `optional_fields` list is a necessary condition for suppression; it is never sufficient.
  - **Consequences**: `_is_governed_by_optional_field` removed; decorator-based governance wired; unit tests asserting file-level governance deleted; corpus specimens repaired; self-hosting scan unaffected (Wardline's own `src/` does not use `schema_default`).
  - **Alternatives rejected**: file-level governance was considered and rejected — overlay declarations are trust-topology statements, not validation claims.

- [ ] **Step 5.2: Add residual risk #18** to `docs/spec/wardline-01-13-residual-risks.md`. Use IRAP's proposed text verbatim (see §5 of the panel synthesis). The entry must document: regression window, discovery mechanism, immediate corrective action, and systemic mitigation.

- [ ] **Step 5.3: Annotate the 2026-04-09 conformance review.** Add a rescission notice to `docs/requirements/spec-fitness/conformance-review-2026-04-09.md`:

  > "**2026-04-11 rescission**: The PY-WL-001 conformance claim in this review is rescinded for the `schema_default()` subset. Between 2026-04-09 and 2026-04-11 the reference scanner implemented file-level governance in contradiction to §A.3 clause 3. The claim is restored after commit [fix SHA] and re-verification per this plan's Phase 6. See ADR-004 and residual risk #18."

- [ ] **Step 5.4: Update the §15.6 assessment package.** Regenerate the corpus verify report, the self-hosting SARIF, and the fingerprint baseline. Reissue the §15.6 evidence with a provenance note explaining the rescission and restoration.

### Phase 6: Conformance re-verification

- [ ] **Step 6.1: Run corpus verify.** `uv run wardline corpus verify --json > /tmp/corpus.json`. Assert `overall_verdict == "PASS"`. Assert the new regression-lock specimen (Phase 4.4) is present and has verdict matching expectation.

- [ ] **Step 6.2: Run full self-hosting scan.** `uv run wardline scan src/`. Review the SARIF output for any new findings introduced by the fix. SAD's analysis indicates zero new findings expected (Wardline's own code does not use `schema_default()`), but verify.

- [ ] **Step 6.3: Regenerate fingerprint baseline.** `uv run wardline fingerprint generate` (or equivalent). The new baseline must match the pre-regression baseline for the `schema_default` subset; any delta requires documented investigation.

- [ ] **Step 6.4: Run the full unit + integration test suite.** `uv run pytest tests/ -q -p no:randomly` with **no** `-m 'not integration'` filter. All tests must pass.

- [ ] **Step 6.5: Lint and type-check.** `uv run ruff check src/` and `uv run mypy src/`. Both clean.

### Phase 7: Drift detection (systemic controls)

The regression persisted because four independent controls failed: (1) integration tests excluded from local runs, (2) unit tests were used as informal spec documentation without citation, (3) no pre-merge check enforced a link between rule code changes and spec changes, (4) no corpus specimen existed for the spec canonical example. Phase 7 installs controls for each failure mode.

#### 7A: Close the observability gap (QE finding)

- [ ] **Step 7A.1: Remove default integration-test exclusion.** Change `pyproject.toml:65` from:
  ```toml
  addopts = "-m 'not integration and not network'"
  ```
  to:
  ```toml
  addopts = "-m 'not network'"
  ```
  Integration tests will run by default. Network tests remain excluded (they require external services).

- [ ] **Step 7A.2: Add a `--fast` pytest profile** for developers who want the quick unit-only loop. Either via a `fast` marker and `--fast` option, or via documentation that recommends `pytest -m 'not integration'` when iterating.

- [ ] **Step 7A.3: Verify CI runs integration tests on all PRs**, not just PRs to `main`. Read `.github/workflows/ci.yml` and ensure the `test-integration` job runs on all branches.

#### 7B: Spec-linked change gate (IRAP, SecArch)

- [ ] **Step 7B.1: Add CODEOWNERS** on rule modules. Create or update `.github/CODEOWNERS`:
  ```
  # Scanner rules require spec-owner review — any change to rule semantics
  # must be verified against docs/spec/wardline-02-*-*.md.
  src/wardline/scanner/rules/py_wl_*.py @wardline-spec-owners
  src/wardline/scanner/rules/scn_*.py   @wardline-spec-owners
  src/wardline/scanner/rules/sup_*.py   @wardline-spec-owners
  docs/spec/                             @wardline-spec-owners
  ```

- [ ] **Step 7B.2: Add pre-merge CI check** that rejects rule module changes without either (a) a matching diff under `docs/spec/wardline-02-*.md`, or (b) a `Spec-Unchanged-Justification:` trailer in the PR description citing the MUST clause that the change does not affect.

  Implementation: a GitHub Action that runs on `pull_request` and inspects `git diff --name-only origin/main...HEAD`. If any file matches `src/wardline/scanner/rules/py_wl_*.py`, assert that either `docs/spec/wardline-02-A-python-binding.md` is also in the diff OR the PR body contains the trailer.

- [ ] **Step 7B.3: Add commit-trailer requirement** for rule-module changes. Any commit modifying `src/wardline/scanner/rules/py_wl_*.py` must include either:
  - `Spec-Impact: tightening` (requires spec edit in the commit)
  - `Spec-Impact: loosening` (requires ADR + spec edit in the commit)
  - `Spec-Impact: none` (requires review)

  Enforced via the same CI check as 7B.2.

- [ ] **Step 7B.4: Reject co-author-only approval.** Update the pre-merge check: a PR whose only human identity on the commit is the co-author trailer (`Co-Authored-By: Claude...`) is not approved. The reviewer must be a human identity distinct from both the commit author and the Claude co-author. This closes the specific gap this incident exposed.

#### 7C: Spec-ref traceability test (SA, ST, QE)

- [ ] **Step 7C.1: Add spec anchors** to `docs/spec/wardline-02-A-python-binding.md`. Every MUST clause gets a stable anchor:
  ```markdown
  3. **Schema default recognition.** <!-- must-id: A.3.3 --> The tool MUST recognise `schema_default()`...
  ```

- [ ] **Step 7C.2: Add `SPEC_REF` constants** to all rule test classes (not just PY-WL-001). Each class references at least one MUST-id.

- [ ] **Step 7C.3: Add a conftest check** in `tests/conftest.py` that asserts every `Test*` class in `tests/unit/scanner/rules/` and `tests/integration/` that tests a Wardline rule has a `SPEC_REF` attribute referencing a MUST-id that resolves to actual text in the spec.

- [ ] **Step 7C.4: Add a meta-test** `tests/conformance/test_must_clause_traceability.py` (QE's proposal). The test:
  1. Parses all MUST clauses from `docs/spec/wardline-02-*.md` by regex and their must-id anchors.
  2. Collects all tests carrying `SPEC_REF` attributes.
  3. Fails if any MUST clause has zero tests citing it.
  4. Fails if any test cites a MUST-id that does not exist in the spec.

#### 7D: Corpus-as-ground-truth (SA, SecArch)

- [ ] **Step 7D.1: Add a corpus specimen for every spec canonical example.** Any `def ... schema_default(...)` pattern shown in `docs/spec/wardline-02-A-python-binding.md` must exist as a corpus specimen with the expected verdict derived from the spec text. Phase 4.3 starts this; extend it in a follow-up to cover all canonical examples in the spec.

- [ ] **Step 7D.2: Add a negative corpus directory.** `corpus/specimens/negative/PY-WL-001/` for specimens that are expected to be ungoverned. Any verdict change on a negative specimen is a CI error.

- [ ] **Step 7D.3: Document the corpus contract.** Update `corpus/README.md` (or create it) stating: "Unit tests may not contradict corpus specimens. If a unit test and a corpus specimen disagree, the build fails and a human must adjudicate."

### Phase 8: Follow-on audit (SecArch)

The `7caf751` commit was a 35-issue omnibus commit touching many rules. The silent loosening of PY-WL-001 raises a reasonable prior that other rules in the same commit were also loosened.

- [ ] **Step 8.1: Enumerate `_is_governed_by_*` helpers across all rule modules.** For each, check whether the helper implements a spec MUST clause and whether the implementation matches the spec text.
  - Files to check: `src/wardline/scanner/rules/py_wl_*.py`, `scn_*.py`, `sup_*.py`.

- [ ] **Step 8.2: Enumerate `or` branches added in `7caf751`.** Any disjunction added in that commit is suspect. Review each one against the spec.
  - This requires reading the commit's full diff against rule modules.

- [ ] **Step 8.3: For each rule with a finding, run the panel review.** Dispatch the 7-specialist panel for each rule with suspected drift. Apply the same evidence-gathering discipline: spec text → code → unit tests → corpus → integration tests → git history → ADR absence.

- [ ] **Step 8.4: Produce an audit report.** File findings as individual regression-recovery plans similar to this one. Each plan gets its own ADR.

## 4. Acceptance Criteria

The fix is complete when ALL of the following hold:

1. **Code:**
   - `_is_governed_by_optional_field` no longer exists in `py_wl_001.py`.
   - `_is_governed_by_validation_context` (or equivalent) exists and accepts both explicit-boundary and decorator-based governance.
   - `ruff check src/` and `mypy src/` pass clean.

2. **Tests:**
   - The 4 spec-violating unit tests are deleted.
   - The 4 inverted tests asserting `UNGOVERNED_DEFAULT` for the same scenarios pass.
   - The 5 new decorator-based governance tests pass.
   - `test_preview_phase2.py` passes with the updated fixture (decorator-based `governed_fn`).
   - Full test suite runs without the `-m 'not integration'` filter: `pytest tests/` green.

3. **Corpus:**
   - Both malformed governed specimens (repair of 4.1, 4.2) are repaired and pass.
   - Two new specimens (4.3, 4.4) exist: the spec canonical example as TN, the regression-lock as TP.
   - `wardline corpus verify` reports overall PASS with PY-WL-001 UNCONDITIONAL cell meeting precision ≥ 80% and recall ≥ 90%.

4. **Documentation:**
   - ADR-004 exists and is signed off.
   - Residual risk #18 is added to `wardline-01-13-residual-risks.md`.
   - `conformance-review-2026-04-09.md` carries the rescission-and-restoration notice.

5. **Systemic controls (Phase 7):**
   - `pyproject.toml:65` no longer excludes integration tests by default.
   - `.github/CODEOWNERS` requires spec-owner review on rule modules.
   - Pre-merge CI check enforces the spec-link requirement on rule module changes.
   - `SPEC_REF` class constants exist on schema_default test classes.
   - The MUST-clause traceability meta-test runs and passes.

6. **Follow-on audit (Phase 8) — scheduled, not blocking this PR:**
   - An audit plan exists for other `_is_governed_by_*` helpers.
   - Any other rules with silent drift have their own recovery plans filed.

## 5. Risk Assessment

**High confidence** on the diagnosis and fix direction. The spec text is unambiguous, the timeline is documented in git history, the corpus corruption is observable, and SAD's architectural finding was independently traced through all three `BoundaryEntry` construction sites.

**Medium confidence** on the Phase 1 implementation details. The exact shape of `ScanContext.annotations_map` and the decorator-identification helper may need adjustment when the code is read in detail during Phase 0. The plan's pseudocode is illustrative, not literal.

**Low risk** of self-hosting regression. SAD verified that Wardline's own `src/` does not use `schema_default()` in runtime code. The fix will not break the self-scan.

**Medium risk** of breaking downstream consumers. Any consumer project that wrote overlays relying on file-level governance will see new `UNGOVERNED_DEFAULT` findings. This is **desirable** — those sites are the ones that need review — but the change must be communicated in the fix commit's release notes.

**Residual risk** after the fix: the class of silent drift this regression represents (code changes contradicting spec MUST clauses without an ADR) can only be fully mitigated by the Phase 7 controls. Without Phase 7, a future session can repeat this incident on a different rule.

## 6. Open Questions for Review

1. **Phase 0 gate outcome.** If Phase 0 finds that decorator → boundary wiring already exists (contrary to SAD's finding), does the plan collapse to Option A (pure revert)? Who verifies Phase 0?

2. **Downstream communication.** Wardline is pre-1.0 and not yet released externally. Is release-note communication required, or is the regression window entirely internal?

3. **7B.4 (co-author governance).** Who enforces "the human reviewer must be distinct from the Claude co-author"? GitHub's branch protection rules can enforce "at least one approving review from someone other than the author," but the Claude co-author trailer is not a GitHub identity. Does CODEOWNERS suffice, or do we need additional tooling?

4. **Phase 8 scope.** The follow-on audit is potentially large (all rules, all `_is_governed_by_*` helpers, all `or` branches in `7caf751`). Is Phase 8 a separate WP after this fix lands, or in-scope for this plan?

5. **ADR-004 decision maker.** IRAP identifies the spec owner as the decision maker. For Wardline, is this a single human, or a role held jointly? Who signs off on ADR-004?

## 7. Panel Recommendations (Full Text)

The full expert recommendations from the 7-specialist panel are preserved in the conversation record for 2026-04-11. Key points:

- **SA (Solution Architect)**: Spec is authoritative. Option A. Write ADR-004. Spec-to-test traceability as the structural intervention.
- **ST (Systems Thinker)**: Shifting the Burden archetype. The reinforcing loop is "code → unit test asserts code → test becomes authority." Leverage point is Meadows level 6 (information flows). Structural intervention: `SPEC_REF` class constants forcing test authors to cite the spec.
- **PE (Python Engineer)**: Found the 5th spec-violating test (`test_case_sensitive_qualname_boundary_still_governed_by_optional_field`). Found the `overlay_scope` gap in the integration test fixture.
- **QE (Quality Engineer)**: Found the observability root cause (`pyproject.toml:65` excludes integration tests). Proposed the MUST-clause traceability meta-test.
- **SecArch (Security Architect)**: Classified as CRITICAL — must block v1.0. Provided 3 concrete attack scenarios (authorization bypass via role defaulting, classification downgrade, blanket `is_admin` suppression). Proposed the spec-impact commit trailer.
- **SAD (Static Analysis Dev)**: Found the architectural gap — no code path converts decorators to boundary entries. Found the malformed corpus specimen. Recommended Option B (decorator → boundary wiring).
- **IRAP (Conformance Assessor)**: NON-CONFORMANT. Provided the full ADR-004 draft, residual risk #18 text, rescission notice text, CMMI maturity analysis (ML2 → ML3 gap in Requirements Management and Configuration Audit), and the detailed process change recommendation.

---

## Notes

- This plan supersedes any prior guidance on PY-WL-001 `schema_default()` governance.
- The plan is designed for execution by a subagent-driven-development workflow. Each phase can be assigned to a separate agent; Phases 1-4 must complete before Phases 5-7.
- Phase 8 (follow-on audit) is intentionally separated. It must not block this fix.
- The fix commit message should include `Spec-Impact: tightening` and reference ADR-004 and residual risk #18.
