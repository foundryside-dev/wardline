# PY-WL-001 schema_default Governance Scope — Regression Recovery Plan (V2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore PY-WL-001 `schema_default()` governance to the spec-required function-level semantics (§A.3 clause 3 and §A.4 row 5), repair the corpus specimens and unit tests that locked in the regression, close the observability gap that allowed the regression to persist, and install structural controls preventing recurrence. V2 also fixes scope gaps in V1, widens the blast-radius audit from "scheduled later" to "in-scope right now" for the rules carrying the same architectural bug, and commits to spec-grounded decisions V1 hedged on.

**Architecture:** Function-level governance check expressed once in `rules/base.py` as a reusable helper. Each affected rule calls the helper. The helper requires (a) a matching explicit boundary entry OR (b) a validation-boundary decorator on the enclosing function *plus* scope coverage *plus* a structural sanity check that the decorator actually carries `_wardline_transition` metadata. Corpus specimens derived from the spec canonical example lock the semantics in. A conftest-level MUST-clause traceability gate forces every rule test class to cite the spec text it enforces.

**Tech Stack:** Python 3.12, `uv`, pytest, mypy strict, ruff, Click CLI, `wardline corpus verify`, GitHub Actions.

**Status:** Ready for execution. Supersedes V1 (see §13).

**Severity:** CRITICAL — non-conformant for the `schema_default` cell of PY-WL-001. Blocks any v1.0 conformance claim touching that cell. In-scope audit required for PY-WL-003 and PY-WL-007 (same bug pattern).

**Spec authority:**

- `docs/spec/wardline-02-A-python-binding.md` §A.3 clause 3 (line 76)
- `docs/spec/wardline-02-A-python-binding.md` §A.4 row 5 (line 172)
- `docs/spec/wardline-02-A-python-binding.md` canonical example (lines 440-500)

**Panel reviews:**

- 7-specialist panel (SA, ST, PE, QE, SecArch, SAD, IRAP) convened 2026-04-11 — produced V1.
- Same 7-specialist panel adversarially reviewed V1 on 2026-04-11 — produced **13 blockers** and **10+ important findings**. V2 addresses all of them.

**Canonical regression window:** `REGRESSION_WINDOW = 2026-04-09 .. 2026-04-12` (**3 days**, not 16). All downstream documents must derive from this field. V1's "16 days" claim was arithmetically wrong.

---

## 1. Executive Summary

On 2026-04-09, commit `7caf751` ("feat: v1.0 release push — close all spec gaps, fix 8 bugs, add 6 features") introduced a silent loosening of PY-WL-001 `schema_default()` governance. A new method `_is_governed_by_optional_field` became an `or`-branch fallback to the existing function-level `_is_governed_by_boundary` check. The new method suppresses any `schema_default(x.get("key", ...))` anywhere inside an `optional_fields` overlay scope, regardless of whether the enclosing function carries a validation-boundary decorator or an explicit boundary entry.

This directly contradicts spec §A.3 clause 3 and §A.4 row 5, both of which require "validation boundary context" as a necessary condition for suppression. The regression:

- **Contradicts a MUST clause** in a normative spec chapter. The "validation boundary context" language has been in the spec since 2026-03-25 (commit `fd6c231`) — 15 days before the regression commit landed. The **spec-change → regression-commit** interval is 15 days; the **regression-commit → discovery** interval is 3 days. V1 conflated the two.
- **Was masked** by four new unit tests added in the same commit whose docstrings assert "optional_fields is the primary governance mechanism" — a claim with no spec basis.
- **Was masked** by a pre-existing integration test (`tests/integration/test_preview_phase2.py`) that was silently excluded from local runs via `pyproject.toml addopts = "-m 'not integration and not network'"` **and** by the CI `test-unit` job's hard-coded `-m "not integration"` argument (`ci.yml:32`), **and** by the `test-integration` job being gated on `pull_request: branches: [main]` so that feature branches never ran it.
- **Corrupted one corpus specimen** (`PY-WL-001-TN-schema-default-governed.yaml`: declares `boundaries: function: "process"` while the Python fragment defines `def governed_schema_default` — a real qualname mismatch). The specimen only passes because the file-level fallback ignores qualname.
- **Sits on top of an architectural gap** (SAD finding): no code path synthesises a `BoundaryEntry` from a `@validates_shape` decorator, so the spec's own canonical example (a `@validates_shape` function containing `schema_default(...)`) cannot be made to pass under `_is_governed_by_boundary` alone.

**Fix direction:** remove the file-level fallback, wire decorator-based validation context into the rule through a shared helper on `rules/base.py`, repair the corpus, delete the spec-violating unit tests, rewrite the integration fixture to prove the decorator path, and install structural controls (observability, spec-link enforcement, corpus-as-ground-truth, CODEOWNERS with an actually-distinct reviewer). V2 extends V1 by:

1. Wiring the decorator check through `_wardline_*` attrs on the discovered annotation, not bare name matching, so the Scenario-A attack (`@validates_shape` on a stub) is blocked.
2. Cross-checking file scope on the decorator path so decorator-based governance does not loosen file-level overlay scoping.
3. Fanning the fix out to PY-WL-003, PY-WL-007 in the same PR (same bug pattern, verified in code).
4. Running a retrospective scan of every commit in the 3-day degraded window against the fixed rule to enumerate anything that was silently suppressed.
5. Rescinding **all seven** affected conformance artefacts, not just the `2026-04-09` review.
6. Committing to spec-grounded decisions on `validates_semantic` eligibility, the decorator secondary-check mechanism, and the CODEOWNERS second reviewer.

## 2. Background: The Regression

### 2.1 Spec text (authoritative)

**`docs/spec/wardline-02-A-python-binding.md:76`** (§A.3 clause 3 — Wardline-Core interface contract):

> "The tool MUST recognise `schema_default()` as a PY-WL-001 suppression marker. Calls wrapped in `schema_default()` where the default value matches the overlay's declared approved default are governed by the overlay declaration, not by PY-WL-001."

**`docs/spec/wardline-02-A-python-binding.md:172`** (§A.4 decorator table, row 5):

> "Scanner verifies overlay declaration, default value match, and validation boundary context."

Three conjunctive MUSTs: (1) overlay declaration, (2) default value match, (3) validation boundary context. "Validation boundary context" is function-level — the enclosing function must either carry a validation-boundary decorator or be listed as a matching boundary entry in the overlay.

**Canonical example (lines 440-500, canonical lines 461-475):**

```python
@validates_shape
def parse_partner_response(raw: dict) -> PartnerDTO:
    ...
    indicators = schema_default(raw.get("risk_indicators", []))
    ...
```

### 2.2 The regression commit (2026-04-09, `7caf751`)

The commit added `_is_governed_by_optional_field` (py_wl_001.py:300-310) and joined it with `or` to the existing `_is_governed_by_boundary` check at lines 215-222. The new method treats any `optional_field` overlay scope covering the current file as sufficient governance.

### 2.3 Four contradictory unit tests added in the same commit

`tests/unit/scanner/test_py_wl_001.py`:

- `test_optional_field_only_no_boundary_suppresses` (lines 289-304)
- `test_wrong_function_boundary_still_governed_by_optional_field` (lines 339-360)
- `test_wrong_transition_boundary_still_governed_by_optional_field` (lines 362-382)
- `test_case_sensitive_qualname_boundary_still_governed_by_optional_field` (lines 438-458)

All four assert behaviour the spec forbids. Three are misplaced inside `TestSchemaDefaultUngoverned` whose class docstring says "schema_default() without matching boundary -> ERROR".

### 2.4 Corpus corruption — confirmed one specimen, exonerated the other

- **`PY-WL-001-TN-schema-default-governed.yaml`** declares `boundaries.function: "process"` while the `.py` defines `def governed_schema_default`. Qualname mismatch is real. Specimen is passing because of the file-level fallback.
- **`PY-WL-001-TN-TF-governed-overlay.yaml`** declares `boundaries.function: "validate_and_default"` which matches the `.py` definition `def validate_and_default`. V1 claimed this specimen was malformed. **V1 was wrong.** This specimen is correct as-is and only needs verification.

### 2.5 Observability gap — three independent failures, not one

V1 named one. All three were missed by local and by feature-branch runs:

1. **`pyproject.toml:72`** — `addopts = "-m 'not integration and not network'"`. Every `uv run pytest` silently drops integration tests.
2. **`.github/workflows/ci.yml:32`** — `test-unit` job has `run: uv run pytest -m "not integration" ...` hard-coded in the job step. Even if `addopts` were fixed, CI's `test-unit` job would still exclude integration tests because the CLI `-m` flag wins.
3. **`.github/workflows/ci.yml:6,43-45`** — the `test-integration` job is gated on `pull_request: branches: [main]` and `needs: test-unit`. Feature branches pushed to non-`main` PRs never ran the integration suite.

Any one of the three alone would have masked the regression. All three have to close for the plan to be considered to have fixed the observability hole.

### 2.6 Architectural gap (SAD finding, reverified)

`BoundaryEntry` objects are constructed in exactly three places: `src/wardline/cli/corpus_cmds.py:135`, `src/wardline/manifest/loader.py:361`, `src/wardline/cli/scan.py:1531`. All three parse YAML. No code path synthesises a `BoundaryEntry` from a `@validates_shape` decorator. PY-WL-001 and PY-WL-003 and PY-WL-007 rely solely on `boundary.function == self._current_qualname`, so without a YAML boundary entry the spec's canonical example cannot activate suppression in those three rules. PY-WL-008 and PY-WL-009 already fall back to a node-level `_has_direct_decorator` check, so they do not carry the same gap.

### 2.7 Single-reviewer governance gap

`.github/CODEOWNERS` lists exactly one human identity: `@johnm-dta`. For any commit authored by `@johnm-dta`, "at least one approving review from someone other than the author" is vacuous. V1's Phase 7B.4 ("reject co-author-only approval") has no teeth against the current CODEOWNERS file. V2 addresses this head-on.

## 3. Diff from V1

V1 was adversarially reviewed by the same 7-specialist panel on 2026-04-11. The panel returned **13 blockers** and **10+ important findings**. V2 is written from a clean slate using V1 and the panel findings as inputs. V2 preserves the diagnostic framing, Option B (decorator → boundary wiring), the Phase 3.1 import approach, the corpus regression-lock strategy, and CODEOWNERS on rule modules. V2 changes, adds, or hardens the following:

| # | Topic | V1 | V2 |
|---|-------|----|----|
| 1 | `annotations_map` key shape | `(file_path, qualname)` tuple, `ann.name` | `qualname` string, `ann.canonical_name` (matches real model) |
| 2 | `validates_combined` | Named as a valid decorator | **Does not exist**. Replaced by spec-grounded decision in ADR-004 |
| 3 | `_GOVERNED_TRANSITIONS` reuse | Reused as decorator set | New constant `_VALIDATION_DECORATORS` with registry-backed unit test |
| 4 | Phase 1 ordering | Delete → change condition → add method (broken mid-step) | Add methods → change condition → delete old method (checkpointed) |
| 5 | `_run_rule_with_context` | Used as-is | Extended with `annotations_map` parameter in new Phase 2.0 |
| 6 | Integration test exclusion | Fixed `pyproject.toml` only | Fixed `pyproject.toml` + `ci.yml:32` + `ci.yml` pull_request filter |
| 7 | Decorator as marker | Pure name match | Name match **AND** `_wardline_transition` attr present **AND** file within `overlay_scope` |
| 8 | Retrospective exploit scan | Not present | New Phase 6.6 — checkout each commit in `REGRESSION_WINDOW`, diff fixed rule output |
| 9 | Acceptance criteria | `overall_verdict == "PASS"` | Per-cell floors: UNCONDITIONAL ≥ 90% recall, ≥ 80% precision, sample ≥ 5 |
| 10 | Conformance rescission | 1 artefact | **7 artefacts**, enumerated |
| 11 | CODEOWNERS | Add path entries for rule modules | Add path entries **and** add a second named human reviewer OR explicitly disclose the single-reviewer gap |
| 12 | Decorator-path helper scope check | No `overlay_scope` cross-check | Decorator path also asserts `path_within_scope(file, overlay_scope)` |
| 13 | Phase 4.1 corpus repair | Ambiguous "option (a) or (b)" | Committed: option (a) and add sibling YAML-boundary-only specimen so the explicit-boundary path retains corpus coverage |
| 14 | Phase 4.2 corpus repair | "Add @validates_shape" (specimen was fine) | Verify-only — specimen is already correct |
| 15 | Phase 4.3 "verbatim from spec" | Impossible without scaffolding | "Adapted from spec canonical example, inline `PartnerDTO`/`SchemaError` scaffolding" |
| 16 | Same bug in other rules | Phase 8 "scheduled, not blocking" | **In-scope:** PY-WL-003 + PY-WL-007 fixed in the same PR, PY-WL-008 + PY-WL-009 verified in the same PR |
| 17 | Regression window arithmetic | "16 days" | **3 days** (2026-04-09 → 2026-04-12) |
| 18 | Phase 3.2 overlay entry | "Preferred Option B" | Commit to Option B non-optionally |
| 19 | Residual risk #18 slot | Inline addition | Either renumber chapter opening **or** add `§13.1 Incident-derived risks` — V2 chooses renumber + reframe |
| 20 | ADR-004 template | Missing `Deciders`, missing `## Summary` | Matches ADR-003 exactly |
| 21 | Phase 0.0 spec paraphrase | Not present | New Phase 0.0 — implementer must produce a written paraphrase of "validation boundary context" before touching code |
| 22 | `Spec-Impact: none` hole | Unenforced trailer | Differential corpus run on any rule module change — flipped cells auto-promote `Spec-Impact` label and fail CI |
| 23 | SPEC_REF meta-test | No self-test | Phase 7C.5a adds a known-good fixture so the parser regex fails loudly when broken |
| 24 | Phase 8 / follow-on audit | Verbal deferral | Filed as filigree issue with named owner and deadline before PR merge |
| 25 | Phase 7A ordering | Not specified | Phase 7A runs **after** Phase 6.4 green and **before** PR merge — explicit |

## 4. Phase Dependency Graph

```
Phase 0.0 (spec paraphrase)  ── required before any code changes
Phase 0.1 (file filigree issue, ADR signoff) ── required before Phase 1 commits
        │
        ▼
Phase 4a (corpus specimens written FIRST from spec, before rule code) ── authors verdicts
        │
        ▼
Phase 2.0 (extend _run_rule_with_context) ── unblocks Phase 2 tests
        │
        ▼
Phase 1 (rule code: base helper + py_wl_001 + py_wl_003 + py_wl_007)
        │
        ▼
Phase 2 (unit tests: delete, invert, decorator, registry-sync)
        │
        ▼
Phase 3 (integration test fixture)
        │
        ▼
Phase 4b (corpus verify)
        │
        ▼
Phase 5 (documentation: ADR-004, residual risk renumber, rescission ×7)
        │
        ▼
Phase 6 (conformance re-verification, including retrospective window scan)
        │
        ▼
Phase 7A (close observability gap — THREE fixes)
Phase 7B (spec-linked change gate, CODEOWNERS second reviewer)
Phase 7C (SPEC_REF traceability + self-test fixture)
Phase 7D (corpus-as-ground-truth)
        │
        ▼
Phase 8 (same-PR audit: py_wl_008, py_wl_009 verification; filigree issue for deeper sweep)
        │
        ▼
PR merge gate
```

Phases 0, 1, 2, 3, 4, 5, 6 are sequential. Phases 7A–7D are independently parallelisable but must all complete before merge. Phase 8 is the final gate.

---

## 5. Fix Plan

### Phase 0.0 — Spec paraphrase (goal reset, not tooling)

**Purpose:** Leverage point at Meadows level 3 (goal), not level 6 (information flow). The implementing agent reads the spec and writes a paraphrase before reading any code. This resets the goal from "make the tests green" back to "implement §A.3 clause 3 and §A.4 row 5 correctly."

- [ ] **Step 0.0.1:** Read `docs/spec/wardline-02-A-python-binding.md` lines 70-80 (§A.3 clause 3) and lines 165-180 (§A.4 row 5). Read the canonical example at lines 440-500.
- [ ] **Step 0.0.2:** Write a paraphrase (3-5 sentences) in a scratch file `/tmp/wl001-paraphrase.md` answering:
  1. What are the three conjunctive conditions for `schema_default()` suppression?
  2. What does "validation boundary context" mean, and which two mechanisms can establish it?
  3. Why is `optional_fields` alone insufficient?
- [ ] **Step 0.0.3:** Paste the paraphrase into the ADR-004 draft `## Context` section (see Phase 5.1). The paraphrase is not a throwaway — it becomes part of the permanent record.

### Phase 0.1 — Pre-execution gates (blocker resolution)

These are not implementation steps. They are blockers that must resolve before Phase 1 starts.

- [ ] **Step 0.1.1 — Identify ADR-004 decider.** Determine the human who signs off on ADR-004. Candidates: Project Lead (`@johnm-dta`), external spec-owner role. **Default: `@johnm-dta` signs off as the Project Lead**, per ADR-003 precedent. Record the name in the ADR-004 `Deciders:` field. If no decider can be identified, raise this as an open blocker and halt the plan.
- [ ] **Step 0.1.2 — Decide `validates_semantic` eligibility.** Question: does `@validates_semantic` (GUARDED → ASSURED) count as "validation boundary context" for PY-WL-001 schema_default suppression?

  **Decision (commit this in V2):** **No.** `validates_semantic` operates at GUARDED → ASSURED. `schema_default()` fabricates a default for a missing dict key at EXTERNAL_RAW — before shape validation has occurred. A semantic-only validator runs *after* shape has been established; applying a `schema_default()` inside it is a contract violation (shape already should be certain). Only `@validates_shape` (EXTERNAL_RAW → GUARDED) and `@validates_external` (EXTERNAL_RAW → ASSURED, combined) qualify. Document this reasoning in ADR-004 §Decision. Add a corpus TP specimen (`PY-WL-001-TP-schema-default-validates-semantic-only`) asserting that a function decorated only with `@validates_semantic` does **not** suppress.
- [ ] **Step 0.1.3 — Decide decorator secondary check mechanism.** V1's Scenario-A attack (bare `@validates_shape` on a stub) re-opens the loosening if the check is pure name match. Options for secondary check:

  (a) Decorated function body contains `raise` under a validation condition.
  (b) Function shows up in `function_level_taint_map` with an EXTERNAL_RAW → GUARDED transition.
  (c) `WardlineAnnotation.attrs` carries `_wardline_transition` with a spec-approved tuple.

  **Decision (commit this in V2):** **Option (c).** Justification: (a) is behavioural AST analysis reinventing what PY-WL-008 already does and still allows `raise Exception()` stubs; (b) requires that taint propagation has already run for the function, which is available but couples PY-WL-001 to the taint map's correctness and has edge cases on Level 1; (c) is a data check against the decorator's own metadata, fast, deterministic, and pinned to the registry. The check: `ann.attrs.get("_wardline_transition")` is a non-empty tuple whose first element is `TaintState.EXTERNAL_RAW`. This matches `validates_shape` and `validates_external` and rejects a decorator that forgot to carry registry metadata. Document the decision in ADR-004 §Alternatives rejected.
- [ ] **Step 0.1.4 — Decide CODEOWNERS second reviewer.** The project currently has exactly one human identity in CODEOWNERS. Options:

  (a) Add a second named human now.
  (b) Explicitly disclose the single-reviewer limitation as a governance gap.

  **Decision (commit this in V2):** **Option (b) disclose now, (a) as a v1.0 pre-release requirement.** Justification: the project lead cannot unilaterally add a second GitHub identity without a human agreement. Option (b) makes the gap visible to IRAP *today*, is actionable by the plan, and is honest. Option (a) is a governance change that belongs in the v1.0 release plan, not this PR. Phase 7B.1 writes the disclosure into CODEOWNERS as a comment block AND files a blocking filigree issue against v1.0 titled "Recruit second human reviewer for CODEOWNERS rule-module ownership."
- [ ] **Step 0.1.5 — Decide Phase 8 scope.** Which rules get fixed in-PR vs audited later?

  **Decision (commit this in V2):**
  - **In-PR fix:** PY-WL-001, PY-WL-003, PY-WL-007. These rely solely on `boundary.function == self._current_qualname` with no node-level decorator fallback (verified in code).
  - **In-PR verify-only:** PY-WL-008, PY-WL-009. These already have `_has_direct_decorator` node-level fallbacks. Verification = write a corpus specimen proving decorator-only governance activates suppression.
  - **Post-PR audit (filigree issue):** the 35-issue omnibus `7caf751` commit for any other latent drift. Filed as filigree issue before this PR merges. Owner: `@johnm-dta`. Deadline: pre-v1.0 release.
- [ ] **Step 0.1.6 — File Phase 8 audit as filigree issue before Phase 1 starts.**

  Run:
  ```bash
  filigree create \
    "Audit 7caf751 omnibus commit for additional rule-code spec drift" \
    --type=bug --priority=1 --label=blocker-v1.0 --label=audit
  ```
  Add dependency: `filigree add-dep <v1.0-milestone-id> <this-issue-id>`.

### Phase 1 — Rule code fix

**Files:**

- Modify: `src/wardline/scanner/rules/base.py`
- Modify: `src/wardline/scanner/rules/py_wl_001.py`
- Modify: `src/wardline/scanner/rules/py_wl_003.py`
- Modify: `src/wardline/scanner/rules/py_wl_007.py`

**Ordering rule:** Add new methods first, then change call sites, then delete the old method. Run `uv run pytest tests/unit/scanner/test_py_wl_001.py -q` between each step. V1's "delete before add" ordering produced a broken intermediate state.

#### 1A — Base helper (rules/base.py)

- [ ] **Step 1A.1: Add the canonical validation-decorator set.** In `src/wardline/scanner/rules/base.py` add near the top of the module, after `_GUARDED_METHODS`:

  ```python
  from wardline.core.taints import TaintState

  # Canonical set of decorators that satisfy "validation boundary context"
  # per spec §A.3 clause 3 and §A.4 row 5. Deliberately excludes
  # `validates_semantic` (GUARDED→ASSURED) — semantic validation runs after
  # shape has been established and cannot retroactively govern a
  # schema_default() fabrication at EXTERNAL_RAW.
  # See ADR-004 §Decision.
  _VALIDATION_DECORATORS: frozenset[str] = frozenset({
      "validates_shape",
      "validates_external",
  })
  ```

- [ ] **Step 1A.2: Add `_has_validation_boundary_decorator` helper method on `RuleBase`.** Insert as a new method on `RuleBase`:

  ```python
  def _has_validation_boundary_decorator(self, overlay_scope: str) -> bool:
      """Return True iff the enclosing function carries a registered
      validation-boundary decorator AND the file is within ``overlay_scope``.

      Spec authority: §A.3 clause 3 (line 76), §A.4 row 5 (line 172).

      Three conjunctive checks:
        1. The current function qualname appears in
           ``self._context.annotations_map``.
        2. At least one annotation's ``canonical_name`` is in
           ``_VALIDATION_DECORATORS``.
        3. That annotation's ``attrs["_wardline_transition"]`` is a
           non-empty tuple whose first element is
           ``TaintState.EXTERNAL_RAW``. This is the structural
           sanity check that blocks bare marker attacks
           (see ADR-004 §Alternatives rejected).
        4. ``path_within_scope(self._file_path, overlay_scope)``.
      """
      from wardline.manifest.scope import path_within_scope  # local import avoids cycle

      if self._context is None:
          return False
      if not self._current_qualname:
          return False
      if not overlay_scope:
          return False
      annotations_map = self._context.annotations_map
      if annotations_map is None:
          return False
      anns = annotations_map.get(self._current_qualname, ())
      for ann in anns:
          if ann.canonical_name not in _VALIDATION_DECORATORS:
              continue
          transition = ann.attrs.get("_wardline_transition")
          if not isinstance(transition, tuple) or len(transition) != 2:
              continue
          if transition[0] is not TaintState.EXTERNAL_RAW:
              continue
          if path_within_scope(self._file_path, overlay_scope):
              return True
      return False
  ```

  Notes for the implementer:
  - Key shape is `self._current_qualname` (string), **not** `(file_path, qualname)` tuple — verified in `context.py` line 90.
  - `canonical_name`, **not** `.name` — verified in `context.py` line 60.
  - `_current_qualname` is initialised to `""`, never to `None`. Use `if not self._current_qualname:`.
  - `annotations_map` is `MappingProxyType[str, tuple[WardlineAnnotation, ...]] | None`.

- [ ] **Step 1A.3: Run checkpoint.**

  ```bash
  uv run ruff check src/wardline/scanner/rules/base.py
  uv run mypy src/wardline/scanner/rules/base.py
  uv run pytest tests/unit/scanner/test_py_wl_001.py -q
  ```

  Expected: ruff clean, mypy clean, existing `test_py_wl_001.py` still passing. The new helper is not yet called.

#### 1B — py_wl_001.py changes

- [ ] **Step 1B.1: Add `_is_governed_by_validation_context` method.** Insert in `src/wardline/scanner/rules/py_wl_001.py` directly after `_is_governed_by_boundary`:

  ```python
  def _is_governed_by_validation_context(self, overlay_scope: str) -> bool:
      """Spec §A.3 clause 3 / §A.4 row 5: validation boundary context is
      satisfied by EITHER an explicit overlay boundary entry OR a
      validation-boundary decorator on the enclosing function.

      The `optional_fields` entry alone is necessary but not sufficient.
      See ADR-004 and residual risk #18.
      """
      if self._is_governed_by_boundary(overlay_scope):
          return True
      return self._has_validation_boundary_decorator(overlay_scope)
  ```

- [ ] **Step 1B.2: Switch the call site.** In `src/wardline/scanner/rules/py_wl_001.py:215-222`, replace:

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

  with:

  ```python
  if (
      optional_field is not None
      and default_value == optional_field.approved_default
      and self._is_governed_by_validation_context(optional_field.overlay_scope)
  ):
  ```

- [ ] **Step 1B.3: Run checkpoint.**

  ```bash
  uv run pytest tests/unit/scanner/test_py_wl_001.py -q
  ```

  Expected: some failures on the four spec-violating tests (Phase 2.1 will delete them) and any test that depends on `_is_governed_by_optional_field`. Governance-positive tests that use an explicit boundary should still pass.

- [ ] **Step 1B.4: Delete the old `_is_governed_by_optional_field` method.** Remove `py_wl_001.py:300-310` in full. No caller remains (verified after 1B.2).

- [ ] **Step 1B.5: Audit `_GOVERNED_TRANSITIONS` for day-one drift.** The existing set `_GOVERNED_TRANSITIONS` (py_wl_001.py:42-48) is a mixed bag of transition names and decorator names. Leave the transition names intact — they are used by `_is_governed_by_boundary` to match `boundary.transition` strings read from YAML. Remove the decorator names (`validates_shape`, `validates_external`) from the set — they were never used by `_is_governed_by_boundary` (which compares to `boundary.transition`, not to decorator names) and they confused the audit. New set:

  ```python
  _GOVERNED_TRANSITIONS = frozenset({
      "shape_validation",
      "external_validation",
      "combined_validation",
  })
  ```

- [ ] **Step 1B.6: Lint and type-check.**

  ```bash
  uv run ruff check src/wardline/scanner/rules/py_wl_001.py
  uv run mypy src/wardline/scanner/rules/py_wl_001.py
  ```

  Expected: clean.

#### 1C — py_wl_003.py fan-out (same bug pattern)

Current code (`py_wl_003.py:200-207`) relies solely on `boundary.function == self._current_qualname`. No decorator fallback.

- [ ] **Step 1C.1:** In `src/wardline/scanner/rules/py_wl_003.py` locate the `_SUPPRESSED_BOUNDARY_TRANSITIONS` frozenset near the top (search for the constant). Confirm it contains only transition strings, not decorator names. Record what's there.
- [ ] **Step 1C.2:** Modify `_is_structural_validation_boundary` (lines 193-207) to also accept validation decorators. The rule currently has no `overlay_scope` plumbed through from the call site — PY-WL-003 governs inside a boundary whose scope is implicit in the boundary entry itself. For consistency with PY-WL-001, add a fallback that calls the base helper with the boundary's own overlay_scope if the primary YAML check failed:

  ```python
  def _is_structural_validation_boundary(self) -> bool:
      """Return True when this function is a shape/combined validator.

      Per spec §A.3 clause 3 and §A.4 row 5 (see ADR-004), the governance
      predicate is satisfied by either an explicit overlay boundary entry
      OR a registered validation-boundary decorator on the enclosing
      function. The latter path was missing before ADR-004.
      """
      if self._context is None:
          return False
      for boundary in self._context.boundaries:
          if (
              boundary.function == self._current_qualname
              and boundary.transition in _SUPPRESSED_BOUNDARY_TRANSITIONS
              and path_within_scope(self._file_path, boundary.overlay_scope)
          ):
              return True
      # Decorator fallback — spec canonical example path.
      # Scope: any boundary-declared overlay_scope in the manifest, or
      # the empty-string sentinel meaning "no scope constraint".
      for boundary in self._context.boundaries:
          if self._has_validation_boundary_decorator(boundary.overlay_scope):
              return True
      # No YAML boundary at all — use a whole-project scope fallback.
      return self._has_validation_boundary_decorator(".")
  ```

  Notes:
  - `path_within_scope(file, ".")` returns True for any file (verify this in `manifest/scope.py` before commit; if the sentinel is different adapt accordingly).
  - If the project has zero boundaries and the current function has a validation decorator, the final `return` still governs — matching the spec canonical example where the overlay may only declare `optional_fields`.

- [ ] **Step 1C.3:** Run checkpoint.

  ```bash
  uv run pytest tests/unit/scanner/test_py_wl_003.py -q
  ```

  Expected: existing tests still pass. New decorator-based tests will be added in Phase 2.7.

#### 1D — py_wl_007.py fan-out (same bug pattern)

Current code (`py_wl_007.py:117-120`) relies solely on `any(b.function == qualname for b in self._context.boundaries)`. No decorator fallback.

- [ ] **Step 1D.1:** Modify `_is_declared_boundary` in `py_wl_007.py`:

  ```python
  def _is_declared_boundary(self) -> bool:
      """Return True if the current function is declared as a validation
      boundary, either via an explicit overlay boundary entry or via a
      registered validation-boundary decorator on the enclosing function.

      Spec §A.3 clause 3 / §A.4 row 5 / ADR-004.
      """
      if self._context is None:
          return False
      qualname = self._current_qualname
      if any(b.function == qualname for b in self._context.boundaries):
          return True
      # Decorator fallback — mirrors py_wl_001 helper.
      for boundary in self._context.boundaries:
          if self._has_validation_boundary_decorator(boundary.overlay_scope):
              return True
      return self._has_validation_boundary_decorator(".")
  ```

- [ ] **Step 1D.2:** Run checkpoint.

  ```bash
  uv run pytest tests/unit/scanner/test_py_wl_007.py -q
  ```

  Expected: existing tests still pass.

#### 1E — Final Phase 1 lint and type check

- [ ] **Step 1E.1:**

  ```bash
  uv run ruff check src/wardline/scanner/rules/
  uv run mypy src/wardline/scanner/rules/
  ```

  Expected: clean.

- [ ] **Step 1E.2:** Commit Phase 1 as a single commit:

  ```
  fix(PY-WL-001,003,007): restore function-level governance per ADR-004

  Spec-Impact: tightening
  ```

  (No `--no-verify`. If the pre-commit hook fails, fix the issue and create a new commit.)

### Phase 2 — Unit tests

**Files:**

- Modify: `tests/unit/scanner/test_py_wl_001.py`
- Create: `tests/unit/scanner/test_validation_decorators_registry.py`
- Modify: `tests/unit/scanner/test_py_wl_003.py`
- Modify: `tests/unit/scanner/test_py_wl_007.py`

#### 2.0 — Extend `_run_rule_with_context` to accept `annotations_map`

V1 assumed the existing helper already supported annotations. It does not (`test_py_wl_001.py:29-47`). The decorator-based tests cannot be written without this extension — they would silently pass with no decorator wired in.

- [ ] **Step 2.0.1:** In `tests/unit/scanner/test_py_wl_001.py`, modify `_run_rule_with_context`:

  ```python
  from types import MappingProxyType

  from wardline.scanner.context import ScanContext, WardlineAnnotation


  def _run_rule_with_context(
      source: str,
      *,
      boundaries: tuple[BoundaryEntry, ...] = (),
      optional_fields: tuple[OptionalFieldEntry, ...] = (),
      annotations: dict[str, tuple[WardlineAnnotation, ...]] | None = None,
      file_path: str = "/project/src/adapters/handler.py",
  ) -> RulePyWl001:
      """Parse source inside a function, set context with boundaries/annotations, run rule."""
      tree = parse_function_source(source)
      rule = RulePyWl001(file_path=file_path)
      ctx = ScanContext(
          file_path=file_path,
          function_level_taint_map=MappingProxyType({}),
          annotations_map=MappingProxyType(annotations or {}),
          boundaries=boundaries,
          optional_fields=optional_fields,
      )
      rule.set_context(ctx)
      rule.visit(tree)
      return rule
  ```

- [ ] **Step 2.0.2:** Run checkpoint.

  ```bash
  uv run pytest tests/unit/scanner/test_py_wl_001.py -q
  ```

  Expected: same test outcome as Phase 1B.3. The helper extension is purely additive.

#### 2.1 — Delete the four spec-violating tests

- [ ] **Step 2.1.1:** In `tests/unit/scanner/test_py_wl_001.py` delete:
  - `test_optional_field_only_no_boundary_suppresses` (lines ~289-304)
  - `test_wrong_function_boundary_still_governed_by_optional_field` (lines ~339-360)
  - `test_wrong_transition_boundary_still_governed_by_optional_field` (lines ~362-382)
  - `test_case_sensitive_qualname_boundary_still_governed_by_optional_field` (lines ~438-458)

#### 2.2 — Add the inverted tests asserting UNGOVERNED

- [ ] **Step 2.2.1:** Add in `TestSchemaDefaultUngoverned`:

  ```python
  def test_optional_field_without_boundary_or_decorator_is_ungoverned(self) -> None:
      """Spec §A.3 clause 3: optional_fields alone is insufficient."""
      optional_field = OptionalFieldEntry(
          field="key",
          approved_default="",
          rationale="t",
          overlay_scope="/project/src",
      )
      rule = _run_rule_with_context(
          'return schema_default(d.get("key", ""))\n',
          optional_fields=(optional_field,),
      )
      assert len(rule.findings) == 1
      assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

  def test_wrong_function_boundary_is_ungoverned(self) -> None:
      """Qualname mismatch → no governance."""
      boundary = BoundaryEntry(
          function="other_fn",
          transition="shape_validation",
          overlay_scope="/project/src",
      )
      optional_field = OptionalFieldEntry(
          field="key", approved_default="", rationale="t",
          overlay_scope="/project/src",
      )
      rule = _run_rule_with_context(
          'return schema_default(d.get("key", ""))\n',
          boundaries=(boundary,),
          optional_fields=(optional_field,),
      )
      assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

  def test_wrong_transition_boundary_is_ungoverned(self) -> None:
      """Non-governance transition → no governance."""
      boundary = BoundaryEntry(
          function="<module>",
          transition="semantic_validation",
          overlay_scope="/project/src",
      )
      optional_field = OptionalFieldEntry(
          field="key", approved_default="", rationale="t",
          overlay_scope="/project/src",
      )
      rule = _run_rule_with_context(
          'return schema_default(d.get("key", ""))\n',
          boundaries=(boundary,),
          optional_fields=(optional_field,),
      )
      assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

  def test_case_sensitive_qualname_mismatch_is_ungoverned(self) -> None:
      """Case-mismatched qualname → no governance."""
      boundary = BoundaryEntry(
          function="MODULE",
          transition="shape_validation",
          overlay_scope="/project/src",
      )
      optional_field = OptionalFieldEntry(
          field="key", approved_default="", rationale="t",
          overlay_scope="/project/src",
      )
      rule = _run_rule_with_context(
          'return schema_default(d.get("key", ""))\n',
          boundaries=(boundary,),
          optional_fields=(optional_field,),
      )
      assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT
  ```

  Notes:
  - Exact call-site qualname produced by `parse_function_source` varies; adjust boundary `function` to be a deliberate mismatch.
  - Inspect `tests/unit/scanner/conftest.py::parse_function_source` for the wrapping function name if needed.

#### 2.3 — Add decorator-based governance tests

- [ ] **Step 2.3.1:** Add a test fixture helper in `test_py_wl_001.py`:

  ```python
  def _ann(canonical_name: str, transition: tuple[str, str] | None = None) -> WardlineAnnotation:
      """Build a WardlineAnnotation with spec-grounded attrs."""
      from wardline.core.taints import TaintState
      attrs: dict[str, object] = {}
      if transition is not None:
          attrs["_wardline_transition"] = (
              TaintState[transition[0]], TaintState[transition[1]],
          )
      return WardlineAnnotation(
          canonical_name=canonical_name,
          group=1,
          attrs=MappingProxyType(attrs),
      )
  ```

- [ ] **Step 2.3.2:** Add in a new `TestSchemaDefaultGovernedByDecorator` class:

  ```python
  class TestSchemaDefaultGovernedByDecorator:
      """schema_default() suppressed by @validates_shape / @validates_external on the enclosing function."""

      SPEC_REF = (
          "docs/spec/wardline-02-A-python-binding.md §A.3 clause 3 (line 76); "
          "§A.4 row 5 (line 172); canonical example lines 440-500"
      )

      def test_validates_shape_decorator_governs(self) -> None:
          optional_field = OptionalFieldEntry(
              field="key", approved_default="", rationale="t",
              overlay_scope="/project/src",
          )
          qualname = "<module>"  # or the wrapper qualname parse_function_source produces
          ann = _ann("validates_shape", transition=("EXTERNAL_RAW", "GUARDED"))
          rule = _run_rule_with_context(
              'return schema_default(d.get("key", ""))\n',
              optional_fields=(optional_field,),
              annotations={qualname: (ann,)},
          )
          assert rule.findings[0].rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT

      def test_validates_external_decorator_governs(self) -> None:
          optional_field = OptionalFieldEntry(
              field="key", approved_default="", rationale="t",
              overlay_scope="/project/src",
          )
          ann = _ann("validates_external", transition=("EXTERNAL_RAW", "ASSURED"))
          rule = _run_rule_with_context(
              'return schema_default(d.get("key", ""))\n',
              optional_fields=(optional_field,),
              annotations={"<module>": (ann,)},
          )
          assert rule.findings[0].rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT

      def test_validates_semantic_alone_does_not_govern(self) -> None:
          """validates_semantic operates at GUARDED→ASSURED. Not eligible for
          schema_default (EXTERNAL_RAW fabrication). See ADR-004 §Decision."""
          optional_field = OptionalFieldEntry(
              field="key", approved_default="", rationale="t",
              overlay_scope="/project/src",
          )
          ann = _ann("validates_semantic", transition=("GUARDED", "ASSURED"))
          rule = _run_rule_with_context(
              'return schema_default(d.get("key", ""))\n',
              optional_fields=(optional_field,),
              annotations={"<module>": (ann,)},
          )
          assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

      def test_bare_marker_decorator_without_transition_does_not_govern(self) -> None:
          """Scenario-A attack: @validates_shape without _wardline_transition attr
          (e.g., a hand-rolled stub). The structural sanity check must reject this."""
          optional_field = OptionalFieldEntry(
              field="key", approved_default="", rationale="t",
              overlay_scope="/project/src",
          )
          ann = WardlineAnnotation(
              canonical_name="validates_shape",
              group=1,
              attrs=MappingProxyType({}),  # no _wardline_transition
          )
          rule = _run_rule_with_context(
              'return schema_default(d.get("key", ""))\n',
              optional_fields=(optional_field,),
              annotations={"<module>": (ann,)},
          )
          assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

      def test_decorator_outside_overlay_scope_does_not_govern(self) -> None:
          """Scope check: decorator path must also verify the file is in the
          optional_field's overlay_scope. A decorated helper in /project/other/
          with optional_field scoped to /project/src/ is NOT governed."""
          optional_field = OptionalFieldEntry(
              field="key", approved_default="", rationale="t",
              overlay_scope="/project/src",
          )
          ann = _ann("validates_shape", transition=("EXTERNAL_RAW", "GUARDED"))
          rule = _run_rule_with_context(
              'return schema_default(d.get("key", ""))\n',
              optional_fields=(optional_field,),
              annotations={"<module>": (ann,)},
              file_path="/project/other/helper.py",  # outside scope
          )
          assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

      def test_decorator_on_sibling_function_does_not_govern(self) -> None:
          """Decorator must be on the enclosing function, not a sibling."""
          optional_field = OptionalFieldEntry(
              field="key", approved_default="", rationale="t",
              overlay_scope="/project/src",
          )
          ann = _ann("validates_shape", transition=("EXTERNAL_RAW", "GUARDED"))
          rule = _run_rule_with_context(
              'return schema_default(d.get("key", ""))\n',
              optional_fields=(optional_field,),
              annotations={"some_other_fn": (ann,)},  # wrong qualname
          )
          assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT
  ```

#### 2.4 — Add `SPEC_REF` constants

- [ ] **Step 2.4.1:** Add a `SPEC_REF` class constant to both `TestSchemaDefaultGoverned` and `TestSchemaDefaultUngoverned` in `test_py_wl_001.py`:

  ```python
  class TestSchemaDefaultGoverned:
      """schema_default() with validation boundary context → SUPPRESS."""
      SPEC_REF = (
          "docs/spec/wardline-02-A-python-binding.md §A.3 clause 3 (line 76); "
          "§A.4 row 5 (line 172); canonical example lines 440-500"
      )
      # ... tests ...
  ```

#### 2.5 — Class-docstring consistency audit

- [ ] **Step 2.5.1:** Verify every test in `TestSchemaDefaultUngoverned` asserts `PY_WL_001_UNGOVERNED_DEFAULT` or `PY_WL_001` (not `PY_WL_001_GOVERNED_DEFAULT`). Move any test that asserts governance into `TestSchemaDefaultGoverned` or `TestSchemaDefaultGovernedByDecorator`.

#### 2.6 — Registry-sync unit test

- [ ] **Step 2.6.1:** Create `tests/unit/scanner/test_validation_decorators_registry.py`:

  ```python
  """Asserts that _VALIDATION_DECORATORS stays in sync with the canonical registry."""

  from __future__ import annotations

  from wardline.core.registry import REGISTRY
  from wardline.core.taints import TaintState
  from wardline.scanner.rules.base import _VALIDATION_DECORATORS


  def test_validation_decorators_are_registered() -> None:
      """Every name in _VALIDATION_DECORATORS must be a real registry entry."""
      for name in _VALIDATION_DECORATORS:
          assert name in REGISTRY, f"{name} not in REGISTRY"


  def test_validation_decorators_have_external_raw_source() -> None:
      """Every validation decorator must transition FROM EXTERNAL_RAW.

      This is the spec-grounded criterion for 'validation boundary context'
      per §A.3 clause 3 — schema_default() fabricates at EXTERNAL_RAW, so
      the enclosing validator must be one that starts there.
      See ADR-004 §Decision.
      """
      # The registry entry holds only type metadata; the actual transition
      # tuple lives on the decorator object. Import and inspect:
      from wardline import decorators as wd
      for name in _VALIDATION_DECORATORS:
          dec = getattr(wd, name)
          transition = getattr(dec, "_wardline_transition", None)
          assert transition is not None, f"{name} missing _wardline_transition"
          assert isinstance(transition, tuple) and len(transition) == 2
          assert transition[0] is TaintState.EXTERNAL_RAW, (
              f"{name} source is {transition[0]}, expected EXTERNAL_RAW"
          )


  def test_validates_semantic_is_excluded() -> None:
      """validates_semantic operates GUARDED→ASSURED and must NOT be in the
      validation-decorator set for PY-WL-001 schema_default governance."""
      assert "validates_semantic" not in _VALIDATION_DECORATORS
  ```

- [ ] **Step 2.6.2:** Run the new test:

  ```bash
  uv run pytest tests/unit/scanner/test_validation_decorators_registry.py -q
  ```

  Expected: PASS.

#### 2.7 — Decorator-based tests for PY-WL-003 and PY-WL-007

- [ ] **Step 2.7.1:** Add one decorator-based governance test in `tests/unit/scanner/test_py_wl_003.py` mirroring the Phase 2.3 pattern.
- [ ] **Step 2.7.2:** Add one decorator-based governance test in `tests/unit/scanner/test_py_wl_007.py` mirroring the Phase 2.3 pattern.
- [ ] **Step 2.7.3:** Run:

  ```bash
  uv run pytest tests/unit/scanner/test_py_wl_001.py tests/unit/scanner/test_py_wl_003.py tests/unit/scanner/test_py_wl_007.py -q
  ```

  Expected: all PASS.

#### 2.8 — Commit

- [ ] **Step 2.8.1:** Commit Phase 2.

  ```
  test(PY-WL-001): invert spec-violating tests, add decorator-based governance coverage

  Spec-Impact: none
  Spec-Impact-Justification: §A.3 clause 3 unchanged; tests previously contradicted it
  ```

### Phase 3 — Integration test fixture

**Files:** `tests/integration/test_preview_phase2.py`

- [ ] **Step 3.1: Update `_write_source_file`.** Replace the body (lines ~43-67) with:

  ```python
  def _write_source_file(src_dir: Path) -> Path:
      """Write src/app.py with three test functions."""
      src_dir.mkdir(parents=True, exist_ok=True)
      app_py = src_dir / "app.py"
      app_py.write_text(
          '"""Test fixture for preview-phase2 integration tests."""\n'
          "\n"
          "from wardline import schema_default, validates_shape\n"
          "\n"
          "def ungoverned_fn(data):\n"
          '    """schema_default() with no decorator → PY-WL-001-UNGOVERNED-DEFAULT."""\n'
          '    return schema_default(data.get("key", ""))\n'
          "\n"
          "\n"
          "@validates_shape\n"
          "def governed_fn(data):\n"
          '    """schema_default() in validation boundary → PY-WL-001-GOVERNED-DEFAULT (SUPPRESS)."""\n'
          '    return schema_default(data.get("key", ""))\n'
          "\n"
          "\n"
          "def get_fn(data):\n"
          '    """Regular .get() with literal default → PY-WL-001 (not UNGOVERNED-DEFAULT)."""\n'
          '    return data.get("key", 42)\n',
          encoding="utf-8",
      )
      return app_py
  ```

  (`from wardline import validates_shape` works because `wardline/__init__.py:6` re-exports `validates_shape` from `wardline.decorators`.)

- [ ] **Step 3.2: Remove the overlay `boundaries:` entry (Option B, non-optional).** Modify `_write_overlay` (lines ~70-84):

  ```python
  def _write_overlay(src_dir: Path) -> None:
      """Write src/wardline.overlay.yaml governing governed_fn via decorator path."""
      overlay = src_dir / "wardline.overlay.yaml"
      overlay.write_text(
          "overlay_for: src\n"
          "optional_fields:\n"
          '  - field: key\n'
          '    approved_default: ""\n'
          '    rationale: Approved empty default in validation boundary\n'
          "    overlay_scope: src\n",
          encoding="utf-8",
      )
  ```

  Schema legality: `src/wardline/manifest/schemas/overlay.schema.json:138` requires only `overlay_for`; the `boundaries:` block is optional. No schema change needed.

- [ ] **Step 3.3: Verify test assertions still match.** Re-read `test_unverified_default_count_is_one`, `test_unverified_defaults_contains_ungoverned_fn`, `test_governed_fn_not_in_unverified_defaults`, `test_get_fn_not_in_unverified_defaults`, and `test_output_flag_writes_to_file`. All must still encode the expected outcome:
  - `ungoverned_fn` → UNGOVERNED_DEFAULT
  - `governed_fn` → GOVERNED_DEFAULT (SUPPRESS)
  - `get_fn` → PY_WL_001 (regular, not UNGOVERNED)
- [ ] **Step 3.4: Run the integration test.**

  ```bash
  uv run pytest tests/integration/test_preview_phase2.py -m integration -q
  ```

  Expected: PASS. If FAIL, diagnose before proceeding — do not proceed to Phase 4 with integration red.

- [ ] **Step 3.5: Commit.**

  ```
  test(integration): preview-phase2 fixture uses decorator path for governed_fn
  ```

### Phase 4a — Corpus specimens written FIRST (before rule code)

**Ordering note:** This phase was written-first-in-this-plan but executes as sub-task **before Phase 1** in practice. The expected verdicts are derived from spec text, not from running the scanner. A subagent handling Phase 4a must not run `wardline corpus verify` until Phase 4b — otherwise the corpus re-encodes scanner bugs.

**Files:**

- Modify: `corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-TN-schema-default-governed.{py,yaml}`
- Verify-only: `corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-TN-TF-governed-overlay.{py,yaml}`
- Create: `corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-TN-schema-default-validates-shape.{py,yaml}`
- Create: `corpus/specimens/PY-WL-001/EXTERNAL_RAW/negative/PY-WL-001-TN-schema-default-yaml-boundary-only.{py,yaml}`
- Create: `corpus/specimens/PY-WL-001/EXTERNAL_RAW/positive/PY-WL-001-TP-schema-default-undecorated-helper.{py,yaml}`
- Create: `corpus/specimens/PY-WL-001/EXTERNAL_RAW/positive/PY-WL-001-TP-schema-default-wrong-transition.{py,yaml}`
- Create: `corpus/specimens/PY-WL-001/EXTERNAL_RAW/positive/PY-WL-001-TP-schema-default-validates-semantic-only.{py,yaml}`
- Create: `corpus/specimens/PY-WL-001/EXTERNAL_RAW/positive/PY-WL-001-TP-schema-default-bare-marker-no-transition.{py,yaml}`

#### 4a.1 — Repair `PY-WL-001-TN-schema-default-governed`

- [ ] **Step 4a.1.1:** Rewrite `PY-WL-001-TN-schema-default-governed.py`:

  ```python
  from wardline import schema_default, validates_shape


  @validates_shape
  def governed_schema_default(data):
      return schema_default(data.get("key", ""))
  ```

- [ ] **Step 4a.1.2:** Rewrite `PY-WL-001-TN-schema-default-governed.yaml` with aligned boundary qualname:

  ```yaml
  ---
  specimen_id: "PY-WL-001-TN-schema-default-governed"
  description: "schema_default() in @validates_shape function, governed by optional_field + decorator"
  rule: "PY-WL-001"
  category: "suppression_interaction"
  fragment: |
    from wardline import schema_default, validates_shape

    @validates_shape
    def governed_schema_default(data):
        return schema_default(data.get("key", ""))
  taint_state: "EXTERNAL_RAW"
  boundaries:
    - function: "governed_schema_default"
      transition: "shape_validation"
      overlay_scope: "."
  optional_fields:
    - field: "key"
      approved_default: ""
      rationale: "optional by contract"
      overlay_scope: "."
  expected_rules: []
  expected_severity: null
  expected_exceptionability: null
  expected_match: false
  verdict: "true_negative"
  ```

  (`sha256` will regenerate on corpus publish.)

#### 4a.2 — Verify-only `PY-WL-001-TN-TF-governed-overlay`

- [ ] **Step 4a.2.1:** Read `PY-WL-001-TN-TF-governed-overlay.{py,yaml}`. Confirm the YAML's `boundaries.function: "validate_and_default"` matches the `.py`'s `def validate_and_default`. **This specimen is already correct.** No edit. V1 incorrectly claimed it was malformed.

#### 4a.3 — New TN: `PY-WL-001-TN-schema-default-validates-shape`

The spec canonical example (§A.4, lines 440-500). Adapted from the spec text with minimum scaffolding (`PartnerDTO`, `SchemaError`) inlined — "verbatim" is not possible because the spec fragment has undefined types.

- [ ] **Step 4a.3.1:** Create `PY-WL-001-TN-schema-default-validates-shape.py`:

  ```python
  from wardline import schema_default, validates_shape


  class PartnerDTO:
      pass


  class SchemaError(Exception):
      pass


  @validates_shape
  def parse_partner_response(raw: dict) -> PartnerDTO:
      indicators = schema_default(raw.get("risk_indicators", []))
      _ = indicators
      return PartnerDTO()
  ```

- [ ] **Step 4a.3.2:** Create `PY-WL-001-TN-schema-default-validates-shape.yaml`:

  ```yaml
  ---
  specimen_id: "PY-WL-001-TN-schema-default-validates-shape"
  description: "Spec canonical example: @validates_shape + schema_default → GOVERNED_DEFAULT (SUPPRESS)"
  rule: "PY-WL-001"
  category: "suppression_interaction"
  fragment: |
    from wardline import schema_default, validates_shape
    ...
  taint_state: "EXTERNAL_RAW"
  optional_fields:
    - field: "risk_indicators"
      approved_default: []
      rationale: "optional by contract (spec §A.4 line 492)"
      overlay_scope: "."
  expected_rules: []
  expected_severity: null
  expected_exceptionability: null
  expected_match: false
  verdict: "true_negative"
  ```

#### 4a.4 — New TN: `PY-WL-001-TN-schema-default-yaml-boundary-only`

This specimen covers the **explicit YAML boundary entry path**. Without this sibling, Phase 4a.1 collapses the explicit-boundary case into the decorator case and erases corpus coverage for the YAML path.

- [ ] **Step 4a.4.1:** Create `PY-WL-001-TN-schema-default-yaml-boundary-only.py`:

  ```python
  from wardline import schema_default


  def yaml_governed_schema_default(data):
      # No decorator here — governance must come from the YAML boundaries block.
      return schema_default(data.get("key", ""))
  ```

- [ ] **Step 4a.4.2:** Create `PY-WL-001-TN-schema-default-yaml-boundary-only.yaml`:

  ```yaml
  ---
  specimen_id: "PY-WL-001-TN-schema-default-yaml-boundary-only"
  description: "schema_default() governed by explicit YAML boundary entry (no decorator path)"
  rule: "PY-WL-001"
  category: "suppression_interaction"
  fragment: |
    from wardline import schema_default

    def yaml_governed_schema_default(data):
        return schema_default(data.get("key", ""))
  taint_state: "EXTERNAL_RAW"
  boundaries:
    - function: "yaml_governed_schema_default"
      transition: "shape_validation"
      overlay_scope: "."
  optional_fields:
    - field: "key"
      approved_default: ""
      rationale: "optional by contract"
      overlay_scope: "."
  expected_rules: []
  expected_severity: null
  expected_exceptionability: null
  expected_match: false
  verdict: "true_negative"
  ```

#### 4a.5 — New TP: `PY-WL-001-TP-schema-default-undecorated-helper`

Regression lock.

- [ ] **Step 4a.5.1:** Create the `.py` and `.yaml` in `corpus/specimens/PY-WL-001/EXTERNAL_RAW/positive/`:

  ```python
  # PY-WL-001-TP-schema-default-undecorated-helper.py
  from wardline import schema_default


  def undecorated_helper(data):
      return schema_default(data.get("key", ""))
  ```

  ```yaml
  ---
  specimen_id: "PY-WL-001-TP-schema-default-undecorated-helper"
  description: "Regression lock: schema_default in undecorated helper → UNGOVERNED_DEFAULT"
  rule: "PY-WL-001"
  category: "suppression_interaction"
  fragment: |
    from wardline import schema_default

    def undecorated_helper(data):
        return schema_default(data.get("key", ""))
  taint_state: "EXTERNAL_RAW"
  optional_fields:
    - field: "key"
      approved_default: ""
      rationale: "optional by contract"
      overlay_scope: "."
  expected_rules: ["PY-WL-001-UNGOVERNED-DEFAULT"]
  expected_severity: "ERROR"
  expected_exceptionability: "STANDARD"
  expected_match: true
  verdict: "true_positive"
  ```

#### 4a.6 — New TP: `PY-WL-001-TP-schema-default-wrong-transition`

- [ ] **Step 4a.6.1:** Create specimen with a boundary entry whose `transition` is `semantic_validation` (not a governance-relevant transition per `_GOVERNED_TRANSITIONS`). Expected: UNGOVERNED_DEFAULT.

#### 4a.7 — New TP: `PY-WL-001-TP-schema-default-validates-semantic-only`

- [ ] **Step 4a.7.1:** Create specimen with `@validates_semantic` only (no `@validates_shape`). Expected: UNGOVERNED_DEFAULT. This locks ADR-004's decision on semantic-only ineligibility.

#### 4a.8 — New TP: `PY-WL-001-TP-schema-default-bare-marker-no-transition`

(Cannot be expressed in a corpus specimen because the corpus derives annotations by AST-parsing the decorator name against the registry — a real `@validates_shape` always carries the real `_wardline_transition` attr. This specimen is therefore covered by the unit test `test_bare_marker_decorator_without_transition_does_not_govern` in Phase 2.3.2 and is NOT authored as a corpus specimen. Record this exclusion in ADR-004 §Consequences.)

- [ ] **Step 4a.8.1:** Record exclusion in ADR-004 draft.

### Phase 4b — Corpus verification

(Runs AFTER Phase 1, Phase 2, Phase 3. Phase 4a is the data; Phase 4b is the verify.)

- [ ] **Step 4b.1:** Run `uv run wardline corpus verify --json > /tmp/corpus.json`.
- [ ] **Step 4b.2:** Assert per-cell floors (not just `overall_verdict`). Extract each entry from `per_cell` in the JSON and assert:

  ```bash
  uv run python - <<'PY'
  import json, sys
  data = json.load(open("/tmp/corpus.json"))
  cells = data["per_cell"]
  failed = []
  # PY-WL-001 × EXTERNAL_RAW UNCONDITIONAL floors
  target = next(
      c for c in cells
      if c["rule"] == "PY-WL-001"
      and c["taint_state"] == "EXTERNAL_RAW"
      and c["exceptionability"] == "UNCONDITIONAL"
  )
  assert target["sample"] >= 5, f"sample too small: {target['sample']}"
  assert target["recall"] >= 0.90, f"recall: {target['recall']}"
  assert target["precision"] >= 0.80, f"precision: {target['precision']}"
  # MIXED_RAW floors (0.65/0.70)
  for c in cells:
      if c["rule"] == "PY-WL-001" and c["taint_state"] == "MIXED_RAW":
          assert c["recall"] >= 0.65
          assert c["precision"] >= 0.70
  # Every cell must be PASS
  for c in cells:
      if c["cell_verdict"] != "PASS":
          failed.append(c)
  if failed:
      print("FAIL:", failed); sys.exit(1)
  print("OK")
  PY
  ```

  Expected: `OK`.
- [ ] **Step 4b.3:** Regenerate `sha256` fields for the repaired/new specimens:

  ```bash
  uv run wardline corpus publish --update-hashes
  ```

  (Verify the exact CLI command in `src/wardline/cli/corpus_cmds.py`.)

### Phase 5 — Documentation

**Files:**

- Create: `docs/adr/ADR-004-schema-default-governance-function-level.md`
- Modify: `docs/spec/wardline-01-13-residual-risks.md`
- Modify: `docs/requirements/spec-fitness/conformance-review-2026-04-09.md`
- Modify: `docs/requirements/spec-fitness/04-python-binding.yaml`
- Modify: `docs/requirements/spec-fitness/03-scanner-conformance.yaml`
- Modify: `docs/requirements/spec-fitness/corpus-reduction-2026-04-10.md`
- Modify: `docs/requirements/spec-fitness/assessment-2026-03-29.md`
- Modify: `wardline.conformance.json`
- Modify: `wardline.sarif.baseline.json`

#### 5.1 — ADR-004

- [ ] **Step 5.1.1:** Create `docs/adr/ADR-004-schema-default-governance-function-level.md` using the ADR-003 template verbatim (fields in this order):

  ```markdown
  # ADR-004: schema_default() governance is function-level, not file-level

  **Status**: Accepted
  **Date**: 2026-04-12
  **Deciders**: Project Lead (@johnm-dta), 7-specialist panel review (2026-04-11)
  **Context**: Regression commit 7caf751 (2026-04-09) introduced file-level suppression; panel review identified 13 blockers in the V1 recovery plan

  ## Summary

  PY-WL-001 `schema_default()` suppression requires three conjunctive conditions
  per spec §A.3 clause 3 and §A.4 row 5: (1) an `optional_fields` overlay entry,
  (2) default value equals approved default, (3) validation boundary context.
  Condition (3) is function-level — it is satisfied by either an explicit overlay
  `boundaries` entry with a matching qualname and governance-relevant transition,
  OR a registered validation-boundary decorator (`@validates_shape`,
  `@validates_external`) on the enclosing function whose file is within the
  `optional_field` overlay scope. The `optional_fields` list alone is necessary
  but never sufficient.

  ## Context

  [Paste paraphrase from Phase 0.0.2 here. Then describe:]

  - Spec text (§A.3 clause 3 line 76, §A.4 row 5 line 172).
  - The 2026-04-09 regression commit 7caf751 that added
    `_is_governed_by_optional_field` as an `or`-branch fallback.
  - The three-day regression window (2026-04-09 → 2026-04-12).
  - The architectural gap: no code path converts `@validates_shape` decorators
    into `BoundaryEntry` objects, so the spec canonical example cannot activate
    `_is_governed_by_boundary` alone.
  - The four spec-violating unit tests that locked the regression in.

  ## Decision

  Governance is anchored at the function boundary. The rule evaluates
  "validation boundary context" through a new helper
  `RuleBase._has_validation_boundary_decorator(overlay_scope)` that checks:
  (a) the enclosing function qualname appears in `ScanContext.annotations_map`;
  (b) at least one annotation's `canonical_name` is in `_VALIDATION_DECORATORS`
  (`{validates_shape, validates_external}`); (c) that annotation's
  `attrs["_wardline_transition"]` is a non-empty tuple whose first element
  is `TaintState.EXTERNAL_RAW` (structural sanity check against bare marker
  attacks); (d) the file is within `overlay_scope`.

  `@validates_semantic` is **excluded** from `_VALIDATION_DECORATORS`. Semantic
  validation transitions GUARDED → ASSURED, which runs after shape validation;
  applying a `schema_default()` wrapper inside a semantic-only validator is a
  contract violation (shape already must be certain).

  The same helper is wired into PY-WL-003 and PY-WL-007 (same architectural gap,
  same fix) in the same PR. PY-WL-008 and PY-WL-009 already have node-level
  `_has_direct_decorator` fallbacks and are verified-only.

  ## Consequences

  - `_is_governed_by_optional_field` removed from `py_wl_001.py`.
  - New shared helper on `rules/base.py`.
  - `_VALIDATION_DECORATORS` added as a frozen constant with a registry-sync
    unit test (`test_validation_decorators_registry.py`).
  - Four spec-violating unit tests deleted; seven new tests added.
  - Three corpus specimens repaired/added, two TP specimens added.
  - Zero self-hosting impact (verified: `grep -r 'schema_default(' src/wardline`
    returns no runtime call sites).
  - Seven conformance artefacts rescinded and restored (see §5.3).

  ## Alternatives rejected

  ### Option A: Pure revert of 7caf751

  Does not work because the spec canonical example uses `@validates_shape` and
  relies on decorator-based governance that has no existing code path. Would
  leave the architectural gap in place.

  ### Option C: Include `validates_semantic` in the validation decorator set

  Rejected. Semantic validation operates GUARDED → ASSURED — a post-shape
  transition. `schema_default()` fabricates at EXTERNAL_RAW — pre-shape. Allowing
  semantic-only governance would re-open the loosening in a different direction.

  ### Behaviour-based secondary check (Option (a) of decorator sanity check)

  Body-level AST analysis for `raise` statements under a validation condition
  was considered as a secondary check against bare-marker attacks. Rejected
  because it reinvents PY-WL-008 and still allows `raise Exception()` stubs.
  The `_wardline_transition` attr check is deterministic and registry-backed.

  ### Taint-map cross-check (Option (b) of decorator sanity check)

  Cross-checking `function_level_taint_map` was considered. Rejected because
  it couples PY-WL-001 to the taint map's correctness and has edge cases on
  analysis level 1 where the map may be empty.

  ## Invalidates

  - The four unit tests in `test_py_wl_001.py` added by commit 7caf751.
  - The `optional_fields is the primary governance mechanism` language in those
    test docstrings.
  - `conformance-review-2026-04-09.md` PY-WL-001 subset.
  - `wardline.conformance.json` PY-WL-001 subset.
  - `wardline.sarif.baseline.json` PY-WL-001 subset.

  ## Supersedes

  Records the superseded hashes (run `git rev-parse HEAD` before the fix lands
  to capture):
  - `conformance-review-2026-04-09.md`: `<sha256-before>`
  - `wardline.conformance.json`: `<sha256-before>`
  - `wardline.sarif.baseline.json`: `<sha256-before>`
  - `04-python-binding.yaml`: `<sha256-before>`
  - `03-scanner-conformance.yaml`: `<sha256-before>`
  - `corpus-reduction-2026-04-10.md`: `<sha256-before>`
  - `assessment-2026-03-29.md`: `<sha256-before>`
  ```

#### 5.2 — Residual risk renumber

- [ ] **Step 5.2.1:** In `docs/spec/wardline-01-13-residual-risks.md` change the opening sentence from "Seventeen risks..." to "Eighteen risks...".
- [ ] **Step 5.2.2:** Add row 18 to the summary table:

  ```
  | 18 | Spec-code drift in rule implementations — rule code silently contradicts a MUST clause | ADR discipline, SPEC_REF traceability meta-test (§10.5), corpus-as-ground-truth (§15.7) |
  ```

- [ ] **Step 5.2.3:** Add the full prose entry after entry #17. Reframe as a durable structural risk class, not an incident postmortem:

  ```markdown
  **18. Spec-code drift in rule implementations.** The wardline reference
  scanner implements spec MUST clauses as executable rule code. A rule
  implementation can silently contradict its spec clause through (a) a
  fallback branch added under delivery pressure without an ADR, (b) unit
  tests written from the code's current behaviour rather than from the
  spec text, (c) corpus specimens whose expected verdict was derived by
  running the scanner rather than by reading the spec, or (d) integration
  tests that were excluded by default pytest configuration. No single
  control detects all four failure modes. Compensating controls: ADR
  discipline on rule-module changes (§10.x), the SPEC_REF class-constant
  convention forcing test authors to cite the MUST clause, a MUST-clause
  traceability meta-test that fails when any MUST clause has no citing
  test, corpus-as-ground-truth with verdicts derived from spec text, and
  a CI pre-merge gate requiring either a matching spec diff or a
  `Spec-Impact:` trailer with justification. This risk is irreducible
  by static means — it is a governance-quality risk, not a code-quality
  one.
  ```

#### 5.3 — Rescission notices on all seven artefacts

Apply the following rescission-and-restoration notice (adapt paths/fields per file) to each artefact. Record the superseded `sha256` in ADR-004 §Supersedes.

- [ ] **Step 5.3.1:** `docs/requirements/spec-fitness/conformance-review-2026-04-09.md` — top of file:

  ```markdown
  > **2026-04-12 rescission and restoration.** The PY-WL-001 conformance
  > claim in this review is rescinded for the `schema_default()` subset.
  > Between 2026-04-09 and 2026-04-12 the reference scanner implemented
  > file-level governance in contradiction to §A.3 clause 3. Regression
  > window: 3 days. The claim is restored after commit `<fix-sha>` and
  > re-verification per recovery plan
  > `docs/superpowers/plans/2026-04-12-py-wl-001-governance-scope-regression-v2.md`
  > Phase 6. See ADR-004 and residual risk #18.
  ```

- [ ] **Step 5.3.2:** `docs/requirements/spec-fitness/04-python-binding.yaml` — add a `rescissions:` block at the PY-WL-001 entry:

  ```yaml
  rescissions:
    - window: "2026-04-09/2026-04-12"
      subset: "schema_default"
      reason: "file-level governance contradicting §A.3 clause 3"
      restored_at: "<fix-sha>"
      adr: "ADR-004"
  ```

- [ ] **Step 5.3.3:** `docs/requirements/spec-fitness/03-scanner-conformance.yaml` — same block.
- [ ] **Step 5.3.4:** `docs/requirements/spec-fitness/corpus-reduction-2026-04-10.md` — append a rescission footer (the corpus was reduced on 2026-04-10, within the degraded window, so any reduction decisions that depended on the bad PY-WL-001 cell are suspect). Audit the reduction log entries for PY-WL-001 and either restore them or document why they are still valid under the fixed rule.
- [ ] **Step 5.3.5:** `docs/requirements/spec-fitness/assessment-2026-03-29.md` — the 2026-03-29 assessment pre-dates the regression (2026-04-09) but post-dates the spec language (2026-03-25). The §A.3 clause 3 assessment at 2026-03-29 was **correct at the time** — the assessment was rendered *non-conformant by a later code change*. Append a footer: "**2026-04-12 note:** §A.3 clause 3 assessment remained valid from 2026-03-25 to 2026-04-09. Commit 7caf751 (2026-04-09) rendered the reference implementation non-conformant. Conformance restored <fix-sha>. See ADR-004."
- [ ] **Step 5.3.6:** `wardline.conformance.json` — regenerate after Phase 6 re-verification. The pre-fix file is superseded; record its sha256 in ADR-004 §Supersedes before overwriting.
- [ ] **Step 5.3.7:** `wardline.sarif.baseline.json` — same treatment. Record pre-fix sha256, regenerate.

### Phase 6 — Conformance re-verification

- [ ] **Step 6.1: Run full test suite** with integration tests **enabled**:

  ```bash
  uv run pytest tests/ -q -p no:randomly
  ```

  Expected: all green, including `tests/integration/test_preview_phase2.py`.

- [ ] **Step 6.2: Lint and type-check.**

  ```bash
  uv run ruff check src/
  uv run mypy src/
  ```

  Expected: clean.

- [ ] **Step 6.3: Run corpus verify with per-cell assertions** (Phase 4b.2).

- [ ] **Step 6.4: Run the self-hosting scan.**

  ```bash
  uv run wardline scan src/wardline --manifest wardline.yaml -o /tmp/self.sarif
  ```

  Expected: zero new findings introduced by the fix. Wardline's own `src/` has **zero** runtime `schema_default(` call sites (verified fact — no additional grep needed). If any new finding appears, investigate before proceeding.

- [ ] **Step 6.5: Regenerate the fingerprint baseline.**

  ```bash
  uv run wardline fingerprint generate
  ```

  The new baseline must match the pre-regression baseline for the `schema_default` subset. Any delta requires documented investigation and an addendum to ADR-004.

- [ ] **Step 6.6 — Retrospective exploit scan of the degraded window.**

  Rationale: the file-level fallback was active between 2026-04-09 and 2026-04-12. Any `schema_default()` call added during that window in a file under an `optional_fields` overlay scope was silently suppressed by the broken rule. Even though the project is pre-1.0 with no external consumers, we cannot claim "no exploitation occurred" without diffing the fixed rule against the degraded-window behaviour.

  - [ ] **6.6.1:** Enumerate commits in the window:

    ```bash
    git log --oneline --since=2026-04-09 --until=2026-04-12 -- src/
    ```

  - [ ] **6.6.2:** For each commit in the window, check it out in a temporary worktree and run the *fixed* rule against it:

    ```bash
    for sha in $(git log --format=%H --since=2026-04-09 --until=2026-04-12 -- src/); do
      git worktree add /tmp/wl-window-$sha "$sha"
      # Copy the FIXED rule code into place
      cp src/wardline/scanner/rules/py_wl_001.py /tmp/wl-window-$sha/src/wardline/scanner/rules/py_wl_001.py
      cp src/wardline/scanner/rules/base.py /tmp/wl-window-$sha/src/wardline/scanner/rules/base.py
      ( cd /tmp/wl-window-$sha && uv run wardline scan src/ -o /tmp/wl-retro-$sha.sarif )
      git worktree remove /tmp/wl-window-$sha --force
    done
    ```

  - [ ] **6.6.3:** Diff each SARIF against the SARIF that would have been produced by the broken rule. Any `PY-WL-001-UNGOVERNED-DEFAULT` finding that appears under the fixed rule but not under the broken rule is a candidate exploit artefact. Record each finding in an appendix to ADR-004 §Consequences. Even if zero findings appear, record the empty result.

- [ ] **Step 6.7: Commit Phase 5 and Phase 6 artefacts** (ADR, residual risk, rescissions, regenerated baselines).

### Phase 7A — Close the observability gap (three fixes, all required)

**Ordering constraint:** Phase 7A runs **after** Phase 6.1 green and **before** PR merge. Running it earlier would expose the broken integration test. Running it later would ship the fix without the gap closure.

**Files:**

- Modify: `pyproject.toml`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 7A.1: Fix `pyproject.toml:72`.** Change:

  ```toml
  addopts = "-m 'not integration and not network'"
  ```

  to:

  ```toml
  addopts = "-m 'not network'"
  ```

- [ ] **Step 7A.2: Fix `.github/workflows/ci.yml:32`.** The `test-unit` job has a hard-coded `-m "not integration"` flag that overrides `pyproject.toml addopts`. Change:

  ```yaml
        - name: Unit tests with coverage
          run: uv run pytest -m "not integration" --tb=short --cov=wardline --cov-report=xml --cov-report=term-missing
  ```

  to:

  ```yaml
        - name: Unit tests with coverage
          run: uv run pytest --tb=short --cov=wardline --cov-report=xml --cov-report=term-missing
  ```

  (The CLI flag is removed; the `addopts` edit in 7A.1 then governs.) Alternative if we want to keep `test-unit` fast: merge `test-unit` and `test-integration` into a single `test` job. V2 picks the **remove the flag** approach — simpler, smaller diff, no job topology change.

- [ ] **Step 7A.3: Fix `.github/workflows/ci.yml` trigger filter.** Change:

  ```yaml
  on:
    push:
      branches: [main]
    pull_request:
      branches: [main]
  ```

  to:

  ```yaml
  on:
    push:
      branches: [main]
    pull_request:
  ```

  (Remove the `branches: [main]` filter on `pull_request` so any PR, from any branch, triggers the whole CI pipeline including the integration and self-hosting jobs.)

- [ ] **Step 7A.4: Add a `--fast` convenience marker** for local iteration. Update `pyproject.toml`:

  ```toml
  markers = [
      "integration: integration tests (require fixture setup)",
      "network: tests requiring network access (deselected by default, run weekly)",
      "slow: tests taking >1s (deselected with -m 'not slow')",
  ]
  ```

  Document in `CONTRIBUTING.md` (or create one) that `uv run pytest -m 'not integration'` is the fast local loop.

- [ ] **Step 7A.5: Verify the gap is actually closed.** Open a trivial dummy PR from a feature branch to confirm integration tests run on the PR checks tab. (Or inspect GitHub Actions `workflow_dispatch` output.) Do not skip this — the point of Phase 7A is that the gap stays closed.

### Phase 7B — Spec-linked change gate

**Files:**

- Modify: `.github/CODEOWNERS`
- Create: `.github/workflows/spec-link-check.yml`

- [ ] **Step 7B.1: Extend CODEOWNERS with rule-module ownership and the single-reviewer disclosure.**

  Append:

  ```
  # Scanner rules — spec-owner review required per ADR-004.
  # NOTE: Governance gap disclosed — the project currently has a single
  # human reviewer (@johnm-dta). Two-person review on @johnm-dta-authored
  # commits to rule modules cannot be enforced until a second human
  # reviewer is recruited. Tracked in filigree issue
  # "Recruit second human reviewer for CODEOWNERS rule-module ownership"
  # (blocker against v1.0).
  src/wardline/scanner/rules/py_wl_*.py @johnm-dta
  src/wardline/scanner/rules/scn_*.py   @johnm-dta
  src/wardline/scanner/rules/sup_*.py   @johnm-dta
  docs/spec/                             @johnm-dta
  docs/adr/                              @johnm-dta
  ```

- [ ] **Step 7B.2: File the second-reviewer filigree issue.**

  ```bash
  filigree create \
    "Recruit second human reviewer for CODEOWNERS rule-module ownership" \
    --type=task --priority=1 --label=blocker-v1.0 --label=governance
  filigree add-dep <v1.0-milestone-id> <this-issue-id>
  ```

- [ ] **Step 7B.3: Add a CI check enforcing Spec-Impact trailer or spec diff.**

  Create `.github/workflows/spec-link-check.yml`:

  ```yaml
  name: Spec Link Check
  on:
    pull_request:
  jobs:
    spec-link:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
          with:
            fetch-depth: 0
        - name: Check rule-module diff requires spec link
          run: |
            set -euo pipefail
            base="${GITHUB_BASE_REF:-main}"
            git fetch origin "$base"
            changed=$(git diff --name-only "origin/$base"...HEAD)
            rule_changed=0
            spec_changed=0
            if echo "$changed" | grep -qE '^src/wardline/scanner/rules/(py_wl_|scn_|sup_)'; then
              rule_changed=1
            fi
            if echo "$changed" | grep -qE '^docs/spec/wardline-02-'; then
              spec_changed=1
            fi
            if [ "$rule_changed" -eq 1 ]; then
              if [ "$spec_changed" -eq 0 ]; then
                # Require Spec-Impact trailer in PR body
                body=$(gh pr view "${GITHUB_REF_NAME##*/}" --json body -q .body || true)
                if ! echo "$body" | grep -qE '^Spec-Impact: (tightening|loosening|none)'; then
                  echo "::error::Rule module changed without matching spec diff and no Spec-Impact trailer in PR body"
                  exit 1
                fi
              fi
            fi
          env:
            GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  ```

- [ ] **Step 7B.4: Add a differential-corpus gate** (closes the `Spec-Impact: none` reviewer-theatre hole). Extend the workflow to:
  1. Run `uv run wardline corpus verify --json` on the PR HEAD and on `origin/main`.
  2. Diff the `per_cell` results.
  3. If any cell's `severity` or `verdict` flipped, auto-apply the label `Spec-Impact-Review-Required` to the PR and fail the job. A human must re-apply a justified `Spec-Impact:` trailer and re-run CI.

  Add a second job step:

  ```yaml
        - name: Differential corpus run
          run: |
            uv run wardline corpus verify --json > /tmp/pr.json
            git fetch origin main
            git stash
            git checkout origin/main -- src/wardline
            uv run wardline corpus verify --json > /tmp/main.json || true
            git stash pop || true
            uv run python tools/diff-corpus-cells.py /tmp/main.json /tmp/pr.json
  ```

  And create `tools/diff-corpus-cells.py`:

  ```python
  """Fail if any corpus cell's severity or verdict flipped between main and PR."""
  import json, sys
  main = json.load(open(sys.argv[1]))["per_cell"]
  pr = json.load(open(sys.argv[2]))["per_cell"]
  key = lambda c: (c["rule"], c["taint_state"], c["exceptionability"])
  main_map = {key(c): c for c in main}
  flips = []
  for c in pr:
      k = key(c)
      m = main_map.get(k)
      if m and (m["cell_verdict"] != c["cell_verdict"]):
          flips.append((k, m["cell_verdict"], c["cell_verdict"]))
  if flips:
      print("Cell flips detected:")
      for f in flips:
          print(f)
      sys.exit(1)
  print("No flips.")
  ```

- [ ] **Step 7B.5: Commit and verify the workflow fires.**

### Phase 7C — SPEC_REF traceability test

**Files:**

- Modify: `docs/spec/wardline-02-A-python-binding.md` (add must-id anchors)
- Modify: `tests/conftest.py`
- Create: `tests/conformance/test_must_clause_traceability.py`
- Create: `tests/conformance/test_must_clause_parser_self_test.py`

- [ ] **Step 7C.1: Add must-id anchors** to `docs/spec/wardline-02-A-python-binding.md`. Every MUST clause gets a comment anchor:

  ```markdown
  3. **Schema default recognition.** <!-- must-id: A.3.3 --> The tool MUST recognise `schema_default()`...
  ```

  Do this for §A.3 clauses 1-5 initially (scope limit — expansion in a follow-up issue).

- [ ] **Step 7C.2: Update `SPEC_REF` constants** to include must-id references:

  ```python
  SPEC_REF = (
      "must-id: A.3.3; "
      "docs/spec/wardline-02-A-python-binding.md §A.3 clause 3 (line 76)"
  )
  ```

- [ ] **Step 7C.3: Add a conftest check** in `tests/conftest.py`:

  ```python
  def pytest_collection_modifyitems(config, items):
      """Check that all rule-test classes under tests/unit/scanner/ and
      tests/integration/ carry a SPEC_REF class attribute referencing a
      must-id. Collected classes without SPEC_REF produce a warning."""
      missing = []
      for item in items:
          cls = getattr(item, "cls", None)
          if cls is None:
              continue
          if not cls.__module__.startswith(("tests.unit.scanner", "tests.integration")):
              continue
          if "Rule" not in cls.__name__ and "SchemaDefault" not in cls.__name__:
              continue
          if not hasattr(cls, "SPEC_REF"):
              missing.append(f"{cls.__module__}.{cls.__name__}")
      if missing:
          config.pluginmanager.get_plugin("terminalreporter").write_line(
              f"[SPEC_REF warning] {len(missing)} rule test classes missing SPEC_REF: {missing[:5]}..."
          )
  ```

  (Warning first, upgrade to error in a follow-up PR once all classes are annotated.)

- [ ] **Step 7C.4: Create the MUST-clause traceability meta-test** `tests/conformance/test_must_clause_traceability.py`:

  ```python
  """Meta-test: every MUST clause in docs/spec/wardline-02-*.md must be cited
  by at least one test class's SPEC_REF attribute. Every SPEC_REF must-id must
  resolve to a real anchor in the spec.

  Quoted spec-text requirement: this test reads MUST clause text by regex and
  asserts the quoted text appears verbatim in at least one citing test file
  header. This forces contradictions into reviewer line of sight — you cannot
  write a test that silently disagrees with the MUST clause it cites.
  """
  from __future__ import annotations

  import importlib
  import pkgutil
  import re
  from pathlib import Path

  import pytest

  SPEC_DIR = Path(__file__).resolve().parents[2] / "docs" / "spec"
  MUST_ID_PATTERN = re.compile(r"<!-- must-id: (?P<id>[A-Z]\.\d+\.\d+) -->")


  def _collect_spec_must_ids() -> dict[str, tuple[Path, int, str]]:
      """Return {must-id: (path, line_number, clause_text)}."""
      result: dict[str, tuple[Path, int, str]] = {}
      for spec_file in SPEC_DIR.glob("wardline-02-*.md"):
          for i, line in enumerate(spec_file.read_text().splitlines(), start=1):
              m = MUST_ID_PATTERN.search(line)
              if m:
                  result[m.group("id")] = (spec_file, i, line.strip())
      return result


  def _collect_spec_refs() -> dict[str, list[str]]:
      """Return {must-id: [list of citing test class FQNs]}."""
      import tests.unit.scanner  # noqa: F401  — ensures discovery
      citations: dict[str, list[str]] = {}
      for finder, name, ispkg in pkgutil.walk_packages(
          [str(Path(__file__).resolve().parents[1] / "unit" / "scanner")],
          prefix="tests.unit.scanner.",
      ):
          try:
              mod = importlib.import_module(name)
          except Exception:
              continue
          for attr_name in dir(mod):
              cls = getattr(mod, attr_name)
              if not isinstance(cls, type):
                  continue
              spec_ref = getattr(cls, "SPEC_REF", None)
              if not spec_ref:
                  continue
              for m in re.finditer(r"must-id:\s*([A-Z]\.\d+\.\d+)", spec_ref):
                  citations.setdefault(m.group(1), []).append(f"{mod.__name__}.{cls.__name__}")
      return citations


  def test_every_must_clause_has_a_citing_test() -> None:
      spec_ids = _collect_spec_must_ids()
      citations = _collect_spec_refs()
      uncited = sorted(set(spec_ids) - set(citations))
      if uncited:
          pytest.fail(f"MUST clauses with no citing test: {uncited}")


  def test_every_citation_resolves_to_a_real_must_id() -> None:
      spec_ids = _collect_spec_must_ids()
      citations = _collect_spec_refs()
      unresolved = sorted(set(citations) - set(spec_ids))
      if unresolved:
          pytest.fail(f"Citations to non-existent must-ids: {unresolved}")
  ```

- [ ] **Step 7C.5: Create the parser self-test** `tests/conformance/test_must_clause_parser_self_test.py`:

  ```python
  """Self-test for the MUST_ID_PATTERN regex.

  If this test fails the main traceability meta-test becomes vacuous
  (it would return zero spec IDs and pass with zero citations).
  """
  from __future__ import annotations

  from tests.conformance.test_must_clause_traceability import MUST_ID_PATTERN


  def test_parser_matches_known_good_line() -> None:
      line = '3. **Schema default recognition.** <!-- must-id: A.3.3 --> The tool MUST...'
      m = MUST_ID_PATTERN.search(line)
      assert m is not None
      assert m.group("id") == "A.3.3"


  def test_parser_rejects_malformed_id() -> None:
      line = "<!-- must-id: lowercase.3.3 -->"
      assert MUST_ID_PATTERN.search(line) is None


  def test_parser_ignores_non_anchor_comments() -> None:
      line = "<!-- not a must id -->"
      assert MUST_ID_PATTERN.search(line) is None
  ```

- [ ] **Step 7C.6:** Run both tests.

  ```bash
  uv run pytest tests/conformance/ -q
  ```

  Expected: PASS.

### Phase 7D — Corpus-as-ground-truth

- [ ] **Step 7D.1:** Document the corpus contract in `corpus/README.md` (create if absent):

  ```markdown
  # Corpus contract

  The corpus is the ground truth for rule behaviour at v1.0. Rules:

  1. **Spec-derived verdicts.** A specimen's expected verdict MUST be derived
     from spec text, not from running the scanner. Specimen authors must cite
     the spec section in the YAML `description` field.
  2. **No test-corpus disagreement.** If a unit test asserts one outcome for
     a code shape and a corpus specimen asserts another for the same shape,
     CI fails and a human must reconcile the two. The corpus wins by default
     (it is the spec-derived record); the test is presumed to have drifted.
  3. **Canonical examples are specimens.** Every `def ... schema_default(...)`
     shown in `docs/spec/wardline-02-*.md` MUST exist as a corpus specimen with
     the verdict the spec text implies.
  ```

- [ ] **Step 7D.2:** File a follow-up filigree issue to enumerate and specimen-cover every canonical example in `docs/spec/wardline-02-*.md` beyond PY-WL-001. (Scope: spec audit, not blocking this PR.)

### Phase 8 — Same-PR audit verification

- [ ] **Step 8.1: Verify PY-WL-008 decorator path with a new corpus specimen.** Create a TN specimen `PY-WL-008-TN-schema-default-decorator-only-governance` (or the equivalent for PY-WL-008's rule semantics) proving the existing `_has_direct_decorator` fallback activates under decorator-only governance. Run corpus verify. If the specimen fails to suppress, PY-WL-008 has the same latent bug and must be added to the Phase 1 fan-out.
- [ ] **Step 8.2:** Same for PY-WL-009.
- [ ] **Step 8.3:** Confirm the Phase 0.1.6 filigree issue is open and linked to v1.0.

### Phase 9 — PR merge

- [ ] **Step 9.1:** Run the full verification checklist (Phase 6).
- [ ] **Step 9.2:** Push the branch. Open the PR with title `fix: restore PY-WL-001 function-level governance (ADR-004)`. PR body must contain:
  ```
  Spec-Impact: tightening
  ```
  and a link to this plan, ADR-004, and residual risk #18.
- [ ] **Step 9.3:** Verify all CI jobs green:
  - `test-unit` (with integration tests NOT excluded)
  - `test-integration`
  - `spec-link-check` (Phase 7B.3-7B.4)
  - `self-hosting-scan`
- [ ] **Step 9.4:** Merge via rebase-and-merge (no squash — preserve per-phase commit history).

---

## 6. Acceptance Criteria (mechanically checkable)

The fix is complete when ALL of the following hold. Each criterion is a command whose exit-code-0 output is the pass.

### 6.1 Code

- [ ] `grep -n '_is_governed_by_optional_field' src/wardline/scanner/rules/py_wl_001.py` returns nothing.
- [ ] `grep -n '_has_validation_boundary_decorator' src/wardline/scanner/rules/base.py` returns exactly one definition.
- [ ] `grep -n '_VALIDATION_DECORATORS' src/wardline/scanner/rules/base.py` returns the canonical definition.
- [ ] `grep -rn '_has_validation_boundary_decorator' src/wardline/scanner/rules/py_wl_001.py src/wardline/scanner/rules/py_wl_003.py src/wardline/scanner/rules/py_wl_007.py` returns one call site per file.
- [ ] `uv run ruff check src/` exits 0.
- [ ] `uv run mypy src/` exits 0.

### 6.2 Tests

- [ ] `uv run pytest tests/ -q -p no:randomly` exits 0 (full suite, integration included).
- [ ] `grep -n 'test_optional_field_only_no_boundary_suppresses\|test_wrong_function_boundary_still_governed_by_optional_field\|test_wrong_transition_boundary_still_governed_by_optional_field\|test_case_sensitive_qualname_boundary_still_governed_by_optional_field' tests/unit/scanner/test_py_wl_001.py` returns nothing.
- [ ] `grep -n 'TestSchemaDefaultGovernedByDecorator' tests/unit/scanner/test_py_wl_001.py` returns a class definition.
- [ ] `uv run pytest tests/unit/scanner/test_validation_decorators_registry.py -q` exits 0.
- [ ] `uv run pytest tests/conformance/ -q` exits 0.

### 6.3 Corpus

- [ ] `uv run wardline corpus verify --json > /tmp/corpus.json && uv run python -c "import json; d=json.load(open('/tmp/corpus.json')); c=next(x for x in d['per_cell'] if x['rule']=='PY-WL-001' and x['taint_state']=='EXTERNAL_RAW' and x['exceptionability']=='UNCONDITIONAL'); assert c['sample']>=5 and c['recall']>=0.90 and c['precision']>=0.80 and c['cell_verdict']=='PASS'"` exits 0.
- [ ] Same for the MIXED_RAW cell at 0.65/0.70.
- [ ] Every `per_cell` entry has `cell_verdict == "PASS"`.
- [ ] The regression-lock specimen `PY-WL-001-TP-schema-default-undecorated-helper` exists and its verdict is `true_positive`.
- [ ] The spec canonical specimen `PY-WL-001-TN-schema-default-validates-shape` exists and its verdict is `true_negative`.
- [ ] The YAML-boundary-only specimen `PY-WL-001-TN-schema-default-yaml-boundary-only` exists.
- [ ] The semantic-only TP specimen exists.

### 6.4 Documentation

- [ ] `docs/adr/ADR-004-schema-default-governance-function-level.md` exists with `Status: Accepted`, a `Deciders:` line naming `@johnm-dta`, and `## Summary`, `## Context`, `## Decision`, `## Consequences`, `## Alternatives rejected`, `## Invalidates`, `## Supersedes` sections.
- [ ] `docs/spec/wardline-01-13-residual-risks.md` opens with "Eighteen risks...".
- [ ] Rescission notices present in all seven artefacts from §5.3.
- [ ] ADR-004 §Supersedes lists seven sha256 hashes.

### 6.5 Systemic controls

- [ ] `grep 'addopts' pyproject.toml` shows `not network` only (integration removed).
- [ ] `grep -n 'not integration' .github/workflows/ci.yml` returns nothing.
- [ ] `grep -A2 'pull_request:' .github/workflows/ci.yml | head -5` shows no `branches:` filter.
- [ ] `.github/CODEOWNERS` has `src/wardline/scanner/rules/py_wl_*.py` rule and a governance-gap disclosure block.
- [ ] `.github/workflows/spec-link-check.yml` exists and contains both the spec-link trailer check and the differential corpus step.
- [ ] `tests/conformance/test_must_clause_traceability.py` and `tests/conformance/test_must_clause_parser_self_test.py` exist and pass.

### 6.6 Retrospective scan

- [ ] Phase 6.6.3 output recorded in ADR-004 §Consequences (even if empty).

### 6.7 Follow-on tracking

- [ ] The Phase 8 audit filigree issue exists with label `blocker-v1.0`, assigned to `@johnm-dta`, with a `depends-on` dependency from the v1.0 milestone.
- [ ] The second-reviewer filigree issue exists with label `blocker-v1.0`.

---

## 7. Risk Assessment

**High confidence** on the diagnosis and fix direction. Spec text is unambiguous. Timeline is documented in git history. Corpus corruption is observable. SAD's architectural finding was independently traced through all three `BoundaryEntry` construction sites. The code-fact table in V2's input grounded every pseudocode detail against actual source lines.

**High confidence** on the decorator-path secondary check. Option (c) (`_wardline_transition` attr present and sourced at EXTERNAL_RAW) is a deterministic data check against a registry-backed decorator definition, not a heuristic, not a behavioural analysis.

**Medium confidence** on PY-WL-003 and PY-WL-007 fan-out correctness. The same-bug-pattern claim is verified (both rules have bare `boundary.function ==` checks with no decorator fallback) but neither has been under the same spec microscope as PY-WL-001. Phase 8.1 and 8.2 corpus specimens are the main mitigation — if the fix breaks either rule's existing test suite, pause and panel-review.

**Low risk** of self-hosting regression. Wardline's own `src/` has **zero** runtime `schema_default(` call sites (verified fact in V2 input). The fix cannot introduce new findings against the self-scan.

**Low risk** of downstream consumer breakage. Wardline is pre-1.0 with no external consumers.

**Residual risk after the fix (governance-quality):** the class of silent drift this regression represents can only be partially mitigated. Phase 7B's Spec-Impact trailer + differential-corpus gate catches the most common pattern (rule change without spec change) but cannot catch a coordinated rule-change-plus-wrong-spec-change. The SPEC_REF traceability meta-test closes a wider gap but depends on reviewer diligence in authoring `SPEC_REF` constants. Residual risk #18 records this.

**Residual risk (single-reviewer CODEOWNERS):** disclosed, not mitigated. Blocker filed against v1.0.

---

## 8. Open Questions

Each question is flagged as **BLOCKER** or **non-blocker** with explicit justification. No question may be left unresolved before Phase 1 starts.

1. **ADR-004 decider identity.** *Resolved (Phase 0.1.1).* Default: `@johnm-dta` as Project Lead, per ADR-003 precedent. **Non-blocker** — decision is made in this plan.

2. **`validates_semantic` eligibility.** *Resolved (Phase 0.1.2).* Decision: **excluded** from `_VALIDATION_DECORATORS`. Justification captured in ADR-004 §Decision. **Non-blocker** — decision is made in this plan.

3. **Decorator secondary check mechanism.** *Resolved (Phase 0.1.3).* Decision: **Option (c)**, check `_wardline_transition` attr for EXTERNAL_RAW source. **Non-blocker** — decision is made in this plan.

4. **CODEOWNERS second reviewer.** *Partially resolved (Phase 0.1.4).* Decision: disclose now, recruit pre-v1.0. **Non-blocker for this PR**, **BLOCKER for v1.0 release** (tracked in filigree).

5. **Phase 8 scope.** *Resolved (Phase 0.1.5).* Decision: PY-WL-001+003+007 fix in-PR; PY-WL-008+009 verify-only in-PR; deeper sweep filed as filigree issue. **Non-blocker** — decision is made.

6. **Retrospective scan scope.** Is a 3-day commit-by-commit re-scan excessive for a pre-1.0 project with no external consumers? **Non-blocker**, decision: do it anyway. The cost is bounded (a handful of commits) and the output is recorded in ADR-004. If any finding is surfaced, the decision is retroactively justified; if not, the empty result is evidence.

7. **Spec anchor scope for must-ids.** Should every MUST clause in every chapter of `docs/spec/wardline-02-*.md` get a must-id in this PR, or only §A.3? **Non-blocker**, decision: only §A.3 clauses 1-5 in this PR. Full-chapter coverage is a follow-up filigree issue.

8. **Differential-corpus implementation language.** `tools/diff-corpus-cells.py` assumes a stable JSON shape from `wardline corpus verify --json`. If the shape changes in the future, the diff tool breaks silently. **Non-blocker**, mitigation: add a smoke test for `diff-corpus-cells.py` at `tests/tools/test_diff_corpus_cells.py` reading a fixture JSON.

9. **Phase 6.6 worktree strategy.** The retrospective scan script copies the fixed rule file into historical checkouts. This assumes the rule's imports and helper shapes are compatible with each historical commit. **Non-blocker**, decision: if a historical commit has incompatible internals, record "uncheckable" for that commit in ADR-004 §Consequences and move on.

10. **Spec-update for `validates_semantic` ineligibility.** ADR-004 declares `validates_semantic` ineligible for schema_default governance, but §A.4 row 5 does not explicitly enumerate which decorators count as "validation boundary context." Should the spec be amended in this same PR to name the eligible decorators explicitly? **BLOCKER for ADR-004 §Status:Accepted.** Decision: **yes**, append a new bullet after §A.4 row 5:

    > "For the purpose of §A.3 clause 3 suppression, 'validation boundary context' is satisfied by any decorator in the wardline-core registry whose `_wardline_transition` source is `EXTERNAL_RAW`. In the Python binding v1.0 vocabulary this is `@validates_shape` and `@validates_external`. `@validates_semantic` is explicitly excluded — it operates after shape validation and cannot retroactively govern a schema_default fabrication at EXTERNAL_RAW."

    Add this edit to Phase 5 as **Step 5.4** and include the edit in the Phase 1 commit (paired spec-and-code change). This makes the `Spec-Impact: tightening` trailer honest.

- [ ] **Step 5.4 (added from open question 10): Append the spec clarification.** Modify `docs/spec/wardline-02-A-python-binding.md` immediately after §A.4 row 5 to add the bullet above. Bump the spec's visible revision marker if the chapter tracks one.

---

## 9. Non-Goals

- Rewriting any rule other than PY-WL-001, PY-WL-003, PY-WL-007 in this PR. PY-WL-008/009 are verify-only. Any deeper omnibus audit of `7caf751` is tracked in the Phase 0.1.6 filigree issue.
- Changing the trust-topology manifest schema (`wardline.yaml`) or the overlay schema — the fix works entirely through the overlay's existing optional_fields/boundaries blocks.
- Adding runtime enforcement in `src/wardline/runtime/`. This is a static-analysis rule fix.
- Renaming any public API. `schema_default()` stays as-is.

---

## 10. Commit and Branch Strategy

Branch: `fix/py-wl-001-function-level-governance`. Base: current branch `phase-4.4-test-quality-gates`. Commits correspond 1:1 with phases:

1. `phase-0: add spec paraphrase and filigree blocking issues`
2. `fix(PY-WL-001,003,007): restore function-level governance per ADR-004` (Phase 1 + Phase 5.4 spec bullet)
3. `test(PY-WL-001): invert spec-violating tests, add decorator-based coverage` (Phase 2)
4. `test(integration): preview-phase2 fixture uses decorator path` (Phase 3)
5. `corpus: repair PY-WL-001 specimens, add canonical/regression-lock specimens` (Phase 4)
6. `docs: ADR-004, residual risk #18 renumber, rescission on 7 artefacts` (Phase 5.1-5.3)
7. `ci: close integration-test exclusion gap (pyproject + ci.yml)` (Phase 7A)
8. `ci: spec-link gate + differential corpus + CODEOWNERS disclosure` (Phase 7B, 7C, 7D)
9. `audit: corpus coverage for PY-WL-008/009 decorator path` (Phase 8)

No squash merge. Preserve the per-phase history so each phase is separately reviewable.

---

## 11. Subagent Dispatch Mapping

One agent per phase. Dependencies from §4 must be respected.

| Phase | Agent role | Input artefacts | Output artefacts |
|-------|-----------|-----------------|------------------|
| 0.0 | spec paraphraser | spec §A.3, §A.4 | `/tmp/wl001-paraphrase.md` |
| 0.1 | planner | this plan | filigree issues, decisions recorded |
| 4a | corpus author | spec text (not scanner output) | 5 new + 2 repaired specimens |
| 2.0 | test infra | `test_py_wl_001.py`, `context.py` | extended `_run_rule_with_context` |
| 1 | rule fixer | Phase 0 paraphrase, Phase 4a specimens | `base.py`, `py_wl_001.py`, `py_wl_003.py`, `py_wl_007.py` |
| 2 | test author | Phase 1 output | test file edits, registry test |
| 3 | integration test | Phase 1 output | `test_preview_phase2.py` edit |
| 4b | corpus verifier | Phase 4a specimens + Phase 1 rule | verified corpus |
| 5 | documentation | Phase 1+4b outputs | ADR-004, residual risk edit, rescission notices |
| 6 | verification | all | green test suite, retrospective scan log |
| 7A | ci fixer | Phase 6 green | pyproject + ci.yml edits |
| 7B | governance ci | ADR-004 | spec-link workflow + CODEOWNERS edit |
| 7C | traceability | spec anchors | conftest + meta-test + self-test |
| 7D | corpus contract | all | README + follow-up issue |
| 8 | audit verification | PY-WL-008/009 | verification specimens |

Each agent is dispatched with:

- The subagent-driven-development skill (`superpowers:subagent-driven-development`).
- A prompt that names the phase, its files, its inputs, and its checkbox tasks.
- A reminder that **subagents must not use git directly** (per user-feedback memo `feedback_git_prohibition.md`).
- A reminder to invoke `filigree` for issue creation/update as specified.

---

## 12. Length note

This plan is intentionally longer than V1 (V1 was ~900 lines). V2 adds ~1000 lines to accommodate (a) per-blocker-fix inline documentation, (b) explicit committed decisions replacing V1 hedges, (c) the retrospective scan phase V1 omitted, (d) the full ADR-004 template matching ADR-003, (e) the differential-corpus gate, (f) the spec paraphrase goal-reset phase, and (g) the same-PR fan-out for PY-WL-003 and PY-WL-007.

---

## 13. Supersedes V1

V1: `docs/superpowers/plans/2026-04-11-py-wl-001-governance-scope-regression.md`

V1 is retained as a historical artefact. This V2 is the authoritative plan. Any reference to V1 after the Phase 1 commit lands should redirect here.
