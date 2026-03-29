# SCN-021 Spec Mapping + ExceptionEntry Enum Cleanup

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile SCN-021 combination count against the spec's 29 pairs, then convert ExceptionEntry/DependencyTaintEntry string fields to their StrEnum types before API freeze.

**Architecture:** Item 1 adds a `spec_entry` field to `_CombinationSpec` and a coverage test. Item 2 converts 5 dataclass fields from `str` to StrEnum types with `__post_init__` coercion on the frozen dataclass, following the existing `BoundaryEntry.__post_init__` pattern.

**Tech Stack:** Python 3.12+, pytest, dataclasses, StrEnum

---

## Item 1: SCN-021 Combination Mapping

### Reconciliation Summary

The spec (§02-A, lines 239-269) defines **29 pairs**. The implementation has **32 entries**.

**Mapping:**

| Impl # | Spec # | Pair | Notes |
|--------|--------|------|-------|
| 1 | 1 | fail_open + fail_closed | |
| 2 | 2 | fail_open + integral_read | |
| 3 | 3 | fail_open + integral_writer | |
| 4 | 4 | fail_open + integral_construction | |
| 5 | 5 | fail_open + integrity_critical | Also covers spec #19 (alias) |
| 6 | 6 | external_boundary + int_data | |
| 7 | 7 | external_boundary + integral_read | |
| 8 | 8 | external_boundary + integral_construction | |
| 9 | 9 | validates_shape + validates_semantic | |
| 10 | 10 | validates_shape + integral_read | |
| 11 | 11 | validates_semantic + external_boundary | |
| 12 | 12 | exception_boundary + must_propagate | Also covers spec #23 (alias) |
| 13 | 13 | idempotent + compensatable | |
| 14 | 14 | deterministic + time_dependent | |
| 15 | 15 | deterministic + external_boundary | |
| 16 | 16 | integral_read + restoration_boundary | |
| 17 | 17 | integral_writer + restoration_boundary | |
| 18 | — | external_boundary + restoration_boundary | Extension |
| 19 | — | validates_shape + restoration_boundary | Extension |
| 20 | — | validates_semantic + restoration_boundary | Extension |
| 21 | — | validates_external + restoration_boundary | Extension |
| 22 | — | integral_construction + restoration_boundary | Extension |
| 23 | 18 | fail_closed + emits_or_explains | |
| 24 | 20 | validates_external + validates_shape | |
| 25 | 21 | validates_external + validates_semantic | |
| 26 | 22 | int_data + validates_shape | |
| 27 | 23 | preserve_cause + exception_boundary | Alias of #12 kept as separate combo |
| 28 | 24 | compensatable + integral_writer | |
| 29 | 26 | system_plugin + integral_read | |
| 30 | 27 | fail_open + deterministic | Suspicious |
| 31 | 28 | compensatable + deterministic | Suspicious |
| 32 | 29 | time_dependent + idempotent | Suspicious |

**Not implemented:**
- Spec #19: `integrity_critical + fail_open` — alias of #5, intentionally omitted (comment at line 111)
- Spec #25: `@data_flow(produces=...)` + `@external_boundary` — requires parameterized-decorator analysis (L2+)

**Extensions beyond spec:** 5 `restoration_boundary` combos (#18-22) — semantically correct (restoration is incompatible with these boundary types for the same reason as spec #16/#17).

### Task 1: Add spec_entry to _CombinationSpec

**Files:**
- Modify: `src/wardline/scanner/rules/scn_021.py:16-131`

- [ ] **Step 1: Add spec_entry field to _CombinationSpec**

```python
@dataclass(frozen=True)
class _CombinationSpec:
    left: str
    right: str
    severity: Severity
    rationale: str
    spec_entry: int | None = None  # Spec §02-A table entry number; None = extension
```

- [ ] **Step 2: Annotate every _COMBINATIONS entry with its spec_entry**

Update each `_CombinationSpec(...)` call. The first 17 entries get `spec_entry=N` matching the table above. The 5 restoration_boundary extensions get `spec_entry=None`. The remaining entries get their spec numbers. Full list:

```python
_COMBINATIONS: tuple[_CombinationSpec, ...] = (
    _CombinationSpec("fail_open", "fail_closed", _CONTRADICTORY, "Mutually exclusive failure modes", spec_entry=1),
    _CombinationSpec(
        "fail_open",
        "integral_read",
        _CONTRADICTORY,
        "Tier 1 requires offensive programming; fail-open is structurally incompatible",
        spec_entry=2,
    ),
    _CombinationSpec("fail_open", "integral_writer", _CONTRADICTORY, "Audit writes must not silently degrade", spec_entry=3),
    _CombinationSpec(
        "fail_open",
        "integral_construction",
        _CONTRADICTORY,
        "Authoritative artefacts must not have fallback construction paths",
        spec_entry=4,
    ),
    _CombinationSpec("fail_open", "integrity_critical", _CONTRADICTORY, "Audit-critical paths must not have fallback paths", spec_entry=5),
    _CombinationSpec("external_boundary", "int_data", _CONTRADICTORY, "External and internal data sources are mutually exclusive", spec_entry=6),
    _CombinationSpec("external_boundary", "integral_read", _CONTRADICTORY, "External data is Tier 4; Tier 1 reads are internal", spec_entry=7),
    _CombinationSpec("external_boundary", "integral_construction", _CONTRADICTORY, "External data cannot be directly authoritative", spec_entry=8),
    _CombinationSpec("validates_shape", "validates_semantic", _CONTRADICTORY, "Use validates_external for combined T4→T2 validation", spec_entry=9),
    _CombinationSpec("validates_shape", "integral_read", _CONTRADICTORY, "Shape validation produces T3, not T1", spec_entry=10),
    _CombinationSpec("validates_semantic", "external_boundary", _CONTRADICTORY, "Semantic validation operates on T3 input, not T4", spec_entry=11),
    _CombinationSpec(
        "exception_boundary",
        "must_propagate",
        _CONTRADICTORY,
        "Exception boundaries terminate; must-propagate requires forwarding",
        spec_entry=12,
    ),
    _CombinationSpec("idempotent", "compensatable", _CONTRADICTORY, "Idempotent operations need no compensation", spec_entry=13),
    _CombinationSpec("deterministic", "time_dependent", _CONTRADICTORY, "Time-dependent operations are inherently non-deterministic", spec_entry=14),
    _CombinationSpec("deterministic", "external_boundary", _CONTRADICTORY, "External calls are non-deterministic by definition", spec_entry=15),
    _CombinationSpec(
        "integral_read",
        "restoration_boundary",
        _CONTRADICTORY,
        "Tier 1 reads access existing authoritative data; restoration reconstructs from raw representation",
        spec_entry=16,
    ),
    _CombinationSpec(
        "integral_writer",
        "restoration_boundary",
        _CONTRADICTORY,
        "Audit writes create new records; restoration reconstructs existing ones",
        spec_entry=17,
    ),
    # Extensions: restoration_boundary is contradictory with all boundary types (generalises spec #16/#17).
    _CombinationSpec(
        "external_boundary",
        "restoration_boundary",
        _CONTRADICTORY,
        "External boundaries receive new untrusted data; "
        "restoration reconstructs previously-known data",
    ),
    _CombinationSpec(
        "validates_shape",
        "restoration_boundary",
        _CONTRADICTORY,
        "Shape validators receive raw input for validation; "
        "restoration reconstructs previously-known data",
    ),
    _CombinationSpec(
        "validates_semantic",
        "restoration_boundary",
        _CONTRADICTORY,
        "Semantic validators receive shape-validated input; "
        "restoration reconstructs previously-known data",
    ),
    _CombinationSpec(
        "validates_external",
        "restoration_boundary",
        _CONTRADICTORY,
        "External validators receive raw external input; "
        "restoration reconstructs previously-known data",
    ),
    _CombinationSpec(
        "integral_construction",
        "restoration_boundary",
        _CONTRADICTORY,
        "Construction creates new authoritative objects from validated input; "
        "restoration reconstructs existing objects from raw representation",
    ),
    _CombinationSpec(
        "fail_closed",
        "emits_or_explains",
        _CONTRADICTORY,
        "Fail-closed raises on failure; emits-or-explains requires structured error output",
        spec_entry=18,
    ),
    # Spec entry #19 (integrity_critical + fail_open) is an alias of #5 — removed to prevent duplicate findings.
    _CombinationSpec("validates_external", "validates_shape", _CONTRADICTORY, "validates_external already encompasses shape validation", spec_entry=20),
    _CombinationSpec(
        "validates_external",
        "validates_semantic",
        _CONTRADICTORY,
        "validates_external already encompasses semantic validation",
        spec_entry=21,
    ),
    _CombinationSpec("int_data", "validates_shape", _CONTRADICTORY, "Internal data does not need shape validation", spec_entry=22),
    _CombinationSpec(
        "preserve_cause",
        "exception_boundary",
        _CONTRADICTORY,
        "preserve_cause implies propagation; exception boundaries terminate",
        spec_entry=23,
    ),
    _CombinationSpec("compensatable", "integral_writer", _CONTRADICTORY, "Audit writes must not be compensated", spec_entry=24),
    # Spec entry #25 (@data_flow(produces=...) + @external_boundary) requires parameterized-decorator analysis (L2+).
    _CombinationSpec("system_plugin", "integral_read", _CONTRADICTORY, "Plugins receive external input; Tier 1 reads are internal", spec_entry=26),
    _CombinationSpec("fail_open", "deterministic", _SUSPICIOUS, "Fail-open with fallback defaults may produce non-deterministic output", spec_entry=27),
    _CombinationSpec("compensatable", "deterministic", _SUSPICIOUS, "Compensation introduces state changes that may affect determinism", spec_entry=28),
    _CombinationSpec("time_dependent", "idempotent", _SUSPICIOUS, "Time-dependent operations may not be idempotent across invocations", spec_entry=29),
)
```

- [ ] **Step 3: Run existing tests to verify no regression**

Run: `uv run pytest tests/unit/scanner/test_scn_021.py -v`
Expected: All 42 tests PASS (32 parametrized + 6 negative + 4 manual)

- [ ] **Step 4: Commit**

```bash
git add src/wardline/scanner/rules/scn_021.py
git commit -m "feat: annotate SCN-021 _COMBINATIONS with spec entry numbers"
```

### Task 2: Add spec coverage test

**Files:**
- Modify: `tests/unit/scanner/test_scn_021.py`

- [ ] **Step 1: Write the spec coverage test**

Add to the end of `test_scn_021.py`:

```python
class TestSpecCoverage:
    """Verify _COMBINATIONS covers all 29 spec entries."""

    # Spec entries intentionally not in _COMBINATIONS:
    # #19: integrity_critical + fail_open — alias of #5, would duplicate
    # #25: @data_flow(produces=...) + @external_boundary — requires L2 parameterized-decorator analysis
    _INTENTIONALLY_MISSING = frozenset({19, 25})
    _SPEC_ENTRIES = frozenset(range(1, 30))  # 1..29

    def test_all_spec_entries_covered_or_documented(self) -> None:
        """Every spec entry is either in _COMBINATIONS or in _INTENTIONALLY_MISSING."""
        covered = {s.spec_entry for s in _COMBINATIONS if s.spec_entry is not None}
        expected = self._SPEC_ENTRIES - self._INTENTIONALLY_MISSING
        assert covered == expected, (
            f"Missing spec entries: {expected - covered}; "
            f"unexpected entries: {covered - expected}"
        )

    def test_extensions_have_no_spec_entry(self) -> None:
        """Implementation extensions must have spec_entry=None."""
        extensions = [s for s in _COMBINATIONS if s.spec_entry is None]
        assert len(extensions) == 5, (
            f"Expected 5 restoration_boundary extensions, got {len(extensions)}"
        )
        for ext in extensions:
            assert "restoration_boundary" in (ext.left, ext.right)

    def test_no_duplicate_spec_entries(self) -> None:
        """Each spec entry number appears at most once."""
        entries = [s.spec_entry for s in _COMBINATIONS if s.spec_entry is not None]
        assert len(entries) == len(set(entries)), (
            f"Duplicate spec entries: {[e for e in entries if entries.count(e) > 1]}"
        )
```

- [ ] **Step 2: Run the new tests**

Run: `uv run pytest tests/unit/scanner/test_scn_021.py::TestSpecCoverage -v`
Expected: 3 tests PASS

- [ ] **Step 3: Commit**

```bash
git add tests/unit/scanner/test_scn_021.py
git commit -m "test: add SCN-021 spec coverage verification"
```

---

## Item 2: ExceptionEntry / DependencyTaintEntry str→enum

### Task 3: Change ExceptionEntry field types and add __post_init__

**Files:**
- Modify: `src/wardline/manifest/models.py:17-49`

- [ ] **Step 1: Write failing test — ExceptionEntry fields are enum types at runtime**

Add to `tests/unit/manifest/test_models.py`:

```python
from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState


class TestExceptionEntryEnumFields:
    """ExceptionEntry stores enum values, not raw strings."""

    def test_construction_from_strings_coerces_to_enums(self) -> None:
        entry = ExceptionEntry(
            id="EXC-TEST",
            rule="PY-WL-004",
            taint_state="EXTERNAL_RAW",
            location="src/foo.py::bar",
            exceptionability="STANDARD",
            severity_at_grant="ERROR",
            rationale="test",
            reviewer="test",
        )
        assert isinstance(entry.rule, RuleId)
        assert isinstance(entry.taint_state, TaintState)
        assert isinstance(entry.exceptionability, Exceptionability)
        assert isinstance(entry.severity_at_grant, Severity)
        # StrEnum still compares equal to string
        assert entry.rule == "PY-WL-004"
        assert entry.taint_state == "EXTERNAL_RAW"

    def test_construction_from_enums_works(self) -> None:
        entry = ExceptionEntry(
            id="EXC-TEST",
            rule=RuleId.PY_WL_004,
            taint_state=TaintState.EXTERNAL_RAW,
            location="src/foo.py::bar",
            exceptionability=Exceptionability.STANDARD,
            severity_at_grant=Severity.ERROR,
            rationale="test",
            reviewer="test",
        )
        assert entry.rule is RuleId.PY_WL_004
        assert entry.taint_state is TaintState.EXTERNAL_RAW

    def test_invalid_rule_raises(self) -> None:
        import pytest
        with pytest.raises(ValueError, match="INVALID"):
            ExceptionEntry(
                id="EXC-TEST",
                rule="INVALID",
                taint_state="EXTERNAL_RAW",
                location="src/foo.py::bar",
                exceptionability="STANDARD",
                severity_at_grant="ERROR",
                rationale="test",
                reviewer="test",
            )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/manifest/test_models.py::TestExceptionEntryEnumFields -v`
Expected: FAIL — `isinstance(entry.rule, RuleId)` is False (still a plain string)

- [ ] **Step 3: Update ExceptionEntry imports and field types in models.py**

Change the imports at the top of `models.py`:

```python
# Move RuleId, TaintState out of TYPE_CHECKING into runtime imports
from wardline.core.severity import Exceptionability, GovernancePath, RuleId, Severity
from wardline.core.taints import TaintState
```

Remove the TYPE_CHECKING block for these imports (keep TYPE_CHECKING if other imports remain).

Change field types on ExceptionEntry:

```python
@dataclass(frozen=True)
class ExceptionEntry:
    """A granted exception to a wardline rule finding."""

    id: str
    rule: RuleId
    taint_state: TaintState
    location: str
    exceptionability: Exceptionability
    severity_at_grant: Severity
    rationale: str
    reviewer: str
    expires: str | None = None
    provenance: str | None = None
    agent_originated: bool | None = None
    ast_fingerprint: str = ""
    recurrence_count: int = 0
    governance_path: GovernancePath = GovernancePath.STANDARD
    last_refreshed_by: str | None = None
    last_refresh_rationale: str | None = None
    last_refreshed_at: str | None = None
    analysis_level: int = 1
    migrated_from: str | None = None
    migrated_by: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.rule, RuleId):
            object.__setattr__(self, "rule", RuleId(self.rule))
        if not isinstance(self.taint_state, TaintState):
            object.__setattr__(self, "taint_state", TaintState(self.taint_state))
        if not isinstance(self.exceptionability, Exceptionability):
            object.__setattr__(self, "exceptionability", Exceptionability(self.exceptionability))
        if not isinstance(self.severity_at_grant, Severity):
            object.__setattr__(self, "severity_at_grant", Severity(self.severity_at_grant))
```

- [ ] **Step 4: Run the new test to verify it passes**

Run: `uv run pytest tests/unit/manifest/test_models.py::TestExceptionEntryEnumFields -v`
Expected: PASS

- [ ] **Step 5: Run the full test suite to check for regressions**

Run: `uv run pytest -x -q`
Expected: All tests pass. The `__post_init__` coercion means all existing call sites that pass strings still work. StrEnum comparison with strings (`entry.rule == "PY-WL-004"`) also still works.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/manifest/models.py tests/unit/manifest/test_models.py
git commit -m "feat: convert ExceptionEntry fields from str to StrEnum types"
```

### Task 4: Convert DependencyTaintEntry.returns_taint to TaintState

**Files:**
- Modify: `src/wardline/manifest/models.py:95-102`

- [ ] **Step 1: Write failing test**

Add to `tests/unit/manifest/test_models.py`:

```python
class TestDependencyTaintEntryEnumFields:
    def test_returns_taint_coerced_to_enum(self) -> None:
        entry = DependencyTaintEntry(
            package="requests",
            function="requests.get",
            returns_taint="EXTERNAL_RAW",
            rationale="HTTP response is external",
        )
        assert isinstance(entry.returns_taint, TaintState)
        assert entry.returns_taint == "EXTERNAL_RAW"

    def test_invalid_returns_taint_raises(self) -> None:
        import pytest
        with pytest.raises(ValueError, match="BOGUS"):
            DependencyTaintEntry(
                package="requests",
                function="requests.get",
                returns_taint="BOGUS",
                rationale="test",
            )
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/manifest/test_models.py::TestDependencyTaintEntryEnumFields -v`
Expected: FAIL

- [ ] **Step 3: Update DependencyTaintEntry**

```python
@dataclass(frozen=True)
class DependencyTaintEntry:
    """A dependency taint declaration for a third-party function."""

    package: str
    function: str
    returns_taint: TaintState
    rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.returns_taint, TaintState):
            object.__setattr__(self, "returns_taint", TaintState(self.returns_taint))
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/unit/manifest/test_models.py::TestDependencyTaintEntryEnumFields -v`
Expected: PASS

- [ ] **Step 5: Run full suite**

Run: `uv run pytest -x -q`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/wardline/manifest/models.py tests/unit/manifest/test_models.py
git commit -m "feat: convert DependencyTaintEntry.returns_taint to TaintState"
```

### Task 5: Remove redundant enum conversions at consumption sites

**Files:**
- Modify: `src/wardline/manifest/exceptions.py:91-94`

- [ ] **Step 1: Simplify _validate_not_unconditional**

The existing code at lines 91-94 does:
```python
try:
    rule_id = RuleId(entry.rule)
    taint = TaintState(entry.taint_state)
except ValueError:
```

After Task 3, `entry.rule` is already a `RuleId` and `entry.taint_state` is already a `TaintState`. The `__post_init__` coercion validates at construction time, so the try/except is now dead code.

**Behavior change:** Previously, exceptions with unknown rule IDs (e.g., from a future version) would load silently and skip validation. Now they fail at construction with `ValueError`. This is intentional for v1.0 API freeze — exceptions.json should only reference known rules.

Simplify to:

```python
    rule_id = entry.rule
    taint = entry.taint_state
```

Remove the `try/except ValueError` block wrapping these lines and the early return inside it.

- [ ] **Step 2: Run validation tests**

Run: `uv run pytest tests/unit/manifest/test_exceptions.py -v`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add src/wardline/manifest/exceptions.py
git commit -m "refactor: remove redundant enum conversion in exception validation"
```

### Task 6: Clean up TYPE_CHECKING imports in models.py

**Files:**
- Modify: `src/wardline/manifest/models.py:17-23`

- [ ] **Step 1: Remove RuleId and TaintState from TYPE_CHECKING block**

After Task 3, these are runtime imports. Check if the `TYPE_CHECKING` block still has any imports — if empty, remove the block and the `TYPE_CHECKING` import from typing.

The current block is:
```python
if TYPE_CHECKING:
    from wardline.core.severity import RuleId
    from wardline.core.taints import TaintState
```

Both are now imported at runtime (Task 3). Remove the entire `if TYPE_CHECKING:` block. If `TYPE_CHECKING` is no longer used anywhere in the file, also remove it from the `typing` import.

- [ ] **Step 2: Run lint and type check**

Run: `uv run ruff check src/wardline/manifest/models.py && uv run mypy src/wardline/manifest/models.py`
Expected: Clean

- [ ] **Step 3: Run full suite**

Run: `uv run pytest -x -q`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add src/wardline/manifest/models.py
git commit -m "refactor: remove stale TYPE_CHECKING imports from models.py"
```
