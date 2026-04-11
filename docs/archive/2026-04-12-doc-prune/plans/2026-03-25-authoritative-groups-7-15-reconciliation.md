# Groups 7-15 Decorator Reconciliation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reconcile Wardline’s decorator registry and public decorator library for authoritative Groups 7-15 so the exported names, group assignments, and parameter surfaces match `docs/wardline/wardline-02-A-python-binding.md`.

**Architecture:** Keep the existing “registry is source of truth, decorators are thin wrappers” design. Execute the reconciliation in two slices: first replace legacy bool-marker decorators with the binding’s authoritative no-arg names, then add the parameterized decorator factories needed for Groups 9, 11, 13, and 15. Preserve `operations.py` as the shared Group 9/10 module, restore `sensitivity.py` for Group 11, and remove legacy names rather than carrying compatibility aliases.

**Tech Stack:** Python 3.12+, `pytest`, `ruff`, `mypy`, Wardline decorator factory in `src/wardline/decorators/_base.py`

**Prerequisites:**
- Read `docs/wardline/wardline-02-A-python-binding.md`, especially §A.4.2 and the “Which groups share decorators and why” note.
- Start from a clean-enough worktree to distinguish this task’s edits from the already-landed Group 10 / SCN-021 changes.
- Use targeted test runs after each slice; do not wait until the end to discover registry/export drift.

---

## Current Codebase Reality

The current codebase diverges from the binding in these concrete ways:

- `src/wardline/core/registry.py` still defines legacy names for Groups 7, 9, 11, 13, and 14:
  `fail_safe`, `fail_secure`, `graceful_degradation`, `retry_safe`, `nondeterministic`, `requires_auth`, `requires_role`, `deprecated_boundary`, `experimental`
- `src/wardline/decorators/__init__.py` still exports those legacy names publicly.
- There is no current implementation for these authoritative decorators:
  `parse_at_init`, `atomic`, `compensatable`, `handles_pii`, `handles_classified`, `declassifies`, `time_dependent`, `ordered_after`, `not_reentrant`, `requires_identity`, `privileged_operation`, `test_only`, `deprecated_by`, `feature_gated`
- Group numbering is currently wrong for determinism, concurrency, access, and lifecycle:
  `deterministic`/`nondeterministic` are in Group 11 instead of 12;
  `thread_safe`/`process_safe` are in Group 12 instead of 13;
  `requires_auth`/`requires_role` are in Group 13 instead of 14;
  `deprecated_boundary`/`experimental` are in Group 14 instead of 15.
- `tests/unit/scanner/test_registry_sync.py`, `tests/unit/core/test_registry.py`, and the per-module decorator tests encode the old surface and will need to be updated first or in lockstep.

This plan intentionally stops at **surface reconciliation**. Scanner semantics for those new decorators belong to `wardline-watcher-ba24663e49`.

## Target Binding Surface

Per `docs/wardline/wardline-02-A-python-binding.md`, the authoritative Groups 7-15 surface is:

- Group 7: `parse_at_init`
- Group 8: `handles_secrets`
- Group 9: `idempotent`, `atomic`, `compensatable(rollback=fn)`
- Group 10: `fail_closed`, `fail_open`, `emits_or_explains`, `exception_boundary`, `must_propagate`, `preserve_cause`
- Group 11: `handles_pii(fields=[...])`, `handles_classified(level=str)`, `declassifies(from_level=str, to_level=str)`
- Group 12: `deterministic`, `time_dependent`
- Group 13: `thread_safe`, `ordered_after(name)`, `not_reentrant`
- Group 14: `requires_identity`, `privileged_operation`
- Group 15: `test_only`, `deprecated_by(date=str, replacement=str)`, `feature_gated(flag=str)`

## Implementation Notes Before Starting

- `wardline_decorator()` already supports zero-arg decorators and validates registry membership.
- Parameterized decorators should be implemented as thin factories that call `wardline_decorator(...)` internally and return the produced decorator.
- Discovery already supports `@decorator(args)` because `_resolve_decorator()` unwraps `ast.Call`; no parser changes are needed for this task.
- For parameterized decorators, store immutable/simple runtime attributes on the wrapped function:
  - `compensatable(rollback=fn)` → `_wardline_compensatable=True`, `_wardline_rollback=<callable>`
  - `handles_pii(fields=[...])` → `_wardline_handles_pii=True`, `_wardline_pii_fields=tuple[str, ...]`
  - `handles_classified(level=...)` → `_wardline_handles_classified=True`, `_wardline_classification_level=str`
  - `declassifies(from_level=..., to_level=...)` → `_wardline_declassifies=True`, `_wardline_from_level=str`, `_wardline_to_level=str`
  - `ordered_after(name)` → `_wardline_ordered_after=str`
  - `deprecated_by(date=..., replacement=...)` → `_wardline_deprecated_by=True`, `_wardline_deprecation_date=str`, `_wardline_replacement=str`
  - `feature_gated(flag=...)` → `_wardline_feature_gated=True`, `_wardline_feature_flag=str`
- `RegistryEntry.attrs` should reflect those attribute types exactly so `tests/unit/scanner/test_registry_sync.py` continues to exercise the contract.

### Task 1: Lock the Authoritative Contract in Tests First

**Files:**
- Modify: `tests/unit/core/test_registry.py`
- Modify: `tests/unit/scanner/test_registry_sync.py`
- Modify: `tests/integration/test_scan_cmd.py` only if implemented-rules assertions need count/name updates from new rule loading or registry churn

**Step 1: Write the failing registry contract tests**

Add explicit per-group expectations for Groups 7-15 in `tests/unit/core/test_registry.py`:

```python
def test_groups_7_to_15_match_authoritative_binding() -> None:
    expected = {
        7: {"parse_at_init"},
        8: {"handles_secrets"},
        9: {"idempotent", "atomic", "compensatable"},
        10: {
            "emits_or_explains",
            "exception_boundary",
            "fail_closed",
            "fail_open",
            "must_propagate",
            "preserve_cause",
        },
        11: {"handles_pii", "handles_classified", "declassifies"},
        12: {"deterministic", "time_dependent"},
        13: {"thread_safe", "ordered_after", "not_reentrant"},
        14: {"requires_identity", "privileged_operation"},
        15: {"test_only", "deprecated_by", "feature_gated"},
    }
    for group, names in expected.items():
        registered = {
            name for name, entry in REGISTRY.items() if entry.group == group
        }
        assert registered == names
```

Also update the total count assertion to the post-reconciliation number:

```python
def test_total_count() -> None:
    assert len(REGISTRY) == 40
```

**Why this test:** It gives an immediate, binding-derived failure signal and prevents partial renames from silently passing.

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/core/test_registry.py -q`

Expected output:

```text
FAILED tests/unit/core/test_registry.py::test_groups_7_to_15_match_authoritative_binding
```

**Step 3: Tighten the registry sync harness around parameterized attrs**

Extend `tests/unit/scanner/test_registry_sync.py` only as needed so it still validates parameterized decorators correctly. The current generic `@dec` test should continue to work if the parameterized exports are represented by zero-arg wrappers for the sync harness, or if the harness grows a small per-name factory map like:

```python
_DECORATOR_FACTORIES: dict[str, Any] = {
    "compensatable": operations.compensatable(rollback=lambda exc: None),
    "handles_pii": sensitivity.handles_pii(fields=["email"]),
    "handles_classified": sensitivity.handles_classified(level="PROTECTED"),
    "declassifies": sensitivity.declassifies("SECRET", "PROTECTED"),
    "ordered_after": concurrency.ordered_after("bootstrap"),
    "deprecated_by": lifecycle.deprecated_by("2026-12-31", "new_api"),
    "feature_gated": lifecycle.feature_gated("flag-name"),
}
```

Then, in the generic attr/type test, prefer the factory map when present.

**Why this change:** The existing registry-sync test assumes every export is a direct decorator. That assumption becomes false once Groups 9, 11, 13, and 15 gain argument-bearing decorators.

**Step 4: Run the focused sync tests to verify red**

Run: `uv run pytest tests/unit/scanner/test_registry_sync.py -q`

Expected output:

```text
FAILED ... Registry entry 'parse_at_init' has no matching library export
```

**Definition of Done:**
- [ ] `tests/unit/core/test_registry.py` asserts the authoritative Groups 7-15 surface
- [ ] `tests/unit/scanner/test_registry_sync.py` is ready for parameterized decorators
- [ ] Both targeted tests fail for the right reason before implementation starts

### Task 2: Replace Legacy Zero-Arg Decorators with Authoritative Zero-Arg Decorators

**Files:**
- Modify: `src/wardline/core/registry.py`
- Modify: `src/wardline/decorators/safety.py`
- Modify: `src/wardline/decorators/secrets.py`
- Modify: `src/wardline/decorators/determinism.py`
- Modify: `src/wardline/decorators/concurrency.py`
- Modify: `src/wardline/decorators/access.py`
- Modify: `src/wardline/decorators/lifecycle.py`
- Modify: `src/wardline/decorators/__init__.py`
- Modify: `tests/unit/decorators/test_safety.py`
- Modify: `tests/unit/decorators/test_secrets.py`
- Modify: `tests/unit/decorators/test_determinism.py`
- Modify: `tests/unit/decorators/test_concurrency.py`
- Modify: `tests/unit/decorators/test_access.py`
- Modify: `tests/unit/decorators/test_lifecycle.py`

**Step 1: Implement the zero-arg canonical replacements in registry and modules**

Make these substitutions:

- Group 7 in `src/wardline/core/registry.py`:

```python
"parse_at_init": _bool_entry("parse_at_init", 7),
```

- Group 8:

```python
"handles_secrets": _bool_entry("handles_secrets", 8),
```

- Group 12:

```python
"deterministic": _bool_entry("deterministic", 12),
"time_dependent": _bool_entry("time_dependent", 12),
```

- Group 13:

```python
"thread_safe": _bool_entry("thread_safe", 13),
"not_reentrant": _bool_entry("not_reentrant", 13),
```

- Group 14:

```python
"requires_identity": _bool_entry("requires_identity", 14),
"privileged_operation": _bool_entry("privileged_operation", 14),
```

- Group 15:

```python
"test_only": _bool_entry("test_only", 15),
```

Update module implementations similarly. Example for `src/wardline/decorators/determinism.py`:

```python
__all__ = ["deterministic", "time_dependent"]

deterministic = wardline_decorator(
    12,
    "deterministic",
    _wardline_deterministic=True,
)

time_dependent = wardline_decorator(
    12,
    "time_dependent",
    _wardline_time_dependent=True,
)
```

**Why minimal:** This gets the no-arg part of the binding surface into place before mixing in parameter factories.

**Step 2: Update package exports to remove legacy names**

Update `src/wardline/decorators/__init__.py` to export:

- `parse_at_init` instead of `fail_safe`, `fail_secure`, `graceful_degradation`
- `time_dependent` instead of `nondeterministic`
- `not_reentrant` instead of `process_safe`
- `requires_identity`, `privileged_operation` instead of `requires_auth`, `requires_role`
- `test_only` instead of `deprecated_boundary`, `experimental`

Do not keep aliases for the legacy names.

**Step 3: Rewrite the matching per-module tests**

Replace old tests such as `TestFailSafe`, `TestRequiresAuth`, and `TestExperimental` with the authoritative names. Example:

```python
from wardline.decorators.access import privileged_operation, requires_identity

class TestRequiresIdentity:
    def test_sets_requires_identity_attr(self) -> None:
        @requires_identity
        def f() -> int:
            return 1

        assert f._wardline_requires_identity is True  # type: ignore[attr-defined]
        assert 14 in f._wardline_groups  # type: ignore[attr-defined]
```

**Step 4: Run the zero-arg decorator slice**

Run:

```bash
uv run pytest \
  tests/unit/core/test_registry.py \
  tests/unit/decorators/test_safety.py \
  tests/unit/decorators/test_secrets.py \
  tests/unit/decorators/test_determinism.py \
  tests/unit/decorators/test_concurrency.py \
  tests/unit/decorators/test_access.py \
  tests/unit/decorators/test_lifecycle.py
```

Expected output:

```text
PASSED
```

**Step 5: Commit**

```bash
git add \
  src/wardline/core/registry.py \
  src/wardline/decorators/__init__.py \
  src/wardline/decorators/safety.py \
  src/wardline/decorators/secrets.py \
  src/wardline/decorators/determinism.py \
  src/wardline/decorators/concurrency.py \
  src/wardline/decorators/access.py \
  src/wardline/decorators/lifecycle.py \
  tests/unit/core/test_registry.py \
  tests/unit/decorators/test_safety.py \
  tests/unit/decorators/test_secrets.py \
  tests/unit/decorators/test_determinism.py \
  tests/unit/decorators/test_concurrency.py \
  tests/unit/decorators/test_access.py \
  tests/unit/decorators/test_lifecycle.py
git commit -m "feat: reconcile zero-arg decorators for groups 7-15"
```

**Definition of Done:**
- [ ] Legacy zero-arg names are removed from registry and package exports
- [ ] Authoritative zero-arg replacements exist with correct group numbers
- [ ] Per-module tests use the authoritative names only

### Task 3: Add Parameterized Decorator Factories for Groups 9, 11, 13, and 15

**Files:**
- Modify: `src/wardline/core/registry.py`
- Modify: `src/wardline/decorators/operations.py`
- Create: `src/wardline/decorators/sensitivity.py`
- Modify: `src/wardline/decorators/concurrency.py`
- Modify: `src/wardline/decorators/lifecycle.py`
- Modify: `src/wardline/decorators/__init__.py`
- Modify: `tests/unit/decorators/test_operations.py`
- Create: `tests/unit/decorators/test_sensitivity.py`
- Modify: `tests/unit/decorators/test_concurrency.py`
- Modify: `tests/unit/decorators/test_lifecycle.py`

**Step 1: Extend the registry with the parameterized surface**

Add entries like:

```python
"atomic": _bool_entry("atomic", 9),
"compensatable": RegistryEntry(
    canonical_name="compensatable",
    group=9,
    attrs={
        "_wardline_compensatable": bool,
        "_wardline_rollback": object,
    },
),
"handles_pii": RegistryEntry(
    canonical_name="handles_pii",
    group=11,
    attrs={
        "_wardline_handles_pii": bool,
        "_wardline_pii_fields": tuple,
    },
),
```

Continue similarly for:

- `handles_classified`
- `declassifies`
- `ordered_after`
- `deprecated_by`
- `feature_gated`

**Why this shape:** It preserves the existing registry contract style while making argument-bearing decorators explicit and testable.

**Step 2: Implement thin parameterized decorators**

Example in `src/wardline/decorators/operations.py`:

```python
def compensatable(*, rollback: object) -> object:
    return wardline_decorator(
        9,
        "compensatable",
        _wardline_compensatable=True,
        _wardline_rollback=rollback,
    )
```

Example in `src/wardline/decorators/sensitivity.py`:

```python
def handles_pii(*, fields: list[str] | tuple[str, ...]) -> object:
    return wardline_decorator(
        11,
        "handles_pii",
        _wardline_handles_pii=True,
        _wardline_pii_fields=tuple(fields),
    )
```

Example in `src/wardline/decorators/lifecycle.py`:

```python
def deprecated_by(*, date: str, replacement: str) -> object:
    return wardline_decorator(
        15,
        "deprecated_by",
        _wardline_deprecated_by=True,
        _wardline_deprecation_date=date,
        _wardline_replacement=replacement,
    )
```

**Step 3: Place Group 11 in `sensitivity.py`**

Create `src/wardline/decorators/sensitivity.py` with:

- `handles_pii`
- `handles_classified`
- `declassifies`

Update `src/wardline/decorators/__init__.py` and `tests/unit/scanner/test_registry_sync.py` to import `sensitivity`.

**Why this file choice:** The binding explicitly calls out that Groups 8 and 11 share the sensitivity module space. Use that structure now instead of growing more mismatched module names.

**Step 4: Add dedicated tests for argument-bearing decorators**

Example for `tests/unit/decorators/test_sensitivity.py`:

```python
def test_handles_pii_sets_fields_tuple() -> None:
    @handles_pii(fields=["email", "name"])
    def f() -> int:
        return 1

    assert f._wardline_handles_pii is True  # type: ignore[attr-defined]
    assert f._wardline_pii_fields == ("email", "name")  # type: ignore[attr-defined]
    assert 11 in f._wardline_groups  # type: ignore[attr-defined]
```

Example for `tests/unit/decorators/test_operations.py`:

```python
def test_compensatable_sets_rollback_attr() -> None:
    def rollback(exc: Exception) -> None:
        return None

    @compensatable(rollback=rollback)
    def f() -> int:
        return 1

    assert f._wardline_compensatable is True  # type: ignore[attr-defined]
    assert f._wardline_rollback is rollback  # type: ignore[attr-defined]
```

**Step 5: Run the parameterized slice**

Run:

```bash
uv run pytest \
  tests/unit/decorators/test_operations.py \
  tests/unit/decorators/test_sensitivity.py \
  tests/unit/decorators/test_concurrency.py \
  tests/unit/decorators/test_lifecycle.py \
  tests/unit/scanner/test_registry_sync.py
```

Expected output:

```text
PASSED
```

**Step 6: Commit**

```bash
git add \
  src/wardline/core/registry.py \
  src/wardline/decorators/operations.py \
  src/wardline/decorators/sensitivity.py \
  src/wardline/decorators/concurrency.py \
  src/wardline/decorators/lifecycle.py \
  src/wardline/decorators/__init__.py \
  tests/unit/decorators/test_operations.py \
  tests/unit/decorators/test_sensitivity.py \
  tests/unit/decorators/test_concurrency.py \
  tests/unit/decorators/test_lifecycle.py \
  tests/unit/scanner/test_registry_sync.py
git commit -m "feat: add parameterized decorators for authoritative groups 9 11 13 and 15"
```

**Definition of Done:**
- [ ] Parameterized decorators exist and stamp the right `_wardline_*` attrs
- [ ] Group 11 lives in `sensitivity.py`
- [ ] Registry sync tests know how to instantiate parameterized decorators

### Task 4: Remove Legacy Names Everywhere and Add Discovery Coverage for Called Decorators

**Files:**
- Modify: `src/wardline/decorators/__init__.py`
- Modify: `tests/unit/scanner/test_discovery.py`
- Modify: `tests/unit/decorators/test_decorators.py` only if helper references still mention removed names
- Modify: any remaining tests returned by `rg`

**Step 1: Remove all remaining legacy references**

Run:

```bash
rg -n "fail_safe|fail_secure|graceful_degradation|retry_safe|nondeterministic|requires_auth|requires_role|deprecated_boundary|experimental|process_safe|redacts_output" src tests
```

Expected output after cleanup:

```text
[no matches]
```

If any references remain in tests or helper comments, replace them with authoritative names from the same group.

**Step 2: Add discovery tests for parameterized imports**

Add to `tests/unit/scanner/test_discovery.py`:

```python
def test_called_decorator_resolves_from_submodule_import(self) -> None:
    tree = _parse(\"\"\"\
        from wardline.decorators.lifecycle import feature_gated
        @feature_gated(flag="beta")
        def handler(): pass
    \"\"\")
    result = discover_annotations(tree, "test.py")
    ann = result[("test.py", "handler")][0]
    assert ann.canonical_name == "feature_gated"
```

Also add an alias case:

```python
def test_called_decorator_alias_resolves(self) -> None:
    tree = _parse(\"\"\"\
        from wardline.decorators.operations import compensatable as comp
        @comp(rollback=rollback_fn)
        def handler(): pass
    \"\"\")
    result = discover_annotations(tree, "test.py")
    ann = result[("test.py", "handler")][0]
    assert ann.canonical_name == "compensatable"
```

**Why this test:** This task introduces many argument-bearing decorators; discovery needs explicit coverage proving that `@decorator(...)` still resolves through the import table.

**Step 3: Run the cleanup/discovery slice**

Run:

```bash
uv run pytest tests/unit/scanner/test_discovery.py tests/unit/scanner/test_registry_sync.py
```

Expected output:

```text
PASSED
```

**Definition of Done:**
- [ ] No legacy decorator names remain in source or tests
- [ ] Discovery has explicit coverage for authoritative parameterized decorators

### Task 5: Full Verification and Final Surface Audit

**Files:**
- Verify only; no intended code changes

**Step 1: Run the full decorator + registry test suite**

Run:

```bash
uv run pytest \
  tests/unit/core/test_registry.py \
  tests/unit/decorators/ \
  tests/unit/scanner/test_registry_sync.py \
  tests/unit/scanner/test_discovery.py
```

Expected output:

```text
PASSED
```

**Step 2: Run quality gates**

Run:

```bash
uv run ruff check src/wardline/core/registry.py src/wardline/decorators/ tests/unit/core/test_registry.py tests/unit/decorators/ tests/unit/scanner/test_registry_sync.py tests/unit/scanner/test_discovery.py
uv run mypy src/wardline/core/registry.py src/wardline/decorators/
```

Expected output:

```text
All checks passed!
Success: no issues found
```

**Step 3: Final audit of authoritative exports**

Run:

```bash
python - <<'PY'
from wardline.decorators import __all__
print(sorted(__all__))
PY
```

Expected output includes the authoritative Groups 7-15 names and excludes all legacy replacements:

```text
['all_fields_mapped', 'atomic', 'audit_critical', ..., 'time_dependent', ...]
```

**Step 4: Commit**

```bash
git add src/wardline/core/registry.py src/wardline/decorators/ tests/unit/core/test_registry.py tests/unit/decorators/ tests/unit/scanner/test_registry_sync.py tests/unit/scanner/test_discovery.py
git commit -m "feat: reconcile authoritative decorator surface for groups 7 through 15"
```

**Definition of Done:**
- [ ] Registry, exports, and per-module decorators match the authoritative binding for Groups 7-15
- [ ] Parameterized decorators are covered by unit tests and discovery tests
- [ ] Legacy names are fully removed
- [ ] `ruff`, `mypy`, and targeted `pytest` suites all pass

## Non-Goals

- Do not implement the scanner semantics for these decorators here; that belongs to `wardline-watcher-ba24663e49`.
- Do not broaden this task into Group 16 / Group 17 reconciliation.
- Do not add compatibility aliases for removed legacy names unless a concrete in-repo dependency is discovered during execution.

## Risks and Checkpoints

- **Risk:** Parameterized decorators break `test_registry_sync.py` because the harness assumes direct decorator callables.
  Mitigation: update the harness in Task 1 before touching implementation files.
- **Risk:** Group renumbering causes unexpected failures in tests that only assert `_wardline_groups`.
  Mitigation: run per-module test files immediately after each slice.
- **Risk:** Public module structure drifts from the binding again if Group 11 is bolted into an unrelated file.
  Mitigation: create `src/wardline/decorators/sensitivity.py` during Task 3 and import it centrally.
- **Checkpoint after Task 2:** zero-arg surface matches the binding and all legacy names are already gone.
- **Checkpoint after Task 3:** all missing parameterized decorators exist and registry sync passes.

Plan complete and saved to `docs/plans/2026-03-25-authoritative-groups-7-15-reconciliation.md`. Two execution options:

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task with code review between tasks for fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans for batch execution with checkpoints

Which approach?
