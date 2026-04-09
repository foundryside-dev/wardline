# Workstream E: Code Hardening

> **Purpose:** Spec and implementation plan for closing test coverage and code
> robustness gaps identified in the 2026-04-09 conformance review (R11, R12).
> Give this to an implementation agent. It is self-contained.

**Branch:** `phase-4.4-test-quality-gates`
**Conformance review:** `docs/requirements/spec-fitness/conformance-review-2026-04-09.md`

---

## 1. Problem Statement

The external conformance review identified 2 code hardening gaps — one test
coverage gap and one fragility issue in security-critical code.

| Finding | Severity | Description |
|---------|----------|-------------|
| R11 | MEDIUM | `resolve.py` and `regime.py` lack dedicated unit tests — governance-critical code covered only transitively |
| R12 | MEDIUM | `assert` exclusion in rejection path analysis is by omission, not explicit — fragile if someone adds Assert matching |

---

## 2. Normative Requirements

### 2.1 Test Coverage for Governance Code (R11)

`resolve.py` and `regime.py` are governance-critical modules:
- `resolve.py` discovers overlays, merges them with the manifest, and resolves
  boundaries, optional fields, and contract bindings
- `regime.py` collects governance health metrics (exception metrics, fingerprint
  metrics, manifest metrics, rule metrics)

Both are exercised transitively through CLI tests but their individual behaviors
— error handling, edge cases, metric calculations — are not directly verified.

### 2.2 Explicit Assert Exclusion (R12)

The spec §7.2 states:

> "The following do NOT constitute rejection paths: An assertion statement
> (`assert` in Python, Java `assert`) — assertions may be disabled at runtime
> (`-O` in Python, `-da` in Java) and do not provide a reliable rejection
> mechanism in production."

The current implementation correctly excludes `assert` but **by omission** —
`rejection_path.py` only checks for `ast.Raise` and `ast.Return`, never
`ast.Assert`. A future developer could add Assert matching thinking the code
is incomplete, breaking spec compliance.

---

## 3. Current State Audit

### 3.1 `resolve.py` (`src/wardline/manifest/resolve.py`, 188 lines)

**3 public functions:**

| Function | Lines | Dedicated Tests? |
|----------|-------|-----------------|
| `resolve_boundaries(root, manifest)` | 31-89 | YES — 12 tests in `test_resolve.py` |
| `resolve_optional_fields(root, manifest)` | 92-147 | NO |
| `resolve_contract_bindings(root, manifest)` | 150-187 | NO |

`resolve_optional_fields()` handles:
- Overlay discovery and field parsing
- Duplicate field detection (lines 128-143)
- Conflicting approved_default detection (lines 131-138)
- Scope assignment from overlay path (line 120)

`resolve_contract_bindings()` handles:
- Overlay discovery and binding collection
- Error handling for malformed overlays
- Scope assignment from overlay path

### 3.2 `regime.py` (`src/wardline/manifest/regime.py`, 262 lines)

**4 public functions:**

| Function | Lines | Dedicated Tests? | Coverage Depth |
|----------|-------|-----------------|----------------|
| `collect_exception_metrics(manifest_dir)` | 93-147 | YES — 3 tests | Shallow |
| `collect_fingerprint_metrics(manifest_dir)` | 150-182 | YES — 2 tests | Shallow |
| `collect_manifest_metrics(manifest_path)` | 185-226 | YES — 2 tests | Shallow |
| `collect_rule_metrics(manifest_path, config_path)` | 229-261 | YES — 2 tests | Shallow |

**Edge cases not covered:**

`collect_exception_metrics()`:
- Malformed expiry dates (ValueError handling, line 119)
- Mixed governance paths (standard + expedited)
- agent_originated with various governance paths
- Zero active exceptions (division edge)

`collect_fingerprint_metrics()`:
- Malformed JSON (JSONDecodeError handling, line 160)
- Malformed ISO datetime (ValueError handling, line 168)
- Missing coverage dict keys (lines 179-181)

`collect_manifest_metrics()`:
- Malformed ratification_date (ValueError handling, line 202)
- None review_interval_days (lines 204-205)
- Various temporal_separation values

`collect_rule_metrics()`:
- Exception handling (line 239)
- Non-canonical rule IDs in disabled_rules config

### 3.3 Rejection Path Analysis (`src/wardline/scanner/rejection_path.py`)

**`_branch_has_rejection_terminator()`** (lines 59-71):
```python
def _branch_has_rejection_terminator(stmts: list[ast.stmt]) -> bool:
    for stmt in stmts:
        for node in walk_skip_nested_defs(stmt):
            if isinstance(node, ast.Raise):
                return True
            if isinstance(node, ast.Return):
                return True
    return False
```

No mention of `ast.Assert`. No comment explaining the omission.

**`_has_rejection_path()`** (lines 106-123):
```python
def _has_rejection_path(node: ...) -> bool:
    """... A raise inside a trivially unreachable branch (``if False:``,
    ``if 0:``) is not counted as a rejection path per spec S7.2."""
    for child in walk_skip_nested_defs(node):
        if isinstance(child, ast.Raise) and not _is_inside_dead_branch(child, node):
            return True
        ...
```

Docstring mentions spec §7.2 for unreachable branches but NOT for assert
exclusion.

**Existing test:** `tests/unit/scanner/test_py_wl_008.py:146-155` —
`test_assert_still_fires` verifies that `assert` does not count as a rejection
path. The behavior IS tested, but the code itself is fragile.

---

## 4. Implementation Plan

### 4.1 Execution Order

```
R12 (assert exclusion)     ─── smallest, highest fragility risk
  │
R11 (resolve.py tests)    ─── independent
  │
R11 (regime.py tests)     ─── independent
```

### 4.2 R12: Explicit Assert Exclusion with Documentation

**Problem:** `ast.Assert` is excluded from rejection paths by omission. A
future developer could add it thinking the code is incomplete.

**Fix:** Add explicit comments and a guard clause. Three changes:

**File: `src/wardline/scanner/rejection_path.py`**

**Change 1:** In `_branch_has_rejection_terminator()` (lines 59-71), add a
comment after the isinstance checks:

```python
def _branch_has_rejection_terminator(stmts: list[ast.stmt]) -> bool:
    """Return True when the branch contains a terminating rejection action.

    Uses ``walk_skip_nested_defs`` so that a ``raise`` inside a nested
    function or class does not count as a rejection for the *outer* scope.

    ``ast.Assert`` is deliberately excluded — assertions may be disabled
    at runtime (``python -O``) and do not provide a reliable rejection
    mechanism in production (spec §7.2).
    """
    for stmt in stmts:
        for node in walk_skip_nested_defs(stmt):
            if isinstance(node, ast.Raise):
                return True
            if isinstance(node, ast.Return):
                return True
            # ast.Assert deliberately excluded — see docstring and spec §7.2.
    return False
```

**Change 2:** In `_has_rejection_path()` (lines 106-123), update the
docstring to mention assert exclusion:

```python
def _has_rejection_path(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True when the boundary body contains a structural rejection path.

    A raise inside a trivially unreachable branch (``if False:``, ``if 0:``)
    is not counted as a rejection path per spec §7.2.

    ``ast.Assert`` is deliberately excluded — assertions may be disabled
    at runtime (``python -O``) and are not a reliable rejection mechanism
    (spec §7.2).
    """
```

**Change 3:** Add a dedicated unit test in
`tests/unit/scanner/test_rejection_path.py` (create if needed, or add to
existing test file for rejection paths):

```python
def test_assert_not_counted_as_rejection_path() -> None:
    """Assert statements are NOT rejection paths (spec §7.2).

    Assertions can be disabled with python -O, so they do not provide
    a reliable rejection mechanism in production.
    """
    import ast
    from wardline.scanner.rejection_path import has_rejection_path

    code = """\
def validate(data):
    assert isinstance(data, dict)
    return data
"""
    tree = ast.parse(code)
    func = tree.body[0]
    # assert-only function has NO rejection path
    assert not has_rejection_path(func)
```

Also add the positive case:

```python
def test_raise_counted_as_rejection_path() -> None:
    """Raise statements ARE rejection paths."""
    import ast
    from wardline.scanner.rejection_path import has_rejection_path

    code = """\
def validate(data):
    if not isinstance(data, dict):
        raise TypeError("expected dict")
    return data
"""
    tree = ast.parse(code)
    func = tree.body[0]
    assert has_rejection_path(func)
```

**Tests:** The existing `test_assert_still_fires` in `test_py_wl_008.py`
tests this at the rule level. The new tests verify it at the rejection-path
analysis level — defense in depth.

**Commit:** `fix(R12): document assert exclusion in rejection path analysis (spec §7.2)`

### 4.3 R11: Dedicated Tests for `resolve.py`

**File: `tests/unit/manifest/test_resolve.py`** (extend existing file)

Add test classes for the two untested functions:

**`TestResolveOptionalFields`** — tests for `resolve_optional_fields()`:

```python
class TestResolveOptionalFields:
    """Tests for resolve_optional_fields()."""

    def test_no_overlays_returns_empty(self, tmp_path: Path) -> None:
        """No overlays discovered → empty tuple."""
        manifest = _make_manifest(tmp_path)
        result = resolve_optional_fields(tmp_path, manifest)
        assert result == ()

    def test_overlay_fields_returned_with_scope(self, tmp_path: Path) -> None:
        """Optional fields from overlay carry overlay_scope."""
        manifest = _make_manifest(tmp_path)
        _write_overlay(tmp_path / "src" / "api" / "wardline.overlay.yaml", {
            "overlay_for": "src/api",
            "optional_fields": [{
                "field": "timeout",
                "approved_default": "30",
                "rationale": "Network timeout default",
            }],
        })
        result = resolve_optional_fields(tmp_path, manifest)
        assert len(result) == 1
        assert result[0].field == "timeout"
        assert result[0].overlay_scope == "src/api"

    def test_duplicate_field_in_same_overlay_rejected(
        self, tmp_path: Path
    ) -> None:
        """Same field declared twice in one overlay raises."""
        manifest = _make_manifest(tmp_path)
        _write_overlay(tmp_path / "src" / "wardline.overlay.yaml", {
            "overlay_for": "src",
            "optional_fields": [
                {"field": "x", "approved_default": "1", "rationale": "r"},
                {"field": "x", "approved_default": "2", "rationale": "r"},
            ],
        })
        with pytest.raises(ManifestPolicyError, match="duplicate"):
            resolve_optional_fields(tmp_path, manifest)

    def test_conflicting_defaults_across_overlays_rejected(
        self, tmp_path: Path
    ) -> None:
        """Same field with different defaults across overlays raises."""
        manifest = _make_manifest(tmp_path)
        _write_overlay(tmp_path / "src/a" / "wardline.overlay.yaml", {
            "overlay_for": "src/a",
            "optional_fields": [
                {"field": "x", "approved_default": "1", "rationale": "r"},
            ],
        })
        _write_overlay(tmp_path / "src/b" / "wardline.overlay.yaml", {
            "overlay_for": "src/b",
            "optional_fields": [
                {"field": "x", "approved_default": "2", "rationale": "r"},
            ],
        })
        with pytest.raises(ManifestPolicyError, match="conflicting"):
            resolve_optional_fields(tmp_path, manifest)

    def test_bad_overlay_file_skipped(self, tmp_path: Path) -> None:
        """Malformed overlay YAML is skipped with logging, not crash."""
        manifest = _make_manifest(tmp_path)
        overlay_path = tmp_path / "src" / "wardline.overlay.yaml"
        overlay_path.parent.mkdir(parents=True, exist_ok=True)
        overlay_path.write_text("not: valid: yaml: [")
        result = resolve_optional_fields(tmp_path, manifest)
        assert result == ()
```

**`TestResolveContractBindings`** — tests for `resolve_contract_bindings()`:

```python
class TestResolveContractBindings:
    """Tests for resolve_contract_bindings()."""

    def test_no_overlays_returns_empty(self, tmp_path: Path) -> None:
        manifest = _make_manifest(tmp_path)
        result = resolve_contract_bindings(tmp_path, manifest)
        assert result == ()

    def test_bindings_returned_from_overlay(self, tmp_path: Path) -> None:
        manifest = _make_manifest(tmp_path)
        _write_overlay(tmp_path / "src" / "wardline.overlay.yaml", {
            "overlay_for": "src",
            "contract_bindings": [{
                "contract": "partner_feed",
                "boundary": "src.api.ingest:parse_feed",
                "data_tier": 4,
                "direction": "inbound",
            }],
        })
        result = resolve_contract_bindings(tmp_path, manifest)
        assert len(result) == 1
        assert result[0].contract == "partner_feed"

    def test_bad_overlay_skipped(self, tmp_path: Path) -> None:
        manifest = _make_manifest(tmp_path)
        overlay_path = tmp_path / "src" / "wardline.overlay.yaml"
        overlay_path.parent.mkdir(parents=True, exist_ok=True)
        overlay_path.write_text("{invalid")
        result = resolve_contract_bindings(tmp_path, manifest)
        assert result == ()
```

**Important:** Read the existing test file first to understand helper functions
(`_make_manifest`, `_write_overlay`, etc.). Follow the existing patterns
exactly. If these helpers don't exist, check how the existing
`TestResolveBoundaries` sets up test fixtures and follow the same approach.

**Commit:** `fix(R11): add dedicated tests for resolve_optional_fields and resolve_contract_bindings`

### 4.4 R11: Deepen Tests for `regime.py`

**File: `tests/unit/manifest/test_regime.py`** (extend existing file)

Add edge case tests to each existing test class. Read the existing tests
first to understand the fixture patterns.

**`TestCollectExceptionMetrics`** — add:

```python
def test_malformed_expiry_date_treated_as_active(
    self, tmp_path: Path
) -> None:
    """Exception with unparseable expiry is counted as active."""
    _write_exceptions(tmp_path, [{
        "id": "EX-001",
        "rule": "PY-WL-001",
        "taint_state": "INTEGRAL",
        "location": "src/core.py:10:process",
        "exceptionability": "STANDARD",
        "severity_at_grant": "ERROR",
        "rationale": "test",
        "reviewer": "test",
        "expires": "not-a-date",
    }])
    metrics = collect_exception_metrics(tmp_path)
    assert metrics.total == 1
    assert metrics.active == 1  # unparseable → treated as active

def test_zero_exceptions_returns_zero_ratios(
    self, tmp_path: Path
) -> None:
    """Empty exception register produces zero counts and ratios."""
    _write_exceptions(tmp_path, [])
    metrics = collect_exception_metrics(tmp_path)
    assert metrics.total == 0
    assert metrics.active == 0
    assert metrics.expedited_ratio == 0.0

def test_mixed_governance_paths(self, tmp_path: Path) -> None:
    """Multiple governance paths are all tracked."""
    _write_exceptions(tmp_path, [
        _make_exception("EX-1", governance_path="standard"),
        _make_exception("EX-2", governance_path="expedited"),
        _make_exception("EX-3", governance_path="standard"),
    ])
    metrics = collect_exception_metrics(tmp_path)
    assert metrics.total == 3
    assert "standard" in metrics.governance_paths
    assert "expedited" in metrics.governance_paths
```

**`TestCollectFingerprintMetrics`** — add:

```python
def test_missing_baseline_returns_not_present(
    self, tmp_path: Path
) -> None:
    """No fingerprint file → present=False."""
    metrics = collect_fingerprint_metrics(tmp_path)
    assert metrics.present is False
    assert metrics.age_days is None
    assert metrics.coverage_ratio is None

def test_malformed_json_returns_not_present(
    self, tmp_path: Path
) -> None:
    """Corrupt JSON → present=False, no crash."""
    (tmp_path / "wardline.fingerprint.json").write_text("{invalid")
    metrics = collect_fingerprint_metrics(tmp_path)
    assert metrics.present is False

def test_malformed_datetime_returns_none_age(
    self, tmp_path: Path
) -> None:
    """Valid JSON with bad datetime → present=True, age_days=None."""
    (tmp_path / "wardline.fingerprint.json").write_text(
        '{"generated_at": "not-a-date", "coverage": {"ratio": 0.5}}'
    )
    metrics = collect_fingerprint_metrics(tmp_path)
    assert metrics.present is True
    assert metrics.age_days is None
    assert metrics.coverage_ratio == 0.5
```

**`TestCollectManifestMetrics`** — add:

```python
def test_malformed_ratification_date(self, tmp_path: Path) -> None:
    """Bad ratification date → age_days=None, not crash."""
    _write_manifest(tmp_path, ratification_date="not-a-date")
    metrics = collect_manifest_metrics(tmp_path / "wardline.yaml")
    assert metrics.age_days is None
    assert metrics.ratification_overdue is False

def test_no_review_interval(self, tmp_path: Path) -> None:
    """Missing review_interval_days → ratification never overdue."""
    _write_manifest(tmp_path, review_interval_days=None)
    metrics = collect_manifest_metrics(tmp_path / "wardline.yaml")
    assert metrics.ratification_overdue is False
```

**`TestCollectRuleMetrics`** — add:

```python
def test_no_config_file(self, tmp_path: Path) -> None:
    """Missing wardline.toml → all rules active."""
    _write_manifest(tmp_path)
    metrics = collect_rule_metrics(
        tmp_path / "wardline.yaml",
        tmp_path / "wardline.toml",
    )
    assert metrics.disabled_rules == 0

def test_disabled_unconditional_rule_flagged(
    self, tmp_path: Path
) -> None:
    """Disabling a rule with UNCONDITIONAL cells is tracked."""
    _write_manifest(tmp_path)
    _write_config(tmp_path, disabled_rules=["PY-WL-001"])
    metrics = collect_rule_metrics(
        tmp_path / "wardline.yaml",
        tmp_path / "wardline.toml",
    )
    assert metrics.disabled_unconditional > 0
```

**Important:** Read the existing test file to understand helper functions and
fixture patterns. The tests above are templates — adapt them to match the
actual helper function signatures and fixture setup used in the file. Create
helper functions like `_write_exceptions()`, `_make_exception()`,
`_write_manifest()`, `_write_config()` if they don't exist, following the
patterns already established.

**Commit:** `fix(R11): deepen regime.py unit tests — edge cases and error handling`

---

## 5. Correctness Constraints

1. **R12 is documentation + defense, not behavior change.** The assert
   exclusion already works correctly. The fix adds comments, docstring
   updates, and a focused unit test — it does not change runtime behavior.

2. **R11 tests must be independent.** Each test must set up its own fixtures
   (tmp_path) and not depend on other tests' state. Follow the existing
   pattern of per-test fixture creation.

3. **R11 tests for error handling must verify graceful degradation.** When
   `regime.py` encounters malformed data (bad dates, corrupt JSON, missing
   files), it should return safe defaults — not crash. Tests verify this.

4. **Helper functions follow existing patterns.** Don't invent new fixture
   patterns — read the existing test files and follow what's there.

---

## 6. Testing Strategy

| Fix | Test Location | What |
|-----|--------------|------|
| R12 | `tests/unit/scanner/test_rejection_path.py` | Assert exclusion at analysis level |
| R11 | `tests/unit/manifest/test_resolve.py` | `resolve_optional_fields`, `resolve_contract_bindings` |
| R11 | `tests/unit/manifest/test_regime.py` | Edge cases for all 4 collection functions |
| All | `uv run pytest` | Full suite still passes |

---

## 7. Key Files Reference

| File | Purpose |
|------|---------|
| `src/wardline/scanner/rejection_path.py:59-71` | `_branch_has_rejection_terminator()` — add assert comment |
| `src/wardline/scanner/rejection_path.py:106-123` | `_has_rejection_path()` — update docstring |
| `src/wardline/manifest/resolve.py:92-187` | Two untested public functions |
| `src/wardline/manifest/regime.py:93-261` | Four shallowly-tested public functions |
| `tests/unit/manifest/test_resolve.py` | Extend with 2 new test classes |
| `tests/unit/manifest/test_regime.py` | Extend with edge case tests |
| `tests/unit/scanner/test_py_wl_008.py:146-155` | Existing assert test (rule level) |
| `docs/spec/wardline-01-07-pattern-rules.md:42-44` | Normative assert exclusion |

---

## 8. Code Conventions

- `from __future__ import annotations` everywhere
- Explicit `ValueError` over `assert` (survives `python -O`)
- Ruff line length: 140. Target: Python 3.12+
- mypy strict mode with `warn_return_any`
- Test files: one class per logical group, `test_` prefix on all methods

---

## 9. Commit Strategy

3 commits:

1. `fix(R12): document assert exclusion in rejection path analysis (spec §7.2)`
2. `fix(R11): add dedicated tests for resolve_optional_fields and resolve_contract_bindings`
3. `fix(R11): deepen regime.py unit tests — edge cases and error handling`

---

## 10. Status Protocol

Report after each fix: DONE, DONE_WITH_CONCERNS, NEEDS_CONTEXT, or BLOCKED.
