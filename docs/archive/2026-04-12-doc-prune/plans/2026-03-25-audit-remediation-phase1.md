# Audit Remediation Phase 1: Correctness & Test Foundation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the body evaluation taint map bug, expand SCN-021 test coverage to all 29 combinations, add parametrized severity matrix cell tests for all 9 rules, and fix PY-WL-006 TryStar deduplication.

**Architecture:** Split `DECORATOR_TAINT_MAP` into `BODY_EVAL_TAINT` (for rule severity lookup) and `RETURN_TAINT` (for taint propagation). Add parametrized test infrastructure for matrix cells. Clean up SCN-021 duplicate entry.

**Tech Stack:** Python 3.12+, pytest, ast module, wardline scanner framework

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `src/wardline/scanner/taint/function_level.py` | Split DECORATOR_TAINT_MAP into BODY_EVAL_TAINT + RETURN_TAINT |
| Modify | `src/wardline/scanner/taint/callgraph_propagation.py` | Use RETURN_TAINT for callee resolution in L3 |
| Modify | `src/wardline/scanner/engine.py` | Pass both taint maps through the pipeline |
| Create | `tests/unit/scanner/taint/__init__.py` | Package init for taint test directory |
| Create | `tests/unit/scanner/taint/test_body_eval_taint.py` | Body eval + return taint verification tests |
| Modify | `src/wardline/scanner/rules/scn_021.py` | Remove duplicate entry #19 |
| Modify | `src/wardline/scanner/rules/py_wl_006.py` | Add TryStar deduplication |
| Create | `tests/unit/scanner/test_matrix_cells.py` | 72 parametrized matrix cell tests |
| Modify | `tests/unit/scanner/test_scn_021.py` | Expand to all 28 combinations + negatives |
| Modify | `tests/unit/scanner/test_py_wl_006.py` | Add TryStar dedup test |
| Modify | `tests/unit/scanner/test_py_wl_003.py` | Update for corrected body taint |
| Modify | `tests/unit/scanner/test_py_wl_007.py` | Update for corrected body taint |
| Modify | `tests/unit/scanner/test_py_wl_008.py` | Update for corrected body taint |
| Modify | `tests/unit/scanner/test_py_wl_009.py` | Update for corrected body taint |

---

### Task 1: Split DECORATOR_TAINT_MAP (CF-1)

**Files:**
- Modify: `src/wardline/scanner/taint/function_level.py:36-49,141-162`
- Modify: `src/wardline/scanner/taint/callgraph_propagation.py:~190` (L3 callee taint lookup)
- Modify: `src/wardline/scanner/engine.py:~196` (pass return_taint_map to L3)

**Critical context — two maps needed for two purposes:**
- `BODY_EVAL_TAINT`: drives `function_level_taint_map` in ScanContext → rules use it for severity lookup. Validators evaluate at the INPUT tier.
- `RETURN_TAINT`: drives L3 callgraph propagation → when computing a caller's taint from its callees, use the callee's RETURN taint (output tier), not its body eval taint. Without this, callers of `@validates_shape` would see EXTERNAL_RAW instead of SHAPE_VALIDATED, making them appear more untrusted than they should be.

- [ ] **Step 1: Write failing test for body evaluation taint**

Create `tests/unit/scanner/taint/__init__.py` (empty) and `tests/unit/scanner/taint/test_body_eval_taint.py`:

```python
"""Verify body evaluation taint matches spec §A.4.3."""

from __future__ import annotations

import ast

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.context import WardlineAnnotation
from wardline.scanner.taint.function_level import assign_function_taints


@pytest.mark.parametrize(
    "decorator,expected_body_taint",
    [
        ("validates_shape", TaintState.EXTERNAL_RAW),
        ("validates_external", TaintState.EXTERNAL_RAW),
        ("validates_semantic", TaintState.SHAPE_VALIDATED),
        ("tier1_read", TaintState.AUDIT_TRAIL),
        ("audit_writer", TaintState.AUDIT_TRAIL),
        ("authoritative_construction", TaintState.AUDIT_TRAIL),
        ("external_boundary", TaintState.EXTERNAL_RAW),
    ],
)
def test_body_eval_taint(decorator: str, expected_body_taint: TaintState) -> None:
    code = f"@{decorator}\ndef target(): pass"
    tree = ast.parse(code)
    annotations = {
        ("test.py", "target"): [
            WardlineAnnotation(canonical_name=decorator, group=1, attrs={})
        ]
    }
    body_map, return_map, _ = assign_function_taints(tree, "test.py", annotations)
    assert body_map["target"] == expected_body_taint


@pytest.mark.parametrize(
    "decorator,expected_return_taint",
    [
        ("validates_shape", TaintState.SHAPE_VALIDATED),
        ("validates_external", TaintState.PIPELINE),
        ("validates_semantic", TaintState.PIPELINE),
        ("tier1_read", TaintState.AUDIT_TRAIL),
        ("audit_writer", TaintState.AUDIT_TRAIL),
        ("authoritative_construction", TaintState.AUDIT_TRAIL),
        ("external_boundary", TaintState.EXTERNAL_RAW),
    ],
)
def test_return_taint(decorator: str, expected_return_taint: TaintState) -> None:
    code = f"@{decorator}\ndef target(): pass"
    tree = ast.parse(code)
    annotations = {
        ("test.py", "target"): [
            WardlineAnnotation(canonical_name=decorator, group=1, attrs={})
        ]
    }
    body_map, return_map, _ = assign_function_taints(tree, "test.py", annotations)
    assert return_map["target"] == expected_return_taint
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/scanner/taint/test_body_eval_taint.py -v`
Expected: FAIL — `assign_function_taints` doesn't return 3 values yet

- [ ] **Step 3: Split DECORATOR_TAINT_MAP into two maps**

In `src/wardline/scanner/taint/function_level.py`, replace lines 36-49:

```python
# ── Decorator → TaintState mappings ──────────────────────────────
#
# Body evaluation taint: the taint state rules evaluate at INSIDE
# the function body. Per spec §A.4.3, validators evaluate at the
# INPUT tier (the data they receive), not the OUTPUT tier.
BODY_EVAL_TAINT: dict[str, TaintState] = {
    "external_boundary": TaintState.EXTERNAL_RAW,
    "validates_shape": TaintState.EXTERNAL_RAW,      # input: T4
    "validates_semantic": TaintState.SHAPE_VALIDATED,  # input: T3
    "validates_external": TaintState.EXTERNAL_RAW,     # input: T4
    "tier1_read": TaintState.AUDIT_TRAIL,
    "audit_writer": TaintState.AUDIT_TRAIL,
    "authoritative_construction": TaintState.AUDIT_TRAIL,
}

# Return value taint: the taint state assigned to the function's
# return value for propagation to callers. This is the OUTPUT tier.
RETURN_TAINT: dict[str, TaintState] = {
    "external_boundary": TaintState.EXTERNAL_RAW,
    "validates_shape": TaintState.SHAPE_VALIDATED,     # output: T3
    "validates_semantic": TaintState.PIPELINE,          # output: T2
    "validates_external": TaintState.PIPELINE,          # output: T2
    "tier1_read": TaintState.AUDIT_TRAIL,
    "audit_writer": TaintState.AUDIT_TRAIL,
    "authoritative_construction": TaintState.AUDIT_TRAIL,
}

# Backward-compatible alias for explain_cmd.py and other importers.
DECORATOR_TAINT_MAP = BODY_EVAL_TAINT
```

- [ ] **Step 4: Update taint_from_annotations to accept a taint map parameter**

Replace the `taint_from_annotations` function:

```python
def taint_from_annotations(
    file_path: str,
    qualname: str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    taint_map: dict[str, TaintState] | None = None,
) -> TaintState | None:
    """Resolve taint from decorator annotations.

    Args:
        taint_map: Which map to look up. Defaults to BODY_EVAL_TAINT.
    """
    if taint_map is None:
        taint_map = BODY_EVAL_TAINT

    key = (file_path, qualname)
    anns = annotations.get(key)
    if not anns:
        return None

    for ann in anns:
        taint = taint_map.get(ann.canonical_name)
        if taint is not None:
            return taint

    return None
```

- [ ] **Step 5: Update assign_function_taints to return both maps**

Update the function signature and `_walk_and_assign` to produce both body and return taint maps:

```python
def assign_function_taints(
    tree: ast.Module,
    file_path: Path | str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    manifest: WardlineManifest | None = None,
) -> tuple[dict[str, TaintState], dict[str, TaintState], dict[str, TaintSource]]:
    """Assign taint states to every function in a parsed module.

    Returns:
        Tuple of (body_taint_map, return_taint_map, taint_sources).
    """
    path_str = str(file_path)
    module_default = resolve_module_default(path_str, manifest)
    body_taint_map: dict[str, TaintState] = {}
    return_taint_map: dict[str, TaintState] = {}
    taint_sources: dict[str, TaintSource] = {}

    _walk_and_assign(
        tree, path_str, annotations, module_default,
        body_taint_map, return_taint_map, taint_sources, scope="",
    )

    return body_taint_map, return_taint_map, taint_sources
```

Update `_walk_and_assign` to populate both maps — the body map uses `BODY_EVAL_TAINT`, the return map uses `RETURN_TAINT`. For non-decorator functions (module default or fallback), both maps get the same value.

- [ ] **Step 6: Update the engine to use both maps**

In `src/wardline/scanner/engine.py` (~line 190-209), update the call to `assign_function_taints` to receive both maps. Pass `body_taint_map` to `ScanContext.function_level_taint_map` and `return_taint_map` to L3 propagation.

The engine flow becomes:
```python
body_taint_map, return_taint_map, taint_sources = assign_function_taints(...)

# L3 propagation uses return_taint_map for callee resolution
if self._analysis_level >= 3:
    body_taint_map, taint_provenance = self._run_callgraph_taint(
        tree, body_taint_map, return_taint_map, taint_sources, file_path, result
    )

# ScanContext gets body_taint_map for rule severity lookup
ctx = ScanContext(
    file_path=str(file_path),
    function_level_taint_map=body_taint_map,
    ...
)
```

Update `_run_callgraph_taint` to accept the return_taint_map and pass it through to `propagate_callgraph_taints`.

- [ ] **Step 7: Update L3 callgraph propagation to use return taints for callee resolution**

In `src/wardline/scanner/taint/callgraph_propagation.py`, update `propagate_callgraph_taints` to accept a `return_taint_map` parameter. At line ~190 where it looks up callee taints:

```python
# For each callee, use return_taint if available (decorator-anchored),
# otherwise fall back to the callee's body_taint (L1/L3 computed).
callee_taint = return_taint_map.get(c, current[c])
callee_ranks = [TRUST_RANK[return_taint_map.get(c, current[c])] for c in callee_set]
```

This ensures callers of `@validates_shape` see SHAPE_VALIDATED (return taint) not EXTERNAL_RAW (body taint).

- [ ] **Step 8: Run tests to verify the fix**

Run: `uv run pytest tests/unit/scanner/taint/test_body_eval_taint.py -v`
Expected: 14/14 PASS (7 body + 7 return)

- [ ] **Step 9: Run full test suite and fix broken tests**

Run: `uv run pytest tests/ -x --tb=short`

Fix failures in the affected test files:
- `tests/unit/scanner/test_py_wl_003.py`
- `tests/unit/scanner/test_py_wl_007.py`
- `tests/unit/scanner/test_py_wl_008.py`
- `tests/unit/scanner/test_py_wl_009.py`
- `tests/integration/test_scan_cmd.py`
- `tests/unit/scanner/taint/` (any existing function_level tests)

Direction of change: tests asserting findings inside validator bodies at SHAPE_VALIDATED or PIPELINE severity will need to assert EXTERNAL_RAW or SHAPE_VALIDATED severity instead. Tests asserting return value taint or L3 caller taint should be unchanged.

- [ ] **Step 10: Run full suite green**

Run: `uv run pytest tests/ --tb=short`
Expected: all pass

- [ ] **Step 11: Run linter and type checker**

Run: `uv run ruff check src/wardline/scanner/taint/ src/wardline/scanner/engine.py && uv run mypy src/wardline/scanner/taint/ src/wardline/scanner/engine.py`
Expected: clean

- [ ] **Step 12: Commit**

```bash
git add src/wardline/scanner/taint/function_level.py src/wardline/scanner/taint/callgraph_propagation.py src/wardline/scanner/engine.py
git add tests/unit/scanner/taint/
git add -u  # pick up test file updates
git commit -m "fix(scanner): split DECORATOR_TAINT_MAP into body eval + return taint

Validators now evaluate pattern rules at the INPUT tier (the data
they receive), not the OUTPUT tier. Per spec §A.4.3:
- @validates_shape body: EXTERNAL_RAW (was SHAPE_VALIDATED)
- @validates_semantic body: SHAPE_VALIDATED (was PIPELINE)
- @validates_external body: EXTERNAL_RAW (was PIPELINE)

Return value taints unchanged — L3 callgraph propagation uses
RETURN_TAINT for callee resolution, ensuring callers of validators
see the correct output taint.

Fixes CF-1 from 35-agent conformance audit."
```

---

### Task 2: Remove SCN-021 duplicate entry (HC-5)

**Files:**
- Modify: `src/wardline/scanner/rules/scn_021.py:73`

- [ ] **Step 1: Write failing test that asserts exactly 1 finding for the alias pair**

Add to `tests/unit/scanner/test_scn_021.py`:

```python
class TestAliasPairDedup:
    def test_fail_open_audit_critical_produces_one_finding(self) -> None:
        """Entry #5 and #19 are the same pair — must produce exactly 1 finding."""
        rule = _run_rule(
            """\
@fail_open
@audit_critical
def target():
    return 1
""",
            annotations=("fail_open", "audit_critical"),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/scanner/test_scn_021.py::TestAliasPairDedup -v`
Expected: FAIL — `assert 2 == 1` (duplicate entry produces 2 findings)

- [ ] **Step 3: Remove duplicate entry #19**

In `src/wardline/scanner/rules/scn_021.py`, remove line 73:
```python
    _CombinationSpec("audit_critical", "fail_open", _CONTRADICTORY, "Audit-critical paths must not have fallback paths"),
```

Replace with a comment:
```python
    # Spec entry #19 (audit_critical + fail_open) is an alias of #5 — removed to prevent duplicate findings.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/scanner/test_scn_021.py::TestAliasPairDedup -v`
Expected: PASS

- [ ] **Step 5: Run full SCN-021 tests**

Run: `uv run pytest tests/unit/scanner/test_scn_021.py -v`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/rules/scn_021.py tests/unit/scanner/test_scn_021.py
git commit -m "fix(scanner): remove SCN-021 duplicate entry #19 (alias of #5)

fail_open + audit_critical appeared twice in _COMBINATIONS, producing
2 findings for 1 violation. Removed the reversed duplicate.

Fixes HC-5 from 35-agent conformance audit."
```

---

### Task 3: SCN-021 full test coverage (CF-2)

**Files:**
- Modify: `tests/unit/scanner/test_scn_021.py`

- [ ] **Step 1: Add parametrized test for all combinations**

Add to `tests/unit/scanner/test_scn_021.py`:

```python
import pytest
from wardline.core.severity import Exceptionability
from wardline.scanner.rules.scn_021 import _COMBINATIONS


class TestAllCombinations:
    @pytest.mark.parametrize(
        "spec",
        _COMBINATIONS,
        ids=[f"{s.left}+{s.right}" for s in _COMBINATIONS],
    )
    def test_combination_fires(self, spec) -> None:
        """Every entry in _COMBINATIONS must produce exactly 1 finding."""
        rule = _run_rule(
            f"""\
@{spec.left}
@{spec.right}
def target():
    return 1
""",
            annotations=(spec.left, spec.right),
        )
        findings = [f for f in rule.findings if f.rule_id == RuleId.SCN_021]
        assert len(findings) == 1, (
            f"Expected 1 finding for {spec.left}+{spec.right}, got {len(findings)}"
        )
        assert findings[0].severity == spec.severity
        assert findings[0].exceptionability == Exceptionability.UNCONDITIONAL


class TestNegativeCombinations:
    @pytest.mark.parametrize(
        "left,right",
        [
            ("fail_closed", "deterministic"),
            ("atomic", "fail_closed"),
            ("handles_pii", "tier1_read"),
            ("thread_safe", "atomic"),
            ("test_only", "deprecated_by"),
            ("handles_secrets", "thread_safe"),
        ],
        ids=[f"{l}+{r}" for l, r in [
            ("fail_closed", "deterministic"),
            ("atomic", "fail_closed"),
            ("handles_pii", "tier1_read"),
            ("thread_safe", "atomic"),
            ("test_only", "deprecated_by"),
            ("handles_secrets", "thread_safe"),
        ]],
    )
    def test_valid_combination_does_not_fire(self, left: str, right: str) -> None:
        rule = _run_rule(
            f"""\
@{left}
@{right}
def target():
    return 1
""",
            annotations=(left, right),
        )
        scn_findings = [f for f in rule.findings if f.rule_id == RuleId.SCN_021]
        assert len(scn_findings) == 0, (
            f"Valid combination {left}+{right} should not fire SCN-021"
        )
```

- [ ] **Step 2: Add Exceptionability import**

Make sure the import at the top of the test file includes `Exceptionability`:
```python
from wardline.core.severity import Exceptionability, RuleId, Severity
```

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/unit/scanner/test_scn_021.py -v`
Expected: 28 parametrized positive tests + 6 negative tests + existing tests = all pass

- [ ] **Step 4: Commit**

```bash
git add tests/unit/scanner/test_scn_021.py
git commit -m "test(scanner): expand SCN-021 to all 28 combinations + 6 negatives

Parametrized test covering every entry in _COMBINATIONS with
severity and exceptionability assertions. Adds 6 negative cases
for valid decorator combinations that must not fire.

Fixes CF-2 from 35-agent conformance audit."
```

---

### Task 4: PY-WL-006 TryStar deduplication (HC-10)

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_006.py:203-227`
- Modify: `tests/unit/scanner/test_py_wl_006.py`

- [ ] **Step 1: Write failing test for TryStar dedup**

Add to `tests/unit/scanner/test_py_wl_006.py`:

```python
class TestTryStarDedup:
    def test_except_star_audit_call_produces_one_finding(self) -> None:
        """except* handler with audit call must produce exactly 1 finding, not 2."""
        rule = _run_rule(
            """\
try:
    do_work()
except* ValueError as eg:
    audit.emit(eg)
""",
        )
        masking_findings = [
            f for f in rule.findings
            if "broad exception handler" in f.message.lower()
        ]
        assert len(masking_findings) == 1
```

Adapt `_run_rule` if the existing helper doesn't support this pattern (it should since it just parses and runs).

- [ ] **Step 2: Run test — may pass or fail depending on current behavior**

Run: `uv run pytest tests/unit/scanner/test_py_wl_006.py::TestTryStarDedup -v`

If it already passes (because `walk_skip_nested_defs` only yields each node once), note this and still add the dedup for safety. If it fails with count > 1, proceed to fix.

- [ ] **Step 3: Add TryStar deduplication to visit_function**

In `src/wardline/scanner/rules/py_wl_006.py`, restructure `visit_function` to use the PY-WL-004 pattern. Replace the handler walk (lines ~210-227) with:

```python
    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Check broad-handler masking and local success-path audit bypasses."""
        # ── Pass 1: collect TryStar handler IDs and process them ──
        _TryStar = getattr(ast, "TryStar", None)
        trystar_handlers: set[int] = set()
        if _TryStar is not None:
            for child in walk_skip_nested_defs(node):
                if isinstance(child, _TryStar):
                    for handler in child.handlers:
                        trystar_handlers.add(id(handler))
                        self._check_broad_handler_for_audit(handler)

        # ── Pass 2: process non-TryStar handlers ──
        for child in walk_skip_nested_defs(node):
            if (
                isinstance(child, ast.ExceptHandler)
                and id(child) not in trystar_handlers
            ):
                self._check_broad_handler_for_audit(child)

        # ── Dominance analysis (unchanged) ──
        if not _has_normal_path_audit(node.body, self._local_audit_names):
            return
        # ... rest of dominance analysis unchanged ...
```

Extract the handler-checking logic (lines 210-227) into a `_check_broad_handler_for_audit` method:

```python
    def _check_broad_handler_for_audit(self, handler: ast.ExceptHandler) -> None:
        if not _is_broad_handler(handler):
            return
        for handler_node in ast.walk(handler):
            if (
                isinstance(handler_node, ast.Call)
                and _is_audit_call(handler_node, self._local_audit_names)
            ):
                self._emit_finding(
                    handler_node,
                    (
                        "Audit-critical write in broad exception handler — "
                        "if the write fails, the broad handler masks the failure"
                    ),
                )
```

- [ ] **Step 4: Run test to verify**

Run: `uv run pytest tests/unit/scanner/test_py_wl_006.py -v`
Expected: all pass including TryStar test

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/rules/py_wl_006.py tests/unit/scanner/test_py_wl_006.py
git commit -m "fix(scanner): add TryStar dedup to PY-WL-006

Matches the dedup pattern already in PY-WL-004 and PY-WL-005 to
prevent duplicate findings for audit calls in except* handlers.

Fixes HC-10 from 35-agent conformance audit."
```

---

### Task 5: Parametrized matrix cell tests (HC-1)

**Files:**
- Create: `tests/unit/scanner/test_matrix_cells.py`

- [ ] **Step 1: Create the test infrastructure and first rule's tests**

Create `tests/unit/scanner/test_matrix_cells.py`:

```python
"""Parametrized severity matrix cell tests for all 9 binding rules.

Each test injects a specific taint state via ScanContext and verifies
the resulting (severity, exceptionability) pair matches the spec §7.3
severity matrix. This is the conformance safety net — a regression in
matrix.py data will be caught by these tests.

72 test cases total: 9 rules × 8 taint states.
"""

from __future__ import annotations

import ast

import pytest

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState
from wardline.scanner.context import ScanContext

from .conftest import parse_function_source

# ── Aliases for readability ──
E = Severity.ERROR
W = Severity.WARNING
Su = Severity.SUPPRESS
U = Exceptionability.UNCONDITIONAL
St = Exceptionability.STANDARD
R = Exceptionability.RELAXED
T = Exceptionability.TRANSPARENT

# Taint states in canonical matrix column order
TAINT_STATES = [
    TaintState.AUDIT_TRAIL,
    TaintState.PIPELINE,
    TaintState.SHAPE_VALIDATED,
    TaintState.EXTERNAL_RAW,
    TaintState.UNKNOWN_RAW,
    TaintState.UNKNOWN_SHAPE_VALIDATED,
    TaintState.UNKNOWN_SEM_VALIDATED,
    TaintState.MIXED_RAW,
]

# ── Spec §7.3 severity matrix (authoritative reference) ──
MATRIX = {
    RuleId.PY_WL_001: [(E,U),(E,St),(E,St),(E,St),(E,St),(E,St),(E,St),(E,St)],
    RuleId.PY_WL_002: [(E,U),(E,St),(E,St),(E,St),(E,St),(E,St),(E,St),(E,St)],
    RuleId.PY_WL_003: [(E,U),(E,U),(E,U),(E,St),(E,St),(E,U),(E,U),(E,St)],
    RuleId.PY_WL_004: [(E,U),(E,St),(W,St),(W,R),(E,St),(W,St),(W,St),(E,St)],
    RuleId.PY_WL_005: [(E,U),(E,St),(E,St),(E,St),(E,St),(E,St),(E,St),(E,St)],
    RuleId.PY_WL_006: [(E,U),(E,U),(E,St),(E,St),(E,St),(E,St),(E,St),(E,St)],
    RuleId.PY_WL_007: [(E,St),(W,R),(W,R),(Su,T),(Su,T),(W,R),(W,R),(W,St)],
    RuleId.PY_WL_008: [(E,U),(E,U),(E,U),(E,U),(E,U),(E,U),(E,U),(E,U)],
    RuleId.PY_WL_009: [(E,U),(E,U),(E,U),(E,U),(E,U),(E,U),(E,U),(E,U)],
}

# ── Minimal triggering code snippets per rule ──
# Each snippet must trigger the rule when placed inside a function body.
# Written to trigger in any taint context (no boundary decorators).
TRIGGER_SNIPPETS = {
    RuleId.PY_WL_001: 'd.get("key", "default")',
    RuleId.PY_WL_002: 'getattr(obj, "attr", "default")',
    RuleId.PY_WL_003: '"key" in d',
    RuleId.PY_WL_004: "try:\n    x = 1\nexcept Exception:\n    pass",
    RuleId.PY_WL_005: "try:\n    x = 1\nexcept Exception:\n    pass",
    RuleId.PY_WL_007: "isinstance(data, dict)",
}

# Rules that need special handling (boundary declarations, etc.)
# are tested with dedicated fixtures below, not the generic runner.


def _run_with_taint(rule_cls, rule_id: RuleId, taint: TaintState):
    """Run a rule with injected taint and return findings."""
    snippet = TRIGGER_SNIPPETS.get(rule_id)
    if snippet is None:
        pytest.skip(f"No trigger snippet for {rule_id}")

    tree = parse_function_source(snippet)
    ctx = ScanContext(
        file_path="test.py",
        function_level_taint_map={"target": taint},
    )
    rule = rule_cls(file_path="test.py")
    rule.set_context(ctx)
    rule.visit(tree)
    return [f for f in rule.findings if f.rule_id == rule_id]


def _make_params(rule_id: RuleId):
    """Generate pytest parametrize args for a rule's matrix row."""
    row = MATRIX[rule_id]
    return [
        pytest.param(
            TAINT_STATES[i], sev, exc,
            id=f"{TAINT_STATES[i].value}_{sev.value}_{exc.value}",
        )
        for i, (sev, exc) in enumerate(row)
    ]


# ── Import rule classes ──
from wardline.scanner.rules.py_wl_001 import RulePyWl001
from wardline.scanner.rules.py_wl_002 import RulePyWl002
from wardline.scanner.rules.py_wl_003 import RulePyWl003
from wardline.scanner.rules.py_wl_004 import RulePyWl004
from wardline.scanner.rules.py_wl_005 import RulePyWl005
from wardline.scanner.rules.py_wl_007 import RulePyWl007


class TestPyWl001MatrixCells:
    @pytest.mark.parametrize("taint,sev,exc", _make_params(RuleId.PY_WL_001))
    def test_cell(self, taint, sev, exc) -> None:
        findings = _run_with_taint(RulePyWl001, RuleId.PY_WL_001, taint)
        assert len(findings) >= 1, f"Expected finding at {taint}"
        assert findings[0].severity == sev
        assert findings[0].exceptionability == exc


class TestPyWl002MatrixCells:
    @pytest.mark.parametrize("taint,sev,exc", _make_params(RuleId.PY_WL_002))
    def test_cell(self, taint, sev, exc) -> None:
        findings = _run_with_taint(RulePyWl002, RuleId.PY_WL_002, taint)
        assert len(findings) >= 1, f"Expected finding at {taint}"
        assert findings[0].severity == sev
        assert findings[0].exceptionability == exc


class TestPyWl003MatrixCells:
    @pytest.mark.parametrize("taint,sev,exc", _make_params(RuleId.PY_WL_003))
    def test_cell(self, taint, sev, exc) -> None:
        findings = _run_with_taint(RulePyWl003, RuleId.PY_WL_003, taint)
        assert len(findings) >= 1, f"Expected finding at {taint}"
        assert findings[0].severity == sev
        assert findings[0].exceptionability == exc


class TestPyWl004MatrixCells:
    @pytest.mark.parametrize("taint,sev,exc", _make_params(RuleId.PY_WL_004))
    def test_cell(self, taint, sev, exc) -> None:
        findings = _run_with_taint(RulePyWl004, RuleId.PY_WL_004, taint)
        assert len(findings) >= 1, f"Expected finding at {taint}"
        assert findings[0].severity == sev
        assert findings[0].exceptionability == exc


class TestPyWl005MatrixCells:
    @pytest.mark.parametrize("taint,sev,exc", _make_params(RuleId.PY_WL_005))
    def test_cell(self, taint, sev, exc) -> None:
        findings = _run_with_taint(RulePyWl005, RuleId.PY_WL_005, taint)
        assert len(findings) >= 1, f"Expected finding at {taint}"
        assert findings[0].severity == sev
        assert findings[0].exceptionability == exc


class TestPyWl007MatrixCells:
    @pytest.mark.parametrize("taint,sev,exc", _make_params(RuleId.PY_WL_007))
    def test_cell(self, taint, sev, exc) -> None:
        findings = _run_with_taint(RulePyWl007, RuleId.PY_WL_007, taint)
        if sev == Su:
            # SUPPRESS cells: finding emitted at SUPPRESS severity
            assert len(findings) >= 1, f"Expected SUPPRESS finding at {taint}"
            assert findings[0].severity == Su
            assert findings[0].exceptionability == T
        else:
            assert len(findings) >= 1, f"Expected finding at {taint}"
            assert findings[0].severity == sev
            assert findings[0].exceptionability == exc
```

Note: PY-WL-006, PY-WL-008, PY-WL-009 require special fixtures (boundary declarations, audit decorators). Add these as dedicated test classes below the generic ones. The implementer should:
- For PY-WL-006: create a snippet with an audit call inside a broad handler, using the `_local_audit_names` mechanism
- For PY-WL-008: create a snippet with a boundary decorator and no rejection path, using boundary context
- For PY-WL-009: create a snippet with a semantic boundary and no shape evidence, using boundary context

Each of these 3 rules has 8 uniform E/U cells, so the tests can use a simpler assertion pattern.

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/unit/scanner/test_matrix_cells.py -v`
Expected: 48+ tests pass (6 rules × 8 taint states via generic runner)

- [ ] **Step 3: Add PY-WL-006, PY-WL-008, PY-WL-009 matrix cell tests**

Add dedicated test classes for the 3 rules that need boundary/audit context. Each needs 8 parametrized cases. Total: 24 additional tests.

The implementer should study how existing tests for these rules set up ScanContext with boundaries and audit decorators, then replicate that setup with injected taint states.

- [ ] **Step 4: Run full matrix cell test suite**

Run: `uv run pytest tests/unit/scanner/test_matrix_cells.py -v`
Expected: 72 tests pass (9 rules × 8 taint states)

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest tests/ --tb=short`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add tests/unit/scanner/test_matrix_cells.py
git commit -m "test(scanner): add 72 parametrized severity matrix cell tests

Each of the 9 binding rules (PY-WL-001 through PY-WL-009) is tested
across all 8 taint states, verifying the (severity, exceptionability)
pair matches the spec §7.3 matrix. This is the conformance safety
net that the 35-agent audit identified as systemically missing.

Fixes HC-1 from 35-agent conformance audit."
```

---

### Task 6: Final verification

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ -v --tb=short`
Expected: all pass

- [ ] **Step 2: Run linter**

Run: `uv run ruff check src/ tests/`
Expected: clean

- [ ] **Step 3: Run type checker**

Run: `uv run mypy src/wardline/`
Expected: clean

- [ ] **Step 4: Verify success criteria**

Check against spec success criteria:
- [ ] `@validates_shape` body evaluates at EXTERNAL_RAW (verified by test_body_eval_taint)
- [ ] `@validates_semantic` body evaluates at SHAPE_VALIDATED (verified by test_body_eval_taint)
- [ ] `@validates_external` body evaluates at EXTERNAL_RAW (verified by test_body_eval_taint)
- [ ] Return value taints unchanged (verified by existing L2/L3 tests)
- [ ] SCN-021 has 28 combination tests + 6 negatives (verified by test_scn_021)
- [ ] 72 matrix cell tests pass (verified by test_matrix_cells)
- [ ] PY-WL-006 TryStar dedup works (verified by test_py_wl_006)
