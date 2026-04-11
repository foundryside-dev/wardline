# PY-WL-006 Audit-Path Dominance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend `PY-WL-006` from audit-sink detection inside broad handlers to local audit-path dominance analysis that flags successful fallback/control-flow paths which can bypass required audit.

**Architecture:** Keep the current audit-sink classifier in `PY-WL-006`, but add a small intra-function control-flow pass over function bodies. The pass should answer a Wardline-specific question: "Can this function reach a success outcome without passing through an audit node?" Scope stays local to a single function body; decorator-aware callees count as audit nodes, but no interprocedural graph is required in the first implementation.

**Tech Stack:** Python 3.12+, `ast`, existing Wardline scanner rule infrastructure, current `PY-WL-006` tests/corpus

**Prerequisites:**
- Current narrowed `PY-WL-006` behavior is in place in `src/wardline/scanner/rules/py_wl_006.py`
- Binding language in `docs/wardline/wardline-02-A-python-binding.md` remains authoritative:
  - "`@audit_writer` ... Audit must dominate telemetry on shared execution paths. Fallback paths that bypass the audit call produce a finding."
  - "`@audit_critical` ... Superset of `@audit_writer` — call sites must not have fallback paths that skip the audit call."

---

## Task 1: Lock the Intended Semantics with Failing Tests

**Files:**
- Modify: `tests/unit/scanner/test_py_wl_006.py`
- Docs: `docs/wardline/wardline-02-A-python-binding.md`

**Step 1: Add unit tests for dominance-style failures**

Add tests that currently fail against the existing implementation:

```python
def test_success_branch_without_audit_fires() -> None:
    rule = _run_rule(
        """\
if ok:
    audit.emit("success", data)
    return result
return cached_result
"""
    )

    assert len(rule.findings) == 1


def test_broad_handler_fallback_success_without_audit_fires() -> None:
    rule = _run_rule(
        """\
try:
    process(data)
except Exception:
    return cached_result
audit.emit("processed", data)
return result
"""
    )

    assert len(rule.findings) == 1
```

**Why these tests:** They encode the spec gap directly: the function can complete successfully on a path that never passes through audit.

**Step 2: Add unit tests for acceptable non-success exits**

```python
def test_rejection_path_without_audit_is_allowed() -> None:
    rule = _run_rule(
        """\
if not ok:
    raise ValueError("bad")
audit.emit("success", data)
return result
"""
    )

    assert len(rule.findings) == 0


def test_fallback_raise_without_audit_is_allowed() -> None:
    rule = _run_rule(
        """\
try:
    process(data)
except Exception:
    raise
audit.emit("processed", data)
return result
"""
    )

    assert len(rule.findings) == 0
```

**Why these tests:** Wardline cares about success-without-audit, not all exit paths indiscriminately. Rejecting or re-raising is not the same defect.

**Step 3: Add decorator-aware audit-call coverage**

```python
def test_local_audit_writer_dominates_success_paths() -> None:
    rule = _run_rule_module(
        """\
@audit_writer
def write_audit(data):
    return None

def target():
    if skip:
        return result
    write_audit(data)
    return result
"""
    )

    assert len(rule.findings) == 1
```

**Step 4: Run tests to verify RED**

Run:

```bash
uv run pytest tests/unit/scanner/test_py_wl_006.py -q
```

Expected output:

```text
FAILED tests/unit/scanner/test_py_wl_006.py::...
```

**Definition of Done:**
- [ ] Dominance-style failure scenarios are encoded in tests
- [ ] Allowed raise/reject exits are encoded in tests
- [ ] At least one new test fails for the right reason against current code

---

## Task 2: Extract Audit-Node Classification into Reusable Helpers

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_006.py`
- Test: `tests/unit/scanner/test_py_wl_006.py`

**Step 1: Isolate the current sink-classification logic**

Refactor the existing logic into helpers that can be reused by both:
- the existing broad-handler scan
- the new control-flow pass

Keep or introduce helpers like:

```python
def _collect_local_audit_names(node: ast.Module) -> frozenset[str]:
    ...


def _is_audit_call(call: ast.Call, local_audit_names: frozenset[str]) -> bool:
    ...
```

**Why this refactor:** The dominance pass should reuse the exact same audit-node vocabulary as the current rule, not invent a second inconsistent detector.

**Step 2: Keep current behavior green**

Run:

```bash
uv run pytest tests/unit/scanner/test_py_wl_006.py -q
```

Expected output at this stage:
- Existing audit-in-broad-handler tests still pass
- New dominance tests still fail

**Definition of Done:**
- [ ] Audit sink detection is factored into reusable helpers
- [ ] No behavior change yet for existing positive/negative tests
- [ ] New dominance tests remain red

---

## Task 3: Add a Minimal Intra-Function Success-Path Analyzer

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_006.py`
- Test: `tests/unit/scanner/test_py_wl_006.py`

**Step 1: Introduce a path-state walker**

Implement a local recursive analyzer over `list[ast.stmt]` that tracks:
- whether audit has been seen on the current path
- whether the path can terminate in success (`return`, fallthrough)
- whether the path terminates exceptionally (`raise`)

Suggested internal shape:

```python
@dataclass(frozen=True)
class _PathState:
    audited: bool
    success_without_audit: bool = False
    success_with_audit: bool = False
    exceptional_exit: bool = False


def _analyze_block(
    stmts: list[ast.stmt],
    *,
    audited: bool,
    local_audit_names: frozenset[str],
) -> _PathState:
    ...
```

**Scope for first version:**
- `Expr(Call(...))`
- assignment statements that contain calls
- `if` / `elif` / `else`
- `try` / `except` / `else` / `finally`
- `return`
- `raise`

Do **not** include loops in the first pass. Treat them conservatively later once the base model is correct.

**Step 2: Define success outcomes conservatively**

Success exits in v1:
- `return <value>`
- normal fallthrough to function end

Not success exits in v1:
- `raise`
- explicit rejection branches that terminate exceptionally

**Step 3: Define the key predicate**

Flag when:

```python
analysis.success_without_audit is True
```

That is the Wardline question: can the function complete successfully on any path that has not passed through an audit node?

**Step 4: Run the focused tests**

Run:

```bash
uv run pytest tests/unit/scanner/test_py_wl_006.py -q
```

Expected output:

```text
PASSED
```

**Definition of Done:**
- [ ] A local path analyzer exists inside `PY-WL-006`
- [ ] It distinguishes success exits from exceptional exits
- [ ] Dominance-style tests pass

---

## Task 4: Integrate Dominance Findings with Existing Broad-Handler Detection

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_006.py`
- Test: `tests/unit/scanner/test_py_wl_006.py`

**Step 1: Decide how the two checks compose**

Keep both sub-checks under `PY-WL-006`:
- Existing check: audit-critical write inside broad exception handler
- New check: success path can bypass audit

Recommended integration:
- keep one finding per distinct offending site/path root
- use different messages under the same rule ID

Example message for dominance:

```python
message=(
    "Audit-critical path has a success/fallback branch that can bypass audit"
)
```

**Step 2: Choose finding locations**

Use the most local control-flow node that introduces the bypass:
- the `if` node for branch-skips-audit
- the `except` handler or fallback `return` for handler-based bypass

This keeps SARIF locations reviewable.

**Step 3: Prevent duplicate findings**

Guard against emitting both:
- one finding on the bypassing `except`
- one second finding on a nested call already covered by the broad-handler check

Rule of thumb for v1:
- handler-contained audit-call masking stays as-is
- success-without-audit emits only for the bypassing control-flow node

**Step 4: Re-run tests**

Run:

```bash
uv run pytest tests/unit/scanner/test_py_wl_006.py -q
```

**Definition of Done:**
- [ ] `PY-WL-006` handles both masking and bypass cases
- [ ] Findings are located on useful control-flow nodes
- [ ] Duplicate findings are avoided

---

## Task 5: Expand Coverage for Tricky Control-Flow Shapes

**Files:**
- Modify: `tests/unit/scanner/test_py_wl_006.py`
- Modify: `corpus/specimens/PY-WL-006/...`

**Step 1: Add branch-shape regression tests**

Cover:
- audit in one branch only
- audit after `try/except`, but `except` returns success
- `try/except/else` where only `else` is audited
- nested `if` inside `except`
- local `@audit_writer` callee used as the audit node

**Step 2: Add negative tests**

Cover:
- all success paths audited
- failure path raises, success path audited
- telemetry-only code still silent
- specific exception handlers still silent unless a success bypass exists

**Step 3: Add corpus specimens**

Suggested specimen set:
- `branch_success_bypasses_audit/positive`
- `raise_fallback_allowed/negative`
- `handler_returns_success_without_audit/positive`
- `all_success_paths_audited/negative`

**Step 4: Verify corpus**

Run:

```bash
uv run wardline corpus verify --corpus-dir corpus/specimens/PY-WL-006
```

**Definition of Done:**
- [ ] New unit tests cover branch and handler edge cases
- [ ] Corpus captures at least one positive and one negative dominance case
- [ ] Corpus verification passes

---

## Task 6: Lint, Type-Check, and Document the Boundaries of the Analysis

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_006.py`
- Modify: `tests/unit/scanner/test_py_wl_006.py`
- Docs: `docs/reviews/...` or audit notes if desired

**Step 1: Clean up rule comments/docstrings**

Document explicitly that v1 audit dominance is:
- intra-function only
- decorator-aware for local audit callees
- not interprocedural
- conservative about exceptional exits
- not loop-sensitive yet

**Step 2: Run the full targeted verification set**

Run:

```bash
uv run pytest tests/unit/scanner/test_py_wl_006.py tests/unit/scanner/test_corpus_runner.py -q
uv run ruff check src/wardline/scanner/rules/py_wl_006.py tests/unit/scanner/test_py_wl_006.py
python -m compileall src/wardline
```

Expected output:

```text
PASSED
All checks passed!
```

**Step 3: Optional broader confidence slice**

Run:

```bash
uv run pytest tests/unit/scanner -q
```

**Definition of Done:**
- [ ] Rule docstring states the exact analysis boundary
- [ ] Targeted tests pass
- [ ] Ruff passes
- [ ] Compile step passes

---

## Design Notes

### Why this plan stops at local dominance

The authoritative binding text requires audit dominance on shared execution paths and bans fallback paths that skip audit, but the first implementation does not need whole-program dataflow. A local path analysis over one function body captures the highest-signal cases while keeping the rule maintainable and auditable.

### Explicit non-goals for v1

- No interprocedural dominance beyond treating known audit callees as audit nodes
- No loop fixed-point analysis
- No exception-propagation authorization modeling
- No attempt to infer whether arbitrary helper functions are "success exits" without local evidence

### Future extension points

- Loop-sensitive path analysis
- Interprocedural audit-node summaries
- Integration with `@exception_boundary` / `@must_propagate`
- Shared CFG utilities if other rules later need dominance reasoning

---

## Recommended Execution Order

1. Task 1
2. Task 2
3. Task 3
4. Task 4
5. Task 5
6. Task 6

This keeps the work TDD-first and avoids building a CFG abstraction before the exact Wardline success/bypass semantics are pinned down in tests.
