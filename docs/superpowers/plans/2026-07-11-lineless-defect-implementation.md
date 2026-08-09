# Lineless Defect Fail-Closed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure a future source-level `DEFECT` without a line cannot silently leave Wardline's gate population.

**Architecture:** Keep `apply_suppressions()` total and non-crashing, but replace the generic DEFECT-to-FACT downgrade with an explicit allowlist and a deterministic gate-eligible engine diagnostic for every unallowlisted case. Preserve the original defect identity in diagnostic properties and pin both suppression-layer and run/gate behavior.

**Tech Stack:** Python 3.12+, frozen Wardline `Finding` records, pytest, Ruff, mypy, Filigree MCP.

---

### Task 1: Start the ticket and record the proven root cause

**Files:**
- Tracker: `wardline-da175547cf`

- [ ] **Step 1: Atomically start work**

Call `mcp__filigree__work_start`:

```json
{
  "actor": "john",
  "assignee": "codex",
  "issue_id": "wardline-da175547cf",
  "commit": "release/consolidation-2026-06-26@HEAD"
}
```

Expected: status `in_progress`, assignee `codex`.

- [ ] **Step 2: Record the root cause before editing**

Call `mcp__filigree__comment_add` with `actor="john"`,
`expected_assignee="codex"`, and this text:

```text
Root cause confirmed at current HEAD: apply_suppressions() rewrites every non-ENGINE_PATH DEFECT with line_start=None into Severity.NONE/Kind.FACT. run_scan applies that transform to both emitted and secure-default gate populations, so gate_trips cannot see the original defect. Existing tests explicitly pin the false-green behavior. The fix will preserve total scan behavior but replace unallowlisted lineless source defects with a deterministic gate-eligible ENGINE_PATH diagnostic.
```

Expected: comment recorded without actor/claim conflict.

### Task 2: Write the red suppression-layer regression

**Files:**
- Modify: `tests/unit/core/test_suppression.py:35-49`

- [ ] **Step 1: Replace the misleading downgrade assertion**

Replace `test_defect_without_line_start_is_rejected` with:

```python
def test_source_defect_without_line_start_becomes_gating_engine_defect() -> None:
    bad = Finding(
        rule_id="PY-WL-101",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/m.py", line_start=None),
        fingerprint=_FP_A,
    )

    out = apply_suppressions([bad], _empty_baseline(), _no_waivers(), today=_TODAY)

    assert len(out) == 1
    diagnostic = out[0]
    assert diagnostic.rule_id == "WLN-ENGINE-LINELESS-DEFECT"
    assert diagnostic.kind is Kind.DEFECT
    assert diagnostic.severity is Severity.ERROR
    assert diagnostic.location == Location(path=ENGINE_PATH)
    assert diagnostic.suppressed is SuppressionState.ACTIVE
    assert diagnostic.properties == {
        "original_rule_id": "PY-WL-101",
        "original_path": "src/m.py",
        "original_fingerprint": _FP_A,
        "original_kind": "defect",
    }
    assert gate_trips(out, Severity.ERROR) is True
```

Add `ENGINE_PATH` to the existing import from `wardline.core.finding`.

- [ ] **Step 2: Run the test and verify the current bug**

Run:

```bash
uv run pytest -q tests/unit/core/test_suppression.py::test_source_defect_without_line_start_becomes_gating_engine_defect
```

Expected: FAIL because the current result is `Kind.FACT`, `Severity.NONE`, and retains `src/m.py`.

### Task 3: Write the red run/gate regression

**Files:**
- Modify: `tests/unit/core/test_run.py:607-630`

- [ ] **Step 1: Invert the false-green run-level test**

Replace `test_lineless_defect_does_not_trip_gate` with:

```python
def test_lineless_source_defect_trips_gate_via_engine_diagnostic() -> None:
    from wardline.core.baseline import Baseline
    from wardline.core.finding import ENGINE_PATH
    from wardline.core.suppression import apply_suppressions, gate_trips
    from wardline.core.waivers import WaiverSet

    lineless = Finding(
        rule_id="PY-WL-101",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="svc.py", line_start=None),
        fingerprint="b" * 64,
        suppressed=SuppressionState.ACTIVE,
    )

    gate_pop = apply_suppressions(
        [lineless], Baseline(frozenset()), WaiverSet([]), today=datetime.now(UTC).date()
    )

    diagnostic = next(f for f in gate_pop if f.rule_id == "WLN-ENGINE-LINELESS-DEFECT")
    assert diagnostic.location.path == ENGINE_PATH
    assert diagnostic.kind is Kind.DEFECT
    assert gate_trips(gate_pop, Severity.ERROR) is True
```

- [ ] **Step 2: Run the test and verify the current bug**

Run:

```bash
uv run pytest -q tests/unit/core/test_run.py::test_lineless_source_defect_trips_gate_via_engine_diagnostic
```

Expected: FAIL because the current transform emits a non-gating FACT.

### Task 4: Implement the fail-closed transformation

**Files:**
- Modify: `src/wardline/core/suppression.py:12-68`

- [ ] **Step 1: Add the explicit allowlist and helper**

Import `hashlib` and `Location` at module scope. Add:

```python
_LINELESS_DEFECT_FACT_ALLOWLIST: frozenset[str] = frozenset()


def _lineless_defect_diagnostic(finding: Finding) -> Finding:
    identity = "\x00".join(
        (
            "WLN-ENGINE-LINELESS-DEFECT",
            finding.rule_id,
            finding.location.path,
            finding.fingerprint,
        )
    )
    fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    properties = {
        "original_rule_id": finding.rule_id,
        "original_path": finding.location.path,
        "original_fingerprint": finding.fingerprint,
        "original_kind": finding.kind.value,
    }
    return Finding(
        rule_id="WLN-ENGINE-LINELESS-DEFECT",
        message=(
            f"DEFECT {finding.rule_id} on path {finding.location.path} has "
            "line_start=None; replaced with a gate-eligible engine diagnostic"
        ),
        severity=finding.severity,
        kind=Kind.DEFECT,
        location=Location(path=ENGINE_PATH),
        fingerprint=fingerprint,
        properties=properties,
    )
```

- [ ] **Step 2: Replace the generic downgrade branch**

Keep the old FACT downgrade in a dedicated helper for explicitly allowlisted
families, then use:

```python
if f.location.path != ENGINE_PATH and f.location.line_start is None:
    if f.rule_id not in _LINELESS_DEFECT_FACT_ALLOWLIST:
        out.append(_lineless_defect_diagnostic(f))
    else:
        out.append(_allowlisted_lineless_defect_fact(f))
    continue
```

The initial allowlist is empty. Keeping its downgrade isolated makes any future exception
an explicit code-and-regression decision rather than the generic default.

- [ ] **Step 3: Run the two red tests and verify green**

Run:

```bash
uv run pytest -q \
  tests/unit/core/test_suppression.py::test_source_defect_without_line_start_becomes_gating_engine_defect \
  tests/unit/core/test_run.py::test_lineless_source_defect_trips_gate_via_engine_diagnostic
```

Expected: `2 passed`.

### Task 5: Add the built-in source-defect line invariant

**Files:**
- Modify: `tests/grammar/test_output_determinism.py`

- [ ] **Step 1: Add a corpus-wide invariant over analyzer output**

Extract the finding-producing portion of `_full_stream()` into `_corpus_findings()`:

```python
def _corpus_findings() -> list[Finding]:
    files = sorted(_CORPUS.rglob("*.py"))
    analyzer = WardlineAnalyzer()
    return analyzer.analyze(files, WardlineConfig(), root=REPO_ROOT)


def _full_stream() -> str:
    return "\n".join(f.to_jsonl() for f in _corpus_findings())
```

Then add:

```python
def test_builtin_source_defects_have_source_lines() -> None:
    findings = _corpus_findings()
    offenders = [
        (f.rule_id, f.location.path, f.qualname)
        for f in findings
        if f.kind is Kind.DEFECT
        and f.location.path != ENGINE_PATH
        and f.location.line_start is None
    ]
    assert offenders == []
```

Import `ENGINE_PATH`, `Finding`, and `Kind`.

- [ ] **Step 2: Run the corpus invariant**

Run:

```bash
uv run pytest -q tests/grammar/test_output_determinism.py::test_builtin_source_defects_have_source_lines
```

Expected: PASS, proving current built-in source rules do not rely on the fail-closed fallback.

### Task 6: Verify, commit, and close

**Files:**
- Modify: `src/wardline/core/suppression.py`
- Modify: `tests/unit/core/test_suppression.py`
- Modify: `tests/unit/core/test_run.py`
- Modify: `tests/grammar/test_output_determinism.py`

- [ ] **Step 1: Run focused verification**

Run:

```bash
uv run pytest -q tests/unit/core/test_suppression.py tests/unit/core/test_run.py tests/grammar/test_output_determinism.py
uv run ruff check src/wardline/core/suppression.py tests/unit/core/test_suppression.py tests/unit/core/test_run.py tests/grammar/test_output_determinism.py
uv run mypy src/wardline/core/suppression.py
git diff --check
```

Expected: all commands exit 0.

- [ ] **Step 2: Run repository verification**

Run:

```bash
uv run pytest -q
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run wardline scan . --fail-on ERROR
git status --short
```

Expected: all gates exit 0; only the four intended files plus planning documents are changed. Record any self-scan inert-gate warning without treating it as ticket proof.

- [ ] **Step 3: Commit the ticket**

Run:

```bash
git add src/wardline/core/suppression.py \
  tests/unit/core/test_suppression.py \
  tests/unit/core/test_run.py \
  tests/grammar/test_output_determinism.py
git commit -m "fix(gate): fail closed on lineless defects"
```

Expected: one commit containing only this ticket's implementation and tests.

- [ ] **Step 4: Record verification and close**

Call `mcp__filigree__comment_add` with actor `john`, expected assignee `codex`, and exact test/gate results plus the commit SHA. Then call `mcp__filigree__issue_close`:

```json
{
  "actor": "john",
  "expected_assignee": "codex",
  "issue_id": "wardline-da175547cf",
  "commit": "release/consolidation-2026-06-26@<actual-sha>",
  "reason": "Lineless source defects now become deterministic gate-eligible engine diagnostics; red/green, corpus invariant, full suite, static checks, and Wardline gate verified.",
  "fields": {
    "root_cause": "The suppression transform generically rewrote non-engine lineless DEFECTs into Severity.NONE FACTs in both emitted and secure-default gate populations.",
    "fix_verification": "Record exact focused/full test counts, Ruff, format, mypy, diff check, and Wardline gate output from this run."
  }
}
```

Replace `<actual-sha>` and the verification field with current evidence before calling.
Expected: issue status `closed`.
