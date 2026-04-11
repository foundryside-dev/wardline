# Scan Gate Severity Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align the `wardline scan` CLI gate logic with the three-tier signal model already documented in the spec (§7.3–§7.5) and correctly implemented in `corpus verify` — so that only ERROR-severity findings block the gate, WARNING findings are visible but non-blocking, and SUPPRESS findings are expected noise excluded from the gate entirely.

**Architecture:** The severity matrix (matrix.py) is already correct — all 72 cells match the spec. The fix is in the *consumers* of findings: the scan command's exit-code logic, the SARIF run-level counters, the stderr summary, and the test suite. The corpus verify gate (corpus_cmds.py:755–787) is the reference implementation of the correct pattern.

**Tech Stack:** Python 3.12+, Click CLI, SARIF v2.1.0, pytest

---

## File Structure

| File | Responsibility | Action |
|------|---------------|--------|
| `src/wardline/cli/scan.py` | Main scan command exit-code logic + stderr summary | Modify (lines 773–801) |
| `src/wardline/scanner/sarif.py` | SARIF run-level property bag | Modify (add severity counters) |
| `tests/unit/cli/test_scan_gate_severity.py` | Gate logic unit tests | Create |
| `tests/unit/scanner/test_sarif_severity_counters.py` | SARIF counter tests | Create |
| `tests/integration/test_scan_cmd.py` | Integration tests for exit codes | Modify (add severity gate cases) |

---

### Task 1: Unit Tests for Scan Gate Severity Filtering

**Files:**
- Create: `tests/unit/cli/test_scan_gate_severity.py`

This task extracts the gate logic into a testable function and writes the failing tests first.

- [ ] **Step 1: Write the failing test file**

```python
"""Unit tests for scan gate severity filtering.

The three-tier signal model (spec §7.3–§7.5, corpus_cmds.py:755–787):
- SUPPRESS (SARIF "note"): expected pattern at this taint state — excluded from gate
- WARNING (SARIF "warning"): suspicious, worth reviewing — excluded from gate
- ERROR (SARIF "error"): violates tier integrity contract — blocks gate unless excepted
"""
from __future__ import annotations

import pytest

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding


def _make_finding(
    *,
    severity: Severity = Severity.ERROR,
    rule_id: RuleId = RuleId.PY_WL_001,
    exception_id: str | None = None,
) -> Finding:
    """Create a minimal Finding for gate logic tests."""
    return Finding(
        file_path="test.py",
        line=1,
        col=1,
        end_line=None,
        end_col=None,
        message="test finding",
        severity=severity,
        exceptionability=Exceptionability.STANDARD,
        taint_state=None,
        analysis_level=1,
        rule_id=rule_id,
        qualname="mod.func",
        source_snippet=None,
        exception_id=exception_id,
        exception_expires=None,
    )


class TestGateBlockingFindings:
    """Gate should only count unexcepted ERROR findings."""

    def test_suppress_findings_do_not_block(self) -> None:
        findings = [_make_finding(severity=Severity.SUPPRESS)]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 0

    def test_warning_findings_do_not_block(self) -> None:
        findings = [_make_finding(severity=Severity.WARNING)]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 0

    def test_error_findings_block(self) -> None:
        findings = [_make_finding(severity=Severity.ERROR)]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 1

    def test_excepted_error_findings_do_not_block(self) -> None:
        findings = [_make_finding(severity=Severity.ERROR, exception_id="EXC-001")]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 0

    def test_mixed_severities(self) -> None:
        findings = [
            _make_finding(severity=Severity.SUPPRESS),
            _make_finding(severity=Severity.WARNING),
            _make_finding(severity=Severity.ERROR),
            _make_finding(severity=Severity.ERROR, exception_id="EXC-002"),
        ]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 1

    def test_empty_findings(self) -> None:
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking([]) == 0


class TestSeverityBreakdown:
    """Severity breakdown for stderr summary and SARIF counters."""

    def test_breakdown_counts(self) -> None:
        findings = [
            _make_finding(severity=Severity.SUPPRESS),
            _make_finding(severity=Severity.SUPPRESS),
            _make_finding(severity=Severity.WARNING),
            _make_finding(severity=Severity.ERROR),
            _make_finding(severity=Severity.ERROR, exception_id="EXC-001"),
        ]
        from wardline.cli._gate import severity_breakdown
        bd = severity_breakdown(findings)
        assert bd.error_count == 2
        assert bd.warning_count == 1
        assert bd.suppress_count == 2
        assert bd.excepted_count == 1
        assert bd.gate_blocking == 1  # 2 errors - 1 excepted

    def test_breakdown_empty(self) -> None:
        from wardline.cli._gate import severity_breakdown
        bd = severity_breakdown([])
        assert bd.error_count == 0
        assert bd.warning_count == 0
        assert bd.suppress_count == 0
        assert bd.excepted_count == 0
        assert bd.gate_blocking == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/cli/test_scan_gate_severity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.cli._gate'`

- [ ] **Step 3: Commit test file**

```bash
git add tests/unit/cli/test_scan_gate_severity.py
git commit -m "test: add failing tests for scan gate severity filtering"
```

---

### Task 2: Implement Gate Logic Module

**Files:**
- Create: `src/wardline/cli/_gate.py`

Extract the gate decision into a small, testable module. The corpus verify gate (corpus_cmds.py:755–787) is the reference pattern, but it operates on SARIF dicts. This module operates on `Finding` objects directly.

- [ ] **Step 1: Create the gate module**

```python
"""Scan gate logic — three-tier signal model.

The severity matrix (§7.3) assigns each (rule, taint) pair a severity:

- **SUPPRESS** — pattern is expected at this taint state.  Excluded from
  the CI gate.  Tracked as a diagnostic counter.
- **WARNING** — pattern is suspicious but does not block.  Excluded from
  the CI gate.  Tracked as a separate counter.
- **ERROR** — pattern violates the tier's integrity contract.  Blocks
  the CI gate unless governed by an exception.

This creates an economic incentive: promoting data to a higher tier
(via validation boundaries) removes findings.  Leaving raw data in
hot code paths is expensive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Sequence

from wardline.core.severity import Severity

if TYPE_CHECKING:
    from wardline.scanner.context import Finding


@dataclass(frozen=True)
class SeverityBreakdown:
    """Severity counts for a set of findings."""

    error_count: int
    warning_count: int
    suppress_count: int
    excepted_count: int
    gate_blocking: int


def count_gate_blocking(findings: Sequence[Finding]) -> int:
    """Count findings that block the CI gate.

    Only ERROR-severity findings without an active exception are
    gate-blocking.  WARNING and SUPPRESS findings are visible in
    the SARIF output but do not affect the exit code.
    """
    return sum(
        1
        for f in findings
        if f.severity == Severity.ERROR and f.exception_id is None
    )


def severity_breakdown(findings: Sequence[Finding]) -> SeverityBreakdown:
    """Compute severity counts for stderr summary and SARIF run properties."""
    error_count = 0
    warning_count = 0
    suppress_count = 0
    excepted_count = 0

    for f in findings:
        if f.severity == Severity.ERROR:
            error_count += 1
            if f.exception_id is not None:
                excepted_count += 1
        elif f.severity == Severity.WARNING:
            warning_count += 1
        elif f.severity == Severity.SUPPRESS:
            suppress_count += 1

    gate_blocking = error_count - excepted_count
    return SeverityBreakdown(
        error_count=error_count,
        warning_count=warning_count,
        suppress_count=suppress_count,
        excepted_count=excepted_count,
        gate_blocking=gate_blocking,
    )
```

- [ ] **Step 2: Run the unit tests**

Run: `uv run pytest tests/unit/cli/test_scan_gate_severity.py -v`
Expected: ALL PASS

- [ ] **Step 3: Commit**

```bash
git add src/wardline/cli/_gate.py
git commit -m "feat: extract gate severity logic into _gate module"
```

---

### Task 3: Rewire Scan Command Exit-Code Logic

**Files:**
- Modify: `src/wardline/cli/scan.py:773-801`

Replace the naive `len(result.findings)` count with `count_gate_blocking()` and add a severity breakdown to the stderr summary.

- [ ] **Step 1: Write failing integration test**

Add to `tests/integration/test_scan_cmd.py`:

```python
@pytest.mark.integration
class TestScanGateSeverity:
    """Exit code respects the three-tier signal model."""

    def test_suppress_only_exits_clean(self, tmp_path: Path) -> None:
        """A scan with only SUPPRESS-severity findings exits 0."""
        # Create a T4 (EXTERNAL_RAW) module with a .get() call —
        # PY-WL-001 at EXTERNAL_RAW = SUPPRESS/TRANSPARENT
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            "tiers:\n"
            '  - id: "external"\n'
            "    tier: 4\n"
            '    description: "external boundary"\n'
            "module_tiers:\n"
            '  - path: "."\n'
            "    taint_state: EXTERNAL_RAW\n"
            "metadata:\n"
            '  organisation: "TestOrg"\n'
        )
        py_file = tmp_path / "loader.py"
        py_file.write_text(
            "def load_config(data: dict) -> str:\n"
            "    return data.get('timeout', 30)\n"
        )
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        # PY-WL-001 at EXTERNAL_RAW is SUPPRESS — should NOT block gate
        assert result.exit_code == 0, (
            f"SUPPRESS findings should not block gate. stderr: {result.output}"
        )

    def test_error_findings_exit_nonzero(self, tmp_path: Path) -> None:
        """A scan with ERROR-severity findings exits 1."""
        # Create a T1 (INTEGRAL) module with a .get() call —
        # PY-WL-001 at INTEGRAL = ERROR/UNCONDITIONAL
        manifest = tmp_path / "wardline.yaml"
        manifest.write_text(
            "tiers:\n"
            '  - id: "audit"\n'
            "    tier: 1\n"
            '    description: "audit trail"\n'
            "module_tiers:\n"
            '  - path: "."\n'
            "    taint_state: INTEGRAL\n"
            "metadata:\n"
            '  organisation: "TestOrg"\n'
        )
        py_file = tmp_path / "audit.py"
        py_file.write_text(
            "def write_record(data: dict) -> str:\n"
            "    return data.get('event_id', 'unknown')\n"
        )
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--manifest", str(manifest),
            "--allow-registry-mismatch",
        ])
        assert result.exit_code == 1, (
            f"ERROR findings should block gate. stderr: {result.output}"
        )
```

- [ ] **Step 2: Run integration test to verify it fails**

Run: `uv run pytest tests/integration/test_scan_cmd.py::TestScanGateSeverity -v`
Expected: `test_suppress_only_exits_clean` FAILS (exit code 1 instead of 0)

- [ ] **Step 3: Modify scan.py — import gate module**

In `src/wardline/cli/scan.py`, add the import at the top of the file (after the existing wardline imports):

Replace:
```python
from wardline.cli._helpers import cli_error
```

With:
```python
from wardline.cli._helpers import cli_error
from wardline.cli._gate import count_gate_blocking, severity_breakdown
```

- [ ] **Step 4: Modify scan.py — replace gate logic (lines 773–801)**

Replace the block from `# --- Summary to stderr ---` through `sys.exit(EXIT_CLEAN)`:

```python
    # --- Summary to stderr ---
    bd = severity_breakdown(result.findings)
    click.echo(
        f"{result.files_scanned} file(s) scanned, "
        f"{len(result.findings)} finding(s) "
        f"({bd.error_count} error, {bd.warning_count} warning, "
        f"{bd.suppress_count} suppressed"
        f"{f', {bd.excepted_count} excepted' if bd.excepted_count else ''}).",
        err=True,
    )

    # --- Determine exit code ---
    # Exit code priority (highest wins):
    #   EXIT_TOOL_ERROR (3) — a rule or scanner component raised an
    #       unhandled exception; signals infrastructure failure.
    #   EXIT_FINDINGS   (1) — at least one unexcepted ERROR finding
    #       exists, or the max_unknown_raw_percent ceiling was exceeded,
    #       or --strict-governance is set and GOVERNANCE findings exist.
    #   EXIT_CLEAN      (0) — no gate-blocking findings.
    #
    # The three-tier signal model (§7.3–§7.5):
    #   SUPPRESS findings are excluded (pattern is expected at this tier).
    #   WARNING findings are excluded (suspicious, non-blocking).
    #   Only ERROR findings block the gate.
    has_tool_error = any(
        f.rule_id == RuleId.TOOL_ERROR for f in all_findings
    )
    has_governance_findings = effective_strict_governance and any(
        str(f.rule_id).startswith("GOVERNANCE-") for f in all_findings
    )

    if has_tool_error:
        sys.exit(EXIT_TOOL_ERROR)
    elif exceeded_pct or bd.gate_blocking > 0 or has_governance_findings:
        sys.exit(EXIT_FINDINGS)
    else:
        sys.exit(EXIT_CLEAN)
```

- [ ] **Step 5: Apply the same fix to the preview exit-code path (lines 693–703)**

Replace the preview exit-code block:

```python
        # Normal exit code rules apply — preview changes format, not enforcement
        has_tool_error = any(
            f.rule_id == RuleId.TOOL_ERROR for f in result.findings
        )
        preview_blocking = count_gate_blocking(result.findings)
        if has_tool_error:
            sys.exit(EXIT_TOOL_ERROR)
        elif exceeded_pct or preview_blocking > 0:
            sys.exit(EXIT_FINDINGS)
        else:
            sys.exit(EXIT_CLEAN)
```

- [ ] **Step 6: Run all tests**

Run: `uv run pytest tests/integration/test_scan_cmd.py -v && uv run pytest tests/unit/cli/test_scan_gate_severity.py -v`
Expected: ALL PASS

- [ ] **Step 7: Run self-hosting scan to check impact**

Run: `uv run wardline scan src/wardline --manifest wardline.yaml --config wardline.toml --allow-registry-mismatch 2>&1 | tail -5`
Expected: stderr shows severity breakdown; exit code may now be 0 if all remaining findings are WARNING/SUPPRESS

- [ ] **Step 8: Commit**

```bash
git add src/wardline/cli/scan.py tests/integration/test_scan_cmd.py
git commit -m "fix: scan gate only blocks on ERROR findings, not WARNING/SUPPRESS

The three-tier signal model (spec §7.3-§7.5) says:
- SUPPRESS: pattern expected at this tier — excluded from gate
- WARNING: suspicious, worth reviewing — excluded from gate
- ERROR: violates tier integrity — blocks gate unless excepted

The scan command was counting ALL findings for its exit code,
making the recalibrated severity matrix ineffective."
```

---

### Task 4: Add Severity Counters to SARIF Run Properties

**Files:**
- Modify: `src/wardline/scanner/sarif.py`
- Create: `tests/unit/scanner/test_sarif_severity_counters.py`

The SARIF run-level properties should include the severity breakdown so that downstream consumers (corpus verify, CI dashboards) can see the split without re-parsing every result.

- [ ] **Step 1: Write the failing test**

```python
"""Tests for SARIF run-level severity counters."""
from __future__ import annotations

import json

import pytest

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.sarif import SarifReport


def _make_finding(
    *,
    severity: Severity = Severity.ERROR,
    rule_id: RuleId = RuleId.PY_WL_001,
    exception_id: str | None = None,
) -> Finding:
    return Finding(
        file_path="test.py",
        line=1,
        col=1,
        end_line=None,
        end_col=None,
        message="test",
        severity=severity,
        exceptionability=Exceptionability.STANDARD,
        taint_state=None,
        analysis_level=1,
        rule_id=rule_id,
        qualname="mod.func",
        source_snippet=None,
        exception_id=exception_id,
        exception_expires=None,
    )


class TestSarifSeverityCounters:
    """Run-level properties include severity breakdown."""

    def test_counters_present(self) -> None:
        report = SarifReport(
            findings=[
                _make_finding(severity=Severity.SUPPRESS),
                _make_finding(severity=Severity.WARNING),
                _make_finding(severity=Severity.ERROR),
                _make_finding(severity=Severity.ERROR, exception_id="EXC-1"),
            ],
            analysis_level=1,
        )
        sarif = json.loads(report.to_json_string())
        props = sarif["runs"][0]["properties"]
        assert props["wardline.errorFindingCount"] == 2
        assert props["wardline.warningFindingCount"] == 1
        assert props["wardline.suppressedCellFindingCount"] == 1
        assert props["wardline.gateBlockingCount"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/scanner/test_sarif_severity_counters.py -v`
Expected: FAIL — KeyError on `wardline.errorFindingCount`

- [ ] **Step 3: Add severity counters to SarifReport**

In `src/wardline/scanner/sarif.py`, add the import at the top:

```python
from wardline.cli._gate import severity_breakdown
```

Then in the `to_sarif_dict` method (or equivalent), within the run `"properties"` dict, add after the existing `"wardline.suppressedFindingCount"` line:

```python
                "wardline.errorFindingCount": sum(
                    1 for f in self.findings if f.severity == Severity.ERROR
                ),
                "wardline.warningFindingCount": sum(
                    1 for f in self.findings if f.severity == Severity.WARNING
                ),
                "wardline.suppressedCellFindingCount": sum(
                    1 for f in self.findings if f.severity == Severity.SUPPRESS
                ),
                "wardline.gateBlockingCount": sum(
                    1 for f in self.findings
                    if f.severity == Severity.ERROR and f.exception_id is None
                ),
```

Note: We inline the counts here rather than importing `_gate` to avoid a circular dependency (sarif.py is in `scanner/`, `_gate.py` is in `cli/`). The logic is trivial enough to duplicate.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/unit/scanner/test_sarif_severity_counters.py tests/unit/cli/test_scan_gate_severity.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/sarif.py tests/unit/scanner/test_sarif_severity_counters.py
git commit -m "feat: add severity breakdown counters to SARIF run properties

Adds wardline.errorFindingCount, wardline.warningFindingCount,
wardline.suppressedCellFindingCount, and wardline.gateBlockingCount
to the SARIF run-level property bag. These let downstream consumers
(corpus verify, CI dashboards) see the severity split without
re-parsing individual results."
```

---

### Task 5: Rename Ambiguous suppressedFindingCount

**Files:**
- Modify: `src/wardline/scanner/sarif.py`

The existing `wardline.suppressedFindingCount` counts *excepted* findings (those with an exception_id), not SUPPRESS-severity findings. Now that we have `wardline.suppressedCellFindingCount` for the matrix-level SUPPRESS, the old name is confusing. Rename it to `wardline.exceptedFindingCount`.

- [ ] **Step 1: Check all consumers of the old property name**

Run: `rg "suppressedFindingCount" src/ tests/`
Identify all locations that reference the old name.

- [ ] **Step 2: Rename in sarif.py**

Replace:
```python
"wardline.suppressedFindingCount": sum(
    1 for f in self.findings if f.exception_id is not None
),
```

With:
```python
"wardline.exceptedFindingCount": sum(
    1 for f in self.findings if f.exception_id is not None
),
```

- [ ] **Step 3: Update corpus_cmds.py if it reads this property**

Search for `suppressedFindingCount` in `corpus_cmds.py` and update any references to `exceptedFindingCount`.

- [ ] **Step 4: Update any test assertions that check the old name**

Search tests for `suppressedFindingCount` and update to `exceptedFindingCount`.

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest -x`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add -u
git commit -m "refactor: rename suppressedFindingCount to exceptedFindingCount

The old name was ambiguous — it counted findings with an active
exception (exception_id != None), not findings at SUPPRESS severity.
Now that wardline.suppressedCellFindingCount exists for matrix-level
SUPPRESS, rename the exception-based counter to avoid confusion."
```

---

### Task 6: Verify Self-Hosting Scan Behaviour

**Files:** (no code changes — verification only)

- [ ] **Step 1: Run self-hosting scan and capture SARIF**

```bash
uv run wardline scan src/wardline \
  --manifest wardline.yaml \
  --config wardline.toml \
  --allow-registry-mismatch \
  -o /tmp/self-hosting.sarif.json 2>&1
```

- [ ] **Step 2: Check the SARIF severity counters**

```bash
python3 -c "
import json
sarif = json.load(open('/tmp/self-hosting.sarif.json'))
props = sarif['runs'][0]['properties']
for k in sorted(props):
    if 'Count' in k or 'count' in k.lower() or 'gate' in k.lower():
        print(f'{k}: {props[k]}')
"
```

Expected: `wardline.gateBlockingCount` should be in the 25–39 range documented in the session log, with `wardline.warningFindingCount` and `wardline.suppressedCellFindingCount` showing the findings that were previously inflating the total.

- [ ] **Step 3: Verify exit code matches gate-blocking count**

```bash
uv run wardline scan src/wardline \
  --manifest wardline.yaml \
  --config wardline.toml \
  --allow-registry-mismatch 2>&1; echo "EXIT: $?"
```

Expected: EXIT 1 if gateBlockingCount > 0, EXIT 0 if all remaining ERRORs are excepted.

- [ ] **Step 4: Run full test suite**

Run: `uv run pytest`
Expected: ALL PASS (1874+ tests)

- [ ] **Step 5: Run corpus verify**

```bash
uv run wardline corpus verify \
  --corpus-path corpus/ \
  --sarif /tmp/self-hosting.sarif.json \
  -o /tmp/conformance.json
```

Expected: Corpus verify still passes. The new SARIF counters don't break existing consumers.

---

### Task 7: Update Spec Comment in scan.py Exit-Code Docstring

**Files:**
- Modify: `src/wardline/cli/scan.py` (module docstring or inline comment at gate logic)

Ensure the exit-code comment references the three-tier signal model and the spec sections.

- [ ] **Step 1: Verify the comment was updated in Task 3**

Read `src/wardline/cli/scan.py` lines 780–800 and confirm the comment references §7.3–§7.5 and describes the three-tier model. If Task 3's edit already includes this (it should), this step is a no-op.

- [ ] **Step 2: If needed, add spec reference**

The comment block from Task 3 Step 4 already includes the spec reference. Verify it's present. No commit needed if Task 3 was followed correctly.

---

## Post-Implementation Verification Checklist

After all tasks are complete, verify:

1. `uv run pytest` — all tests pass
2. `uv run ruff check src/` — no lint errors
3. `uv run mypy src/` — no type errors
4. Self-hosting scan stderr shows severity breakdown (not just total count)
5. Self-hosting SARIF contains all four new counters
6. `wardline.suppressedFindingCount` has been renamed to `wardline.exceptedFindingCount`
7. Corpus verify still works with the updated SARIF format
8. Exit code from self-hosting scan matches `gateBlockingCount > 0`
