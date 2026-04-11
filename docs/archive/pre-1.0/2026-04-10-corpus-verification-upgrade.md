# Corpus Verification Upgrade (R3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade corpus `expected_match` from boolean to structured `{line, text, function}` with SARIF snippet comparison, closing conformance finding R3.

**Architecture:** 5-phase approach. Phase 0 populates `source_snippet` on findings via a shared helper and exposes Finding objects from the corpus pipeline. Phase 1 adds SARIF snippet emission. Phase 2 adds structural comparison logic (before data migration to prevent truthy-dict bypass). Phase 3 migrates specimens using AST-derived values (oracle-independent). Phase 4 adds coverage gates, CODEOWNERS, and CI enforcement.

**Tech Stack:** Python 3.12+, pytest, PyYAML (SafeDumper/WardlineSafeLoader), ast module, dataclasses.replace(), TypedDict

**Design spec:** `docs/plans/workstream-b-corpus-verification-upgrade.md` (full context, rationale, review history)

---

## File Structure

### New files
| File | Responsibility |
|------|---------------|
| `scripts/migrate_expected_match.py` | One-time migration script (Phase 3) |
| `tests/unit/scripts/test_migrate_expected_match.py` | Migration safety tests |

### Modified files
| File | What changes |
|------|-------------|
| `src/wardline/scanner/context.py` | Add `populate_snippets()` shared helper |
| `src/wardline/scanner/engine.py` | Add `source` param to `_run_rule()`, call `populate_snippets()` |
| `src/wardline/scanner/sarif.py` | Add `snippet.text` to `_make_region()` |
| `src/wardline/cli/corpus_cmds.py` | Add `_collect_findings_on_fragment()`, `ExpectedLocation`, structural comparison, `location_mismatches` counter |
| `scripts/generate_corpus.py` | Structured `expected_match` for new specimens, SafeDumper |
| `corpus/specimens/**/*.yaml` | ~117 positive specimens get structured `expected_match` |
| `corpus/corpus_manifest.json` | Regenerated |
| `tests/unit/scanner/test_engine.py` | Snippet population tests |
| `tests/unit/scanner/test_sarif.py` | Region snippet tests |
| `tests/unit/scanner/test_corpus_runner.py` | 17+ structural comparison tests |
| `tests/unit/corpus/test_corpus_oracle.py` | Updated oracle + coverage gate |
| `tests/integration/test_corpus_verify.py` | Location mismatch CI gate + structural integrity |

---

## Task 1: Add `populate_snippets()` Shared Helper (Phase 0)

**Files:**
- Modify: `src/wardline/scanner/context.py` (after `Finding` class, ~line 50)
- Test: `tests/unit/scanner/test_engine.py` (new test class)

- [ ] **Step 1: Write failing test for `populate_snippets`**

Create or add to `tests/unit/scanner/test_engine.py`:

```python
from __future__ import annotations

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding, populate_snippets


class TestPopulateSnippets:
    """Tests for the shared snippet-population helper."""

    def test_populates_none_snippet_from_source(self) -> None:
        source = "line_zero\ndef process(data):\n    x = data.get('key', 'default')\n"
        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="test.py", line=3, col=4,
            end_line=3, end_col=30, message="test", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet=None, qualname="process",
        )
        result = populate_snippets([f], source)
        assert len(result) == 1
        assert result[0].source_snippet == "x = data.get('key', 'default')"

    def test_preserves_existing_snippet(self) -> None:
        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="test.py", line=1, col=0,
            end_line=1, end_col=10, message="test", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="already set", qualname=None,
        )
        result = populate_snippets([f], "some source")
        assert result[0].source_snippet == "already set"

    def test_none_source_returns_findings_unchanged(self) -> None:
        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="test.py", line=1, col=0,
            end_line=None, end_col=None, message="test", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet=None, qualname=None,
        )
        result = populate_snippets([f], None)
        assert result[0].source_snippet is None

    def test_out_of_range_line_keeps_none(self) -> None:
        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="test.py", line=0, col=0,
            end_line=None, end_col=None, message="test", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet=None, qualname=None,
        )
        result = populate_snippets([f], "one line")
        assert result[0].source_snippet is None

    def test_snippet_is_stripped(self) -> None:
        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="test.py", line=1, col=0,
            end_line=None, end_col=None, message="test", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet=None, qualname=None,
        )
        result = populate_snippets([f], "    indented_code    ")
        assert result[0].source_snippet == "indented_code"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_engine.py::TestPopulateSnippets -v`
Expected: FAIL — `ImportError: cannot import name 'populate_snippets'`

- [ ] **Step 3: Implement `populate_snippets` in context.py**

Add at the end of `src/wardline/scanner/context.py` (after the `ScanContext` class):

```python
def populate_snippets(
    findings: list[Finding],
    source: str | None,
) -> list[Finding]:
    """Populate source_snippet on findings that lack it.

    Uses line-range extraction from source text. Returns new Finding
    instances (Finding is frozen — uses dataclasses.replace).

    Both the scan engine and the corpus pipeline call this function
    to avoid duplicating snippet-population logic.
    """
    if source is None:
        return list(findings)
    source_lines = source.splitlines()
    result: list[Finding] = []
    for f in findings:
        if f.source_snippet is None and 1 <= f.line <= len(source_lines):
            f = replace(f, source_snippet=source_lines[f.line - 1].strip())
        result.append(f)
    return result
```

Also add `from dataclasses import replace` to the imports at the top of `context.py` (add to the existing `from dataclasses import dataclass` line):

```python
from dataclasses import dataclass, replace
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/scanner/test_engine.py::TestPopulateSnippets -v`
Expected: All 5 PASS

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `uv run pytest`
Expected: All existing tests pass

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/context.py tests/unit/scanner/test_engine.py
git commit -m "fix(R3/phase-0): add populate_snippets shared helper to context.py"
```

---

## Task 2: Wire `populate_snippets` into `_run_rule()` (Phase 0)

**Files:**
- Modify: `src/wardline/scanner/engine.py:553` (call site) and `871-913` (`_run_rule`)

- [ ] **Step 1: Write failing test for engine snippet population**

Add to `tests/unit/scanner/test_engine.py`:

```python
import ast
from pathlib import Path
from unittest.mock import MagicMock

from wardline.scanner.engine import ScanEngine, ScanResult


class TestEngineSnippetPopulation:
    """Verify _run_rule populates source_snippet on findings."""

    def test_source_snippet_populated_after_rule_visit(self, tmp_path: Path) -> None:
        """Scan a Python file containing a PY-WL-001 pattern, verify snippets."""
        code = 'def process(data):\n    x = data.get("key", "default")\n'
        py_file = tmp_path / "test_snippet.py"
        py_file.write_text(code)

        from wardline.scanner.rules import make_rules
        rules = make_rules()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=rules,
        )
        result = engine.scan()

        # Should have at least one finding with source_snippet populated
        pywl001 = [f for f in result.findings if str(f.rule_id) == "PY-WL-001"]
        assert len(pywl001) >= 1, f"Expected PY-WL-001 finding, got: {[str(f.rule_id) for f in result.findings]}"
        for f in pywl001:
            assert f.source_snippet is not None, (
                f"source_snippet should be populated, got None for finding at line {f.line}"
            )
            assert f.source_snippet == 'x = data.get("key", "default")'
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/scanner/test_engine.py::TestEngineSnippetPopulation -v`
Expected: FAIL — `source_snippet` is None

- [ ] **Step 3: Add `source` parameter to `_run_rule` and call `populate_snippets`**

In `src/wardline/scanner/engine.py`, modify `_run_rule` (line 871):

Change the signature from:
```python
def _run_rule(
    self,
    rule: RuleBase,
    tree: ast.Module,
    file_path: Path,
    result: ScanResult,
) -> None:
```

To:
```python
def _run_rule(
    self,
    rule: RuleBase,
    tree: ast.Module,
    file_path: Path,
    result: ScanResult,
    source: str | None = None,
) -> None:
```

Then change the body. Replace:
```python
        # Collect findings from the rule into the result
        result.findings.extend(rule.findings)
```

With:
```python
        # Collect findings, populating source_snippet via shared helper
        result.findings.extend(populate_snippets(rule.findings, source))
```

Also add `populate_snippets` to the **top-level** import from `wardline.scanner.context`
(do NOT use an inner import — this is called once per rule per file):

```python
from wardline.scanner.context import Finding, ScanContext, WardlineAnnotation, populate_snippets
```

Then update the single call site at line 553. Change:
```python
            self._run_rule(rule, tree, file_path, result)
```

To:
```python
            self._run_rule(rule, tree, file_path, result, source=source)
```

Note: `source` is a local variable already in scope in `_scan_file()` (read at line 267).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/scanner/test_engine.py::TestEngineSnippetPopulation -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/engine.py tests/unit/scanner/test_engine.py
git commit -m "fix(R3/phase-0): wire populate_snippets into engine._run_rule via source parameter"
```

---

## Task 3: Add `_collect_findings_on_fragment()` (Phase 0)

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py:169-208`
- Test: `tests/unit/scanner/test_corpus_runner.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/unit/scanner/test_corpus_runner.py`:

```python
class TestCollectFindings:
    """Tests for _collect_findings_on_fragment."""

    def test_returns_finding_objects(self) -> None:
        from wardline.cli.corpus_cmds import _collect_findings_on_fragment
        from wardline.scanner.context import Finding
        from wardline.scanner.rules import make_rules

        source = 'def process(data):\n    x = data.get("key", "default")\n'
        rules = make_rules()
        findings = _collect_findings_on_fragment(source, rules, taint_state="EXTERNAL_RAW")
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)
        pywl001 = [f for f in findings if str(f.rule_id) == "PY-WL-001"]
        assert len(pywl001) >= 1

    def test_excludes_suppressed(self) -> None:
        from wardline.cli.corpus_cmds import _collect_findings_on_fragment
        from wardline.core.severity import Severity
        from wardline.scanner.rules import make_rules

        source = 'def process(data):\n    x = data.get("key", "default")\n'
        rules = make_rules()
        findings = _collect_findings_on_fragment(source, rules, taint_state="INTEGRAL")
        for f in findings:
            assert f.severity != Severity.SUPPRESS

    def test_populates_source_snippet(self) -> None:
        from wardline.cli.corpus_cmds import _collect_findings_on_fragment
        from wardline.scanner.rules import make_rules

        source = 'def process(data):\n    x = data.get("key", "default")\n'
        rules = make_rules()
        findings = _collect_findings_on_fragment(source, rules, taint_state="EXTERNAL_RAW")
        pywl001 = [f for f in findings if str(f.rule_id) == "PY-WL-001"]
        assert len(pywl001) >= 1
        assert pywl001[0].source_snippet is not None

    def test_run_rules_on_fragment_unchanged_behavior(self) -> None:
        from wardline.cli.corpus_cmds import _run_rules_on_fragment
        from wardline.scanner.rules import make_rules

        source = 'def process(data):\n    x = data.get("key", "default")\n'
        rules = make_rules()
        fired = _run_rules_on_fragment(source, rules, taint_state="EXTERNAL_RAW")
        assert isinstance(fired, set)
        assert "PY-WL-001" in fired
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py::TestCollectFindings -v`
Expected: FAIL — `ImportError: cannot import name '_collect_findings_on_fragment'`

- [ ] **Step 3: Implement `_collect_findings_on_fragment` and refactor `_run_rules_on_fragment`**

In `src/wardline/cli/corpus_cmds.py`, add `Finding` and `populate_snippets` to the runtime imports (move from `TYPE_CHECKING` block):

```python
from wardline.scanner.context import Finding, ScanContext, populate_snippets
```

Remove the `from wardline.scanner.context import ScanContext` line from the `TYPE_CHECKING` block (it's now a runtime import). Keep `ScanContext` in runtime imports too since it's used at runtime.

Then replace the `_run_rules_on_fragment` function (lines 169-208) with:

```python
def _collect_findings_on_fragment(
    source: str,
    rules: tuple[RuleBase, ...],
    taint_state: str | None = None,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
    optional_fields: tuple[OptionalFieldEntry, ...] = (),
) -> list[Finding]:
    """Run all rules on a source fragment, return non-suppressed findings.

    Findings have source_snippet populated via the shared populate_snippets
    helper — same logic as the scan engine.
    """
    from wardline.core.severity import Severity

    tree = ast.parse(source)

    ctx: ScanContext | None = None
    if taint_state is not None:
        ctx = _build_specimen_context(
            tree,
            taint_state,
            boundaries=boundaries,
            optional_fields=optional_fields,
        )

    all_findings: list[Finding] = []
    for rule in rules:
        rule.findings.clear()
        rule.set_context(ctx)
        try:
            rule.visit(tree)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            logger.warning(
                "Rule %s crashed on specimen: %s", rule.RULE_ID, exc,
            )
            continue
        all_findings.extend(
            f for f in rule.findings if f.severity != Severity.SUPPRESS
        )
    return populate_snippets(all_findings, source)


def _run_rules_on_fragment(
    source: str,
    rules: tuple[RuleBase, ...],
    taint_state: str | None = None,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
    optional_fields: tuple[OptionalFieldEntry, ...] = (),
) -> set[str]:
    """Run all rules on a source fragment, return set of fired rule IDs.

    Findings with ``Severity.SUPPRESS`` are excluded — they represent
    matrix cells where the rule is intentionally silent at that taint state.
    """
    findings = _collect_findings_on_fragment(
        source, rules, taint_state,
        boundaries=boundaries, optional_fields=optional_fields,
    )
    return {str(f.rule_id) for f in findings}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py::TestCollectFindings -v`
Expected: All 4 PASS

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest`
Expected: All pass (zero-impact refactor)

- [ ] **Step 6: Commit**

```bash
git add src/wardline/cli/corpus_cmds.py tests/unit/scanner/test_corpus_runner.py
git commit -m "fix(R3/phase-0): add _collect_findings_on_fragment exposing Finding objects"
```

---

## Task 4: Add SARIF Snippet to Region (Phase 1)

**Files:**
- Modify: `src/wardline/scanner/sarif.py:170-180`
- Test: `tests/unit/scanner/test_sarif.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/unit/scanner/test_sarif.py`:

```python
class TestRegionSnippet:
    """Test snippet.text in SARIF region (§3.30.13)."""

    def test_region_includes_snippet_when_present(self) -> None:
        finding = _make_finding(source_snippet='x = data.get("key", "default")')
        report = SarifReport(findings=[finding])
        sarif = report.to_dict()
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert "snippet" in region
        assert region["snippet"]["text"] == 'x = data.get("key", "default")'

    def test_region_omits_snippet_when_none(self) -> None:
        finding = _make_finding(source_snippet=None)
        report = SarifReport(findings=[finding])
        sarif = report.to_dict()
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert "snippet" not in region
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_sarif.py::TestRegionSnippet -v`
Expected: FAIL — `"snippet" not in region`

- [ ] **Step 3: Add snippet to `_make_region`**

In `src/wardline/scanner/sarif.py`, modify `_make_region()` (line 170-180). Add before the `return region` line:

```python
    if finding.source_snippet is not None:
        region["snippet"] = {"text": finding.source_snippet}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/scanner/test_sarif.py::TestRegionSnippet -v`
Expected: Both PASS

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/sarif.py tests/unit/scanner/test_sarif.py
git commit -m "fix(R3/phase-1): add SARIF snippet.text to region for source_snippet findings"
```

---

## Task 5: Add `ExpectedLocation` TypedDict and `_CellStats.location_mismatches` (Phase 2)

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py` (imports and _CellStats)

- [ ] **Step 1: Add TypedDict and update _CellStats**

In `src/wardline/cli/corpus_cmds.py`, add to imports (line 15 area):

```python
from typing import TYPE_CHECKING, Any
```

(No `TypedDict` or `cast` needed — the `expected_match` from YAML is a
plain `dict` at runtime, and `isinstance(x, dict)` cannot narrow to a
TypedDict. Using `dict[str, Any]` with `.get()` is more honest.)

Then add `location_mismatches` to `_CellStats` (line ~38):

```python
    location_mismatches: int = 0
```

- [ ] **Step 2: Run full test suite to verify no regressions**

Run: `uv run pytest`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add src/wardline/cli/corpus_cmds.py
git commit -m "fix(R3/phase-2): add ExpectedLocation TypedDict and location_mismatches counter"
```

---

## Task 6: Add Structural Comparison Helpers (Phase 2)

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py`
- Test: `tests/unit/scanner/test_corpus_runner.py`

- [ ] **Step 1: Write failing tests for comparison helpers**

Add to `tests/unit/scanner/test_corpus_runner.py`:

```python
class TestStructuralComparison:
    """Tests for _normalize_snippet_text, _find_matching_finding, _check_location_match."""

    def test_normalize_strips_and_collapses(self) -> None:
        from wardline.cli.corpus_cmds import _normalize_snippet_text
        assert _normalize_snippet_text("  x =  data.get('k')  ") == "x = data.get('k')"

    def test_normalize_empty_string(self) -> None:
        from wardline.cli.corpus_cmds import _normalize_snippet_text
        assert _normalize_snippet_text("") == ""

    def test_normalize_tabs_and_newlines(self) -> None:
        from wardline.cli.corpus_cmds import _normalize_snippet_text
        assert _normalize_snippet_text("\t  x\n  =  1\t") == "x = 1"

    def test_find_matching_exact_line(self) -> None:
        from wardline.cli.corpus_cmds import _find_matching_finding
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f1 = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        f2 = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=5, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="y = 2", qualname="other",
        )
        result = _find_matching_finding([f1, f2], "PY-WL-001", expected_line=5)
        assert result is f2

    def test_find_matching_no_exact_returns_none(self) -> None:
        from wardline.cli.corpus_cmds import _find_matching_finding
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f1 = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        result = _find_matching_finding([f1], "PY-WL-001", expected_line=10)
        assert result is None

    def test_find_matching_same_line_text_tiebreaker(self) -> None:
        from wardline.cli.corpus_cmds import _find_matching_finding
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f1 = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet='x = data.get("a", 1), data.get("b", 2)',
            qualname="process",
        )
        f2 = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=20,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet='x = data.get("a", 1), data.get("b", 2)',
            qualname="process",
        )
        # With text tiebreaker matching, should find a match
        result = _find_matching_finding(
            [f1, f2], "PY-WL-001", expected_line=2,
            expected_text='x = data.get("a", 1), data.get("b", 2)',
        )
        assert result is not None

    def test_check_location_line_mismatch(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=5, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        ok, reasons = _check_location_match(f, {"line": 2})
        assert not ok
        assert any("line" in r for r in reasons)

    def test_check_location_text_mismatch(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        ok, reasons = _check_location_match(f, {"text": "y = 2"})
        assert not ok
        assert any("text" in r for r in reasons)

    def test_check_location_none_snippet_with_expected_text(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet=None, qualname="process",
        )
        ok, reasons = _check_location_match(f, {"text": "x = 1"})
        assert not ok
        assert any("None" in r for r in reasons)

    def test_check_location_function_mismatch(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="wrong_func",
        )
        ok, reasons = _check_location_match(f, {"function": "process"})
        assert not ok
        assert any("function" in r for r in reasons)

    def test_check_location_all_pass(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        ok, reasons = _check_location_match(f, {"line": 2, "text": "x = 1", "function": "process"})
        assert ok
        assert reasons == []

    def test_check_location_partial_fields(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = 1", qualname="process",
        )
        ok, reasons = _check_location_match(f, {"line": 2})
        assert ok

    def test_text_normalization_handles_indentation(self) -> None:
        from wardline.cli.corpus_cmds import _check_location_match
        from wardline.core.severity import Exceptionability, RuleId, Severity
        from wardline.scanner.context import Finding

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="t.py", line=2, col=0,
            end_line=None, end_col=None, message="m", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="x = data.get('key', 'default')",
            qualname="process",
        )
        ok, _ = _check_location_match(f, {"text": "  x = data.get('key',   'default')  "})
        assert ok
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py::TestStructuralComparison -v`
Expected: FAIL — `ImportError: cannot import name '_normalize_snippet_text'`

- [ ] **Step 3: Implement the three helper functions**

Add to `src/wardline/cli/corpus_cmds.py` (after `_collect_findings_on_fragment`):

```python
def _normalize_snippet_text(text: str) -> str:
    """Normalize snippet text for comparison.

    Strips leading/trailing whitespace and collapses internal whitespace
    runs to single spaces. Handles indentation differences between
    source extraction and YAML round-tripping.
    """
    return " ".join(text.split())


def _find_matching_finding(
    findings: list[Finding],
    rule_id: str,
    expected_line: int | None,
    expected_text: str | None = None,
) -> Finding | None:
    """Find the finding matching the expected rule and line.

    Uses (rule_id, line) as the match key. Returns None if no exact line
    match exists — no nearest-line fallback. Uses normalized text as a
    tiebreaker for same-line duplicates.
    """
    candidates = [f for f in findings if str(f.rule_id) == rule_id]
    if not candidates:
        return None
    if expected_line is not None:
        exact = [f for f in candidates if f.line == expected_line]
        if not exact:
            return None
        if len(exact) == 1:
            return exact[0]
        if expected_text is not None:
            norm_expected = _normalize_snippet_text(expected_text)
            for f in exact:
                if _normalize_snippet_text(f.source_snippet or "") == norm_expected:
                    return f
        return exact[0]
    return candidates[0]


def _check_location_match(
    finding: Finding,
    expected: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Check if finding matches expected line/text/function.

    Returns (ok, mismatch_reasons) where mismatch_reasons lists
    which fields failed for diagnostic output.
    """
    mismatches: list[str] = []

    expected_line = expected.get("line")
    if expected_line is not None and finding.line != expected_line:
        mismatches.append(
            f"line: expected {expected_line}, got {finding.line}"
        )

    expected_text = expected.get("text")
    if expected_text is not None:
        if finding.source_snippet is None:
            mismatches.append(
                f"text: expected {expected_text!r}, got None (source_snippet not populated)"
            )
        elif _normalize_snippet_text(finding.source_snippet) != _normalize_snippet_text(expected_text):
            mismatches.append(
                f"text: expected {expected_text!r}, got {finding.source_snippet!r}"
            )

    expected_func = expected.get("function")
    if expected_func is not None:
        actual_func = (
            finding.qualname.rsplit(".", 1)[-1]
            if finding.qualname else None
        )
        if actual_func != expected_func:
            mismatches.append(
                f"function: expected {expected_func!r}, got {actual_func!r}"
            )

    return (len(mismatches) == 0, mismatches)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py::TestStructuralComparison -v`
Expected: All 13 PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/cli/corpus_cmds.py tests/unit/scanner/test_corpus_runner.py
git commit -m "fix(R3/phase-2): add structural comparison helpers"
```

---

## Task 7: Upgrade `_evaluate_specimen()` for Structural Comparison (Phase 2)

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py:211-259`
- Test: `tests/unit/scanner/test_corpus_runner.py`

This is the core change. Refer to the design spec `docs/plans/workstream-b-corpus-verification-upgrade.md` §4.4.5 for the full `_evaluate_specimen` replacement code. The implementation must:

1. Replace `_run_rules_on_fragment` call with `_collect_findings_on_fragment`
2. Derive `fired` set from findings
3. Add structural comparison branch for `isinstance(expected_match, dict)`
4. Add validation for empty dicts and unknown keys
5. Add deprecation warning for boolean `expected_match: true`
6. Handle `match_finding is None` (no exact line match) as a location mismatch

- [ ] **Step 1: Write failing tests for the upgraded `_evaluate_specimen`**

Add integration-style tests that exercise the full pipeline through the CLI. Add to `tests/unit/scanner/test_corpus_runner.py`:

```python
class TestStructuredEvaluation:
    """Tests for structural expected_match in corpus verify pipeline."""

    def test_structured_match_passes(self, tmp_path: Path) -> None:
        """Specimen with correct structured expected_match passes."""
        source = (
            "def f():\n"
            "    try:\n"
            "        pass\n"
            "    except Exception:\n"
            "        pass\n"
        )
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tp.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'taint_state: "EXTERNAL_RAW"\n'
            f'sha256: "{sha}"\n'
            f"expected_match:\n"
            f"  line: 4\n"
            f"  text: 'except Exception:'\n"
            f"  function: f\n"
            f"fragment: |\n"
            f"  def f():\n"
            f"      try:\n"
            f"          pass\n"
            f"      except Exception:\n"
            f"          pass\n"
        )
        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path), "--json"],
        )
        assert result.exit_code == 0

    def test_boolean_expected_match_backward_compat(self, tmp_path: Path) -> None:
        """Boolean expected_match: true still works (deprecation path)."""
        source = (
            "def f():\n"
            "    try:\n"
            "        pass\n"
            "    except Exception:\n"
            "        pass\n"
        )
        sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
        specimen = tmp_path / "tp.yaml"
        specimen.write_text(
            f'rule: "PY-WL-004"\n'
            f'verdict: "true_positive"\n'
            f'expected_match: true\n'
            f'sha256: "{sha}"\n'
            f"fragment: |\n"
            f"  def f():\n"
            f"      try:\n"
            f"          pass\n"
            f"      except Exception:\n"
            f"          pass\n"
        )
        runner = CliRunner()
        result = runner.invoke(
            cli, ["corpus", "verify", "--corpus-dir", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "1 TP" in result.output
        # Deprecation warning must be emitted via click.echo(err=True)
        assert "deprecated" in (result.stderr or "").lower() or "boolean" in (result.stderr or "").lower(), (
            f"Expected deprecation warning in stderr, got: {result.stderr!r}"
        )
```

- [ ] **Step 2: Run tests to verify current behavior**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py::TestStructuredEvaluation -v`
Expected: May pass or fail depending on current state — establishes baseline

- [ ] **Step 3: Implement the upgraded `_evaluate_specimen()`**

Replace the body of `_evaluate_specimen()` in `src/wardline/cli/corpus_cmds.py` with the implementation from the design spec §4.4.5. The key change: replace `_run_rules_on_fragment` with `_collect_findings_on_fragment`, add the structural comparison branch with empty-dict validation, unknown-key warnings, and the `match_finding is None` path.

- [ ] **Step 4: Add location match metrics to `_build_json_report()`**

In `_build_json_report()`, add to each cell dict (after `"cell_verdict": verdict`):

```python
"location_mismatches": s.location_mismatches,
"location_match_rate": (
    round(max(0, s.tp - s.location_mismatches) / s.tp, 4)
    if s.tp > 0 else None
),
```

Add to the summary dict:

```python
"total_location_mismatches": sum(
    s.location_mismatches for s in stats.values()
),
```

**Update `overall_verdict` computation** (line 449). Change:

```python
overall = "PASS" if failing == 0 and no_data == 0 else "FAIL"
```

To:

```python
total_loc_mismatches = sum(s.location_mismatches for s in stats.values())
overall = "PASS" if failing == 0 and no_data == 0 and total_loc_mismatches == 0 else "FAIL"
```

This ensures `corpus publish` (which reads `overall_verdict`) also fails
when location mismatches exist. Without this, the conformance file would
claim PASS despite structural verification failures.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/unit/scanner/test_corpus_runner.py -v`
Expected: All pass including new and existing tests

- [ ] **Step 6: Run full test suite**

Run: `uv run pytest`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add src/wardline/cli/corpus_cmds.py tests/unit/scanner/test_corpus_runner.py
git commit -m "fix(R3/phase-2): add structured expected_match comparison to corpus verify"
```

---

## Task 8: Write Migration Script (Phase 3)

**Files:**
- Create: `scripts/migrate_expected_match.py`
- Test: `tests/unit/scripts/test_migrate_expected_match.py`

This is the largest task. Refer to the design spec §4.5.1-4.5.3 for full requirements. Key constraints:

- **Oracle independence:** MUST NOT import from `wardline.scanner.rules`, `wardline.scanner.engine`, or `wardline.scanner.taint`
- **YAML safety:** Use `WardlineSafeLoader` for reading, `yaml.SafeDumper` with `explicit_start=True` for writing
- **Idempotent:** Skip already-migrated specimens (dict expected_match)
- **Dry-run mode:** `--dry-run` flag
- **Fragment integrity:** Verify sha256 still matches after write-back
- **AST patterns:** Follow the corrected pattern table from the design spec §4.5.2.
  **Critical corrections from R3 review:**
  - PY-WL-003 patterns 2-3: check BOTH sides of comparison bidirectionally
  - PY-WL-005: match 4 body types (pass/continue/break/Ellipsis), not just pass
  - PY-WL-006: MANUAL ONLY (dominance analysis, not simple "logging in handler")
  - Auto-migratable rules: PY-WL-001, 002, 003, 004, 005, 007
  - Manual-only rules: PY-WL-006, 008, 009

- [ ] **Step 1: Write migration script safety tests**

Create `tests/unit/scripts/test_migrate_expected_match.py` with tests for import boundary, no-exec-eval, idempotency, dry-run, and TN preservation. See design spec §4.5.5 for the full test list.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scripts/test_migrate_expected_match.py -v`
Expected: FAIL — script doesn't exist yet

- [ ] **Step 3: Implement migration script**

Create `scripts/migrate_expected_match.py` following the design spec §4.5.2. Implement AST patterns for PY-WL-001 through PY-WL-005 and PY-WL-007 (auto-migratable). PY-WL-006, PY-WL-008, PY-WL-009 are manual-only — the script should skip them gracefully.

- [ ] **Step 4: Run safety tests**

Run: `uv run pytest tests/unit/scripts/test_migrate_expected_match.py -v`
Expected: All pass

- [ ] **Step 5: Update oracle test (must ship in same commit)**

Update `tests/unit/corpus/test_corpus_oracle.py:53-67` per design spec §4.5.4. This prevents `dict is not True` breakage.

- [ ] **Step 6: Run migration in dry-run mode**

Run: `uv run python scripts/migrate_expected_match.py --dry-run --verbose`
Expected: Summary output showing how many specimens would be migrated

- [ ] **Step 7: Run actual migration**

Run: `uv run python scripts/migrate_expected_match.py --verbose`
Expected: Summary with Migrated count > 0

- [ ] **Step 8: Run full test suite**

Run: `uv run pytest`
Expected: All pass including updated oracle test

- [ ] **Step 9: Commit**

```bash
git add scripts/migrate_expected_match.py tests/unit/scripts/test_migrate_expected_match.py tests/unit/corpus/test_corpus_oracle.py corpus/specimens/
git commit -m "fix(R3/phase-3): migrate specimens and update oracle test (AST-reimplemented)"
```

---

## Task 9: Coverage Gates, Manifest, Generation, CODEOWNERS (Phase 4)

**Files:**
- Modify: `tests/unit/corpus/test_corpus_oracle.py`
- Modify: `tests/integration/test_corpus_verify.py`
- Modify: `scripts/generate_corpus.py`
- Regenerate: `corpus/corpus_manifest.json`

- [ ] **Step 1: Add coverage and structural integrity tests**

Add `test_structured_expected_match_coverage` (≥80% floor) and `test_no_new_boolean_expected_match_for_auto_migrated_rules` to `tests/unit/corpus/test_corpus_oracle.py`. Add `test_real_corpus_zero_location_mismatches` and `test_migrated_specimens_structural_integrity` to `tests/integration/test_corpus_verify.py`. See design spec §4.6.1-4.6.5 for exact code.

**Key implementation notes from R3 review:**
- `auto_rules` set must be `{PY-WL-001..005, PY-WL-007}` — NOT including 006
- Use `s.get("rule", "") or s.get("rule_id", "")` for dual-key compat
- Coverage tests must load manifest data inline: `data = json.loads(manifest_path.read_text(encoding="utf-8"))`
- CI gate should use `.get()` for robustness: `total = data.get("summary", {}).get("total_location_mismatches")` then `assert total is not None` before `assert total == 0`
- Structural integrity test should also validate `function` field when present

- [ ] **Step 2: Run new tests**

Run: `uv run pytest tests/unit/corpus/test_corpus_oracle.py tests/integration/test_corpus_verify.py -v -m "not network"`
Expected: All pass

- [ ] **Step 3: Update generation script**

Modify `scripts/generate_corpus.py` to produce structured `expected_match` for new TP specimens. Fix `yaml.dump` to use `SafeDumper`. See design spec §4.6.4.

- [ ] **Step 4: Regenerate corpus manifest**

Run: `uv run python scripts/generate_corpus.py`
Verify: `corpus/corpus_manifest.json` updated with structured `expected_match` values

- [ ] **Step 5: Add CODEOWNERS**

Add or update `.github/CODEOWNERS`:
```
corpus/specimens/ @wardline-corpus-reviewers
```

- [ ] **Step 6: Run full test suite**

Run: `uv run pytest`
Expected: All pass

- [ ] **Step 7: Run self-hosting scan**

Run: `uv run wardline scan src/`
Expected: No new findings from these changes

- [ ] **Step 8: Commit**

```bash
git add tests/unit/corpus/test_corpus_oracle.py tests/integration/test_corpus_verify.py scripts/generate_corpus.py corpus/corpus_manifest.json .github/CODEOWNERS
git commit -m "fix(R3/phase-4): manifest, generation, coverage gates, CODEOWNERS, CI location gate"
```

---

## Verification

After all tasks, run the acceptance gate:

```bash
uv run wardline corpus verify --json | python -c "
import json, sys
data = json.load(sys.stdin)
m = data['summary']['total_location_mismatches']
print(f'Location mismatches: {m}')
assert m == 0, f'FAIL: {m} location mismatches'
print('PASS: zero location mismatches')
"
```
