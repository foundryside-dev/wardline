# Workstream B: Corpus Verification Upgrade

> **Purpose:** Spec and implementation plan for upgrading corpus `expected_match`
> from boolean to structured object with SARIF snippet comparison (R3).
> Give this to an implementation agent. It is self-contained.

**Branch:** `phase-4.4-test-quality-gates`
**Conformance review:** `docs/requirements/spec-fitness/conformance-review-2026-04-09.md`
**Spec authority:** `docs/spec/wardline-01-10-verification-properties.md`
**Review date:** 2026-04-09 R1, 2026-04-10 R2 (7-reviewer panel: SA, ST, PE, QE, SecArch, SA-Tool-Dev, IRAP)

---

## 1. Problem Statement

The external conformance review (2026-04-09) identified that corpus verification
only confirms "did the rule fire" — not "did it fire at the correct location
with the correct text." This weakens verification property 1 (the corpus oracle)
from a location-precise assertion to a coarse presence check.

| Finding | Severity | Description |
|---------|----------|-------------|
| R3 | CRITICAL | `expected_match` is a boolean, not the structured `{line, text, function}` the spec requires. Verification does not compare snippet text or line number. |

**Security context:** This is a security product. Verifying that a rule fires
is not sufficient — we must verify it fires at the right location with the right
source text. A rule that fires on line 3 instead of line 6 may be matching a
false pattern rather than the actual violation.

---

## 2. Normative Requirements (from §10)

### 2.1 Structured `expected_match`

The spec defines `expected_match` as a structured object, not a boolean:

```yaml
expected_match:
  line: 6                          # 1-indexed line within fragment
  text: 'record.get("security_classification", "OFFICIAL")'  # literal source
  function: "get_audit_record"     # enclosing function name
```

For true_negative and known_false_negative specimens, `expected_match` remains
`false` (boolean) because no finding is expected.

### 2.2 SARIF Snippet in Region

The spec (§10.1) shows that SARIF results must include snippet text in the
region:

```json
"region": {
  "startLine": 6,
  "startColumn": 5,
  "snippet": { "text": "record.get(\"security_classification\", \"OFFICIAL\")" }
}
```

The current `_make_region()` in `sarif.py:170-180` does NOT include the
`snippet` field. The `source_snippet` field on `Finding` exists but is `None`
in ALL rule Finding constructors — no rule currently populates it.

### 2.3 Verification Comparison

The spec states (§10, line 44):

> "Verification compares these fields against the SARIF result's
> `locations[0].physicalLocation.region.startLine`,
> `locations[0].physicalLocation.region.snippet.text`, and the enclosing
> `logicalLocation`. The `text` field MUST match the SARIF `snippet.text`
> exactly."

Verification must compare:
1. `expected_match.line` against finding's `startLine` (within the fragment)
2. `expected_match.text` against finding's `snippet.text` (normalized match)
3. `expected_match.function` against finding's enclosing qualname

### 2.4 Text Normalization Contract

**IMPORTANT:** Exact byte-for-byte comparison of `text` fields is fragile
because source snippets may include leading indentation that YAML block scalars
strip. The normalization contract is:

1. Both sides strip leading/trailing whitespace before comparison.
2. Both sides normalize internal whitespace runs to single spaces.
3. This normalization happens at comparison time, not at storage time — stored
   values preserve the original text.

This avoids systematic mismatches on indented code while remaining precise
enough to catch actual text differences. The normalization function must be
a shared helper used by both verification and migration validation.

---

## 3. Current State Audit

### 3.1 Specimen Format

**Location:** `corpus/specimens/{RULE}/{TAINT_STATE}/{positive,negative}/`

Each specimen is a YAML file. Example (`corpus/specimens/PY-WL-001/EXTERNAL_RAW/positive/PY-WL-001-TP-01.yaml`):

```yaml
---
specimen_id: "PY-WL-001-TP-01"
description: "dict.get() with default value fires PY-WL-001"
rule: "PY-WL-001"
fragment: |
  def process(data):
      x = data.get("key", "default")
taint_state: "EXTERNAL_RAW"
expected_rules:
  - "PY-WL-001"
expected_severity: "ERROR"
expected_exceptionability: "STANDARD"
expected_match: true                # ← THIS IS THE PROBLEM: boolean, not structured
sha256: "fde5ab3dd8c9e06f9da8a26d1cfe64280ee6e33d25e69bfa541b06a4764517b5"
verdict: "true_positive"
```

### 3.2 Corpus Manifest

**Location:** `corpus/corpus_manifest.json`

JSON index of all specimens. Each entry has `expected_match` as a boolean.
The manifest must be regenerated after specimen changes.

**Generation script:** `scripts/generate_corpus.py` — sets `expected_match`
as boolean (`tp_will_fire` at line 137, `False` at lines 164 and 197).

### 3.3 Verification Code

**Location:** `src/wardline/cli/corpus_cmds.py`

Key function: `_evaluate_specimen()` at lines 211-259.

Current logic at lines 240-258:
```python
rule_fired = rule_id in fired
# TP + rule_fired → tp += 1
# TP + no rule → fn += 1
# TN + rule_fired → fp += 1
# TN + no rule → tn += 1
# KFN → kfn += 1
```

**Critical:** The `expected_match` field is populated on specimens but **never
consulted** during verification. The function calls `_run_rules_on_fragment()`
which returns `set[str]` (fired rule IDs only) — Finding objects are discarded
at line 207. Verification checks `rule_id in fired` — a pure boolean presence
check.

### 3.4 SARIF Region (snippet gap)

**Location:** `src/wardline/scanner/sarif.py:170-180`

```python
def _make_region(finding: Finding) -> dict[str, Any]:
    """Build a SARIF region dict, omitting None fields."""
    region: dict[str, Any] = {
        "startLine": finding.line,
        "startColumn": finding.col + 1,  # SARIF uses 1-based columns
    }
    if finding.end_line is not None:
        region["endLine"] = finding.end_line
    if finding.end_col is not None:
        region["endColumn"] = finding.end_col + 1
    return region
```

Missing: `"snippet": {"text": finding.source_snippet}` when
`finding.source_snippet` is not None.

### 3.5 Finding Fields Available

From `src/wardline/scanner/context.py:22-50`:

```python
@dataclass(frozen=True, kw_only=True)
class Finding:
    rule_id: RuleId
    file_path: str
    line: int              # 1-indexed line number
    col: int               # 0-indexed column
    end_line: int | None
    end_col: int | None
    message: str
    severity: Severity
    exceptionability: Exceptionability
    taint_state: TaintState | None
    analysis_level: int
    source_snippet: str | None   # ← exists but ALWAYS None — no rule populates it
    qualname: str | None = None  # ← enclosing function name, IS populated by rules
    ...
```

### 3.6 `_run_rules_on_fragment()` Returns Only Rule IDs

**Location:** `src/wardline/cli/corpus_cmds.py:169-208`

```python
def _run_rules_on_fragment(
    source: str,
    rules: tuple[RuleBase, ...],
    taint_state: str | None = None,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
    optional_fields: tuple[OptionalFieldEntry, ...] = (),
) -> set[str]:
    """Run all rules on a source fragment, return set of fired rule IDs."""
    ...
    fired: set[str] = set()
    for rule in rules:
        rule.findings.clear()
        rule.set_context(ctx)
        try:
            rule.visit(tree)
        except (...) as exc:
            continue
        if any(f.severity != Severity.SUPPRESS for f in rule.findings):
            fired.add(str(rule.RULE_ID))
    return fired
```

Finding objects are discarded after checking whether they exist. The
migration script AND verification logic both need actual Finding objects.

### 3.7 `source_snippet` Is Never Populated

**CRITICAL PREREQUISITE DISCOVERY:** Every rule in the codebase passes
`source_snippet=None` when constructing Finding objects:

- `base.py:215` (`_emit_matrix_finding`): `source_snippet=None`
- `py_wl_001.py:195`: `source_snippet=None`
- `engine.py:910` (TOOL-ERROR fallback): `source_snippet=None`
- Every other rule file: same pattern

The data needed for structured verification does NOT exist yet.
**Phase 0 must populate `source_snippet` before any other phase can work.**

### 3.8 Test Coverage

**Unit tests:** `tests/unit/scanner/test_corpus_runner.py`
- `TestNoExecEval` (lines 20-87) — security invariants (no exec/eval/compile)
- `TestHashVerification` (lines 90-234) — SHA-256 hash verification
- `TestVerdictEvaluation` (lines 237-499) — tests TP/TN/KFN classification
- `TestPerCellStats` (lines 501-521) — metric accumulation
- `TestCorpusVerifyJson` (lines 524-568) — JSON output structure

**Integration test:** `tests/integration/test_corpus_verify.py`
- `TestCorpusVerifyIntegration` — runs on fixture corpus
- `TestRealCorpusVerify` (line 49) — runs on real corpus, checks `exit_code == 0`

**Oracle test:** `tests/unit/corpus/test_corpus_oracle.py`
- `test_expected_match_aligns_with_verdict` (line 53) — **WILL BREAK after
  migration** because it checks `expected is not True` for TP specimens.
  After migration, TP `expected_match` is a dict, and `dict is not True`
  evaluates to `True`, so every migrated specimen will false-positive.

**SARIF test:** `tests/unit/scanner/test_sarif.py`
- `test_result_property_bag_qualname_and_snippet` (line 157) — tests
  `wardline.sourceSnippet` in properties bag
- No existing test for `snippet.text` in SARIF region (different location)

---

## 4. Implementation Plan

### 4.1 Execution Order and Dependencies

```
Phase 0: Populate source_snippet + expose Finding objects  ─── PREREQUISITE
  │
Phase 1: SARIF snippet emission (now has data)
  │
Phase 2: Structural comparison logic (backward-compat)     ─── BEFORE data migration
  │
Phase 3: Specimen metadata migration (AST-derived values)  ─── AFTER comparison code
  │
Phase 4: Manifest, generation, oracle tests, sunset boolean fallback
```

**CRITICAL ORDERING NOTE:** Phase 2 (structural comparison) MUST land before
Phase 3 (specimen migration). If migrated specimens (structured dicts) exist
without the comparison logic, `_evaluate_specimen()` treats dicts as truthy
booleans, silently passing without structural comparison. Three independent
reviewers confirmed this creates a verification bypass.

### 4.2 Phase 0: Populate `source_snippet` and Expose Finding Objects

This phase adds two infrastructure prerequisites that the entire plan depends on.

#### 4.2.1 Populate `source_snippet` in Engine Post-Processing

**Files:**
- Modify: `src/wardline/scanner/engine.py:871-913` (`_run_rule()`)

**Approach:** After `rule.visit(tree)` completes and before findings are
collected into the result, populate `source_snippet` for any finding that
has `source_snippet=None`. Use line-range extraction from the source text
(NOT `ast.get_source_segment()`, which has edge cases on Python 3.12+ where
it returns `None` for Match case patterns and nodes with missing
`end_col_offset`).

**Change in `_run_rule()`:** Add `source: str | None` as an explicit
parameter. Do NOT use mutable instance state (`self._current_source`) —
`_run_rule` already receives `tree`, `file_path`, and `result` as explicit
per-file arguments, so `source` follows the same convention. There is
exactly one call site (`_scan_file`, where `source` is already in scope).

```python
def _run_rule(
    self,
    rule: RuleBase,
    tree: ast.Module,
    file_path: Path,
    result: ScanResult,
    source: str | None = None,  # NEW — pass from _scan_file
) -> None:
    """Execute a single rule, catching crashes as TOOL-ERROR findings."""
    try:
        rule.findings.clear()
        rule.visit(tree)

        # Post-process: populate source_snippet via shared helper
        result.findings.extend(
            populate_snippets(rule.findings, source)
        )
    except Exception as exc:
        ...  # existing TOOL-ERROR handling unchanged
```

**Call site change in `_scan_file()`:** Pass the `source` local variable
(already in scope at line 267) to `_run_rule()`:

```python
# In _scan_file(), where _run_rule is called:
self._run_rule(rule, tree, file_path, result, source=source)
```

**Shared helper — `populate_snippets()`:** Extract snippet-population into
a single function used by BOTH the engine and the corpus pipeline. This
prevents logic divergence. Place in `src/wardline/scanner/context.py`
alongside Finding:

```python
from dataclasses import replace

def populate_snippets(
    findings: list[Finding],
    source: str | None,
) -> list[Finding]:
    """Populate source_snippet on findings that lack it.

    Uses line-range extraction from source text. Returns new Finding
    instances (Finding is frozen).
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

**Why line-range slicing, not `ast.get_source_segment()`:**
- `ast.get_source_segment()` requires the original source string and the AST
  node, but rules only expose Finding objects (which don't reference the AST
  node). Storing the AST node on Finding would break the frozen dataclass.
- Line slicing produces predictable output: one stripped line of source.
- This matches what humans would write in `expected_match.text`.
- Line-level granularity is a known limitation for sub-expression findings
  (e.g., `x = data.get(...)` captures the assignment, not just the `.get()`
  call). This is acceptable for corpus specimens (which are deliberately
  simple) and documented as a future enhancement opportunity.

**Tests:** Add to `tests/unit/scanner/test_engine.py` (or new file):
- `test_source_snippet_populated_after_rule_visit` — scan a file, verify
  every finding has `source_snippet is not None`
- `test_source_snippet_is_stripped_source_line` — verify snippet matches
  the stripped source line at the finding's line number
- `test_source_snippet_none_for_out_of_range_line` — finding with line=0
  keeps `source_snippet=None`

#### 4.2.2 Expose Finding Objects from `_run_rules_on_fragment()`

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py:169-208`

**Change:** Add a sibling function that returns Finding objects instead of
just rule ID strings. Refactor `_run_rules_on_fragment()` to call it.

```python
def _collect_findings_on_fragment(
    source: str,
    rules: tuple[RuleBase, ...],
    taint_state: str | None = None,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
    optional_fields: tuple[OptionalFieldEntry, ...] = (),
) -> list[Finding]:
    """Run all rules on a source fragment, return non-suppressed findings."""
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
    # Use SAME shared helper as engine — no duplicated logic
    from wardline.scanner.context import populate_snippets
    return populate_snippets(all_findings, source)


def _run_rules_on_fragment(
    source: str,
    rules: tuple[RuleBase, ...],
    taint_state: str | None = None,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
    optional_fields: tuple[OptionalFieldEntry, ...] = (),
) -> set[str]:
    """Run all rules on a source fragment, return set of fired rule IDs."""
    findings = _collect_findings_on_fragment(
        source, rules, taint_state,
        boundaries=boundaries, optional_fields=optional_fields,
    )
    return {str(f.rule_id) for f in findings}
```

**This is a zero-impact refactor.** `_run_rules_on_fragment()` returns the
same `set[str]` as before. `_evaluate_specimen()` is unchanged. The new
`_collect_findings_on_fragment()` is used by the migration script (Phase 3)
and by the structural comparison (Phase 2).

**Tests:**
- `test_collect_findings_returns_finding_objects` — verify return type is
  `list[Finding]` with expected fields
- `test_collect_findings_excludes_suppressed` — SUPPRESS-severity findings
  are not in the returned list
- `test_collect_findings_populates_source_snippet` — findings have
  non-None `source_snippet`
- `test_run_rules_on_fragment_unchanged_behavior` — existing callers get
  identical `set[str]` results

**Commit:** `fix(R3/phase-0): populate source_snippet and expose Finding objects from corpus pipeline`

---

### 4.3 Phase 1: Add SARIF Snippet to Region

**Files:**
- Modify: `src/wardline/scanner/sarif.py:170-180`

**Change:** In `_make_region()`, add snippet when source_snippet is available:

```python
def _make_region(finding: Finding) -> dict[str, Any]:
    """Build a SARIF region dict, omitting None fields."""
    region: dict[str, Any] = {
        "startLine": finding.line,
        "startColumn": finding.col + 1,  # SARIF uses 1-based columns
    }
    if finding.end_line is not None:
        region["endLine"] = finding.end_line
    if finding.end_col is not None:
        region["endColumn"] = finding.end_col + 1
    if finding.source_snippet is not None:
        region["snippet"] = {"text": finding.source_snippet}
    return region
```

**Keep** `wardline.sourceSnippet` in the properties bag at `sarif.py:231`
too — the properties bag is wardline-specific metadata; the region snippet
is SARIF-standard (§3.30.13). Both serve different consumers.

**Tests:** Add to `tests/unit/scanner/test_sarif.py`:
- `test_region_includes_snippet_when_present` — Finding with
  `source_snippet="x = data.get(...)"` produces region with
  `"snippet": {"text": "x = data.get(...)"}` in the SARIF output
- `test_region_omits_snippet_when_none` — Finding with
  `source_snippet=None` has no `snippet` field in region

**Note:** The existing test `test_result_property_bag_qualname_and_snippet`
(line 157) tests the properties bag location, NOT the region. These are
distinct SARIF locations. The new tests specifically verify the region.

**Commit:** `fix(R3/phase-1): add SARIF snippet.text to region for source_snippet findings`

---

### 4.4 Phase 2: Structural Comparison Logic

**CRITICAL:** This phase lands BEFORE specimen migration (Phase 3).
The comparison code must be in place before any specimen gets a structured
`expected_match`, otherwise dicts evaluate as truthy and silently bypass
verification.

#### 4.4.1 Define `ExpectedLocation` TypedDict

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py` (near imports, after line 28)

```python
from typing import TypedDict

class ExpectedLocation(TypedDict, total=False):
    """Structured expected match for true_positive specimens.

    All fields are optional — you can assert just line, just function,
    or any combination. Missing fields are not checked.
    """
    line: int
    text: str
    function: str
```

**Why TypedDict over `dict[str, Any]`:** mypy strict mode. `dict[str, Any]`
is a type-safety escape hatch. `TypedDict` with `total=False` makes all
fields optional (matching the plan's semantics) while preserving type safety.

**mypy note:** `isinstance(x, dict)` narrows to `dict`, not `ExpectedLocation`
(TypedDict is erased at runtime). Use `cast(ExpectedLocation, x)` after the
isinstance check when passing to functions typed as `ExpectedLocation`, or
keep the function parameter typed as `dict[str, Any]` since it uses `.get()`
defensively. The latter is more honest — choose one approach and be consistent.

#### 4.4.2 Add `location_mismatch` Counter to `_CellStats`

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py:31-44`

```python
@dataclass
class _CellStats:
    """Per-cell (rule x taint_state) verdict counters."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    kfn: int = 0
    location_mismatches: int = 0  # NEW: structural match failures

    @property
    def sample_size(self) -> int:
        return self.tp + self.fp + self.tn + self.fn + self.kfn
```

#### 4.4.3 Add Text Normalization Helper

```python
def _normalize_snippet_text(text: str) -> str:
    """Normalize snippet text for comparison.

    Strips leading/trailing whitespace and collapses internal whitespace
    runs to single spaces. This handles indentation differences between
    source extraction and YAML round-tripping.
    """
    return " ".join(text.split())
```

#### 4.4.4 Add Structural Comparison Helpers

```python
def _find_matching_finding(
    findings: list[Finding], rule_id: str,
    expected_line: int | None,
    expected_text: str | None = None,
) -> Finding | None:
    """Find the finding matching the expected rule and line.

    Uses (rule_id, line) as the match key — NOT ordinal position,
    which is fragile across rule refactors and AST traversal changes.
    Returns None if no exact line match exists — no nearest-line fallback.
    Uses normalized text as a tiebreaker for same-line duplicates.
    """
    candidates = [f for f in findings if str(f.rule_id) == rule_id]
    if not candidates:
        return None
    if expected_line is not None:
        exact = [f for f in candidates if f.line == expected_line]
        if not exact:
            return None  # NO fallback — exact match required
        if len(exact) == 1:
            return exact[0]
        # Same-line tiebreaker: use normalized text comparison
        if expected_text is not None:
            norm_expected = _normalize_snippet_text(expected_text)
            for f in exact:
                if _normalize_snippet_text(f.source_snippet or "") == norm_expected:
                    return f
        return exact[0]  # fallback to first if no text match
    return candidates[0]


def _check_location_match(
    finding: Finding,
    expected: ExpectedLocation,
) -> tuple[bool, list[str]]:
    """Check if finding matches expected line/text/function.

    Returns (ok, mismatch_reasons) where mismatch_reasons lists
    which fields failed for diagnostic output.
    """
    mismatches: list[str] = []

    # Line check
    expected_line = expected.get("line")
    if expected_line is not None and finding.line != expected_line:
        mismatches.append(
            f"line: expected {expected_line}, got {finding.line}"
        )

    # Text check (normalized)
    expected_text = expected.get("text")
    if expected_text is not None:
        if finding.source_snippet is None:
            # source_snippet should have been populated by Phase 0.
            # If it's still None, that is itself a mismatch — not a silent pass.
            mismatches.append(
                f"text: expected {expected_text!r}, got None (source_snippet not populated)"
            )
        elif _normalize_snippet_text(finding.source_snippet) != _normalize_snippet_text(expected_text):
            mismatches.append(
                f"text: expected {expected_text!r}, got {finding.source_snippet!r}"
            )

    # Function check — compare against last component of qualname
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

#### 4.4.5 Upgrade `_evaluate_specimen()`

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py:211-259`

**Change:** After confirming the rule fired, add structural comparison for
true_positive specimens with structured `expected_match`. The change
replaces `_run_rules_on_fragment` with `_collect_findings_on_fragment` so
that Finding objects are available.

```python
def _evaluate_specimen(
    data: dict[str, object],
    source: str,
    rules: tuple[RuleBase, ...],
    stats: dict[tuple[str, str], _CellStats],
) -> None:
    """Evaluate a specimen's verdict against scanner results."""
    rule_id = str(data.get("rule", "") or data.get("rule_id", ""))
    verdict = str(data.get("verdict", ""))

    if not rule_id or not verdict:
        return

    raw_taint = data.get("taint_state")
    taint_state = str(raw_taint) if raw_taint is not None else "UNKNOWN"

    key = (rule_id, taint_state)
    if key not in stats:
        stats[key] = _CellStats()

    boundaries = _parse_specimen_boundaries(data)
    optional_fields = _parse_specimen_optional_fields(data)

    # Use _collect_findings_on_fragment to get Finding objects
    findings = _collect_findings_on_fragment(
        source,
        rules,
        taint_state=taint_state if taint_state != "UNKNOWN" else None,
        boundaries=boundaries,
        optional_fields=optional_fields,
    )
    fired = {str(f.rule_id) for f in findings}
    rule_fired = rule_id in fired

    if verdict == "true_positive":
        if rule_fired:
            stats[key].tp += 1

            # Structural comparison if expected_match is a dict
            expected_match = data.get("expected_match")
            if isinstance(expected_match, dict):
                # Validate dict is not empty and has no unknown keys
                _valid_keys = {"line", "text", "function"}
                unknown = set(expected_match) - _valid_keys
                if unknown:
                    click.echo(
                        f"  warning: {rule_id}/{taint_state}: "
                        f"unknown expected_match keys: {unknown}",
                        err=True,
                    )
                if not expected_match:
                    # Empty dict {} — treat as error, not silent pass
                    click.echo(
                        f"  warning: {rule_id}/{taint_state}: "
                        f"empty expected_match dict (no fields to verify)",
                        err=True,
                    )
                    stats[key].location_mismatches += 1
                else:
                    match_finding = _find_matching_finding(
                        findings, rule_id,
                        expected_match.get("line"),
                        expected_text=expected_match.get("text"),
                    )
                    if match_finding is None:
                        # No finding at expected line — count as mismatch
                        stats[key].location_mismatches += 1
                        click.echo(
                            f"  location mismatch: {rule_id}/{taint_state}: "
                            f"no finding at expected line {expected_match.get('line')}",
                            err=True,
                        )
                    else:
                        ok, reasons = _check_location_match(
                            match_finding, expected_match,
                        )
                        if not ok:
                            stats[key].location_mismatches += 1
                            click.echo(
                                f"  location mismatch: {rule_id}/{taint_state}: "
                                + "; ".join(reasons),
                                err=True,
                            )
            elif isinstance(expected_match, bool) and expected_match:
                # Legacy boolean form — emit deprecation warning via click
                # (not logger.warning, which CliRunner doesn't capture)
                click.echo(
                    f"  deprecated: {data.get('specimen_id', '?')} uses "
                    f"boolean expected_match=true (upgrade to structured form)",
                    err=True,
                )
        else:
            stats[key].fn += 1
    elif verdict == "true_negative":
        if rule_fired:
            stats[key].fp += 1
        else:
            stats[key].tn += 1
    elif verdict == "known_false_negative":
        if rule_fired:
            click.echo(
                f"notice: {rule_id} fired on KFN specimen — consider promoting to true_positive",
                err=True,
            )
        stats[key].kfn += 1
```

#### 4.4.6 Add Location Match Metrics to JSON Report

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py:361-465` (`_build_json_report()`)

Add to each cell dict (after existing fields at line 447):

```python
"location_mismatches": s.location_mismatches,
"location_match_rate": (
    round(max(0, s.tp - s.location_mismatches) / s.tp, 4)
    if s.tp > 0 else None
),
```

Add to the summary dict (after existing fields at line 464):

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

This ensures location mismatches contribute to the overall verdict.
Any consumer of the JSON report (including `corpus publish`) will see
FAIL when structural verification is failing. Without this, `publish`
would generate a conformance file claiming PASS despite location
mismatches, because `publish` reads `overall_verdict` from the report.

#### 4.4.7 Tests

Add to `tests/unit/scanner/test_corpus_runner.py`:

- `test_structured_expected_match_line_mismatch` — finding at line 3 but
  `expected_match.line: 2` produces `location_mismatches == 1` and
  diagnostic output naming the `line` field
- `test_structured_expected_match_text_mismatch` — finding with wrong
  snippet text produces mismatch with `text` field named
- `test_structured_expected_match_function_mismatch` — finding in wrong
  function produces mismatch with `function` field named
- `test_structured_expected_match_all_pass` — all fields match, no mismatch,
  `location_mismatches == 0`
- `test_structured_expected_match_partial_fields` — `expected_match` with
  only `line` (no `text` or `function`) — only line is checked, others
  are skipped
- `test_boolean_expected_match_backward_compat` — old `expected_match: true`
  still works (no structural comparison). **Must assert** the deprecation
  warning is emitted via `click.echo(..., err=True)` (check `result.stderr`
  contains "deprecated" or "boolean"). Use `click.echo` not `logger.warning`
  for the deprecation so it is captured by CliRunner.
- `test_boolean_false_expected_match_no_comparison` — `expected_match: false`
  for TN specimens, no structural comparison attempted
- `test_text_normalization_strips_whitespace` — indented snippet matches
  dedented expected text after normalization
- `test_find_matching_finding_by_rule_and_line` — `(rule_id, line)` key
  match, not ordinal position
- `test_find_matching_finding_no_exact_match_returns_none` — no finding at
  expected line → returns None (no nearest-line fallback)
- `test_find_matching_finding_same_line_text_tiebreaker` — two findings on
  same line, text tiebreaker selects correct one
- `test_source_snippet_none_with_expected_text_is_mismatch` —
  `source_snippet=None` + `expected_match.text` set → explicit mismatch
- `test_empty_dict_expected_match_is_error` — `expected_match: {}` → counted
  as location mismatch with diagnostic
- `test_unknown_keys_in_expected_match_warned` — `expected_match: {lien: 6}`
  → warning about unknown key
- `test_location_mismatch_in_json_report` — JSON output includes
  `location_mismatches` and `location_match_rate` fields

**Commit:** `fix(R3/phase-2): add structured expected_match comparison to corpus verify`

---

### 4.5 Phase 3: Specimen Metadata Migration

This is the bulk of the work. Every true_positive specimen (117 files in
`corpus/specimens/*/positive/`) needs its `expected_match` upgraded from
`true` to a structured object.

#### 4.5.1 Oracle Independence Requirement

**CRITICAL SECURITY CONSTRAINT:** The migration script MUST NOT derive
expected values by running the scanner's rule logic. Running the scanner
to seed its own oracle is circular — if the scanner has a location bug,
the expected value encodes that bug, and verification becomes a tautology.

Three independent reviewers (Systems Thinker, Security Architect, IRAP
Assessor) flagged this as blocking. The IRAP assessor stated: "A
self-calibrated structured `expected_match` would be dishonestly strong."

**The migration script derives values from the fragment source using
`ast.parse()` and AST walking ONLY — completely independent of scanner
rule logic.**

The approach:
1. Parse the fragment with `ast.parse()`
2. Walk the AST to find the enclosing function (`ast.FunctionDef`)
3. For each rule, identify the AST node pattern that would trigger it
   (e.g., `ast.Call` with `.get()` for PY-WL-001)
4. Extract `line` from `node.lineno`, `text` from source line slicing,
   `function` from the enclosing function name

**Import boundary enforcement:** The migration script MUST NOT import from:
- `wardline.scanner.rules` (rule implementations)
- `wardline.scanner.engine` (scan engine)
- `wardline.scanner.taint` (taint propagation)

It MAY import from:
- `wardline.core.severity` (RuleId enum — for rule ID validation only)
- `wardline.manifest.loader` (WardlineSafeLoader — for YAML safety)
- Standard library (`ast`, `yaml`, `pathlib`, `hashlib`, `logging`)

A test must enforce this import boundary (see §4.5.4).

#### 4.5.2 Migration Script

**File:** Create `scripts/migrate_expected_match.py`

**Behavior:**

```
Usage: uv run python scripts/migrate_expected_match.py [--dry-run] [--verbose]

Flags:
  --dry-run   Print changes without writing files
  --verbose   Log each specimen's old → new expected_match
```

**For each specimen YAML file:**
1. Load with `WardlineSafeLoader` (from `wardline.manifest.loader`)
2. Check `verdict`:
   - If `true_negative` or `known_false_negative`: keep `expected_match: false`
   - If `true_positive` and `expected_match` is already a dict: **skip**
     (idempotency — already migrated)
   - If `true_positive` and `expected_match is True`: migrate (below)
3. Parse `fragment` with `ast.parse()`
4. Walk the AST to find the expected match location:
   - Find all `ast.FunctionDef` / `ast.AsyncFunctionDef` nodes
   - For the specimen's `rule` field, apply the rule-specific AST pattern
     (see pattern table below) to find the triggering node
   - Extract:
     - `line`: `node.lineno` (1-indexed, fragment-relative)
     - `text`: `source_lines[node.lineno - 1].strip()` (stripped source line)
     - `function`: enclosing function's simple name
5. Set `expected_match` to structured dict
6. Add `expected_match_source: "ast-reimplemented"` provenance tag (updated
   to `"human-verified"` after review gate)
7. Write updated YAML back. Since the migration rewrites the full file
   content, use `yaml.dump(data, f, Dumper=yaml.SafeDumper,
   default_flow_style=False, sort_keys=False, explicit_start=True)`.
   The `explicit_start=True` emits the `---` document separator
   automatically — do NOT also write `"---\n"` manually (the existing
   `_write_specimen` in `generate_corpus.py:77` does write `"---\n"`
   then calls `yaml.dump` WITHOUT `explicit_start`, but the migration
   script should use `explicit_start=True` instead, which is cleaner).
   Combining both would produce duplicate `---` markers.

**Rule-specific AST patterns for finding the triggering node:**

These patterns were audited against the actual rule implementations
(R2 review, 2026-04-10). Each pattern is listed with its coverage status.

| Rule | AST Pattern | What to Look For | Coverage |
|------|-------------|-----------------|----------|
| PY-WL-001 | `ast.Call` where `func` is `Attribute(attr="get")` on dict | `data.get("key", "default")` | Full |
| PY-WL-002 | `ast.Call` where `func` is `Name(id="getattr")` with 3 args | `getattr(obj, "name", None)` | Full |
| PY-WL-003 | **5 patterns** — see below | Existence checks | Partial — see note |
| PY-WL-004 | **3 patterns** — see below | Broad exception handlers | Partial — see note |
| PY-WL-005 | `ast.ExceptHandler` where `len(body)==1` and body is `Pass`, `Continue`, `Break`, or `Expr(Constant(Ellipsis))` | `except Exception: pass` / `...` / `continue` / `break` | Full |
| PY-WL-006 | **MANUAL ONLY** | Dominance analysis on audit-critical writes (not simple "logging in handler") | N/A |
| PY-WL-007 | `ast.Call` where `func` is `Name(id="isinstance")` | `isinstance(data, dict)` | Full |
| PY-WL-008 | **MANUAL ONLY** | Complex validation patterns | N/A |
| PY-WL-009 | **MANUAL ONLY** | Semantic checks without shape validation | N/A |

**PY-WL-003 detailed patterns** (rule fires on 5 distinct AST shapes):
1. `ast.Compare` with `In` / `NotIn` op — `"key" in data`
2. `ast.Compare` with `Is` / `IsNot` op where **either side** is a `.get()`
   call with exactly 1 positional arg and no kwargs, and the other side is
   `None` — `d.get(k) is None` OR `None is d.get(k)` (bidirectional check,
   confirmed: `py_wl_003.py:362-380`)
3. `ast.Compare` with `Eq` / `NotEq` op where **either side** is a `.get()`
   call (same constraints as pattern 2) and the other side is `None` —
   `d.get(k) == None` OR `None == d.get(k)` (bidirectional)
4. `ast.Call` where `func` is `Name(id="hasattr")` — `hasattr(obj, "attr")`
5. `ast.MatchMapping` or `ast.MatchClass` — structural pattern matching

**CRITICAL for patterns 2-3:** The migration script must check BOTH sides
of the comparison. The rule implementation checks left-vs-right and
right-vs-left orderings. A migration script that only checks the left side
will miss `None is d.get(k)` specimens.

The migration script should implement patterns 1-4. Pattern 5
(`MatchMapping`/`MatchClass`) is unlikely in existing specimens but the
script should attempt it. If pattern 5 fails, fall through to "no match."

**PY-WL-004 detailed patterns** (rule fires on 3 shapes):
1. `ast.ExceptHandler` with `handler.type is None` — bare `except:`
2. `ast.ExceptHandler` with broad exception type — `except Exception:`
3. `ast.Call` matching `contextlib.suppress(BroadException)` — `suppress(Exception)`

The migration script must handle ALL THREE. The previous version of this
plan incorrectly said "non-bare except" — the rule also fires on bare
`except:` (confirmed: `py_wl_004.py:55-62`).

**PY-WL-006, PY-WL-008, and PY-WL-009 are MANUAL ONLY.** These rules have
complex triggering conditions that cannot be reliably replicated as simple
AST patterns without reimplementing rule logic:
- PY-WL-006: performs dominance analysis on audit-critical writes inside
  broad exception handlers — checks whether audit paths can be bypassed,
  not whether logging calls appear. The finding node can be a `FunctionDef`,
  not just an `ExceptHandler`.
- PY-WL-008: semantic validation patterns (shape-check absence)
- PY-WL-009: semantic checks without shape validation

Specimens for these rules will remain on boolean `expected_match: true`
after auto-migration and must be manually authored.

**Important:** These patterns are INDEPENDENT of the scanner's rule
implementations. They are AST pattern matchers derived from reading the
spec's rule definitions, not from importing rule code. However, the
patterns encode the same domain knowledge as the rules — this is
"reimplementation independence," not true oracle independence. The human
review gate (§10.1) provides the independent verification layer.

**Error handling:**
- If fragment fails `ast.parse()`: log error, skip specimen, continue
- If no matching AST pattern found: log warning, keep `expected_match: true`,
  continue (do not fabricate values)
- If function name cannot be determined (module-level code): set
  `function: null` in the structured form

**Idempotency:** If `expected_match` is already a dict, skip the specimen.
This means the script can be run multiple times safely.

**Summary output:**
```
Migration complete:
  Migrated:  98
  Skipped (already structured):  0
  Skipped (TN/KFN):  135
  Failed (no AST match):  19
  Failed (parse error):  0
```

**Validation pass:** After writing, re-read every migrated specimen and
verify:
- YAML parses successfully (using `WardlineSafeLoader`, not bare `safe_load`)
- `expected_match` is a dict with at least `line` and `text` keys
- `expected_match.line` is a positive integer
- `expected_match.text` is a non-empty string
- `expected_match` dict keys are all in `{"line", "text", "function"}` — no typos
- Round-trip: `yaml.load(yaml.dump(data, Dumper=SafeDumper), Loader=WardlineSafeLoader)["expected_match"]`
  equals the written value
- **Fragment integrity:** After write-back, verify `sha256` still matches
  the `fragment` field. YAML re-serialization can alter block scalar style
  (trailing newlines, chomping). If the hash breaks, either (a) recompute
  and update `sha256`, or (b) use a text-level patch that only modifies the
  `expected_match` line without re-serializing the full file

#### 4.5.3 Specimens That Cannot Be Auto-Migrated

Some specimens may not match the AST patterns above (e.g., adversarial
specimens with unusual code patterns, or rules PY-WL-006 through PY-WL-009
which have complex triggering conditions). For these:

1. The migration script leaves `expected_match: true` (boolean)
2. Phase 2's comparison code handles this via the boolean fallback path
   (with deprecation warning)
3. These specimens are tracked in the migration summary as "Failed (no AST match)"
4. A follow-up task should be created to manually author their structured
   `expected_match` values

#### 4.5.4 Update Oracle Test (moved from Phase 4 to prevent inter-commit breakage)

**IMPORTANT:** This update MUST ship in the same commit as the specimen
migration. Otherwise, between Phase 3 and Phase 4, the oracle test
`test_expected_match_aligns_with_verdict` will fail because `dict is not True`
evaluates to `True`, triggering false mismatches for every migrated specimen.

**Files:**
- Modify: `tests/unit/corpus/test_corpus_oracle.py:53-67`

**Updated code:**
```python
def test_expected_match_aligns_with_verdict(self) -> None:
    for s in data["specimens"]:
        verdict = s["verdict"]
        expected = s.get("expected_match")
        if verdict == "true_positive":
            # Structured dict or legacy boolean True — both valid
            if not (isinstance(expected, dict) or expected is True):
                mismatches.append(
                    f"{s['specimen_id']}: TP but expected_match={expected}"
                )
            # If structured, validate required keys
            if isinstance(expected, dict):
                if "line" not in expected or "text" not in expected:
                    mismatches.append(
                        f"{s['specimen_id']}: TP structured match missing line/text"
                    )
        elif verdict == "true_negative" and expected is not False:
            mismatches.append(
                f"{s['specimen_id']}: TN but expected_match={expected}"
            )
```

#### 4.5.5 Tests for Migration Script

Add `tests/unit/scripts/test_migrate_expected_match.py`:

- `test_migration_script_does_not_import_scanner_rules` — snapshot
  `set(sys.modules.keys())` BEFORE importing the migration script, import
  it, then check the DELTA for `wardline.scanner.rules`,
  `wardline.scanner.engine`, or `wardline.scanner.taint`. Must use
  before/after delta (not absolute check) because earlier tests in the
  suite may have already imported these modules.
- `test_migration_script_no_exec_eval` — same pattern as
  `TestNoExecEval` in `test_corpus_runner.py`: patch `builtins.exec` and
  `builtins.eval`, run migration, verify they are never called
- `test_migration_script_uses_safe_loader` — verify YAML loading uses
  `WardlineSafeLoader`, not bare `yaml.safe_load` or `yaml.load`
- `test_migration_idempotent` — run migration twice on same specimen,
  verify output is identical
- `test_migration_dry_run` — `--dry-run` flag does not modify files
- `test_migration_preserves_tn_specimens` — TN/KFN specimens keep
  `expected_match: false`
- `test_migration_round_trip_yaml` — migrated YAML round-trips through
  `safe_load(safe_dump(...))` without loss

**Commit:** `fix(R3/phase-3): migrate specimen expected_match from boolean to structured (AST-derived)`

---

### 4.6 Phase 4: Manifest, Generation, Coverage Gates, Boolean Sunset

**Note:** The oracle test update (`test_expected_match_aligns_with_verdict`)
was moved into Phase 3 (§4.5.4) to prevent inter-commit test breakage.

#### 4.6.1 Add Independent Structural Integrity Test

**Files:**
- Add to: `tests/integration/test_corpus_verify.py`

This test reads actual migrated corpus files independently of the migration
script's own validation pass — catching bugs the script's internal checks
would miss (e.g., writing to the wrong file, YAML serialization quirks).

```python
def test_migrated_specimens_structural_integrity(self) -> None:
    """Every TP specimen with structured expected_match has valid fields."""
    import yaml
    from wardline.manifest.loader import make_wardline_loader

    Loader = make_wardline_loader()
    specimens_dir = self._CORPUS_ROOT / "specimens"
    invalid: list[str] = []

    for yaml_path in specimens_dir.glob("**/positive/*.yaml"):
        with open(yaml_path) as f:
            data = yaml.load(f, Loader=Loader)
        em = data.get("expected_match")
        if not isinstance(em, dict):
            continue  # boolean — skip (covered by coverage test)
        if not isinstance(em.get("line"), int) or em["line"] < 1:
            invalid.append(f"{yaml_path.name}: line={em.get('line')}")
        if not isinstance(em.get("text"), str) or not em["text"].strip():
            invalid.append(f"{yaml_path.name}: text={em.get('text')!r}")

    assert not invalid, (
        f"{len(invalid)} specimens have invalid structured expected_match: "
        f"{invalid[:10]}"
    )
```

#### 4.6.2 Add Structured Coverage Metric Test

Add to `tests/unit/corpus/test_corpus_oracle.py`:

```python
def test_structured_expected_match_coverage(self) -> None:
    """At least 80% of TP specimens must use structured expected_match."""
    tp_total = 0
    tp_structured = 0
    tp_boolean: list[str] = []
    for s in data["specimens"]:
        if s["verdict"] == "true_positive":
            tp_total += 1
            if isinstance(s.get("expected_match"), dict):
                tp_structured += 1
            else:
                tp_boolean.append(s["specimen_id"])

    assert tp_total > 0, "No TP specimens found"
    ratio = tp_structured / tp_total

    # Floor: 80% structured. Raise as specimens are manually migrated.
    # Target: 100% before v1.0 ships.
    assert ratio >= 0.80, (
        f"Structured expected_match coverage too low: "
        f"{tp_structured}/{tp_total} ({ratio:.0%}). "
        f"Boolean specimens: {tp_boolean[:10]}"
    )
    print(f"Structured expected_match coverage: {tp_structured}/{tp_total} ({ratio:.0%})")
```

#### 4.6.2b Prevent New Boolean Specimens

Add to `tests/unit/corpus/test_corpus_oracle.py`:

```python
def test_no_new_boolean_expected_match_for_auto_migrated_rules(self) -> None:
    """Rules with auto-migration support must not have boolean expected_match.

    PY-WL-001 through PY-WL-007 have mechanical AST patterns.
    New specimens for these rules must use structured expected_match.
    PY-WL-008 and PY-WL-009 are excluded (manual-only).
    """
    # PY-WL-001 through PY-WL-005 and PY-WL-007 have mechanical AST patterns.
    # PY-WL-006, PY-WL-008, PY-WL-009 are manual-only (complex triggering).
    auto_rules = {f"PY-WL-{i:03d}" for i in (1, 2, 3, 4, 5, 7)}
    violations: list[str] = []
    for s in data["specimens"]:
        rule = s.get("rule", "") or s.get("rule_id", "")
        if (
            s["verdict"] == "true_positive"
            and rule in auto_rules
            and s.get("expected_match") is True
        ):
            violations.append(s["specimen_id"])

    assert not violations, (
        f"{len(violations)} auto-migratable specimens still use boolean "
        f"expected_match: {violations[:10]}"
    )
```

#### 4.6.3 Regenerate Corpus Manifest

After Phase 3 upgrades specimens, regenerate `corpus/corpus_manifest.json`.
The manifest's `expected_match` field must reflect the specimen's value
(structured dict for TP, `false` for TN/KFN).

#### 4.6.4 Update Generation Script

**Files:**
- Modify: `scripts/generate_corpus.py:128-139`

When creating new true_positive specimens, the script must compute and
populate the structured `expected_match` using AST analysis of the fragment
(same approach as the migration script — no scanner invocation).

Replace line 137:
```python
"expected_match": tp_will_fire,
```

With:
```python
"expected_match": (
    _compute_expected_location(tp_frag, rule_str)
    if tp_will_fire else False
),
```

Where `_compute_expected_location()` uses the same AST pattern matching
as the migration script (shared code or duplicated — implementor's choice,
but the patterns must be identical).

**YAML safety:** Also fix the existing inconsistency: `generate_corpus.py`
line 76 uses `yaml.dump()` with the default Dumper. Change to
`yaml.dump(data, f, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False)`
to match the project's security posture.

#### 4.6.5 Add CI Gate for Location Mismatches

**Files:**
- Modify: `tests/integration/test_corpus_verify.py:49-59`

Add to `TestRealCorpusVerify`:

```python
def test_real_corpus_zero_location_mismatches(self) -> None:
    """corpus verify --json reports zero location mismatches."""
    import json

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["corpus", "verify", "--corpus-dir", str(self._CORPUS_ROOT), "--json"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    total_mismatches = data["summary"]["total_location_mismatches"]
    assert total_mismatches == 0, (
        f"Expected 0 location mismatches, got {total_mismatches}"
    )
```

#### 4.6.7 Add CODEOWNERS Entry

**Files:**
- Modify or create: `.github/CODEOWNERS` (or equivalent)

Add:
```
corpus/specimens/ @wardline-corpus-reviewers
```

This is a spec §10 MUST — changes to corpus specimens require designated
reviewer approval.

#### 4.6.8 Tests

- Add `test_structured_expected_match_coverage` as shown above
- Add `test_no_new_boolean_expected_match_for_auto_migrated_rules` as shown above
- Add `test_real_corpus_zero_location_mismatches` to integration tests
- Add `test_migrated_specimens_structural_integrity` to integration tests
- Add `test_generate_corpus_produces_structured_match` — run generation
  script on a single TP fragment, verify output has structured `expected_match`

**Note:** The oracle test update (`test_expected_match_aligns_with_verdict`)
ships in Phase 3 (§4.5.4), not Phase 4.

**Commit:** `fix(R3/phase-4): manifest, generation, coverage gates, CODEOWNERS, CI location gate`

---

### 4.7 Follow-Up Tasks (not in scope, track as issues)

These items were identified during review but are out of scope for this
workstream. Create tracking issues:

1. **SARIF `logicalLocations` emission.** The spec §10 references
   `logicalLocations` for verification comparison. The current SARIF output
   only places `qualname` in the properties bag (`wardline.qualname`), not in
   the standard SARIF `logicalLocations` array. Corpus verification works
   around this by comparing against `Finding.qualname` directly, but external
   SARIF consumers (GitHub Code Scanning, Azure DevOps) cannot extract
   enclosing function context from the non-standard location.

2. **Manual authoring of structured `expected_match` for PY-WL-006, PY-WL-008,
   and PY-WL-009 specimens.** These rules have complex triggering conditions
   that cannot be mechanically derived. Target: all specimens structured
   before v1.0.

5. **Specimen `category` field.** The spec §10 specimen schema requires a
   `category` field (`standard`, `adversarial_false_positive`,
   `adversarial_false_negative`, `taint_flow`, `suppression_interaction`).
   Existing specimens lack this field. Add `category: standard` to all
   existing specimens and `category: adversarial_*` to adversarial specimens.
   Required for assessors to evaluate adversarial coverage.

3. **Expression-level snippet extraction.** Current snippets are full
   stripped source lines. For sub-expression findings (e.g.,
   `data.get("key", "default")` on a line with an assignment), the snippet
   includes the assignment target. A future enhancement could use column
   offsets to extract the precise triggering expression.

4. **Pattern drift detection test.** Add a cross-validation test that runs
   both the scanner and the AST pattern matcher on a subset of specimens and
   asserts they agree on triggering node line numbers. This catches drift
   between the generation script's patterns and the scanner's actual rules.

---

## 5. Correctness Constraints

1. **Line numbers are fragment-relative.** When running a specimen fragment
   through the scanner, line numbers in findings are already relative to the
   fragment (since the fragment IS the entire source). No adjustment needed.

2. **Text comparison uses normalization.** Both sides are normalized via
   `_normalize_snippet_text()` (strip + collapse whitespace) before
   comparison. This handles indentation differences from YAML round-tripping.

3. **Function name is the simple name.** `expected_match.function` is
   `"process"`, not `"module.MyClass.process"`. Comparison extracts from
   `finding.qualname` by taking the last `.`-separated component.

4. **Boolean backward compatibility with deprecation.** `expected_match: true`
   (old form) continues to work but logs a deprecation warning. This allows
   incremental migration. Specimens that cannot be auto-migrated keep the
   boolean form until manually authored.

5. **`expected_match: false`** means "rule should NOT fire." No structural
   comparison needed — only the absence check.

6. **Finding match by `(rule_id, line)` with exact match required.** If a
   rule fires multiple times on a specimen, match by exact line. If no exact
   match exists, return None (count as location mismatch). For same-line
   duplicates, use normalized `expected_match.text` as a tiebreaker. No
   nearest-line fallback — it masks location bugs.

11. **Single expected match per specimen.** Each true_positive specimen is
    expected to have exactly one triggering location per rule. Multi-finding
    specimens with distinct locations are not supported by this design.
    Document this constraint for future specimen authors.

12. **Empty `expected_match: {}` is an error.** An empty dict passes
    `isinstance(x, dict)` but has no fields to verify. It is rejected with
    a diagnostic and counted as a location mismatch.

13. **`expected_match` dict keys must be from `{"line", "text", "function"}`.**
    Unknown keys (e.g., typos like `lien`) are logged as warnings.

7. **SARIF snippet.text in region.** The snippet field in the SARIF region is
   SARIF-standard (§3.30.13, not wardline-specific). Keep
   `wardline.sourceSnippet` in properties too — both serve different consumers.

8. **Migration script is one-time but idempotent.** Can be run repeatedly
   without changing already-migrated specimens.

9. **Oracle independence.** Migration derives expected values from AST analysis
   of fragment source code. The scanner's rule implementations are NOT invoked.
   An import boundary test enforces this.

10. **Provenance tracking.** Migrated specimens include
    `expected_match_source: "ast-reimplemented"` to honestly communicate that
    values were produced by reimplementing rule patterns (not by an
    independent oracle). After human review, updated to `"human-verified"`.
    This two-tier provenance gives future assessors a clear signal of which
    specimens have been independently confirmed.

---

## 6. Testing Strategy

| Phase | Test Location | What |
|-------|--------------|------|
| 0 | `tests/unit/scanner/test_engine.py` | `source_snippet` populated after rule execution |
| 0 | `tests/unit/scanner/test_corpus_runner.py` | `_collect_findings_on_fragment` returns Finding objects with snippets |
| 0 | `tests/unit/scanner/test_context.py` | `populate_snippets()` shared helper |
| 1 | `tests/unit/scanner/test_sarif.py` | Region includes `snippet.text` |
| 2 | `tests/unit/scanner/test_corpus_runner.py` | Structural comparison logic (17 tests) |
| 3 | `tests/unit/corpus/test_corpus_oracle.py` | Oracle test updated (moved from Phase 4) |
| 3 | `tests/unit/scripts/test_migrate_expected_match.py` | Migration safety, idempotency, import boundary |
| 3 | Post-migration validation | Migration script's built-in validation + fragment integrity |
| 4 | `tests/unit/corpus/test_corpus_oracle.py` | Coverage ≥80%, no new boolean for auto-rules |
| 4 | `tests/integration/test_corpus_verify.py` | Zero location mismatches + structural integrity |

**Acceptance gate:** After all phases, `uv run wardline corpus verify --json`
must report `total_location_mismatches: 0`. This is enforced by the CI
integration test `test_real_corpus_zero_location_mismatches`.

---

## 7. Key Files Reference

| File | Lines | Purpose |
|------|-------|---------|
| `src/wardline/scanner/engine.py` | 871-913 | `_run_rule()` — add source_snippet post-processing |
| `src/wardline/scanner/sarif.py` | 170-180 | `_make_region()` — add snippet |
| `src/wardline/cli/corpus_cmds.py` | 31-44 | `_CellStats` — add `location_mismatches` |
| `src/wardline/cli/corpus_cmds.py` | 169-208 | `_run_rules_on_fragment()` — refactor + add sibling |
| `src/wardline/cli/corpus_cmds.py` | 211-259 | `_evaluate_specimen()` — add structural comparison |
| `src/wardline/cli/corpus_cmds.py` | 361-465 | `_build_json_report()` — add location_match_rate |
| `src/wardline/scanner/context.py` | 22-50 | `Finding` dataclass + NEW `populate_snippets()` shared helper |
| `src/wardline/scanner/rules/base.py` | 200-219 | `_emit_matrix_finding()` — where source_snippet=None |
| `corpus/specimens/` | — | 252 specimen YAML files (117 positive) |
| `corpus/corpus_manifest.json` | — | Specimen index |
| `scripts/generate_corpus.py` | 73-78, 128-139 | Specimen generation — update expected_match |
| `scripts/migrate_expected_match.py` | — | NEW: one-time migration script |
| `tests/unit/scanner/test_corpus_runner.py` | 20-87 | Security invariant tests |
| `tests/unit/scanner/test_corpus_runner.py` | 237-499 | Verdict evaluation tests |
| `tests/unit/scanner/test_corpus_runner.py` | 524-568 | JSON output tests |
| `tests/unit/corpus/test_corpus_oracle.py` | 53-67 | Oracle validation — MUST UPDATE |
| `tests/integration/test_corpus_verify.py` | 49-59 | Real corpus integration test |
| `tests/unit/scanner/test_sarif.py` | 157-172 | SARIF property bag tests |

---

## 8. Code Conventions

- `from __future__ import annotations` everywhere
- Explicit `ValueError` over `assert` (survives `python -O`)
- Ruff line length: 140. Target: Python 3.12+
- mypy strict mode with `warn_return_any`
- YAML loading uses `WardlineSafeLoader` — no unsafe deserialization.
  **This applies to the migration script too.** The existing `generate_corpus.py`
  uses bare `yaml.safe_load` at line 390 — fix this inconsistency.
- **Security invariant:** Specimen fragments are ONLY parsed with `ast.parse()`.
  Never `exec()`, never `eval()`. Tests enforce this. The migration script
  must pass the same security invariant tests.
- `TypedDict` for structured data shapes under mypy strict (not `dict[str, Any]`)
- `dataclasses.replace()` for immutable dataclass field updates (Finding is frozen)
- **Import note:** `Finding` must be a RUNTIME import in `corpus_cmds.py` (not
  under `TYPE_CHECKING`) because `_collect_findings_on_fragment` returns and
  inspects Finding objects at runtime. Currently `ScanContext` is under
  `TYPE_CHECKING`; `Finding` must be moved to unconditional imports.

---

## 9. Commit Strategy

5 commits, one per phase:

1. `fix(R3/phase-0): populate source_snippet via shared helper and expose Finding objects`
2. `fix(R3/phase-1): add SARIF snippet.text to region for source_snippet findings`
3. `fix(R3/phase-2): add structured expected_match comparison to corpus verify`
4. `fix(R3/phase-3): migrate specimens and update oracle test (AST-reimplemented)`
5. `fix(R3/phase-4): manifest, generation, coverage gates, CODEOWNERS, CI location gate`

**Each commit must leave tests passing.** Specifically:
- After commit 3 (Phase 2): structural comparison code exists but no
  specimens use it yet. Boolean path still works. Tests pass.
- After commit 4 (Phase 3): migrated specimens now exercise the structural
  comparison code. Oracle test is updated in the SAME commit (moved from
  Phase 4 to prevent inter-commit breakage). Tests pass.

---

## 10. Governance Requirements

### 10.1 Human Review Gate for Migration

The Phase 3 migration commit modifies ~100+ specimen files. Before merging:

1. The migration script must produce a human-readable diff summary showing
   each specimen's old `expected_match: true` → new structured form
2. A reviewer must spot-check **at least 3 specimens per rule** (covering
   all 9 rules, ~27 minimum) by reading the fragment and confirming the
   `line`, `text`, and `function` values are correct
3. The PR description must include the migration summary output
4. The provenance tag `expected_match_source: "ast-reimplemented"` (not
   "ast-derived") honestly communicates that the values were produced by
   reimplementing rule patterns, not by an independent oracle. After human
   review, update reviewed specimens to `expected_match_source: "human-verified"`

**Review artifact and traceability:**
- The review is documented as a **PR review comment** on the migration
  commit, listing each reviewed specimen and confirming correctness
- The reviewer MUST NOT be the migration script author (spec §10 requires
  "at least one reviewer who is not a contributor to the enforcement
  tool's implementation")
- After review approval, the reviewer (or a follow-up commit by the
  reviewer) updates `expected_match_source` from `"ast-reimplemented"` to
  `"human-verified"` on the reviewed specimens. This is a per-batch
  operation, not per-specimen — the review comment identifies which batch
  was reviewed, and the provenance update covers that batch

### 10.2 Specimen Update Governance

After this migration, changes to `expected_match` values should require:
1. A reference to the rule change that caused the location shift (if any)
2. Confirmation that the new values are correct (not just "makes tests pass")

**Add CODEOWNERS protection on `corpus/specimens/`.** The spec (§10) requires
this — it is a MUST, not a consideration. Add a CODEOWNERS entry as a
deliverable in Phase 4.

---

## 11. Status Protocol

Report after each phase: DONE, DONE_WITH_CONCERNS, NEEDS_CONTEXT, or BLOCKED.
