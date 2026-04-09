# Workstream B: Corpus Verification Upgrade

> **Purpose:** Spec and implementation plan for upgrading corpus `expected_match`
> from boolean to structured object with SARIF snippet comparison (R3).
> Give this to an implementation agent. It is self-contained.

**Branch:** `phase-4.4-test-quality-gates`
**Conformance review:** `docs/requirements/spec-fitness/conformance-review-2026-04-09.md`
**Spec authority:** `docs/spec/wardline-01-10-verification-properties.md`

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

The current `_make_region()` in `sarif.py:166-176` does NOT include the
`snippet` field. The `source_snippet` field on `Finding` IS populated by rules
but is placed in `properties["wardline.sourceSnippet"]` instead of in the
region's `snippet.text` where the spec expects it.

### 2.3 Verification Comparison

The spec states (§10, line 44):

> "Verification compares these fields against the SARIF result's
> `locations[0].physicalLocation.region.startLine`,
> `locations[0].physicalLocation.region.snippet.text`, and the enclosing
> `logicalLocation`. The `text` field MUST match the SARIF `snippet.text`
> exactly."

Verification must compare:
1. `expected_match.line` against finding's `startLine` (within the fragment)
2. `expected_match.text` against finding's `snippet.text` (exact match)
3. `expected_match.function` against finding's enclosing qualname

### 2.4 Backward Compatibility

True-negative and known-false-negative specimens keep `expected_match: false`.
Only true-positive specimens get the structured form. The verification code
must handle both forms.

---

## 3. Current State Audit

### 3.1 Specimen Format

**Location:** `corpus/specimens/{RULE}/{TAINT_STATE}/{positive,negative}/`

Each specimen is a YAML file. Example (`corpus/specimens/PY-WL-001/INTEGRAL/positive/PY-WL-001-TP-INTEGRAL.yaml`):

```yaml
---
specimen_id: PY-WL-001-TP-INTEGRAL
description: PY-WL-001 true_positive at INTEGRAL
rule: PY-WL-001
fragment: "def process(data):\n    x = data.get(\"key\", \"default\")\n"
taint_state: INTEGRAL
expected_rules:
- PY-WL-001
expected_severity: ERROR
expected_exceptionability: UNCONDITIONAL
expected_match: true                # ← THIS IS THE PROBLEM: boolean, not structured
sha256: fde5ab3dd8c9e06f9da8a26d1cfe64280ee6e33d25e69bfa541b06a4764517b5
verdict: true_positive
```

### 3.2 Corpus Manifest

**Location:** `corpus/corpus_manifest.json`

JSON index of all specimens. Each entry has `expected_match` as a boolean.
The manifest must be regenerated after specimen changes.

**Generation script:** `scripts/generate_corpus.py` — sets `expected_match`
as boolean (lines 136, 163, 196). Must be updated.

### 3.3 Verification Code

**Location:** `src/wardline/cli/corpus_cmds.py`

Key function: `_evaluate_specimen()` at lines 211-259.

Current logic:
```python
rule_fired = rule_id in fired_set
# TP + rule_fired → pass
# TP + no rule → fail (false negative)
# TN + rule_fired → fail (false positive)
# TN + no rule → pass
```

**Critical:** The `expected_match` field is populated on specimens but **never
consulted** during verification. The verification only checks whether the rule
ID appears in the fired set — it does not check WHERE it fired or WHAT text
it matched.

### 3.4 SARIF Region (snippet gap)

**Location:** `src/wardline/scanner/sarif.py:166-176`

```python
def _make_region(finding: Finding) -> dict[str, Any]:
    region: dict[str, Any] = {
        "startLine": finding.line,
        "startColumn": finding.col + 1,
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

From `src/wardline/scanner/context.py:22-46`:

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
    source_snippet: str | None   # ← source text, populated by most rules
    qualname: str | None = None  # ← enclosing function name
    ...
```

The data needed for structured verification already exists on `Finding`:
- `line` → `expected_match.line`
- `source_snippet` → `expected_match.text`
- `qualname` → `expected_match.function`

### 3.6 Test Coverage

**Unit tests:** `tests/unit/scanner/test_corpus_runner.py`
- `TestVerdictEvaluation` (lines 237-408) — tests TP/TN/KFN classification
- `TestPrecisionRecall` (lines 410-499) — tests floor comparison
- `TestCorpusVerifyJson` (lines 524-568) — tests JSON output structure

**Integration test:** `tests/integration/test_corpus_verify.py`
- Runs actual `corpus verify` on fixture corpus
- Validates exit codes and output format

**Oracle test:** `tests/unit/corpus/test_corpus_oracle.py`
- Validates boolean `expected_match` alignment with verdict

---

## 4. Implementation Plan

### 4.1 Execution Order and Dependencies

```
Phase 1: SARIF snippet emission     ─── enables structured comparison
  │
Phase 2: Specimen metadata upgrade  ─── compute structured expected_match
  │
Phase 3: Verification upgrade       ─── compare line/text/function
  │
Phase 4: Manifest + generation      ─── update index and tooling
```

### 4.2 Phase 1: Add SARIF Snippet to Region

**Files:**
- Modify: `src/wardline/scanner/sarif.py:166-176`

**Change:** In `_make_region()`, add snippet when source_snippet is available:

```python
def _make_region(finding: Finding) -> dict[str, Any]:
    region: dict[str, Any] = {
        "startLine": finding.line,
        "startColumn": finding.col + 1,
    }
    if finding.end_line is not None:
        region["endLine"] = finding.end_line
    if finding.end_col is not None:
        region["endColumn"] = finding.end_col + 1
    if finding.source_snippet is not None:
        region["snippet"] = {"text": finding.source_snippet}
    return region
```

**Keep** `wardline.sourceSnippet` in properties too — the properties bag is
wardline-specific metadata; the region snippet is SARIF-standard. Both serve
different consumers.

**Tests:** Add to `tests/unit/scanner/test_sarif.py`:
- `test_region_includes_snippet_when_present` — Finding with source_snippet
  produces region with `snippet.text`
- `test_region_omits_snippet_when_none` — Finding without source_snippet
  has no snippet field in region

**Commit:** `fix(R3): add SARIF snippet.text to region for source_snippet findings`

### 4.3 Phase 2: Upgrade Specimen Metadata

This is the bulk of the work. Every true_positive specimen (approximately 120+
files) needs its `expected_match` upgraded from `true` to a structured object.

**Approach:** Write a migration script that:
1. Loads each specimen YAML
2. If `verdict == "true_positive"` and `expected_match is True`:
   a. Parse the `fragment` with `ast.parse()`
   b. Run the expected rule against it (using `_run_rules_on_fragment()`)
   c. Extract the first matching finding's `line`, `source_snippet`, `qualname`
   d. Replace `expected_match: true` with structured form:
      ```yaml
      expected_match:
        line: 2
        text: 'data.get("key", "default")'
        function: "process"
      ```
   e. Recompute `sha256` if fragment unchanged (the sha256 is of the fragment,
      not the full YAML)
3. If `verdict == "true_negative"` or `verdict == "known_false_negative"`:
   keep `expected_match: false`
4. Write updated YAML back

**Files:**
- Create: `scripts/migrate_expected_match.py` — one-time migration script
- Modify: ~120 specimen YAML files in `corpus/specimens/`

**Important considerations:**
- The `line` value must be 1-indexed within the fragment (which it already is
  since findings from fragment scanning use fragment-relative line numbers)
- The `text` field must be the literal source text, not AST unparse output.
  Use `finding.source_snippet` which is already the original source text
- The `function` field is the enclosing function's simple name (not qualname
  with module path). Extract from `finding.qualname` — take the last component
  after splitting on `.`
- Some specimens may have multiple expected rules (`expected_rules` list).
  The structured `expected_match` corresponds to the primary rule in `rule`
  field
- If the scanner doesn't produce a `source_snippet` for a particular finding,
  the `text` field should be computed by extracting the source line from the
  fragment at the finding's line number

**Validation:** After migration, verify:
- Every true_positive specimen has `expected_match.line`, `.text`, `.function`
- Every true_negative/known_false_negative has `expected_match: false`
- No specimen has `expected_match: true` (the old boolean form for positives)

**Commit:** `fix(R3): upgrade specimen expected_match from boolean to structured`

### 4.4 Phase 3: Upgrade Verification Logic

**Files:**
- Modify: `src/wardline/cli/corpus_cmds.py` (lines 211-259,
  `_evaluate_specimen()`)

**Change:** After confirming the rule fired (existing logic), add structural
comparison for true_positive specimens:

```python
def _evaluate_specimen(data, source, rules, stats):
    # ... existing rule firing check ...

    if verdict == "true_positive" and rule_fired:
        expected = data.get("expected_match", True)
        if isinstance(expected, dict):
            # Structured comparison
            match_finding = _find_matching_finding(findings, rule_id)
            if match_finding is not None:
                location_ok = _check_location_match(
                    match_finding, expected, source
                )
                if not location_ok:
                    # Rule fired but at wrong location/text
                    stats[cell]["location_mismatches"] += 1
    # ... rest of existing logic ...
```

**New helper functions:**

```python
def _find_matching_finding(
    findings: list[Finding], rule_id: RuleId
) -> Finding | None:
    """Find the first finding matching the expected rule."""
    for f in findings:
        if f.rule_id == rule_id:
            return f
    return None


def _check_location_match(
    finding: Finding,
    expected: dict[str, Any],
    source: str,
) -> bool:
    """Check if finding matches expected line/text/function."""
    ok = True

    # Line check
    expected_line = expected.get("line")
    if expected_line is not None and finding.line != expected_line:
        ok = False

    # Text check (exact match)
    expected_text = expected.get("text")
    if expected_text is not None:
        actual_text = finding.source_snippet
        if actual_text != expected_text:
            ok = False

    # Function check
    expected_func = expected.get("function")
    if expected_func is not None:
        actual_func = (
            finding.qualname.rsplit(".", 1)[-1]
            if finding.qualname else None
        )
        if actual_func != expected_func:
            ok = False

    return ok
```

**Stats tracking:** Add `location_mismatches` counter to the per-cell stats
dict. Location mismatches should be reported in the output (both text and JSON
modes) as a separate metric. A finding that fires at the wrong location is
still a TP for precision/recall purposes (the rule detected the pattern) but
indicates a location accuracy issue.

**JSON output:** Add `location_match_rate` to the per-cell JSON report:
```python
"locationMatchRate": (tp - location_mismatches) / tp if tp > 0 else None
```

**Tests:** Add to `tests/unit/scanner/test_corpus_runner.py`:
- `test_structured_expected_match_line_check` — finding at wrong line
  produces location mismatch
- `test_structured_expected_match_text_check` — finding with wrong snippet
  text produces location mismatch
- `test_structured_expected_match_function_check` — finding in wrong function
  produces location mismatch
- `test_structured_expected_match_all_pass` — all fields match, no mismatch
- `test_boolean_expected_match_backward_compat` — old boolean `true` still
  works (no structural comparison)

**Commit:** `fix(R3): add structured expected_match comparison to corpus verify`

### 4.5 Phase 4: Update Manifest and Generation

**Files:**
- Modify: `corpus/corpus_manifest.json` — regenerate with structured
  expected_match values
- Modify: `scripts/generate_corpus.py` — produce structured expected_match
  for new specimens
- Modify: `tests/unit/corpus/test_corpus_oracle.py` — update to validate
  structured form

**Manifest regeneration:** After Phase 2 upgrades specimens, regenerate
the manifest. The `expected_match` field in manifest entries should reflect
the specimen's value (structured dict for TP, `false` for TN/KFN).

**Generation script:** When creating new true_positive specimens, the script
must compute and populate the structured `expected_match` by running the
rule and extracting finding location data.

**Oracle test:** Update `test_corpus_oracle.py` to validate:
- TP specimens have `expected_match` as dict with `line`, `text`, `function`
- TN/KFN specimens have `expected_match: false`
- The structured values are consistent with the specimen's fragment content

**Commit:** `fix(R3): update manifest, generation, and oracle tests for structured expected_match`

---

## 5. Correctness Constraints

1. **Line numbers are fragment-relative.** When running a specimen fragment
   through the scanner, line numbers in findings are already relative to the
   fragment (since the fragment IS the entire source). No adjustment needed.

2. **Text comparison is exact.** `expected_match.text` must match
   `finding.source_snippet` byte-for-byte. No normalization, no whitespace
   stripping. If they differ, the verification must flag it.

3. **Function name is the simple name.** `expected_match.function` is
   `"process"`, not `"module.MyClass.process"`. Extract from `qualname` by
   taking the last `.`-separated component.

4. **Boolean backward compatibility.** `expected_match: true` (old form) must
   continue to work — it means "rule fires, no location check." This allows
   incremental migration and avoids breaking specimens that haven't been
   upgraded yet.

5. **`expected_match: false`** means "rule should NOT fire." No structural
   comparison needed — only the absence check.

6. **Multiple findings per specimen.** If a rule fires multiple times on a
   specimen, match against the first finding for that rule. If the spec later
   requires matching specific findings, this can be extended.

7. **SARIF snippet.text in region.** The snippet field in the SARIF region is
   SARIF-standard (not wardline-specific). Keep `wardline.sourceSnippet` in
   properties too — both serve different consumers.

8. **Migration script is one-time.** The migration script runs once to upgrade
   existing specimens. After that, the generation script produces structured
   expected_match for new specimens.

---

## 6. Testing Strategy

| Phase | Test Location | What |
|-------|--------------|------|
| 1 | `tests/unit/scanner/test_sarif.py` | Region includes snippet.text |
| 2 | Manual validation | All TP specimens have structured expected_match |
| 3 | `tests/unit/scanner/test_corpus_runner.py` | Structural comparison logic |
| 3 | `tests/integration/test_corpus_verify.py` | Full corpus verify still passes |
| 4 | `tests/unit/corpus/test_corpus_oracle.py` | Oracle validates structured form |

**Critical integration test:** After all phases, `uv run wardline corpus verify`
must pass on the full corpus with zero location mismatches. This is the
acceptance gate.

---

## 7. Key Files Reference

| File | Purpose |
|------|---------|
| `src/wardline/scanner/sarif.py:166-176` | `_make_region()` — add snippet |
| `src/wardline/cli/corpus_cmds.py:211-259` | `_evaluate_specimen()` — add structural comparison |
| `src/wardline/cli/corpus_cmds.py:361-465` | `_build_json_report()` — add location_match_rate |
| `src/wardline/scanner/context.py:22-46` | `Finding` dataclass — fields available |
| `corpus/specimens/` | ~252 specimen YAML files |
| `corpus/corpus_manifest.json` | Specimen index |
| `scripts/generate_corpus.py` | Specimen generation — update expected_match |
| `tests/unit/scanner/test_corpus_runner.py` | Corpus verification tests |
| `tests/unit/corpus/test_corpus_oracle.py` | Oracle validation tests |
| `tests/integration/test_corpus_verify.py` | Integration test |

---

## 8. Code Conventions

- `from __future__ import annotations` everywhere
- Explicit `ValueError` over `assert` (survives `python -O`)
- Ruff line length: 140. Target: Python 3.12+
- mypy strict mode with `warn_return_any`
- YAML loading uses `WardlineSafeLoader` — no unsafe deserialization
- **Security invariant:** Specimen fragments are ONLY parsed with `ast.parse()`.
  Never `exec()`, never `eval()`. Tests enforce this.

---

## 9. Commit Strategy

4 commits, one per phase:

1. `fix(R3): add SARIF snippet.text to region for source_snippet findings`
2. `fix(R3): upgrade specimen expected_match from boolean to structured`
3. `fix(R3): add structured expected_match comparison to corpus verify`
4. `fix(R3): update manifest, generation, and oracle tests for structured expected_match`

---

## 10. Status Protocol

Report after each phase: DONE, DONE_WITH_CONCERNS, NEEDS_CONTEXT, or BLOCKED.
