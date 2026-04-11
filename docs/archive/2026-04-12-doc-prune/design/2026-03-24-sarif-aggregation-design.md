# SARIF Aggregation Design — WP 3.3

**Date:** 2026-03-24
**Status:** Draft (revised after 7-reviewer panel)
**Scope:** `wardline sarif diff` and `wardline sarif trend` — multi-run comparison, trend analysis, SARIF-native output
**Target release:** v0.4.0
**Dependencies:** None (operates on SARIF output files, no runtime or scanner changes)

**Panel review findings incorporated (7 reviewers):**
- **Python C + Static Analysis C:** `qualname` and `source_snippet` not serialized to SARIF — must fix `_make_result()` as prerequisite
- **Static Analysis I:** Use SARIF `baselineState` (not `suppressions`) for diff status — native SARIF v2.1.0 field
- **SA C1 + QE C1:** Duplicate key collision policy undefined — extend key with `col`
- **SA C2:** Governance findings collide at `(rule_id, "<governance>", 1)` — include message hash
- **IRAP C-1/C-3:** No operator identity or input file integrity — add invocation metadata + SHA-256
- **Systems C-1/I-4:** Suppressed findings contaminate diff — filter by default, `--include-suppressed` flag
- **Systems C-2:** Analysis level mismatch warning
- **Systems C-1 + IRAP I-2:** `--gate` misses severity escalation — add `--gate-on-severity-change`
- **Security C-1:** Argument swap bypasses gate — validate timestamp ordering
- **Python I:** Separator collision in fingerprint hash — use `\x00` separator
- **Python I:** `RunSummary.by_rule` mutable dict in frozen dataclass — use `MappingProxyType`
- **Static Analysis I:** Name the diff identity function `compute_diff_key` (distinct from AST/annotation fingerprints)
- **QE C2/C3:** Trend with 1 file, propertyBagVersion mismatch — handle explicitly
- **SA I4:** `SarifTrend.match_strategy` unused — remove field

## Prerequisite: Serialize `qualname` and `source_snippet` to SARIF

**BLOCKING:** Before implementing aggregation, add to `_make_result()` in `scanner/sarif.py`:
```python
"wardline.qualname": finding.qualname,
"wardline.sourceSnippet": finding.source_snippet,
```

Both guarded by the existing `_clean_none` filter. Without this, both match strategies silently degrade to line-based matching on real SARIF output.

## 1. Finding Identity

Two matching strategies, toggled by `--match-strategy qualname|fingerprint`.

**`qualname` (default):** Identity key = `f"{rule_id}\x00{file_path}\x00{qualname or ''}\x00{line}\x00{col}"`. The full 5-tuple avoids collisions when multiple findings share the same function. Uses null byte separator (guaranteed absent from paths and rule IDs) to prevent delimiter collision.

**`fingerprint`:** Identity key = `sha256(f"{rule_id}\x00{file_path}\x00{qualname or ''}\x00{source_snippet or ''}")[:16]`. Falls back to qualname strategy when `source_snippet` is absent.

**Governance finding handling:** Governance findings commonly have `qualname=None`, `file_path="<governance>"`, `line=1`. To avoid collisions, the qualname strategy includes `message[:64]` hash as an additional discriminator when `qualname` is None.

**Function name:** `compute_diff_key(finding_dict, strategy) -> str` — distinct from `compute_ast_fingerprint` (exception staleness) and `compute_annotation_fingerprint` (governance drift).

**Duplicate policy:** If two findings in the same run produce the same key, both are retained. The diff operates on multisets (counters), not sets. A key appearing twice in baseline and once in current → one "unchanged" + one "fixed."

## 2. `wardline sarif diff`

### CLI Interface

```
wardline sarif diff <baseline.sarif.json> <current.sarif.json> \
    [--match-strategy qualname|fingerprint] \
    [--json] [--sarif] [--gate] [--gate-on-severity-change] \
    [--include-suppressed]
```

### Validation

- Both files must be valid SARIF JSON with `runs` array
- Extract from `runs[0].results` only — if `len(runs) > 1`, emit WARNING and use first run
- **Timestamp ordering:** If baseline `wardline.scanTimestamp` > current `wardline.scanTimestamp`, exit 2 with error "Baseline appears newer than current — arguments may be swapped"
- **Analysis level mismatch:** If `wardline.analysisLevel` differs, emit WARNING: "Runs at different analysis levels (L{x} vs L{y}) — diff may contain phantom findings"

### Algorithm

1. Load both SARIF files, extract findings from `runs[0].results`
2. **Filter suppressed findings** by default (severity == `"note"` AND `wardline.severity == "SUPPRESS"`). Include them only with `--include-suppressed`.
3. Compute identity key per finding using chosen strategy
4. Partition into four sets using multiset (Counter) comparison:
   - **New:** in current but not baseline (regressions)
   - **Fixed:** in baseline but not current (improvements)
   - **Unchanged:** in both with same severity
   - **Severity changed:** in both but severity differs

### Output Formats

**Text:** Summary with counts, direction, net change.

**JSON (`--json`):** Structured object with `new`, `fixed`, `unchanged`, `severity_changed` arrays. Each entry has full finding details + identity key. Summary counts at top level. `invocation` metadata (see below).

**SARIF (`--sarif`):** Valid SARIF v2.1.0 using native `baselineState` field (NOT `suppressions`):
- `"new"` → `baselineState: "new"`
- `"fixed"` → `baselineState: "absent"` (finding was in baseline but not current)
- `"unchanged"` → `baselineState: "unchanged"`
- `"severity_changed"` → `baselineState: "updated"` + `wardline.previousSeverity` in property bag

Run-level properties:
- `wardline.baselineTimestamp`, `wardline.currentTimestamp`
- `wardline.matchStrategy`
- `wardline.diffSummary` (counts object)
- `wardline.analysisLevelBaseline`, `wardline.analysisLevelCurrent`
- `wardline.invocation` (tool_version, invoked_at, operator if `--actor` provided)
- `wardline.inputFiles` (array of `{path, sha256}` for chain of custody)

### Gate Behavior

- `--gate`: Exit 1 if `new > 0`. Exit 0 otherwise.
- `--gate-on-severity-change`: Exit 1 if `new > 0 OR severity_changed_to_higher > 0` (any finding that escalated severity, e.g., note→ERROR from lapsed exception). Recommended for ISM-assessed systems.
- L3 diagnostic pseudo-findings (`L3_LOW_RESOLUTION`, `L3_CONVERGENCE_BOUND`) are excluded from gate evaluation (they are informational, not regressions).

## 3. `wardline sarif trend`

### CLI Interface

```
wardline sarif trend <run1.sarif.json> [run2.sarif.json ...] [--json] [--sarif]
```

**Minimum 2 files required.** With 1 file, exit 2: "trend requires at least 2 SARIF runs."

### Algorithm

1. Load each SARIF file. Extract `wardline.scanTimestamp` from run properties. If absent, use file modification time AND emit WARNING: "Using file mtime for {path} — timestamp may be unreliable"
2. Sort by timestamp. If timestamps tie, use positional argument order.
3. Per run: count findings by `rule_id` and by `severity`. Exclude SUPPRESS-severity by default.
4. Compute deltas between consecutive runs.

### Output Formats

**Text:** Table with date, total, new, fixed, per-rule columns. Direction label with date range.

**JSON:** Array of run summaries with timestamp, total, per-rule counts, per-severity counts, delta.

**SARIF (`--sarif`):** Single SARIF file with multiple runs. Each run has:
- Valid `tool.driver` block and `results: []` (empty for earlier runs — SARIF v2.1.0 requires `results` array)
- `wardline.trendIndex` (0-based position)
- `wardline.trendDelta` (+N/-N from previous)
- `wardline.findingKeys` (array of identity key strings for cross-referencing without full finding detail)
- Final run carries full finding details

No `--gate` on trend — trend is informational.

## 4. Data Models

```python
@dataclass(frozen=True)
class DiffEntry:
    key: str
    rule_id: str
    file_path: str
    line: int
    col: int
    qualname: str | None
    severity: str
    message: str
    source_snippet: str | None = None

@dataclass(frozen=True)
class SeverityChangedEntry:
    baseline: DiffEntry
    current: DiffEntry

@dataclass(frozen=True)
class SarifDiff:
    new: tuple[DiffEntry, ...]
    fixed: tuple[DiffEntry, ...]
    unchanged: tuple[DiffEntry, ...]
    severity_changed: tuple[SeverityChangedEntry, ...]
    baseline_timestamp: str | None
    current_timestamp: str | None
    match_strategy: str

@dataclass(frozen=True)
class RunSummary:
    timestamp: str | None
    timestamp_source: str  # "sarif_property" or "file_mtime"
    total: int
    by_rule: MappingProxyType[str, int]
    by_severity: MappingProxyType[str, int]
    delta_from_previous: int | None

@dataclass(frozen=True)
class SarifTrend:
    runs: tuple[RunSummary, ...]
```

Note: `SarifTrend` has no `match_strategy` field — trend counts by rule/severity, not by identity key.

## 5. Implementation

### Prerequisite change: `scanner/sarif.py`
- Add `wardline.qualname` and `wardline.sourceSnippet` to `_make_result()` property bag

### New module: `scanner/sarif_aggregation.py` (~250 lines)
- `compute_diff_key(finding_dict, strategy) -> str`
- `diff_sarif_runs(baseline, current, strategy, include_suppressed) -> SarifDiff`
- `trend_sarif_runs(runs) -> SarifTrend`
- `diff_to_sarif(diff, input_files) -> dict`
- `trend_to_sarif(trend) -> dict`

### New CLI: `cli/sarif_cmd.py` (~200 lines)
- `wardline sarif` click group
- `diff` and `trend` subcommands
- Text/JSON/SARIF formatters
- Gate logic with pseudo-rule exclusion

### Files Changed

| File | Change |
|---|---|
| `scanner/sarif.py` | Add `wardline.qualname` + `wardline.sourceSnippet` to `_make_result()` |
| `scanner/sarif_aggregation.py` | New — diff/trend logic + data models |
| `cli/sarif_cmd.py` | New — CLI commands |
| `cli/main.py` | Register `sarif` group |
| `tests/unit/scanner/test_sarif_aggregation.py` | New |
| `tests/integration/test_sarif_cmd.py` | New |

### Testing (~25 tests)

**Diff:**
- `test_diff_all_new` — empty baseline → all new
- `test_diff_all_fixed` — empty current → all fixed
- `test_diff_unchanged` — identical runs → all unchanged
- `test_diff_severity_changed` — same key, different severity
- `test_diff_mixed` — combination
- `test_diff_qualname_strategy` — qualname matching
- `test_diff_fingerprint_strategy` — fingerprint matching
- `test_diff_governance_finding_collision` — multiple governance findings with same rule at line 1 → distinct keys
- `test_diff_duplicate_keys_in_run` — multiset handling, not set
- `test_diff_suppressed_filtered_by_default`
- `test_diff_include_suppressed_flag`
- `test_diff_json_output`
- `test_diff_sarif_output_baseline_state` — uses `baselineState`, not `suppressions`
- `test_diff_gate_new` — exit 1
- `test_diff_gate_clean` — exit 0
- `test_diff_gate_severity_change` — `--gate-on-severity-change` exits 1
- `test_diff_gate_excludes_pseudo_rules`
- `test_diff_argument_swap_detected` — timestamp ordering → exit 2
- `test_diff_analysis_level_mismatch_warning`
- `test_diff_malformed_sarif` — exit 2

**Trend:**
- `test_trend_two_runs`
- `test_trend_multiple_runs`
- `test_trend_one_run_error` — exit 2
- `test_trend_sarif_output_with_finding_keys`
- `test_trend_mtime_fallback_warns`
