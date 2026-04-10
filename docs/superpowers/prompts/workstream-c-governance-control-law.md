# Workstream C: Governance & Control Law

> **Purpose:** Spec and implementation plan for closing governance and control
> law gaps identified in the 2026-04-09 conformance review (R4, R6, R7, R10).
> Give this to an implementation agent. It is self-contained.

**Branch:** `phase-4.4-test-quality-gates`
**Conformance review:** `docs/requirements/spec-fitness/conformance-review-2026-04-09.md`
**Spec authority:** `docs/spec/wardline-01-10-governance-model.md` (§10.5),
`docs/spec/wardline-01-11-verification-properties.md` (§11),
`docs/spec/wardline-01-15-conformance.md` (§15)

---

## 1. Problem Statement

The external conformance review identified 4 gaps in the governance and control
law subsystems. These weaken the enforcement regime's ability to self-report its
own health accurately.

| Finding | Severity | Description |
|---------|----------|-------------|
| R4 | HIGH | Control law does not check corpus staleness or precision/recall floor violations as dedicated degradation conditions |
| R6 | HIGH | `coverageRatio` absent from SARIF when no fingerprint baseline exists — the spec says coverage MUST be visible |
| R7 | HIGH | "Data paths traced" coverage metric absent — only annotation coverage is reported |
| R10 | MEDIUM | Retrospective scan absence detection unclear — no automatic mechanism to detect when retrospective scan is required |

---

## 2. Normative Requirements

### 2.1 Control Law Degradation (§10.5)

The spec defines three enforcement states:
- **Normal:** Full enforcement capability
- **Alternate:** Degraded but running — findings are still governance-grade
- **Direct:** No meaningful enforcement output

`compute_control_law()` at `src/wardline/scanner/sarif.py:122-155` currently
accepts 5 inputs: `manifest_unavailable`, `ratification_overdue`,
`conformance_gaps`, `rules_disabled`, `stale_exception_count`.

**Missing inputs per R4:**

1. **Precision floor violations** — When any corpus cell's precision falls
   below the defined floor (80% default, 65% for MIXED_RAW), this indicates a
   tool defect producing false positives. Per §11 property 3, this should be a
   distinct degradation condition, not bundled into generic `conformance_gaps`.

2. **Recall floor violations** — When any corpus cell's recall falls below
   floor (90% UNCONDITIONAL, 70% STANDARD/RELAXED), the tool is missing real
   violations. Same argument as precision.

3. **Corpus staleness (time-based)** — The fingerprint baseline tracks
   `generated_at` and computes `age_days` (in `src/wardline/manifest/regime.py`).
   When the fingerprint baseline is old enough that governance claims are
   unreliable, control law should degrade. The spec (§15.3.3) mentions
   "fingerprint baseline established" but doesn't define a hard threshold.
   Use a configurable threshold (default 180 days) in `wardline.toml`.

### 2.2 Coverage Ratio Independence (§13)

The spec (§13) says coverage metrics MUST be visible. Currently,
`coverageRatio` is read from the fingerprint baseline file
(`wardline.fingerprint.json`) via `_read_coverage_ratio()` in
`src/wardline/cli/scan.py:166-182`. When no baseline exists, the property is
omitted entirely from SARIF.

**R6 requirement:** Compute coverage ratio independently of the fingerprint
baseline. The scanner already discovers all functions and their annotations
during pass 1 — it can count annotated vs total functions without needing a
pre-existing baseline file.

### 2.3 Data Paths Traced (§11, §13)

The spec (§13) requires reporting both:
1. Annotation coverage (% of functions annotated) — **implemented**
2. Data paths traced (% of data-flow paths the taint engine actually followed)
   — **not implemented**

**R7 requirement:** Implement a `dataPathsTraced` metric that reports the
taint engine's coverage. This measures how many call-graph edges were resolved
vs total edges encountered during taint propagation. The data exists in the
L3 call-graph propagation pass (`src/wardline/scanner/taint/callgraph_propagation.py`)
which already tracks resolution statistics for the `L3_LOW_RESOLUTION`
governance finding.

### 2.4 Retrospective Scan Detection (§10.5)

The spec (§10.5) requires that when control law transitions from direct/alternate
back to normal, a retrospective scan MUST occur covering the commit range during
which degraded law was in effect.

Currently, `--retrospective <range>` is a manual CLI flag. There is no automatic
detection of when a retrospective scan is required.

**R10 requirement:** When the scanner detects that the previous scan's control
law was `"alternate"` or `"direct"` and the current scan's control law is
`"normal"`, emit a governance finding recommending a retrospective scan. The
previous control law state is available from the SARIF baseline file (if
baseline comparison is enabled via `--compare`).

---

## 3. Current State Audit

### 3.1 `compute_control_law()` (`sarif.py:122-155`)

```python
def compute_control_law(
    *,
    manifest_unavailable: bool = False,
    ratification_overdue: bool = False,
    conformance_gaps: tuple[str, ...] = (),
    rules_disabled: tuple[str, ...] = (),
    stale_exception_count: int = 0,
) -> tuple[str, tuple[str, ...]]:
```

Returns `(law, degradations)`. Direct law only when manifest unavailable.
Alternate when any other condition triggers. Normal when all clear.

**Current degradation conditions:**
- `"manifest_unavailable"`
- `"ratification_overdue"`
- `"conformance_gaps_present"`
- `"rules_disabled"`
- `"stale_exceptions_present"`

### 3.2 Precision/Recall Floor Checking (`corpus_cmds.py`)

Floors are defined in `_get_floors()` at lines 434-477:
- Precision: 80% (65% for MIXED_RAW)
- Recall: 90% for UNCONDITIONAL, 70% for STANDARD/RELAXED

Floor violations currently flow into control law indirectly:
1. Corpus verify reports failing cells → overall verdict FAIL
2. `corpus publish` appends `"{N} corpus cell(s) below floor"` to gaps
3. Gap string fed to `compute_control_law()` as part of `conformance_gaps`
4. Triggers generic `"conformance_gaps_present"` degradation

**Gap:** No dedicated `precision_floor_violations` or `recall_floor_violations`
input. The control law cannot distinguish "corpus cell failed" from "tool
version changed" — both are just conformance gaps.

### 3.3 Coverage Ratio (`scan.py:166-182`)

```python
def _read_coverage_ratio(manifest_path: Path) -> float | None:
    baseline = manifest_path.parent / "wardline.fingerprint.json"
    if not baseline.exists():
        return None
    # ... read from baseline JSON ...
```

Returns `None` when baseline doesn't exist → property omitted from SARIF.

### 3.4 Call-Graph Resolution Stats

The L3 taint propagation in `src/wardline/scanner/taint/callgraph_propagation.py`
tracks call-graph edges. The `L3_LOW_RESOLUTION` governance finding fires when
>70% of edges are unresolved. The resolution statistics exist but are not
surfaced as a SARIF run-level metric.

### 3.5 Retrospective Scan (`scan.py`)

The `--retrospective` flag sets `retroactive_scan=True` on all findings and
records the range in SARIF. No automatic detection of when retrospective is
needed. The baseline SARIF file (used for `--compare` comparison) contains
the previous run's `wardline.controlLaw` value.

---

## 4. Implementation Plan

### 4.1 Execution Order and Dependencies

```
R6 (coverage independence)     ─── no deps ─── changes scan.py only
  │
R7 (data paths traced)        ─── needs engine stats ─── changes engine + sarif
  │
R4 (control law inputs)       ─── needs R6/R7 data ─── changes sarif.py + scan.py
  │
R10 (retrospective detection) ─── needs control law ─── changes scan.py
```

### 4.2 R6: Compute Coverage Ratio Independently

**Problem:** Coverage ratio is only available when a fingerprint baseline file
exists. The scanner should compute it from the scan itself.

**Approach:** During scan, the engine already discovers all functions (for taint
assignment) and all annotations (for rule context). Count annotated functions
vs total functions to produce a coverage ratio without needing the baseline.

**Files:**
- Modify: `src/wardline/scanner/engine.py` — Add coverage tracking to
  `ScanResult`. After pass 1 completes, count functions with at least one
  wardline annotation vs total functions discovered.
- Modify: `src/wardline/scanner/engine.py` — Add fields to `ScanResult`:
  ```python
  annotated_function_count: int = 0
  total_function_count: int = 0
  ```
- Modify: `src/wardline/cli/scan.py` — Compute coverage ratio from scan
  result when fingerprint baseline is absent:
  ```python
  if coverage_ratio is None and result.total_function_count > 0:
      coverage_ratio = result.annotated_function_count / result.total_function_count
  ```
  This makes the fingerprint baseline the preferred source (it includes
  historical tracking), with scan-time computation as fallback.

  **Dual-source divergence warning:** When BOTH baseline and scan-time
  coverage ratios are available, compare them. If they diverge by more
  than 10 percentage points (`abs(baseline - scan_time) > 0.10`), emit
  a governance event warning that the baseline may be stale:
  ```python
  if baseline_ratio is not None and scan_ratio is not None:
      if abs(baseline_ratio - scan_ratio) > 0.10:
          # Emit governance event: stale baseline detected
  ```
  This catches the silent failure where a stale baseline inflates the
  reported coverage ratio.
- Modify: `src/wardline/scanner/sarif.py:365-366` — Always emit
  `coverageRatio` as a key (never conditionally omit), but use `null` when
  no data is available (zero functions discovered):
  ```python
  "wardline.coverageRatio": round(self.coverage_ratio, 4) if self.coverage_ratio is not None else None,
  ```
  **IMPORTANT:** Do NOT emit `0.0` as a fallback when no functions are
  discovered. `0.0` means "functions exist but none are annotated" — a
  real measurement. `null` means "no functions discovered, coverage is
  not applicable." Emitting `0.0` for both cases creates a false signal
  in machine-readable SARIF evidence that assessors rely on.

  The key MUST always be present (satisfying the spec's "MUST be visible"
  requirement). `null` value with key present is distinct from key absent.

**Tests:**
- `test_coverage_ratio_from_scan_when_no_baseline` — scan without fingerprint
  baseline still produces coverage ratio
- `test_coverage_ratio_prefers_baseline` — when baseline exists, its value
  takes precedence over scan-time computation
- `test_coverage_ratio_null_when_zero_functions` — when `total_function_count
  == 0` and no baseline exists, coverage ratio is `null` (not `0.0`)
- `test_dual_source_divergence_warning_above_threshold` — baseline ratio 0.90,
  scan-time ratio 0.75 (15% divergence > 10% threshold) → governance event
  warning emitted
- `test_dual_source_no_warning_at_exactly_threshold` — baseline ratio 0.80,
  scan-time ratio 0.70 (exactly 10% divergence) → NO warning (uses strict `>`,
  not `>=`)
- `test_dual_source_no_warning_below_threshold` — 5% divergence → no warning
- `test_zero_functions_logs_debug` — when total_function_count == 0, emit
  debug-level log: "no functions discovered, coverageRatio will be null"
- `test_engine_coverage_counts` — Add to `tests/unit/scanner/test_engine.py`:
  scan a fixture with known annotated and unannotated functions, assert
  `result.annotated_function_count` and `result.total_function_count` are
  the expected raw values. This catches counting bugs that CLI/SARIF tests
  would miss (they only see the derived ratio).

**Commit:** `fix(R6): compute coverage ratio from scan when fingerprint baseline absent`

### 4.3 R7: Data Paths Traced Metric

**Problem:** Only annotation coverage is reported. The spec also requires
reporting data-flow path coverage — how many call-graph edges the taint engine
resolved.

**Approach:** Surface the call-graph resolution statistics that L3 propagation
already computes internally.

**Files:**
- **DO NOT modify `src/wardline/scanner/taint/callgraph_propagation.py`.**
  The `resolved_counts: dict[str, int]` and `unresolved_counts: dict[str, int]`
  dicts are returned by `extract_call_edges()` (defined in
  `src/wardline/scanner/taint/callgraph.py:37`) and unpacked at
  `engine.py:801`:
  ```python
  edges, resolved_counts, unresolved_counts = extract_call_edges(tree, qualname_map)
  ```
  They are then passed as positional arguments to `propagate_callgraph_taints()`
  at `engine.py:804-807`. They are **local variables inside
  `_run_callgraph_taint()`**, NOT accessible at the main scan loop call site
  (`engine.py:512`). The return value of `_run_callgraph_taint()` is currently
  `(refined_map, provenance)` and does not include these dicts.

  **Fix:** Compute the aggregate stats **inside `_run_callgraph_taint()`**
  (which is in `engine.py`, respecting the no-modify constraint on
  `callgraph_propagation.py`), and extend its return value to include them:
  ```python
  # Inside _run_callgraph_taint(), after extract_call_edges():
  total_resolved = sum(resolved_counts.values())
  total_unresolved = sum(unresolved_counts.values())
  total_edges = total_resolved + total_unresolved
  call_edge_resolution_ratio = total_resolved / total_edges if total_edges > 0 else None
  low_resolution_count = ...  # count from existing L3_LOW_RESOLUTION logic

  # Return extended tuple:
  return refined_map, provenance, call_edge_resolution_ratio, low_resolution_count
  ```
  Then at the call site in the main scan loop, unpack the extended return
  and assign to `ScanResult` fields.

  Do NOT create a `PropagationStats` dataclass — it adds unnecessary churn
  to `callgraph_propagation.py` and risks breaking the fixed-point algorithm.
- Modify: `src/wardline/scanner/engine.py` — Add to `ScanResult`:
  ```python
  call_edge_resolution_ratio: float | None = None  # None when L3 didn't run
  low_resolution_function_count: int = 0  # count of functions with >70% unresolved
  ```
- Modify: `src/wardline/scanner/sarif.py` — Add to `SarifReport`:
  ```python
  data_paths_traced_ratio: float | None = None
  low_resolution_function_count: int = 0
  ```
  Emit in run properties:
  ```python
  "wardline.dataPathsTracedRatio": round(self.data_paths_traced_ratio, 4) if self.data_paths_traced_ratio is not None else None,
  "wardline.lowResolutionFunctionCount": self.low_resolution_function_count,
  ```
  **Why both:** The aggregate ratio alone masks hot-spots. A codebase where
  10 functions have 100% unresolved calls but 990 have 100% resolved shows
  ~90% ratio — looks healthy but has 10 blind-spot functions. The count
  gives assessors the full picture.
- Modify: `src/wardline/cli/scan.py` — Wire propagation stats from scan
  result to SARIF report.

**Note:** When analysis level is L1 (no call-graph propagation), the metric
is `null` because no paths were traced. At L2, the metric is also `null` —
L2 performs intra-module taint propagation but does NOT run the call-graph
(L3) pass, so no call edges are resolved. Only L3 produces a non-null ratio.
This is correct — the metric reports what the engine actually did, not what
it could have done.

**Coverage ratio denominator:** Count all functions that appear in the taint
engine's qualname map (`build_qualname_map()` in `src/wardline/scanner/_qualnames.py`).
This includes:
- Module-level `def`/`async def` nodes
- Class methods (including `@property`-decorated methods — `build_qualname_map()`
  has no decorator awareness, but `@property` methods are `FunctionDef` nodes
  and are therefore included by the generic node-type match)
- Inner/nested function definitions (mapped with dotted qualnames like `outer.inner`)

Exclude ONLY:
- Lambda expressions (`ast.Lambda`) — `build_qualname_map()` only matches
  `FunctionDef`/`AsyncFunctionDef`

**IMPORTANT:** The previous version of this plan incorrectly stated that inner
functions and `@property` methods were excluded from the qualname map. They are
NOT excluded — `build_qualname_map()` recursively maps all `FunctionDef` and
`AsyncFunctionDef` nodes (verified: `_qualnames.py:29-32`). The denominator
MUST match what the engine actually tracks.

**Assessor visibility:** Because the denominator includes all qualname-mapped
functions (which may include functions the taint engine cannot meaningfully
analyze), also emit `wardline.denominatorExcludedCount` in run properties —
the count of lambda expressions discovered but excluded from the denominator.
This lets assessors judge whether the denominator is representative:
```python
"wardline.denominatorExcludedCount": self.denominator_excluded_count,
```

**Tests:**
- `test_data_paths_traced_ratio_from_l3_scan` — L3 scan produces non-null ratio
- `test_data_paths_traced_ratio_null_at_l1` — L1 scan produces null
- `test_data_paths_traced_ratio_null_at_l2` — L2 scan produces null (L2 does
  not run call-graph propagation)
- `test_data_paths_traced_in_sarif` — ratio appears in run properties
- `test_low_resolution_function_count_in_sarif` — count appears alongside ratio
- `test_data_paths_traced_ratio_zero_edges` — L3 scan with zero call edges
  produces null (not division by zero)
- `test_coverage_denominator_includes_inner_functions` — inner functions ARE
  counted in the denominator (they are in the qualname map)
- `test_coverage_denominator_includes_property_methods` — `@property` methods
  ARE counted (they are `FunctionDef` nodes)
- `test_coverage_denominator_excludes_lambdas` — `ast.Lambda` nodes are NOT
  counted (qualname map does not include them)
- `test_denominator_excluded_count_in_sarif` — `wardline.denominatorExcludedCount`
  appears in run properties

**Commit:** `fix(R7): add wardline.dataPathsTracedRatio to SARIF run properties`

### 4.4 R4: Dedicated Control Law Degradation Inputs

**Problem:** Precision/recall floor violations and corpus staleness are bundled
into generic `conformance_gaps`. The control law should distinguish these.

**Approach:** Add dedicated inputs to `compute_control_law()`.

**Files:**
- Modify: `src/wardline/scanner/sarif.py:122-155` — Extend
  `compute_control_law()` with new parameters:
  ```python
  def compute_control_law(
      *,
      manifest_unavailable: bool = False,
      ratification_overdue: bool = False,
      conformance_gaps: tuple[str, ...] = (),
      rules_disabled: tuple[str, ...] = (),
      stale_exception_count: int = 0,
      # NEW: dedicated quality signals
      precision_floor_violations: int = 0,
      recall_floor_violations: int = 0,
      fingerprint_age_days: int | None = None,
      fingerprint_max_age_days: int = 180,
  ) -> tuple[str, tuple[str, ...]]:
  ```

  New degradation conditions (use FIXED keys, not count-embedded names):
  ```python
  if precision_floor_violations > 0:
      degradations.append("precision_below_floor")
  if recall_floor_violations > 0:
      degradations.append("recall_below_floor")
  if (fingerprint_age_days is not None
          and fingerprint_age_days > fingerprint_max_age_days):
      degradations.append("fingerprint_baseline_stale")
  # NOTE: Uses strict > (not >=) intentionally. A fingerprint that is
  # exactly at the threshold is still within its validity window. This
  # differs from ratification_overdue which uses >= (in regime.py:205).
  # The difference is deliberate: ratification is a deadline (due on
  # the day), while staleness is a decay window (stale only after).
  ```

  **IMPORTANT:** Degradation condition names are FIXED strings — do NOT
  embed dynamic counts in the key (e.g., NOT `"precision_below_floor_3_cells"`).
  Embedding counts makes keys unstable for downstream parsing. Instead,
  surface the violation counts as separate structured fields in SARIF
  run-level properties:
  ```python
  "wardline.precisionFloorViolations": precision_floor_violations,
  "wardline.recallFloorViolations": recall_floor_violations,
  ```
  This gives downstream tooling both a stable key to match on and the
  count for observability.

  All three trigger alternate law (not direct — the scanner is still
  functioning, just with degraded quality assurance).

- Modify: `src/wardline/cli/scan.py` — Read precision/recall floor violation
  counts from the conformance status file (`wardline.conformance.json`). The
  `corpus publish` command already writes `cells_below_precision_floor` and
  `cells_below_recall_floor` to this file. Parse these and pass to
  `compute_control_law()`.

  **CRITICAL: Handle absent `wardline.conformance.json` explicitly.** When
  this file is absent (e.g., first scan on a new project, or corpus publish
  has not been run since corpus changes), floor violation counts are unknown.
  Do NOT silently default to 0 — that makes control law appear healthier
  than it is. Instead:
  1. Log a warning: `"wardline.conformance.json not found — corpus floor
     violations unknown, treating as conformance data unavailable"`
  2. Add a degradation condition (triggers alternate law) — the scanner
     cannot vouch for its own precision/recall without this data
  3. Emit a governance event explaining the situation

  **Distinguish two absence scenarios with separate degradation strings:**
  - `"conformance_never_run"` — file has NEVER existed (no corpus publish
    has ever been run). Corrective action: run `uv run wardline corpus publish`.
    Detect by checking that the file does not exist AND no historical
    conformance data exists (e.g., no `.wardline/conformance/` directory).
    For v1.0, the simple heuristic is: file absent = `conformance_never_run`
    (since deletion of an existing file is an edge case).
  - `"conformance_data_unavailable"` — file existed but was deleted or is
    malformed/unparseable. Corrective action: investigate deletion, re-run
    `corpus publish`.

  This distinction gives operators a clear corrective action. Both trigger
  alternate law.

  **Known limitation of the heuristic:** The file-absent = `conformance_never_run`
  heuristic is fragile. If a project has been using the tool but the
  conformance file was deleted (CI artifact cleanup, repo clone without
  artifacts), the scanner will report `conformance_never_run` instead of
  `conformance_data_unavailable`, giving the operator the wrong corrective
  action ("run corpus publish" vs "investigate deletion"). This is an
  accepted simplification for v1.0 — document in conformance evidence as
  a known limitation. A future enhancement could check git history or a
  `.wardline/conformance/` directory for evidence of prior runs.

  **Handle present-but-malformed conformance file:** If the file exists but
  fails JSON parsing or is missing expected keys (`cells_below_precision_floor`,
  `cells_below_recall_floor`), treat as `"conformance_data_unavailable"` with
  a warning. Do NOT silently default missing keys to 0.

  This ensures a missing conformance file produces alternate law (degraded
  but running) rather than silently claiming normal law with unknown quality.

  **First-run alternate law is expected and must be documented.** A brand-new
  project will enter alternate law on its first scan from TWO simultaneous
  conditions: (1) no `wardline.conformance.json` → `conformance_never_run`,
  (2) no fingerprint baseline → `fingerprint_age_unknown`. This is
  architecturally correct (unknown quality IS degraded), but creates a bad
  onboarding experience if undocumented.

  To help downstream tooling distinguish "first run" from "ongoing degradation":
  - Emit `wardline.isInitialSetup: true` in SARIF run properties when BOTH
    conformance file AND fingerprint baseline are absent on the same scan
  - This lets CI pipelines apply different alerting thresholds for new project
    onboarding (e.g., suppress alternate-law alerts on first scan)
  - Add to `SarifReport` as `is_initial_setup: bool = False`

- Modify: `src/wardline/cli/scan.py` — Read fingerprint age from the
  fingerprint baseline. The `FingerprintMetrics` dataclass in
  `src/wardline/manifest/regime.py` already computes `age_days`. Wire this
  through.

  **Error handling for malformed fingerprint:** Wrap `age_days` access in
  a try/except. If `generated_at` is missing, malformed, or unparseable,
  set a sentinel that triggers alternate law:
  ```python
  try:
      fingerprint_age = fingerprint_metrics.age_days
  except (KeyError, ValueError, TypeError) as exc:
      logger.warning("Cannot compute fingerprint age: %s — treating as unknown (triggers alternate law)", exc)
      fingerprint_age = None
      fingerprint_age_unknown = True
  ```
  **CRITICAL (corrected from previous version):** Unknown fingerprint age MUST
  trigger alternate law via a `"fingerprint_age_unknown"` degradation condition.
  Treating unknown age as "not stale" creates a bypass: an attacker can corrupt
  `generated_at` to garbage, producing `age_days=None`, which silently skips
  staleness detection. Unknown is not the same as stale, but unknown IS a
  degradation condition — the scanner cannot vouch for baseline freshness.
  Add to `compute_control_law()`:
  ```python
  fingerprint_age_unknown: bool = False,
  ```
  And in the function body:
  ```python
  if fingerprint_age_unknown:
      degradations.append("fingerprint_age_unknown")
  ```

- Modify: `wardline.toml` schema — Add `[governance]` section with
  `fingerprint_max_age_days = 180` (configurable threshold).

  **Clamp to sane maximum:** The implementation MUST reject or clamp
  `fingerprint_max_age_days` values above 365 days. An absurdly high
  value (e.g., 999999) effectively disables staleness detection, allowing
  a repo committer to suppress alternate law via config manipulation.

  **IMPORTANT:** The clamp logic MUST live inside `compute_control_law()`
  itself — NOT in the caller (`scan.py`). Placing it in the function ensures
  the cap is always enforced regardless of which caller invokes the function.
  A new caller that bypasses the clamp in `scan.py` would silently disable
  staleness detection.
  ```python
  # Inside compute_control_law():
  MAX_FINGERPRINT_AGE_CAP = 365
  if fingerprint_max_age_days > MAX_FINGERPRINT_AGE_CAP:
      logger.warning(
          "fingerprint_max_age_days=%d exceeds cap of %d — clamping",
          fingerprint_max_age_days, MAX_FINGERPRINT_AGE_CAP,
      )
      fingerprint_max_age_days = MAX_FINGERPRINT_AGE_CAP
  ```

**Tests:**
- `test_control_law_precision_floor_violation` — precision violations trigger
  alternate law with `"precision_below_floor"` degradation (fixed key, no count)
- `test_control_law_recall_floor_violation` — same for recall with
  `"recall_below_floor"` degradation
- `test_control_law_fingerprint_stale` — old fingerprint triggers alternate
- `test_control_law_fingerprint_within_threshold` — young fingerprint is normal
- `test_control_law_multiple_degradations` — multiple conditions produce
  multiple degradation strings
- `test_control_law_conformance_never_run` — file never existed → triggers
  `"conformance_never_run"` degradation
- `test_control_law_conformance_data_unavailable` — file malformed or deleted
  → triggers `"conformance_data_unavailable"` degradation
- `test_control_law_conformance_missing_keys` — file present but missing
  `cells_below_precision_floor` key → `"conformance_data_unavailable"`
- `test_fingerprint_max_age_clamped` — values above 365 are clamped with warning
- `test_fingerprint_max_age_at_exactly_365` — value of exactly 365 is NOT
  clamped (boundary test)
- `test_fingerprint_age_exactly_at_threshold` — `age_days == fingerprint_max_age_days`
  does NOT trigger staleness (uses strict `>`, not `>=` — confirm intentional)
- `test_malformed_fingerprint_age_triggers_alternate` — bad `generated_at` →
  `fingerprint_age_unknown=True` → alternate law with `"fingerprint_age_unknown"`
  degradation
- `test_floor_violation_counts_in_sarif_properties` — `precisionFloorViolations`
  and `recallFloorViolations` appear as separate run-level SARIF properties
- `test_control_law_clean_path` — all inputs at healthy values
  (`precision_floor_violations=0`, `recall_floor_violations=0`,
  `fingerprint_age_days=10`, `fingerprint_max_age_days=180`) produces
  normal law with zero degradation strings. Explicitly tests the clean path
  to catch regressions where a new degradation condition fires spuriously.
- `test_conformance_missing_keys_logs_warning` — file present but missing
  `cells_below_precision_floor` key → warning logged (not just silent
  degradation). Operators watching stdout need the diagnostic.

**Commit:** `fix(R4): add precision/recall floor and corpus staleness to control law`

### 4.5 R10: Retrospective Scan Absence Detection

**Problem:** When control law transitions from degraded back to normal, the
spec requires a retrospective scan of code merged during the degraded window.
No automatic detection or enforcement exists.

**Approach:** When `--compare` is provided, read the previous SARIF's
`wardline.controlLaw`. If it was `"alternate"` or `"direct"` and the current
scan is `"normal"`, emit a `GOVERNANCE_RETROSPECTIVE_REQUIRED` finding
recommending a retrospective scan.

**IMPORTANT:** The CLI flag is `--compare` (NOT `--baseline`). The comparison
helper is `_compare_sarif_baseline()` at `scan.py:952`. Do NOT create a
`--baseline` flag — `--compare` already provides this functionality.

**Enforcement model:** The spec says retrospective scan MUST occur, but this
plan implements detection, not enforcement. The governance event makes the
requirement visible in SARIF output. Enforcement is delegated to the CI
pipeline (which should read `wardline.controlLaw` and the governance events
to gate merges when retrospective scan is outstanding). Document this
delegation in the conformance evidence so assessors can trace the enforcement
chain.

**Files:**
- Modify: `src/wardline/core/severity.py` — Add
  `GOVERNANCE_RETROSPECTIVE_REQUIRED` to `RuleId` enum. This member does NOT
  currently exist — it must be created.
- Modify: `src/wardline/scanner/sarif.py` — Add
  `GOVERNANCE_RETROSPECTIVE_REQUIRED` to the `_PSEUDO_RULE_IDS` frozenset.
  Without this, the SARIF emitter will reject findings with the new rule ID.
- Modify: `src/wardline/cli/scan.py` — Add a new helper
  `_read_baseline_control_law(compare: str | None) -> str | None` that reads
  ONLY the `wardline.controlLaw` property from the baseline SARIF file. Call
  this helper **before line 859** (before `governance_events` is frozen),
  NOT inside `_compare_sarif_baseline()`.

  **Why this placement matters:** The current code flow is:
  1. Line 783: `control_law` computed
  2. Line 845–858: governance events accumulated in `_gov_events` list
  3. Line 859: `governance_events = tuple(_gov_events)` — frozen
  4. Line 861: `SarifReport` constructed with `governance_events`
  5. Line 891: SARIF serialized to JSON
  6. Line 914: `_compare_sarif_baseline()` called — **after SARIF is written**

  If retrospective detection runs inside `_compare_sarif_baseline()` (step 6),
  the governance event cannot appear in the SARIF output (already written at
  step 5). The detection MUST happen between steps 1 and 3.

  **Implementation:**
  ```python
  def _read_baseline_control_law(compare: str | None) -> str | None:
      """Read wardline.controlLaw from baseline SARIF, or None."""
      if compare is None:
          return None
      import json
      try:
          data = json.loads(Path(compare).read_text(encoding="utf-8"))
          runs = data.get("runs", [])
          if not isinstance(runs, list) or not runs:
              return None
          return runs[0].get("properties", {}).get("wardline.controlLaw")
      except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
          logger.warning("Cannot read baseline control law: %s", exc)
          return None
  ```

  Then, in the scan command function, between `compute_control_law()` (line 783)
  and the governance events freeze (line 859):
  ```python
  prev_control_law = _read_baseline_control_law(compare)
  if (
      prev_control_law in ("alternate", "direct")
      and control_law == "normal"
  ):
      _gov_events.append(GovernanceEvent(
          event_type="retrospective_scan_recommended",
          message=(
              f"Control law improved from {prev_control_law} to normal. "
              f"Code merged during {prev_control_law} law should be "
              f"retrospectively scanned."
          ),
      ))
  ```

  **CRITICAL: Do NOT default missing `wardline.controlLaw` to `"normal"`.** When
  the baseline SARIF has no `wardline.controlLaw` property, use `None` (unknown).
  This prevents a false clean signal in the scenario where a `direct`-law scan
  failed to write SARIF — the next scan would see no baseline controlLaw,
  default to `"normal"`, and silently suppress the retrospective recommendation
  in exactly the scenario where it matters most. With `None`, the `in ("alternate",
  "direct")` check naturally skips detection (correct: unknown ≠ clean).

  **Baseline integrity note:** The SARIF baseline file has no integrity
  protection (signing, hashing). There are THREE suppression paths an
  attacker can exploit: (1) edit `wardline.controlLaw` to `"normal"`,
  (2) delete the baseline file entirely (`prev_control_law` → `None`, check
  skipped), (3) corrupt the JSON to trigger the malformed-JSON handler (no
  baseline, no detection). All three are **accepted risks** for v1.0 —
  document ALL THREE in the conformance evidence (not just the edit path).
  The mitigation is that CI pipelines should generate baseline SARIF in a
  trusted environment, not read it from the repo. Future work: add
  hash-based integrity verification for SARIF baseline files.

  **Malformed baseline JSON handling:** Wrap the entire baseline-reading block
  in a try/except. If the baseline fails JSON parsing, treat as no baseline
  (no retrospective detection) and log a warning — do not raise an unhandled
  exception.

  This emits a governance event (visible in SARIF) rather than a hard gate.
  The spec says retrospective scan MUST occur but enforcement is through the
  governance model, not the scanner exit code.

  **Enforcement delegation:** The conformance evidence MUST explicitly:
  1. Name the **specific, existing** CI gate mechanism that reads
     `wardline.controlLaw` and governance events to enforce retrospective
     scans — not a hypothetical future gate
  2. Confirm that a qualifying CI gate exists in every deployment context
  3. If no qualifying CI gate exists at v1.0 ship, honestly disclose that
     the spec §10.5 MUST requirement for retrospective scans is unenforceable
     by tooling alone — this is a **residual risk**, not a "future work" item
  4. Document that without a CI gate, the MUST requirement is unenforced
     (honest disclosure for assessors)

**Tests:**
- `test_retrospective_recommended_on_law_improvement` — `--compare` baseline
  with alternate law + current normal → governance event emitted
- `test_no_retrospective_when_law_unchanged` — normal→normal → no event
- `test_no_retrospective_when_law_degrades` — normal→alternate → no event
- `test_no_retrospective_without_compare_flag` — no `--compare` → no
  detection (R10 is baseline-gated)
- `test_retrospective_baseline_missing_control_law` — baseline SARIF has no
  `wardline.controlLaw` property → `prev_control_law` is `None`, no spurious
  event emitted (unknown ≠ clean)
- `test_retrospective_baseline_empty_runs` — baseline SARIF has `"runs": []` →
  no crash, no event (guard against IndexError)
- `test_retrospective_baseline_malformed_json` — baseline file has invalid
  JSON → treated as no baseline, warning logged, no crash
- `test_is_initial_setup_true_when_both_absent` — no conformance file AND no
  fingerprint baseline → `wardline.isInitialSetup` is `true`
- `test_is_initial_setup_false_when_conformance_exists` — conformance file
  present (even if fingerprint absent) → `isInitialSetup` is `false`
- `test_is_initial_setup_false_when_fingerprint_exists` — fingerprint present
  (even if conformance absent) → `isInitialSetup` is `false`

**Commit:** `fix(R10): detect control law improvement and recommend retrospective scan`

---

## 5. Correctness Constraints

1. **Precision/recall floor violations are alternate-law triggers, not
   direct-law.** The scanner is still functioning — it's producing findings
   that may have accuracy issues. Direct law is reserved for "no meaningful
   enforcement output."

2. **Fingerprint staleness threshold is configurable.** Different projects
   have different governance cadences. The default (180 days) should be
   overridable in `wardline.toml` under a `[governance]` section.

3. **Coverage ratio MUST always be present as a key in SARIF.** The key
   `wardline.coverageRatio` is never omitted. When both fingerprint baseline
   and scan-time computation fail (e.g., zero functions discovered), emit
   `null` — NOT `0.0`. `0.0` means "functions exist, none annotated" (a real
   measurement). `null` means "no functions discovered, metric not applicable."
   Assessors rely on this distinction in machine-readable evidence.

4. **`dataPathsTracedRatio` is null at L1.** This is correct — L1 analysis
   does not trace call-graph paths. The metric reports actual coverage, not
   theoretical capability. Complement with `lowResolutionFunctionCount` to
   avoid masking hot-spots in the aggregate ratio.

5. **Retrospective detection is advisory with documented enforcement owner.**
   Emit a governance event, not a hard gate. The user may have already
   performed the retrospective scan manually. The governance event makes the
   recommendation visible in SARIF for auditors. The enforcement chain is:
   scanner emits governance event → CI pipeline reads SARIF → CI gates merge
   when retrospective is outstanding. Document this delegation in the
   conformance evidence.

6. **Degradation condition names are FIXED machine-readable strings.** Use
   underscore-separated lowercase identifiers (e.g., `"precision_below_floor"`,
   `"recall_below_floor"`, `"fingerprint_baseline_stale"`,
   `"conformance_data_unavailable"`). Do NOT embed dynamic counts in the key
   name — that makes keys unstable for downstream parsing. Surface counts as
   separate structured SARIF properties (`wardline.precisionFloorViolations`,
   `wardline.recallFloorViolations`).

7. **Absent `wardline.conformance.json` triggers alternate law.** When the
   conformance file is missing, floor violation counts are unknown. Do NOT
   silently default to 0 — add `"conformance_data_unavailable"` to
   degradation conditions so control law correctly reflects unknown quality.

8. **`fingerprint_max_age_days` is clamped to 365.** Values above 365 are
   clamped with a warning. This prevents config manipulation from disabling
   staleness detection. The 180-day default is a project decision, not an
   ISM standard — document the rationale in the conformance evidence.

9. **Malformed fingerprint `generated_at` triggers alternate law.** If the
   timestamp is missing or unparseable, `age_days` is unknown. Unknown age
   MUST trigger `"fingerprint_age_unknown"` degradation (alternate law).
   Treating unknown as "not stale" creates a bypass — an attacker can corrupt
   `generated_at` to skip staleness detection. Log a warning. This was
   corrected from the initial plan which treated unknown as a silent pass.

10. **Coverage ratio denominator: all qualname-mapped functions.** Count all
    functions in the taint engine's qualname map (`build_qualname_map()` in
    `src/wardline/scanner/_qualnames.py`). This INCLUDES inner/nested functions
    (mapped with dotted qualnames) and `@property` methods (`build_qualname_map()`
    has no decorator awareness but matches all `FunctionDef`/`AsyncFunctionDef`
    nodes, so `@property` methods are included by node type). EXCLUDES only
    `ast.Lambda` (not matched by `build_qualname_map()`). This was corrected
    from the initial plan which incorrectly claimed inner functions and
    `@property` were excluded.

11. **`MAX_FINGERPRINT_AGE_CAP` enforced inside `compute_control_law()`.**
    The 365-day cap must be enforced inside the function, not in the caller.
    This ensures the cap is always applied regardless of call site.

12. **Two distinct conformance-absence degradation strings.**
    `"conformance_never_run"` (file never existed — run `corpus publish`) vs
    `"conformance_data_unavailable"` (file deleted or malformed — investigate).
    Both trigger alternate law but give operators different corrective actions.

13. **Baseline SARIF has no integrity protection (accepted risk).** Three
    suppression paths exist: (1) edit `wardline.controlLaw` to `"normal"`,
    (2) delete the baseline file, (3) corrupt the JSON. All three are
    accepted risks for v1.0 — document ALL THREE in conformance evidence.
    The mitigation is that CI pipelines should generate baseline SARIF in a
    trusted environment, not read it from the repo.

14. **180-day fingerprint staleness default.** The 180-day default must be
    justified in the conformance evidence against the project's governance
    cadence. For ISM-aligned projects, 90 days (quarterly assurance cycle)
    is the defensible default. The value is configurable in `wardline.toml`
    — the conformance evidence must explain why the chosen value is
    appropriate. The 365-day cap may be too generous for security tools —
    consider whether the cap itself should be reduced for ISM deployments.

15. **`wardline.denominatorExcludedCount` surfaces denominator scoping.** The
    count of lambda expressions excluded from the coverage ratio denominator
    MUST be emitted in SARIF run properties. This lets assessors judge whether
    the coverage ratio denominator is representative of the codebase.

16. **Control law transition table in conformance evidence.** The control law
    state machine (normal/alternate/direct with all degradation conditions)
    must be expressed as a declarative transition table in the conformance
    evidence, not only as source code. Assessors should not need to read
    Python to verify transition completeness. **This is an explicit
    deliverable of this workstream** (commit 5), not just a constraint.

17. **`wardline.isInitialSetup` run property.** Emit `true` when BOTH
    conformance file AND fingerprint baseline are absent on the same scan.
    This helps downstream tooling distinguish first-run degradation from
    ongoing quality problems. Emit `false` otherwise.

18. **`wardline.conformance.json` lacks integrity protection (accepted risk).**
    A fake file with `cells_below_precision_floor: 0` is indistinguishable
    from a legitimate one. The same CI-trusted-environment mitigation applies
    as for baseline SARIF (constraint 13). Document in conformance evidence.
    Future enhancement: cross-validate `generated_at` timestamp against
    corpus manifest hash to detect stale conformance data.

---

## 6. Testing Strategy

| Fix | Test Location | What |
|-----|--------------|------|
| R6 | `tests/unit/cli/test_scan_cmd.py` | Coverage ratio computed from scan |
| R6 | `tests/unit/scanner/test_sarif.py` | coverageRatio always emitted (key present) |
| R6 | `tests/unit/cli/test_scan_cmd.py` | Coverage ratio null when zero functions |
| R7 | `tests/unit/scanner/test_sarif.py` | dataPathsTracedRatio in properties |
| R7 | `tests/unit/scanner/test_sarif.py` | lowResolutionFunctionCount in properties |
| R7 | `tests/unit/scanner/test_engine.py` | ScanResult carries resolution stats |
| R4 | `tests/unit/scanner/test_sarif.py` | compute_control_law with new inputs |
| R4 | `tests/unit/scanner/test_sarif.py` | conformance_data_unavailable degradation |
| R4 | `tests/unit/cli/test_scan_cmd.py` | Floor violations wired to control law |
| R4 | `tests/unit/cli/test_scan_cmd.py` | Missing conformance.json triggers alternate |
| R4 | `tests/unit/cli/test_scan_cmd.py` | fingerprint_max_age_days clamped to 365 |
| R4 | `tests/unit/cli/test_scan_cmd.py` | Malformed generated_at triggers fingerprint_age_unknown |
| R4 | `tests/unit/cli/test_scan_cmd.py` | conformance_never_run vs conformance_data_unavailable |
| R4 | `tests/unit/cli/test_scan_cmd.py` | fingerprint_age_days boundary (== threshold, == 365) |
| R10 | `tests/unit/cli/test_scan_cmd.py` | Retrospective detection via `_read_baseline_control_law()` + governance event before SARIF freeze |
| R10 | `tests/unit/cli/test_scan_cmd.py` | Missing controlLaw → None (not "normal"), empty runs, malformed JSON — all via `_read_baseline_control_law()` |
| R6 | `tests/unit/scanner/test_engine.py` | `test_engine_coverage_counts` — raw annotated/total function counts from fixture |
| All | `tests/integration/test_self_hosting_scan.py` | Self-hosting scan passes + assertions on new SARIF properties (see below) |

**Integration test guidance:** The self-hosting integration test MUST use
**key-existence and range checks**, NOT exact value assertions. The codebase
changes over time, so exact values (e.g., `coverageRatio == 0.42`) will break.
Use:
```python
assert "wardline.coverageRatio" in props  # key always present
assert props["wardline.coverageRatio"] is None or 0 <= props["wardline.coverageRatio"] <= 1
assert "wardline.dataPathsTracedRatio" in props
assert "wardline.lowResolutionFunctionCount" in props
assert isinstance(props["wardline.lowResolutionFunctionCount"], int)
assert "wardline.denominatorExcludedCount" in props
assert "wardline.precisionFloorViolations" in props
assert "wardline.recallFloorViolations" in props
assert "wardline.isInitialSetup" in props
assert props["wardline.propertyBagVersion"] == "0.6"
```

---

## 7. Key Files Reference

| File | Purpose |
|------|---------|
| `src/wardline/scanner/sarif.py:122` | `compute_control_law()` — add inputs + MAX_FINGERPRINT_AGE_CAP clamp |
| `src/wardline/scanner/sarif.py` | `SarifReport` — add fields + `to_dict()` emit; add to `_PSEUDO_RULE_IDS` |
| `src/wardline/scanner/engine.py:63` | `ScanResult` — add coverage/resolution stats (aggregate from existing dicts) |
| `src/wardline/cli/scan.py:166` | `_read_coverage_ratio()` — fallback logic |
| `src/wardline/cli/scan.py` | New `_read_baseline_control_law()` — retrospective detection (called before line 859, NOT inside `_compare_sarif_baseline()`) |
| `src/wardline/cli/scan.py` | Control law invocation — wire new inputs + conformance.json handling |
| `src/wardline/core/severity.py` | `RuleId` — add `GOVERNANCE_RETROSPECTIVE_REQUIRED` member |
| `src/wardline/manifest/regime.py` | `FingerprintMetrics` — `age_days` |
| `src/wardline/cli/corpus_cmds.py:434` | `_get_floors()` — floor definitions |
| `src/wardline/scanner/_qualnames.py:12` | `build_qualname_map()` — denominator source of truth |

**DO NOT modify:** `src/wardline/scanner/taint/callgraph_propagation.py` — resolution
stats originate from `extract_call_edges()` in `callgraph.py` and are unpacked
as local variables inside `_run_callgraph_taint()` at `engine.py:801`. Aggregate
them there and extend the return value — no changes needed in
`callgraph_propagation.py`.

---

## 8. Code Conventions

- `from __future__ import annotations` everywhere
- `MappingProxyType` for deep immutability of registries
- Explicit `ValueError` over `assert` (survives `python -O`)
- Ruff line length: 140. Target: Python 3.12+
- mypy strict mode with `warn_return_any`

---

## 9. Commit Strategy

5 commits, one per fix plus one for the transition table:

1. `fix(R6): compute coverage ratio from scan when fingerprint baseline absent`
2. `fix(R7): add wardline.dataPathsTracedRatio to SARIF run properties`
3. `fix(R4): add precision/recall floor and corpus staleness to control law`
4. `fix(R10): detect control law improvement and recommend retrospective scan`
5. `docs(governance): add control law transition table to conformance evidence`

**Property bag version:** Bump `wardline.propertyBagVersion` to `"0.6"` in
the R7 commit (when the first new run-level properties land). The R6 commit
changes `coverageRatio` from conditionally-absent to always-present — that's
a behavior change but not a new property, so the bump happens at R7.

**Each commit must leave tests passing.**

---

## 10. Deliverables Beyond Code

### 10.1 Control Law Transition Table (§6.16)

**This is an explicit deliverable, not just a constraint.** Create a
declarative transition table in the conformance evidence
(`docs/requirements/spec-fitness/`) that documents ALL degradation conditions,
their trigger thresholds, which law they produce, and the corrective action.
Assessors should be able to verify transition completeness from this table
without reading Python source code.

Example format:

| Condition | Trigger | Law | Corrective Action |
|-----------|---------|-----|-------------------|
| `manifest_unavailable` | wardline.yaml not found | direct | Create wardline.yaml |
| `conformance_never_run` | wardline.conformance.json absent | alternate | Run `wardline corpus publish` |
| `precision_below_floor` | Any corpus cell precision < floor | alternate | Investigate false positives |
| `fingerprint_baseline_stale` | age_days > max_age_days (capped 365) | alternate | Regenerate fingerprint baseline |
| `fingerprint_age_unknown` | generated_at missing or unparseable | alternate | Fix fingerprint baseline |
| ... | ... | ... | ... |

This table must cover ALL conditions from both the existing implementation
AND this workstream's additions.

### 10.2 First-Run Onboarding Documentation

Document in the operator guide that a brand-new project will immediately
enter alternate law on its first scan. Explain that this is expected behavior
(unknown quality IS degraded) and list the steps to reach normal law:
1. Run `wardline corpus publish` (clears `conformance_never_run`)
2. Run `wardline fingerprint generate` (clears `fingerprint_age_unknown`)
3. Re-scan

---

## 11. Status Protocol

Report after each fix: DONE, DONE_WITH_CONCERNS, NEEDS_CONTEXT, or BLOCKED.
