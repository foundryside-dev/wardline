# Workstream C: Governance & Control Law

> **Purpose:** Spec and implementation plan for closing governance and control
> law gaps identified in the 2026-04-09 conformance review (R4, R6, R7, R10).
> Give this to an implementation agent. It is self-contained.

**Branch:** `phase-4.4-test-quality-gates`
**Conformance review:** `docs/requirements/spec-fitness/conformance-review-2026-04-09.md`
**Spec authority:** `docs/spec/wardline-01-09-governance-model.md` (§9.5),
`docs/spec/wardline-01-10-verification-properties.md` (§10),
`docs/spec/wardline-01-14-conformance.md` (§14)

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

### 2.1 Control Law Degradation (§9.5)

The spec defines three enforcement states:
- **Normal:** Full enforcement capability
- **Alternate:** Degraded but running — findings are still governance-grade
- **Direct:** No meaningful enforcement output

`compute_control_law()` at `src/wardline/scanner/sarif.py:118-151` currently
accepts 5 inputs: `manifest_unavailable`, `ratification_overdue`,
`conformance_gaps`, `rules_disabled`, `stale_exception_count`.

**Missing inputs per R4:**

1. **Precision floor violations** — When any corpus cell's precision falls
   below the defined floor (80% default, 65% for MIXED_RAW), this indicates a
   tool defect producing false positives. Per §10 property 3, this should be a
   distinct degradation condition, not bundled into generic `conformance_gaps`.

2. **Recall floor violations** — When any corpus cell's recall falls below
   floor (90% UNCONDITIONAL, 70% STANDARD/RELAXED), the tool is missing real
   violations. Same argument as precision.

3. **Corpus staleness (time-based)** — The fingerprint baseline tracks
   `generated_at` and computes `age_days` (in `src/wardline/manifest/regime.py`).
   When the fingerprint baseline is old enough that governance claims are
   unreliable, control law should degrade. The spec (§14.3.3) mentions
   "fingerprint baseline established" but doesn't define a hard threshold.
   Use a configurable threshold (default 180 days) in `wardline.toml`.

### 2.2 Coverage Ratio Independence (§12)

The spec (§12) says coverage metrics MUST be visible. Currently,
`coverageRatio` is read from the fingerprint baseline file
(`wardline.fingerprint.json`) via `_read_coverage_ratio()` in
`src/wardline/cli/scan.py:149-165`. When no baseline exists, the property is
omitted entirely from SARIF.

**R6 requirement:** Compute coverage ratio independently of the fingerprint
baseline. The scanner already discovers all functions and their annotations
during pass 1 — it can count annotated vs total functions without needing a
pre-existing baseline file.

### 2.3 Data Paths Traced (§10, §12)

The spec (§12) requires reporting both:
1. Annotation coverage (% of functions annotated) — **implemented**
2. Data paths traced (% of data-flow paths the taint engine actually followed)
   — **not implemented**

**R7 requirement:** Implement a `dataPathsTraced` metric that reports the
taint engine's coverage. This measures how many call-graph edges were resolved
vs total edges encountered during taint propagation. The data exists in the
L3 call-graph propagation pass (`src/wardline/scanner/taint/callgraph_propagation.py`)
which already tracks resolution statistics for the `L3_LOW_RESOLUTION`
governance finding.

### 2.4 Retrospective Scan Detection (§9.5)

The spec (§9.5) requires that when control law transitions from direct/alternate
back to normal, a retrospective scan MUST occur covering the commit range during
which degraded law was in effect.

Currently, `--retrospective <range>` is a manual CLI flag. There is no automatic
detection of when a retrospective scan is required.

**R10 requirement:** When the scanner detects that the previous scan's control
law was `"alternate"` or `"direct"` and the current scan's control law is
`"normal"`, emit a governance finding recommending a retrospective scan. The
previous control law state is available from the SARIF baseline file (if
baseline comparison is enabled via `--baseline`).

---

## 3. Current State Audit

### 3.1 `compute_control_law()` (`sarif.py:118-151`)

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

Floors are defined in `_get_floors()` at lines 261-305:
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

### 3.3 Coverage Ratio (`scan.py:149-165`)

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
needed. The baseline SARIF file (used for `--baseline` comparison) contains
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
- Modify: `src/wardline/scanner/sarif.py:342-343` — Always emit
  `coverageRatio`, never conditionally omit:
  ```python
  "wardline.coverageRatio": round(self.coverage_ratio, 4) if self.coverage_ratio is not None else 0.0,
  ```

**Tests:**
- `test_coverage_ratio_from_scan_when_no_baseline` — scan without fingerprint
  baseline still produces coverage ratio
- `test_coverage_ratio_prefers_baseline` — when baseline exists, its value
  takes precedence over scan-time computation

**Commit:** `fix(R6): compute coverage ratio from scan when fingerprint baseline absent`

### 4.3 R7: Data Paths Traced Metric

**Problem:** Only annotation coverage is reported. The spec also requires
reporting data-flow path coverage — how many call-graph edges the taint engine
resolved.

**Approach:** Surface the call-graph resolution statistics that L3 propagation
already computes internally.

**Files:**
- Modify: `src/wardline/scanner/taint/callgraph_propagation.py` — Ensure
  the propagation pass returns resolution statistics. Look for where
  `L3_LOW_RESOLUTION` is computed — the resolution ratio is calculated there.
  Add to the return value or to a stats object:
  ```python
  @dataclass(frozen=True)
  class PropagationStats:
      total_call_edges: int
      resolved_call_edges: int
      resolution_ratio: float
  ```
- Modify: `src/wardline/scanner/engine.py` — Capture propagation stats from
  L3 pass. Add to `ScanResult`:
  ```python
  call_edge_resolution_ratio: float | None = None  # None when L3 didn't run
  ```
- Modify: `src/wardline/scanner/sarif.py` — Add to `SarifReport`:
  ```python
  data_paths_traced_ratio: float | None = None
  ```
  Emit in run properties:
  ```python
  "wardline.dataPathsTracedRatio": round(self.data_paths_traced_ratio, 4) if self.data_paths_traced_ratio is not None else None,
  ```
- Modify: `src/wardline/cli/scan.py` — Wire propagation stats from scan
  result to SARIF report.

**Note:** When analysis level is L1 (no call-graph propagation), the metric
is `null` because no paths were traced. This is correct — the metric reports
what the engine actually did, not what it could have done.

**Tests:**
- `test_data_paths_traced_ratio_from_l3_scan` — L3 scan produces non-null ratio
- `test_data_paths_traced_ratio_null_at_l1` — L1 scan produces null
- `test_data_paths_traced_in_sarif` — ratio appears in run properties

**Commit:** `fix(R7): add wardline.dataPathsTracedRatio to SARIF run properties`

### 4.4 R4: Dedicated Control Law Degradation Inputs

**Problem:** Precision/recall floor violations and corpus staleness are bundled
into generic `conformance_gaps`. The control law should distinguish these.

**Approach:** Add dedicated inputs to `compute_control_law()`.

**Files:**
- Modify: `src/wardline/scanner/sarif.py:118-151` — Extend
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

  New degradation conditions:
  ```python
  if precision_floor_violations > 0:
      degradations.append(f"precision_below_floor_{precision_floor_violations}_cells")
  if recall_floor_violations > 0:
      degradations.append(f"recall_below_floor_{recall_floor_violations}_cells")
  if (fingerprint_age_days is not None
          and fingerprint_age_days > fingerprint_max_age_days):
      degradations.append("fingerprint_baseline_stale")
  ```

  All three trigger alternate law (not direct — the scanner is still
  functioning, just with degraded quality assurance).

- Modify: `src/wardline/cli/scan.py` — Read precision/recall floor violation
  counts from the conformance status file (`wardline.conformance.json`). The
  `corpus publish` command already writes `cells_below_precision_floor` and
  `cells_below_recall_floor` to this file. Parse these and pass to
  `compute_control_law()`.

- Modify: `src/wardline/cli/scan.py` — Read fingerprint age from the
  fingerprint baseline. The `FingerprintMetrics` dataclass in
  `src/wardline/manifest/regime.py` already computes `age_days`. Wire this
  through.

- Modify: `wardline.toml` schema — Add `[governance]` section with
  `fingerprint_max_age_days = 180` (configurable threshold).

**Tests:**
- `test_control_law_precision_floor_violation` — precision violations trigger
  alternate law with specific degradation name
- `test_control_law_recall_floor_violation` — same for recall
- `test_control_law_fingerprint_stale` — old fingerprint triggers alternate
- `test_control_law_fingerprint_within_threshold` — young fingerprint is normal
- `test_control_law_multiple_degradations` — multiple conditions produce
  multiple degradation strings

**Commit:** `fix(R4): add precision/recall floor and corpus staleness to control law`

### 4.5 R10: Retrospective Scan Absence Detection

**Problem:** When control law transitions from degraded back to normal, the
spec requires a retrospective scan of code merged during the degraded window.
No automatic detection or enforcement exists.

**Approach:** When `--baseline` is provided, read the previous SARIF's
`wardline.controlLaw`. If it was `"alternate"` or `"direct"` and the current
scan is `"normal"`, emit a `GOVERNANCE_RETROSPECTIVE_REQUIRED` finding
recommending a retrospective scan.

**Files:**
- Modify: `src/wardline/core/severity.py` — Add
  `GOVERNANCE_RETROSPECTIVE_REQUIRED` to `RuleId` enum (if not already present).
- Modify: `src/wardline/cli/scan.py` — In the baseline comparison section
  (around lines 870-900), after computing current control law:
  ```python
  if baseline_data is not None:
      prev_control_law = (
          baseline_data.get("runs", [{}])[0]
          .get("properties", {})
          .get("wardline.controlLaw", "normal")
      )
      if prev_control_law in ("alternate", "direct") and control_law == "normal":
          # Control law improved — retrospective scan recommended
          governance_events = (*governance_events, GovernanceEvent(
              event_type="retrospective_scan_recommended",
              message=(
                  f"Control law improved from {prev_control_law} to normal. "
                  f"Code merged during {prev_control_law} law should be "
                  f"retrospectively scanned."
              ),
          ))
  ```

  This emits a governance event (visible in SARIF) rather than a hard gate.
  The spec says retrospective scan MUST occur but enforcement is through the
  governance model, not the scanner exit code.

**Tests:**
- `test_retrospective_recommended_on_law_improvement` — baseline with
  alternate law + current normal → governance event emitted
- `test_no_retrospective_when_law_unchanged` — normal→normal → no event
- `test_no_retrospective_when_law_degrades` — normal→alternate → no event

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

3. **Coverage ratio MUST always be present in SARIF.** When both fingerprint
   baseline and scan-time computation fail (e.g., zero functions discovered),
   emit `0.0` rather than omitting the property.

4. **`dataPathsTracedRatio` is null at L1.** This is correct — L1 analysis
   does not trace call-graph paths. The metric reports actual coverage, not
   theoretical capability.

5. **Retrospective detection is advisory.** Emit a governance event, not a
   hard gate. The user may have already performed the retrospective scan
   manually. The governance event makes the recommendation visible in SARIF
   for auditors.

6. **Degradation condition names are machine-readable.** Use underscore-
   separated lowercase identifiers (e.g., `"precision_below_floor_3_cells"`)
   that downstream tooling can parse. Include the count in the name for
   observability.

---

## 6. Testing Strategy

| Fix | Test Location | What |
|-----|--------------|------|
| R6 | `tests/unit/cli/test_scan_cmd.py` | Coverage ratio computed from scan |
| R6 | `tests/unit/scanner/test_sarif.py` | coverageRatio always emitted |
| R7 | `tests/unit/scanner/test_sarif.py` | dataPathsTracedRatio in properties |
| R7 | `tests/unit/scanner/test_engine.py` | ScanResult carries resolution stats |
| R4 | `tests/unit/scanner/test_sarif.py` | compute_control_law with new inputs |
| R4 | `tests/unit/cli/test_scan_cmd.py` | Floor violations wired to control law |
| R10 | `tests/unit/cli/test_scan_cmd.py` | Retrospective detection from baseline |
| All | `tests/integration/test_self_hosting_scan.py` | Self-hosting scan still passes |

---

## 7. Key Files Reference

| File | Purpose |
|------|---------|
| `src/wardline/scanner/sarif.py:118-151` | `compute_control_law()` — add inputs |
| `src/wardline/scanner/sarif.py:255-287` | `SarifReport` — add fields |
| `src/wardline/scanner/sarif.py:332-386` | `to_dict()` — emit new properties |
| `src/wardline/scanner/engine.py` | `ScanResult` — add coverage/resolution stats |
| `src/wardline/scanner/taint/callgraph_propagation.py` | L3 resolution stats |
| `src/wardline/cli/scan.py:149-165` | `_read_coverage_ratio()` — fallback logic |
| `src/wardline/cli/scan.py:749-763` | Control law invocation — wire new inputs |
| `src/wardline/cli/scan.py:870-900` | Baseline comparison — retrospective detection |
| `src/wardline/manifest/regime.py` | `FingerprintMetrics` — age_days |
| `src/wardline/cli/corpus_cmds.py:261-305` | `_get_floors()` — floor definitions |

---

## 8. Code Conventions

- `from __future__ import annotations` everywhere
- `MappingProxyType` for deep immutability of registries
- Explicit `ValueError` over `assert` (survives `python -O`)
- Ruff line length: 140. Target: Python 3.12+
- mypy strict mode with `warn_return_any`

---

## 9. Commit Strategy

4 commits, one per fix:

1. `fix(R6): compute coverage ratio from scan when fingerprint baseline absent`
2. `fix(R7): add wardline.dataPathsTracedRatio to SARIF run properties`
3. `fix(R4): add precision/recall floor and corpus staleness to control law`
4. `fix(R10): detect control law improvement and recommend retrospective scan`

---

## 10. Status Protocol

Report after each fix: DONE, DONE_WITH_CONCERNS, NEEDS_CONTEXT, or BLOCKED.
