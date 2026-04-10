# Control Law Transition Table

> **Spec authority:** wardline-01-10-governance-model.md (§10.5)
> **Implementation:** `src/wardline/scanner/sarif.py:compute_control_law()`
> **Workstream:** C (Governance & Control Law), 2026-04-11

## Overview

The wardline scanner operates under one of three enforcement states (control
laws). The state is computed on every scan by `compute_control_law()` based on
the presence or absence of degradation conditions.

| Law | Meaning | Output quality |
|-----|---------|----------------|
| **normal** | Full enforcement capability | Governance-grade |
| **alternate** | Degraded but running | Findings produced, quality uncertain |
| **direct** | No meaningful enforcement | Findings unreliable or absent |

## Degradation Conditions

Each condition is a fixed machine-readable string. Conditions are NOT
mutually exclusive -- multiple may fire simultaneously.

### Direct Law Conditions

Direct law is returned immediately when any of these conditions hold.
No further conditions are evaluated.

| Condition | Input parameter | Trigger | Corrective action |
|-----------|----------------|---------|-------------------|
| `manifest_unavailable` | `manifest_unavailable: bool` | `wardline.yaml` not found or unreadable | Create or restore `wardline.yaml` |

### Alternate Law Conditions

Alternate law is produced when one or more of these conditions hold and
no direct-law condition applies. All conditions are evaluated and all
active conditions are reported in the `wardline.controlLawDegradations`
SARIF property.

| Condition | Input parameter | Trigger | Corrective action |
|-----------|----------------|---------|-------------------|
| `conformance_gaps_present` | `conformance_gaps: tuple[str, ...]` | Non-empty conformance gap list from `wardline.conformance.json` | Resolve conformance gaps; re-run `wardline corpus publish` |
| `conformance_data_unavailable` | `conformance_data_unavailable: bool` | `wardline.conformance.json` exists but is malformed or missing required keys (`cells_below_precision_floor`, `cells_below_recall_floor`) | Investigate file corruption; re-run `wardline corpus publish` |
| `conformance_never_run` | `conformance_never_run: bool` | `wardline.conformance.json` does not exist (corpus publish has never been run) | Run `wardline corpus publish` |
| `fingerprint_age_unknown` | `fingerprint_age_unknown: bool` | Fingerprint baseline absent or `generated_at` timestamp missing/unparseable | Generate fingerprint baseline: `wardline fingerprint generate` |
| `fingerprint_baseline_stale` | `fingerprint_age_days: int \| None`, `fingerprint_max_age_days: int` | `fingerprint_age_days > fingerprint_max_age_days` (strict `>`, not `>=`; max capped at 365) | Regenerate fingerprint baseline |
| `precision_below_floor` | `precision_floor_violations: int` | Any corpus cell's precision falls below floor (80% default, 65% for MIXED_RAW) | Investigate false positives in failing corpus cells |
| `ratification_overdue` | `ratification_overdue: bool` | Manifest ratification date has passed | Re-ratify the manifest |
| `recall_below_floor` | `recall_floor_violations: int` | Any corpus cell's recall falls below floor (90% UNCONDITIONAL, 70% STANDARD/RELAXED) | Investigate missed detections in failing corpus cells |
| `rules_disabled` | `rules_disabled: tuple[str, ...]` | One or more canonical rules not loaded (excluded from scan) | Enable all rules or document exclusion rationale |
| `stale_exceptions_present` | `stale_exception_count: int` | Active exceptions past their expiry date | Refresh or remove stale exceptions |

### Normal Law

Normal law is returned when no degradation conditions are active. All
input parameters are at their healthy defaults.

## Threshold Details

### Fingerprint Staleness

- **Default threshold:** 180 days (`fingerprint_max_age_days` parameter)
- **Configurable:** Yes, via `wardline.toml` `[governance]` section
- **Hard cap:** 365 days (enforced inside `compute_control_law()`, not caller)
- **Boundary behavior:** `age_days == max_age_days` does NOT trigger staleness (strict `>`)
- **Rationale:** 180-day default aligns with semi-annual governance review cadence. The 365-day cap prevents config manipulation from disabling staleness detection.

### Precision/Recall Floors

- **Precision floor:** 80% (65% for MIXED_RAW taint state)
- **Recall floor:** 90% for UNCONDITIONAL, 70% for STANDARD/RELAXED
- **Source:** `_get_floors()` in `src/wardline/cli/corpus_cmds.py:434-477`
- **Violation counts** are surfaced separately in SARIF run properties (`wardline.precisionFloorViolations`, `wardline.recallFloorViolations`) for observability.

## First-Run Behavior

A brand-new project will immediately enter alternate law on its first scan
from two simultaneous conditions:

1. `conformance_never_run` -- no `wardline.conformance.json` exists
2. `fingerprint_age_unknown` -- no fingerprint baseline exists

This is architecturally correct: unknown quality IS degraded. The
`wardline.isInitialSetup` SARIF run property is set to `true` when both
conformance file and fingerprint baseline are absent, allowing downstream
tooling to distinguish first-run degradation from ongoing quality problems.

**Steps to reach normal law on a new project:**

1. Run `wardline corpus publish` (clears `conformance_never_run`)
2. Run `wardline fingerprint generate` (clears `fingerprint_age_unknown`)
3. Re-scan

## Retrospective Scan Detection

When the scanner detects (via `--compare` baseline) that the previous scan
operated under `"alternate"` or `"direct"` law and the current scan is
`"normal"`, it emits a `retrospective_scan_recommended` governance event.

This is advisory, not enforced by the scanner. Enforcement is delegated to
CI pipelines which should read `wardline.controlLaw` and governance events
from SARIF output to gate merges when a retrospective scan is outstanding.

## Accepted Risks

### Baseline SARIF Integrity (v1.0)

The SARIF baseline file used for retrospective detection has no integrity
protection. Three suppression paths exist:

1. Edit `wardline.controlLaw` to `"normal"` in the baseline file
2. Delete the baseline file entirely (`prev_control_law` -> `None`, check skipped)
3. Corrupt the JSON to trigger the malformed-JSON handler (no baseline, no detection)

**Mitigation:** CI pipelines should generate baseline SARIF in a trusted
environment, not read it from the repository.

### Conformance File Integrity (v1.0)

`wardline.conformance.json` has no integrity protection. A fake file with
`cells_below_precision_floor: 0` is indistinguishable from a legitimate
one. The same CI-trusted-environment mitigation applies.

### Conformance Absence Heuristic (v1.0)

File-absent is interpreted as `conformance_never_run`. If a project has
used the tool but the conformance file was deleted (CI artifact cleanup,
repo clone without artifacts), the scanner reports the wrong corrective
action ("run corpus publish" instead of "investigate deletion").
