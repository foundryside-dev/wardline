# Exception Governance Assessment

**Auditor:** Exception Governance Agent
**Date:** 2026-03-25
**Scope:** Exception register schema, management logic, and governance model enforcement

## Files Assessed

| File | Role |
|------|------|
| `src/wardline/manifest/models.py` | `ExceptionEntry` dataclass |
| `src/wardline/manifest/exceptions.py` | Register loader and UNCONDITIONAL validation |
| `src/wardline/manifest/schemas/exceptions.schema.json` | JSON Schema for register |
| `src/wardline/scanner/exceptions.py` | Finding suppression and governance finding emission |
| `src/wardline/cli/exception_cmds.py` | CLI lifecycle commands (add, grant, refresh, expire, review, migrate) |
| `src/wardline/scanner/sarif.py` | SARIF output including governance metrics |
| `src/wardline/cli/scan.py` | Scan command wiring of exception metrics into SARIF |

## Spec References

- **wardline-01-13** SS 13.1.3 -- Exception register schema
- **wardline-01-09** SS 9.1 -- Exceptionability classes
- **wardline-01-09** SS 9.4 -- Governance capacity, recurrence tracking, expedited governance

---

## 1. Schema Completeness

**Spec requirement (SS 13.1.3):** Each exception record must contain identifier, rule+taint_state, location (file/function/line), exceptionability class, severity_at_grant, rationale, reviewer (identity/role/date), temporal bounds (grant/expiry/review_interval), provenance (standard/expedited, agent_originated).

| Field | Spec | Schema | Model | Status |
|-------|------|--------|-------|--------|
| Identifier | Required | `id` (required) | `id: str` | PASS |
| Rule | Required | `rule` (required) | `rule: str` | PASS |
| Taint state | Required | `taint_state` (required, enum) | `taint_state: str` | PASS |
| Location (file/function/line) | Required | `location` (required, string) | `location: str` | PASS -- encoded as `file_path::qualname`; line is not separately captured but qualname + AST fingerprint is more precise |
| Exceptionability class | Required | `exceptionability` (required, enum: STANDARD, RELAXED, TRANSPARENT) | `exceptionability: str` | PASS -- UNCONDITIONAL excluded from enum |
| Severity at grant | Required | `severity_at_grant` (required, enum) | `severity_at_grant: str` | PASS |
| Rationale | Required | `rationale` (required) | `rationale: str` | PASS |
| Reviewer identity | Required (identity, role, date) | `reviewer` (required, string) | `reviewer: str` | **CONCERN** -- spec says "identity, role, and date"; schema stores a single opaque string. No structured sub-fields for role or date. The CLI populates this from `--reviewer` as a free-text string. |
| Grant date | Required (temporal bounds) | Not present | Not present | **CONCERN** -- no `grant_date` field. The spec requires "grant date" as part of temporal bounds. The closest proxy is `last_refreshed_at` which tracks refresh, not grant. |
| Expiry date | Required | `expires` (optional, date or null) | `expires: str or None` | PASS |
| Review interval | Required (temporal bounds) | Not present | Not present | **CONCERN** -- the spec requires a `review_interval` per exception. Only the manifest-level `review_interval_days` exists. No per-exception review interval. |
| Governance path | Required | `governance_path` (enum: standard, expedited) | `governance_path: GovernancePath` | PASS |
| Agent originated | Required | `agent_originated` (boolean or null) | `agent_originated: bool or None` | PASS |

**Assessment:** Core fields are present. Three sub-fields are missing: structured reviewer (role+date), grant_date, and per-exception review_interval.

## 2. UNCONDITIONAL Rejection

**Spec requirement (SS 9.1):** "UNCONDITIONAL exceptions are schema-invalid -- an enforcement tool that encounters one MUST reject the register."

**Implementation:**

- **JSON Schema** (`exceptions.schema.json`): The `exceptionability` enum is `["STANDARD", "RELAXED", "TRANSPARENT"]`. UNCONDITIONAL is not in the enum, so schema validation rejects it. PASS.
- **Load-time validation** (`exceptions.py:_validate_not_unconditional`): After schema validation, each entry is checked against the severity matrix. If `cell.exceptionability == Exceptionability.UNCONDITIONAL`, a `ManifestLoadError` is raised. PASS.
- **CLI creation** (`exception_cmds.py:_create_exception`): Checks `cell.exceptionability == Exceptionability.UNCONDITIONAL` before writing. PASS.
- **Runtime matching** (`scanner/exceptions.py`): Finding with `exceptionability == UNCONDITIONAL` is never suppressed (line 155-156). PASS.

**Assessment:** PASS -- UNCONDITIONAL rejection is enforced at all four layers (schema, loader, CLI, runtime).

## 3. Severity-at-Grant Staleness

**Spec requirement (SS 13.1.3):** "When the enforcement tool detects that a finding's current severity differs from the exception's severity_at_grant, the exception is flagged as stale: a governance-level finding is produced."

**Implementation:** Not found. The `scanner/exceptions.py:apply_exceptions` function does not compare the current finding severity against `exc.severity_at_grant`. The field is recorded at grant time (CLI stamps `str(cell.severity)`) and stored in the register, but it is never read back during exception matching or governance finding emission.

The `_emit_register_governance` function checks agent_originated, recurrence_count, and expires -- but not severity_at_grant.

**Assessment:** **FAIL** -- `severity_at_grant` is write-only. The spec requires a governance-level finding when current severity differs from severity at grant; this check is not implemented.

## 4. Recurrence Tracking

**Spec requirement (SS 9.4):** "The exception register MUST track recurrence: when an exception for the same rule at the same code location is renewed after expiry, the renewal MUST be flagged as a recurrence event."

**Implementation:**

- **Schema:** `recurrence_count` field exists (integer, minimum 0). PASS.
- **Model:** `recurrence_count: int = 0`. PASS.
- **Governance finding:** `_emit_register_governance` emits `GOVERNANCE_RECURRING_EXCEPTION` when `recurrence_count >= 2`. PASS.
- **CLI review:** The `review` command reports recurring exceptions. PASS.
- **Automatic increment:** The `refresh` command does NOT increment `recurrence_count`. The `add`/`grant` commands initialize it to 0 but do not search for prior expired exceptions at the same (rule, location) to auto-increment. Recurrence counting appears to require manual management.

**Assessment:** **CONCERN** -- The field and governance finding exist, but automatic recurrence detection (incrementing the count when a new exception is granted at a previously-excepted location) is not implemented. The count must be manually managed, which undermines the spec's anti-gaming intent.

## 5. Expedited Governance Ratio

**Spec requirement (SS 9.4):** "The enforcement tool MUST compute and report the expedited/standard ratio -- the proportion of active (non-expired) exceptions granted through the expedited path -- in its findings output."

**Implementation:**

- **SARIF field:** `SarifReport.expedited_exception_ratio` is present and emitted as `wardline.expeditedExceptionRatio` in run properties. PASS.
- **Computation:** In `cli/scan.py` (lines 417-419), the ratio is computed as `_expedited / _active`. PASS.
- **CLI review:** The `review` command computes and displays the ratio. PASS.

**Assessment:** PASS -- expedited ratio is computed and reported in SARIF.

## 6. Agent-Originated Flag

**Spec requirement (SS 9.3):** Exceptions must carry an agent_originated flag.

**Implementation:**

- **Schema:** `agent_originated` (boolean or null). PASS.
- **Model:** `agent_originated: bool | None = None`. PASS.
- **CLI:** `--agent-originated` flag on `add`, `grant`, and `refresh` commands. PASS.
- **Governance:** `GOVERNANCE_UNKNOWN_PROVENANCE` finding when `agent_originated is None`. PASS.

**Assessment:** PASS.

## 7. Elimination Path Fields

**Spec requirement (SS 13.1.3):** "Two fields that convert the exception register from a finding-suppression mechanism into an architectural debt ledger: `elimination_path` and `elimination_cost`."

**Implementation:** Not found. A grep across all source files for `elimination_path` and `elimination_cost` returns zero results. These fields are not present in:
- The JSON schema (`exceptions.schema.json`)
- The data model (`ExceptionEntry`)
- The CLI commands
- The scanner logic

The spec marks these as "optional but recommended."

**Assessment:** **CONCERN** -- the spec says "optional but recommended." The fields are entirely absent from schema, model, and CLI. While not strictly required, their absence means the exception register cannot function as an architectural debt ledger as the spec envisions.

---

## Summary

| Check | Status | Detail |
|-------|--------|--------|
| 1. Schema completeness | CONCERN | Missing: structured reviewer (role/date), grant_date, per-exception review_interval |
| 2. UNCONDITIONAL rejection | PASS | Enforced at schema, loader, CLI, and runtime layers |
| 3. Severity-at-grant staleness | **FAIL** | Field is recorded but never compared at scan time; no governance finding emitted |
| 4. Recurrence tracking | CONCERN | Field and governance finding exist but count is never auto-incremented |
| 5. Expedited governance ratio | PASS | Computed and reported in SARIF |
| 6. Agent-originated flag | PASS | Present in schema, model, CLI, and governance checks |
| 7. Elimination path fields | CONCERN | "Optional but recommended" fields entirely absent |

## Verdict: CONCERN

**Rationale:** The exception governance model is substantially implemented -- UNCONDITIONAL rejection, expedited ratio, and agent-originated tracking are solid across all layers. However, one hard spec requirement is unmet: severity-at-grant staleness detection (SS 13.1.3) is not implemented despite the field being present. This is the most impactful gap because it means exceptions silently continue to suppress findings even when the underlying severity has been raised, which is the exact scenario the spec warns about. Recurrence tracking has the structural field but lacks automatic increment logic, reducing it to a manual honour system. Three temporal/structural sub-fields required by SS 13.1.3 (grant_date, review_interval, structured reviewer) are also absent.

The severity-at-grant gap alone would warrant FAIL, but is moderated to CONCERN because: (a) the field is present and correctly populated at grant time, so the fix is a comparatively small addition to `apply_exceptions`; and (b) the remaining gaps are in optional-but-recommended or sub-field-level areas rather than missing top-level governance controls.

**Recommended remediation priority:**
1. **(P1)** Implement severity-at-grant staleness detection in `scanner/exceptions.py:apply_exceptions` -- compare `exc.severity_at_grant` against current matrix cell severity, emit `GOVERNANCE_STALE_EXCEPTION` variant when they differ.
2. **(P2)** Add `grant_date` field to schema/model; populate from CLI at creation time.
3. **(P2)** Implement automatic recurrence count increment in `_create_exception` when a prior expired exception exists for the same (rule, location).
4. **(P3)** Add `elimination_path` and `elimination_cost` optional fields to schema/model.
5. **(P3)** Add per-exception `review_interval` field or document that manifest-level interval governs all exceptions.
6. **(P3)** Structure `reviewer` as an object with `identity`, `role`, and `date` sub-fields.
