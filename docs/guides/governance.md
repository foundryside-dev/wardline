# Governance Walkthrough

Wardline governance manages exceptions — recorded decisions to accept findings
that would otherwise block your scan.

## When You Need an Exception

A finding is blocking your build (exit code 1), and:

- You understand the finding and have decided the pattern is acceptable in this
  specific case, OR
- You need time to fix it and want to unblock the build while tracking the debt

Exceptions are not a way to silence the scanner permanently. They have expiry
dates, and the scanner monitors them for staleness.

## The Exception Lifecycle

```
Finding blocks build
       |
       v
  wardline exception add    <- declare the exception
       |
       v
  wardline exception grant  <- reviewer approves
       |
       v
  Exception active          <- finding is covered, build passes
       |
       |-- Code changes -> fingerprint mismatch -> GOVERNANCE-STALE-EXCEPTION
       |
       |-- Taint changes -> GOVERNANCE-EXCEPTION-TAINT-DRIFT
       |
       +-- Expiry date reached -> exception inactive -> finding blocks again
```

## Step-by-Step: Granting an Exception

### 1. Identify the finding

```bash
# Run a scan and note the finding you want to except
wardline scan src/ -o findings.sarif

# Or use explain to understand a specific function
wardline explain myapp.core.auth.lookup_user
```

### 2. Add the exception

```bash
wardline exception add \
  --rule PY-WL-001 \
  --location "src/myapp/core/auth.py::lookup_user" \
  --taint-state INTEGRAL \
  --rationale "Cache lookup uses sentinel default; validated by caller" \
  --elimination-path "Refactor to use Optional return type" \
  --expires 2026-07-01
```

### 3. Grant the exception (reviewer step)

```bash
wardline exception grant <exception-id> \
  --reviewer "jane.smith"
```

### 4. Verify the exception is active

```bash
wardline scan src/ --verification-mode
# Exit code should now be 0 (finding is covered)
```

## Exception Fields

| Field | Required | Purpose |
|-------|----------|---------|
| `rule` | Yes | Which rule is being excepted |
| `location` | Yes | File path and function name |
| `taint_state` | Yes | Taint state context |
| `rationale` | Yes | Why this exception is acceptable |
| `elimination_path` | Yes | How to eventually fix the code |
| `expires` | Recommended | ISO 8601 date; scanner warns when approaching |
| `reviewer` | At grant | Who approved the exception |
| `governance_path` | Auto | `standard` or `expedited` |

## Governance Profiles

The governance profile affects how strictly exceptions are scrutinized:

| Profile | Exception Rules |
|---------|----------------|
| **lite** | Temporal separation alternatives allowed; governance gaps emit warnings |
| **assurance** | All fields mandatory; governance gaps are errors; coherence failures auto-gate |

See [Profiles Guide](profiles.md) for choosing between them.

## Monitoring Governance Health

Run `wardline coherence` periodically to check for:

- **Stale exceptions** — code changed but exception fingerprint was not updated
- **Taint drift** — function's effective taint no longer matches the exception
- **Recurring exceptions** — exception has been renewed multiple times (indicates
  the elimination path is not being followed)
- **Expedited ratio** — too many exceptions on the expedited path (suggests
  governance is being bypassed)

## Common Governance Findings

| Finding | Meaning | Action |
|---------|---------|--------|
| `GOVERNANCE-STALE-EXCEPTION` | Code changed under the exception | Run `wardline fingerprint update` then `wardline exception refresh` |
| `GOVERNANCE-RECURRING-EXCEPTION` | Exception renewed 3+ times | Prioritize the elimination path |
| `GOVERNANCE-NO-EXPIRY-EXCEPTION` | Exception has no expiry | Add an expiry date with `wardline exception add --expires` |
| `GOVERNANCE-EXCEPTION-TAINT-DRIFT` | Taint state changed | Review whether the exception is still valid |
| `GOVERNANCE-WEAK-ELIMINATION-PATH` | Elimination path is a placeholder | Write a real elimination plan |

## Further Reading

- [CLI Reference](../reference/cli.md#wardline-exception) — exception command options
- [Error Messages](../reference/error-messages.md) — governance error diagnostics
- [Profiles Guide](profiles.md) — lite vs assurance
- [Spec §9: Governance Model](../spec/wardline-01-09-governance-model.md) — normative definition
