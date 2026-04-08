# Governance Audit Retention

This document defines the retention requirements for wardline governance
artefacts, per WL-FIT-GOV-015 and Wardline Framework Specification
section 9.2.1.

## Governance Artefacts

Wardline produces four categories of governance artefact:

| Artefact | Location | Content |
|----------|----------|---------|
| **Exception register** | `wardline.exceptions.json` | All granted exceptions with rationale, reviewer, fingerprint, expiry |
| **Fingerprint baseline** | `wardline.fingerprint.json` | Per-function annotation hashes for drift detection |
| **SARIF scan output** | CI artefact or `--output` file | Findings, governance events, control law state, manifest hash |
| **Manifest** | `wardline.yaml` + overlays | Tier assignments, boundaries, governance profile, metadata |

## Retention Requirements

### Minimum Retention Period

All governance artefacts SHOULD be retained for the **duration of the
system's accreditation period**. For ISM-assessed systems, this is
typically **3 years** from the last IRAP assessment.

### What to Retain

1. **SARIF output from every CI scan** on the default branch.
   These are the primary audit trail — each contains the manifest hash,
   control law state, governance events, and all findings.

2. **VCS history of governance files.** The exception register,
   fingerprint baseline, and manifest are version-controlled. Retain
   the git history of these files for the retention period. Do not
   rebase or squash commits that modify governance artefacts.

3. **Exception lifecycle records.** The exception register tracks
   `recurrence_count`, `last_refreshed_at`, and `governance_path`.
   These fields form the audit trail for exception grants, refreshes,
   and expirations.

### Recommended CI Configuration

Store SARIF scan output as a CI artefact with retention matching your
accreditation cycle:

```yaml
# GitHub Actions example
- name: Wardline scan
  run: wardline scan src/ --output wardline-scan.sarif.json
- uses: actions/upload-artifact@v4
  with:
    name: wardline-sarif-${{ github.sha }}
    path: wardline-scan.sarif.json
    retention-days: 1095  # 3 years
```

### Governance Events in SARIF

Each SARIF run includes a `wardline.governanceEvents` array recording:

- `exception_expired` — exception reached its expiry date
- `exception_escalated` — recurrence count threshold exceeded
- `control_law_transition` — control law changed (normal/alternate/direct)
- `ratification` — manifest ratification metadata assessed

These events are timestamped and linked to specific exceptions or
manifest states, providing a structured audit trail.

## Deletion Policy

Do not delete governance artefacts before the retention period expires.
If artefacts must be purged (e.g., infrastructure migration), archive
them to durable storage first. The `wardline regime verify` command
checks artefact presence — missing artefacts will produce governance
findings.
