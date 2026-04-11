# SARIF Output Format

Wardline emits [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json)
JSON. This document describes the exact structure, documents every
`wardline.*` property, and explains how the output maps to CI tooling.

---

## Quick Start

Write to a file:

```bash
wardline scan src/ --manifest wardline.yaml -o results.sarif.json
```

Pipe directly to `jq` for ad-hoc inspection:

```bash
wardline scan src/ --manifest wardline.yaml | jq '.runs[0].results[] | select(.level == "error")'
```

---

## Annotated Example

The following is a complete, minimal SARIF document for a single finding.
Field values are realistic; comments (`//`) are for this document only — the
actual JSON contains no comments.

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "wardline",
          "version": "1.0.0",
          "informationUri": "https://wardline.dev",
          "rules": [
            {
              "id": "PY-WL-001",
              "shortDescription": {
                "text": "Dict key access with fallback default"
              },
              "defaultConfiguration": {
                "level": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          // Standard SARIF fields
          "ruleId": "PY-WL-001",
          "level": "error",
          "message": {
            "text": "d.get('user_id', None) fabricates a value for missing key 'user_id' — use direct key access inside a shape-validation boundary"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  // Relative to the project root when --manifest is found;
                  // absolute POSIX path otherwise.
                  "uri": "src/myapp/handlers/auth.py"
                },
                "region": {
                  "startLine": 47,
                  "startColumn": 18,
                  "endLine": 47,
                  "endColumn": 38,
                  "snippet": {
                    "text": "user_id = d.get('user_id', None)"
                  }
                }
              }
            }
          ],
          // Wardline-specific result properties (see table below)
          "properties": {
            "wardline.rule": "PY-WL-001",
            "wardline.taintState": "INTEGRAL",
            "wardline.severity": "ERROR",
            "wardline.exceptionability": "STANDARD",
            "wardline.analysisLevel": 1,
            "wardline.enclosingTier": 1,
            "wardline.annotationGroups": [3],
            "wardline.excepted": false,
            "wardline.dataSource": null,
            "wardline.qualname": "myapp.handlers.auth.handle_login"
          }
        }
      ],
      // Wardline-specific run properties (see table below)
      "properties": {
        "wardline.analysisLevel": 1,
        "wardline.commitRef": "refs/heads/main",
        "wardline.conformanceGaps": [],
        "wardline.controlLaw": "normal",
        "wardline.coverageRatio": 0.9412,
        "wardline.governanceProfile": "lite",
        "wardline.implementedRules": [
          "PY-WL-001", "PY-WL-002", "PY-WL-003",
          "PY-WL-004", "PY-WL-005", "PY-WL-006",
          "PY-WL-007", "PY-WL-008", "PY-WL-009",
          "SCN-021", "SCN-022", "SUP-001"
        ],
        "wardline.inputFiles": 42,
        "wardline.inputHash": "sha256:a3f2c1...",
        "wardline.manifestHash": "sha256:b9e4d7...",
        "wardline.overlayHashes": ["sha256:c1a2b3..."],
        "wardline.propertyBagVersion": "0.5",
        "wardline.scanTimestamp": "2026-04-10T03:14:15Z",
        "wardline.errorFindingCount": 1,
        "wardline.warningFindingCount": 0,
        "wardline.suppressedCellFindingCount": 0,
        "wardline.exceptedFindingCount": 0,
        "wardline.gateBlockingCount": 1,
        "wardline.unknownRawFunctionCount": 0,
        "wardline.unresolvedDecoratorCount": 0,
        "wardline.filesWithDegradedTaint": 0,
        "wardline.activeExceptionCount": 0,
        "wardline.staleExceptionCount": 0,
        "wardline.expeditedExceptionRatio": 0.0,
        "wardline.deterministic": true,
        "wardline.deferredFixRatio": null
      }
    }
  ]
}
```

---

## Result Properties

Every result in `runs[0].results[].properties` carries the following
`wardline.*` properties.

### Mandatory result properties

These nine properties are always present (never omitted, though some may be
`null`).

| Property | Type | Description |
|---|---|---|
| `wardline.rule` | `string` | Canonical rule ID string (e.g. `"PY-WL-001"`). Mirrors the top-level `ruleId` field. |
| `wardline.taintState` | `string \| null` | Taint state of the enclosing function at the time the finding was emitted. One of `INTEGRAL`, `ASSURED`, `GUARDED`, `EXTERNAL_RAW`, `UNKNOWN_RAW`, `UNKNOWN_GUARDED`, `UNKNOWN_ASSURED`, `MIXED_RAW`. `null` for governance and pseudo-rule findings that operate outside the taint model. |
| `wardline.severity` | `string` | Wardline severity enumeration: `ERROR`, `WARNING`, or `SUPPRESS`. Use this rather than the SARIF `level` field when comparing against wardline rules — they map identically but this value is the canonical source. |
| `wardline.exceptionability` | `string` | Exception governance class. One of `UNCONDITIONAL`, `STANDARD`, `RELAXED`, `TRANSPARENT`. Controls the approval path required to grant an exception for this finding. |
| `wardline.analysisLevel` | `integer` | Analysis pass that produced this finding. `1` = AST-only; `2` = variable-level taint; `3` = L3 call-graph taint. |
| `wardline.enclosingTier` | `integer \| null` | Authority tier of the enclosing function, derived from `wardline.taintState`. `1` = INTEGRAL (highest authority), `2` = ASSURED, `3` = GUARDED / UNKNOWN_GUARDED / UNKNOWN_ASSURED, `4` = EXTERNAL_RAW / UNKNOWN_RAW / MIXED_RAW. `null` when `wardline.taintState` is `null`. |
| `wardline.annotationGroups` | `integer[]` | Sorted, deduplicated list of supplementary annotation group IDs active on the enclosing function. Empty array when no annotation groups apply. |
| `wardline.excepted` | `boolean` | `true` when this finding has an active exception in the exception register. When `true`, `wardline.exceptionId` is also present. |
| `wardline.dataSource` | `string \| null` | Taint provenance data source identifier. Always `null` in v1.0 (requires taint provenance threading, scheduled for a future release). |

### Optional result properties

These properties are omitted entirely when not applicable.

| Property | Type | Condition | Description |
|---|---|---|---|
| `wardline.qualname` | `string` | Present when the finding is inside a named function or method. | Fully qualified Python name of the enclosing callable (e.g. `myapp.handlers.auth.handle_login`). |
| `wardline.sourceSnippet` | `string` | Present when source text was available during the scan. | The source text of the flagged expression or statement, without leading/trailing whitespace. Also reflected in `region.snippet.text`. |
| `wardline.exceptionId` | `string` | Present when `wardline.excepted` is `true`. | The exception register entry ID granting this finding an active exception. |
| `wardline.exceptionExpires` | `string` | Present when the active exception has an expiry date. | ISO 8601 date string (e.g. `"2026-06-30"`) after which the exception is considered stale. |
| `wardline.retroactiveScan` | `boolean` (always `true`) | Present only when the scan was invoked with `--retrospective`. | Marks findings produced during a retrospective scan of a degraded-law window. |

---

## Run Properties

Every run in `runs[0].properties` carries the following `wardline.*`
properties.

### Always-present run properties

| Property | Type | Description |
|---|---|---|
| `wardline.analysisLevel` | `integer` | Analysis level used for this run (mirrors the result-level property but set once at the run level). |
| `wardline.conformanceGaps` | `string[]` | List of conformance gap identifiers active at scan time. Empty array when no gaps are known. |
| `wardline.controlLaw` | `string` | Enforcement control law state. One of `"normal"` (full enforcement), `"alternate"` (degraded but running), or `"direct"` (manifest unavailable — no meaningful enforcement output). |
| `wardline.governanceProfile` | `string` | Governance profile active for this run. Currently `"lite"` for all production scans. |
| `wardline.implementedRules` | `string[]` | Sorted list of canonical rule ID strings implemented by this tool version. Excludes pseudo-rule-IDs and diagnostic signals. |
| `wardline.inputFiles` | `integer` | Number of Python source files submitted to the scanner. |
| `wardline.inputHash` | `string` | Hash of the combined input file set (used for reproducibility checks). Empty string when not computed. |
| `wardline.manifestHash` | `string \| null` | SHA-256 hash of the resolved wardline manifest. `null` when no manifest was found. |
| `wardline.overlayHashes` | `string[]` | Ordered list of SHA-256 hashes for each overlay file contributing to the resolved manifest. Empty array when no overlays are present. |
| `wardline.propertyBagVersion` | `string` | Schema version for the `wardline.*` property bag. Current value: `"0.5"`. Consumers can use this to detect property bag evolution. |
| `wardline.errorFindingCount` | `integer` | Total number of `ERROR`-severity findings in this run (excepted and unexcepted combined). |
| `wardline.warningFindingCount` | `integer` | Total number of `WARNING`-severity findings in this run. |
| `wardline.suppressedCellFindingCount` | `integer` | Total number of `SUPPRESS`-severity findings in this run. |
| `wardline.exceptedFindingCount` | `integer` | Number of findings (any severity) with an active exception. |
| `wardline.gateBlockingCount` | `integer` | Number of `ERROR`-severity findings with no active exception. This is the number that causes a non-zero exit code. A CI quality gate passes when this value is `0`. |
| `wardline.unknownRawFunctionCount` | `integer` | Number of functions assigned `UNKNOWN_RAW` taint because taint could not be determined statically. High values may indicate gaps in manifest coverage. |
| `wardline.unresolvedDecoratorCount` | `integer` | Number of wardline decorator references that could not be statically resolved (aliased or conditionally imported). |
| `wardline.filesWithDegradedTaint` | `integer` | Number of files scanned with an empty fallback taint map — taint assignments for those files are less reliable. |
| `wardline.activeExceptionCount` | `integer` | Number of exception register entries that are currently active (non-stale). |
| `wardline.staleExceptionCount` | `integer` | Number of exception register entries whose AST fingerprint no longer matches the current code, or whose expiry date has passed. |
| `wardline.expeditedExceptionRatio` | `number` | Fraction of active exceptions granted via the expedited governance path (0.0–1.0, rounded to 3 decimal places). |
| `wardline.deterministic` | `boolean` | `true` when the run was executed in `--verification-mode` or otherwise produced fully deterministic output. When `false`, `wardline.scanTimestamp` reflects wall-clock time and results may vary between identical inputs due to non-deterministic ordering. |
| `wardline.deferredFixRatio` | `number \| null` | Fraction of excepted findings whose exception elimination path is a placeholder rather than a concrete fix plan. `null` when not computed. |

### Conditionally present run properties

These properties are omitted when not applicable.

| Property | Type | Condition | Description |
|---|---|---|---|
| `wardline.commitRef` | `string` | Omitted in `--verification-mode`. | Git ref at scan time (e.g. `"refs/heads/main"` or a commit SHA). Populated from the `WARDLINE_COMMIT_REF` environment variable or the `--commit-ref` flag. |
| `wardline.scanTimestamp` | `string` | Omitted in `--verification-mode`. | ISO 8601 UTC timestamp when the scan completed (e.g. `"2026-04-10T03:14:15Z"`). |
| `wardline.coverageRatio` | `number` | Omitted when not computable. | Fraction of scanned functions with a statically-known taint state (0.0–1.0, rounded to 4 decimal places). Values below 0.8 indicate significant manifest gaps. |
| `wardline.controlLawDegradations` | `string[]` | Omitted when `wardline.controlLaw` is `"normal"`. | Sorted list of degradation condition names active when the control law is `"alternate"` or `"direct"`. Possible values: `"conformance_gaps_present"`, `"manifest_unavailable"`, `"ratification_overdue"`, `"rules_disabled"`, `"stale_exceptions_present"`. |
| `wardline.retroactiveScan` | `boolean` (always `true`) | Omitted unless `--retrospective` was passed. | Marks runs produced during a retrospective scan of a degraded-law window. Always `true` when present; always co-present with `wardline.retroactiveScanRange`. |
| `wardline.retroactiveScanRange` | `string` | Omitted unless `wardline.retroactiveScan` is `true`. | The commit range passed to `--retrospective` (e.g. `"abc123..def456"`). |
| `wardline.governanceEvents` | `object[]` | Omitted when there are no governance audit events. | Structured governance audit trail. Each entry has `eventType` (string), `message` (string), and optionally `timestamp` (ISO 8601 string, omitted in verification mode). |

---

## SARIF Level Mapping

Wardline severity maps to SARIF `level` as follows. Most CI SARIF consumers
(GitHub Advanced Security, Azure DevOps, VS Code SARIF Viewer) treat `error`
as blocking and `warning`/`note` as advisory.

| Wardline severity | SARIF `level` | GitHub Code Scanning | CI exit code |
|---|---|---|---|
| `ERROR` | `error` | Shown as a code-scanning alert; blocks PR merge when quality gate is enabled. | Exit 1 when unexcepted. |
| `WARNING` | `warning` | Shown as a code-scanning alert (advisory). | No effect on exit code. |
| `SUPPRESS` | `note` | Shown as a note (informational). | No effect on exit code. |

The authoritative source for the exit code is `wardline.gateBlockingCount` in
`run.properties`. A CI step passes when `wardline.gateBlockingCount == 0`.

---

## Further Reading

- [CLI reference](cli.md) — all `wardline scan` flags and exit codes
- [Rules reference](rules.md) — full description of every rule ID
- [CI integration guide](../guides/ci-integration.md) — GitHub Actions, GitLab CI, and Azure Pipelines recipes
