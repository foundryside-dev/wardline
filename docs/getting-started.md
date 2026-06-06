# Getting Started

This guide takes you from an empty environment to reading your first finding.

## 1. Install

The `wardline scan` command lives in the `scanner` extra:

```bash
pip install "wardline[scanner]"
```

(The base `wardline` install is a zero-dependency library with no CLI; the
`scanner` extra adds pyyaml, jsonschema, and click.)

Check the install:

```bash
wardline --version
```

```text
wardline, version 0.2.0
```

## 2. Run a first scan

Point `wardline scan` at a directory and choose an output format:

```bash
wardline scan . --format jsonl
```

```text
scanned 2 file(s); 4 finding(s) — 0 suppressed (0 baseline / 0 waiver / 0 judged), 1 active -> findings.jsonl
```

!!! note "Where the findings go"
    In `jsonl` mode the findings are written to a file, not printed. The summary
    line names the destination — here, `findings.jsonl` in the current
    directory. Use `--output PATH` to write somewhere else, or `--format sarif`
    for SARIF. The summary itself is printed to standard output.

The other format is SARIF (`--format sarif`), for tools that consume the SARIF
standard. If you are sending findings to Filigree for promotion, deduplication,
or close/reopen lifecycle tracking, prefer native emission with
`--filigree-url`; SARIF import is a generic interchange path and depends on the
importer preserving Wardline's SARIF fingerprint field.

## 3. Read one finding

Each line of `findings.jsonl` is one finding. Here is a real one (re-flowed for
readability):

```json
{
  "rule_id": "PY-WL-101",
  "severity": "ERROR",
  "kind": "defect",
  "qualname": "service.current_user",
  "location": {"path": "service.py", "line_start": 7, "line_end": 8, "col_start": 0, "col_end": 26},
  "message": "service.current_user declares return trust INTEGRAL but actually returns EXTERNAL_RAW (less trusted) — untrusted data reaches a trusted producer",
  "properties": {"declared_return": "INTEGRAL", "actual_return": "EXTERNAL_RAW"},
  "suppressed": "active",
  "suppression_reason": null,
  "confidence": null,
  "suggestion": null,
  "related_entities": [],
  "fingerprint": "6277037752d48f88ceda3d27aaca5389e36af0ed5d492e777f5a3fa749afb673"
}
```

The fields:

| Field | Meaning |
| --- | --- |
| `rule_id` | Which rule fired. `PY-WL-101` is "untrusted data reaches a trusted producer". |
| `severity` | One of `CRITICAL`, `ERROR`, `WARN`, `INFO`, `NONE`. |
| `kind` | The category of finding — here `defect`. |
| `qualname` | The qualified name of the code entity the finding is about. |
| `location` | The source `path` plus `line_start`/`line_end` and `col_start`/`col_end`. |
| `message` | A human-readable description of the violation. |
| `properties` | Rule-specific detail. Here, the declared vs. actually-returned trust tier. |
| `suppressed` | `active` means the finding is live (not suppressed). |
| `suppression_reason` | Why it was suppressed, if it was; `null` for a live finding. |
| `confidence`, `suggestion` | Optional extras, `null` when the rule does not supply them. |
| `related_entities` | Other entities involved in the finding, if any. |
| `fingerprint` | A stable hash identifying the finding across runs — used for baselining and suppression. |

This finding says `service.current_user` is annotated as a trusted producer but
actually returns `EXTERNAL_RAW` data — untrusted input reaching a trusted
surface with no validation in between.

## 4. Gate your build

To make a scan fail (non-zero exit) when findings at or above a level are
present, use `--fail-on`:

```bash
wardline scan . --format jsonl --fail-on ERROR
```

With an `ERROR` finding present this exits with status `1`, which is enough to
fail a CI step.

## Next steps

- [Configuration](guides/configuration.md) — tune which rules run, severities, and scan settings.
- [Suppressing findings](guides/suppression.md) — baselines and waivers for findings you have triaged.
