# CLI Command Reference

Wardline — semantic boundary enforcement for Python.

**Entry point:** `wardline`

## Global Options

| Flag | Description |
|------|-------------|
| `--help` | Show help message and exit. |

---

## `wardline scan`

Run the static analysis scanner against Python files and emit SARIF output.

**Usage:** `wardline scan [OPTIONS] [PATH]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--manifest FILE` | Path to `wardline.yaml` manifest. | auto-detect |
| `--config PATH` | Path to `wardline.toml` config. | auto-detect |
| `-o, --output PATH` | Output file path. | stdout |
| `-v, --verbose` | Verbose logging to stderr. | off |
| `--debug` | Debug logging to stderr. | off |
| `--verification-mode` | Deterministic output (no timestamps). Useful for reproducible CI output. | off |
| `--max-unknown-raw-percent FLOAT` | Maximum percentage of `UNKNOWN_RAW` findings per file scanned (denominator is `files_scanned`). Exit 1 if exceeded. | none |
| `--allow-registry-mismatch` | Emit a `GOVERNANCE` finding instead of exiting with code 2 on a registry sync mismatch. | off |
| `--allow-permissive-distribution` | Emit a `GOVERNANCE` finding when permissive distribution mode is active, instead of treating it as a configuration error. | off |
| `--preview-phase2` | Output a Phase 2 migration impact report (JSON) instead of SARIF. Normal exit code rules still apply. | off |
| `--resolved PATH` | Use a pre-resolved manifest (`wardline.resolved.json`) instead of resolving overlays at scan time. | none |
| `--allow-stale-resolved` | Warn instead of exiting with code 2 when the resolved file's manifest hash is stale. | off |
| `--strict-governance` | Treat any `GOVERNANCE-*` finding as a scan failure (exit 1). | off |
| `--retrospective TEXT` | Retrospective scan for a degraded-law window. Accepts a commit range (e.g. `abc123..def456`). Marks all findings with `retroactive_scan: true`. | none |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | No gate-blocking findings. |
| 1 | At least one unexcepted `ERROR`-severity finding, or `--max-unknown-raw-percent` ceiling exceeded, or `--strict-governance` set and at least one `GOVERNANCE-*` finding. |
| 2 | Configuration error (manifest not found or invalid, registry mismatch, resolved file stale without `--allow-stale-resolved`, overlay policy error, or output file cannot be written). |
| 3 | Internal tool error — a rule or scanner component raised an unhandled exception. |

**Notes:**
- `WARNING` and `SUPPRESS` findings are non-blocking and do not affect the exit code.
- CLI flags take precedence over `wardline.toml` settings when both are supplied.
- The output is SARIF v2.1.0 unless `--preview-phase2` is used.

**Examples:**

```bash
# Scan with auto-detected manifest
wardline scan src/

# Scan with explicit manifest and config, write SARIF to file
wardline scan src/ --manifest wardline.yaml --config wardline.toml -o scan.sarif

# CI: deterministic output, exit 1 on any findings
wardline scan src/ --verification-mode

# Enforce a coverage threshold
wardline scan src/ --max-unknown-raw-percent 5.0

# Use a pre-resolved manifest for faster scanning in monorepos
wardline scan src/ --resolved wardline.resolved.json
```

---

## `wardline explain`

Show the taint resolution path for a named function. Useful for diagnosing why a function received a particular taint state and which rules apply.

**Usage:** `wardline explain [OPTIONS] QUALNAME`

**Arguments:**

| Argument | Description |
|----------|-------------|
| `QUALNAME` | Qualified name of the function to explain (e.g. `MyClass.process`). Required. |

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--manifest PATH` | Path to `wardline.yaml` manifest. | auto-detect |
| `--path PATH` | Root path to search for the function. | `.` |
| `--json` | Output as JSON. | off |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Function found; resolution path displayed. |
| 1 | Function not found in any Python file under `--path`. |
| 2 | Configuration error (manifest malformed). |

**Output includes:**
- File path where the function was found.
- Resolved taint state and how it was determined (decorator, `module_tiers` entry, or fallback).
- Rules evaluated at that taint state with severity and exceptionability.
- Exception register status for each rule.
- Overlay resolution (which overlay governs the file, if any).
- Annotation fingerprint hash and baseline match status.

**Examples:**

```bash
wardline explain MyClass.process
wardline explain MyClass.process --path src/ --json
wardline explain validate_payload --manifest wardline.yaml --path src/
```

---

## `wardline manifest`

Manifest validation and baseline management. Groups subcommands for working with `wardline.yaml`.

**Usage:** `wardline manifest [OPTIONS] COMMAND [ARGS]...`

**Subcommands:**

| Command | Description |
|---------|-------------|
| `validate` | Validate a `wardline.yaml` against the schema. |
| `baseline` | Manage manifest baselines. |
| `coherence` | Run all coherence checks against the manifest and code annotations. |

---

### `wardline manifest validate`

Validate a `wardline.yaml` manifest against the JSON Schema. If no file is given, the manifest is auto-discovered from the current directory.

**Usage:** `wardline manifest validate [OPTIONS] [FILE]`

**Arguments:**

| Argument | Description |
|----------|-------------|
| `FILE` | Path to `wardline.yaml`. Optional; auto-discovered if omitted. |

**Options:**

| Flag | Description |
|------|-------------|
| `--help` | Show help message and exit. |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Manifest is valid. |
| 1 | Manifest is invalid (schema violation or parse error). |
| 2 | File not found (explicit path missing, or no manifest discovered). |

**Examples:**

```bash
wardline manifest validate
wardline manifest validate wardline.yaml
wardline manifest validate path/to/wardline.yaml
```

---

### `wardline manifest baseline`

Write manifest baseline files (`wardline.manifest.baseline.json` and `wardline.perimeter.baseline.json`) from the current manifest. The `--approve` flag is required as a deliberate confirmation step.

**Usage:** `wardline manifest baseline [OPTIONS] {update}`

**Arguments:**

| Argument | Description |
|----------|-------------|
| `update` | Action to perform. Currently only `update` is supported. |

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--approve` | Required to confirm the baseline update. | off |
| `--manifest PATH` | Path to `wardline.yaml`. | auto-detect |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Baselines written successfully. |
| 1 | `--approve` not provided, or manifest is invalid. |
| 2 | Manifest not found. |

**Examples:**

```bash
wardline manifest baseline update --approve
wardline manifest baseline update --approve --manifest wardline.yaml
```

---

### `wardline manifest coherence`

Run all 14 coherence checks against the manifest and code annotations. This is identical to `wardline coherence` (the top-level command is an alias).

See [`wardline coherence`](#wardline-coherence) for full documentation.

---

## `wardline coherence`

Run all 14 coherence checks against the manifest and code annotations. Checks cover tier topology, boundary declarations, contract bindings, exception governance, and validation scope.

**Usage:** `wardline coherence [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--manifest PATH` | Path to `wardline.yaml` manifest. Required. | — |
| `--path PATH` | Root path to scan for Python files. Required. | — |
| `--json` | JSON output. | off |
| `--gate` | Exit 1 if any `ERROR`-level coherence issues are found. | off |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | No issues found, or issues found but `--gate` not set (or no `ERROR`-level issues). |
| 1 | `ERROR`-level coherence issues found (when `--gate` is set, or when the manifest's assurance profile forces gating). |
| 2 | Configuration error (manifest not found or malformed). |

**Coherence checks run:**

| Check | Category | Severity |
|-------|----------|----------|
| `orphaned_annotation` | enforcement | WARNING |
| `undeclared_boundary` | enforcement | ERROR |
| `unmatched_contract` | enforcement | ERROR |
| `stale_contract_binding` | enforcement | WARNING |
| `tier_distribution` | enforcement | WARNING |
| `tier_downgrade` | policy | ERROR |
| `tier_upgrade_without_evidence` | policy | WARNING |
| `tier_topology_inconsistency` | policy | ERROR |
| `agent_originated_exception` | enforcement | WARNING |
| `expired_exception` | enforcement | WARNING |
| `first_scan_perimeter` | enforcement | WARNING |
| `missing_validation_scope` | enforcement | WARNING |
| `insufficient_restoration_evidence` | enforcement | WARNING |
| `restoration_evidence_divergence` | enforcement | ERROR |

**Examples:**

```bash
wardline coherence --manifest wardline.yaml --path src/
wardline coherence --manifest wardline.yaml --path src/ --gate
wardline coherence --manifest wardline.yaml --path src/ --json
```

---

## `wardline corpus`

Corpus management commands. Groups subcommands for working with the test corpus of rule specimens.

**Usage:** `wardline corpus [OPTIONS] COMMAND [ARGS]...`

**Subcommands:**

| Command | Description |
|---------|-------------|
| `verify` | Verify corpus specimens against scanner rules. |
| `publish` | Generate `wardline.conformance.json` from corpus verify and self-hosting SARIF. |

---

### `wardline corpus verify`

Verify corpus specimens (YAML files in the corpus directory) against scanner rules. Computes per-cell (rule × taint_state) precision and recall where sample size is at least 5. Known false negatives are tracked separately from true negatives.

**Usage:** `wardline corpus verify [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--corpus-dir DIRECTORY` | Directory containing specimen YAML files. | `corpus/specimens` |
| `--analysis-level INTEGER` | Analysis level (1–3). Specimens requiring a higher level are skipped. | 1 |
| `--json` | Output per-cell assessment JSON instead of text. | off |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All verified specimens matched expected verdicts. |
| 1 | One or more specimens did not match expected verdicts. |

**Examples:**

```bash
wardline corpus verify
wardline corpus verify --corpus-dir corpus/specimens --analysis-level 2
wardline corpus verify --json
```

---

### `wardline corpus publish`

Generate `wardline.conformance.json` by combining corpus verification results with a self-hosting SARIF scan output. This file is consumed by `wardline scan` to report conformance gaps in the SARIF run properties.

**Usage:** `wardline corpus publish [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--corpus-dir DIRECTORY` | Corpus specimen directory. | `corpus/specimens` |
| `--sarif FILE` | Self-hosting SARIF output file from a previous `wardline scan`. Required. | — |
| `-o, --output FILE` | Output path for the conformance status file. | `wardline.conformance.json` |
| `--analysis-level INTEGER` | Analysis level (1–3). | 1 |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Conformance file written successfully. |
| 1 | Corpus verification failures detected. |

**Examples:**

```bash
# First produce a self-hosting SARIF, then publish conformance
wardline scan src/ -o scan.sarif
wardline corpus publish --sarif scan.sarif
wardline corpus publish --sarif scan.sarif -o wardline.conformance.json --analysis-level 3
```

---

## `wardline exception`

Manage the wardline exception register (`wardline.exceptions.json`). Exceptions suppress specific rule findings at named locations with documented rationale and reviewer sign-off.

**Usage:** `wardline exception [OPTIONS] COMMAND [ARGS]...`

**Subcommands:**

| Command | Description |
|---------|-------------|
| `add` | Add a new exception to the register. |
| `grant` | Grant a new exception (same as `add`, also stamps `analysis_level`). |
| `expire` | Mark an exception as expired. |
| `refresh` | Refresh exception fingerprints after code changes. |
| `review` | Review exceptions needing attention. |
| `preview-drift` | Preview which exceptions would drift under L3 taint analysis. |
| `migrate` | Migrate exception `taint_state` values to match current taint analysis. |

---

### `wardline exception add`

Add a new exception to the register. All fields are required. Use `--governance-path expedited` for time-sensitive approvals (subject to the 15% expedited ratio threshold).

**Usage:** `wardline exception add [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--rule TEXT` | Rule ID to except (e.g. `PY-WL-001`). Required. | — |
| `--location TEXT` | Location in `file_path::qualname` format. Required. | — |
| `--taint-state TEXT` | Taint state of the finding (e.g. `EXTERNAL_RAW`). Required. | — |
| `--rationale TEXT` | Why this exception is granted. Required. | — |
| `--reviewer TEXT` | Who approved this exception. Required. | — |
| `--governance-path [standard\|expedited]` | Governance path for approval. | `standard` |
| `--expires TEXT` | Expiry date in ISO 8601 format (e.g. `2027-03-23`). | none |
| `--agent-originated` | Mark exception as agent-originated. | off |
| `--analysis-level INTEGER` | Analysis level to stamp on the exception. | 1 |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Exception added successfully. |
| 1 | Invalid rule ID, invalid taint state, or the finding is `UNCONDITIONAL` (non-exceptable). |

**Examples:**

```bash
wardline exception add \
  --rule PY-WL-001 \
  --location "src/app/views.py::create_record" \
  --taint-state EXTERNAL_RAW \
  --rationale "Manually validated upstream; downstream consumers sanitise." \
  --reviewer "alice" \
  --expires 2027-06-01
```

---

### `wardline exception grant`

Grant a new exception. Functionally identical to `add` but explicitly stamps the `analysis_level` field to indicate which level of taint analysis the exception was reviewed under.

**Usage:** `wardline exception grant [OPTIONS]`

**Options:** Same as [`wardline exception add`](#wardline-exception-add).

**Exit Codes:** Same as [`wardline exception add`](#wardline-exception-add).

---

### `wardline exception expire`

Mark an existing exception as expired by its exception ID.

**Usage:** `wardline exception expire [OPTIONS] EXC_ID`

**Arguments:**

| Argument | Description |
|----------|-------------|
| `EXC_ID` | The exception ID to expire. Required. |

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--reason TEXT` | Reason for expiry. | none |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Exception marked expired. |
| 1 | Exception ID not found. |

**Examples:**

```bash
wardline exception expire exc-a1b2c3d4
wardline exception expire exc-a1b2c3d4 --reason "Finding resolved in v2.1"
```

---

### `wardline exception refresh`

Refresh exception fingerprints after code changes to re-anchor exceptions to their new AST context. Required when code at an excepted location changes.

**Usage:** `wardline exception refresh [OPTIONS] [IDS]...`

**Arguments:**

| Argument | Description |
|----------|-------------|
| `IDS` | One or more exception IDs to refresh. Optional when `--all` is used. |

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--all` | Refresh all non-expired exceptions. | off |
| `--actor TEXT` | Who is performing this refresh. Required. | — |
| `--rationale TEXT` | Why the code change is safe. Required. | — |
| `--confirm` | Required when using `--all`. | off |
| `--dry-run` | Show rule context without modifying any exceptions. | off |
| `--json` | JSON output. | off |
| `--agent-originated` | Mark refresh as agent-originated. | off |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Exceptions refreshed (or dry-run completed). |
| 1 | One or more IDs not found, or `--all` used without `--confirm`. |

**Examples:**

```bash
wardline exception refresh exc-a1b2c3d4 --actor alice --rationale "Renamed function only"
wardline exception refresh --all --confirm --actor alice --rationale "Bulk refresh after refactor"
wardline exception refresh exc-a1b2c3d4 --dry-run --actor alice --rationale "Checking context"
```

---

### `wardline exception review`

List exceptions that need attention — expired exceptions, agent-originated exceptions awaiting human review, and exceptions with high recurrence counts.

**Usage:** `wardline exception review [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--json` | JSON output. | off |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Review complete (output may still list exceptions requiring action). |

**Examples:**

```bash
wardline exception review
wardline exception review --json
```

---

### `wardline exception preview-drift`

Preview which exceptions would change taint state (drift) if the analysis were run at L3 taint propagation. Does not modify anything.

**Usage:** `wardline exception preview-drift [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--analysis-level INTEGER` | Analysis level for taint computation. | 1 |
| `--manifest PATH` | Path to `wardline.yaml`. | auto-detect |
| `--path PATH` | Path to scan for taint computation. Required. | — |
| `--json` | JSON output. | off |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Preview complete. |
| 2 | Manifest not found or scan path missing. |

**Examples:**

```bash
wardline exception preview-drift --path src/ --manifest wardline.yaml
wardline exception preview-drift --path src/ --analysis-level 3 --json
```

---

### `wardline exception migrate`

Migrate exception `taint_state` values to match the taint states produced by the current analysis. Requires `--confirm` to actually modify the exception register.

**Usage:** `wardline exception migrate [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--analysis-level INTEGER` | Analysis level for taint computation. | 1 |
| `--manifest PATH` | Path to `wardline.yaml`. | auto-detect |
| `--path PATH` | Path to scan for taint computation. Required. | — |
| `--confirm` | Required to actually perform the migration. | off |
| `--actor TEXT` | Who is performing this migration. Required. | — |
| `--json` | JSON output. | off |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Migration complete (or dry-run if `--confirm` not supplied). |
| 2 | Manifest not found or path missing. |

**Examples:**

```bash
# Dry-run: preview what would change
wardline exception migrate --path src/ --actor alice

# Perform the migration
wardline exception migrate --path src/ --actor alice --confirm
```

---

## `wardline fingerprint`

Annotation fingerprint baseline management. Tracks changes to wardline decorator annotations over time, enabling detection of unapproved annotation removal.

**Usage:** `wardline fingerprint [OPTIONS] COMMAND [ARGS]...`

**Subcommands:**

| Command | Description |
|---------|-------------|
| `update` | Compute and write the annotation fingerprint baseline. |
| `diff` | Compare current annotations against the fingerprint baseline. |

---

### `wardline fingerprint update`

Compute annotation fingerprints for all decorated functions under `--path` and write `wardline.fingerprint.json` next to the manifest.

**Usage:** `wardline fingerprint update [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--manifest PATH` | Path to `wardline.yaml` manifest. Required. | — |
| `--path PATH` | Root path to scan for Python files. Required. | — |
| `--json` | JSON output (emits baseline path, coverage stats, and fingerprint count). | off |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Baseline written successfully. |
| 2 | Manifest not found or malformed. |

**Examples:**

```bash
wardline fingerprint update --manifest wardline.yaml --path src/
wardline fingerprint update --manifest wardline.yaml --path src/ --json
```

---

### `wardline fingerprint diff`

Compare current annotations against the stored baseline. Reports added, removed, and modified annotation fingerprints. Groups changes by artefact class (`policy` vs enforcement).

**Usage:** `wardline fingerprint diff [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--manifest PATH` | Path to `wardline.yaml` manifest. Required. | — |
| `--path PATH` | Root path to scan for Python files. Required. | — |
| `--json` | JSON output. | off |
| `--gate` | Exit 1 if any Tier 1 annotations have been removed. | off |
| `--since TEXT` | Only show changes after this ISO date (`YYYY-MM-DD`). | none |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | No gate-triggering changes (or `--gate` not set). |
| 1 | Tier 1 annotations removed (when `--gate` is set). |
| 2 | Manifest not found or malformed. |

**Examples:**

```bash
wardline fingerprint diff --manifest wardline.yaml --path src/
wardline fingerprint diff --manifest wardline.yaml --path src/ --gate
wardline fingerprint diff --manifest wardline.yaml --path src/ --since 2026-01-01 --json
```

---

## `wardline regime`

Governance regime health commands. Provides a read-only status dashboard and active verification checks.

**Usage:** `wardline regime [OPTIONS] COMMAND [ARGS]...`

**Subcommands:**

| Command | Description |
|---------|-------------|
| `status` | Read-only governance health dashboard. |
| `verify` | Run active governance verification checks. |

---

### `wardline regime status`

Display a read-only governance health dashboard assembled from existing artefacts (manifest, exception register, fingerprint baseline, scanner config). Does not run analysis or modify any files.

**Usage:** `wardline regime status [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--manifest PATH` | Path to `wardline.yaml` manifest. Required. | — |
| `--path PATH` | Root path to scan for Python files. Required. | — |
| `--json` | JSON output. | off |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Status displayed. |
| 2 | Manifest not found. |

**Dashboard sections:** governance profile, analysis level, active/disabled rules, exception counts (active, expired, agent-originated, expedited ratio), fingerprint baseline coverage, and manifest ratification status.

**Examples:**

```bash
wardline regime status --manifest wardline.yaml --path src/
wardline regime status --manifest wardline.yaml --path src/ --json
```

---

### `wardline regime verify`

Run 12 active governance verification checks covering manifest validity, coherence, exception register integrity, annotation change tracking, and ratification currency. Use `--gate` to make failures block CI.

**Usage:** `wardline regime verify [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--manifest PATH` | Path to `wardline.yaml` manifest. Required. | — |
| `--path PATH` | Root path to scan for Python files. Required. | — |
| `--json` | JSON output. | off |
| `--gate` | Exit 1 if any `ERROR`-level checks fail. Combine with `--strict` to also gate on `WARNING`-level failures. | off |
| `--strict` | With `--gate`, also exit 1 on `WARNING`-level failures. | off |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All checks passed (or failures exist but `--gate` not set). |
| 1 | One or more checks failed at the gated severity level (requires `--gate`). |
| 2 | Manifest not found. |

**Verification checks:**

| Check | Severity |
|-------|----------|
| `manifest_loads` | ERROR |
| `coherence_checks` | ERROR |
| `no_disabled_unconditional` | ERROR |
| `exception_register_valid` | ERROR |
| `ratification_metadata_present` | ERROR |
| `temporal_separation_declared` | ERROR (assurance) / WARNING (lite) |
| `expedited_ratio` | WARNING |
| `fingerprint_baseline_exists` | WARNING |
| `fingerprint_baseline_fresh` | WARNING |
| `no_expired_exceptions` | WARNING |
| `ratification_current` | WARNING |
| `annotation_change_tracking` | WARNING |

**Examples:**

```bash
wardline regime verify --manifest wardline.yaml --path src/
wardline regime verify --manifest wardline.yaml --path src/ --gate
wardline regime verify --manifest wardline.yaml --path src/ --gate --strict
wardline regime verify --manifest wardline.yaml --path src/ --json
```

---

## `wardline resolve`

Resolve all overlays and produce `wardline.resolved.json`. The resolved file pre-computes boundary merges, rule overrides, and optional field declarations so that `wardline scan --resolved` can skip overlay processing at scan time.

**Usage:** `wardline resolve [OPTIONS]`

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--manifest TEXT` | Path to `wardline.yaml`. | auto-detect |
| `--path TEXT` | Project root to scan for overlays. | `.` |
| `-o, --output TEXT` | Output file path. | stdout |
| `--help` | Show help message and exit. | |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Resolved file written (or emitted to stdout). |
| 2 | Manifest not found, or output file cannot be written. |

**Output format:** JSON with `format_version: "0.2"`. Contains resolved tiers, module tiers, merged rule overrides with provenance, boundaries (with overlay scope and path), optional fields, governance signals from overlays, overlay discovery summary, scanner config snapshot, and manifest metadata.

**Examples:**

```bash
# Emit to stdout
wardline resolve --manifest wardline.yaml

# Write to file for use with wardline scan --resolved
wardline resolve --manifest wardline.yaml -o wardline.resolved.json

# Resolve from a monorepo subdirectory
wardline resolve --manifest wardline.yaml --path /repo/services/api -o resolved.json
```
