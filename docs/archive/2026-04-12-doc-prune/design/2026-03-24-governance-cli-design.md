# Governance CLI Design — WP 2.3a

**Date:** 2026-03-24
**Status:** Draft
**Scope:** `wardline manifest coherence`, `wardline fingerprint update/diff`, `wardline regime status/verify`, extended `wardline explain`
**Target release:** v0.3.0
**Dependencies:** None (ships independently of WP 2.1 L3 taint)
**Governance profile target:** Lite-complete + Assurance hooks (SARIF metadata)
**Spec references:** Wardline Framework Specification v0.2.0 — §9.2 (governance mechanisms), §9.3.1 (artefact classification), §14.3.2 (governance profiles). File: `docs/wardline/wardline-01-10-governance-model.md`

## Context

Wardline v0.2.0 ships with 9 rules, overlay system, exception register, and 184 corpus specimens. The governance CLI surfaces exist piecemeal — 8 coherence checks implemented as library functions but unwired to CLI, a basic `explain` command, fingerprint computation code, and exception lifecycle commands. v0.3.0 WP 2.3a wires these into a complete Lite governance surface.

This design was informed by a 7-reviewer panel (solution architect, systems thinker, Python engineer, quality engineer, security architect, static analysis specialist, IRAP assessor). Key panel findings incorporated:

- **Solution architect I2:** WP 2.3 dependency on WP 2.1 is partially false — split into 2.3a (no L3 dependency) and 2.3b (depends on L3).
- **IRAP C-01:** `regime status` must report governance profile, analysis level, exception health, ratification state, fingerprint coverage.
- **IRAP I-03:** Annotation fingerprint and AST fingerprint serve different governance purposes — scope `fingerprint update/diff` to annotation fingerprints only.
- **Security F3:** Annotation fingerprint baseline needed as CI gate for decorator tamper-evidence.
- **Security F5:** Regime status metrics gameable via decorator carpet-bombing — coverage reporting and PY-WL-008 provide countermeasures.
- **Systems thinker I4:** Add `taint_provenance` to findings — deferred to WP 2.3b (depends on L3).

## 1. `wardline manifest coherence`

### CLI Interface

```
wardline manifest coherence [--manifest PATH] [--path PATH] [--json] [--gate]
```

Runs all 8 coherence checks from `manifest/coherence.py` in sequence. Each check returns `list[CoherenceIssue]`. The command aggregates, formats, and optionally gates.

### Checks (existing implementations)

| Check | Function | Severity |
|-------|----------|----------|
| Orphaned annotations | `check_orphaned_annotations` | WARNING |
| Undeclared boundaries | `check_undeclared_boundaries` | WARNING |
| Tier distribution | `check_tier_distribution` | WARNING |
| Tier downgrades | `check_tier_downgrades` | ERROR |
| Tier upgrade without evidence | `check_tier_upgrade_without_evidence` | ERROR |
| Agent-originated exceptions | `check_agent_originated_exceptions` | WARNING |
| Expired exceptions | `check_expired_exceptions` | WARNING |
| First scan perimeter | `check_first_scan_perimeter` | WARNING |

### Output Formats

**Text mode:**
```
Coherence: 3 issues found (1 error, 2 warnings)

  ERROR  COHERENCE-TIER-DOWNGRADE  adapters/client.py::fetch_data
         Tier downgrade from ASSURED to EXTERNAL_RAW without boundary declaration

  WARN   COHERENCE-ORPHAN          utils/helpers.py::parse_config
         Decorator @validates_shape has no manifest boundary declaration

  WARN   COHERENCE-ORPHAN          utils/helpers.py::clean_input
         Decorator @external_boundary has no manifest boundary declaration
```

**JSON mode:** Array of objects with the following fields:

| JSON field | Source | Notes |
|------------|--------|-------|
| `check_name` | `CoherenceIssue.kind` | e.g., `"orphaned_annotation"` |
| `severity` | Derived from check table above | `"ERROR"` or `"WARNING"` |
| `file_path` | `CoherenceIssue.file_path` | Empty string for module-level issues |
| `function` | `CoherenceIssue.function` | Empty string for module-level issues |
| `message` | `CoherenceIssue.detail` | Human-readable description |
| `category` | Derived per §9.3.1 mapping | `"policy"` or `"enforcement"` |

The `category` field requires a mapping from `CoherenceIssue.kind` to policy/enforcement. Tier-related checks (`tier_downgrades`, `tier_upgrade_without_evidence`) are policy; annotation-related checks (`orphaned_annotations`, `undeclared_boundaries`) are enforcement. Add this mapping to `cli/coherence_cmd.py`.

### Gate Behavior

`--gate`: Exit 1 if any error-level issues. Exit 0 if warnings only or clean. This is the CI gate described in spec §9.2 — coherence must pass before enforcement findings are considered valid.

### Implementation

- New file: `cli/coherence_cmd.py` (~80 lines)
- Wired into `cli/manifest_cmds.py` as a subcommand of the existing `manifest` click group
- Thin wrapper — all check logic already exists

## 2. `wardline fingerprint update` / `wardline fingerprint diff`

### CLI Interface

```
wardline fingerprint update [--manifest PATH] [--path PATH] [--output PATH]
wardline fingerprint diff [--manifest PATH] [--path PATH] [--baseline PATH] [--json] [--gate]
```

### Fingerprint Scope: Annotation Surface Only

Scoped to **annotation fingerprints** (governance surface changes). AST fingerprints for exception staleness are already handled by `apply_exceptions` in the scan pipeline. These serve different governance purposes per spec §9.2:

- Annotation fingerprint: "has the governance surface changed?" (decorator additions, modifications, removals)
- AST fingerprint: "has the code under an exception changed?" (exception staleness detection)

### Baseline Format

`wardline.fingerprint.json` in the manifest directory:

```json
{
  "schema_version": "0.1",
  "generated_at": "2026-03-24T10:30:00Z",
  "python_version": "3.12.3",
  "coverage": {
    "annotated": 47,
    "total": 83,
    "ratio": 0.566,
    "tier1_annotated": 12,
    "tier1_total": 15,
    "tier1_unannotated": ["core/registry.py::_build_entry", "core/matrix.py::_severity_matrix_builder"]
  },
  "entries": [
    {
      "qualified_name": "adapters.client.fetch_data",
      "module": "adapters/client.py",
      "decorators": ["external_boundary", "validates_shape"],
      "annotation_hash": "a1b2c3d4e5f6g7h8",
      "tier_context": 4,
      "boundary_transition": "shape_validation",
      "artefact_class": "policy"
    }
  ]
}
```

### Hash Algorithm

Per the fingerprint hashing scheme spec (`docs/superpowers/specs/2026-03-23-fingerprint-hashing-scheme.md`):

```
annotation_fingerprint = sha256(
    "{python_version}|{qualname}|{sorted_canonical_decorator_names}|{sorted_decorator_attrs}"
)[:16]
```

**Hash inputs:** Python version (major.minor), qualname, sorted canonical decorator names from registry, sorted `_wardline_*` attributes as key=value pairs.

**NOT hash inputs:** `tier_context` and `boundary_transition` are stored in the `FingerprintEntry` alongside the hash for display context (diff output shows what changed) but do not participate in hash computation. File path is excluded intentionally — a function moved between files with identical annotations produces the same fingerprint.

Changes to function implementation that do not alter annotations produce no hash change (spec §9.2 requirement).

The `FingerprintEntry` dataclass in `manifest/models.py` has most required fields. **Model addition needed:** Add `artefact_class: str = ""` to `FingerprintEntry` to store the policy/enforcement classification per §9.3.1. This is derived at computation time from the decorator types (tier/boundary decorators → "policy", supplementary decorators → "enforcement") and stored in the baseline for diff output.

### `fingerprint update`

1. Walk all `.py` files (same discovery as scan engine)
2. Run `discover_annotations()` per file
3. Compute annotation hash per function
4. Resolve tier context from manifest module_tiers
5. Classify each entry as policy or enforcement per spec §9.3.1
6. Write baseline JSON with coverage report

### `fingerprint diff`

Compares current annotation surface against stored baseline. Three change categories per spec §9.2:

| Category | Meaning | Risk | Display |
|----------|---------|------|---------|
| **Added** | New function has decorators | Low | Green/info |
| **Modified** | Decorator set, tier, or boundary type changed | Medium | Yellow/warning |
| **Removed** | Annotated function lost decorators | High | Red/error |

Each change classified as **policy** or **enforcement** per spec §9.3.1:
- Policy: tier assignments, boundary declarations, provenance claims, optional-field declarations
- Enforcement: rule severity overrides, scanner config changes

Output presents them as distinct sections so reviewers can prioritize policy changes.

**Text output:**
```
Fingerprint diff: 4 changes (1 policy, 3 enforcement)

Policy changes:
  REMOVED  adapters/client.py::fetch_data
           Lost decorators: external_boundary, validates_shape
           Tier 1 module — PRIORITY REVIEW

Enforcement changes:
  ADDED    utils/new_module.py::process
           Decorators: validates_shape
  MODIFIED core/engine.py::scan_file
           Hash changed: a1b2 → c3d4 (decorator set changed)
  ADDED    core/engine.py::_scan_tree
           Decorators: integral_read

Coverage: 48/84 functions (57.1%) [was 47/83 (56.6%)]
  Tier 1: 12/15 (80.0%) [unchanged]
```

### Gate Behavior

`--gate`: Exit 1 if any **removed** annotations in Tier 1 modules. Exit 0 otherwise. Modified annotations in Tier 1 produce a warning in output but do not fail the gate — they remain on the enforcement surface, so the function is still governed. Removal is the higher-risk event because the function exits governance entirely (spec §9.2: "Annotation removal in Tier 1 modules MUST be flagged as a priority review item").

### Implementation

- Extends `scanner/fingerprint.py` with batch computation (~100 lines)
- New file: `cli/fingerprint_cmd.py` (~150 lines)
- Reads `FingerprintEntry` model from `manifest/models.py`
- Uses existing `discover_annotations()` pipeline for raw data

## 3. `wardline regime status` / `wardline regime verify`

### CLI Interface

```
wardline regime status [--manifest PATH] [--path PATH] [--json]
wardline regime verify [--manifest PATH] [--path PATH] [--json] [--gate]
```

### `regime status` — Read-Only Dashboard

Gathers governance health metrics from existing artifacts. No scan performed.

**Data sources:**
- Manifest (`wardline.yaml`) → governance profile, ratification metadata, analysis level, tier definitions
- Exception register (`wardline.exceptions.json`) → active/expired/stale counts, expedited ratio, agent-originated count, governance paths. If absent: all exception fields show 0/N/A.
- Fingerprint baseline (`wardline.fingerprint.json`) → staleness, coverage ratio, Tier 1 coverage. If absent: `Status: not present (run wardline fingerprint update)`.

**Text output:**
```
Wardline Regime Status
──────────────────────

Governance profile:    lite
Analysis level:        2
Manifest version:      0.2

Rules:                 9 active, 0 disabled
Coherence:             not run (use `wardline manifest coherence`)

Exceptions:
  Active:              3
  Expired:             1
  Stale fingerprint:   0
  Agent-originated:    1 (33.3%)
  Expedited ratio:     0.0% (threshold: 15.0%)
  Governance paths:    3 standard, 0 expedited

Fingerprint baseline:
  Status:              present (updated 2026-03-22)
  Coverage:            47/83 functions (56.6%)
  Tier 1 coverage:     12/15 (80.0%)

Manifest ratification:
  Last ratified:       2026-03-15
  Ratification age:    9 days (interval: 180 days)
  Overdue:             no
```

**JSON mode:** Same fields as structured object.

### `regime verify` — Active Checks

Runs `regime status` data collection plus active verification checks. The coherence check runs the 8 coherence functions from `manifest/coherence.py` inline — it does not depend on a cached result from a previous `wardline manifest coherence` run.

| Check | Pass Condition | Severity |
|-------|---------------|----------|
| Manifest loads | Parse succeeds | ERROR |
| Coherence checks pass | No error-level coherence issues | ERROR |
| No disabled UNCONDITIONAL rules | All UNCONDITIONAL rules active | ERROR |
| Exception register valid | Schema validates, no UNCONDITIONAL targets | ERROR |
| Expedited ratio below threshold | `expedited / total < manifest threshold` | WARNING |
| Fingerprint baseline exists | File present in manifest dir | WARNING |
| Fingerprint baseline fresh | Age < ratification interval | WARNING |
| No expired exceptions | All active exceptions within expiry | WARNING |
| Manifest ratification current | Age < declared interval (overdue when `age >= interval`) | WARNING |

**Exit codes (with `--gate`):** Exit 1 if any ERROR check fails. Exit 0 if only warnings or clean. Without `--gate`, always exits 0 (reporting mode).

### SARIF Metadata Additions

Added to `scanner/sarif.py` run-level properties on every scan:

| Field | Value | Purpose |
|-------|-------|---------|
| `wardline.analysisLevel` | Integer (1, 2, or 3) | Engine analysis depth |
| `wardline.manifestHash` | `sha256:...` (hex) | Binds findings to policy version |
| `wardline.scanTimestamp` | ISO 8601 UTC | Temporal binding |
| `wardline.commitRef` | Git HEAD hash or `null` | Codebase state binding |

`manifestHash` computation: SHA-256 of `wardline.yaml` content + sorted overlay file contents, concatenated with `\n---\n` separator. Deterministic regardless of filesystem traversal order.

### Implementation

- New file: `manifest/regime.py` (~100 lines) — metric collection logic
- New file: `cli/regime_cmd.py` (~200 lines) — two subcommands
- SARIF additions in `scanner/sarif.py` (~20 lines)

## 4. Extended `wardline explain`

### CLI Interface (extends existing)

```
wardline explain QUALNAME [--manifest PATH] [--path PATH] [--json]
```

Same single-function interface. Three new sections added to existing output.

### New Section: Exception Status

For each canonical rule, shows whether an active exception applies to this function at its current taint state:

```
Exceptions:
  PY-WL-001  EXC-2026-001 (active, expires 2026-06-15)
             Rationale: "Legacy adapter, migration scheduled for Q3"
             Reviewer: john@example.com
             Governance path: standard
             Recurrence: 0
  PY-WL-003  (no exception)
```

Implementation: Load exceptions via `load_exceptions()`, match by `(rule, taint_state, location)` key. Matching logic already exists in `scanner/exceptions.py`.

### New Section: Overlay Resolution

```
Overlay:
  Governed by: overlays/adapters/wardline.overlay.yaml
  Scope: adapters/
  Boundaries declared: 2 (shape_validation, semantic_validation)
  schema_default() status: governed (boundary match)
```

Or: `Overlay: none (module not covered by any overlay)`.

Implementation: Call `resolve_boundaries()` with manifest, filter by file path scope. Logic exists in `manifest/resolve.py`.

### New Section: Fingerprint State

```
Fingerprint:
  Annotation hash: a1b2c3d4e5f6g7h8
  Baseline match: yes (unchanged since 2026-03-22)
```

Or: `Baseline match: MODIFIED (decorators changed since baseline)` / `Baseline match: no baseline stored`.

Implementation: Compute current fingerprint, compare against `wardline.fingerprint.json` if present.

### JSON Mode

Returns complete explain result as structured object:

```json
{
  "qualname": "adapters.client.fetch_data",
  "file": "src/wardline/adapters/client.py",
  "taint_state": "EXTERNAL_RAW",
  "resolution": {
    "source": "decorator",
    "decorators": ["external_boundary"]
  },
  "module_default": "ASSURED",
  "unresolved_decorators": [],
  "rules": [
    {
      "rule_id": "PY-WL-001",
      "severity": "ERROR",
      "exceptionability": "STANDARD"
    }
  ],
  "exceptions": [
    {
      "rule": "PY-WL-001",
      "id": "EXC-2026-001",
      "status": "active",
      "expires": "2026-06-15",
      "governance_path": "standard",
      "recurrence_count": 0
    }
  ],
  "overlay": {
    "path": "overlays/adapters/wardline.overlay.yaml",
    "scope": "adapters/",
    "boundaries": 2,
    "schema_default_governed": true
  },
  "fingerprint": {
    "annotation_hash": "a1b2c3d4e5f6g7h8",
    "baseline_match": true
  }
}
```

### Implementation

Extends existing `cli/explain_cmd.py` (~80 lines of additions). No new files. The three new sections are additive reads from existing data structures.

**Multi-file match behavior:** Inherited from existing implementation (first match wins, `break` after first hit). `--path` narrows the search space. No change to this behavior in WP 2.3a.

### Deferred to WP 2.3b (depends on L3)

- L3 call-graph taint provenance chains
- `taintInferenceSource` field per finding
- `--all` batch mode for bulk evidence generation
- `--compare-levels 2,3` dual-run transition assurance

## 5. Cross-Cutting Concerns

### Error Handling

All commands follow existing CLI patterns (exit codes defined in `cli/scan.py`: `EXIT_CLEAN=0`, `EXIT_FINDINGS=1`, `EXIT_CONFIG_ERROR=2`, `EXIT_TOOL_ERROR=3`):

- Missing manifest: warn and continue with reduced output (explain already does this)
- Missing fingerprint baseline: report as "not present" in status, warn in diff
- Missing exception register: treat as empty (0 exceptions) — not an error
- Malformed JSON (manifest, exceptions, fingerprint): exit 2 (`EXIT_CONFIG_ERROR`) with `error:` message to stderr
- Permission errors: skip file, log warning, continue
- `fingerprint update` with no annotated functions: write baseline with empty `entries` array and coverage showing 0/N. Not an error — this is the first-run case for projects without decorators.
- `fingerprint diff` when baseline was generated on a different Python version: report all entries as "MODIFIED (Python version changed)" with a distinct message. The hash includes `python_version`, so version upgrades invalidate all fingerprints. Users must run `fingerprint update` after Python upgrades.

### Testing Strategy

- **Unit tests:** Each metric collection function in `manifest/regime.py` tested independently with fixture data
- **Integration tests:** Frozen test project under `tests/fixtures/governance/` with known manifest, exceptions, fingerprints, and source files. CLI commands run against fixture and assert exact output. Isolates governance tests from scanner evolution.
- **Negative tests:** Malformed manifest/exceptions JSON (assert exit 2), missing baseline (assert warning not error), `--gate` exit codes (assert exit 1 on error conditions for coherence, fingerprint, and regime verify)
- **Self-hosting:** `wardline regime verify --gate` added to CI as an informational job (not blocking initially)

### Effort Estimate

| Subsystem | New Files | Lines (est.) | Effort |
|-----------|-----------|-------------|--------|
| `manifest coherence` | `cli/coherence_cmd.py` | ~80 | XS |
| `fingerprint update/diff` | `cli/fingerprint_cmd.py` + extends `scanner/fingerprint.py` | ~250 | M |
| `regime status/verify` | `cli/regime_cmd.py` + `manifest/regime.py` + SARIF additions | ~320 | M |
| Extended `explain` | extends `cli/explain_cmd.py` | ~80 | S |
| Test fixtures | `tests/fixtures/governance/` + tests | ~300 | S |
| **Total** | | ~1030 | **L** |
