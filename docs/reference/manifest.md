# Manifest Field Reference

## Overview

`wardline.yaml` defines the trust topology for a project. It tells the scanner which
modules occupy which authority tier, where tier transitions happen, and what governance
policy applies to exceptions and rule findings. Every field in this file is either used
directly by the scanner or validated at manifest-load time.

The manifest is validated against the JSON Schema at
`src/wardline/manifest/schemas/wardline.schema.json`. Local boundary details live in
per-directory overlay files (`wardline.overlay.yaml`) that are validated against
`src/wardline/manifest/schemas/overlay.schema.json`.

---

## Top-Level Fields

### `$id`

**Type:** string
**Required:** no

The schema version URI for this manifest. Wardline uses this to route the file through
the correct validator. Always set this to the canonical schema URL for the version you
are targeting.

```yaml
$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"
```

---

### `governance_profile`

**Type:** string, one of `"lite"` or `"assurance"`
**Required:** no
**Default:** `"lite"`

Declares which governance profile the project operates under. The profile controls which
rules are mandatory, what audit trails are required, and how strictly exceptions are
scrutinised.

- `"lite"` — appropriate for open-source or early-stage projects. Fewer mandatory
  governance fields; the scanner emits warnings rather than hard errors for some
  governance gaps.
- `"assurance"` — appropriate for regulated or production systems. All governance fields
  are mandatory; the scanner treats governance gaps as errors.

```yaml
governance_profile: "lite"
```

---

### `metadata`

**Type:** object
**Required:** no

Organisational and governance metadata attached to this manifest. These fields do not
affect scanner behaviour directly — they feed audit trails and coherence reports.

#### `metadata.organisation`

**Type:** string
**Required:** no

The name of the organisation or project that owns this manifest.

```yaml
metadata:
  organisation: "acme-corp"
```

#### `metadata.ratified_by`

**Type:** object with `name` (string) and `role` (string)
**Required:** no

Records who ratified this manifest and in what capacity. Both sub-fields are required if
`ratified_by` is present.

```yaml
metadata:
  ratified_by:
    name: "Jane Smith"
    role: "Security Lead"
```

#### `metadata.ratification_date`

**Type:** string (ISO 8601 date, e.g. `"2026-03-27"`)
**Required:** no

The date on which this manifest was formally ratified. Used to enforce
`review_interval_days` and to flag stale manifests in coherence checks.

```yaml
metadata:
  ratification_date: "2026-03-27"
```

#### `metadata.review_interval_days`

**Type:** integer, minimum 1
**Required:** no

How many days may elapse between manifest reviews. Coherence checks will flag the
manifest as overdue for review once `ratification_date + review_interval_days` is in the
past.

```yaml
metadata:
  review_interval_days: 180
```

#### `metadata.temporal_separation`

**Type:** object
**Required:** no

Declares the project's posture on temporal separation — the requirement that the person
who authors a change is not the same person who approves it, or that approval is deferred
to a later retrospective. This field documents an explicit governance decision; omitting
it leaves the posture undeclared.

##### `metadata.temporal_separation.alternative`

**Type:** string, one of `"enforced"` or `"same-actor-with-retrospective"`
**Required:** yes (within `temporal_separation`)

- `"enforced"` — different-actor review is in place for all changes.
- `"same-actor-with-retrospective"` — the same person may author and approve, provided a
  retrospective review occurs within `retrospective_window_days`.

```yaml
metadata:
  temporal_separation:
    alternative: "same-actor-with-retrospective"
```

##### `metadata.temporal_separation.retrospective_window_days`

**Type:** integer, minimum 1
**Required:** no

The maximum number of days before a retrospective review must occur. Only meaningful when
`alternative` is `"same-actor-with-retrospective"`.

```yaml
metadata:
  temporal_separation:
    retrospective_window_days: 10
```

##### `metadata.temporal_separation.rationale`

**Type:** string
**Required:** no

Free-text justification for choosing the declared alternative. Recording a rationale here
is good practice even when the field is not enforced by the schema.

```yaml
metadata:
  temporal_separation:
    rationale: >
      Single-developer project. Same-actor approval permitted for enforcement
      artefact changes with mandatory retrospective review within 10 days.
```

---

### `tiers`

**Type:** array of objects
**Required:** no

Human-readable declarations that name the four authority tiers for this project. These
are documentary — they do not change the scanner's tier model, which is fixed at four
levels. They exist so that `wardline explain` and coherence reports can render
project-specific names and descriptions rather than bare tier numbers.

#### `tiers[].id`

**Type:** string
**Required:** yes

A short identifier for this tier. By convention this matches the corresponding
`TaintState` name (`"INTEGRAL"`, `"ASSURED"`, `"GUARDED"`, `"EXTERNAL_RAW"`), but any
unique string is accepted.

```yaml
tiers:
  - id: "INTEGRAL"
```

#### `tiers[].tier`

**Type:** integer, 1–4
**Required:** yes

The numeric tier level. Lower numbers indicate higher authority: Tier 1 is the most
trusted; Tier 4 is untrusted external input.

```yaml
tiers:
  - id: "INTEGRAL"
    tier: 1
```

#### `tiers[].description`

**Type:** string
**Required:** no

A sentence describing what this tier represents in the context of this project. Shown in
`wardline explain` output and audit reports.

```yaml
tiers:
  - id: "INTEGRAL"
    tier: 1
    description: "Authoritative internal data — enums, registries, base classes"
```

---

### `module_tiers`

**Type:** array of objects
**Required:** no

Maps source paths to taint defaults. The scanner uses these entries to assign an initial
taint state to every name defined in a module before propagating taint through the call
graph. Without a `module_tiers` entry, a module's taint defaults to whatever
`default_taint` is set to in `wardline.toml` (or `UNKNOWN_RAW` if unset).

Entries are matched prefix-first: a path of `"src/wardline/core"` covers all files under
that directory. A more specific path takes precedence over a less specific one.

#### `module_tiers[].path`

**Type:** string
**Required:** yes

A file path or directory path, relative to the project root. Directories match all files
beneath them.

```yaml
module_tiers:
  - path: "src/myapp/core"
```

#### `module_tiers[].default_taint`

**Type:** string, one of the eight canonical taint states
**Required:** yes

The taint state assigned to names defined in this path. Valid values are:

| Value | Tier | Meaning |
|---|---|---|
| `INTEGRAL` | 1 | Authoritative internal data — trusted completely |
| `ASSURED` | 2 | Validated data that has passed all required checks |
| `GUARDED` | 3 | Partially validated — shape-checked but not semantically verified |
| `UNKNOWN_ASSURED` | 3 | Provenance unclear; appears to be assured |
| `UNKNOWN_GUARDED` | 3 | Provenance unclear; appears to be guarded |
| `EXTERNAL_RAW` | 4 | Untrusted external input |
| `UNKNOWN_RAW` | 4 | Provenance unknown; treated as untrusted |
| `MIXED_RAW` | 4 | Combination of taints; absorbing element in the join lattice |

For most codebases: assign `INTEGRAL` to pure-internal definitions (enums, constants),
`ASSURED` to post-validation pipeline code, `GUARDED` to AST or partially-validated
processing code, and `EXTERNAL_RAW` to CLI entry points and file parsers.

```yaml
module_tiers:
  - path: "src/myapp/core"
    default_taint: "INTEGRAL"
  - path: "src/myapp/validators"
    default_taint: "ASSURED"
  - path: "src/myapp/cli"
    default_taint: "EXTERNAL_RAW"
```

---

### `dependency_taint`

**Type:** array of objects
**Required:** no

Declares the taint state of return values from third-party library functions. Without
this, the scanner cannot determine what taint state a call to, say, `requests.get`
produces, and will fall back to `UNKNOWN_RAW`. Use this table to tell the scanner
precisely how much to trust each external dependency.

#### `dependency_taint[].package`

**Type:** string
**Required:** yes

The package identifier, optionally including a version constraint (e.g.
`"requests>=2.28"`). Informational only — the scanner does not enforce version ranges.

```yaml
dependency_taint:
  - package: "requests"
```

#### `dependency_taint[].function`

**Type:** string
**Required:** yes

The fully-qualified function name as it would appear in a Python import path.

```yaml
dependency_taint:
  - function: "requests.get"
```

#### `dependency_taint[].returns_taint`

**Type:** string, one of the eight canonical taint states
**Required:** yes

The taint state the scanner assigns to the return value of this function.

```yaml
dependency_taint:
  - function: "requests.get"
    returns_taint: "EXTERNAL_RAW"
```

#### `dependency_taint[].rationale`

**Type:** string
**Required:** yes

A governance justification for this taint assignment. Required to ensure taint
declarations are reviewed and documented rather than silently applied.

```yaml
dependency_taint:
  - package: "requests"
    function: "requests.get"
    returns_taint: "EXTERNAL_RAW"
    rationale: "HTTP responses are untrusted external input; no validation performed by the library."
```

---

### `rules`

**Type:** object
**Required:** no

Overrides to the scanner's default severity matrix. Use this section to promote warnings
to errors, demote errors to warnings, or disable rules entirely for this project.

#### `rules.overrides`

**Type:** array of objects
**Required:** no

Each entry changes the effective severity of one rule ID.

##### `rules.overrides[].id`

**Type:** string
**Required:** yes

The rule ID to override. Must be a valid `RuleId` value (e.g. `"PY-WL-001"`). See
`src/wardline/core/severity.py` for the full list.

##### `rules.overrides[].severity`

**Type:** string, one of `"OFF"`, `"INFO"`, `"WARNING"`, `"ERROR"`, `"CRITICAL"`
**Required:** yes

The severity to assign to findings from this rule. Setting a rule to `"OFF"` suppresses
it entirely and emits a `GOVERNANCE-RULE-DISABLED` diagnostic finding.

```yaml
rules:
  overrides:
    - id: "PY-WL-003"
      severity: "WARNING"
    - id: "SCN-021"
      severity: "OFF"
```

---

### `delegation`

**Type:** object
**Required:** no

Controls which teams or directories have authority to grant exceptions to rule findings.
By default all exception grants require standard review. This section lets you delegate
relaxed-authority exception grants to specific paths — useful in monorepos where
individual teams own their own boundary governance.

#### `delegation.default_authority`

**Type:** string, one of `"NONE"`, `"RELAXED"`, `"STANDARD"`
**Required:** no
**Default:** `"RELAXED"`

The authority level granted to any path not matched by a specific grant.

- `"NONE"` — no path may grant exceptions by default; every exception requires an
  explicit grant entry.
- `"RELAXED"` — paths may grant exceptions for findings in the `RELAXED`
  exceptionability class without an explicit entry.
- `"STANDARD"` — paths may grant exceptions for findings in both `RELAXED` and
  `STANDARD` exceptionability classes.

```yaml
delegation:
  default_authority: "RELAXED"
```

#### `delegation.grants`

**Type:** array of objects
**Required:** no

Path-specific authority overrides. Each entry grants a named path the ability to approve
exceptions up to the specified authority level.

##### `delegation.grants[].path`

**Type:** string
**Required:** yes

A directory path (relative to project root) for which this grant applies.

##### `delegation.grants[].authority`

**Type:** string, one of `"NONE"`, `"RELAXED"`, `"STANDARD"`
**Required:** yes

The exception authority granted for this path.

```yaml
delegation:
  default_authority: "NONE"
  grants:
    - path: "src/myapp/payments"
      authority: "STANDARD"
    - path: "src/myapp/reporting"
      authority: "RELAXED"
```

---

### `overlay_paths`

**Type:** array of strings
**Required:** no

An allowlist of directories in which the scanner will look for `wardline.overlay.yaml`
files. Set to `["*"]` to allow overlays in any directory. If omitted, overlay discovery
is unrestricted.

This field exists to give security-conscious projects explicit control over which parts
of the codebase may declare local boundary overrides.

```yaml
overlay_paths:
  - "src/myapp/api"
  - "src/myapp/db"
```

---

### `max_exception_duration_days`

**Type:** integer, minimum 1
**Required:** no
**Default:** 365

The maximum number of days for which any exception may be granted. Exceptions with an
`expires` date further in the future than this value will be rejected at load time.

```yaml
max_exception_duration_days: 90
```

---

### `exception_age_limits`

**Type:** object
**Required:** no

Per-exceptionability-class maximum duration in days. Allows tighter limits for more
permissive exceptionability classes. Valid keys are `"STANDARD"`, `"RELAXED"`, and
`"TRANSPARENT"`. Each value is an integer (minimum 1).

```yaml
exception_age_limits:
  STANDARD: 180
  RELAXED: 30
  TRANSPARENT: 365
```

---

## Overlay Fields

Overlays are per-directory files named `wardline.overlay.yaml`. They declare boundary
functions and local rule tuning for the directory they govern. The scanner merges overlays
into the root manifest at scan time; all boundary declarations in all overlays are
available to every rule.

An overlay may only narrow the root manifest's tier assignments — it cannot promote a
module to a more-trusted tier than the root manifest declares.

---

### `$id` (overlay)

**Type:** string
**Required:** no

Schema version URI. Set to the overlay schema URL.

```yaml
$id: "https://wardline.dev/schemas/1.0/overlay.schema.json"
```

---

### `overlay_for`

**Type:** string
**Required:** yes

The directory path this overlay governs, relative to the project root. The scanner uses
this to scope the overlay's boundary declarations.

```yaml
overlay_for: "src/myapp/api"
```

---

### `boundaries`

**Type:** array of objects
**Required:** no

Declares the boundary functions in this directory — functions where a tier transition
occurs. The scanner uses these declarations to verify that data crossing a tier boundary
is handled by a properly-annotated boundary function.

#### `boundaries[].function`

**Type:** string
**Required:** yes

The fully-qualified name of the boundary function (e.g. `"myapp.api.parse_request"`).

```yaml
boundaries:
  - function: "myapp.api.parse_request"
```

#### `boundaries[].transition`

**Type:** string, one of `"shape_validation"`, `"semantic_validation"`, `"combined_validation"`, `"construction"`, `"restoration"`
**Required:** yes

Declares what kind of boundary crossing this function performs:

- `"shape_validation"` — the function checks structural conformance (e.g. schema
  validation, type checking) without verifying business semantics.
- `"semantic_validation"` — the function verifies business meaning and rules.
- `"combined_validation"` — the function performs both structural and semantic checks
  in a single step.
- `"construction"` — the function constructs a trusted object from validated components
  (e.g. a factory or builder).
- `"restoration"` — the function restores a trusted tier state from a lower-tier
  representation (e.g. deserialising a stored record back to a domain object).

```yaml
boundaries:
  - function: "myapp.api.parse_request"
    transition: "shape_validation"
```

#### `boundaries[].from_tier`

**Type:** integer, 1–4
**Required:** no

The tier of the incoming data before this boundary function processes it.

```yaml
boundaries:
  - function: "myapp.api.parse_request"
    transition: "shape_validation"
    from_tier: 4
    to_tier: 3
```

#### `boundaries[].to_tier`

**Type:** integer, 1–4
**Required:** no

The tier of the data after this boundary function has validated or transformed it.

#### `boundaries[].restored_tier`

**Type:** integer, 1–4
**Required:** no

For `"restoration"` transitions, the tier that data is restored to. Separate from
`to_tier` because restoration claims a specific prior trust level that must be
justified.

```yaml
boundaries:
  - function: "myapp.db.load_record"
    transition: "restoration"
    from_tier: 4
    restored_tier: 2
```

#### `boundaries[].provenance`

**Type:** object
**Required:** no

Describes what evidence backs the boundary function's trust claim. At least one of the
sub-fields should be set to document what kind of validation is occurring.

##### `boundaries[].provenance.structural`

**Type:** boolean
**Required:** no

`true` if the function performs structural (schema/shape) validation.

##### `boundaries[].provenance.semantic`

**Type:** boolean
**Required:** no

`true` if the function performs semantic (business-rule) validation.

##### `boundaries[].provenance.integrity`

**Type:** string or null, one of `"checksum"`, `"signature"`, `"hmac"`, or `null`
**Required:** no

The integrity mechanism used, if any. Use `"signature"` for cryptographic signatures,
`"hmac"` for message authentication codes, `"checksum"` for weaker hash-based checks.

##### `boundaries[].provenance.institutional`

**Type:** string or null
**Required:** no

A reference to an institutional control (e.g. a policy document identifier or approval
record) that backs the trust claim.

```yaml
boundaries:
  - function: "myapp.api.parse_request"
    transition: "combined_validation"
    from_tier: 4
    to_tier: 2
    provenance:
      structural: true
      semantic: true
      integrity: null
      institutional: "ISM-CTRL-0042"
```

#### `boundaries[].validation_scope`

**Type:** object
**Required:** no

Documents the data contracts that this boundary function is responsible for validating.
This links the boundary declaration to formal contract definitions for audit purposes.

##### `boundaries[].validation_scope.contracts`

**Type:** array of objects
**Required:** yes (within `validation_scope`)

Each entry names a contract and declares the data tier and direction it applies to.

###### `validation_scope.contracts[].name`

**Type:** string
**Required:** yes

The name of the contract, matching a contract defined in `contract_bindings`.

###### `validation_scope.contracts[].data_tier`

**Type:** integer, 1–4
**Required:** yes

The tier of data that this contract governs.

###### `validation_scope.contracts[].direction`

**Type:** string, one of `"inbound"` or `"outbound"`
**Required:** yes

Whether this contract applies to data entering (`"inbound"`) or leaving (`"outbound"`)
the boundary.

###### `validation_scope.contracts[].description`

**Type:** string
**Required:** no

A human-readable description of what this contract validates.

###### `validation_scope.contracts[].preconditions`

**Type:** string
**Required:** no

Conditions that must hold before this contract applies.

```yaml
boundaries:
  - function: "myapp.api.parse_request"
    transition: "combined_validation"
    from_tier: 4
    to_tier: 2
    validation_scope:
      description: "Validates inbound HTTP request payload against the API schema"
      contracts:
        - name: "api.request.body"
          data_tier: 4
          direction: "inbound"
          description: "Raw request body from client"
```

---

### `rule_overrides` (overlay)

**Type:** array of objects
**Required:** no

Directory-scoped severity overrides. Works identically to `rules.overrides` in the root
manifest but applies only to files within `overlay_for`. Useful when a specific
subsystem has legitimate reasons to suppress or elevate a rule for its own code.

Each entry requires `id` (rule ID string) and `severity` (one of `"OFF"`, `"INFO"`,
`"WARNING"`, `"ERROR"`, `"CRITICAL"`).

```yaml
rule_overrides:
  - id: "PY-WL-004"
    severity: "WARNING"
```

---

### `optional_fields` (overlay)

**Type:** array of objects
**Required:** no

Declares fields that are optional-by-contract for this directory. When a wardline rule
would normally flag a missing annotation field as a violation, an entry here records that
the absence has been explicitly approved and documents why.

#### `optional_fields[].field`

**Type:** string
**Required:** yes

The annotation field name that is permitted to be absent.

#### `optional_fields[].approved_default`

**Type:** any
**Required:** yes

The value that should be assumed when the field is absent. This makes the contract
explicit: the scanner and reviewers know exactly what behaviour the absent field implies.

#### `optional_fields[].rationale`

**Type:** string
**Required:** yes

The governance justification for permitting this field to be absent.

```yaml
optional_fields:
  - field: "audit_tier"
    approved_default: 3
    rationale: "All functions in this package operate at Tier 3 by design; repeating the annotation would add noise without adding information."
```

---

### `contract_bindings` (overlay)

**Type:** array of objects
**Required:** no

Maps named contracts referenced in `validation_scope.contracts` to the specific functions
that implement them. This lets the scanner verify that every declared contract has a
corresponding implementation.

#### `contract_bindings[].contract`

**Type:** string
**Required:** yes

The contract name, matching a `name` value in a `validation_scope.contracts` entry.

#### `contract_bindings[].functions`

**Type:** array of strings
**Required:** yes

The fully-qualified names of the functions that implement this contract.

```yaml
contract_bindings:
  - contract: "api.request.body"
    functions:
      - "myapp.api.parse_request"
      - "myapp.api.parse_multipart_request"
```
