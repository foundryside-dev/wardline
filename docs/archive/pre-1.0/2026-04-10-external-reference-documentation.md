# External Reference Documentation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the "missing middle" documentation layer for external Wardline users — 6 lookup references (Layer 1) and 6 explanation guides (Layer 2) that bridge the gap between the getting-started guide and the 500KB normative spec.

**Architecture:** Each document extracts and reformats data that already exists in the codebase (severity matrix in `src/wardline/core/matrix.py`, rule descriptions in `src/wardline/scanner/sarif.py`, taint states in `src/wardline/core/taints.py`, etc.). Layer 1 docs are single-screen scannable tables. Layer 2 docs are 2-5 minute reads with a "answer first, explanation below" structure. No content duplicates the spec — all docs link to the relevant spec section for normative definitions. No code changes required.

**Tech Stack:** Markdown (GitHub-flavored), compatible with MkDocs/GitHub Pages rendering.

**Cross-linking convention:** Every Layer 1 doc links down to relevant Layer 2 guides and Layer 3 spec sections. Every Layer 2 doc links up to Layer 1 lookup tables. Use relative links throughout (`../reference/rules.md`, `../spec/wardline-01-08-pattern-rules.md`).

---

## File Map

### New files (12)

| File | Layer | Purpose |
|------|-------|---------|
| `docs/reference/rules.md` | 1 | Rule quick-reference table |
| `docs/reference/severity-matrix.md` | 1 | 9x8 severity matrix cheat sheet |
| `docs/reference/taint-states.md` | 1 | Taint state definitions + join lattice |
| `docs/reference/glossary.md` | 1 | Term definitions A-Z |
| `docs/reference/sarif-format.md` | 1 | Annotated SARIF output sample |
| `docs/reference/error-messages.md` | 1 | Common errors + fixes table |
| `docs/guides/adoption.md` | 2 | Onboarding existing projects |
| `docs/guides/ci-integration.md` | 2 | GitHub Actions, GitLab CI examples |
| `docs/guides/governance.md` | 2 | Exception workflow walkthrough |
| `docs/guides/analysis-levels.md` | 2 | L1/L2/L3 comparison + decision guide |
| `docs/guides/profiles.md` | 2 | Lite vs Assurance decision guide |
| `docs/guides/troubleshooting.md` | 2 | FAQ + diagnostic guide |

### Modified files (2)

| File | Change |
|------|--------|
| `docs/README.md` | Add `reference/` and `guides/` to directory table and reading order |
| `docs/getting-started.md` | Add "Next Steps" cross-links to new reference docs |

---

## Task 1: Severity Matrix Cheat Sheet

The highest-value document. A single-screen 9x8 grid showing severity + exceptionability for every (rule, taint_state) combination.

**Files:**
- Create: `docs/reference/severity-matrix.md`

**Source data:** `src/wardline/core/matrix.py:94-125` — the `_MATRIX_DATA` list contains all 72 cells.

- [ ] **Step 1: Create the severity matrix document**

```markdown
# Severity Matrix

Quick-reference for the 72-cell severity matrix. Each cell shows
**severity / exceptionability** for a (rule, taint state) pair.

**Legend:** E = ERROR, W = WARNING, S = SUPPRESS | U = UNCONDITIONAL,
St = STANDARD, R = RELAXED, T = TRANSPARENT

| Rule | INTEGRAL | ASSURED | GUARDED | EXTERNAL_RAW | UNKNOWN_RAW | UNKNOWN_GUARDED | UNKNOWN_ASSURED | MIXED_RAW |
|------|----------|---------|---------|--------------|-------------|-----------------|-----------------|-----------|
| [PY-WL-001](rules.md#py-wl-001) | E/U | E/St | W/R | S/T | S/T | W/R | E/St | S/T |
| [PY-WL-002](rules.md#py-wl-002) | E/U | E/St | W/R | W/R | W/R | W/R | E/St | W/St |
| [PY-WL-003](rules.md#py-wl-003) | E/U | E/U | E/St | S/T | S/T | E/St | E/St | S/T |
| [PY-WL-004](rules.md#py-wl-004) | E/U | E/St | W/St | W/R | E/St | W/St | W/St | E/St |
| [PY-WL-005](rules.md#py-wl-005) | E/U | E/St | W/St | W/R | E/St | W/St | W/St | E/St |
| [PY-WL-006](rules.md#py-wl-006) | E/U | E/U | E/St | E/St | E/St | E/St | E/St | E/St |
| [PY-WL-007](rules.md#py-wl-007) | E/St | W/R | W/R | S/T | S/T | W/R | W/R | W/St |
| [PY-WL-008](rules.md#py-wl-008) | E/U | E/U | E/U | E/U | E/U | E/U | E/U | E/U |
| [PY-WL-009](rules.md#py-wl-009) | E/U | E/U | E/U | E/U | E/U | E/U | E/U | E/U |

## Reading the Matrix

**Columns** are taint states ordered from highest trust (INTEGRAL, Tier 1) to
lowest (EXTERNAL_RAW, Tier 4), plus four UNKNOWN/MIXED states.

**Rows** are the nine canonical pattern-detection rules.

**Severity** scales with consequence, not pattern frequency:
- **ERROR** at Tier 1-2 means the pattern undermines the guarantees that tier
  exists to provide.
- **WARNING** at Tier 3 means flag for review — partially validated data may
  legitimately use defensive access.
- **SUPPRESS** at Tier 4 means the pattern is expected here — `.get("timeout", 30)`
  in CLI parsing is fine.

**Exceptionability** controls what happens when you request an exception:
- **UNCONDITIONAL** — cannot be excepted. Fix the code.
- **STANDARD** — exception requires reviewer approval via governance workflow.
- **RELAXED** — exception available with less scrutiny.
- **TRANSPARENT** — auto-suppressed. No action needed.

## Notable Patterns

**PY-WL-008 and PY-WL-009 are ERROR/UNCONDITIONAL everywhere.** A declared
validation boundary with no rejection path, or semantic validation without prior
shape validation, is a structural defect regardless of taint context.

**PY-WL-006 is ERROR everywhere (varies only in exceptionability).** Audit-critical
writes inside broad exception handlers are dangerous at every tier — the only
question is whether you can request an exception.

**T4 (EXTERNAL_RAW) is mostly SUPPRESS or WARNING.** This is the developer-freedom
zone. Patterns that are dangerous in high-trust code are expected at the boundary.

## Further Reading

- [Rule Quick Reference](rules.md) — what each rule detects
- [Taint State Reference](taint-states.md) — what each column means
- [Governance Walkthrough](../guides/governance.md) — how exceptions work
- [Spec §7.3: Severity Matrix](../spec/wardline-01-08-pattern-rules.md) — normative definition
```

Write this content to `docs/reference/severity-matrix.md`.

- [ ] **Step 2: Verify the matrix values match source code**

Cross-check every cell against `src/wardline/core/matrix.py:94-125`. The matrix data in the document must exactly match the `_MATRIX_DATA` list. Read the source file and compare row by row.

- [ ] **Step 3: Commit**

```bash
git add docs/reference/severity-matrix.md
git commit -m "docs: add severity matrix cheat sheet (72-cell quick reference)"
```

---

## Task 2: Rule Quick Reference

Single-page lookup table for all 12 rules (9 canonical + SCN-021, SCN-022, SUP-001).

**Files:**
- Create: `docs/reference/rules.md`

**Source data:** `src/wardline/scanner/sarif.py:33-76` — `_RULE_SHORT_DESCRIPTIONS` dict. Rule implementation files in `src/wardline/scanner/rules/py_wl_*.py` for detection patterns.

- [ ] **Step 1: Create the rule quick reference document**

```markdown
# Rule Quick Reference

Quick lookup for all Wardline rules. For severity at each taint state, see the
[Severity Matrix](severity-matrix.md).

## Canonical Rules (Pattern Detection)

These rules detect suspicious code patterns. Severity depends on the taint state
of the enclosing function — see the [Severity Matrix](severity-matrix.md).

| Rule | Name | Detects | Fix |
|------|------|---------|-----|
| PY-WL-001 | Dict key access with fallback default | `.get(key, default)`, `.pop(key, default)`, `.setdefault(key, default)`, `defaultdict(factory)` | Remove the default; handle `None`/`KeyError` explicitly, or route through `@validates_shape` first |
| PY-WL-002 | Attribute access with fallback default | Three-argument `getattr(obj, name, default)` | Use two-argument `getattr()` (raises `AttributeError`) or validate the object first |
| PY-WL-003 | Existence-checking as structural gate | `"key" in dict`, `hasattr()`, `.get(key) is None`, `match/case` with `MatchMapping`/`MatchClass` | Validate structure with `@validates_shape` instead of probing at the use site |
| PY-WL-004 | Broad exception handler | `except:`, `except Exception:`, `except BaseException:` | Catch specific exceptions |
| PY-WL-005 | Silent exception handler | `except: pass`, `except: ...`, `except: continue/break` | Log, re-raise, or handle the exception explicitly |
| PY-WL-006 | Audit-critical write in broad handler | `@integrity_critical` function body inside `except Exception/BaseException/bare` | Narrow the except clause, or move the audit write outside the handler |
| PY-WL-007 | Runtime type-checking on internal data | `isinstance()`, `type() ==`, `type() is` on internal data | Use static typing; if dispatch is needed, use `@singledispatch` or protocol |
| PY-WL-008 | Validation boundary with no rejection path | `@validates_shape`/`@validates_semantic`/`@validates_external`/`@restoration_boundary` with no `raise` or guarded early return | Add a rejection path — the boundary function must refuse invalid input |
| PY-WL-009 | Semantic validation without prior shape validation | `@validates_semantic` boundary with no prior `@validates_shape` in the call chain | Add a shape validation step before semantic validation, or use `@validates_external` for combined validation |

## Supplementary Rules

These rules enforce decorator contracts and structural consistency. They are not
in the severity matrix — they have fixed severity based on the violation type.

| Rule | Name | Detects |
|------|------|---------|
| SCN-021 | Contradictory decorator combination | Incompatible decorator pairs (e.g., `@fail_open` + `@fail_closed`, `@fail_open` + `@integral_writer`) |
| SCN-022 | Field-completeness verification | `@all_fields_mapped` function that does not access all fields from the source class |
| SUP-001 | Supplementary decorator contract violation | 14+ local AST-checkable contracts (e.g., `@parse_at_init` outside `__init__`, `@deterministic` with banned calls, `@test_only` imported in production) |

## Diagnostic Signals

These are not violations — they are informational findings that appear in SARIF
output to aid governance and debugging.

| Rule | Name | Meaning |
|------|------|---------|
| PY-WL-001-GOVERNED-DEFAULT | Governed default value | `schema_default()` used with an overlay boundary — governed, SUPPRESS severity |
| PY-WL-001-UNGOVERNED-DEFAULT | Ungoverned schema_default() | `schema_default()` used without an overlay boundary — diagnostic warning |
| WARDLINE-UNRESOLVED-DECORATOR | Unresolved decorator | A wardline decorator could not be resolved to a registry entry |
| WARDLINE-DYNAMIC-IMPORT | Dynamic import | Dynamic import of a wardline-decorated module detected |
| TOOL-ERROR | Internal tool error | A rule or scanner component raised an unhandled exception |

## Governance Findings

These findings monitor governance health — exception staleness, taint drift,
configuration concerns. Emitted as informational findings in SARIF output.

| Rule | Name |
|------|------|
| GOVERNANCE-STALE-EXCEPTION | Exception's AST fingerprint no longer matches the code |
| GOVERNANCE-RECURRING-EXCEPTION | Exception has been renewed multiple times |
| GOVERNANCE-NO-EXPIRY-EXCEPTION | Exception has no expiration date |
| GOVERNANCE-EXCEPTION-TAINT-DRIFT | Exception taint state no longer matches function's effective taint |
| GOVERNANCE-EXCEPTION-SEVERITY-DRIFT | Exception severity_at_grant differs from current severity |
| GOVERNANCE-EXCEPTION-LEVEL-STALE | Exception granted at lower analysis level than active scan |
| GOVERNANCE-RULE-DISABLED | Rule disabled by configuration |
| GOVERNANCE-TAINT-DEGRADED | File scanned with empty fallback taint map |
| GOVERNANCE-TAINT-CONFLICT | Conflicting taint decorators — first wins |
| GOVERNANCE-RESTORATION-OVERCLAIM | Restoration claims tier unsupported by evidence |
| GOVERNANCE-MODULE-TIERS-BLANKET | Module default covers >80% of functions with no decorators |
| GOVERNANCE-MODULE-TIERS-UNDECORATED | High-trust module with zero decorator usage |
| GOVERNANCE-PERMISSIVE-DISTRIBUTION | Permissive distribution mode active |
| GOVERNANCE-REGISTRY-MISMATCH-ALLOWED | Registry mismatch allowed via flag |
| GOVERNANCE-CUSTOM-KNOWN-VALIDATOR | Custom known_validators entry |
| GOVERNANCE-FILE-SKIPPED | File skipped due to parse failure |
| GOVERNANCE-WEAK-ELIMINATION-PATH | Exception elimination_path is a placeholder |
| GOVERNANCE-UNKNOWN-PROVENANCE | Unknown agent provenance on exception |
| GOVERNANCE-BATCH-REFRESH | Batch exception refresh performed |
| L3-LOW-RESOLUTION | L3 call-graph based on >70% unresolved edges |
| L3-CONVERGENCE-BOUND | L3 propagation hit iteration limit |

## Further Reading

- [Severity Matrix](severity-matrix.md) — severity and exceptionability per rule per taint state
- [Decorator Vocabulary](decorators.md) — the annotations rules enforce
- [Spec §7: Pattern Rules](../spec/wardline-01-08-pattern-rules.md) — normative definitions
- [Semantic Equivalents](../spec/semantic-equivalents/) — evasion variant catalogs per rule
```

Write this content to `docs/reference/rules.md`.

- [ ] **Step 2: Verify rule descriptions match sarif.py**

Cross-check the rule names and descriptions against `src/wardline/scanner/sarif.py:33-76` (`_RULE_SHORT_DESCRIPTIONS`). Ensure every `RuleId` member from `src/wardline/core/severity.py:29-81` is represented. The document should cover all 12 analysis rules + all pseudo-rule-IDs.

- [ ] **Step 3: Commit**

```bash
git add docs/reference/rules.md
git commit -m "docs: add rule quick reference (all 12 rules + diagnostics + governance)"
```

---

## Task 3: Taint State Reference

Definitions for all 8 canonical taint states, the tier mapping, and the join lattice.

**Files:**
- Create: `docs/reference/taint-states.md`

**Source data:** `src/wardline/core/taints.py` (TaintState enum, `_JOIN_TABLE`, `taint_join()`), `src/wardline/core/tiers.py` (tier mapping).

- [ ] **Step 1: Create the taint state reference document**

```markdown
# Taint State Reference

Wardline tracks eight canonical taint states. Each represents a level of
validation confidence for data flowing through your code.

## The Four Tier-Aligned States

These map directly to the four authority tiers:

| Taint State | Tier | Trust Level | Meaning | Example |
|-------------|------|-------------|---------|---------|
| `INTEGRAL` | 1 | Highest | Audit-critical, authoritative data | DB writes, compliance logs, cryptographic material |
| `ASSURED` | 2 | High | Structurally and semantically validated | Business logic operating on checked inputs |
| `GUARDED` | 3 | Medium | Shape-validated but not semantically verified | Data that passed structural checks but not business rules |
| `EXTERNAL_RAW` | 4 | Lowest | Untrusted external input | API payloads, file reads, CLI arguments, environment variables |

**Data flows freely downward** (Tier 1 to Tier 4). Flowing **upward** requires
an explicit validation boundary (`@validates_shape`, `@validates_semantic`, or
`@validates_external`).

## The Four Unknown/Mixed States

These arise when the scanner cannot determine the taint state with full
confidence:

| Taint State | Meaning | How It Arises |
|-------------|---------|---------------|
| `UNKNOWN_RAW` | Unknown validation, weakest assumption | No decorator, no manifest entry, no call-graph evidence |
| `UNKNOWN_GUARDED` | Unknown but appears partially validated | Some structural evidence but not from a declared boundary |
| `UNKNOWN_ASSURED` | Unknown but appears validated | Some semantic evidence but not from a declared boundary |
| `MIXED_RAW` | Incompatible taint states joined | Two data paths with different taint states merge (e.g., `INTEGRAL` + `EXTERNAL_RAW`) |

**`MIXED_RAW` is the absorbing element** — once data becomes `MIXED_RAW`, it
cannot be promoted without passing through a validation boundary.

## Join Lattice

When two data flows merge (e.g., at a ternary expression or function that
receives arguments with different taint states), the scanner computes their
**join** — the least-trusted common state.

**Self-joins:** `join(X, X) = X` (identity)

**MIXED_RAW absorbs:** `join(MIXED_RAW, X) = MIXED_RAW` for all X

**Within the UNKNOWN family:**

| A | B | join(A, B) |
|---|---|------------|
| `UNKNOWN_ASSURED` | `UNKNOWN_RAW` | `UNKNOWN_RAW` |
| `UNKNOWN_GUARDED` | `UNKNOWN_RAW` | `UNKNOWN_RAW` |
| `UNKNOWN_ASSURED` | `UNKNOWN_GUARDED` | `UNKNOWN_GUARDED` |

**All other cross-family pairs:** `join(A, B) = MIXED_RAW`

This means `join(INTEGRAL, EXTERNAL_RAW) = MIXED_RAW` — mixing trusted and
untrusted data without a validation boundary produces the least-trusted state.

## How Taint States Are Assigned

Taint assignment happens in three layers, controlled by the analysis level:

| Level | Method | Precision |
|-------|--------|-----------|
| L1 | Decorators + manifest `module_tiers` | Function-level (all values in function body share one taint) |
| L2 | L1 + per-variable tracking | Variable-level (different variables can have different taints) |
| L3 | L2 + transitive call-graph inference | Interprocedural (follows taint through function call chains) |

See [Analysis Levels Guide](../guides/analysis-levels.md) for choosing the right level.

## Further Reading

- [Severity Matrix](severity-matrix.md) — how taint state affects rule severity
- [Decorator Vocabulary](decorators.md) — decorators that set or promote taint
- [Spec §5: Authority Tier Model](../spec/wardline-01-05-authority-tier-model.md) — normative definitions
```

Write this content to `docs/reference/taint-states.md`.

- [ ] **Step 2: Verify join table matches source code**

Cross-check the join table against `src/wardline/core/taints.py:34-41` (`_JOIN_TABLE`). Ensure all three non-trivial pairs are listed and the results are correct.

- [ ] **Step 3: Commit**

```bash
git add docs/reference/taint-states.md
git commit -m "docs: add taint state reference (8 states + join lattice)"
```

---

## Task 4: Glossary

Alphabetical term definitions. Focus on terms that a new user encounters in
scanner output, CLI help, or the getting-started guide.

**Files:**
- Create: `docs/reference/glossary.md`

**Source data:** Terms are drawn from across the codebase — severity.py, taints.py, matrix.py, sarif.py, manifest models, decorator registry, spec lite.

- [ ] **Step 1: Create the glossary document**

```markdown
# Glossary

Terms you will encounter in Wardline output, documentation, and configuration.

| Term | Definition |
|------|-----------|
| **Analysis level** | Depth of taint tracking: L1 (function-level), L2 (variable-level), L3 (call-graph). Higher levels find more violations but scan slower. See [Analysis Levels](../guides/analysis-levels.md). |
| **Assured** | Taint state for Tier 2 data — structurally and semantically validated. See [Taint States](taint-states.md). |
| **Authority tier** | One of four trust levels (1=highest to 4=lowest) assigned to code and data. See [Taint States](taint-states.md). |
| **Boundary** | A function decorated with `@validates_shape`, `@validates_semantic`, `@validates_external`, or `@restoration_boundary` that promotes data from a lower tier to a higher tier. |
| **Coherence check** | Cross-reference validation run by `wardline coherence` — verifies manifest, decorators, exception registry, and fingerprint baseline are mutually consistent. |
| **Control law** | Enforcement state of the scanner: `normal` (full enforcement), `alternate` (degraded but running), or `direct` (manifest unavailable, minimal enforcement). |
| **Decorator** | A Python `@decorator` from `wardline.decorators` that annotates a function with trust-boundary metadata. See [Decorator Vocabulary](decorators.md). |
| **Exception** | A recorded decision to accept a finding that would otherwise block the scan. Managed via `wardline exception`. See [Governance](../guides/governance.md). |
| **Exceptionability** | Whether a finding can be excepted: UNCONDITIONAL (no), STANDARD (with approval), RELAXED (easily), TRANSPARENT (auto-suppressed). See [Severity Matrix](severity-matrix.md). |
| **External_raw** | Taint state for Tier 4 data — untrusted external input. See [Taint States](taint-states.md). |
| **Finding** | A single violation or diagnostic emitted by the scanner. Contains rule ID, severity, location, taint state, and exceptionability. |
| **Fingerprint** | AST-based hash of a function's structure. Used to detect when code changes under an existing exception. |
| **Governance profile** | Project-level policy setting: `lite` (fewer mandatory fields) or `assurance` (all governance fields mandatory). See [Profiles](../guides/profiles.md). |
| **Guarded** | Taint state for Tier 3 data — shape-validated but not semantically verified. See [Taint States](taint-states.md). |
| **Integral** | Taint state for Tier 1 data — audit-critical, highest trust. See [Taint States](taint-states.md). |
| **Join** | The operation that combines two taint states when data flows merge. Produces the least-trusted common state. See [Taint States](taint-states.md#join-lattice). |
| **Manifest** | The `wardline.yaml` file that declares which modules belong to which tier, governance profile, and rule overrides. See [Manifest Reference](manifest.md). |
| **Mixed_raw** | Taint state produced when incompatible taint states merge — the absorbing element of the join lattice. See [Taint States](taint-states.md). |
| **Overlay** | A per-directory `wardline.overlay.yaml` file that extends the root manifest with local boundary declarations and rule overrides. See [Manifest Reference](manifest.md). |
| **Rejection path** | A branch in a validation boundary function that raises an exception or returns early on invalid input. Required by PY-WL-008. |
| **Restoration boundary** | A `@restoration_boundary` decorator that re-promotes data to a higher tier with explicit evidence (structural, semantic, integrity, institutional). |
| **SARIF** | Static Analysis Results Interchange Format (v2.1.0). Wardline's output format for CI/CD integration. See [SARIF Format](sarif-format.md). |
| **Severity** | How a finding affects the scan exit code: ERROR (blocks, exit 1), WARNING (informational), SUPPRESS (hidden unless verbose). See [Severity Matrix](severity-matrix.md). |
| **Taint state** | The validation confidence level carried by data: one of 8 canonical states. See [Taint States](taint-states.md). |
| **Tier** | Shorthand for authority tier (1-4). See **Authority tier**. |
| **Transition** | A declared taint-state change on a boundary decorator, e.g., `(EXTERNAL_RAW, GUARDED)` on `@validates_shape`. |
| **Unknown_raw / Unknown_guarded / Unknown_assured** | Taint states assigned when the scanner lacks sufficient evidence to determine full validation status. See [Taint States](taint-states.md). |
| **Validation boundary** | See **Boundary**. |

## Further Reading

- [Getting Started](../getting-started.md) — 15-minute introduction
- [Wardline Lite](../spec/wardline-lite.md) — 5-question practical overview
```

Write this content to `docs/reference/glossary.md`.

- [ ] **Step 2: Commit**

```bash
git add docs/reference/glossary.md
git commit -m "docs: add glossary (30+ terms for external users)"
```

---

## Task 5: SARIF Format Guide

Annotated SARIF output sample showing every wardline-specific property.

**Files:**
- Create: `docs/reference/sarif-format.md`

**Source data:** `src/wardline/scanner/sarif.py:212-298` (result properties, run properties).

- [ ] **Step 1: Create the SARIF format guide**

```markdown
# SARIF Output Format

Wardline emits [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
output. This document describes the Wardline-specific properties embedded in the
standard SARIF envelope.

## Quick Start

```bash
# Write SARIF to file
wardline scan src/ -o findings.sarif

# Pipe to jq for quick inspection
wardline scan src/ | jq '.runs[0].results | length'
```

## Annotated Example

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "wardline",
        "version": "1.0.0",
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
    "results": [{
      "ruleId": "PY-WL-001",
      "level": "error",
      "message": {
        "text": "dict.get() with fallback default in INTEGRAL code..."
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "src/myapp/core/auth.py"
          },
          "region": {
            "startLine": 42,
            "startColumn": 12,
            "snippet": {
              "text": "user = cache.get(user_id, default_user)"
            }
          }
        }
      }],
      "properties": {
        "wardline.rule": "PY-WL-001",
        "wardline.taintState": "INTEGRAL",
        "wardline.severity": "ERROR",
        "wardline.exceptionability": "UNCONDITIONAL",
        "wardline.analysisLevel": 1,
        "wardline.enclosingTier": 1,
        "wardline.annotationGroups": [2],
        "wardline.excepted": false,
        "wardline.dataSource": "decorator",
        "wardline.qualname": "myapp.core.auth.lookup_user",
        "wardline.sourceSnippet": "cache.get(user_id, default_user)"
      }
    }],
    "properties": {
      "wardline.governanceProfile": "lite",
      "wardline.controlLaw": "normal",
      "wardline.controlLawDegradations": [],
      "wardline.analysisLevel": 1,
      "wardline.manifestHash": "sha256:abc123...",
      "wardline.unknownRawCount": 3,
      "wardline.unresolvedDecoratorCount": 0,
      "wardline.filesWithDegradedTaint": 0,
      "wardline.activeExceptionCount": 2,
      "wardline.staleExceptionCount": 0,
      "wardline.expeditedExceptionRatio": 0.0
    }
  }]
}
```

## Result Properties

Every finding includes these properties under `result.properties`:

| Property | Type | Description |
|----------|------|-------------|
| `wardline.rule` | string | Rule ID (e.g., `"PY-WL-001"`) |
| `wardline.taintState` | string \| null | Taint state of the enclosing function. Null for governance findings. |
| `wardline.severity` | string | `"ERROR"`, `"WARNING"`, or `"SUPPRESS"` |
| `wardline.exceptionability` | string | `"UNCONDITIONAL"`, `"STANDARD"`, `"RELAXED"`, or `"TRANSPARENT"` |
| `wardline.analysisLevel` | int | Analysis level that produced this finding (1, 2, or 3) |
| `wardline.enclosingTier` | int \| null | Authority tier (1-4). Null for governance findings. |
| `wardline.annotationGroups` | int[] | Decorator group numbers present on the function |
| `wardline.excepted` | bool | Whether an active exception covers this finding |
| `wardline.dataSource` | string | How taint was determined (`"decorator"`, `"manifest"`, `"callgraph"`) |
| `wardline.qualname` | string? | Fully qualified name of the enclosing function |
| `wardline.sourceSnippet` | string? | Matched source text |
| `wardline.exceptionId` | string? | Exception ID if `wardline.excepted` is true |
| `wardline.exceptionExpires` | string? | ISO 8601 expiry date of the covering exception |
| `wardline.retroactiveScan` | bool? | Present and true for retrospective scan findings |

## Run Properties

Run-level metadata under `run.properties`:

| Property | Type | Description |
|----------|------|-------------|
| `wardline.governanceProfile` | string | `"lite"` or `"assurance"` |
| `wardline.controlLaw` | string | `"normal"`, `"alternate"`, or `"direct"` |
| `wardline.controlLawDegradations` | string[] | Active degradation conditions |
| `wardline.analysisLevel` | int | Scan analysis level (1, 2, or 3) |
| `wardline.manifestHash` | string? | SHA-256 of the resolved manifest |
| `wardline.unknownRawCount` | int | Findings on `UNKNOWN_RAW` taint state |
| `wardline.unresolvedDecoratorCount` | int | Unresolvable decorator references |
| `wardline.filesWithDegradedTaint` | int | Files scanned with empty taint map |
| `wardline.activeExceptionCount` | int | Currently active exceptions |
| `wardline.staleExceptionCount` | int | Exceptions with mismatched fingerprints |
| `wardline.expeditedExceptionRatio` | float | Fraction of exceptions on expedited path |

## SARIF Level Mapping

Wardline severities map to SARIF levels as follows:

| Wardline Severity | SARIF Level | CI Impact |
|-------------------|-------------|-----------|
| `ERROR` | `error` | Exit code 1 (blocks) |
| `WARNING` | `warning` | Exit code 0 (informational) |
| `SUPPRESS` | `note` | Exit code 0 (hidden unless verbose) |

## Further Reading

- [CLI Reference](cli.md) — scan command options and exit codes
- [Rule Quick Reference](rules.md) — what each ruleId means
- [CI Integration Guide](../guides/ci-integration.md) — consuming SARIF in pipelines
```

Write this content to `docs/reference/sarif-format.md`.

- [ ] **Step 2: Verify property names match sarif.py**

Cross-check all property names against `src/wardline/scanner/sarif.py:215-234` (result properties) and `src/wardline/scanner/sarif.py:276-299` (SarifReport fields). Every `wardline.*` property in the document must exist in the source.

- [ ] **Step 3: Commit**

```bash
git add docs/reference/sarif-format.md
git commit -m "docs: add SARIF format guide (annotated output + property reference)"
```

---

## Task 6: Error Messages Reference

Common error messages, their causes, and fixes. Organized by exit code.

**Files:**
- Create: `docs/reference/error-messages.md`

**Source data:** CLI exit codes from `docs/reference/cli.md:40-48`, error messages from scanner, manifest loader, and coherence checker source files.

- [ ] **Step 1: Create the error messages reference**

```markdown
# Error Messages Reference

Common errors from `wardline scan` and other commands, organized by exit code.

## Exit Code 2: Configuration Error

These errors prevent the scan from running. Fix the configuration before retrying.

| Error | Cause | Fix |
|-------|-------|-----|
| `Manifest not found` | No `wardline.yaml` in the project root or `--manifest` path | Create `wardline.yaml` — see [Getting Started](../getting-started.md#creating-a-manifest) |
| `Invalid manifest` | `wardline.yaml` fails JSON Schema validation | Run `wardline manifest validate` for detailed errors |
| `Registry mismatch` | Exception registry references rules/taint states not in current matrix | Run `wardline exception refresh` to update stale entries, or pass `--allow-registry-mismatch` |
| `Overlay policy error` | An overlay file violates governance constraints (e.g., overriding a locked rule) | Check `wardline.overlay.yaml` against manifest governance policy |
| `Resolved file stale` | `wardline.resolved.json` hash does not match current manifest | Re-run `wardline resolve` to regenerate, or pass `--allow-stale-resolved` |
| `Output file cannot be written` | `-o` path is not writable | Check file permissions and directory existence |

## Exit Code 1: Findings Present

The scan completed but found violations.

| Situation | Meaning | Fix |
|-----------|---------|-----|
| Unexcepted ERROR findings | At least one finding has severity ERROR and no covering exception | Fix the code (see [Rule Reference](rules.md)), or grant an exception via `wardline exception add` |
| `--max-unknown-raw-percent` exceeded | Too many `UNKNOWN_RAW` findings relative to files scanned | Add `module_tiers` entries or decorators to reduce unknowns |
| `--strict-governance` with GOVERNANCE findings | Governance findings treated as blocking | Address governance concerns or remove `--strict-governance` |

## Exit Code 3: Internal Tool Error

The scanner itself failed. This is a bug.

| Situation | Action |
|-----------|--------|
| `TOOL-ERROR` finding in output | Report the issue with the SARIF output attached |
| Stack trace on stderr | Report with `--debug` output |

## Common Warnings (Non-Blocking)

These appear in SARIF output but do not affect the exit code:

| Warning | Meaning | Action |
|---------|---------|--------|
| `GOVERNANCE-STALE-EXCEPTION` | An exception's AST fingerprint no longer matches the code | Run `wardline fingerprint update` then `wardline exception refresh` |
| `GOVERNANCE-TAINT-DEGRADED` | File scanned with empty taint map (no decorators or manifest entries) | Add `module_tiers` entry for the file's package |
| `GOVERNANCE-MODULE-TIERS-BLANKET` | Module default covers >80% of functions with no decorator evidence | Add decorators to key functions, or accept the blanket assignment |
| `L3-LOW-RESOLUTION` | L3 call graph has >70% unresolved edges | Add decorators to called functions, or accept lower-precision results |
| `WARDLINE-UNRESOLVED-DECORATOR` | A `@wardline.*` decorator could not be matched to the registry | Check the decorator name for typos; ensure `wardline` is installed |

## Coherence Check Errors

From `wardline coherence`:

| Check | Meaning | Fix |
|-------|---------|-----|
| `Orphaned exception` | Exception references a function that no longer exists | Remove the exception via `wardline exception expire` |
| `Fingerprint drift` | Code changed but fingerprint baseline not updated | Run `wardline fingerprint update` |
| `Decorator/manifest conflict` | Function has both a taint decorator and a conflicting `module_tiers` entry | Remove one — decorators take precedence over `module_tiers` |

## Further Reading

- [CLI Reference](cli.md) — full command options and exit codes
- [Governance Walkthrough](../guides/governance.md) — managing exceptions
- [Troubleshooting](../guides/troubleshooting.md) — diagnostic decision tree
```

Write this content to `docs/reference/error-messages.md`.

- [ ] **Step 2: Commit**

```bash
git add docs/reference/error-messages.md
git commit -m "docs: add error messages reference (exit codes, common errors, fixes)"
```

---

## Task 7: Adoption Guide

Step-by-step guide for onboarding an existing Python codebase onto Wardline.

**Files:**
- Create: `docs/guides/adoption.md`

- [ ] **Step 1: Create the adoption guide**

```markdown
# Adopting Wardline in an Existing Project

This guide walks you through adding Wardline to a codebase that already has code.
It assumes you have read [Getting Started](../getting-started.md) and understand
the basic concepts (tiers, taint states, decorators).

## Overview

Adoption is incremental. You do not need to annotate every function on day one.
The recommended sequence:

1. Install and create a manifest
2. Run a baseline scan
3. Triage findings — fix, except, or defer
4. Add decorators to key boundaries
5. Wire into CI
6. Iterate: reduce unknowns, increase analysis level

## Step 1: Install and Create a Manifest

```bash
pip install wardline
```

Create a minimal `wardline.yaml` at your project root:

```yaml
$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"

module_tiers:
  - path: "src/myapp/"
    default_taint: "UNKNOWN_RAW"

metadata:
  organisation: "My Company"
```

Starting with `UNKNOWN_RAW` is honest — you are declaring that no validation
assumptions exist yet. The scanner will report findings against this baseline,
and you will promote modules as you add decorators.

Validate the manifest:

```bash
wardline manifest validate
```

## Step 2: Run a Baseline Scan

```bash
wardline scan src/myapp/ -o baseline.sarif
```

Expect many findings. This is normal. The baseline tells you where your
boundaries are missing.

Review the summary:

```bash
# Count findings by rule
cat baseline.sarif | jq '[.runs[0].results[].ruleId] | group_by(.) | map({rule: .[0], count: length})'
```

## Step 3: Triage Findings

For each finding, decide:

- **Fix**: Change the code to satisfy the rule. This is the right choice for
  real violations.
- **Except**: Grant an exception for findings that are intentional or deferred.
  Use `wardline exception add`.
- **Suppress via module_tiers**: Promote a module's default taint (e.g., from
  `UNKNOWN_RAW` to `GUARDED`) if you are confident the module's code is at
  that trust level.

Start with the highest-severity findings (ERROR at INTEGRAL/ASSURED) — these
represent the most significant trust violations.

## Step 4: Add Decorators to Key Boundaries

Identify your trust boundaries — the functions where external data enters and
where validation happens. Decorate them:

```python
from wardline.decorators import external_boundary, validates_shape, integrity_critical

@external_boundary
def receive_api_request(request):
    ...

@validates_shape
def parse_request(raw):
    if "required_field" not in raw:
        raise ValueError("missing required_field")
    ...

@integrity_critical
def write_audit_log(validated_data):
    ...
```

After adding decorators, promote the module in your manifest:

```yaml
module_tiers:
  - path: "src/myapp/adapters/"
    default_taint: "EXTERNAL_RAW"
  - path: "src/myapp/core/"
    default_taint: "ASSURED"
  - path: "src/myapp/audit/"
    default_taint: "INTEGRAL"
```

Re-scan and compare:

```bash
wardline scan src/myapp/ -o after-decorators.sarif
```

## Step 5: Wire into CI

See [CI Integration Guide](ci-integration.md) for detailed examples.

Quick GitHub Actions setup:

```yaml
- name: Wardline Scan
  run: |
    pip install wardline
    wardline scan src/ --verification-mode
```

## Step 6: Iterate

- **Reduce unknowns**: Add `module_tiers` entries and decorators until
  `UNKNOWN_RAW` findings are near zero.
- **Increase analysis level**: Move from L1 to L2 or L3 as your annotation
  coverage improves. See [Analysis Levels](analysis-levels.md).
- **Choose governance profile**: Once decorators are in place, consider moving
  from `lite` to `assurance`. See [Profiles](profiles.md).

## Common Mistakes

| Mistake | Why It's Wrong | Fix |
|---------|---------------|-----|
| Setting everything to `INTEGRAL` | Triggers ERROR on every pattern rule | Start with `UNKNOWN_RAW` and promote as you add decorators |
| Excepting everything | Defeats the purpose; exceptions accumulate governance debt | Only except findings you have reviewed and accepted |
| Skipping `@validates_shape` | Data flows from T4 to T2 without structural validation | Add shape validation before semantic validation |
| One big `module_tiers` entry | Blanket assignment triggers `GOVERNANCE-MODULE-TIERS-BLANKET` | Use per-package entries with appropriate taint levels |

## Further Reading

- [Getting Started](../getting-started.md) — 15-minute introduction
- [Rule Quick Reference](../reference/rules.md) — what each finding means
- [Severity Matrix](../reference/severity-matrix.md) — severity per rule per taint
- [Governance Walkthrough](governance.md) — managing exceptions
```

Write this content to `docs/guides/adoption.md`.

- [ ] **Step 2: Commit**

```bash
git add docs/guides/adoption.md
git commit -m "docs: add adoption guide for existing projects"
```

---

## Task 8: CI Integration Guide

Concrete CI pipeline examples for GitHub Actions and GitLab CI.

**Files:**
- Create: `docs/guides/ci-integration.md`

**Source data:** Exit codes from `docs/reference/cli.md:40-48`, SARIF upload patterns from GitHub documentation.

- [ ] **Step 1: Create the CI integration guide**

```markdown
# CI Integration Guide

Wardline integrates into CI pipelines via its exit codes and SARIF output.

## Exit Code Reference

| Code | Meaning | CI Action |
|------|---------|-----------|
| 0 | No gate-blocking findings | Pass |
| 1 | ERROR-severity findings present | Fail the build |
| 2 | Configuration error | Fail the build (fix config) |
| 3 | Internal tool error | Fail the build (report bug) |

## GitHub Actions

### Basic: Fail on Findings

```yaml
name: Wardline
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install wardline
      - run: wardline scan src/ --verification-mode
```

### With SARIF Upload (GitHub Code Scanning)

```yaml
name: Wardline
on: [pull_request, push]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install wardline
      - name: Run Wardline
        run: wardline scan src/ --verification-mode -o wardline.sarif
        continue-on-error: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: wardline.sarif
        if: always()
```

This uploads findings to the **Security** tab in your repository, where they
appear as code scanning alerts with inline annotations on pull requests.

### With Coverage Threshold

```yaml
      - name: Run Wardline
        run: |
          wardline scan src/ \
            --verification-mode \
            --max-unknown-raw-percent 5.0 \
            -o wardline.sarif
```

This fails the build if more than 5% of scanned files have `UNKNOWN_RAW` taint —
a proxy for annotation coverage.

### Changed Files Only

```yaml
      - name: Run Wardline (changed files)
        run: |
          wardline scan src/ \
            --changed-only \
            --verification-mode
```

Scans only files changed in the current commit or PR. Useful for incremental
adoption — existing violations do not block new PRs.

## GitLab CI

```yaml
wardline:
  stage: test
  image: python:3.12
  script:
    - pip install wardline
    - wardline scan src/ --verification-mode -o wardline.sarif
  artifacts:
    reports:
      sast: wardline.sarif
    when: always
```

GitLab ingests the SARIF file as a SAST report, displaying findings in the
merge request security widget.

## Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: wardline
        name: wardline scan
        entry: wardline scan
        language: python
        types: [python]
        pass_filenames: false
```

## Tips

- **Use `--verification-mode`** in CI to get deterministic output (no timestamps).
  This makes SARIF output diffable and cacheable.
- **Start with `continue-on-error: true`** during adoption so you can upload
  SARIF without blocking builds, then remove it once findings are triaged.
- **Gate on ERROR only** — WARNING and SUPPRESS findings are non-blocking by
  default. Use `--strict-governance` only when you want governance findings to
  also block.

## Further Reading

- [CLI Reference](../reference/cli.md) — all scan options
- [SARIF Format](../reference/sarif-format.md) — understanding the output
- [Adoption Guide](adoption.md) — incremental adoption strategy
```

Write this content to `docs/guides/ci-integration.md`.

- [ ] **Step 2: Commit**

```bash
git add docs/guides/ci-integration.md
git commit -m "docs: add CI integration guide (GitHub Actions, GitLab CI, pre-commit)"
```

---

## Task 9: Governance Walkthrough

Narrative walkthrough of the exception lifecycle.

**Files:**
- Create: `docs/guides/governance.md`

**Source data:** `docs/reference/cli.md` (exception subcommands), `src/wardline/manifest/models.py` (ExceptionEntry), `docs/spec/wardline-01-10-governance-model.md`.

- [ ] **Step 1: Create the governance walkthrough**

```markdown
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
       │
       ▼
  wardline exception add    ← declare the exception
       │
       ▼
  wardline exception grant  ← reviewer approves
       │
       ▼
  Exception active          ← finding is covered, build passes
       │
       ├── Code changes → fingerprint mismatch → GOVERNANCE-STALE-EXCEPTION
       │
       ├── Taint changes → GOVERNANCE-EXCEPTION-TAINT-DRIFT
       │
       └── Expiry date reached → exception inactive → finding blocks again
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
- [Spec §9: Governance Model](../spec/wardline-01-10-governance-model.md) — normative definition
```

Write this content to `docs/guides/governance.md`.

- [ ] **Step 2: Commit**

```bash
git add docs/guides/governance.md
git commit -m "docs: add governance walkthrough (exception lifecycle)"
```

---

## Task 10: Analysis Levels Guide

Comparison of L1/L2/L3 with a decision guide.

**Files:**
- Create: `docs/guides/analysis-levels.md`

**Source data:** `src/wardline/manifest/models.py` (analysis_level field), spec §7.6, L3 design doc.

- [ ] **Step 1: Create the analysis levels guide**

```markdown
# Analysis Levels Guide

Wardline scans at three analysis levels. Higher levels find more violations but
scan slower and require more annotation coverage to be effective.

## Quick Comparison

| | L1 (Default) | L2 | L3 |
|---|---|---|---|
| **Taint granularity** | Function-level | Variable-level | Interprocedural |
| **What it tracks** | One taint per function body | Different taint per variable | Taint through call chains |
| **Speed** | Fast | Moderate | Slowest |
| **False negatives** | Highest (multiplicative) | Medium | Lowest |
| **False positives** | Lowest | Low | Low |
| **Annotation needs** | Minimal | Moderate | Comprehensive |
| **Best for** | Initial adoption, fast CI | Growing projects | High-assurance systems |

## L1: Function-Level Taint

Every value inside a function body gets the function's taint state. If a function
is decorated with `@integrity_critical`, every variable in that function is
treated as `INTEGRAL`.

**Strengths:**
- Fast — single pass, no data-flow analysis
- Works with minimal decorators

**Weaknesses:**
- Cannot distinguish tainted and untainted variables within the same function
- Two-hop heuristic: undecorated function calls are treated as pass-through,
  which can miss violations through longer call chains
- These approximations compound multiplicatively — both the function-level
  approximation and the two-hop heuristic apply at the same time

**Example false negative at L1:**
```python
@integrity_critical
def process(user_input, db_record):
    # L1 treats both as INTEGRAL — misses the risk from user_input
    result = user_input["name"]  # Actually EXTERNAL_RAW!
    db.write(result)
```

## L2: Variable-Level Taint

Tracks taint per variable within a function. Different variables can carry
different taint states.

**Strengths:**
- Catches the L1 false negative above — `user_input` and `db_record` get
  different taints
- Still reasonably fast

**Weaknesses:**
- No transitive call-graph inference — if taint flows through a chain of
  undecorated helper functions, L2 may not follow it

## L3: Callgraph-Level Taint

Full interprocedural analysis. The scanner builds a call graph, computes
strongly-connected components (SCCs), and runs fixed-point taint propagation.

**Strengths:**
- Catches violations through arbitrary call chains
- Two-hop rejection delegation — follows rejection paths through function calls
- Most accurate analysis level

**Weaknesses:**
- Slowest — requires full call-graph construction
- Needs good annotation coverage to resolve call edges
- May hit convergence bounds on large codebases (`L3-CONVERGENCE-BOUND`)
- Low-resolution warning when >70% of call edges are unresolved
  (`L3-LOW-RESOLUTION`)

## Choosing a Level

| Situation | Recommended Level |
|-----------|-------------------|
| Just installed wardline, few decorators | L1 |
| Moderate decorator coverage, want fewer false negatives | L2 |
| High decorator coverage, regulated codebase, need maximum precision | L3 |
| CI on every PR (speed matters) | L1 or L2 |
| Nightly full scan (thoroughness matters) | L3 |

A common pattern: **L1 in PR checks, L3 in nightly scans.**

## Configuration

In `wardline.toml`:

```toml
[wardline]
analysis_level = 2
```

Or via CLI:

```bash
wardline scan src/ --analysis-level 3
```

## Further Reading

- [Taint State Reference](../reference/taint-states.md) — what taint states mean
- [Severity Matrix](../reference/severity-matrix.md) — how taint affects severity
- [Adoption Guide](adoption.md) — incremental adoption strategy
```

Write this content to `docs/guides/analysis-levels.md`.

- [ ] **Step 2: Commit**

```bash
git add docs/guides/analysis-levels.md
git commit -m "docs: add analysis levels guide (L1/L2/L3 comparison)"
```

---

## Task 11: Profiles Guide

Decision guide for lite vs assurance governance profiles.

**Files:**
- Create: `docs/guides/profiles.md`

**Source data:** `src/wardline/manifest/models.py:228-240` (governance_profile), `docs/reference/manifest.md:35-48`.

- [ ] **Step 1: Create the profiles guide**

```markdown
# Governance Profiles: Lite vs Assurance

Wardline supports two governance profiles that control how strictly findings
and exceptions are enforced.

## Quick Comparison

| | Lite (default) | Assurance |
|---|---|---|
| **Target** | Open-source, startups, early-stage | Regulated, production, compliance-critical |
| **Governance gaps** | Emit warnings | Emit errors (block build) |
| **Coherence failures** | Manual gating | Auto-gate (build fails) |
| **Exception fields** | Recommended | All mandatory |
| **Temporal separation** | Alternatives allowed | Must be enforced |
| **Typical adoption stage** | Initial rollout, growing teams | Mature annotation coverage |

## When to Use Lite

Use `lite` when:

- You are adopting Wardline for the first time
- Your decorator coverage is still growing
- You want findings to inform but not block development
- Your team is learning the trust-tier model

Lite is the default. You do not need to set it explicitly.

```yaml
# wardline.yaml — lite is the default
governance_profile: "lite"
```

## When to Use Assurance

Use `assurance` when:

- Your codebase has comprehensive decorator coverage
- You operate under regulatory or compliance requirements
- You want governance gaps to block the build, not just warn
- You are ready for strict exception management

```yaml
# wardline.yaml
governance_profile: "assurance"
```

## What Changes with Assurance

### Coherence failures auto-gate

In `lite`, a coherence failure (e.g., orphaned exception, fingerprint drift)
produces a warning. In `assurance`, it produces an error and fails the build.

### All exception fields are mandatory

In `lite`, fields like `elimination_path` and `expires` are recommended. In
`assurance`, they are required — `wardline exception add` will reject entries
without them.

### Temporal separation must be enforced

Temporal separation is a governance mechanism that ensures policy changes and
enforcement changes do not happen in the same commit. In `lite`, alternatives
to temporal separation are allowed. In `assurance`, it must be enforced.

## Migration Path

Moving from `lite` to `assurance`:

1. Run `wardline coherence` and fix all findings
2. Ensure all exceptions have `expires` and `elimination_path`
3. Set `governance_profile: "assurance"` in `wardline.yaml`
4. Run `wardline scan` — any new governance errors must be resolved

This is a one-way ratchet in practice — going back to `lite` from `assurance`
weakens governance guarantees and should be treated as a deliberate decision.

## Further Reading

- [Manifest Reference](../reference/manifest.md#governance_profile) — configuration field
- [Governance Walkthrough](governance.md) — exception management
- [Adoption Guide](adoption.md) — incremental rollout strategy
- [Spec §9: Governance Model](../spec/wardline-01-10-governance-model.md) — normative definition
```

Write this content to `docs/guides/profiles.md`.

- [ ] **Step 2: Commit**

```bash
git add docs/guides/profiles.md
git commit -m "docs: add governance profiles guide (lite vs assurance)"
```

---

## Task 12: Troubleshooting FAQ

Diagnostic decision tree for common problems.

**Files:**
- Create: `docs/guides/troubleshooting.md`

- [ ] **Step 1: Create the troubleshooting guide**

```markdown
# Troubleshooting

Common questions and diagnostic steps when working with Wardline.

## "Why is my function getting UNKNOWN_RAW taint?"

The scanner assigns `UNKNOWN_RAW` when it has no evidence for a function's taint
state. Check:

1. **Is the function's module in `module_tiers`?** If not, add it:
   ```yaml
   module_tiers:
     - path: "src/myapp/services/"
       default_taint: "ASSURED"
   ```

2. **Does the function have a decorator?** Decorators override `module_tiers`.
   Add `@external_boundary`, `@validates_shape`, etc. as appropriate.

3. **At L3: Are callers decorated?** L3 propagates taint through call chains,
   but unresolved call edges default to `UNKNOWN_RAW`.

Use `wardline explain <qualname>` to see the taint resolution path:

```bash
wardline explain myapp.services.user.get_user
```

## "Why does the same rule give ERROR in one file and SUPPRESS in another?"

Severity depends on **taint state**, not the file. A function in an `INTEGRAL`
module gets ERROR; the same pattern in an `EXTERNAL_RAW` module gets SUPPRESS.

Check the function's taint state:

```bash
wardline explain myapp.core.auth.lookup_user
```

Then look up the rule + taint state in the [Severity Matrix](../reference/severity-matrix.md).

## "The scan is slow at L3"

L3 builds a full call graph. Reduce scan time by:

- **Adding decorators**: Resolved call edges are cheaper than unresolved ones
- **Using L1/L2 in CI**: Reserve L3 for nightly scans
- **Scanning a subset**: `wardline scan src/myapp/core/` instead of `src/`

## "I have a finding on code I can't change"

Use an exception:

```bash
wardline exception add \
  --rule PY-WL-004 \
  --location "src/vendor/legacy.py::handle_error" \
  --taint-state GUARDED \
  --rationale "Third-party code, cannot modify" \
  --elimination-path "Replace vendor library" \
  --expires 2026-12-31
```

See [Governance Walkthrough](governance.md) for the full process.

## "Scan exits with code 2 but I don't see an error"

Exit code 2 is a configuration error. Run with `--debug` for details:

```bash
wardline scan src/ --debug 2>debug.log
```

Common causes:
- Missing `wardline.yaml` — see [Getting Started](../getting-started.md#creating-a-manifest)
- Stale `wardline.resolved.json` — re-run `wardline resolve`
- Invalid overlay file — check `wardline.overlay.yaml` syntax

See [Error Messages Reference](../reference/error-messages.md) for a full list.

## "My exception stopped working after a code change"

When code changes, the AST fingerprint changes, and the exception becomes stale.
The scanner emits `GOVERNANCE-STALE-EXCEPTION`.

Fix:

```bash
# Update fingerprints to match current code
wardline fingerprint update

# Refresh exceptions against updated fingerprints
wardline exception refresh
```

## "How do I see what the scanner thinks about a function?"

```bash
wardline explain myapp.core.auth.lookup_user
```

This shows:
- The function's effective taint state
- How that taint was determined (decorator, manifest, callgraph)
- Which rules apply and their severity
- Whether any exceptions cover it

## "I added a decorator but the finding didn't go away"

Check:
1. **Correct decorator?** `@validates_shape` promotes to GUARDED, not ASSURED.
   If the caller expects ASSURED, you need `@validates_semantic` too.
2. **Rejection path present?** PY-WL-008 fires if the boundary function has
   no `raise` or guarded early return.
3. **Right transition?** The decorator's transition must match the data flow.
   `@validates_shape` expects `EXTERNAL_RAW` input.
4. **Re-scanned?** Scan results are not cached — re-run `wardline scan`.

## Further Reading

- [Error Messages Reference](../reference/error-messages.md) — error lookup table
- [Rule Quick Reference](../reference/rules.md) — what each rule means
- [CLI Reference](../reference/cli.md) — command options
```

Write this content to `docs/guides/troubleshooting.md`.

- [ ] **Step 2: Commit**

```bash
git add docs/guides/troubleshooting.md
git commit -m "docs: add troubleshooting FAQ (diagnostic decision trees)"
```

---

## Task 13: Update docs/README.md and Getting Started Cross-Links

Wire the new documents into the existing navigation.

**Files:**
- Modify: `docs/README.md`
- Modify: `docs/getting-started.md:299-307`

- [ ] **Step 1: Update docs/README.md**

Add two new rows to the directory table and update the reading order. The existing content at `docs/README.md:6-11` has the directory table. Add:

```markdown
| [reference/](reference/) | Quick-reference lookups: rules, severity matrix, taint states, SARIF format, glossary | Living reference |
| [guides/](guides/) | Task-oriented guides: adoption, CI, governance, analysis levels, profiles, troubleshooting | Living reference |
```

Update the reading order at `docs/README.md:14-18` to insert between items 1 and 2:

```markdown
1. **New to Wardline?** Start with [spec/wardline-lite.md](spec/wardline-lite.md) for a 5-question overview, then [getting-started.md](getting-started.md) for a hands-on quickstart.
2. **Looking something up?** The [reference/](reference/) directory has quick-reference tables for rules, severity matrix, taint states, decorators, manifest fields, SARIF format, and error messages.
3. **Adopting or integrating?** The [guides/](guides/) directory covers adoption, CI integration, governance, analysis levels, and troubleshooting.
4. **Building or reviewing?** The [spec/](spec/) directory contains the full normative specification.
5. **Contributing?** Check [plans/](plans/) for the current milestone roadmap.
6. **Auditing?** The [audits/](audits/) directory contains conformance audits.
```

- [ ] **Step 2: Update getting-started.md Next Steps section**

Replace the "Next Steps" section at `docs/getting-started.md:299-307` with:

```markdown
## Next Steps

- **Quick lookups:** [Rule Quick Reference](reference/rules.md) and [Severity Matrix](reference/severity-matrix.md)
- **Understanding taint:** [Taint State Reference](reference/taint-states.md) and [Glossary](reference/glossary.md)
- **Adopting at scale:** [Adoption Guide](guides/adoption.md)
- **CI integration:** [CI Integration Guide](guides/ci-integration.md)
- **Managing exceptions:** [Governance Walkthrough](guides/governance.md)
- **Diagnostic help:** [Troubleshooting](guides/troubleshooting.md) and [Error Messages](reference/error-messages.md)
- **CLI deep dive:** [CLI Reference](reference/cli.md)
- **SARIF output:** [SARIF Format Guide](reference/sarif-format.md)
- **Full specification:** [docs/spec/](spec/) (normative)
```

- [ ] **Step 3: Commit**

```bash
git add docs/README.md docs/getting-started.md
git commit -m "docs: wire new reference and guides into navigation"
```

---

## Self-Review Checklist

### Spec coverage
- [x] Severity matrix (Task 1) — extracted from `matrix.py:94-125`
- [x] All 12 analysis rules (Task 2) — extracted from `sarif.py:33-76`, `severity.py:29-49`
- [x] All pseudo/governance rule IDs (Task 2) — extracted from `severity.py:52-81`
- [x] All 8 taint states (Task 3) — extracted from `taints.py:8-23`
- [x] Join lattice (Task 3) — extracted from `taints.py:34-41`
- [x] SARIF properties (Task 5) — extracted from `sarif.py:212-298`
- [x] Exit codes (Task 6) — extracted from `cli.md:40-48`
- [x] Governance lifecycle (Task 9) — extracted from spec §9
- [x] Analysis levels L1/L2/L3 (Task 10) — extracted from `models.py:287-300`
- [x] Governance profiles (Task 11) — extracted from `models.py:228-240`
- [x] All 38 decorators in 17 groups — covered by existing `decorators.md` (no new doc needed)
- [x] Cross-links between all new docs and existing docs (Task 13)

### Placeholder scan
- [x] No "TBD", "TODO", "implement later" in any task
- [x] Every task has full document content (no "write similar to Task N")

### Consistency check
- [x] Matrix values in Task 1 match `_MATRIX_DATA` in `matrix.py`
- [x] Rule IDs use hyphenated form everywhere (PY-WL-001, not PY_WL_001)
- [x] Taint states use UPPER_SNAKE_CASE everywhere
- [x] Cross-links use relative paths consistently
- [x] All "Further Reading" sections link to real documents
