# Wardline Rules Reference

Quick-reference for all Wardline rule IDs — canonical pattern rules, supplementary
rules, diagnostic signals, and governance findings.

---

## Canonical Rules (Pattern Detection)

These nine rules detect structural boundary violations in Python code. All are
emitted as `Finding` objects with taint-gated severity (see
[severity-matrix.md](severity-matrix.md)).

| Rule | Name | Detects | Fix |
|------|------|---------|-----|
| PY-WL-001 | Dict key access with fallback default | `d.get(key, default)`, `d.pop(key, default)`, `d.setdefault(key, default)`, `defaultdict(factory)` — patterns that silently fabricate values for missing keys, bypassing validation. `schema_default()` without a matching overlay boundary also fires here. | Replace fallback defaults with explicit key access that raises on missing keys; or declare an overlay boundary and use `schema_default()` inside it. |
| PY-WL-002 | Attribute access with fallback default | Three-argument `getattr(obj, name, default)` — silently returns a fabricated value when the attribute is absent, masking structural gaps. Two-argument `getattr` (which raises `AttributeError`) is not flagged. | Use two-argument `getattr` and handle `AttributeError` explicitly, or access the attribute directly. |
| PY-WL-003 | Existence-checking as structural gate | `"key" in d`, `key not in d`, `d.get(key) is None`, `hasattr(obj, name)`, `match/case` with `MatchMapping` or `MatchClass` — treating presence/absence of a key or attribute as a control-flow branch rather than enforcing known shape up front. | Validate structure at a declared shape-validation boundary; within the boundary body, direct key/attribute access is permitted. |
| PY-WL-004 | Broad exception handler | Bare `except:`, `except Exception:`, `except BaseException:`, and `except*` with those broad types — handlers that catch far more than intended, masking unexpected failures. | Catch specific exception types. If broad handling is required, re-raise after logging or use a governed suppression. |
| PY-WL-005 | Silent exception handler | Exception handlers whose bodies are `pass`, `...`, `continue`, or `break` — the exception is caught and completely discarded with no log, re-raise, or side effect. | Log the exception, re-raise it, or convert it to a domain error with meaningful context. |
| PY-WL-006 | Audit-critical write in broad exception handler | Audit/ledger write calls (e.g. functions decorated `@integral_writer` / `@integrity_critical`, calls to `audit`, `record`, `write_audit`, etc.) inside a broad exception handler — if the write itself raises, the handler silently masks the failure and the audit trail loses a record. | Move audit writes outside broad handlers, or catch only the specific exceptions the write can raise and propagate the rest. |
| PY-WL-007 | Runtime type-checking on internal data | `isinstance()` and `type() ==` / `type() is` checks on data that should have a statically known type. Severity is taint-gated: suppressed for `EXTERNAL_RAW`/`UNKNOWN_RAW` taint states where type checks are expected; escalated for internal taint states. AST node dispatch, dunder comparison protocol, and frozen-dataclass `__post_init__` patterns are structurally suppressed. | Enforce types at the external boundary with a shape-validation decorator so internal code can rely on the type statically. |
| PY-WL-008 | Validation boundary with no rejection path | A function declared as a validation or restoration boundary (via manifest transition or `@validates_shape` / `@validates_semantic` / `@validates_external` decorator) whose body contains no raised exception or guarded early-return that constitutes a rejection path. | Add an explicit rejection path — raise a domain exception or return early on invalid input before the function proceeds. |
| PY-WL-009 | Semantic validation without prior shape validation | A function declared as a `semantic_validation` boundary (or decorated `@validates_semantic`) that performs semantic checks on data before structural validation has occurred within the same boundary. Combined-validation boundaries are excluded because they satisfy the ordering requirement internally. | Either precede semantic checks with a call to a shape-validation boundary, or promote the boundary to `combined_validation`. |

---

## Supplementary Rules

These rules enforce decorator contracts and cross-cutting structural concerns beyond
the nine canonical patterns.

| Rule | Name | Detects |
|------|------|---------|
| SCN-021 | Contradictory or suspicious wardline decorator combination | Pairs of wardline decorators that are mutually exclusive or structurally incompatible on the same function — e.g. `@fail_open` + `@fail_closed`, `@fail_open` + `@integral_writer`, `@external_boundary` + `@integral_read`. Contradictory pairs emit ERROR; suspicious pairs emit WARNING. |
| SCN-022 | Field-completeness verification for @all_fields_mapped | Functions decorated with `@all_fields_mapped(source="ClassName")` where one or more annotated fields of the named source class are never accessed on the function's first parameter — silent data-loss risk in mapping/projection functions. |
| SUP-001 | Supplementary decorator contract violation | Local AST-checkable contracts for supplementary decorators: `@parse_at_init` call-site placement, `@atomic` transaction wrapping, `@compensatable` rollback arity, `@deterministic` bans, `@ordered_after` lexical ordering, `@not_reentrant` cycle detection, `@requires_identity` audit threading, `@privileged_operation` authorization-before-mutation, `@deprecated_by` expiry/advisory checks, `@feature_gated` stale-flag detection, `@test_only` production import bans, `@handles_secrets` sink leak checks, `@handles_pii` / `@handles_classified` / `@declassifies` sensitivity checks. |

For the full decorator catalogue see [decorators.md](decorators.md) and
[supplementary-groups.md](supplementary-groups.md).

---

## Diagnostic Signals

These pseudo-rule-IDs appear in SARIF output as informational signals; they are not
in `implementedRules` and cannot be excepted.

| Rule | Name | Meaning |
|------|------|---------|
| PY-WL-001-GOVERNED-DEFAULT | Governed default value (diagnostic) | A `schema_default()` call with a matching overlay boundary declaration was found. Emitted at SUPPRESS severity to record the governed use; does not require remediation. |
| PY-WL-001-UNGOVERNED-DEFAULT | Ungoverned schema_default() — no overlay boundary (diagnostic) | A `schema_default()` call with no corresponding overlay boundary declaration. Emitted at ERROR severity alongside the parent PY-WL-001 finding. |
| WARDLINE-UNRESOLVED-DECORATOR | Unresolved decorator (diagnostic) | A wardline decorator reference could not be statically resolved — e.g. the decorator is aliased or conditionally imported. Taint and boundary analysis for the affected function may be incomplete. |
| WARDLINE-DYNAMIC-IMPORT | Dynamic import of wardline module (diagnostic) | A wardline module is being imported dynamically (e.g. via `importlib.import_module`). Static analysis of symbols resolved through this import may be unreliable. |
| TOOL-ERROR | Internal tool error | An unexpected error occurred inside the Wardline scanner engine. The finding message contains the traceback. Report persistent occurrences as scanner bugs. |

---

## Governance Findings

Governance findings are emitted by the exception and taint governance subsystems.
They record policy events, drift detections, and configuration anomalies. All are
pseudo-rule-IDs and cannot themselves be excepted.

| Rule | Name |
|------|------|
| GOVERNANCE-REGISTRY-MISMATCH-ALLOWED | Registry mismatch allowed (diagnostic) |
| GOVERNANCE-RULE-DISABLED | Rule disabled by configuration (governance) |
| GOVERNANCE-PERMISSIVE-DISTRIBUTION | Permissive distribution allowed (governance) |
| GOVERNANCE-STALE-EXCEPTION | Stale exception — AST fingerprint mismatch (governance) |
| GOVERNANCE-UNKNOWN-PROVENANCE | Unknown agent provenance on exception (governance) |
| GOVERNANCE-RECURRING-EXCEPTION | Recurring exception — multiple renewals (governance) |
| GOVERNANCE-BATCH-REFRESH | Batch exception refresh performed (governance) |
| GOVERNANCE-NO-EXPIRY-EXCEPTION | Exception has no expiry date (governance) |
| GOVERNANCE-EXCEPTION-TAINT-DRIFT | Exception taint state no longer matches function's effective taint |
| GOVERNANCE-EXCEPTION-LEVEL-STALE | Exception granted at lower analysis level than active scan |
| GOVERNANCE-EXCEPTION-SEVERITY-DRIFT | Exception severity_at_grant differs from current finding severity |
| GOVERNANCE-TAINT-DEGRADED | Taint assignment degraded — file scanned with empty fallback taint map |
| GOVERNANCE-TAINT-CONFLICT | Conflicting taint decorators on function — first decorator wins, others ignored |
| GOVERNANCE-RESTORATION-OVERCLAIM | Restoration decorator claims tier unsupported by declared evidence (governance) |
| GOVERNANCE-MODULE-TIERS-BLANKET | Module-level taint default covers >80% of functions with no decorator evidence |
| GOVERNANCE-MODULE-TIERS-UNDECORATED | High-trust module_tiers entry with zero wardline decorator usage in file |
| GOVERNANCE-CUSTOM-KNOWN-VALIDATOR | Custom known_validators entry (governance) |
| GOVERNANCE-FILE-SKIPPED | File skipped due to parse failure (governance) |
| GOVERNANCE-WEAK-ELIMINATION-PATH | Exception elimination_path is a placeholder (governance) |
| L3-LOW-RESOLUTION | L3 call-graph taint based on minority of call edges (>70% unresolved) |
| L3-CONVERGENCE-BOUND | L3 propagation hit iteration safety bound — results may be incomplete |

For the full governance exception lifecycle see [governance-retention.md](governance-retention.md).

---

## Further Reading

- [severity-matrix.md](severity-matrix.md) — Taint-state × rule severity matrix
- [decorators.md](decorators.md) — Full wardline decorator catalogue
- Spec §7 — Semantic boundary enforcement normative requirements
- [semantic-equivalents/](semantic-equivalents/) — Equivalent patterns across languages
