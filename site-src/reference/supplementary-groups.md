# Supplementary Group Enforcement Scope

This document defines which supplementary decorator groups (5-17) are
actively enforced versus expressiveness-only in the Python binding,
per WL-FIT-CONF-005 and Wardline Framework Specification section 15.5.

## Background

The Wardline Framework defines 17 decorator groups. Groups 1-4 are
**framework-mandated** — all conformant bindings must enforce them.
Groups 5-17 are **supplementary** — bindings define their own
enforcement depth. What matters is that the binding can express the
full vocabulary and that the regime documentation accurately declares
scope.

## Enforcement Status by Group

| Group | Name | Decorators | Enforcement | Rule(s) |
|-------|------|-----------|-------------|---------|
| 1 | Authority Tier Flow | `@external_boundary`, `@validates_shape`, `@validates_semantic`, `@validates_external`, `@integral_read`, `@integral_writer`, `@integral_construction` | **Enforced** | PY-WL-001 through PY-WL-009 |
| 2 | Audit | `@integrity_critical` | **Enforced** | PY-WL-006 (audit-call bypass) |
| 3 | Data Provenance | `@int_data` | **Enforced** | Taint assignment (function_level.py) |
| 4 | Error Handling | `@fail_closed`, `@fail_open`, `@exception_boundary`, `@must_propagate`, `@preserve_cause`, `@emits_or_explains` | **Enforced** | PY-WL-004, PY-WL-005, SCN-021 |
| 5 | Schema Contracts | `@all_fields_mapped`, `@output_schema`, `@schema_default` | **Enforced** | SCN-022 (field completeness), PY-WL-001 (default governance) |
| 6 | Trust Boundaries | `@trust_boundary`, `@tier_transition` | **Enforced** | SCN-021 (contradictory combinations) |
| 7 | Operations | `@atomic`, `@compensatable`, `@idempotent` | **Enforced** | SCN-021 (contradictory combinations) |
| 8 | Sensitivity | `@handles_pii`, `@handles_classified`, `@declassifies`, `@handles_secrets` | Expressiveness-only | None — documentation markers |
| 9 | Access Control | `@privileged_operation`, `@requires_identity` | **Partial** | SUP-001 (`@requires_identity` audit threading) |
| 10 | Safety | `@parse_at_init` | **Enforced** | SUP-001 (placement verification) |
| 11 | Lifecycle | `@deprecated_by`, `@test_only`, `@feature_gated` | Expressiveness-only | None — documentation markers |
| 12 | Determinism | `@deterministic`, `@time_dependent` | **Enforced** | SUP-001 (non-deterministic call ban list), SCN-021 |
| 13 | Concurrency | `@ordered_after`, `@not_reentrant`, `@thread_safe` | **Partial** | SUP-001 (`@ordered_after` ordering, `@not_reentrant` reentrance); `@thread_safe` advisory-only |
| 14 | Plugin | `@system_plugin` | **Enforced** | SCN-021 (contradictory combinations) |
| 15 | Feature Flags | `@feature_gated` | Expressiveness-only | None — documentation marker |
| 16 | Data Flow | `@data_flow` | Advisory | L2+ parameterised analysis required for full enforcement |
| 17 | Restoration | `@restoration_boundary` | **Enforced** | Evidence-bounded restoration; overclaim detection |

## Summary

- **Actively enforced:** Groups 1-7, 10, 12, 14, 17 (12 groups)
- **Partially enforced:** Groups 9, 13 (2 groups — subset of decorators enforced)
- **Expressiveness-only:** Groups 8, 11, 15 (3 groups — markers for documentation and tooling)
- **Advisory:** Group 16 (requires L2+ analysis for enforcement)

## Overlay Configuration

Adopters can adjust supplementary group enforcement scope via overlays.
The `supplementary_enforcement` section declares per-group scope:

```yaml
supplementary_enforcement:
  - group: 8
    scope: "src/sensitive/"
    severity: WARNING
    description: "Sensitivity markers enforced in sensitive data modules"
```

This converts expressiveness-only decorators to enforced within the
declared scope. The scanner reads these declarations and adjusts finding
severity accordingly.
