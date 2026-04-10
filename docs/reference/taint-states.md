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
- [Spec §6: Authority Tier Model](../spec/wardline-01-05-authority-tier-model.md) — normative definitions
