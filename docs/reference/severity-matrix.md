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
- [Spec §7.3: Severity Matrix](../spec/wardline-01-07-pattern-rules.md) — normative definition
