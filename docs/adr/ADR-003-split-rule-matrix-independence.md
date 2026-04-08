# ADR-003: Split-rule severity matrix independence

**Status**: Accepted
**Date**: 2026-04-09
**Deciders**: Project Lead, 6-person expert panel review
**Context**: External audit SCAN-014 found PY-WL-002 widens 3 matrix cells relative to WL-001

## Summary

When a language binding splits a framework rule into sub-rules (e.g., WL-001 →
PY-WL-001 + PY-WL-002), sub-rules inherit the framework matrix as their default
but MAY establish their own matrix rows when the language-specific semantics that
motivated the split create risks absent from the framework-level pattern.

The §7.3 "MUST NOT widen" invariant remains absolute — it applies to each
sub-rule relative to its own documented matrix row, not relative to the parent
framework rule.

## Context

PY-WL-002 (attribute access with fallback default) is a Python-specific split of
framework rule WL-001. It covers two detection patterns:

1. `getattr(obj, name, default)` — 3-arg form (attribute absence → default)
2. `obj.attr or default` — or-expression (falsy value → default)

The or-expression form has a **falsy-substitution risk** absent from dict-key
access (PY-WL-001): it silently replaces present-but-falsy values (0, "", False,
None) with the fabricated default. This is not a theoretical concern — it enables
silent data corruption at trust boundaries where security-relevant fields hold
legitimate falsy values.

The Python binding spec documented PY-WL-002 using WARNING (not SUPPRESS) at
EXTERNAL_RAW, UNKNOWN_RAW, and MIXED_RAW for this reason. However:

1. The binding spec incorrectly called this deviation "narrowing" — it is
   widening (WARNING > SUPPRESS in severity).
2. Framework §7.1 stated split sub-rules "inherit WL-001's severity matrix
   entries" with no provision for deviation.
3. Framework §7.3 states bindings "MUST NOT assign higher severity" than the
   framework matrix.
4. An external audit correctly flagged this as FAIL (SCAN-014).

## Decision

Amend §7.1 to formalize that split sub-rules can establish their own matrix rows
when language-specific semantics justify it. This is Option C from the panel
review — it preserves both the §7.3 monotonicity guarantee and the
falsy-substitution safety signal.

## Alternatives Considered

### Option A: Comply with §7.3 as written

Change PY-WL-002 to SUPPRESS at the 3 cells. Simple and conformant, but loses a
real safety signal. The Security Architect's STRIDE analysis showed that
compensating controls (WL-007, WL-008) cannot catch falsy-substitution because
the corruption occurs before the boundary validator sees the data.

Rejected because it sacrifices a genuine safety signal to satisfy a constraint
that was not designed for the split-rule case.

### Option B: Amend §7.3 with exception clause

Add "unless the target language introduces a semantic risk" to §7.3's "MUST NOT
widen" constraint. The Systems Thinker identified this as an Eroding Goals
archetype — it weakens a clean invariant with a subjective gate that future
binding authors would exploit.

Rejected because it destroys the monotonicity guarantee that makes §7.3 useful
for cross-language policy and CI pipeline thresholds.

### Option C (chosen): Amend §7.1 for split-rule independence

Fix the problem at the abstraction layer where it actually lives — the
rule-splitting mechanism. §7.3 stays absolute. Split sub-rules get their own
documented matrix rows. The narrowing constraint applies relative to each
sub-rule's own matrix, not the parent rule.

## Consequences

### Positive

- PY-WL-002 retains falsy-substitution visibility at T4 boundaries
- §7.3's "MUST NOT widen" invariant remains absolute and simple
- Future bindings that split rules have a governed mechanism for the same case
- The binding spec's deviation is correctly characterized and authorized

### Negative

- Split-rule governance is slightly more complex — reviewers must check both the
  split rationale and each sub-rule's matrix
- Creates a second class of matrix baseline (framework-inherited vs
  binding-documented) that conformance testing must distinguish

### Process gaps identified

- Test oracle in `test_matrix.py` was authored from the implementation, not the
  spec — oracle provenance must be independently verified
- Binding spec contained a factual error ("narrowing" for a widening) that
  persisted through self-assessment — cross-layer conformance testing should
  compare framework cells to binding cells explicitly

## Panel Input

Six-person panel reviewed this decision on 2026-04-09:

| Role | Recommendation | Key Insight |
|------|---------------|-------------|
| Solution Architect | Option A | Monotonicity guarantee has real cross-language value |
| Systems Thinker | Option B with tight governance | Eroding Goals archetype — leverage is in amendment specificity |
| Python Engineer | Option A + new rule (PY-WL-002B) | Detection split already exists in code |
| Quality Engineer | Option A (default) | Oracle contamination is the root process failure |
| Security Architect | Keep current (misread §7.3) | Compensating controls can't catch pre-boundary corruption |
| ADR Reviewer | **Option C** | Fix at §7.1 where the semantic gap lives, not §7.3 |
