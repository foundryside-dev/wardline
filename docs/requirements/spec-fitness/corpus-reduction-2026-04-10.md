# Corpus Specimen Reduction: 259 → 224

**Date:** 2026-04-10
**Issue:** wardline-01a36526c7
**Design spec:** `docs/superpowers/specs/2026-04-10-taint-specific-specimen-rewrite-design.md`

## Summary

35 corpus specimens were removed as part of a quality improvement to eliminate
fragment duplication. No detection coverage was lost.

## Specimens Removed

### PY-WL-008/009 taint-variant collapse (28 specimens)

PY-WL-008 and PY-WL-009 are **taint-invariant rules**: they produce identical
severity (ERROR), exceptionability (UNCONDITIONAL), and detection results
regardless of taint state. A parametrized test in
`tests/unit/corpus/test_corpus_oracle.py::test_taint_invariant_rules_produce_identical_outputs`
mechanically verifies this property.

The 8 taint variants per verdict were collapsed to 1 representative (EXTERNAL_RAW).
Adversarial specimens (AFP, AFN, TF) were preserved.

### PY-WL-002-TN-01 (1 specimen)

True duplicate of PY-WL-002-TN-EXTERNAL_RAW (kept): same taint state
(EXTERNAL_RAW), same fragment (`def process(obj): x = getattr(obj, "name")`),
same verdict (true_negative). Removed as redundant.

### ADV same-verdict duplicates (6 specimens)

Each ADV specimen below had an identical fragment, taint state, and verdict
as the listed rule-specific specimen. The rule specimen was kept.

| Deleted Specimen | Kept Specimen | Rule | Taint | Verdict |
|-----------------|---------------|------|-------|---------|
| ADV-005-long-function | PY-WL-005-TP-long-function | PY-WL-005 | EXTERNAL_RAW | TP |
| ADV-006-decorator-stack | PY-WL-001-TP-decorator-stack | PY-WL-001 | ASSURED | TP |
| ADV-008-async-except | PY-WL-004-TP-async-except | PY-WL-004 | UNKNOWN_RAW | TP |
| ADV-009-async-silent | PY-WL-005-TP-async-silent | PY-WL-005 | MIXED_RAW | TP |
| ADV-010-async-getattr | PY-WL-002-TP-async-getattr | PY-WL-002 | ASSURED | TP |
| ADV-011-class-method | PY-WL-001-TP-class-method | PY-WL-001 | GUARDED | TP |

## PY-WL-001 SUPPRESS Taint States

PY-WL-001 suppresses findings at EXTERNAL_RAW, MIXED_RAW, and UNKNOWN_RAW
(Tier 3-4 taint states). This is a deliberate design choice: at these trust
levels, dict-default patterns are expected and flagging them would produce
excessive noise. KFN specimens at these taint states document the known
suppression gap. The suppression policy is defined in the severity matrix
and verified by existing matrix tests.

## Coverage Assurance

- All remaining specimens use unique code fragments per rule (verified by
  `test_no_duplicate_sha256_within_rule`)
- `wardline corpus verify` passes with zero failures
- Full test suite (`uv run pytest`) passes with 2224 tests
- Scanner detection logic unchanged — only corpus metadata was modified
