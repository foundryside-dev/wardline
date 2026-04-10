# Rename Migration Manifest

Generated: 2026-03-28
ADRs: ADR-001 (taint states), ADR-002 (decorators)

## Statistics

- Total files to update: ~160 (excludes archived docs)
- Total lines affected in updated files: ~1,780
- Archived docs left as-is: ~42 files, ~365 lines (historical records)
- By layer:
  - Core source (`src/wardline/core/`): 5 files, 28 lines
  - Scanner source (`src/wardline/scanner/`): 7 files, 50 lines
  - Manifest source (`src/wardline/manifest/`): 4 files, 12 lines
  - Decorators source (`src/wardline/decorators/`): 3 files, 16 lines (+ 2 file renames: `audit.py` → `integrity.py`, `test_audit.py` → `test_integrity.py`)
  - Runtime source (`src/wardline/runtime/`): 1 file, 1 line
  - CLI source (`src/wardline/cli/`): 0 files, 0 lines
  - Tests: 38 files, 512 lines
  - Spec docs: 11 files, 114 lines
  - Active design/requirements docs: 10 files, ~65 lines (Layer 10a)
  - Archived docs: ~42 files — DO NOT UPDATE (Layer 10b)
  - Schemas: 3 files, 12 lines
  - Corpus: 74 files, 311 lines (+ 45 directory renames, + ~90 file renames). `corpus_manifest.json`: **regenerate, don't sed**
  - Config/manifests: 5 files, 90 lines
  - ADR/verification docs (rename-aware): 5 files, ~90 lines (UPDATE references, do NOT erase old names from the ADR decision record)
  - Scripts: 1 file, 10 lines
- Verified clean (no old name references): `AGENTS.md`, `README.md`, `docs/superpowers/`

## Safe Replacement Order

**CRITICAL: Longer tokens must be replaced before shorter tokens to
prevent partial-match corruption.**

### Taint state tokens (within each file, apply in this order):

1. `UNKNOWN_SHAPE_VALIDATED` -> `UNKNOWN_GUARDED` (15 chars vs 21 -- no substring of others)
2. `UNKNOWN_SEM_VALIDATED` -> `UNKNOWN_ASSURED` (no substring of others)
3. `SHAPE_VALIDATED` -> `GUARDED` (substring of `UNKNOWN_SHAPE_VALIDATED` -- MUST go after step 1)
4. `AUDIT_TRAIL` -> `INTEGRAL` (no longer token contains it)
5. `PIPELINE` -> `ASSURED` (no longer token contains it)

### Decorator names (within each file, apply in this order):

1. `authoritative_construction` -> `integral_construction` (longest, no substring risk)
2. `audit_writer` -> `integral_writer` (safe -- `audit_writer` is not a substring of `audit_critical`)
3. `audit_critical` -> `integrity_critical`
4. `tier1_read` -> `integral_read`

### Derived identifiers (rename after primary tokens):

1. `_wardline_audit_writer` -> `_wardline_integral_writer`
2. `_wardline_audit_critical` -> `_wardline_integrity_critical`
3. `_AUDIT_DECORATORS` -> `_INTEGRITY_DECORATORS` (contains decorator name references)

---

## Layer 1: Core Source (src/wardline/core/)

### core/taints.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 16 | `AUDIT_TRAIL = "AUDIT_TRAIL"` | `INTEGRAL = "INTEGRAL"` | TaintState enum member definition |
| 17 | `PIPELINE = "PIPELINE"` | `ASSURED = "ASSURED"` | TaintState enum member definition |
| 18 | `SHAPE_VALIDATED = "SHAPE_VALIDATED"` | `GUARDED = "GUARDED"` | TaintState enum member definition |
| 21 | `UNKNOWN_SHAPE_VALIDATED = "UNKNOWN_SHAPE_VALIDATED"` | `UNKNOWN_GUARDED = "UNKNOWN_GUARDED"` | TaintState enum member definition |
| 22 | `UNKNOWN_SEM_VALIDATED = "UNKNOWN_SEM_VALIDATED"` | `UNKNOWN_ASSURED = "UNKNOWN_ASSURED"` | TaintState enum member definition |
| 31 | `_USH = TaintState.UNKNOWN_SHAPE_VALIDATED` | `_USH = TaintState.UNKNOWN_GUARDED` | Join table alias |
| 32 | `_USE = TaintState.UNKNOWN_SEM_VALIDATED` | `_USE = TaintState.UNKNOWN_ASSURED` | Join table alias |

### core/tiers.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 27 | `TaintState.AUDIT_TRAIL: AuthorityTier.TIER_1` | `TaintState.INTEGRAL: AuthorityTier.TIER_1` | TAINT_TO_TIER mapping |
| 28 | `TaintState.PIPELINE: AuthorityTier.TIER_2` | `TaintState.ASSURED: AuthorityTier.TIER_2` | TAINT_TO_TIER mapping |
| 29 | `TaintState.SHAPE_VALIDATED: AuthorityTier.TIER_3` | `TaintState.GUARDED: AuthorityTier.TIER_3` | TAINT_TO_TIER mapping |
| 30 | `TaintState.UNKNOWN_SEM_VALIDATED: AuthorityTier.TIER_3` | `TaintState.UNKNOWN_ASSURED: AuthorityTier.TIER_3` | TAINT_TO_TIER mapping |
| 31 | `TaintState.UNKNOWN_SHAPE_VALIDATED: AuthorityTier.TIER_3` | `TaintState.UNKNOWN_GUARDED: AuthorityTier.TIER_3` | TAINT_TO_TIER mapping |

### core/matrix.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 14 | `T1 (INTEGRAL/AUDIT_TRAIL)` | `T1 (INTEGRAL)` | Docstring comment |
| 17 | `T2 (ASSURED/PIPELINE)` | `T2 (ASSURED)` | Docstring comment |
| 19 | `T3 (GUARDED/SHAPE_VALIDATED)` | `T3 (GUARDED)` | Docstring comment |
| 57 | `# AUDIT_TRAIL, PIPELINE, SHAPE_VALIDATED, EXTERNAL_RAW,` | `# INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW,` | Column order comment |
| 58 | `# UNKNOWN_RAW, UNKNOWN_SHAPE_VALIDATED, UNKNOWN_SEM_VALIDATED, MIXED_RAW` | `# UNKNOWN_RAW, UNKNOWN_GUARDED, UNKNOWN_ASSURED, MIXED_RAW` | Column order comment |
| 60 | `TaintState.AUDIT_TRAIL` | `TaintState.INTEGRAL` | _TAINT_ORDER list |
| 61 | `TaintState.PIPELINE` | `TaintState.ASSURED` | _TAINT_ORDER list |
| 62 | `TaintState.SHAPE_VALIDATED` | `TaintState.GUARDED` | _TAINT_ORDER list |
| 65 | `TaintState.UNKNOWN_SHAPE_VALIDATED` | `TaintState.UNKNOWN_GUARDED` | _TAINT_ORDER list |
| 66 | `TaintState.UNKNOWN_SEM_VALIDATED` | `TaintState.UNKNOWN_ASSURED` | _TAINT_ORDER list |

### core/evidence.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 27 | `TaintState.UNKNOWN_SEM_VALIDATED` | `TaintState.UNKNOWN_ASSURED` | Evidence matrix return |
| 28 | `TaintState.UNKNOWN_SHAPE_VALIDATED` | `TaintState.UNKNOWN_GUARDED` | Evidence matrix return |
| 31 | `TaintState.AUDIT_TRAIL  # Tier 1` | `TaintState.INTEGRAL  # Tier 1` | Evidence matrix return |
| 33 | `TaintState.PIPELINE  # Tier 2` | `TaintState.ASSURED  # Tier 2` | Evidence matrix return |
| 34 | `TaintState.SHAPE_VALIDATED  # Tier 3` | `TaintState.GUARDED  # Tier 3` | Evidence matrix return |

### core/registry.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 73 | `"tier1_read": RegistryEntry(` | `"integral_read": RegistryEntry(` | Registry key |
| 74 | `canonical_name="tier1_read"` | `canonical_name="integral_read"` | Registry canonical_name |
| 78 | `"audit_writer": RegistryEntry(` | `"integral_writer": RegistryEntry(` | Registry key |
| 79 | `canonical_name="audit_writer"` | `canonical_name="integral_writer"` | Registry canonical_name |
| 83 | `"_wardline_audit_writer": bool` | `"_wardline_integral_writer": bool` | Registry attr name |
| 86 | `"authoritative_construction": RegistryEntry(` | `"integral_construction": RegistryEntry(` | Registry key |
| 87 | `canonical_name="authoritative_construction"` | `canonical_name="integral_construction"` | Registry canonical_name |
| 92 | `"audit_critical": RegistryEntry(` | `"integrity_critical": RegistryEntry(` | Registry key |
| 93 | `canonical_name="audit_critical"` | `canonical_name="integrity_critical"` | Registry canonical_name |
| 95 | `"_wardline_audit_critical": bool` | `"_wardline_integrity_critical": bool` | Registry attr name |

---

## Layer 2: Scanner Source (src/wardline/scanner/)

### scanner/taint/function_level.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 65 | `"validates_semantic": TaintState.SHAPE_VALIDATED` | `"validates_semantic": TaintState.GUARDED` | BODY_EVAL_TAINT |
| 67 | `"tier1_read": TaintState.AUDIT_TRAIL` | `"integral_read": TaintState.INTEGRAL` | BODY_EVAL_TAINT |
| 68 | `"audit_writer": TaintState.AUDIT_TRAIL` | `"integral_writer": TaintState.INTEGRAL` | BODY_EVAL_TAINT |
| 69 | `"authoritative_construction": TaintState.AUDIT_TRAIL` | `"integral_construction": TaintState.INTEGRAL` | BODY_EVAL_TAINT |
| 76 | `"validates_shape": TaintState.SHAPE_VALIDATED` | `"validates_shape": TaintState.GUARDED` | RETURN_TAINT |
| 77 | `"validates_semantic": TaintState.PIPELINE` | `"validates_semantic": TaintState.ASSURED` | RETURN_TAINT |
| 78 | `"validates_external": TaintState.PIPELINE` | `"validates_external": TaintState.ASSURED` | RETURN_TAINT |
| 79 | `"tier1_read": TaintState.AUDIT_TRAIL` | `"integral_read": TaintState.INTEGRAL` | RETURN_TAINT |
| 80 | `"audit_writer": TaintState.AUDIT_TRAIL` | `"integral_writer": TaintState.INTEGRAL` | RETURN_TAINT |
| 81 | `"authoritative_construction": TaintState.AUDIT_TRAIL` | `"integral_construction": TaintState.INTEGRAL` | RETURN_TAINT |

### scanner/taint/callgraph.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 13 | `TaintState.AUDIT_TRAIL: 0` | `TaintState.INTEGRAL: 0` | TRUST_RANK mapping |
| 14 | `TaintState.PIPELINE: 1` | `TaintState.ASSURED: 1` | TRUST_RANK mapping |
| 15 | `TaintState.SHAPE_VALIDATED: 2` | `TaintState.GUARDED: 2` | TRUST_RANK mapping |
| 16 | `TaintState.UNKNOWN_SEM_VALIDATED: 3` | `TaintState.UNKNOWN_ASSURED: 3` | TRUST_RANK mapping |
| 17 | `TaintState.UNKNOWN_SHAPE_VALIDATED: 4` | `TaintState.UNKNOWN_GUARDED: 4` | TRUST_RANK mapping |

### scanner/taint/variable_level.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 95 | `Literals ... -> AUDIT_TRAIL` | `Literals ... -> INTEGRAL` | Comment |
| 104 | `TaintState.AUDIT_TRAIL` | `TaintState.INTEGRAL` | Literal int return |
| 119 | `TaintState.AUDIT_TRAIL` | `TaintState.INTEGRAL` | Literal string return |
| 130 | `TaintState.AUDIT_TRAIL` | `TaintState.INTEGRAL` | Literal bool/None/Ellipsis return |
| 138 | `TaintState.AUDIT_TRAIL` | `TaintState.INTEGRAL` | Literal JoinedStr return |

### scanner/taint/callgraph_propagation.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 244 | `TRUST_RANK[TaintState.AUDIT_TRAIL]` | `TRUST_RANK[TaintState.INTEGRAL]` | Default rank for empty callee sets |

### scanner/engine.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 378 | `TaintState.AUDIT_TRAIL, TaintState.PIPELINE` | `TaintState.INTEGRAL, TaintState.ASSURED` | Taint state references |
| 653 | `SHAPE_VALIDATED` | `GUARDED` | Comment |

### scanner/rules/py_wl_006.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 32 | `_AUDIT_DECORATORS = frozenset({"audit_writer", "audit_critical"})` | `_INTEGRITY_DECORATORS = frozenset({"integral_writer", "integrity_critical"})` | Decorator name set + variable name |
| 171 | `decorator_name(decorator) in _AUDIT_DECORATORS` | `decorator_name(decorator) in _INTEGRITY_DECORATORS` | Reference to renamed set |

**Note:** The variable `_AUDIT_DECORATORS` must be renamed to `_INTEGRITY_DECORATORS` and all references updated. The functions `_looks_audit_scoped`, `_is_audit_call`, `_AUDIT_ATTR_PREFIXES`, `_AUDIT_FUNC_NAMES`, `_local_audit_names`, `_has_normal_path_audit`, `_contains_audit_call` are **heuristic names referring to the audit detection feature** (PY-WL-006 rule "audit-critical writes"), not the decorator names. These are NOT in scope for ADR-002 and should be evaluated separately.

### scanner/rules/scn_021.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 28 | `"tier1_read"` | `"integral_read"` | Combination spec reference |
| 32 | `"audit_writer"` | `"integral_writer"` | Combination spec reference |
| 35 | `"authoritative_construction"` | `"integral_construction"` | Combination spec reference |
| 39 | `"audit_critical"` | `"integrity_critical"` | Combination spec reference |
| 41 | `"tier1_read"` | `"integral_read"` | Combination spec reference |
| 42 | `"authoritative_construction"` | `"integral_construction"` | Combination spec reference |
| 44 | `"tier1_read"` | `"integral_read"` | Combination spec reference |
| 56 | `"tier1_read"` | `"integral_read"` | Combination spec reference |
| 62 | `"audit_writer"` | `"integral_writer"` | Combination spec reference |
| 96 | `"authoritative_construction"` | `"integral_construction"` | Combination spec reference |
| 123 | `"audit_writer"` | `"integral_writer"` | Combination spec reference |
| 124 | `"tier1_read"` | `"integral_read"` | Combination spec reference |

### scanner/rules/sup_001.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 301 | `{"audit_writer", "audit_critical"}` | `{"integral_writer", "integrity_critical"}` | Canonical name check |
| 614 | `@audit_writer/@audit_critical` | `@integral_writer/@integrity_critical` | Error message string |

### scanner/fingerprint.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 176 | `authoritative_construction` | `integral_construction` | Import reference |
| 183 | `"authoritative_construction": "construction"` | `"integral_construction": "construction"` | Transition map key |

---

## Layer 3: Manifest Source (src/wardline/manifest/)

### manifest/coherence.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 707 | `TaintState.UNKNOWN_SEM_VALIDATED` | `TaintState.UNKNOWN_ASSURED` | Coherence check |
| 708 | `TaintState.UNKNOWN_SHAPE_VALIDATED` | `TaintState.UNKNOWN_GUARDED` | Coherence check |

### manifest/schemas/corpus-specimen.schema.json

| Line | Old | New | Context |
|------|-----|-----|---------|
| 27 | `"AUDIT_TRAIL", "PIPELINE", "SHAPE_VALIDATED"` | `"INTEGRAL", "ASSURED", "GUARDED"` | Enum values |
| 29 | `"UNKNOWN_SHAPE_VALIDATED", "UNKNOWN_SEM_VALIDATED"` | `"UNKNOWN_GUARDED", "UNKNOWN_ASSURED"` | Enum values |

### manifest/schemas/wardline.schema.json

| Line | Old | New | Context |
|------|-----|-----|---------|
| 141 | `"AUDIT_TRAIL", "PIPELINE", "SHAPE_VALIDATED"` | `"INTEGRAL", "ASSURED", "GUARDED"` | Enum values |
| 143 | `"UNKNOWN_SHAPE_VALIDATED", "UNKNOWN_SEM_VALIDATED"` | `"UNKNOWN_GUARDED", "UNKNOWN_ASSURED"` | Enum values |

### manifest/schemas/exceptions.schema.json

| Line | Old | New | Context |
|------|-----|-----|---------|
| 28 | `"AUDIT_TRAIL", "PIPELINE", "SHAPE_VALIDATED"` | `"INTEGRAL", "ASSURED", "GUARDED"` | Enum values |
| 30 | `"UNKNOWN_SHAPE_VALIDATED", "UNKNOWN_SEM_VALIDATED"` | `"UNKNOWN_GUARDED", "UNKNOWN_ASSURED"` | Enum values |

---

## Layer 4: Decorators Source (src/wardline/decorators/)

### decorators/authority.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 13 | `"audit_writer"` | `"integral_writer"` | __all__ entry |
| 14 | `"authoritative_construction"` | `"integral_construction"` | __all__ entry |
| 16 | `"tier1_read"` | `"integral_read"` | __all__ entry |
| 31 | `TaintState.SHAPE_VALIDATED` | `TaintState.GUARDED` | validates_shape transition (to_tier) |
| 37 | `TaintState.SHAPE_VALIDATED, TaintState.PIPELINE` | `TaintState.GUARDED, TaintState.ASSURED` | validates_semantic transition |
| 43 | `TaintState.PIPELINE` | `TaintState.ASSURED` | validates_external transition (to_tier) |
| 46 | `tier1_read = wardline_decorator(` | `integral_read = wardline_decorator(` | Variable name |
| 48 | `"tier1_read"` | `"integral_read"` | Canonical name arg |
| 49 | `TaintState.AUDIT_TRAIL` | `TaintState.INTEGRAL` | Tier source |
| 52 | `audit_writer = wardline_decorator(` | `integral_writer = wardline_decorator(` | Variable name |
| 54 | `"audit_writer"` | `"integral_writer"` | Canonical name arg |
| 55 | `TaintState.AUDIT_TRAIL` | `TaintState.INTEGRAL` | Tier source |
| 56 | `_wardline_audit_writer=True` | `_wardline_integral_writer=True` | Attribute name |
| 59 | `authoritative_construction = wardline_decorator(` | `integral_construction = wardline_decorator(` | Variable name |
| 61 | `"authoritative_construction"` | `"integral_construction"` | Canonical name arg |
| 62 | `TaintState.PIPELINE, TaintState.AUDIT_TRAIL` | `TaintState.ASSURED, TaintState.INTEGRAL` | Transition tuple |

### decorators/audit.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 12 | `"audit_critical"` | `"integrity_critical"` | __all__ entry |
| 15 | `audit_critical = wardline_decorator(` | `integrity_critical = wardline_decorator(` | Variable name |
| 17 | `"audit_critical"` | `"integrity_critical"` | Canonical name arg |
| 18 | `_wardline_audit_critical=True` | `_wardline_integrity_critical=True` | Attribute name |

### decorators/__init__.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 4 | `from wardline.decorators.audit import audit_critical` | `from wardline.decorators.audit import integrity_critical` | Import |
| 6 | `audit_writer` | `integral_writer` | Import from authority |
| 7 | `authoritative_construction` | `integral_construction` | Import from authority |
| 9 | `tier1_read` | `integral_read` | Import from authority |
| 44 | `"audit_critical"` | `"integrity_critical"` | __all__ entry |
| 45 | `"audit_writer"` | `"integral_writer"` | __all__ entry |
| 46 | `"authoritative_construction"` | `"integral_construction"` | __all__ entry |
| 76 | `"tier1_read"` | `"integral_read"` | __all__ entry |

---

## Layer 5: Runtime Source (src/wardline/runtime/)

### runtime/enforcement.py

| Line | Old | New | Context |
|------|-----|-----|---------|
| 238 | `A tier of 1 (AUDIT_TRAIL)` | `A tier of 1 (INTEGRAL)` | Docstring |

---

## Layer 6: Tests

### tests/unit/core/test_taints.py (13 lines)

All `TaintState.AUDIT_TRAIL` -> `TaintState.INTEGRAL`, `TaintState.PIPELINE` -> `TaintState.ASSURED`, `TaintState.SHAPE_VALIDATED` -> `TaintState.GUARDED`, `TaintState.UNKNOWN_SHAPE_VALIDATED` -> `TaintState.UNKNOWN_GUARDED`, `TaintState.UNKNOWN_SEM_VALIDATED` -> `TaintState.UNKNOWN_ASSURED`. Also string literals: `"AUDIT_TRAIL"` -> `"INTEGRAL"`, `"PIPELINE"` -> `"ASSURED"`, `"SHAPE_VALIDATED"` -> `"GUARDED"`, `"UNKNOWN_SHAPE_VALIDATED"` -> `"UNKNOWN_GUARDED"`, `"UNKNOWN_SEM_VALIDATED"` -> `"UNKNOWN_ASSURED"`.

Lines: 27, 28, 29, 32, 33, 39, 79, 80, 81, 83, 100, 101, 102, 103, 105, 106, 107, 108, 109, 110, 111, 112, 113, 115, 116, 117

### tests/unit/core/test_taint_to_tier.py (6 lines)

Lines: 17, 18, 19, 20, 21, 32

### tests/unit/core/test_evidence.py (8 lines)

Lines: 14, 15, 16, 17, 18, 29, 30, 31

### tests/unit/core/test_matrix.py (36 lines)

Lines: 28-34, 38-44, 48-54, 58-64, 68-74, 78-84, 88-94, 98-104, 108-114, 152, 163

### tests/unit/core/test_registry.py (4 lines)

Lines: 34 (`tier1_read` -> `integral_read`), 35 (`audit_writer` -> `integral_writer`), 36 (`authoritative_construction` -> `integral_construction`), and `audit_critical` references

### tests/unit/decorators/test_decorators.py (22 lines)

Lines: 14 (import `audit_writer` -> `integral_writer`), 15 (import `authoritative_construction` -> `integral_construction`), 16 (import `tier1_read` -> `integral_read`), 38 (`_wardline_audit_critical` -> `_wardline_integrity_critical`), 158 (`_wardline_audit_critical` -> `_wardline_integrity_critical`), 338, 359, 380, 389-404 (`tier1_read` tests), 410-427 (`audit_writer` tests), 432-447 (`authoritative_construction` tests), 444 (transition tuple with `TaintState.PIPELINE, TaintState.AUDIT_TRAIL`)

### tests/unit/decorators/test_audit.py (3 lines)

Lines: 16 (`_wardline_audit_critical` -> `_wardline_integrity_critical`), plus import of `audit_critical` -> `integrity_critical`

### tests/unit/decorators/test_auto_stamping.py (5 lines)

Lines: 38, 42, 56, 76, 211 (references to SHAPE_VALIDATED, _wardline_audit_critical)

### tests/unit/scanner/test_taint.py (29 lines)

Lines: 66, 67, 76, 77, 78, 79, 81, 84, 88, 90, 93, 97, 99, 102, 106, 108, 112, 137, 145, 153, 161, 191, 233, 247, 254, 261, 305, 310, 391, 395, 399, 401, 408, 435, 450, 486, 498, 525-576, 616, 625, 646, 648, 665, 681

### tests/unit/scanner/test_variable_level_taint.py (22 lines)

All references to `TaintState.AUDIT_TRAIL` (lines 25, 31, 33, 39, 56, 57, 81, 83, 130, 140, 154, 155, 173, 197, 210, 212, 252, 278, 290, 320, 345, 364, 365, 378) and `TaintState.PIPELINE`, `TaintState.SHAPE_VALIDATED`

### tests/unit/scanner/test_callgraph_propagation.py (30 lines)

All references to `TaintState.AUDIT_TRAIL`, `TaintState.PIPELINE`, `TaintState.SHAPE_VALIDATED` in test data and comments (lines 135, 142, 145, 148, 162, 165, 175, 178, 179, 185, 188, 191, 192, 198, 199, 202, 206, 212, 225, 229, 235, 253, 256, 263, 307, 311, 407, 417, 440, 441, 448, 457, 460, 461, 491, 533, 551-554, 579, 582, 590, 603, 606, 620, 623, 624, 640, 643, 644, 662, 665, 673, 684, 693, 694, 698, 702, 703, 713, 716)

### tests/unit/scanner/test_callgraph.py (2 lines)

Lines: 23, 24 (comments and `TaintState.AUDIT_TRAIL`)

### tests/unit/scanner/test_callgraph_properties.py (2 lines)

Lines: 26, 27 (comment and `TRUST_RANK[TaintState.AUDIT_TRAIL]`)

### tests/unit/scanner/test_matrix_cells.py (6 lines)

Lines: 42-48 (all taint state enum references)

### tests/unit/scanner/test_rules_taint_aware.py (19 lines)

Lines: 54, 55, 57, 69, 78, 80, 88, 89, 116, 124, 125, 137, 151, 152, 163, 165, 179, 180, 211, 213, 217, 218, 223, 227, 228, 233, 237, 238, 243, 247, 248

### tests/unit/scanner/test_py_wl_006.py (9 lines)

Lines: 91, 94 (`@audit_writer` -> `@integral_writer`), 108, 111 (`@audit_critical` -> `@integrity_critical`), 213, 216 (`@audit_writer` -> `@integral_writer`), 325, 326, 332, 338, 344, 350 (taint state references)

### tests/unit/scanner/test_py_wl_007.py (2 lines)

Lines: 154, 157 (TaintState.AUDIT_TRAIL), 184 (TaintState.PIPELINE), 386 (TaintState.SHAPE_VALIDATED)

### tests/unit/scanner/test_py_wl_008.py (3 lines)

Lines: 102 (SHAPE_VALIDATED), 320, 323 (AUDIT_TRAIL), 345 (PIPELINE)

### tests/unit/scanner/test_py_wl_009.py (4 lines)

Lines: 18, 40 (PIPELINE), 261, 264 (AUDIT_TRAIL), 275 (UNKNOWN_SHAPE_VALIDATED)

### tests/unit/scanner/test_context.py (6 lines)

Lines: 73 (AUDIT_TRAIL), 94 (PIPELINE), 135 (PIPELINE), 181 (`audit_critical` -> `integrity_critical`), 183 (`_wardline_audit_critical` -> `_wardline_integrity_critical`), 198 (PIPELINE), 200 (`tier1_read` -> `integral_read`)

### tests/unit/scanner/test_engine_taint_wiring.py (1 line)

Line: 298 (TaintState.AUDIT_TRAIL)

### tests/unit/scanner/test_engine_l3.py (4 lines)

Lines: 187, 188, 191, 208 (PIPELINE, EXTERNAL_RAW references)

### tests/unit/scanner/test_sarif.py (2 lines)

Lines: 107, 109 (`"PIPELINE"` string)

### tests/unit/scanner/test_taint_observability.py (5 lines)

Lines: 66, 73 (PIPELINE), 108 (SHAPE_VALIDATED), 191 (PIPELINE string), 245-247 (`tier1_read` references)

### tests/unit/scanner/test_module_tiers_auditability.py (9 lines)

Lines: 40, 72, 94, 146 (PIPELINE string), 115, 123, 135, 186-187, 192 (AUDIT_TRAIL string and `tier1_read` references)

### tests/unit/scanner/test_l1_provenance.py (4 lines)

Lines: 52, 60, 83, 98 (SHAPE_VALIDATED references)

### tests/unit/scanner/test_sup_001.py (2 lines)

Lines: 168, 170 (`audit_writer` -> `integral_writer` in test fixture code)

### tests/unit/scanner/test_annotation_fingerprint.py (7 lines)

Lines: 50, 56, 69, 72, 84, 105 (`audit_critical` -> `integrity_critical`)

### tests/unit/scanner/test_discovery.py (5 lines)

References to `audit_critical` in test discovery checks

### tests/unit/scanner/test_scn_021.py (5 lines)

Lines: 178, 186 (`tier1_read` -> `integral_read`), plus `audit_critical` references

### tests/unit/scanner/test_registry_sync.py (8 lines)

Lines: 333, 335 (`_wardline_audit_critical` -> `_wardline_integrity_critical`), plus `audit_critical` references

### tests/unit/scanner/test_corpus_runner.py (3 lines)

Lines: 508, 518, 520 (`"AUDIT_TRAIL"` -> `"INTEGRAL"`)

### tests/unit/scanner/test_rule_base_context.py (2 lines)

Lines: 89, 92 (TaintState.PIPELINE)

### tests/unit/scanner/test_exception_taint_drift.py (11 lines)

Lines: 22, 55, 85, 87, 106, 153, 161, 200, 208, 211, 245 (`"PIPELINE"` and `TaintState.PIPELINE`)

### tests/unit/scanner/taint/test_body_eval_taint.py (12 lines)

Lines: 24-27, 34-39 (decorator name keys and TaintState values)

### tests/unit/scanner/taint/test_variable_callee_resolution.py (7 lines)

Lines: 6, 26, 27, 29, 32, 97, 101, 108 (SHAPE_VALIDATED, PIPELINE, AUDIT_TRAIL references)

### tests/unit/cli/test_fingerprint_cmd.py (13 lines)

Lines: 33, 41 (PIPELINE), 57, 64, 300, 310, 363, 453, 463, 514, 575, 628, 720 (`tier1_read` -> `integral_read`)

### tests/unit/cli/test_coherence_cmd.py (6 lines)

Lines: 42, 56, 97, 104, 109, 113 (PIPELINE string references)

### tests/unit/cli/test_regime_cmd.py (6 lines)

Lines: 78, 86, 98, 112, 129, 133 (PIPELINE string references)

### tests/unit/cli/test_resolve_cmd.py (2 lines)

Lines: 32, 53 (PIPELINE string)

### tests/unit/cli/test_exception_migration.py (13 lines)

Lines: 45, 78, 98, 103, 106, 131, 155, 177, 179, 199, 203, 230, 234, 253 (PIPELINE string, AUDIT_TRAIL)

### tests/unit/manifest/test_loader.py (1 line)

Line: 45 (`"AUDIT_TRAIL"`)

### tests/unit/manifest/test_models.py (1 line)

Line: 179 (`"AUDIT_TRAIL"`)

### tests/unit/manifest/test_resolve.py (2 lines)

Lines: 102, 104 (`"AUDIT_TRAIL"`)

### tests/unit/manifest/test_exceptions.py (2 lines)

Lines: 69, 70 (`"AUDIT_TRAIL"`)

### tests/unit/manifest/test_discovery.py (1 line)

Line: 141 (`"AUDIT_TRAIL"`)

### tests/unit/manifest/test_merge.py (7 lines)

Lines: 273, 275, 279, 280, 303, 304, 308 (PIPELINE, AUDIT_TRAIL strings)

### tests/unit/manifest/test_coherence.py (2 lines)

Lines: 117 (`tier1_read`), 1219 (`UNKNOWN_SEM_VALIDATED`)

### tests/unit/manifest/test_regime.py (1 line)

Line: 130 (`"PIPELINE"`)

### tests/unit/runtime/test_enforcement.py (11 lines)

Lines: 362, 371, 379, 388, 406, 410, 502, 505, 509, 517, 524 (`tier1_read` -> `integral_read`)

### tests/integration/test_explain.py (6 lines)

Lines: 90, 217, 233, 252 (PIPELINE, `tier1_read`)

### tests/integration/test_manifest_cmds.py (1 line)

Line: 23 (`"PIPELINE"`)

### tests/integration/test_exception_cmds.py (12 lines)

Lines: 57, 75, 88, 95, 116, 137, 226, 316, 499, 511, 522, 537 (PIPELINE, AUDIT_TRAIL)

### tests/integration/test_enforcement_integration.py (3 lines)

Lines: 45, 126, 136 (SHAPE_VALIDATED, `tier1_read`)

### tests/fixtures/governance/src/example.py (2 lines)

Lines: 2, 17 (`tier1_read` -> `integral_read`)

### tests/fixtures/governance/wardline.yaml (1 line)

Line: 24 (`"PIPELINE"` -> `"ASSURED"`)

### tests/fixtures/governance/wardline.fingerprint.json (1 line)

Line: 35 (`"tier1_read"` -> `"integral_read"`)

### tests/fixtures/governance/wardline.exceptions.json (1 line)

Line: 45 (`"PIPELINE"` -> `"ASSURED"`)

### tests/fixtures/integration/sample_project/wardline.yaml (1 line)

Line: 12 (`"PIPELINE"` -> `"ASSURED"`)

### tests/fixtures/integration/sample_project/core/processor.py (1 line)

Line: 3 (`PIPELINE` -> `ASSURED` in comment)

---

## Layer 7: Config/Manifests (root)

### wardline.yaml (17 lines)

| Line | Old | New | Context |
|------|-----|-----|---------|
| 27 | `id: "AUDIT_TRAIL"` | `id: "INTEGRAL"` | Tier definition |
| 30 | `id: "PIPELINE"` | `id: "ASSURED"` | Tier definition |
| 33 | `id: "SHAPE_VALIDATED"` | `id: "GUARDED"` | Tier definition |
| 47, 51, 55, 63, 70, 77, 83 | `default_taint: "AUDIT_TRAIL"` | `default_taint: "INTEGRAL"` | Module tier assignments (7 lines) |
| 91, 97, 103, 109, 114, 150 | `default_taint: "PIPELINE"` | `default_taint: "ASSURED"` | Module tier assignments (6 lines) |
| 122, 129, 136, 143 | `default_taint: "SHAPE_VALIDATED"` | `default_taint: "GUARDED"` | Module tier assignments (4 lines) |
| 176 | `# Tier 1 (AUDIT_TRAIL):` | `# Tier 1 (INTEGRAL):` | Comment |
| 185 | `# Tier 2 (PIPELINE):` | `# Tier 2 (ASSURED):` | Comment |
| 193 | `# Tier 3 (SHAPE_VALIDATED):` | `# Tier 3 (GUARDED):` | Comment |

### wardline.manifest.baseline.json (18 lines)

| Line | Old | New | Context |
|------|-----|-----|---------|
| 4 | `"id": "AUDIT_TRAIL"` | `"id": "INTEGRAL"` | Tier definition |
| 9 | `"id": "PIPELINE"` | `"id": "ASSURED"` | Tier definition |
| 14 | `"id": "SHAPE_VALIDATED"` | `"id": "GUARDED"` | Tier definition |
| 27-51 | `"default_taint": "AUDIT_TRAIL"` (7x) | `"default_taint": "INTEGRAL"` | Module tiers |
| 55-71 | `"default_taint": "PIPELINE"` (5x) | `"default_taint": "ASSURED"` | Module tiers |
| 75-83 | `"default_taint": "SHAPE_VALIDATED"` (3x) | `"default_taint": "GUARDED"` | Module tiers |

### wardline.exceptions.json (~61 lines)

All `"taint_state": "AUDIT_TRAIL"` (10 occurrences), `"taint_state": "PIPELINE"` (26 occurrences), `"taint_state": "SHAPE_VALIDATED"` (25 occurrences) must be updated to `"INTEGRAL"`, `"ASSURED"`, `"GUARDED"` respectively.

### CLAUDE.md (1 line)

| Line | Old | New | Context |
|------|-----|-----|---------|
| 7 | `Tier 1 AUDIT_TRAIL -> Tier 4 EXTERNAL_RAW` | `Tier 1 INTEGRAL -> Tier 4 EXTERNAL_RAW` | Project description |

---

## Layer 8: Corpus

### corpus/corpus_manifest.json (~311 lines)

All taint state string values in this JSON file: `"AUDIT_TRAIL"` (60 occurrences), `"PIPELINE"` (86 occurrences), `"SHAPE_VALIDATED"` (111 occurrences, includes UNKNOWN variants), `"UNKNOWN_SHAPE_VALIDATED"` (54 occurrences), `"UNKNOWN_SEM_VALIDATED"` (54 occurrences).

### corpus/specimens/ YAML files (74 files, 3 lines each typically)

Each specimen YAML contains a `taint_state:` field and often the taint state name in the file name and description. Affected files include all specimens under the 5 renamed taint state directories across PY-WL-001 through PY-WL-009, plus L3 specimens and adversarial specimens.

Representative pattern (repeated per rule per taint state):
- `corpus/specimens/PY-WL-001/AUDIT_TRAIL/positive/PY-WL-001-TP-AUDIT_TRAIL.yaml` (3 lines)
- `corpus/specimens/PY-WL-001/AUDIT_TRAIL/negative/PY-WL-001-TN-AUDIT_TRAIL.yaml` (3 lines)

Plus additional specimen files:
- `corpus/specimens/PY-WL-006/AUDIT_TRAIL/positive/PY-WL-006-TP-AFN-audit-in-broad-handler.yaml` (1 line)
- `corpus/specimens/PY-WL-006/AUDIT_TRAIL/negative/PY-WL-006-TN-AFP-logger-not-audit.yaml` (1 line)
- `corpus/specimens/adversarial/ADV-014-hasattr-taint-gate.yaml` (2 lines)
- `corpus/specimens/adversarial/ADV-006-decorator-stack.yaml` (1 line)
- Various L3 specimens (6 files, references to `tier1_read`, AUDIT_TRAIL, PIPELINE, SHAPE_VALIDATED)

### scripts/generate_corpus.py (10 lines)

Lines: 23-25, 28-29 (TaintState enum refs), 250, 294, 305, 338, 349 (string literals)

---

## Layer 9: Spec Documents

### docs/spec/wardline-01-06-authority-tier-enforcement-spec.md

~20 occurrences of AUDIT_TRAIL, PIPELINE, SHAPE_VALIDATED, UNKNOWN_SHAPE_VALIDATED, UNKNOWN_SEM_VALIDATED in spec prose.

### docs/spec/wardline-01-07-annotation-vocabulary.md

References to `audit_writer`, `authoritative_construction`, `tier1_read`, and taint state names.

### docs/spec/wardline-01-08-pattern-rules.md

~14 occurrences of taint state names in rule descriptions.

### docs/spec/wardline-01-10-governance-model.md

~2 occurrences (AUDIT_TRAIL, PIPELINE).

### docs/spec/wardline-01-11-verification-properties.md

~20 occurrences of taint state names and `tier1_read` references.

### docs/spec/wardline-01-12-language-evaluation-criteria.md

References to `tier1_read`.

### docs/spec/wardline-01-13-residual-risks.md

1 occurrence (SHAPE_VALIDATED).

### docs/spec/wardline-01-14-portability-and-manifest-format.md

~7 occurrences (SHAPE_VALIDATED, PIPELINE, `authoritative_construction`).

### docs/spec/wardline-01-15-conformance.md

~17 occurrences of taint state names.

### docs/spec/wardline-02-A-python-binding.md

~26 occurrences: all decorator names (`audit_writer`, `audit_critical`, `tier1_read`, `authoritative_construction`) and taint state names in the decorator table, combination table, and code examples.

### docs/spec/wardline-02-B-java-binding.md

~7 occurrences of taint state names.

### docs/spec/semantic-equivalents/py-wl-006.md

References to `@audit_writer` and `_AUDIT_FUNC_NAMES`.

---

## Layer 10a: Active Design & Requirements Documents (UPDATE)

These documents describe **current architecture and requirements** — they must
track the rename so readers see names that match the code.

### Design documents (docs/design/)

- `2026-03-21-wardline-python-design.md` — 13 lines (decorator names, taint states, `_wardline_audit_*` attrs)
- `2026-03-24-l3-callgraph-taint-design.md` — 13 lines (taint states, `tier1_read`)
- `2026-03-24-runtime-enforcement-design.md` — 4 lines (taint states)
- `2026-03-24-governance-cli-design.md` — 3 lines (`tier1_read`, PIPELINE)
- `2026-03-24-flake8-plugin-design.md` — 1 line (AUDIT_TRAIL)
- `2026-03-25-audit-remediation-phase1-design.md` — 21 lines (decorator names, taint states)

### Requirements fitness docs (docs/requirements/spec-fitness/)

- `01-framework-core.yaml` — 7 lines
- `02-manifest-governance.yaml` — 1 line
- `03-scanner-conformance.yaml` — 1 line
- `04-python-binding.yaml` — 1 line

### Verified clean (no old name references)

- `AGENTS.md` — checked, no references to old taint state or decorator names
- `README.md` — checked, no references to old taint state or decorator names
- `docs/superpowers/` — all 4 files checked, no references to old names

---

## Layer 10b: Archived Documents (DO NOT UPDATE)

These are **point-in-time historical records** — audit findings, completed plans,
session logs, and archived documents. They used the names that were current when
written. Updating them rewrites history. Leave as-is; they live in git.

### Audit documents (docs/audits/)

- `rule-conformance-audit-2026-03-25.md` — 1 line
- `phase-1/phase-1-synthesis.md` — 2 lines
- `phase-1/group-a/` — 4 files, ~24 lines total
- `phase-1/group-b/` — 6 files, ~68 lines total
- `phase-1/group-c/` — 4 files, ~40 lines total
- `phase-1/group-d/` — 5 files, ~36 lines total
- `phase-2/f1/` — 4 files, ~27 lines
- `phase-2/f2/` — 1 file, ~15 lines
- `phase-2/f3/` — 1 file, ~2 lines
- `synthesis.md` — 3 lines

### Plan documents (docs/plans/) — completed work products

- `2026-03-24-wp-2.1-l3-callgraph-taint.md` — 14 lines
- `2026-03-24-wp-2.3a-governance-cli.md` — 1 line
- `2026-03-24-wp-3.2-runtime-enforcement.md` — 11 lines
- `2026-03-25-audit-remediation-phase1.md` — 30 lines
- `2026-03-25-py-wl-006-audit-path-dominance.md` — 7 lines
- `2026-03-25-authoritative-groups-7-15-reconciliation.md` — 1 line

### Archive documents (docs/archive/)

- `2026-03-22-execution-sequence.md` — 3 lines
- `2026-03-22-filigree-population-plan.md` — 1 line
- `2026-03-23-fingerprint-hashing-scheme.md` — 2 lines
- `2026-03-24-rust-migration-feasibility.md` — 2 lines
- `05-quality-assessment.md` — 7 lines
- `2026-03-23-engine-taint-wiring.md` — 28 lines
- `2026-03-23-overlay-system.md` — 6 lines
- `2026-03-23-exception-register.md` — 2 lines
- `2026-03-23-overlay-system.errata.md` — 2 lines
- `2026-03-23-overlay-system-design.md` — 1 line

### Session log

- `docs/session-log-2026-03-28.md` — 2 lines (SHAPE_VALIDATED, PIPELINE)

---

## Layer 11: ADR and Verification Documents

These documents describe the rename itself and should be updated to reflect
completion, but the old names should be PRESERVED in the "before" columns
and historical context:

- `docs/adr/ADR-001-rename-taint-states-to-posture-vocabulary.md` — Update status to "accepted/completed"; old names remain in the mapping tables as the "from" column
- `docs/adr/ADR-002-rename-tier-source-decorators.md` — Same treatment
- `docs/verification/RENAME-EXECUTE-PROMPT.md` — References to old names in the execution plan
- `docs/verification/RENAME-IMPACT-PROMPT.md` — References to old names (this is the prompt that generated this manifest)
- `docs/verification/MINISPEC-PROMPT.md` — References to taint state names

---

## Directory Renames

45 corpus specimen directories require `git mv`:

| Old Path | New Path |
|----------|----------|
| `corpus/specimens/PY-WL-001/AUDIT_TRAIL/` | `corpus/specimens/PY-WL-001/INTEGRAL/` |
| `corpus/specimens/PY-WL-001/PIPELINE/` | `corpus/specimens/PY-WL-001/ASSURED/` |
| `corpus/specimens/PY-WL-001/SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-001/GUARDED/` |
| `corpus/specimens/PY-WL-001/UNKNOWN_SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-001/UNKNOWN_GUARDED/` |
| `corpus/specimens/PY-WL-001/UNKNOWN_SEM_VALIDATED/` | `corpus/specimens/PY-WL-001/UNKNOWN_ASSURED/` |
| `corpus/specimens/PY-WL-002/AUDIT_TRAIL/` | `corpus/specimens/PY-WL-002/INTEGRAL/` |
| `corpus/specimens/PY-WL-002/PIPELINE/` | `corpus/specimens/PY-WL-002/ASSURED/` |
| `corpus/specimens/PY-WL-002/SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-002/GUARDED/` |
| `corpus/specimens/PY-WL-002/UNKNOWN_SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-002/UNKNOWN_GUARDED/` |
| `corpus/specimens/PY-WL-002/UNKNOWN_SEM_VALIDATED/` | `corpus/specimens/PY-WL-002/UNKNOWN_ASSURED/` |
| `corpus/specimens/PY-WL-003/AUDIT_TRAIL/` | `corpus/specimens/PY-WL-003/INTEGRAL/` |
| `corpus/specimens/PY-WL-003/PIPELINE/` | `corpus/specimens/PY-WL-003/ASSURED/` |
| `corpus/specimens/PY-WL-003/SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-003/GUARDED/` |
| `corpus/specimens/PY-WL-003/UNKNOWN_SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-003/UNKNOWN_GUARDED/` |
| `corpus/specimens/PY-WL-003/UNKNOWN_SEM_VALIDATED/` | `corpus/specimens/PY-WL-003/UNKNOWN_ASSURED/` |
| `corpus/specimens/PY-WL-004/AUDIT_TRAIL/` | `corpus/specimens/PY-WL-004/INTEGRAL/` |
| `corpus/specimens/PY-WL-004/PIPELINE/` | `corpus/specimens/PY-WL-004/ASSURED/` |
| `corpus/specimens/PY-WL-004/SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-004/GUARDED/` |
| `corpus/specimens/PY-WL-004/UNKNOWN_SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-004/UNKNOWN_GUARDED/` |
| `corpus/specimens/PY-WL-004/UNKNOWN_SEM_VALIDATED/` | `corpus/specimens/PY-WL-004/UNKNOWN_ASSURED/` |
| `corpus/specimens/PY-WL-005/AUDIT_TRAIL/` | `corpus/specimens/PY-WL-005/INTEGRAL/` |
| `corpus/specimens/PY-WL-005/PIPELINE/` | `corpus/specimens/PY-WL-005/ASSURED/` |
| `corpus/specimens/PY-WL-005/SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-005/GUARDED/` |
| `corpus/specimens/PY-WL-005/UNKNOWN_SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-005/UNKNOWN_GUARDED/` |
| `corpus/specimens/PY-WL-005/UNKNOWN_SEM_VALIDATED/` | `corpus/specimens/PY-WL-005/UNKNOWN_ASSURED/` |
| `corpus/specimens/PY-WL-006/AUDIT_TRAIL/` | `corpus/specimens/PY-WL-006/INTEGRAL/` |
| `corpus/specimens/PY-WL-006/PIPELINE/` | `corpus/specimens/PY-WL-006/ASSURED/` |
| `corpus/specimens/PY-WL-006/SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-006/GUARDED/` |
| `corpus/specimens/PY-WL-006/UNKNOWN_SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-006/UNKNOWN_GUARDED/` |
| `corpus/specimens/PY-WL-006/UNKNOWN_SEM_VALIDATED/` | `corpus/specimens/PY-WL-006/UNKNOWN_ASSURED/` |
| `corpus/specimens/PY-WL-007/AUDIT_TRAIL/` | `corpus/specimens/PY-WL-007/INTEGRAL/` |
| `corpus/specimens/PY-WL-007/PIPELINE/` | `corpus/specimens/PY-WL-007/ASSURED/` |
| `corpus/specimens/PY-WL-007/SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-007/GUARDED/` |
| `corpus/specimens/PY-WL-007/UNKNOWN_SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-007/UNKNOWN_GUARDED/` |
| `corpus/specimens/PY-WL-007/UNKNOWN_SEM_VALIDATED/` | `corpus/specimens/PY-WL-007/UNKNOWN_ASSURED/` |
| `corpus/specimens/PY-WL-008/AUDIT_TRAIL/` | `corpus/specimens/PY-WL-008/INTEGRAL/` |
| `corpus/specimens/PY-WL-008/PIPELINE/` | `corpus/specimens/PY-WL-008/ASSURED/` |
| `corpus/specimens/PY-WL-008/SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-008/GUARDED/` |
| `corpus/specimens/PY-WL-008/UNKNOWN_SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-008/UNKNOWN_GUARDED/` |
| `corpus/specimens/PY-WL-008/UNKNOWN_SEM_VALIDATED/` | `corpus/specimens/PY-WL-008/UNKNOWN_ASSURED/` |
| `corpus/specimens/PY-WL-009/AUDIT_TRAIL/` | `corpus/specimens/PY-WL-009/INTEGRAL/` |
| `corpus/specimens/PY-WL-009/PIPELINE/` | `corpus/specimens/PY-WL-009/ASSURED/` |
| `corpus/specimens/PY-WL-009/SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-009/GUARDED/` |
| `corpus/specimens/PY-WL-009/UNKNOWN_SHAPE_VALIDATED/` | `corpus/specimens/PY-WL-009/UNKNOWN_GUARDED/` |
| `corpus/specimens/PY-WL-009/UNKNOWN_SEM_VALIDATED/` | `corpus/specimens/PY-WL-009/UNKNOWN_ASSURED/` |

**Note:** Files inside these directories also need their filenames renamed
(e.g., `PY-WL-001-TP-AUDIT_TRAIL.yaml` -> `PY-WL-001-TP-INTEGRAL.yaml`).
These file renames happen implicitly with `git mv` of the parent directory,
but the YAML content inside also references the old taint state name.

---

## Source File Renames

| Old Path | New Path |
|----------|----------|
| `src/wardline/decorators/audit.py` | `src/wardline/decorators/integrity.py` |
| `tests/unit/decorators/test_audit.py` | `tests/unit/decorators/test_integrity.py` |

**Import chain updates required:**
- `src/wardline/decorators/__init__.py` line 4: `from .audit import ...` → `from .integrity import ...`

---

## Corpus File Renames (inside directories)

Specimen YAML files with old names in their filenames. Each directory above
contains 2 standard files (positive/negative) with the taint state in the
name. 9 rules x 5 taint states x 2 files = 90 file renames.

Representative pattern:
- `PY-WL-001-TP-AUDIT_TRAIL.yaml` -> `PY-WL-001-TP-INTEGRAL.yaml`
- `PY-WL-001-TN-AUDIT_TRAIL.yaml` -> `PY-WL-001-TN-INTEGRAL.yaml`
- `PY-WL-004-TP-UNKNOWN_SHAPE_VALIDATED.yaml` -> `PY-WL-004-TP-UNKNOWN_GUARDED.yaml`

---

## Ordering Constraints

1. **Directory renames before file content updates.** If using `git mv` for
   directories, do it before sed/replace operations on file content --
   otherwise the paths in the sed commands will be wrong.

2. **Schema files before test execution.** JSON schema enum values must be
   updated before any test run that validates corpus specimens against
   the schema.

3. **core/taints.py first.** This is the source of truth. Every other file
   imports or references these enum members. Rename here first, then
   propagate outward.

4. **Decorators before scanner.** The scanner reads decorator canonical
   names from the decorators package. Update decorators, then scanner
   rules that reference those names.

5. **YAML/JSON configs after source.** The `wardline.yaml`, schemas, and
   `wardline.exceptions.json` contain string values that must match the
   enum member values (the string representation).

6. **corpus_manifest.json after directory renames.** The manifest indexes
   specimens by path; paths must match after renames.

7. **Token replacement order within each file** (critical):
   - `UNKNOWN_SHAPE_VALIDATED` before `SHAPE_VALIDATED`
   - `UNKNOWN_SEM_VALIDATED` before any shorter match
   - `authoritative_construction` before shorter matches
   - `audit_writer` before `audit` (but `audit_critical` is distinct)

---

## Risk Areas

### 1. Partial-match corruption (HIGH RISK)

`SHAPE_VALIDATED` is a substring of `UNKNOWN_SHAPE_VALIDATED`. A naive
`sed s/SHAPE_VALIDATED/GUARDED/g` would corrupt `UNKNOWN_SHAPE_VALIDATED`
to `UNKNOWN_GUARDED` (the wrong name -- should be `UNKNOWN_GUARDED` which
happens to be correct in this case). However, the replacement order still
matters because `UNKNOWN_SHAPE_VALIDATED` must become `UNKNOWN_GUARDED`
(not `UNKNOWN_GUARDED` via the SHAPE_VALIDATED->GUARDED replacement
applied to the UNKNOWN_ prefix, which would produce the same result only
by coincidence).

**Mitigation:** Always replace `UNKNOWN_SHAPE_VALIDATED` first, then
`SHAPE_VALIDATED`. Verify with a second grep pass after replacement.

### 2. String serialization in SARIF output (HIGH RISK)

`TaintState` is a `StrEnum` -- its `str()` output equals its value.
After the rename, `str(TaintState.INTEGRAL) == "INTEGRAL"`. SARIF output,
corpus matching, and exception register all use the string value. These
must all be updated consistently.

### 3. `_wardline_audit_writer` / `_wardline_audit_critical` attribute names (HIGH RISK)

These are runtime function attributes set by decorators and read by the
scanner. The rename changes:
- `_wardline_audit_writer` -> `_wardline_integral_writer`
- `_wardline_audit_critical` -> `_wardline_integrity_critical`

Every test that asserts on these attribute names must be updated. The
decorator definitions and the registry entries must match.

### 4. The `_AUDIT_DECORATORS` frozenset in py_wl_006.py (MEDIUM RISK)

This set contains the decorator **canonical names** (currently
`"audit_writer"`, `"audit_critical"`). After the rename, these become
`"integral_writer"`, `"integrity_critical"`. The variable should also be
renamed to `_INTEGRITY_DECORATORS` for consistency.

### 5. PY-WL-006 audit heuristic names (LOW RISK -- OUT OF SCOPE)

The functions `_looks_audit_scoped`, `_is_audit_call`, `_AUDIT_FUNC_NAMES`,
`_AUDIT_ATTR_PREFIXES`, and `_local_audit_names` in `py_wl_006.py` refer to
the **audit detection feature** (the rule still detects "audit-critical
writes in broad handlers"). These are heuristic identifiers for the rule's
detection logic, not references to the decorator names. They do NOT need
to be renamed as part of ADR-001/ADR-002. The decorator *names* they
look for (in `_AUDIT_DECORATORS`) DO need updating.

### 6. The `audit.py` file rename (MEDIUM RISK — IN SCOPE)

`src/wardline/decorators/audit.py` defines `@audit_critical` (renamed to
`@integrity_critical`). The file must be renamed to `integrity.py` to
match. This changes the import path (`wardline.decorators.audit` ->
`wardline.decorators.integrity`), which affects:

- `src/wardline/decorators/__init__.py` (line 4) — update import
- `tests/unit/decorators/test_audit.py` — rename to `test_integrity.py`

**Added to file renames:**

| Old Path | New Path |
|----------|----------|
| `src/wardline/decorators/audit.py` | `src/wardline/decorators/integrity.py` |
| `tests/unit/decorators/test_audit.py` | `tests/unit/decorators/test_integrity.py` |

### 7. `validates_semantic` and `validates_external` transition tuples (MEDIUM RISK)

These decorators use taint states in their transition tuples that are being
renamed:
- `validates_shape`: `(EXTERNAL_RAW, SHAPE_VALIDATED)` -> `(EXTERNAL_RAW, GUARDED)`
- `validates_semantic`: `(SHAPE_VALIDATED, PIPELINE)` -> `(GUARDED, ASSURED)`
- `validates_external`: `(EXTERNAL_RAW, PIPELINE)` -> `(EXTERNAL_RAW, ASSURED)`
- `authoritative_construction`: `(PIPELINE, AUDIT_TRAIL)` -> `(ASSURED, INTEGRAL)`

These are in `decorators/authority.py` and must be updated.

### 8. Exception register taint drift (MEDIUM RISK)

`wardline.exceptions.json` contains `"taint_state"` fields with old names.
The exception migration CLI (`wardline exception migrate`) may need to
handle both old and new names during the transition period. Existing
exceptions referencing `"PIPELINE"` must be updated to `"ASSURED"` etc.

### 9. Test function/class names containing old names (LOW RISK)

Several test methods contain old names:
- `test_audit_trail_is_error` -> `test_integral_is_error`
- `test_tier1_read_gets_audit_trail` -> `test_integral_read_gets_integral`
- `test_audit_writer_gets_audit_trail` -> `test_integral_writer_gets_integral`
- `test_authoritative_construction_gets_audit_trail` -> `test_integral_construction_gets_integral`
- `test_audit_trail_produces_error_unconditional` -> `test_integral_produces_error_unconditional`
- `test_literal_gets_audit_trail` -> `test_literal_gets_integral`
- `test_restoration_full_evidence_audit_trail` -> `test_restoration_full_evidence_integral`
- etc.

These are not functional but should be renamed for consistency.

### 10. Backward compatibility / migration period (DESIGN DECISION)

After the rename, any existing `wardline.yaml` files in downstream projects
using `AUDIT_TRAIL`, `PIPELINE`, etc. will fail schema validation. Consider:
- Adding backward-compatible aliases in the manifest loader
- Or documenting the migration as a breaking change for v1.0

### 11. corpus_manifest.json is generated — REGENERATE, DON'T SED (LOW RISK)

`corpus/corpus_manifest.json` is generated by `scripts/generate_corpus.py`.
**Do not manually edit this file.** After renaming the specimen
directories/files and updating the generator script's references,
regenerate the manifest:

```bash
uv run python scripts/generate_corpus.py
```

The ~311 lines of changes listed in Layer 7 for this file are informational
only — they show what will change after regeneration, not manual edits to make.
