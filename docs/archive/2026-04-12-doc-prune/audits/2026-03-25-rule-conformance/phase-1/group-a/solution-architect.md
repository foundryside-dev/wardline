# Group A -- Solution Architect Assessment

Audit date: 2026-03-25
Rules: PY-WL-001, PY-WL-002, PY-WL-003
Spec references: Part I SS7.1, SS7.2.1, SS7.3; Part II-A SS A.3, SS A.4.2

---

## 1. Severity Matrix Conformance

### Method

Each rule delegates to `matrix.lookup(self.RULE_ID, taint)` (confirmed in all three
`_emit_finding` methods). The matrix is encoded in `src/wardline/core/matrix.py` lines
45-51. Column order is verified at lines 32-41 against the eight canonical taint states.
Verification is therefore cell-by-cell comparison of `_MATRIX_DATA` rows against the
spec SS7.3 table.

### PY-WL-001 (inherits WL-001)

Spec WL-001 row: E/U, E/St, E/St, E/St, E/St, E/St, E/St, E/St

Implementation (`matrix.py` line 47):
```
(RuleId.PY_WL_001, [(_E,_U), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St)])
```

| Column           | Spec  | Impl  | Verdict |
|------------------|-------|-------|---------|
| AUDIT_TRAIL      | E/U   | E/U   | PASS    |
| PIPELINE         | E/St  | E/St  | PASS    |
| SHAPE_VALIDATED  | E/St  | E/St  | PASS    |
| EXTERNAL_RAW     | E/St  | E/St  | PASS    |
| UNKNOWN_RAW      | E/St  | E/St  | PASS    |
| UNKNOWN_SHAPE_V  | E/St  | E/St  | PASS    |
| UNKNOWN_SEM_V    | E/St  | E/St  | PASS    |
| MIXED_RAW        | E/St  | E/St  | PASS    |

**Result: 8/8 PASS**

### PY-WL-002 (inherits WL-001)

Spec WL-001 row (inherited per SS A.3 rule mapping): E/U, E/St, E/St, E/St, E/St, E/St, E/St, E/St

Implementation (`matrix.py` line 49):
```
(RuleId.PY_WL_002, [(_E,_U), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St)])
```

| Column           | Spec  | Impl  | Verdict |
|------------------|-------|-------|---------|
| AUDIT_TRAIL      | E/U   | E/U   | PASS    |
| PIPELINE         | E/St  | E/St  | PASS    |
| SHAPE_VALIDATED  | E/St  | E/St  | PASS    |
| EXTERNAL_RAW     | E/St  | E/St  | PASS    |
| UNKNOWN_RAW      | E/St  | E/St  | PASS    |
| UNKNOWN_SHAPE_V  | E/St  | E/St  | PASS    |
| UNKNOWN_SEM_V    | E/St  | E/St  | PASS    |
| MIXED_RAW        | E/St  | E/St  | PASS    |

**Result: 8/8 PASS**

### PY-WL-003 (inherits WL-002)

Spec WL-002 row: E/U, E/U, E/U, E/St, E/St, E/U, E/U, E/St

Implementation (`matrix.py` line 51):
```
(RuleId.PY_WL_003, [(_E,_U), (_E,_U), (_E,_U), (_E,_St), (_E,_St), (_E,_U), (_E,_U), (_E,_St)])
```

| Column           | Spec  | Impl  | Verdict |
|------------------|-------|-------|---------|
| AUDIT_TRAIL      | E/U   | E/U   | PASS    |
| PIPELINE         | E/U   | E/U   | PASS    |
| SHAPE_VALIDATED  | E/U   | E/U   | PASS    |
| EXTERNAL_RAW     | E/St  | E/St  | PASS    |
| UNKNOWN_RAW      | E/St  | E/St  | PASS    |
| UNKNOWN_SHAPE_V  | E/U   | E/U   | PASS    |
| UNKNOWN_SEM_V    | E/U   | E/U   | PASS    |
| MIXED_RAW        | E/St  | E/St  | PASS    |

**Result: 8/8 PASS**

### Matrix Summary

All 24 cells across three rules match the spec exactly. No deviations.

---

## 2. Interface Contract Conformance

### Point 3: schema_default() recognition (PY-WL-001)

**Spec requirement (SS A.3 point 3):** The tool MUST recognise `schema_default()` as a
PY-WL-001 suppression marker. Suppression requires: (1) overlay field declaration,
(2) default value match, and (3) validation boundary context.

**Implementation** (`py_wl_001.py` lines 196-266):

The `_emit_schema_default_finding` method checks three conditions before emitting
SUPPRESS (lines 210-214):

1. `optional_field is not None` -- overlay field declaration exists via
   `_find_matching_optional_field` (line 208), which searches `self._context.optional_fields`
   for a matching field name within scope.
2. `default_value == optional_field.approved_default` -- exact default value match
   (line 212).
3. `self._is_governed_by_boundary(optional_field.overlay_scope)` -- validation boundary
   context check (line 213). The `_is_governed_by_boundary` method (lines 290-310) verifies:
   qualname match, governance-relevant transition type (`_GOVERNED_TRANSITIONS` at line 41),
   and overlay scope path containment.

When all three conditions are met: emits `PY-WL-001-GOVERNED-DEFAULT` with
`Severity.SUPPRESS` and `Exceptionability.TRANSPARENT` (lines 215-234).

When conditions are NOT met: emits `PY-WL-001-UNGOVERNED-DEFAULT` with `Severity.ERROR`
(lines 235-266). When the default value explicitly mismatches the approved default,
exceptionability escalates to UNCONDITIONAL (lines 241-249), consistent with SS7.2.1's
mismatch severity rule.

The `_unwrap_schema_default_get` method (lines 134-145) correctly identifies the
`schema_default(d.get(...))` wrapping pattern, and the `handled_calls` set in
`visit_function` (lines 65-74) prevents double-counting the inner `.get()` call.

**Result: PASS** -- All three suppression conditions are implemented correctly.

### Point 5: Rule ID declaration

- PY-WL-001: `RULE_ID = RuleId.PY_WL_001` (line 40) -- PASS
- PY-WL-002: `RULE_ID = RuleId.PY_WL_002` (line 29) -- PASS
- PY-WL-003: `RULE_ID = RuleId.PY_WL_003` (line 47) -- PASS

All three use the `RuleId` enum (StrEnum with hyphenated values), and the values are
defined in `severity.py` lines 38-40:
- `PY_WL_001 = "PY-WL-001"`
- `PY_WL_002 = "PY-WL-002"`
- `PY_WL_003 = "PY-WL-003"`

**Result: PASS**

### Point 4: SARIF property bag keys

**Spec requirement (SS A.3 point 4):** Each `result` object must carry five mandatory
property bag keys: `wardline.rule`, `wardline.taintState`, `wardline.severity`,
`wardline.exceptionability`, `wardline.analysisLevel`.

**Implementation** (`sarif.py` lines 113-145, `_make_result` function):

The `properties` dict is built at lines 115-127:
- `wardline.rule`: `str(finding.rule_id)` -- PRESENT
- `wardline.taintState`: `str(finding.taint_state)` -- PRESENT (conditionally: only
  when `finding.taint_state` is truthy, via `_clean_none`)
- `wardline.severity`: `str(finding.severity)` -- PRESENT
- `wardline.exceptionability`: `str(finding.exceptionability)` -- PRESENT
- `wardline.analysisLevel`: `finding.analysis_level` -- PRESENT

**CONCERN:** The `wardline.taintState` key is wrapped in a conditional
(`str(finding.taint_state) if finding.taint_state else None`) and then
`_clean_none` strips None values. If `taint_state` is None, the key will be absent
from the property bag. All three Group A rules populate `taint_state` via
`_get_function_taint()` which defaults to `UNKNOWN_RAW` (never None) when no context
is set. However, the SARIF layer does not enforce the contract -- a Finding constructed
elsewhere with `taint_state=None` would produce a non-conformant result. This is a
defensive-depth concern at the SARIF layer, not a conformance failure for these three
rules specifically.

**Result: PASS for Group A rules** (all three always populate taint_state).
Architectural note: the SARIF layer should enforce the mandatory key contract
independently of rule implementations.

---

## 3. Pattern Coverage

### PY-WL-001: Dict key access with fallback default

Spec patterns (SS A.3 rule mapping table):
`.get()`, `.setdefault()`, `collections.defaultdict`

| Pattern                              | Implementation                              | Verdict |
|--------------------------------------|---------------------------------------------|---------|
| `d.get(key, default)` (2+ args)     | Line 87-88: `_is_method_call(call, "get") and len(call.args) >= 2` | PASS |
| `d.setdefault(key, default)` (2+ args) | Lines 91-93: `_is_method_call(call, "setdefault") and len(call.args) >= 2` | PASS |
| `defaultdict(factory)` (1+ args)    | Lines 96-98: `_is_defaultdict_call(call)`, checks both bare `defaultdict` and `collections.defaultdict` (lines 109-123) | PASS |
| `schema_default(d.get(...))` suppression | Lines 71-74, 82-84, 196-266: full three-condition suppression mechanism | PASS |

**Result: PASS** -- All specified patterns are detected.

### PY-WL-002: Attribute access with fallback default

Spec patterns (SS A.3 rule mapping table):
`getattr()` with default

| Pattern                              | Implementation                              | Verdict |
|--------------------------------------|---------------------------------------------|---------|
| `getattr(obj, name, default)` (3-arg) | Lines 54-59: `call.func.id == "getattr" and len(call.args) >= 3` | PASS |
| `obj.attr or default` (BoolOp)      | Lines 62-72: detects `Or` with attribute LHS | PASS (extension) |

The `obj.attr or default` pattern is not listed in the SS A.3 mapping table but is a
semantic equivalent of attribute-access-with-fallback. Per SS7.1 paragraph 2
("Language bindings MUST maintain version-tracked lists of semantic equivalents"),
this is a conformant extension.

**Result: PASS**

### PY-WL-003: Existence-checking as structural gate

Spec patterns (SS A.3 rule mapping table):
`if key in dict`, `hasattr()`, match/case patterns

| Pattern                              | Implementation                              | Verdict |
|--------------------------------------|---------------------------------------------|---------|
| `key in dict` / `key not in dict`   | Lines 101-117: checks `ast.In` and `ast.NotIn` operators in Compare nodes | PASS |
| `hasattr(obj, name)`                | Lines 119-133: checks `call.func.id == "hasattr"` | PASS |
| `match/case` MatchMapping           | Lines 68-76: checks `ast.MatchMapping` | PASS |
| `match/case` MatchClass             | Lines 76-83: checks `ast.MatchClass` | PASS |
| Structural validation boundary suppression | Lines 85-99: suppresses inside shape/combined/external validation boundaries | PASS |

**Result: PASS** -- All specified patterns are detected, plus structural-validation
boundary suppression is correctly implemented.

---

## 4. Architectural Fit

### Subclass RuleBase

- PY-WL-001: `class RulePyWl001(RuleBase)` (line 33) -- PASS
- PY-WL-002: `class RulePyWl002(RuleBase)` (line 22) -- PASS
- PY-WL-003: `class RulePyWl003(RuleBase)` (line 40) -- PASS

### Uses walk_skip_nested_defs

- PY-WL-001: `for child in walk_skip_nested_defs(node)` (line 66) -- PASS
- PY-WL-002: `for child in walk_skip_nested_defs(node)` (line 42) -- PASS
- PY-WL-003: `for child in walk_skip_nested_defs(node)` (line 63) -- PASS

### Delegates to matrix.lookup

- PY-WL-001: `cell = matrix.lookup(self.RULE_ID, taint)` (line 174) -- PASS
- PY-WL-002: `cell = matrix.lookup(self.RULE_ID, taint)` (line 81) -- PASS
- PY-WL-003: `cell = matrix.lookup(RuleId.PY_WL_003, taint)` (line 143) -- PASS

Note: PY-WL-003 uses the literal `RuleId.PY_WL_003` instead of `self.RULE_ID`.
Functionally identical since `RULE_ID = RuleId.PY_WL_003`, but inconsistent with
the pattern used by PY-WL-001 and PY-WL-002. Minor style inconsistency, not a
conformance issue.

### Implements visit_function

All three rules implement `visit_function(self, node, *, is_async)` -- the abstract
method required by RuleBase. None override `visit_FunctionDef` or
`visit_AsyncFunctionDef` (enforced by RuleBase's `__init_subclass__`).

### Finding construction

All three rules construct `Finding` dataclasses with all required fields populated:
`rule_id`, `file_path`, `line`, `col`, `end_line`, `end_col`, `message`, `severity`,
`exceptionability`, `taint_state`, `analysis_level`, `source_snippet`, `qualname`.

**Result: PASS** -- All three rules follow the established engine integration pattern.

---

## 5. Verdict: PASS

All three Group A rules are fully conformant with the spec:

- **24/24 severity matrix cells match exactly** -- zero deviations from SS7.3.
- **schema_default() three-condition suppression** is correctly implemented with
  mismatch escalation to UNCONDITIONAL per SS7.2.1.
- **Rule IDs** are correctly declared via `RuleId` StrEnum.
- **SARIF property bags** carry all five mandatory keys for findings produced by
  these rules.
- **Pattern coverage** matches or exceeds the SS A.3 mapping table.
- **Architectural pattern** (RuleBase subclass, walk_skip_nested_defs,
  matrix.lookup delegation) is consistently followed.

One architectural observation (not a conformance finding): the SARIF layer's
`_make_result` allows `wardline.taintState` to be absent when `taint_state` is None.
The Group A rules never produce None taint states, so this is not a conformance
failure for this group, but the SARIF layer lacks independent enforcement of the
mandatory-key contract from SS A.3 point 4.
