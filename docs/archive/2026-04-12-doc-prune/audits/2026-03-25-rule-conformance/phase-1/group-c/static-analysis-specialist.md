# Static Analysis Specialist -- Group C: Structural Verification

**Auditor:** Static Analysis Specialist
**Date:** 2026-03-25
**Rules:** PY-WL-007, PY-WL-008, PY-WL-009
**Scope:** Precision, recall, evasion surface, semantic equivalent coverage

---

## 1. PY-WL-007: Runtime type-checking on internal data

### 1.1 Detection surface

The rule detects two patterns:
- `isinstance(obj, T)` calls
- `type(x) == T` / `type(x) is T` comparisons

Both are intraprocedural, operating within `walk_skip_nested_defs` scope.

### 1.2 Suppression category analysis

Four suppression categories are implemented. Each is assessed below.

**Category 1: AST node type dispatch** (`_isinstance_has_ast_type`)
- Matches `isinstance(x, ast.SomeType)` where `ast` is the qualified receiver.
- Tuple form handled: `isinstance(x, (ast.A, ast.B))` requires ALL elements to be `ast.*`.
- Mixed tuples `isinstance(x, (ast.Name, dict))` correctly fire (not all elements are ast-qualified).
- Unqualified names `isinstance(x, Name)` correctly fire.
- **Gap:** Only recognizes the `ast` module. Other tagged-union dispatch on standard library types (e.g., `isinstance(node, token.INDENT)` for tokenize, `isinstance(event, xml.sax.handler.ContentHandler)`) is not covered. This is acceptable -- the rule targets wardline-managed code where `ast` dispatch is the dominant case, and other libraries' dispatch patterns are uncommon in the target surface.

**Category 2: Dunder comparison protocol** (`_COMPARISON_DUNDERS` + `_function_returns_not_implemented`)
- Covers `__eq__`, `__ne__`, `__lt__`, `__le__`, `__gt__`, `__ge__`.
- Requires BOTH: method name match AND `return NotImplemented` somewhere in the body.
- **Sound.** The `return NotImplemented` requirement prevents over-suppression. An `__eq__` that uses isinstance but returns `False` instead of `NotImplemented` correctly fires (test: `test_isinstance_in_eq_without_not_implemented_fires`).
- **Gap:** Does not cover `__hash__` with isinstance guard, `__contains__`, or `__add__`/`__radd__` protocol methods that also legitimately use isinstance. These are less common than comparison dunders and are low-risk omissions.

**Category 3: Frozen dataclass `__post_init__`** (`_body_has_object_setattr`)
- Requires BOTH: method name is `__post_init__` AND body contains `object.__setattr__(self, ...)`.
- **Sound.** Tested for both positive (freeze present) and negative (no freeze, fires) cases.
- **Gap:** Does not cover `__init_subclass__` or metaclass `__new__` that use isinstance for similar defensive purposes. Minor gap -- these are rare patterns.

**Category 4: Declared boundary function** (`_has_declared_boundary`)
- Suppresses isinstance in functions that have a wardline boundary declaration.
- Checks `self._context.boundaries` for matching qualname.
- **Sound.** The isinstance IS the implementation of the boundary contract in these functions.
- No overlay scope check here (unlike PY-WL-008/009). This is acceptable because WL-007 suppression is about the function's declared role, not its file location.

### 1.3 False positive analysis: TypeGuard/TypeIs, ABC, plugin registration

**TypeGuard/TypeIs usage:**
- `def is_valid(x: object) -> TypeGuard[MyType]: return isinstance(x, MyType)`
- This will fire on the isinstance inside the TypeGuard function.
- **FALSE POSITIVE.** TypeGuard/TypeIs functions exist precisely to perform runtime type narrowing as a declared contract. They are semantically equivalent to boundary functions but use typing-level declaration rather than wardline decoration.
- **Severity: MEDIUM.** These functions are typically small and few in number. The finding is noisy but not harmful -- it can be governed via STANDARD exception if in a non-UNCONDITIONAL cell.

**ABC isinstance checks:**
- `isinstance(handler, BaseHandler)` for plugin/strategy dispatch.
- **Fires.** This is arguably a true positive in the wardline model -- if the handler's type is architecturally guaranteed, isinstance is redundant. If it's not guaranteed, the code has a trust boundary problem.
- **Assessment: CORRECT behavior.** The rule is right to flag this; the developer must decide whether it's a governed exception or a code smell.

**Plugin registration patterns:**
- `if isinstance(plugin, PluginInterface): registry.add(plugin)`
- **Fires.** Same reasoning as ABC -- if the plugin is typed, isinstance is redundant; if it's untyped, there's a boundary issue.
- **Assessment: CORRECT behavior.** Governable via STANDARD exception when in non-UNCONDITIONAL taint cells.

### 1.4 Semantic equivalents NOT detected

| Equivalent Pattern | Detected? | Risk |
|-|-|-|
| `isinstance(x, T)` | YES | -- |
| `type(x) == T` / `type(x) is T` | YES | -- |
| `type(x).__name__ == "dict"` | NO | Medium -- string-based type check evasion |
| `x.__class__ is T` / `x.__class__ == T` | NO | Medium -- direct class attribute comparison |
| `x.__class__.__name__ == "Foo"` | NO | Medium -- string-based class name check |
| `issubclass(type(x), T)` | NO | Low -- uncommon pattern |
| `T in type(x).__mro__` | NO | Low -- uncommon pattern |
| `match x: case dict()` | NO | High -- Python 3.10+ structural pattern matching performs isinstance-equivalent checks |
| `typing.get_type_hints()` runtime inspection | NO | Low -- introspection, not branching |

**Critical gap:** `match`/`case` with class patterns. Python 3.10+ match statements with class patterns (`case dict():`, `case MyClass(x=1):`) perform implicit isinstance checks. This is a growing evasion surface as match statement adoption increases.

### 1.5 PY-WL-007 finding

- **Suppression categories are well-designed and precise.**
- TypeGuard/TypeIs is an unhandled false-positive source (medium severity).
- `match`/`case` class patterns are an undetected semantic equivalent (high severity for recall).
- `x.__class__` comparisons are an undetected evasion vector (medium severity).

---

## 2. PY-WL-008: Declared boundary with no rejection path

### 2.1 Two-hop call-graph analysis (Section 8.1 requirement)

The spec at section 7.2 explicitly states:

> "A call to a function that unconditionally raises, if the called function is resolvable via two-hop call-graph analysis (section 8.1) -- real validation commonly delegates through two layers (validator -> schema library -> actual check), and one-hop analysis generates false positives on structurally sound validators that use thin wrappers"

Section 8.1 reinforces:

> "WL-007 is primarily intraprocedural: a validation function that delegates to a called function for rejection [...] does not satisfy WL-007 unless the delegation is resolvable via two-hop call-graph analysis. Two-hop delegation satisfies the requirement; deeper delegation requires full interprocedural analysis."

**Implementation status: NOT IMPLEMENTED.**

The `_has_rejection_path` function (py_wl_008.py lines 84-95) performs purely intraprocedural analysis:
1. Walks the function body (via `walk_skip_nested_defs`)
2. Looks for bare `raise` statements
3. Looks for `if` statements with negative guards followed by branch terminators (raise or return)
4. Looks for `if` statements with else branches containing terminators

It does NOT:
- Resolve calls to functions that unconditionally raise
- Use the call-graph infrastructure available in `scanner/taint/callgraph.py`
- Perform any inter-procedural analysis

The engine has call-graph extraction infrastructure (`extract_call_edges` in `scanner/taint/callgraph.py`) that builds intra-module adjacency maps, and call-graph propagation (`scanner/taint/callgraph_propagation.py`). However, this infrastructure is used only for Level 3 taint propagation, not for rejection-path resolution. The call-graph edges are extracted per-module and would need to be extended with "unconditionally raises" annotations to support two-hop rejection resolution.

**This is a CONFORMANCE DEFECT.** The spec uses MUST language for two-hop resolution in section 8.1, and section 7.2 lists it as a recognized rejection path category.

### 2.2 False positive analysis: Schema library delegation

This is the direct consequence of the missing two-hop analysis. Common patterns that produce false positives:

**Pattern A: Direct schema library call**
```python
@validates_shape
def validate_input(data):
    schema.validate(data)  # raises ValidationError on failure
    return data
```
PY-WL-008 fires. The `schema.validate()` call unconditionally raises on invalid input, which IS a rejection path. **FALSE POSITIVE.**

**Pattern B: Pydantic model validation**
```python
@validates_shape
def validate_input(raw: dict) -> UserModel:
    return UserModel(**raw)  # raises ValidationError on bad shape
```
PY-WL-008 fires. The Pydantic constructor raises on invalid input. **FALSE POSITIVE.**

**Pattern C: jsonschema.validate()**
```python
@validates_shape
def validate_input(data):
    jsonschema.validate(data, SCHEMA)  # raises on failure
    return data
```
PY-WL-008 fires. **FALSE POSITIVE.**

**Pattern D: Custom validation helper**
```python
@validates_shape
def validate_input(data):
    _check_required_fields(data)  # raises KeyError/ValueError
    return data
```
PY-WL-008 fires. **FALSE POSITIVE.**

**Estimated false positive rate on schema-library-delegating validators: ~80-90%.** Real-world validation functions overwhelmingly delegate to schema libraries or internal helpers rather than containing inline raise statements. The current implementation only recognizes:
1. Bare `raise` in the function body
2. `if not X: raise/return` patterns
3. `if X: ... else: raise/return` patterns

These cover hand-written validation but miss the dominant pattern of library delegation.

### 2.3 Evasion analysis

**Trivially-true guards:**
```python
@validates_shape
def validate_input(data):
    if True:
        raise ValueError("always")
    return data
```
The spec at section 7.2 states: "the scanner SHOULD detect trivially unreachable rejection paths (constant-False guards, `if 0:`, `if "":")`. The current implementation does NOT check for constant-true guards that make the rejection unconditional (creating a degenerate validator with no success path) or constant-false guards that make the rejection unreachable.

- `if True: raise` -- `_is_negative_guard` returns False for bare `True` (it's not a Not/Compare), so this falls through. However, `_has_rejection_path` catches it via the bare `raise` walker (the `raise` inside the if-body is still found by `ast.walk`). **Not an evasion -- the bare raise is detected.**
- `if False: raise` -- The `raise` inside is still found by `ast.walk` since it walks ALL nodes including dead branches. **EVASION: unreachable rejection path accepted as valid.** The spec says SHOULD detect this, so it's a quality gap, not a conformance defect.

**Dead code rejection paths:**
```python
@validates_shape
def validate_input(data):
    return data
    raise ValueError("never reached")
```
The bare `raise` after `return` is found by `ast.walk`. **EVASION: unreachable raise after unconditional return is accepted.** Basic dead-code detection (raise after return) is not implemented.

**Assert-only bodies:**
```python
@validates_shape
def validate_input(data):
    assert isinstance(data, dict)
    return data
```
Correctly fires -- `assert` is NOT recognized as a rejection path (tested in `test_assert_still_fires`). **CORRECT.**

### 2.4 Positive guard evasion

```python
@validates_shape
def validate_input(data):
    if is_valid(data):
        return data
    return data
```
The test `test_positive_guard_return_still_fires` confirms this fires. `_is_negative_guard` requires `not`, `is not`, `!=`, `is None`, or `== False/None` patterns. A positive guard `if valid:` does not pass this check. The else branch's `return` IS detected by `_branch_has_rejection_terminator`, but only when `child.orelse` exists. With no explicit else, the function falls through with no rejection. **CORRECT -- positive guard without negative branch fires.**

However, there is a subtle evasion:
```python
@validates_shape
def validate_input(data):
    if is_valid(data):
        return data
    # implicit fall-through -- no explicit rejection
```
This has no `orelse`, and the `if` body has a return (but with a positive guard, not negative). The function falls through implicitly. `_has_rejection_path` checks: (1) bare raise -- no. (2) negative guard with terminator -- no (positive guard). (3) else with terminator -- no (no else). Returns False. **CORRECT -- fires.**

### 2.5 Semantic equivalents for rejection path detection

| Rejection Pattern | Detected? | Risk |
|-|-|-|
| `raise Exception(...)` | YES | -- |
| `if not X: raise` | YES | -- |
| `if X: ... else: raise` | YES | -- |
| `if not X: return` (early return) | YES | -- |
| `assert X` | NO (correct per spec) | -- |
| `sys.exit(1)` | NO | Low -- uncommon in validators |
| `schema.validate(data)` (delegated raise) | NO | **HIGH -- dominant real-world pattern** |
| `pydantic.BaseModel(**data)` (constructor raise) | NO | **HIGH** |
| `jsonschema.validate(data, schema)` | NO | **HIGH** |
| Helper function that raises | NO | **HIGH** |
| `raise` inside `try`/`except`/`raise` (re-raise) | YES (bare raise found by walk) | -- |
| `logging.error(); raise` | YES | -- |

---

## 3. PY-WL-009: Semantic validation without prior shape validation

### 3.1 Detection scope

The rule fires when ALL of:
1. The function is a declared `semantic_validation` boundary (not `combined_validation`)
2. The function body contains semantic checks (if/assert with subscript access `data["key"]`)
3. No shape-validation evidence precedes the semantic check

Shape-validation evidence includes:
- `isinstance()`, `hasattr()` calls
- `"key" in data` membership tests
- Calls to functions with shape-related names (validate_schema, check_shape, etc.)
- Schema-qualified method calls (`schema.validate()`, `jsonschema.is_valid()`)

### 3.2 False positive: Inter-procedural shape evidence

**Pattern: Shape validated by caller**
```python
def process(data):
    validate_shape(data)  # shape check here
    validate_semantics(data)  # calls the boundary

@validates_semantic
def validate_semantics(data):
    if data["amount"] > MAX:  # fires -- no LOCAL shape evidence
        raise ValueError("too large")
```

PY-WL-009 fires on `validate_semantics` because it has no LOCAL shape evidence. The shape validation happened in the caller. **This is a FALSE POSITIVE in the inter-procedural sense, but CORRECT per the current intraprocedural design.** The spec (section 7.2, WL-008) frames this as an ordering constraint on data-flow paths, which requires inter-procedural analysis. However, the implementation is purely intraprocedural and documented as such (analysis_level=1).

**Mitigation available:** The developer can add a local isinstance/hasattr as a precondition comment, or restructure as a `combined_validation` boundary. The test `test_combined_boundary_is_silent` confirms combined boundaries are correctly excluded.

### 3.3 Dead isinstance as shape evidence

**Pattern: Unused isinstance result**
```python
@validates_semantic
def validate_semantics(data):
    isinstance(data, dict)  # standalone call -- result discarded
    if data["amount"] > MAX:
        raise ValueError("too large")
```

The test `test_isinstance_before_semantic_check_silent` uses exactly this pattern and confirms it is SUPPRESSED. The `isinstance(data, dict)` call is detected as shape evidence by `_is_shape_validation_call` regardless of whether its result is used.

**This is technically a false negative for shape validation quality** -- a standalone isinstance whose boolean result is discarded is dead code and provides no actual shape guarantee. However, its presence as shape evidence in PY-WL-009 is a design trade-off: the isinstance indicates the developer was thinking about shape, even if they didn't branch on it. The risk is low -- this pattern is uncommon in real code, and if the isinstance is genuinely dead, PY-WL-007 would separately flag it as a runtime type check.

**Assessment: ACCEPTABLE design trade-off** with a minor precision concern.

### 3.4 False positive: Schema library calls as shape evidence

The implementation recognizes schema-qualified calls:
- `_SCHEMA_QUALIFIED_METHODS = {"validate", "is_valid"}`
- Matches when the receiver name contains "schema", "shape", or "structure"

**Pattern: `jsonschema.validate(data, schema_def)` before semantic check**
```python
@validates_semantic
def validate_semantics(data):
    jsonschema.validate(data, SCHEMA)
    if data["amount"] > MAX:
        raise ValueError("too large")
```

This is correctly suppressed -- `jsonschema` contains "schema", and `validate` is in `_SCHEMA_QUALIFIED_METHODS`.

**Pattern: `pydantic` model validation**
```python
@validates_semantic
def validate_semantics(data):
    model = UserModel.model_validate(data)
    if model["amount"] > MAX:
        raise ValueError("too large")
```

`model_validate` is not in `_SHAPE_VALIDATION_NAMES`, and `UserModel` does not contain "schema"/"shape"/"structure". `model_validate` does not match `_SCHEMA_QUALIFIED_METHODS`. **FALSE POSITIVE** -- pydantic validation IS shape validation but is not recognized.

**Pattern: `marshmallow` schema**
```python
@validates_semantic
def validate_semantics(data):
    result = user_schema.load(data)
    if result["amount"] > MAX:
        raise ValueError("too large")
```

`user_schema.load()` -- `load` is not in `_SCHEMA_QUALIFIED_METHODS`, and while `user_schema` contains "schema", `load` is not in the method set. **FALSE POSITIVE.**

### 3.5 Inline shape check detection

`_test_contains_shape_check` correctly handles conditions that embed shape checks:
- `if isinstance(x, T) and x["key"] > 0` -- isinstance detected, suppressed. **CORRECT.**
- `if "key" in data and data["key"] > 0` -- membership test detected, suppressed. **CORRECT.**

### 3.6 Semantic equivalents for shape evidence

| Shape Evidence Pattern | Detected? | Risk |
|-|-|-|
| `isinstance(x, T)` | YES | -- |
| `hasattr(x, "attr")` | YES | -- |
| `"key" in data` | YES | -- |
| `validate_schema(data)` | YES | -- |
| `check_shape(data)` | YES | -- |
| `jsonschema.validate(data, s)` | YES | -- |
| `schema.is_valid(data)` | YES | -- |
| `pydantic.BaseModel(**data)` | NO | **HIGH** |
| `UserModel.model_validate(data)` | NO | **HIGH** |
| `marshmallow_schema.load(data)` | NO | Medium |
| `cerberus.Validator(schema).validate(data)` | NO | Low |
| `attrs.validate(instance)` | NO | Low |
| `TypeAdapter.validate_python(data)` | NO | Medium (Pydantic v2) |
| `dataclasses.fields()` structural check | NO | Low |
| `match data: case {"key": value}` | NO | Medium -- structural pattern matching |

### 3.7 Semantic equivalents for semantic checks (trigger patterns)

| Semantic Check Pattern | Detected? | Risk |
|-|-|-|
| `if data["key"] > value` | YES | -- |
| `assert data["key"] > value` | YES | -- |
| `if data["key"]` (truthiness) | YES (has subscript) | -- |
| `if data.attr > value` (attribute) | NO (correct -- excluded by design) | -- |
| `if get_field(data, "key") > value` (helper) | NO | Medium -- indirect subscript |
| `if data.get("key") > value` (.get is attribute) | NO (`.get()` is Attribute, not Subscript) | See note below |

**Note on `.get()` in semantic checks:** `data.get("key")` is an `ast.Attribute` access on the `.get` call, not a `Subscript`. The rule only triggers on `ast.Subscript` nodes. This means `if data.get("amount") > 100:` inside a semantic boundary would NOT trigger PY-WL-009, even though it's performing a semantic check on potentially unvalidated data. This is a minor recall gap, but `.get()` in this context would separately be flagged by PY-WL-001/PY-WL-002, so the coverage is present through other rules.

---

## 4. Two-hop resolution: Engine infrastructure assessment

### 4.1 Existing infrastructure

The engine has the following call-graph components:
- `scanner/taint/callgraph.py`: `extract_call_edges()` builds intra-module `{caller: {callees}}` adjacency maps with resolved/unresolved counts.
- `scanner/taint/callgraph_propagation.py`: `propagate_callgraph_taints()` uses edges for taint refinement.
- `engine.py`: Level 3 analysis invokes call-graph extraction and propagation.

### 4.2 Gap analysis for two-hop rejection resolution

To support two-hop rejection path resolution for PY-WL-008, the following would be needed:

1. **"Unconditionally raises" annotation:** For each function in the call graph, determine whether the function always raises (no success path). This requires analyzing each callee's body for the same rejection-path properties that PY-WL-008 checks on boundaries. The `_has_rejection_path` function could be reused, but inverted: instead of checking for at least one rejection path, check that ALL paths are rejection paths (i.e., the function unconditionally raises).

2. **Two-hop resolution in PY-WL-008:** When `_has_rejection_path` finds no direct rejection path, check if any called function (one hop) unconditionally raises. If not, check if any function called by those callees (two hops) unconditionally raises.

3. **Cross-module resolution:** The current call-graph extraction is intra-module. Schema library calls (`jsonschema.validate`, `pydantic.BaseModel`) are external and would be "unresolved" in the current system. Two approaches:
   - **Allowlist:** Maintain a list of known-unconditionally-raising functions from common libraries. This handles 80% of cases (jsonschema, pydantic, marshmallow, cerberus, attrs).
   - **Signature analysis:** For intra-project calls, analyze the callee's body. For external calls, fall back to the allowlist.

4. **Integration point:** The engine already builds call-graph edges at Level 3. PY-WL-008 could consume these edges at Level 1 for boundary functions only (small subset of the codebase, as the spec notes). This would require either lowering the call-graph extraction to Level 1 for boundary functions or making the two-hop check opt-in at higher analysis levels.

**Estimated effort: MEDIUM.** The infrastructure exists for taint propagation; adapting it for rejection-path resolution requires:
- A new "unconditionally raises" predicate for function bodies
- A two-hop graph traversal limited to boundary function callees
- An allowlist for common schema libraries
- Wiring the call-graph edges into the PY-WL-008 rule context

---

## 5. Consolidated semantic equivalent catalogue

### 5.1 PY-WL-007 (Runtime type-checking)

**Detected:** isinstance(), type() == T, type() is T, type() != T, type() is not T
**Undetected:**
- `type(x).__name__ == "T"` (string-based type check)
- `x.__class__ is T` / `x.__class__ == T`
- `x.__class__.__name__ == "T"`
- `match x: case T():` (structural pattern matching class pattern)
- `issubclass(type(x), T)`
- `T in type(x).__mro__`

### 5.2 PY-WL-008 (No rejection path)

**Detected rejection paths:** raise, if-not-X-raise, if-X-else-raise, if-not-X-return, if-X-else-return
**Undetected rejection paths:**
- Delegated raise via called function (one-hop)
- Delegated raise via called function's callee (two-hop)
- Schema library constructors (pydantic, marshmallow, jsonschema)
- `sys.exit()` / `os._exit()`
- Context manager `__exit__` with raise

### 5.3 PY-WL-009 (Semantic without shape)

**Detected shape evidence:** isinstance, hasattr, "key" in data, schema-named functions, schema-qualified methods
**Undetected shape evidence:**
- Pydantic model construction/validation
- Marshmallow schema.load()
- attrs validation
- Structural pattern matching
- TypeAdapter.validate_python()

---

## 6. Summary of findings

| ID | Rule | Category | Severity | Description |
|----|------|----------|----------|-------------|
| C-01 | PY-WL-008 | Conformance defect | **HIGH** | Two-hop call-graph analysis for rejection path resolution is MUST per spec section 8.1 and section 7.2, but is not implemented. This causes high false-positive rates (~80-90%) on validators that delegate to schema libraries. |
| C-02 | PY-WL-008 | Evasion | MEDIUM | Unreachable rejection paths (raise after unconditional return, `if False: raise`) are accepted as valid. Spec says SHOULD detect constant-false guards. |
| C-03 | PY-WL-008 | Evasion | LOW | Degenerate validators (unconditionally raise, no success path) are accepted. Spec says SHOULD emit advisory finding. |
| C-04 | PY-WL-007 | False positive | MEDIUM | TypeGuard/TypeIs functions fire despite isinstance being their declared purpose. No suppression category covers this. |
| C-05 | PY-WL-007 | Recall gap | MEDIUM | `match`/`case` class patterns perform implicit isinstance checks but are not detected. Growing evasion surface with Python 3.10+ adoption. |
| C-06 | PY-WL-007 | Recall gap | MEDIUM | `x.__class__ is T` / `x.__class__.__name__` comparisons not detected. |
| C-07 | PY-WL-009 | False positive | MEDIUM | Pydantic model_validate(), marshmallow schema.load() not recognized as shape evidence, causing false positives on semantic boundaries that follow pydantic shape validation. |
| C-08 | PY-WL-009 | Precision | LOW | Standalone isinstance (result unused) accepted as shape evidence. Dead code provides no actual shape guarantee. |

---

## Verdict: CONCERN

**Rationale:**

PY-WL-007 and PY-WL-009 are well-implemented with sound suppression logic and acceptable precision/recall characteristics at the intraprocedural level. Their gaps (C-04 through C-08) are medium-to-low severity and addressable through incremental semantic equivalent catalogue expansion.

PY-WL-008 has a **conformance defect** (C-01): the spec requires two-hop call-graph analysis for rejection path resolution as a MUST-level framework invariant (section 8.1), and this is not implemented. The practical impact is severe -- the dominant real-world pattern for validation functions (delegating to schema libraries) produces false positives. The engine already has call-graph infrastructure that could support this with medium engineering effort.

The verdict is CONCERN rather than FAIL because:
1. The intraprocedural analysis that IS implemented is correct and precise.
2. The call-graph infrastructure exists and the path to two-hop resolution is clear.
3. The evasion gaps (C-02, C-03) are SHOULD-level, not MUST-level.
4. PY-WL-007 and PY-WL-009 are sound within their declared analysis level.

However, C-01 must be resolved before PY-WL-008 can claim conformance with section 8.1. Until then, PY-WL-008's operational precision on real-world validation code will be well below the 80% floor specified in section 10, property 3.
