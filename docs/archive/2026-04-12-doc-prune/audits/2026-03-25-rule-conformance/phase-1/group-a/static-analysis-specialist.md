# Group A -- Static Analysis Specialist Assessment

**Audit date:** 2026-03-25
**Rules under review:** PY-WL-001, PY-WL-002, PY-WL-003
**Spec mapping:** PY-WL-001 + PY-WL-002 implement framework WL-001 (member access with fallback default, split by Python access pattern). PY-WL-003 implements framework WL-002 (existence-checking as structural gate).

---

## False Positive Analysis

### PY-WL-001: Dict key access with fallback default

**FP-001-1: `.get()` on non-dict mapping-like objects.**
The rule matches ANY `x.get(key, default)` call where there are >= 2 args. This fires on:
- `os.environ.get("KEY", "default")` -- environment variable access, extremely common
- `configparser["section"].get("key", "fallback")` -- config file parsing
- `request.args.get("param", "")` -- Flask/Django query parameter access
- `headers.get("Content-Type", "application/octet-stream")` -- HTTP header access
- Any custom class with a `.get()` method that takes two positional args

**Frequency estimate:** HIGH. In a typical web application codebase, `os.environ.get()` alone will produce 10-50 findings per project. Flask/Django codebases will have dozens more from request parameter access. This is the single largest false positive source across all three rules.

**Mitigation assessment:** This is arguably NOT a false positive in the Wardline model. The spec explicitly treats ALL fallback defaults as findings, with severity/exceptionability governed by taint state. In EXTERNAL_RAW context (where `os.environ` and HTTP params would be classified), it fires as ERROR/STANDARD, which IS governable. The question is whether governance volume becomes noise. The `schema_default()` mechanism exists to suppress approved defaults, but it requires manifest declarations per field.

**Verdict:** By-design behaviour, not a precision defect. However, the volume in real codebases without full manifest adoption will be significant.

**FP-001-2: `defaultdict` attribute match is overly broad.**
`_is_defaultdict_call` matches:
1. `defaultdict(factory)` -- Name node with id "defaultdict"
2. ANY `x.defaultdict(factory)` -- Attribute node with attr "defaultdict"

Pattern (2) matches `collections.defaultdict(list)` (correct) but also ANY attribute access ending in `.defaultdict()` with >= 1 arg. In practice, no standard library or popular framework has a `.defaultdict()` method besides `collections`, so this is a theoretical rather than practical concern.

**Frequency estimate:** NEGLIGIBLE. The attribute match is broader than necessary but rarely triggers falsely in practice.

**FP-001-3: `.setdefault()` on non-dict objects.**
Same overly-broad method matching applies. `setdefault` is almost exclusively a dict method in practice, so false positive rate is very low.

**Frequency estimate:** NEGLIGIBLE.

### PY-WL-002: Attribute access with fallback default

**FP-002-1: 3-arg `getattr()` for legitimate dynamic dispatch.**
The rule flags ALL 3-arg `getattr()` calls. Common legitimate uses:
- `getattr(module, handler_name, default_handler)` -- plugin systems
- `getattr(obj, attr_name, None)` used to check existence before proceeding (overlap with PY-WL-003 semantics)
- `getattr(self, f"handle_{event_type}", self._default_handler)` -- event dispatch
- `getattr(settings, "DEBUG", False)` -- Django settings access

**Frequency estimate:** MODERATE. A typical Django project will have 5-20 `getattr()` with default calls. Plugin-heavy architectures (pytest, click) more.

**Verdict:** By-design. The spec treats this as a member access with fallback default. The taint context determines severity.

**FP-002-2: `obj.attr or default` pattern is very broad.**
The `_check_boolop` method fires on ANY `ast.Attribute or <expr>` pattern with exactly 2 values. This matches:
- `self.name or "Anonymous"` -- legitimate fallback for falsy values, very common
- `config.timeout or 30` -- configuration with falsy-value fallback
- `response.data or []` -- empty-collection fallback
- `logger.handler or default_handler` -- any attribute-or pattern

Critically, this also fires on patterns where the attribute IS present but has a falsy value (0, "", False, [], None). The `or` operator is not an existence check -- it is a truthiness check. An object with `obj.count = 0` will trigger the fallback via `obj.count or 1`, which is semantically different from "attribute is missing."

**Frequency estimate:** HIGH. `x.attr or default` is an extremely common Python idiom. In a 10k-line codebase, expect 20-50 occurrences. Many of these are not "attribute access with fallback default" in the Wardline sense -- they are falsy-value substitution on attributes that definitely exist.

**Verdict:** CONCERN. The `or` pattern conflates attribute absence with falsy-value substitution. The spec's WL-001 targets "member absence is meaningful" cases -- `obj.attr or default` fires when the attribute EXISTS but is falsy, which is a different semantic category. This is a genuine precision issue.

**FP-002-3: `getattr` imported under a different name.**
If code uses `from builtins import getattr as ga`, the rule will miss `ga(obj, name, default)`. Conversely, if a user defines their own function named `getattr`, the rule fires incorrectly. Both are edge cases.

**Frequency estimate:** NEGLIGIBLE.

### PY-WL-003: Existence-checking as structural gate

**FP-003-1: `in` operator on non-structural containers.**
The rule fires on ALL `in` / `not in` Compare nodes:
- `"substring" in text` -- string containment, not structural gate
- `item in [1, 2, 3]` -- list membership, not structural gate
- `char in "aeiou"` -- character set membership
- `element in my_set` -- set membership for algorithmic purposes
- `x in range(10)` -- range containment

The rule does not distinguish between `key in dict` (structural gate) and `item in list` (value membership). The AST for both is identical (`Compare` with `In` op), so distinguishing them requires type inference that the scanner does not perform.

**Frequency estimate:** VERY HIGH. `in` is one of Python's most-used operators. In a typical codebase, string containment checks alone (`"x" in some_string`) will outnumber structural-gate `in` checks by 5:1 or more. This is the largest false positive source across all three rules.

**Verdict:** CONCERN. Without type information, the `in` operator pattern has very poor precision. The majority of `in` operator uses in typical Python code are not structural gates on dicts/objects.

**FP-003-2: `hasattr()` for feature detection.**
The rule flags ALL `hasattr()` calls:
- `hasattr(obj, "__iter__")` -- duck-typing protocol check
- `hasattr(module, "function_name")` -- optional feature detection
- `hasattr(cls, "__dataclass_fields__")` -- introspection

These are legitimate Python patterns for protocol compliance checking, not structural probing in the Wardline sense.

**Frequency estimate:** MODERATE. 5-15 per typical project.

**Verdict:** By-design for the Wardline model (existence-checking IS the concern), but high false positive rate in code that uses Pythonic duck-typing.

**FP-003-3: `match/case` with MatchMapping or MatchClass.**
The rule flags structural pattern matching, which is relatively new (Python 3.10+) and typically used for exactly the kind of structural dispatch the rule targets. False positive rate is low here.

**Frequency estimate:** LOW.

---

## False Negative Analysis

### PY-WL-001: Dict key access with fallback default

**FN-001-1: Ternary fallback pattern.**
```python
value = d[k] if k in d else default
```
The `in` check is caught by PY-WL-003, but the overall pattern -- fabricating a default for a missing key -- is not flagged by PY-WL-001. The two rules fire on different parts of the expression and neither captures the composite semantics.

**Agent production likelihood:** MODERATE. AI agents produce this pattern when prompted to "avoid .get()". It is a direct evasion of PY-WL-001 while preserving the same semantics.

**FN-001-2: try/except KeyError fallback.**
```python
try:
    value = d[key]
except KeyError:
    value = default
```
Not detected by PY-WL-001. This is a semantic equivalent of `.get(key, default)`.

**Agent production likelihood:** MODERATE. AI agents trained on Python idioms will produce this as an alternative to `.get()`.

**FN-001-3: `dict.pop(key, default)` with default.**
```python
value = d.pop("key", "default_value")
```
Not detected. `pop()` with a default argument is semantically equivalent to `.get()` + `del` -- it fabricates a default for a missing key.

**Agent production likelihood:** LOW-MODERATE. Less common than `.get()` but AI agents will produce it for "extract and remove" patterns.

**FN-001-4: Or-expression default.**
```python
value = d.get("key") or default_value
```
The `.get("key")` call without a second arg is NOT flagged by PY-WL-001 (requires >= 2 args). Combined with `or`, this fabricates a default for both missing keys AND falsy values. The `or` is not flagged because PY-WL-002's `_check_boolop` only matches `ast.Attribute` (not method call results).

**Agent production likelihood:** HIGH. This is extremely common Python -- "use `.get()` without a default and then `or` for the fallback." AI agents produce this naturally and frequently.

**FN-001-5: ChainMap layering.**
```python
from collections import ChainMap
effective = ChainMap(overrides, defaults)
value = effective["key"]  # defaults silently provide fallback
```
Not detected. The default fabrication is structural (at ChainMap construction) rather than at the access site.

**Agent production likelihood:** LOW. AI agents rarely reach for ChainMap unprompted.

**FN-001-6: `collections.abc.Mapping` subclass with custom `__missing__`.**
```python
class DefaultingDict(dict):
    def __missing__(self, key):
        return "default"
```
Not detected. This is a semantic equivalent of `defaultdict` but uses `__missing__` directly.

**Agent production likelihood:** LOW. AI agents typically use `defaultdict` or `.get()`.

**FN-001-7: Walrus-operator default.**
```python
value = v if (v := d.get("key")) is not None else default
```
The `.get("key")` has only 1 arg, so PY-WL-001 does not fire. The composite pattern fabricates a default.

**Agent production likelihood:** MODERATE. AI agents produce walrus-operator patterns with increasing frequency.

### PY-WL-002: Attribute access with fallback default

**FN-002-1: hasattr-guarded ternary.**
```python
value = obj.attr if hasattr(obj, "attr") else default
```
`hasattr` is caught by PY-WL-003, but the overall attribute-fallback-default pattern is not caught by PY-WL-002.

**Agent production likelihood:** MODERATE. Common Python pattern.

**FN-002-2: try/except AttributeError fallback.**
```python
try:
    value = obj.attr
except AttributeError:
    value = default
```
Not detected by PY-WL-002.

**Agent production likelihood:** MODERATE. AI agents produce this when told to "handle missing attributes safely."

**FN-002-3: `vars(obj).get(name, default)`.**
```python
value = vars(obj).get("attr_name", default_value)
```
The `.get()` with 2 args IS caught by PY-WL-001, but it is misclassified -- this is an attribute access pattern (PY-WL-002 semantics) reported as a dict access pattern (PY-WL-001). The distinction matters for the severity matrix if the binding has different matrix entries.

**Agent production likelihood:** LOW. Uncommon pattern.

**FN-002-4: `obj.__dict__.get(name, default)`.**
```python
value = obj.__dict__.get("attr_name", default_value)
```
Caught by PY-WL-001 (dict `.get()` with default), but again misclassified as dict access rather than attribute access.

**Agent production likelihood:** LOW.

**FN-002-5: Conditional attribute access with `and`.**
```python
value = obj and obj.attr
```
Not detected. The `and` operator provides a fallback (the falsy `obj` itself) when `obj` is None/falsy.

**Agent production likelihood:** MODERATE. Common None-guard pattern.

### PY-WL-003: Existence-checking as structural gate

**FN-003-1: try/except KeyError as existence probe.**
```python
try:
    value = d["key"]
    # key exists path
except KeyError:
    # key missing path
```
Not detected by PY-WL-003. This is a semantic equivalent of `if "key" in d`.

**Agent production likelihood:** MODERATE.

**FN-003-2: try/except AttributeError as existence probe.**
```python
try:
    value = obj.attr
except AttributeError:
    # attribute missing path
```
Not detected. Semantic equivalent of `hasattr()`.

**Agent production likelihood:** MODERATE.

**FN-003-3: Set intersection / difference as existence check.**
```python
missing_keys = required_keys - d.keys()
if missing_keys:
    # structural gate
```
Not detected. This is a structural completeness check.

**Agent production likelihood:** LOW-MODERATE. AI agents produce this for batch validation patterns.

**FN-003-4: `.keys()` / `.values()` / `.items()` iteration as structural probe.**
```python
for key in d.keys():
    if key == "expected_field":
        ...
```
Not detected.

**Agent production likelihood:** LOW.

**FN-003-5: `getattr()` with 2 args (no default) used as existence test.**
```python
try:
    getattr(obj, name)  # raises if missing
except AttributeError:
    ...
```
Not detected by PY-WL-003 (only checks `hasattr`). The 2-arg `getattr` is explicitly excluded from PY-WL-002.

**Agent production likelihood:** LOW.

---

## Suppression Mechanism Accuracy

### PY-WL-001: `schema_default()` three-condition gate

The suppression requires all three conditions simultaneously:
1. **Field declaration match:** `optional_field.field == field_name` -- the field name in `.get("field", ...)` must match a declared optional field in the manifest
2. **Default value match:** `default_value == optional_field.approved_default` -- the literal default must exactly equal the approved default (compared via `ast.literal_eval`)
3. **Governed boundary:** The current function must be in the `_GOVERNED_TRANSITIONS` set AND share the same `overlay_scope`

**Bypass analysis:**

**Gate 1 (field match):** Sound. Uses exact string comparison on the first positional arg to `.get()`. Cannot be bypassed without changing the field name.

**Gate 2 (default value match):** Mostly sound, with one edge case. `ast.literal_eval` handles standard Python literals (strings, numbers, booleans, None, tuples, lists, dicts, sets). Non-literal defaults (function calls, variable references) return `_UNPARSEABLE_DEFAULT`, which will never equal a declared approved default, so they fall through to the ungoverned path. This is correct behaviour -- a non-literal default cannot be statically verified.

Edge case: `ast.literal_eval` compares by Python equality. `0 == False` and `1 == True` in Python, so a declared default of `0` would match code using `False`, and vice versa. This is unlikely to cause practical problems but is technically imprecise.

**Gate 3 (boundary match):** Sound. Requires exact qualname match, a governed transition type, AND matching overlay scope with path containment. The `_GOVERNED_TRANSITIONS` set includes:
- `shape_validation`, `external_validation`, `combined_validation` (manifest-style)
- `validates_shape`, `validates_external` (decorator-style)

This set correctly excludes `semantic_validation` / `validates_semantic`, which should not suppress PY-WL-001 (semantic validation is not where optional-field handling belongs).

**Missing from governed transitions:** `validates_combined` is absent. If the decorator-style name for combined validation is `validates_combined` rather than `validates_external`, the gate would fail to suppress governed defaults in combined validation boundaries. Checking whether `validates_combined` exists as a decorator name would confirm this.

**Overall suppression verdict:** The three-condition gate is well-designed. No practical bypass path exists short of falsifying manifest declarations (which would be a governance failure, not a scanner failure).

### PY-WL-003: Validation-boundary suppression

The suppression set `_SUPPRESSED_BOUNDARY_TRANSITIONS` includes:
- `shape_validation`, `combined_validation`, `external_validation`
- `validates_shape`, `validates_external`

**Analysis:**

**Correctly included:** Shape validation and combined validation boundaries are where existence-checking IS the purpose -- checking field presence during structural validation is correct behaviour, not a violation.

**Potentially over-inclusive:** `external_validation` / `validates_external` suppresses PY-WL-003 in combined validation boundaries. This is correct per the spec: combined boundaries perform both shape and semantic validation, so existence-checking is expected.

**Correctly excluded:** `semantic_validation` / `validates_semantic` is not in the suppression set. Semantic validation should operate on shape-validated data where structure is guaranteed -- existence-checking in a semantic validator IS suspicious (per spec WL-002 derivation).

**Missing from suppression set:** `validates_combined` -- same question as PY-WL-001 above. If this decorator name exists, its absence would cause false positives inside combined validation boundaries.

**Non-validation boundary leakage:** A function that is NOT a validation boundary cannot get suppression because the check requires `boundary.function == self._current_qualname` -- only functions explicitly declared as boundaries in the manifest are candidates. The transition type check further constrains this. No leakage path exists.

**Overall suppression verdict:** Sound. The suppression is correctly scoped to validation boundaries where existence-checking is expected.

---

## Semantic Equivalent Catalogue

The spec (SS7 para 2) requires: "Language bindings MUST maintain version-tracked lists of semantic equivalents for each pattern rule." The current implementations do NOT maintain such catalogues. Below is an initial catalogue derived from the false negative analysis above.

### PY-WL-001 Semantic Equivalents

| ID | Pattern | Detection Status | Priority |
|----|---------|-----------------|----------|
| PY-WL-001-SE-001 | `d.get(key, default)` | DETECTED | -- |
| PY-WL-001-SE-002 | `d.setdefault(key, default)` | DETECTED | -- |
| PY-WL-001-SE-003 | `defaultdict(factory)` / `collections.defaultdict(factory)` | DETECTED | -- |
| PY-WL-001-SE-004 | `d[k] if k in d else default` (ternary fallback) | NOT DETECTED | HIGH |
| PY-WL-001-SE-005 | `try: v=d[k] except KeyError: v=default` | NOT DETECTED | HIGH |
| PY-WL-001-SE-006 | `d.pop(key, default)` | NOT DETECTED | MEDIUM |
| PY-WL-001-SE-007 | `d.get(key) or default` (or-expression) | NOT DETECTED | HIGH |
| PY-WL-001-SE-008 | `ChainMap(overrides, defaults)[key]` | NOT DETECTED | LOW |
| PY-WL-001-SE-009 | Custom `__missing__` method on dict subclass | NOT DETECTED | LOW |
| PY-WL-001-SE-010 | `v if (v := d.get(k)) is not None else default` (walrus) | NOT DETECTED | MEDIUM |
| PY-WL-001-SE-011 | `{**defaults, **actual_data}[key]` (spread merge) | NOT DETECTED | LOW |

### PY-WL-002 Semantic Equivalents

| ID | Pattern | Detection Status | Priority |
|----|---------|-----------------|----------|
| PY-WL-002-SE-001 | `getattr(obj, name, default)` (3-arg) | DETECTED | -- |
| PY-WL-002-SE-002 | `obj.attr or default` | DETECTED | -- |
| PY-WL-002-SE-003 | `obj.attr if hasattr(obj, "attr") else default` | NOT DETECTED (hasattr caught by 003) | MEDIUM |
| PY-WL-002-SE-004 | `try: v=obj.attr except AttributeError: v=default` | NOT DETECTED | HIGH |
| PY-WL-002-SE-005 | `vars(obj).get(name, default)` | DETECTED by 001 (misclassified) | LOW |
| PY-WL-002-SE-006 | `obj.__dict__.get(name, default)` | DETECTED by 001 (misclassified) | LOW |
| PY-WL-002-SE-007 | `obj and obj.attr` (None-guard) | NOT DETECTED | MEDIUM |

### PY-WL-003 Semantic Equivalents

| ID | Pattern | Detection Status | Priority |
|----|---------|-----------------|----------|
| PY-WL-003-SE-001 | `key in d` / `key not in d` | DETECTED | -- |
| PY-WL-003-SE-002 | `hasattr(obj, name)` | DETECTED | -- |
| PY-WL-003-SE-003 | `match/case` with MatchMapping | DETECTED | -- |
| PY-WL-003-SE-004 | `match/case` with MatchClass | DETECTED | -- |
| PY-WL-003-SE-005 | `try: d[k] except KeyError` (existence probe) | NOT DETECTED | HIGH |
| PY-WL-003-SE-006 | `try: obj.attr except AttributeError` | NOT DETECTED | HIGH |
| PY-WL-003-SE-007 | `required_keys - d.keys()` (set difference) | NOT DETECTED | MEDIUM |
| PY-WL-003-SE-008 | `d.keys() & expected_keys` (set intersection) | NOT DETECTED | LOW |
| PY-WL-003-SE-009 | `any(k == "field" for k in d)` (generator probe) | NOT DETECTED | LOW |

---

## Evasion Surface Summary

### PY-WL-001: Dict key access with fallback default

**Accidental evasion difficulty:** EASY. An AI agent that uses `d.get("key") or default` (no second arg to `.get()`) accidentally evades detection. This is an extremely natural Python idiom that agents produce frequently. The try/except KeyError pattern and ternary fallback are also natural evasion paths.

**Deliberate evasion difficulty:** TRIVIAL. Any of SE-004 through SE-011 evade detection. Wrapping `.get()` in a one-line helper function (`def safe_get(d, k, default): return d.get(k, default)`) also evades, since the rule matches on AST method name, not semantics.

**Compensating controls:** The taint-state model provides context-dependent severity, but only for detected patterns. Undetected semantic equivalents bypass all severity controls. Code review is the primary compensating control for evasion.

### PY-WL-002: Attribute access with fallback default

**Accidental evasion difficulty:** EASY. `obj.attr if hasattr(obj, "attr") else default` is a natural pattern that evades PY-WL-002 (though `hasattr` is caught by PY-WL-003). try/except AttributeError is also natural.

**Deliberate evasion difficulty:** TRIVIAL. Same helper-function wrapping applies.

**Compensating controls:** PY-WL-003 provides partial coverage for the hasattr-guarded ternary pattern, but only flags the existence check, not the default fabrication.

### PY-WL-003: Existence-checking as structural gate

**Accidental evasion difficulty:** MODERATE. The `in` operator detection is so broad that accidental evasion is less likely -- most existence-checking patterns DO use `in` or `hasattr`. However, try/except KeyError is a natural alternative.

**Deliberate evasion difficulty:** EASY. try/except KeyError/AttributeError evades cleanly. Set operations on `.keys()` also evade.

**Compensating controls:** The validation-boundary suppression correctly avoids false positives where existence-checking is expected. However, the broad `in` operator matching means the rule has poor signal-to-noise ratio outside of type-aware contexts.

---

## Verdict: CONCERN

### Evidence

**Precision concerns (2 significant):**

1. **PY-WL-003 `in` operator over-matching.** The rule fires on ALL `in`/`not in` operations including string containment, list membership, and range checks. Without type information, the false positive rate on `in` will be very high in typical Python codebases. This directly threatens the 80% precision floor (spec SS10 property 3) for most taint-state cells.

2. **PY-WL-002 `obj.attr or default` over-matching.** The `or` pattern conflates attribute absence (the spec's concern) with falsy-value substitution (a different semantic). `self.name or "Anonymous"` fires when `.name` exists but is empty string -- this is NOT a fallback default for a missing attribute. The pattern will generate significant false positive volume.

**Recall concerns (1 significant, 2 moderate):**

1. **PY-WL-001 or-expression gap (HIGH priority).** `d.get("key") or default` is not detected. This is the single most common evasion path because it is natural Python idiom -- AI agents produce it routinely without any intent to evade. Given the HIGH agent-production likelihood, this gap poses a material recall risk.

2. **try/except fallback patterns (MODERATE priority).** All three rules miss try/except-based semantic equivalents. These are moderately common in AI-generated code.

3. **Semantic equivalent catalogue is absent.** The spec requires version-tracked lists of semantic equivalents (SS7 para 2 MUST). The implementations track no such catalogue. The initial catalogue above should be adopted and tracked.

**Suppression mechanisms: PASS.** Both the `schema_default()` three-condition gate and the validation-boundary suppression are correctly designed with no practical bypass paths.

**Overall:** The rules correctly detect the canonical forms of their target patterns and the suppression mechanisms are sound. However, two precision issues (PY-WL-003 `in` operator, PY-WL-002 `or` pattern) and one high-priority recall gap (PY-WL-001 or-expression) prevent a clean PASS. The missing semantic equivalent catalogue is a spec conformance gap.
