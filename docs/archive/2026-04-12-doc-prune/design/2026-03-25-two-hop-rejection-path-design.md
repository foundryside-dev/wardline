# Two-Hop Rejection Path Resolution for PY-WL-008

**Date:** 2026-03-25
**Status:** Design (revised after 2 rounds of 6-role panel review)
**Audit source:** HC-2 from 35-agent conformance audit (5 independent agents confirmed)
**Spec requirement:** Part I §8.1 (MUST), §7.2
**Panel review rounds:**
- R1: 6 reviewers, 3 ISSUES / 3 N/A (pre-design) → critical import alias gap, governance classification, merge semantics
- R2: 6 reviewers, 3 APPROVED / 3 ISSUES → sequencing bug (alias maps during index build), FQN qualnames, missing RuleId

---

## Problem

PY-WL-008 (WL-007) checks that declared validation/restoration boundary functions contain a rejection path. The current implementation is purely intraprocedural — it only finds `raise` statements and guarded returns directly in the boundary body. Validators that delegate to schema libraries produce false positives:

```python
@validates_shape
def validate_payload(data):
    jsonschema.validate(data, SCHEMA)  # raises ValidationError on failure
    return data
```

This boundary has a valid rejection path through delegation, but PY-WL-008 fires because no `raise` or guarded return exists in the body itself.

Since PY-WL-008 is E/U (UNCONDITIONAL) across all 8 taint states, these false positives cannot be governed via exceptions. The audit's systems thinker identified this as creating a **declaration-avoidance reinforcing loop** — developers remove boundary declarations to avoid false positives, reducing the annotation surface all other rules depend on.

---

## Spec Clarification Required

**Current spec wording (§7.2):** "A call to a function that **unconditionally raises**, if the called function is resolvable via two-hop call-graph analysis."

**Problem with current wording:** "Unconditionally raises" means every code path leads to a raise — the function never returns normally. This describes functions like `sys.exit()` or `typing.assert_never()`, NOT schema validators. `jsonschema.validate()` raises conditionally (on invalid input) and returns None on valid input. The current wording makes the feature useless for its primary use case.

**Recommended clarification:** Replace "a function that unconditionally raises" with "a function that **has a rejection path** — contains at least one reachable raise or guarded-return terminator on its normal control flow that can reject invalid input."

**Rationale:** The spec's §8.1 context makes the intent clear — "real validation commonly delegates through two layers (validator → schema library → actual check), and one-hop analysis generates false positives on structurally sound validators that use thin wrappers." Schema libraries are the stated use case, and they raise conditionally.

**Known precision trade-off (per SA review):** "Has a rejection path" is broader than "unconditionally raises" — it includes any function containing a reachable raise, even in error-handling code unrelated to input validation. This is an acceptable trade-off: the feature's purpose is to reduce false positives on delegation patterns, and over-inclusion (accepting a callee that technically can raise but doesn't validate) is far less harmful than under-inclusion (rejecting legitimate schema library delegation). The existing `_has_rejection_path` logic already excludes trivially-unreachable paths (constant-false guards).

This clarification should be proposed as a spec revision in a future Wardline spec update cycle.

---

## Design

### Approach: Pre-computed rejection path index with import resolution

Before rules run, the engine pre-computes a set of fully-qualified function names (FQNs) that "have a rejection path." PY-WL-008 consults this index when checking boundary functions — if a callee in the boundary body resolves to an FQN in the index, the boundary satisfies WL-007 through delegation.

### Two data sources feed the index

**[R2 fix #5: Source 1 (intra-file) was redundant with source 2 (cross-module). Merged into a single project-wide pass.]**

1. **Project-wide functions** — the engine already parses all files during `_build_project_indexes()`. Extend this pass to also check each function for rejection paths. For each file: call `build_qualname_map(tree)` to get module-relative qualnames, then prefix with the module name from `_module_name_for()` to produce FQNs. **[R2 fix #2: Qualnames must be fully-qualified.]** Example: file `src/myproject/validators.py` with function `validate_input` → FQN `myproject.validators.validate_input`.

2. **Third-party known validators** — a configurable list of FQN third-party functions known to raise on invalid input. The scanner cannot follow into third-party source, so these are declared.

**Two-hop-aware index construction (per ST review):** After the initial index is seeded from sources 1-2, apply one round of expansion: any project function that contains a **reachable** call to a function already in the index also enters the index. The expansion step MUST apply the same reachability discipline as direct rejection-path detection: calls inside dead branches (`if False:`, `if 0:`, etc.) do not qualify, and nested function bodies are not scanned when determining whether the outer function delegates rejection. **The expansion step builds per-file import alias maps** to resolve calls to known_validators entries. **[R2 fix #1: Alias maps must be built during `_build_project_indexes`, not deferred to `_scan_file`.]**

This covers the common **wrapper pattern**:

```python
def _validate_with_logging(data, schema):
    logger.debug("Validating %s", schema)
    jsonschema.validate(data, schema)  # in known_validators → in index

@validates_shape
def validate_payload(data):
    _validate_with_logging(data, PAYLOAD_SCHEMA)  # wrapper now in index → suppressed
```

Without this expansion, the wrapper is NOT in the index (it has no direct raise), and the boundary's call to it is not recognized — making the effective hop limit one-hop for the most common real-world pattern.

**No further recursion** — the expansion runs exactly once (seed → expand). This is not a fixed-point iteration. Two-hop is the spec limit.

### Import alias map (per PE, SA, SAS, QE review — critical gap)

A per-file **import alias map** is built by walking module-level `Import` and `ImportFrom` statements:

```python
# import jsonschema         → {"jsonschema": "jsonschema"}
# import jsonschema as js   → {"js": "jsonschema"}
# from jsonschema import validate        → {"validate": "jsonschema.validate"}
# from jsonschema import validate as v   → {"v": "jsonschema.validate"}
```

The map is `dict[str, str]` mapping local names to fully-qualified names.

**Import resolution is syntactic, not semantic** — the map is built from the import statement as written in source. `from jsonschema import validate` maps to `jsonschema.validate` regardless of whether jsonschema internally re-exports from `jsonschema._validators`. This matches Python's import semantics from the developer's perspective. **[R2 fix #8: Explicitly documented.]**

**Alias maps are built in TWO places:**
- During `_build_project_indexes()` — needed by the expansion step to resolve calls in wrapper functions against known_validators
- During `_scan_file()` — passed to ScanContext for PY-WL-008's `_has_delegated_rejection`

Building the map is cheap (one walk of module-level statements, O(imports)).

**Call resolution uses the alias map:**
- Bare call `validate(data)` → look up `"validate"` in alias map → `"jsonschema.validate"` → check index
- Attribute call `js.validate(data)` → look up `"js"` in alias map → `"jsonschema"`, concatenate with `.validate` → `"jsonschema.validate"` → check index
- Attribute call `jsonschema.validate(data)` → look up `"jsonschema"` → `"jsonschema"`, concat → `"jsonschema.validate"` → check index
- Bare call `validate(data)` with no import → look up `"validate"` → not found → check against intra-module FQNs only

**Receiver method calls are OUT OF SCOPE for this design:** Calls like `self.validate(data)` or `obj.validator.validate(data)` are not resolvable with the proposed syntactic alias map alone because the receiver type is unknown. Treat them as unresolvable and let PY-WL-008 fire unless the boundary also has a direct reachable rejection path. This keeps the design aligned with the spec's structural requirement while avoiding unsound pseudo-resolution.

**Local definitions shadow imports (FunctionDef/AsyncFunctionDef only):** If a module defines its own `def validate():`, bare-name calls resolve to the local definition (checked via its FQN in the index), NOT to the import alias. This prevents false negatives where a local no-op `validate` is mistaken for `jsonschema.validate`. Assignments (`validate = lambda x: x`) and class definitions are NOT considered local shadows — only `def`/`async def` at module level. **[R2 fix from PE #5: Scoped to FunctionDef/AsyncFunctionDef.]**

**Known limitations:**
- `from jsonschema import *` — cannot resolve without executing the import or parsing `__all__`. Star imports are treated as unresolvable; the finding may fire.
- Dynamic imports (`importlib.import_module`) — unresolvable by static analysis. Finding fires.

### wardline.toml extension

```toml
[wardline]
# Functions known to raise on invalid input. Used by PY-WL-008 two-hop
# rejection path resolution. The scanner cannot follow into third-party
# source, so known validators are declared here.
#
# Use known_validators_extra to ADD entries to the built-in defaults.
# Use known_validators to REPLACE the entire list (advanced).
known_validators_extra = [
    "mycompany.validators.check_payload",
]
```

**Configuration keys:**
- `known_validators_extra` (recommended) — entries are MERGED with the built-in default list. This is the safe default — adding a project-specific validator doesn't lose jsonschema/pydantic/marshmallow coverage.
- `known_validators` (advanced) — REPLACES the built-in list entirely. For teams that need to remove a built-in entry that causes false negatives.
- If both are present, `known_validators` takes precedence and `known_validators_extra` is ignored (with a warning).

**Built-in default list:**
```python
_BUILTIN_KNOWN_VALIDATORS = frozenset({
    "jsonschema.validate",
    "jsonschema.Draft4Validator.validate",
    "jsonschema.Draft7Validator.validate",
    "pydantic.TypeAdapter.validate_python",
    "pydantic.BaseModel.model_validate",
    "marshmallow.Schema.load",
    "marshmallow.Schema.loads",
})
```

Note: `cerberus.Validator.validate` removed from defaults (per ST review — it returns a boolean, does not raise).

**Artefact classification (per SecA review):** `known_validators` is a **policy artefact** (§9.3.1), not an enforcement artefact. Entries directly suppress a MUST-level E/U rule. Changes SHOULD be tracked in the fingerprint baseline and SHOULD require the same review as boundary declarations.

**GOVERNANCE finding for custom entries:** The scanner MUST emit a `GOVERNANCE_CUSTOM_KNOWN_VALIDATOR` finding (severity: `WARNING`) for each entry in the effective known_validators set that is NOT in `_BUILTIN_KNOWN_VALIDATORS`. This makes custom additions visible in SARIF output and subject to governance review. **Emission point:** after CLI/config merging determines the effective validator set, and before `ScanEngine.scan()` runs, `scan.py` appends one governance finding per custom entry using the existing governance-finding path (the same mechanism already used for disabled rules, permissive distribution, and registry mismatch). This avoids hiding policy-surface changes inside the engine and keeps the review signal in SARIF even when no PY-WL-008 finding fires. **[R2 fix #3: explicit owner for RuleId emission.]**

**Config location:** Both keys live under `[wardline]` (the existing config section), NOT `[scanner]`. The `_KNOWN_KEYS` frozenset in `models.py` must be extended.

### Data flow (revised)

```
Engine._build_project_indexes()
  ├── existing: annotations, module_file_map, string_literal_counts
  └── NEW: rejection_path_index: frozenset[str]
       ├── for each file:
       │    ├── build_qualname_map(tree) → module-relative qualnames
       │    ├── prefix with module_name → FQNs  [R2 fix #2]
       │    ├── build_import_alias_map(tree)  [R2 fix #1]
       │    └── _has_rejection_path(func_node) for each FunctionDef → seed
       ├── seed: known_validators from wardline.toml / built-in defaults
       ├── expand: for each file, re-walk function bodies:
       │    resolve calls via that file's alias map + FQN qualnames
       │    any function calling a seed entry → enters the index
       └── freeze: frozenset for immutability

Engine._scan_file()
  ├── build per-file import_alias_map (reuse from index if same file, else rebuild)
  └── pass rejection_path_index + import_alias_map to ScanContext

CLI scan setup
  ├── load wardline.toml / CLI overrides
  ├── compute effective known_validators set
  ├── compare effective set to built-in defaults
  └── emit GOVERNANCE_CUSTOM_KNOWN_VALIDATOR findings for custom entries

PY-WL-008.visit_function(node)
  ├── _has_rejection_path(node)  [existing — unchanged]
  └── _has_delegated_rejection(node, context)
       ├── walk body for ast.Call nodes
       ├── resolve call target using context.import_alias_map + local definitions
       └── check resolved FQN ∈ context.rejection_path_index
```

### Changes to ScanContext

Add two fields with `__post_init__` conversion:

```python
@dataclass(frozen=True)
class ScanContext:
    ...
    rejection_path_index: frozenset[str] = frozenset()
    import_alias_map: MappingProxyType[str, str] | None = None

    def __post_init__(self) -> None:
        # ... existing conversions ...
        # [R2 fix #7: explicit __post_init__ for both new fields]
        if isinstance(self.rejection_path_index, set):
            object.__setattr__(
                self, "rejection_path_index",
                frozenset(self.rejection_path_index),
            )
        if isinstance(self.import_alias_map, dict):
            object.__setattr__(
                self, "import_alias_map",
                MappingProxyType(self.import_alias_map),
            )
```

### Engine changes

**`_build_project_indexes` return type:** Extract into a `ProjectIndex` dataclass replacing the current 3-tuple. The engine stores this as `self._project_index` and updates all attribute accesses (`self._project_annotations` → `self._project_index.annotations`, etc.). **[R2 fix from SA #6: Explicitly call out all callsite updates.]**

```python
@dataclass(frozen=True)
class ProjectIndex:
    annotations: MappingProxyType[tuple[str, str], tuple[WardlineAnnotation, ...]]
    module_file_map: MappingProxyType[str, str]
    string_literal_counts: MappingProxyType[str, int]
    rejection_path_index: frozenset[str]
```

Callers in `scan()` and `_scan_file()` that currently access `self._project_annotations`, `self._module_file_map`, `self._string_literal_counts` must be updated to `self._project_index.annotations`, etc.

**Error handling:** If `_has_rejection_path` raises on a malformed function node during the indexing pass, catch the exception, log a warning, and exclude the function from the index. Follow the existing fault-tolerance pattern (try/except with TOOL-ERROR finding).

### Implementation touchpoints

| Action | File | What |
|--------|------|------|
| Modify | `src/wardline/scanner/rejection_path.py` | Keep `_has_rejection_path` + helpers authoritative here; ensure expansion and direct detection share reachability semantics |
| Modify | `src/wardline/scanner/import_resolver.py` | `build_import_alias_map(tree) → dict[str, str]`; keep resolver explicitly limited to syntactic import/local-name resolution |
| Modify | `src/wardline/scanner/rules/py_wl_008.py` | Import from `scanner.rejection_path`, add `_has_delegated_rejection` |
| Modify | `src/wardline/scanner/context.py` | Add `rejection_path_index` and `import_alias_map` fields + `__post_init__` |
| Modify | `src/wardline/scanner/engine.py` | `ProjectIndex` dataclass, compute index + alias maps in `_build_project_indexes`, update all `self._project_*` → `self._project_index.*` |
| Modify | `src/wardline/core/severity.py` | Add `GOVERNANCE_CUSTOM_KNOWN_VALIDATOR` RuleId |
| Modify | `src/wardline/scanner/sarif.py` | Add new RuleId to `_RULE_SHORT_DESCRIPTIONS` and `_PSEUDO_RULE_IDS` |
| Modify | `src/wardline/manifest/models.py` | Add `known_validators` + `known_validators_extra` to `_KNOWN_KEYS` and `ScannerConfig` |
| Modify | `src/wardline/cli/scan.py` | Compute effective known_validators, emit GOVERNANCE_CUSTOM_KNOWN_VALIDATOR findings, and thread the effective set into `ScanEngine` |

### Pre-existing bug to fix: `_is_inside_dead_branch` walks into nested defs

**[R2 fix #6 from PE:]** `_is_inside_dead_branch` in current `py_wl_008.py` (line 115-129) uses `ast.walk(root)` which descends into nested function bodies. A nested function's `raise` could wrongly mark the outer function as NOT being inside a dead branch. When extracting to `scanner/rejection_path.py`, replace `ast.walk` with `walk_skip_nested_defs` in `_is_inside_dead_branch`. This is a pre-existing bug that the index would amplify.

### Testing strategy (expanded — 36 cases)

**Unit tests for `_has_delegated_rejection` (isolated, no boundary context):**
1. Body calls function in index → True
2. Body calls function NOT in index → False
3. Multiple calls, only one in index → True (any match suffices)
4. No calls at all → False
5. Call to imported project module attribute `validators.validate()` where `validators` resolves via alias map and `myproject.validators.validate` is in index → resolved correctly
6. Lambda in body → not matched as delegation

**Unit tests for import alias resolution (`build_import_alias_map`):**
7. `import jsonschema` → `{"jsonschema": "jsonschema"}`
8. `from jsonschema import validate` → `{"validate": "jsonschema.validate"}`
9. `import jsonschema as js` → `{"js": "jsonschema"}`
10. `from jsonschema import validate as v` → `{"v": "jsonschema.validate"}`
11. Local `def validate()` shadows imported `validate` → resolves to local FQN, not import
12. Star import → not in alias map (unresolvable)

**Integration tests for PY-WL-008 (through visit_function):**
13. Boundary calls local helper that raises → no finding
14. Boundary calls local helper that doesn't raise → finding fires
15. Boundary calls known validator (dotted name `jsonschema.validate()`) → no finding
16. Boundary calls known validator (bare name `from jsonschema import validate; validate()`) → no finding
17. Boundary calls unknown third-party → finding fires
18. Boundary with no calls → finding fires
19. Boundary with direct raise → no finding (existing logic)
20. Wrapper pattern: boundary → wrapper → known validator → no finding (index expansion)
21. Three-hop chain: boundary → wrapper → helper → raise → finding fires (expansion limited to one round) **[R2 fix #9 from SecA: clarified description]**
22. Async boundary with delegated rejection → no finding
23. Decorator-detected boundary (no manifest) with delegation → no finding
24. Boundary calling helper only in `if False:` block → finding fires (delegated call is unreachable, so expansion/reuse does not suppress)

**Config tests:**
25. `known_validators_extra` merges with built-in defaults
26. `known_validators` replaces built-in defaults
27. Both present → `known_validators` wins with warning
28. Neither present → built-in defaults used
29. Custom entry produces `GOVERNANCE_CUSTOM_KNOWN_VALIDATOR` finding with `Severity.WARNING`

**Backward compatibility:**
30. Empty `rejection_path_index` (ScanContext default) → all existing behavior preserved
31. Boundary calling `jsonschema.validate()` with empty index still fires (confirms index is required, not automatic)

**Edge cases:**
32. Qualname collision: `foo.validate` (has rejection) vs `bar.validate` (no rejection) — FQNs distinguish them
33. Circular calls between project functions — neither has a raise, neither enters index
34. Malformed function node during index build → warning logged, function excluded, scan continues
35. `self.validate()` / receiver-method call remains unresolved and does not suppress the finding

**Integration test for full pipeline:**
36. Engine with fixture project: file with `@validates_shape` boundary delegating to local helper with raise → no finding end-to-end (validates `_build_project_indexes` → ScanContext → rule)

### Interaction with existing rules

- **PY-WL-009** is unaffected — checks shape evidence, not rejection paths
- **PY-WL-007** is unaffected — checks isinstance/type patterns
- **SCN-021** is unaffected — decorator combination detection
- **Matrix cell tests** are unaffected — inject taint directly
- **Taint propagation (L3)** is unaffected — rejection path index is orthogonal to taint flow

### Known limitations

1. **Star imports** — `from jsonschema import *` makes `validate` unresolvable. Finding fires.
2. **Dynamic imports** — `importlib.import_module` calls cannot be followed. Finding fires.
3. **Vacuous guards in callees** — a function with `if some_runtime_condition: raise` where the condition is always false at runtime but not a constant expression will be in the index despite never actually rejecting. This is inherited from `_has_rejection_path` and **amplified by the index** (per SecA review — one poisoned function suppresses all boundaries that call it, vs current intraprocedural check which requires evasion at each boundary individually). Mitigated by requiring expansion to honor the same dead-branch exclusions as direct rejection-path detection, plus the GOVERNANCE finding on custom known_validators entries. This remains a residual risk, not a conformance blocker, because WL-007 is defined in the spec as a structural-presence check rather than a semantic-proof obligation.
4. **`sys.exit()` and `typing.assert_never()`** — not recognized as rejection paths by `_has_rejection_path`. Pre-existing limitation, not introduced by this design.
5. **Assignments as local shadows** — `validate = some_factory()` at module level does not shadow an imported `validate` for the purposes of call resolution. Only `def`/`async def` count as local definitions.
6. **Receiver method calls** — `self.validate()` / `obj.validate()` are intentionally unresolved in this design. Supporting them would require receiver/type analysis beyond the spec-required two-hop structural check.

---

## Success Criteria

- `@validates_shape` boundary calling `jsonschema.validate(data, schema)` does NOT fire (any import form: `import jsonschema`, `from jsonschema import validate`, `import jsonschema as js`)
- `@validates_shape` boundary calling a local helper with `raise` does NOT fire
- `@validates_shape` boundary calling a wrapper around `jsonschema.validate` does NOT fire (index expansion)
- `@validates_shape` boundary with no rejection path (direct or delegated) DOES fire
- Delegated suppression only occurs for reachable calls; dead-branch helper calls do NOT satisfy WL-007
- All existing PY-WL-008 tests continue to pass with empty index
- `known_validators_extra` merges with defaults; `known_validators` replaces
- Custom entries produce `GOVERNANCE_CUSTOM_KNOWN_VALIDATOR` finding at `Severity.WARNING`
- Import aliases correctly resolved across all 4 import forms
- Receiver-method calls such as `self.validate()` remain unresolved by design and do not suppress WL-007
- FQNs used throughout (index, alias map, call resolution)
- `_is_inside_dead_branch` uses `walk_skip_nested_defs` (pre-existing bug fix)
- `uv run pytest` green, `uv run ruff check` clean, `uv run mypy` clean
