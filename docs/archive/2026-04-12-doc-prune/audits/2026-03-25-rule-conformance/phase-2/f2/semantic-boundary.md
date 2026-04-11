# Semantic Boundary Assessment

**Assessor:** Semantic Boundary Agent
**Date:** 2026-03-25
**Scope:** Boundary contract names, implementation stability, refactor-safety
**Spec reference:** wardline-01-14-portability-and-manifest-format.md, section 13.1.2

---

## 1. Contract Declaration Schema

**Spec requirement:** Each contract declares `name`, `data_tier`, `direction`, `description` (optional), `preconditions` (optional).

**Implementation:**

- **JSON Schema** (`src/wardline/manifest/schemas/overlay.schema.json`, lines 61-82): The `bounded_context.contracts` items define `name` (string, required), `data_tier` (integer 1-4, required), `direction` (enum `"inbound"` / `"outbound"`, required), `description` (string, optional), `preconditions` (string, optional). `additionalProperties: false` enforces the closed schema.
- **Data model** (`src/wardline/manifest/models.py`, line 149): `BoundaryEntry.bounded_context` is typed as `dict[str, object] | None`. There is no dedicated `ContractDeclaration` dataclass -- contracts remain untyped dicts inside the `bounded_context` dict after loading.
- **Loader** (`src/wardline/manifest/loader.py`, lines 267-269): `_build_overlay` passes `b.get("bounded_context")` through as a raw dict. No further structural validation or typed construction occurs.

**Finding:** The JSON Schema validates the contract structure at load time, which is correct. However, contract declarations are never promoted to typed objects in the Python layer -- they persist as raw dicts. This means downstream code accessing `boundary.bounded_context["contracts"][0]["name"]` has no static type safety. The spec's contract fields are all present and validated at the schema level. This is a design choice, not a conformance gap, but it reduces refactor safety: a typo in a dict key access would not be caught by type checkers.

**Assessment: PASS** (schema-level validation is conformant; typed model is a quality concern, not a spec violation)

---

## 2. Contract Bindings

**Spec requirement:** Separation of stable contract declarations (what crosses the boundary) from volatile function bindings (where code currently lives). `contract_bindings` is a secondary mapping in the overlay.

**Implementation:**

- **JSON Schema** (`overlay.schema.json`, lines 110-125): `contract_bindings` is an array of objects with `contract` (string, required) and `functions` (array of strings, required). `additionalProperties: false`.
- **Data model** (`src/wardline/manifest/models.py`, lines 166-170): `ContractBinding` dataclass with `contract: str` and `functions: tuple[str, ...]`. Frozen, correctly typed.
- **Overlay model** (`src/wardline/manifest/models.py`, line 192): `WardlineOverlay.contract_bindings: tuple[ContractBinding, ...]`.
- **Loader** (`src/wardline/manifest/loader.py`, lines 273-279): `_build_overlay` constructs `ContractBinding` objects from the YAML data.

**Finding:** The separation between contract declarations (inside `bounded_context.contracts` on boundary entries) and contract bindings (top-level `contract_bindings` on the overlay) is correctly implemented. Contract declarations are policy artefacts; bindings are enforcement artefacts. A function rename only requires updating `contract_bindings`, not the contract declarations themselves.

**Gap:** There is no cross-validation that every contract name referenced in `contract_bindings` has a corresponding declaration in some boundary's `bounded_context.contracts`. A binding could reference a non-existent contract name without error. The spec does not explicitly require this check, but it is implied by the governance model. This is a minor integrity gap.

**Assessment: PASS** (separation is correct; cross-validation gap is minor)

---

## 3. Overlay Merge Semantics (Narrowing-Only)

**Spec requirement:** Overlays may narrow but never widen: cannot relax tier assignments, cannot lower severity, can raise severity or add boundaries. Widening is a hard error.

**Implementation** (`src/wardline/manifest/merge.py`):

- **Severity narrowing** (lines 100-119): The merge function checks overlay rule overrides against base overrides. If `overlay_severity < base_severity` (using `_severity_rank`), it raises `ManifestWidenError`. Correctly rejects severity lowering.
- **Tier narrowing** (lines 136-156): Boundary-level checks compare `from_tier` and `to_tier` against the resolved module tier from the base manifest. If a boundary declares a tier number higher than the module's assigned tier, `ManifestWidenError` is raised.
- **Error, not warning** (line 40): `ManifestWidenError` is an exception class, causing a hard failure -- not a warning. This matches the spec requirement.

**Finding:** The narrowing-only invariant is enforced for both severity and tier assignments. The merge rejects widening with a hard error as required.

**Gap:** The tier narrowing check uses `_resolve_module_tier` which resolves via `tier_number_map` keyed by `TierEntry.id`. `ModuleTierEntry.default_taint` is used as the lookup key into the tier map. If a module's `default_taint` does not match any `TierEntry.id`, `_resolve_module_tier` returns `None` and the boundary tier check is skipped entirely (lines 141-156). This means a boundary in a module with no tier mapping silently bypasses the narrow-only check. This is noted in the code comment (line 78) as "deferred to coherence checks," which partially mitigates but does not eliminate the gap.

**Assessment: PASS** (narrowing enforced; edge case on unmapped modules is documented and mitigated by coherence checks)

---

## 4. Optional-Field Declarations

**Spec requirement:** `optional_fields` in overlays with `field`, `approved_default`, and `rationale`.

**Implementation:**

- **JSON Schema** (`overlay.schema.json`, lines 97-109): `optional_fields` array with items requiring `field` (string), `approved_default` (any type), `rationale` (string). `additionalProperties: false`.
- **Data model** (`src/wardline/manifest/models.py`, lines 155-162): `OptionalFieldEntry` frozen dataclass with `field: str`, `approved_default: object`, `rationale: str`, plus `overlay_scope` and `overlay_path` provenance fields.
- **Loader** (`src/wardline/manifest/loader.py`, lines 285-292): `_build_overlay` constructs `OptionalFieldEntry` objects.
- **Scanner context** (`src/wardline/scanner/context.py`, line 96): `ScanContext.optional_fields: tuple[OptionalFieldEntry, ...]` -- optional fields are available to rules.

**Finding:** The full optional-field mechanism is implemented end-to-end: schema validates the structure, the loader constructs typed objects, and the scanner context exposes them to rules.

**Assessment: PASS**

---

## 5. Dependency Taint Declarations

**Spec requirement:** `dependency_taint` section in overlays declaring third-party function return taint states with `package`, `functions` (each with `function` and `returns_taint`), `rationale`, and `reviewed` date.

**Implementation:**

- **JSON Schema** (`overlay.schema.json`): No `dependency_taint` property defined. The schema has `additionalProperties: false`, meaning any overlay with a `dependency_taint` section would be **rejected at schema validation**.
- **Data model** (`src/wardline/manifest/models.py`): No `DependencyTaintEntry` or equivalent class exists.
- **Overlay model** (`src/wardline/manifest/models.py`, line 185-193): `WardlineOverlay` has no `dependency_taint` field.
- **Loader** (`src/wardline/manifest/loader.py`): No loading logic for `dependency_taint`.
- **Grep confirmation:** Zero matches for `dependency_taint` or `DependencyTaint` across all Python source files.

**Finding:** The dependency taint mechanism specified in section 13.1.2 is entirely unimplemented. No schema, no model, no loader, no engine consumption. Furthermore, because the overlay schema uses `additionalProperties: false`, a user who adds a `dependency_taint` section to their overlay will receive a schema validation error.

**Assessment: FAIL** -- the feature is absent from schema, model, and loader.

---

## 6. "Both Must Agree" Constraint

**Spec requirement:** An enforcement tool that finds a manifest boundary declaration without a corresponding code annotation, or vice versa, produces a finding.

**Implementation** (`src/wardline/manifest/coherence.py`):

- **`check_orphaned_annotations`** (lines 43-77): Finds functions with wardline decorators in code but no matching boundary declaration in any overlay. Produces `orphaned_annotation` issues.
- **`check_undeclared_boundaries`** (lines 80-113): Finds boundary declarations whose function name has no matching decorated function in code. Produces `undeclared_boundary` issues.

**Integration:**
- `src/wardline/cli/coherence_cmd.py` wires both checks into the `wardline manifest coherence` command.
- `src/wardline/cli/regime_cmd.py` (line 88-89) runs both checks as part of `regime verify`.

**Finding:** The bidirectional "both must agree" check is implemented correctly. Both directions (code without manifest, manifest without code) produce findings. The checks are wired into both the standalone coherence command and the regime verification flow.

**Assessment: PASS**

---

## Summary

| Check | Result | Notes |
|-------|--------|-------|
| 1. Contract declaration schema | PASS | All five fields present in JSON Schema; contracts remain untyped dicts in Python |
| 2. Contract bindings | PASS | Separation of declarations from bindings is correct; no cross-name validation |
| 3. Overlay merge (narrowing-only) | PASS | Severity and tier widening rejected as hard errors |
| 4. Optional-field declarations | PASS | Full end-to-end implementation |
| 5. Dependency taint declarations | **FAIL** | Entirely absent -- no schema, model, loader, or engine support |
| 6. "Both must agree" constraint | PASS | Bidirectional coherence checks implemented and wired |

---

## Verdict: CONCERN

Five of six assessment criteria pass. One criterion -- dependency taint declarations (section 13.1.2) -- is entirely unimplemented. The feature is absent from the overlay JSON schema (`additionalProperties: false` would reject it), the data model, the loader, and the scanner engine. A user attempting to declare dependency taint in an overlay would receive a schema validation error.

This is a spec-implementation gap, not a subtle bug. The dependency taint mechanism is a distinct feature that requires schema extension, a new model class, loader logic, and engine integration. Its absence means third-party library return values cannot be classified beyond the UNKNOWN_RAW default (section 5.5), reducing taint precision for projects that depend on external libraries.

Secondary concerns (not rising to FAIL):
- Contract declarations inside `bounded_context` are carried as raw `dict[str, object]` rather than typed dataclasses, reducing static type safety.
- No cross-validation between `contract_bindings` contract names and `bounded_context.contracts` names exists.
- Boundary tier narrowing check is silently skipped when module tier cannot be resolved (documented, mitigated by coherence).

**Evidence for FAIL on criterion 5:**
- `overlay.schema.json` line 128: `"additionalProperties": false` -- no room for `dependency_taint`
- `models.py` `WardlineOverlay` (line 185-193): no `dependency_taint` field
- Zero grep hits for `dependency_taint` across all Python source
