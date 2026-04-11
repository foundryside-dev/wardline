# Workstream D: Manifest Enforcement

> **Purpose:** Spec and implementation plan for closing manifest validation and
> enforcement gaps identified in the 2026-04-09 conformance review (R5, R8, R13).
> Give this to an implementation agent. It is self-contained.

**Branch:** `phase-4.4-test-quality-gates`
**Conformance review:** `docs/requirements/spec-fitness/conformance-review-2026-04-09.md`
**Spec authority:** `docs/spec/wardline-01-14-portability-and-manifest-format.md` (§14),
`docs/spec/wardline-01-07-annotation-vocabulary.md` (§7),
`docs/spec/wardline-02-A-python-binding.md` (§A.4.2)

---

## 1. Problem Statement

The external conformance review identified 3 gaps in manifest enforcement
that allow invalid or under-specified configurations to pass without error.

| Finding | Severity | Description |
|---------|----------|-------------|
| R5 | HIGH | `validation_scope` not schema-required for boundaries claiming Tier 2 — spec says MUST |
| R8 | MEDIUM | Group 16 parameterised `trust_boundary(from_tier, to_tier)` decorator missing |
| R13 | HIGH | Delegation authority not checked at overlay merge — overlays can grant exceptions beyond their authority |

---

## 2. Normative Requirements

### 2.1 Validation Scope on Tier 2 Boundaries (§14.1.2)

The spec (§14.1.2) states:

> "Every boundary that claims Tier 2 semantics — `semantic_validation`
> boundaries, `combined_validation` boundaries, and restoration boundaries
> with `semantic: true` in their provenance evidence — MUST include a
> `validation_scope` object."

And:

> "**Enforcement:** The tool presence-checks the `validation_scope` field — a
> boundary claiming Tier 2 semantics without a `validation_scope` declaration
> is a finding."

The `validation_scope` object declares named boundary contracts with:
- `contracts`: array of `{name, data_tier, direction, description?, preconditions?}`
- `description`: optional top-level description

**Tier 2 boundary transitions are:**
- `semantic_validation` (from_tier=3, to_tier=2) — e.g., `@validates_semantic`
- `combined_validation` (from_tier=4, to_tier=2) — e.g., `@validates_external`
- `restoration` with `semantic: true` in provenance — restoration boundaries
  claiming semantic validation

### 2.2 Parameterised Trust Boundary (§7, §A.4.2)

The spec (§A.4.2) defines Group 16:

```
| 16 | Generic Trust Boundary | @trust_boundary(from_tier=N, to_tier=M) |
|    |                        | from_tier, to_tier: integers 1-4        |
|    |                        | Parameterised tier transition.           |
|    |                        | Skip-promotions to T1 are schema-invalid.|
```

Group 1 decorators are aliases for common Group 16 configurations:

| Group 1 Decorator | Equivalent Group 16 |
|---|---|
| `@validates_shape` | `@trust_boundary(from_tier=4, to_tier=3)` |
| `@validates_semantic` | `@trust_boundary(from_tier=3, to_tier=2)` |
| `@validates_external` | `@trust_boundary(from_tier=4, to_tier=2)` |
| `@integral_writer` | `@trust_boundary(from_tier=2, to_tier=1)` + call-site enforcement |
| `@integral_construction` | `@trust_boundary(from_tier=2, to_tier=1)` |

The parameterised form allows custom transitions not covered by Group 1,
with the constraint: `to_tier=1` is only valid when `from_tier=2` (no skip
promotion to T1).

### 2.3 Delegation Authority at Merge (§14.1.3)

The spec (§14.1) states:

> "An overlay CANNOT grant exception classes it has not been delegated
> authority for (§14.1.3)"

And:

> "The root manifest declares a default delegation authority (RECOMMENDED:
> RELAXED) and per-path grants that raise or lower the authority for specific
> module paths. An overlay at a path with `authority: NONE` cannot self-grant
> any exceptions."

The delegation config is:
```yaml
delegation:
  default_authority: RELAXED
  grants:
    - path: src/core/
      authority: STANDARD
    - path: src/external/
      authority: NONE
```

Authority levels (from most to least permissive):
- `RELAXED` — can grant RELAXED exceptions
- `STANDARD` — can grant STANDARD and RELAXED exceptions
- `NONE` — cannot grant any exceptions

`UNCONDITIONAL` is never delegable — this is structural (already enforced).

---

## 3. Current State Audit

### 3.1 BoundaryEntry (`models.py:179-201`)

```python
@dataclass(frozen=True)
class BoundaryEntry:
    function: str
    transition: str
    from_tier: int | None = None
    to_tier: int | None = None
    restored_tier: int | None = None
    provenance: MappingProxyType[str, object] | None = None
    validation_scope: MappingProxyType[str, object] | None = None  # OPTIONAL
    overlay_scope: str = ""
    overlay_path: str = ""
```

`validation_scope` is optional — no enforcement for Tier 2 boundaries.

### 3.2 Overlay Schema (`schemas/overlay.schema.json`)

Lines 88-89 — boundary required fields:
```json
"required": ["function", "transition"],
```

`validation_scope` is NOT in the required array. The schema validates
`validation_scope` structure IF present (requires `contracts` array with
`name`, `data_tier`, `direction`) but doesn't require the field itself.

### 3.3 Boundary Loading (`loader.py:356-371`)

```python
validation_scope=b.get("validation_scope"),  # Just gets value, no validation
```

No check that Tier 2 boundaries have `validation_scope`.

### 3.4 Group 16 in Registry (`registry.py:197-206`)

Only `data_flow` is registered for Group 16:
```python
"data_flow": RegistryEntry(
    canonical_name="data_flow",
    group=16,
    attrs={
        "_wardline_data_flow": bool,
        "_wardline_consumes": int,
        "_wardline_produces": int,
    },
),
```

No `trust_boundary` entry with `from_tier`/`to_tier` parameters.

### 3.5 Existing Trust Boundary Decorators (`decorators/boundaries.py:20-32`)

```python
trust_boundary = wardline_decorator(6, "trust_boundary", ...)
tier_transition = wardline_decorator(6, "tier_transition", ...)
```

These are Group 6 (non-parameterised). The Group 16 parameterised form does
not exist.

### 3.6 DelegationConfig (`models.py:116-128`)

```python
@dataclass(frozen=True)
class DelegationConfig:
    default_authority: str = "RELAXED"
    grants: tuple[DelegationGrant, ...] = ()
```

Loaded correctly from manifest. But never checked during merge or exception
matching.

### 3.7 Merge Logic (`merge.py:69-191`)

Checks performed:
- Rule override narrowing (severity can only increase, not decrease)
- Boundary tier narrowing (tier can only go up, not down)

NOT checked:
- Delegation authority for exceptions in the overlay

### 3.8 Exception Loading (`exceptions.py:28-86`)

Validates:
- UNCONDITIONAL cells rejected (structural, non-delegable)
- AST fingerprints present

NOT validated:
- Whether the overlay's delegation authority permits the exception's
  exceptionability class

---

## 4. Implementation Plan

### 4.1 Execution Order and Dependencies

```
R5 (validation_scope)      ─── no deps ─── schema + loader change
  │
R8 (trust_boundary)        ─── no deps ─── registry + decorator + scanner
  │
R13 (delegation authority)  ─── no deps ─── merge + exception loading
```

All three are independent — no cross-dependencies.

### 4.2 R5: Enforce `validation_scope` on Tier 2 Boundaries

**Approach:** Two layers of enforcement:
1. **Schema-level:** Add a conditional requirement in the JSON schema (or
   document that JSON Schema draft-07 doesn't support conditional requires
   cleanly — use runtime validation instead)
2. **Loader-level:** After loading boundaries, validate that Tier 2 boundaries
   have `validation_scope`. Emit a governance finding if missing.

The spec says "a boundary claiming Tier 2 semantics without a `validation_scope`
declaration is a finding" — this is a scanner finding, not a load-time rejection.
The boundary loads successfully but the scanner flags the missing scope.

**Files:**
- Modify: `src/wardline/manifest/loader.py` — Add validation after building
  boundaries. For each boundary where `to_tier == 2` (or transition is
  `semantic_validation` or `combined_validation`, or transition is `restoration`
  with `provenance.semantic == True`), check that `validation_scope` is not
  None. If missing, emit a warning or store for later scanner findings.

  The cleanest approach: add a `_validate_tier2_boundaries()` function called
  after `_build_overlay()`:
  ```python
  def _validate_tier2_boundaries(
      boundaries: tuple[BoundaryEntry, ...],
  ) -> list[str]:
      """Return warning messages for Tier 2 boundaries missing validation_scope."""
      warnings = []
      for b in boundaries:
          if _is_tier2_boundary(b) and b.validation_scope is None:
              warnings.append(
                  f"Boundary {b.function} ({b.transition}) claims Tier 2 "
                  f"semantics but has no validation_scope declaration"
              )
      return warnings

  def _is_tier2_boundary(b: BoundaryEntry) -> bool:
      """Check if boundary claims Tier 2 semantics."""
      if b.transition in ("semantic_validation", "combined_validation"):
          return True
      if b.to_tier == 2:
          return True
      if (b.transition == "restoration"
              and b.provenance is not None
              and b.provenance.get("semantic") is True):
          return True
      return False
  ```

- Modify: `src/wardline/cli/scan.py` — Wire validation warnings into
  governance findings. When `_validate_tier2_boundaries()` returns warnings,
  emit `GOVERNANCE_MISSING_VALIDATION_SCOPE` findings (add to RuleId if
  needed).

- Modify: `src/wardline/core/severity.py` — Add
  `GOVERNANCE_MISSING_VALIDATION_SCOPE` to `RuleId` if not already present.

**Tests:**
- `test_tier2_boundary_without_validation_scope_emits_finding` — semantic_validation
  boundary with no validation_scope produces governance finding
- `test_tier2_boundary_with_validation_scope_ok` — no finding when present
- `test_combined_validation_without_scope_emits_finding` — combined_validation
- `test_restoration_semantic_without_scope_emits_finding` — restoration with
  semantic provenance
- `test_tier3_boundary_without_scope_ok` — shape_validation (Tier 3) doesn't
  require validation_scope

**Commit:** `fix(R5): enforce validation_scope on Tier 2 boundaries`

### 4.3 R8: Implement Group 16 Parameterised `trust_boundary`

**Approach:** Add a parameterised `@trust_boundary(from_tier=N, to_tier=M)`
decorator in Group 16 that:
1. Accepts `from_tier` and `to_tier` as integer parameters (1-4)
2. Enforces the skip-promotion constraint: `to_tier=1` only when `from_tier=2`
3. Sets `_wardline_*` attributes that the scanner reads
4. Is recognized by taint assignment and boundary detection

**Files:**
- Modify: `src/wardline/core/registry.py` — Add Group 16 entry for
  `trust_boundary`:
  ```python
  "trust_boundary": RegistryEntry(
      canonical_name="trust_boundary",
      group=16,
      attrs={
          "_wardline_trust_boundary": bool,
          "_wardline_from_tier": int,
          "_wardline_to_tier": int,
      },
  ),
  ```

  Note: This may conflict with the existing Group 6 `trust_boundary` entry.
  Check if Group 6 already has a `trust_boundary` name. If so, the Group 16
  version needs a distinct canonical name (e.g., `parameterised_trust_boundary`)
  or the Group 6 entry should be renamed. **Read `registry.py` carefully to
  resolve naming conflicts.**

  Looking at the current code: Group 6 has `trust_boundary` (non-parameterised,
  `_wardline_trust_boundary=True`) and `tier_transition`
  (`_wardline_tier_transition=True`). The Group 16 parameterised form is a
  different decorator with parameters. Options:
  - **Option A:** Keep Group 6 `trust_boundary` as-is, add Group 16 as
    `parameterised_trust_boundary` — awkward naming
  - **Option B:** Move Group 6's `trust_boundary` to Group 16 with optional
    parameters (no params = Group 6 behavior, with params = Group 16 behavior)
    — cleaner but riskier
  - **Option C:** The spec says Group 16's decorator IS `@trust_boundary(from_tier, to_tier)`.
    The Group 6 usage is the non-parameterised marker. Add the Group 16
    entry with the same name but different group number. The registry keyed
    by canonical_name will need to handle this — **check if the registry
    allows duplicate canonical names across groups.**

  Read `registry.py` to determine the registry's key structure before deciding.
  The frozen `REGISTRY` is a `MappingProxyType` keyed by canonical_name, so
  **duplicate names are not possible**. The solution is likely to make the
  Group 16 decorator `trust_boundary` with parameters while the Group 6
  decorator keeps a different name or is subsumed.

  **Recommended approach:** Since the spec says Group 16 is
  `@trust_boundary(from_tier, to_tier)`, rename the Group 6 non-parameterised
  `trust_boundary` to `trust_boundary_marker` (or similar internal name) and
  register the parameterised version as `trust_boundary` in Group 16. This is
  a breaking change for the Group 6 decorator but since this is pre-v1.0, no
  backwards compatibility needed (per project feedback: "no backcompat shims
  for unreleased specs").

- Modify: `src/wardline/decorators/boundaries.py` — Implement the
  parameterised decorator:
  ```python
  def trust_boundary(*, from_tier: int, to_tier: int):
      """Parameterised tier transition boundary (Group 16).

      Enforces skip-promotion constraint: to_tier=1 only when from_tier=2.
      """
      if not (1 <= from_tier <= 4 and 1 <= to_tier <= 4):
          raise ValueError(
              f"from_tier and to_tier must be 1-4, "
              f"got from_tier={from_tier}, to_tier={to_tier}"
          )
      if to_tier == 1 and from_tier != 2:
          raise ValueError(
              f"Skip-promotion to Tier 1: to_tier=1 requires from_tier=2, "
              f"got from_tier={from_tier}"
          )
      if to_tier >= from_tier:
          raise ValueError(
              f"to_tier must be less than from_tier (promotion), "
              f"got from_tier={from_tier}, to_tier={to_tier}"
          )
      def decorator(func):
          func._wardline_trust_boundary = True
          func._wardline_from_tier = from_tier
          func._wardline_to_tier = to_tier
          func._wardline_group = 16
          return func
      return decorator
  ```

- Modify: `src/wardline/scanner/taint/function_level.py` — Ensure taint
  assignment recognizes Group 16 trust boundaries when computing function
  taint from annotations. A `@trust_boundary(from_tier=4, to_tier=3)` should
  assign the function the same taint as `@validates_shape`.

- Modify: `tests/unit/decorators/test_boundaries.py` — Add tests for the
  parameterised decorator:
  - `test_trust_boundary_valid_transition` — from_tier=4, to_tier=3 works
  - `test_trust_boundary_skip_promotion_rejected` — from_tier=4, to_tier=1
    raises ValueError
  - `test_trust_boundary_tier1_from_tier2_ok` — from_tier=2, to_tier=1 works
  - `test_trust_boundary_no_demotion` — from_tier=2, to_tier=3 raises ValueError
  - `test_trust_boundary_sets_attrs` — verify `_wardline_*` attributes set

**Commit:** `fix(R8): implement Group 16 parameterised trust_boundary decorator`

### 4.4 R13: Enforce Delegation Authority at Merge

**Approach:** When loading exceptions from overlays, check that each
exception's exceptionability class is within the overlay's delegation
authority. The delegation authority is determined by matching the exception's
location against the delegation config's path grants.

**Files:**
- Modify: `src/wardline/manifest/merge.py` or
  `src/wardline/scanner/exceptions.py` — Add delegation authority check.

  The check belongs in the exception loading/matching path, not the overlay
  merge path, because exceptions are in `wardline.exceptions.json` (separate
  from overlay YAML). The delegation config comes from the root manifest.

  Add to `src/wardline/scanner/exceptions.py` (or a new helper):
  ```python
  def _check_delegation_authority(
      exception: ExceptionEntry,
      delegation: DelegationConfig,
  ) -> str | None:
      """Check if exception is within delegation authority.

      Returns None if ok, or an error message if the exception exceeds
      the overlay's delegated authority.
      """
      authority = _resolve_authority(exception.location, delegation)
      if authority == "NONE":
          return (
              f"Exception {exception.id} at {exception.location}: "
              f"delegation authority is NONE — no exceptions permitted"
          )
      # UNCONDITIONAL is never delegable (already enforced at schema level)
      exc_class = str(exception.exceptionability)
      if authority == "RELAXED" and exc_class not in ("RELAXED", "TRANSPARENT"):
          return (
              f"Exception {exception.id} at {exception.location}: "
              f"exceptionability {exc_class} exceeds delegation authority "
              f"RELAXED"
          )
      if authority == "STANDARD" and exc_class not in (
          "STANDARD", "RELAXED", "TRANSPARENT"
      ):
          return (
              f"Exception {exception.id} at {exception.location}: "
              f"exceptionability {exc_class} exceeds delegation authority "
              f"STANDARD"
          )
      return None


  def _resolve_authority(
      location: str, delegation: DelegationConfig
  ) -> str:
      """Resolve the delegation authority for a given location.

      Matches against grants by longest-prefix match, falling back
      to default_authority.
      """
      best_match = ""
      best_authority = delegation.default_authority
      for grant in delegation.grants:
          if location.startswith(grant.path) and len(grant.path) > len(best_match):
              best_match = grant.path
              best_authority = grant.authority
      return best_authority
  ```

- Modify: `src/wardline/scanner/exceptions.py` — In `apply_exceptions()`
  (or wherever exceptions are matched to findings), call the delegation
  check. When an exception exceeds its authority, emit a
  `GOVERNANCE_DELEGATION_EXCEEDED` finding and treat the exception as
  ineffective (the finding remains unexcepted).

- Modify: `src/wardline/core/severity.py` — Add
  `GOVERNANCE_DELEGATION_EXCEEDED` to `RuleId` if not already present.

- Modify: `src/wardline/cli/scan.py` — Pass `delegation` config from the
  loaded manifest to the exception matching path.

**Tests:**
- `test_exception_within_authority_ok` — RELAXED exception at path with
  RELAXED authority, no finding
- `test_exception_exceeds_relaxed_authority` — STANDARD exception at path
  with RELAXED authority, governance finding emitted
- `test_exception_at_none_authority_rejected` — any exception at path with
  NONE authority, governance finding emitted
- `test_delegation_longest_prefix_match` — path with nested grants resolves
  to most specific
- `test_delegation_default_when_no_grant` — falls back to default_authority
- `test_unconditional_never_delegable` — already enforced, verify it still
  works

**Commit:** `fix(R13): enforce delegation authority at exception matching`

---

## 5. Correctness Constraints

1. **R5 is a finding, not a load rejection.** The spec says "a boundary
   claiming Tier 2 semantics without a `validation_scope` declaration is a
   **finding**." The manifest loads successfully — the scanner emits a
   governance finding. This matches the precedent of other governance checks
   (coherence checks produce findings, not load failures).

2. **R8 skip-promotion constraint is enforced at decoration time.** The
   `@trust_boundary(from_tier=4, to_tier=1)` must raise `ValueError`
   immediately — it doesn't wait for the scanner to catch it. This is
   consistent with other decorator validation (e.g., tier values out of range).

3. **R8 naming conflict must be resolved.** The Group 6 `trust_boundary`
   and Group 16 `trust_boundary` share a name. The registry is keyed by
   canonical name. Since this is pre-v1.0 (no backcompat needed), rename
   the Group 6 entry or subsume it into Group 16.

4. **R13 delegation check uses longest-prefix match.** When multiple grants
   overlap (e.g., `src/` → RELAXED, `src/core/` → STANDARD), the most
   specific (longest) path wins. This is standard path-matching semantics.

5. **R13 exceeding delegation produces a governance finding AND makes the
   exception ineffective.** A finding covered by an unauthorized exception
   remains unexcepted — it still blocks the gate if its severity is ERROR.
   The governance finding provides the audit trail.

6. **UNCONDITIONAL is never delegable — already enforced.** The schema
   rejects UNCONDITIONAL exceptions, and `apply_exceptions()` skips
   UNCONDITIONAL cells. R13 adds the delegation layer on top of these
   existing protections.

---

## 6. Testing Strategy

| Fix | Test Location | What |
|-----|--------------|------|
| R5 | `tests/unit/manifest/test_loader.py` | Tier 2 boundary without scope detected |
| R5 | `tests/unit/cli/test_scan_cmd.py` | Governance finding emitted in scan |
| R8 | `tests/unit/decorators/test_boundaries.py` | Parameterised decorator validation |
| R8 | `tests/unit/scanner/test_rules_taint_aware.py` | Taint assignment from Group 16 |
| R13 | `tests/unit/scanner/test_exceptions.py` | Delegation authority enforcement |
| R13 | `tests/unit/manifest/test_merge.py` | Authority resolution by path prefix |
| All | `tests/integration/test_self_hosting_scan.py` | Self-hosting scan still passes |

---

## 7. Key Files Reference

| File | Purpose |
|------|---------|
| `src/wardline/manifest/models.py:179-201` | `BoundaryEntry` — validation_scope field |
| `src/wardline/manifest/models.py:116-128` | `DelegationConfig` — authority grants |
| `src/wardline/manifest/schemas/overlay.schema.json:88-89` | Boundary required fields |
| `src/wardline/manifest/loader.py:356-371` | Boundary loading — no validation |
| `src/wardline/manifest/merge.py:69-191` | Merge logic — narrow-only checks |
| `src/wardline/scanner/exceptions.py:38-270` | Exception matching — no delegation check |
| `src/wardline/core/registry.py:197-206` | Group 16 registry entries |
| `src/wardline/decorators/boundaries.py:20-32` | Trust boundary decorators |
| `src/wardline/scanner/taint/function_level.py` | Taint assignment from annotations |
| `src/wardline/core/severity.py` | `RuleId` enum — add governance IDs |

---

## 8. Code Conventions

- `from __future__ import annotations` everywhere
- `MappingProxyType` for deep immutability of registries
- Explicit `ValueError` over `assert` (survives `python -O`)
- Ruff line length: 140. Target: Python 3.12+
- mypy strict mode with `warn_return_any`
- No backcompat shims for unreleased specs — just make clean changes

---

## 9. Commit Strategy

3 commits, one per fix:

1. `fix(R5): enforce validation_scope on Tier 2 boundaries`
2. `fix(R8): implement Group 16 parameterised trust_boundary decorator`
3. `fix(R13): enforce delegation authority at exception matching`

---

## 10. Status Protocol

Report after each fix: DONE, DONE_WITH_CONCERNS, NEEDS_CONTEXT, or BLOCKED.
