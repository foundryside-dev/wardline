# Runtime Enforcement Hooks Design — WP 3.2

**Date:** 2026-03-24
**Status:** Draft (revised after 6-reviewer panel)
**Scope:** Opt-in runtime tier enforcement — automatic decorator stamping, explicit stamping API, checking functions, WardlineBase integration
**Target release:** v0.4.0
**Dependencies:** WP 2.2 (NewType migration — shipped), `core/tiers.py` (AuthorityTier — exists)

## Problem

The first implementation of WP 3.2 failed a 7-reviewer panel because:
1. The runtime model (`_wardline_tier: int`) was disconnected from the decorator model (`_wardline_tier_source: TaintState`)
2. `WardlineBase.__init__` broke cooperative MRO (no `super().__init__()`, no `*args/**kwargs`)
3. `check_subclass_tier_consistency` read a non-existent attribute (`_wardline_transition_from_tier`)
4. No audit logging before raising — violations left no trace
5. The `ValidatedRecord` Protocol was correct but nothing in the system produced conforming objects

**Second-pass panel review (6 reviewers on redesign) — additional findings incorporated:**
- **Static Analysis C:** `DECORATOR_TAINT_MAP` inconsistent with `_wardline_transition` for `validates_semantic` and `validates_external` — pre-existing bug, must audit before implementing
- **Security C-1/C-2:** In-place stamping is mutable — add `overwrite=False` to `stamp_tier`, document shared-object risks
- **Security C-3:** `disable()` unguarded — implement call-once latch
- **Security C-4:** `TierViolationError(TypeError)` caught by broad handlers — change to `Exception` base
- **Security I-5:** Silent primitive skip is escape hatch — log WARNING on skip
- **SA I-6:** Plain dicts DON'T support `setattr` — fix spec to acknowledge this
- **Systems C:** `_try_stamp_tier` must catch `AttributeError` AND `TypeError` (AST `__slots__`, frozen dataclasses)
- **Systems C:** Shared/cached objects permanently mutated by stamping — document, recommend `TierStamped`
- **All 6:** `_wardline_groups` set vs tuple — normalize to `tuple(sorted(...))` at stamp time
- **QE:** Generator, namedtuple, None return types need explicit tests
- **Security S:** Add optional `on_violation` callback hook for structured observability

## Prerequisites

**BLOCKING: Audit `DECORATOR_TAINT_MAP` against `_wardline_transition` "to" states.** At least `validates_semantic` and `validates_external` have inconsistent taint assignments between the scanner's taint map and the decorator's transition attribute. Fix this pre-existing bug before implementing runtime enforcement — otherwise the runtime and scanner will produce contradictory trust signals.

## Design

### 1. Trust Model Bridge (`core/tiers.py`)

Codify the `TaintState → AuthorityTier` mapping as a frozen dict:

```python
TAINT_TO_TIER: MappingProxyType[TaintState, AuthorityTier] = MappingProxyType({
    TaintState.INTEGRAL: AuthorityTier.TIER_1,
    TaintState.ASSURED: AuthorityTier.TIER_2,
    TaintState.GUARDED: AuthorityTier.TIER_3,
    TaintState.UNKNOWN_ASSURED: AuthorityTier.TIER_3,
    TaintState.UNKNOWN_GUARDED: AuthorityTier.TIER_3,
    TaintState.EXTERNAL_RAW: AuthorityTier.TIER_4,
    TaintState.UNKNOWN_RAW: AuthorityTier.TIER_4,
    TaintState.MIXED_RAW: AuthorityTier.TIER_4,
})
```

Import-time check (NOT `assert` — survives `python -O`):
```python
if len(TAINT_TO_TIER) != len(TaintState):
    raise ValueError(...)
```

**Output tier derivation from decorators:**
- `_wardline_transition` decorators (e.g., `@validates_shape`): output tier = `TAINT_TO_TIER[transition[1]]` (the "to" state)
- `_wardline_tier_source` decorators (e.g., `@external_boundary`): output tier = `TAINT_TO_TIER[tier_source]`
- Supplementary decorators (e.g., `@integrity_critical`): no tier — not a trust boundary

### 2. Automatic Stamping (Decorator Path)

When enforcement is enabled, the decorator wrapper in `decorators/_base.py` gains a post-call hook:

```python
result = unwrapped(*args, **kwargs)
if _enforcement_enabled and result is not None:
    _try_stamp_tier(result, output_tier, output_groups, stamped_by)
return result
```

`_try_stamp_tier` attempts to set three attributes via `setattr`:
- `_wardline_tier: int` — the AuthorityTier value (1-4)
- `_wardline_groups: tuple[int, ...]` — normalized from decorator's set via `tuple(sorted(...))`
- `_wardline_stamped_by: str` — qualname of the function that produced this data

**Error handling:** Catches BOTH `AttributeError` AND `TypeError` silently. `AttributeError` covers `__slots__`-based objects (AST nodes, C extensions). `TypeError` covers frozen dataclasses. On catch: log at DEBUG level ("Skipping auto-stamp for {type}: {reason}") and return without stamping.

**What CAN be stamped:** Class instances with `__dict__`, mutable dataclasses.

**What CANNOT be stamped (silently skipped with WARNING log):**
- Primitives: int, str, bytes, bool, float
- Immutables: tuple, frozenset, frozen dataclasses
- `__slots__`-based objects: AST nodes, some C extension types
- **Plain dicts:** `setattr({}, "x", 1)` raises `AttributeError` — dicts do not support arbitrary attribute assignment. Use `TierStamped` wrapping for dicts.

**Auto-wrapping for unstampable returns:** When `_try_stamp_tier` detects an unstampable return value (dict, primitive, frozen), the decorator wrapper automatically returns `TierStamped(value=result, _wardline_tier=output_tier, ...)` instead of the raw result. This is the zero-ceremony path — users get `TierStamped` objects from boundary functions without writing any wrapping code. The WARNING log still fires to inform operators.

**WARNING log on non-None skip:** When a non-None return value from a boundary-decorated function cannot be stamped, log at WARNING level: `"Auto-stamp skipped for {qualname} return type {type.__name__} — use TierStamped wrapping for this type"`. This prevents the silent escape hatch identified by the security review.

**Output tier computed once at decorator construction time** — not per call. Zero overhead when disabled (single bool check).

**Shared object caveat:** In-place stamping modifies the return value permanently. If the return value is a cached/shared/singleton object, the stamp persists across all references. For cached or shared objects, use `TierStamped` wrapping instead of in-place stamping. Document this explicitly.

### 3. Explicit Stamping API

**`stamp_tier(obj, tier, *, groups=(), stamped_by="", overwrite=False)`**

Sets `_wardline_tier`, `_wardline_groups`, `_wardline_stamped_by` on `obj` via `setattr`. Always stamps (no enforcement flag check). Validates tier is 1-4 (raises `ValueError`). Raises `TypeError` if object doesn't support `setattr`.

**Re-stamp protection:** If `_wardline_tier` already exists on the object and `overwrite=False` (default), raises `ValueError("Object already stamped at tier {existing}. Pass overwrite=True to re-stamp.")`. This prevents silent escalation/weakening.

**`_wardline_groups` normalization:** Groups are stored as `tuple(sorted(groups))` regardless of input type (set, list, tuple). This resolves the set-vs-tuple inconsistency.

**`TierStamped[T]`** — The primary tier-aware data container. A frozen generic dataclass:

```python
T = TypeVar("T")

@dataclass(frozen=True, slots=True)
class TierStamped(Generic[T]):
    value: T
    _wardline_tier: int
    _wardline_groups: tuple[int, ...] = ()
    _wardline_stamped_by: str = ""

    def __post_init__(self) -> None:
        if self._wardline_tier not in (1, 2, 3, 4):
            raise ValueError(f"tier must be 1-4, got {self._wardline_tier}")
```

**This is the answer for dicts, primitives, and all unstampable types.** Generic parameter preserves inner type for mypy: `TierStamped[dict[str, int]]`. Frozen = immutable = tier cannot be escalated after construction. `slots=True` for performance.

**7-reviewer panel decision (D over container subclasses):** Dict subclasses (`TieredDict`) were rejected 5-2 because `|`, `**unpacking`, `copy()`, `json.dumps` all silently strip the subclass, mutation invalidates the tier, mypy cannot distinguish tiers on the same class, and the test surface is unbounded (~80+ tests vs ~25). `TierStamped` makes the tier boundary explicit — the `.value` unwrap IS the trust boundary crossing.

**Recommended lifecycle pattern (from IRAP assessor):**
1. Build data with plain dicts/objects (mutable, no tier claims)
2. Validate at boundary function (decorated with `@validates_shape` etc.)
3. Freeze with `TierStamped` (decorator auto-wraps, or explicit construction)
4. Downstream code receives `TierStamped` — unwraps via `.value` or `unstamp()`

The type transition from mutable dict to frozen `TierStamped` IS the validation event.

**Caveat:** `TierStamped.value` can be a mutable object (e.g., a dict). The wrapper is frozen but the wrapped value is not. Document: "TierStamped stamps a snapshot — if you mutate the underlying value after wrapping, the tier is no longer valid." Follow-up hardening: consider `copy.deepcopy` in constructor for mutable values.

**`unstamp(obj)`** — Returns `obj.value` if `TierStamped`, otherwise returns `obj`.

### 4. Checking API

Both no-ops when enforcement is disabled.

**`check_tier_boundary(obj, *, expected_min_tier, context="")`**

Reads `_wardline_tier` from the object. Raises `TierViolationError` if:
- No `_wardline_tier` attribute
- Value is not an int in range 1-4
- Tier is less trusted than `expected_min_tier` (higher number = less trusted, so check is `tier <= expected_min_tier`)

**Audit logging:** Logs at WARNING level BEFORE raising — every violation leaves a trace even if caught. Log includes: object type, expected tier, actual tier, context string, `_wardline_stamped_by` if present.

**Optional violation callback:** `wardline.runtime.enforcement.on_violation` — if set to a callable, called with the `TierViolationError` instance before raising. Allows routing violations to SIEM, metrics counters, or scan results API without coupling the core to any sink.

**`check_validated_record(obj)`**

Structural check with post-`isinstance` type validation:
- `_wardline_tier` must be `int` in range 1-4
- `_wardline_groups` must be `tuple` or `set` of ints
Logs before raising.

**`TierViolationError(Exception)`** — inherits `Exception` directly, NOT `TypeError`. This prevents broad `except TypeError` handlers from silently swallowing tier violations. Includes `obj`, `expected_tier`, `actual_tier` attributes.

### 5. WardlineBase Integration

**`__init__` — cooperative, with enforcement:**

```python
def __init__(self, *args: object, **kwargs: object) -> None:
    super().__init__(*args, **kwargs)  # cooperative MRO first
    from wardline.runtime.enforcement import enforce_construction
    enforce_construction(self)
```

**Cooperative MRO requirement:** All classes in the MRO chain must forward `**kwargs` for cooperative `__init__` to work. This is standard Python cooperative inheritance — not a wardline-specific requirement. Document in docstring: "If you mix `WardlineBase` with other base classes, all `__init__` methods in the chain must accept and forward `**kwargs`."

**`enforce_construction(instance)`** — When enabled, checks tier consistency across decorated methods. Uses the REAL decorator attributes:
- Reads `_wardline_tier_source` (a `TaintState`) from each decorated method via `getattr`
- Maps to `AuthorityTier` via `TAINT_TO_TIER`
- Reads `_wardline_transition` to find bridging decorators
- If methods span multiple tiers without transition decorators bridging them, logs WARNING

Does not raise — mixed tiers are a design smell, not necessarily a bug.

### 6. ValidatedRecord Protocol (unchanged shape)

```python
@runtime_checkable
class ValidatedRecord(Protocol):
    @property
    def _wardline_tier(self) -> int: ...

    @property
    def _wardline_groups(self) -> tuple[int, ...]: ...
```

Protocol shape is correct. `@property` in Protocol is notation only — plain attributes satisfy `runtime_checkable` `isinstance` check. Document this in Protocol docstring.

### 7. Enable/Disable

```python
import wardline.runtime.enforcement
wardline.runtime.enforcement.enable()
```

Or: `WARDLINE_ENFORCE=1` (checked at import time).

**Call-once latch:** After `enable()` is called and any check function has been invoked, `disable()` raises `RuntimeError("Enforcement state cannot be changed after first use")`. This prevents runtime bypass. `enable()` can be called multiple times (idempotent). `disable()` is only valid before any enforcement check runs.

**Thread safety:** Document: "Call `enable()` once at application startup before spawning threads. Stamping is not atomic with respect to concurrent calls returning the same object. For concurrent workloads, use `TierStamped` wrapping (immutable) rather than in-place stamping."

### 8. Testing Strategy

**Trust model bridge:**
- `test_taint_to_tier_covers_all_states` — completeness AND correctness (assert specific mappings)
- `test_taint_to_tier_frozen` — MappingProxyType, mutation raises TypeError

**Automatic stamping:**
- `test_decorator_stamps_return_instance` — class instance gets `_wardline_tier`, `_wardline_groups` (as tuple), `_wardline_stamped_by`
- `test_decorator_skips_dict_with_warning` — plain dict cannot be stamped, WARNING logged
- `test_decorator_skips_primitives_with_warning` — int/str return, WARNING logged, no stamp
- `test_decorator_skips_none_silently` — None return, no log, no stamp
- `test_decorator_skips_generator` — generator return, WARNING logged
- `test_decorator_skips_namedtuple` — namedtuple return, WARNING logged
- `test_decorator_skips_frozen_dataclass` — catches TypeError silently
- `test_decorator_skips_slots_object` — catches AttributeError silently
- `test_decorator_no_stamp_when_disabled` — enforcement off, no stamping
- `test_stamped_by_records_qualname` — captures function's `__qualname__`
- `test_supplementary_decorator_no_stamp` — `@integrity_critical` doesn't stamp
- `test_groups_normalized_to_sorted_tuple` — set input → tuple output

**Explicit API:**
- `test_stamp_tier_sets_attributes` — sets all three attrs
- `test_stamp_tier_validates_range` — tier 0 or 5 raises ValueError
- `test_stamp_tier_raises_on_frozen` — frozen dataclass raises TypeError
- `test_stamp_tier_raises_on_restamp` — already-stamped object raises ValueError
- `test_stamp_tier_overwrite_flag` — `overwrite=True` allows re-stamp
- `test_tier_stamped_wrapper` — satisfies ValidatedRecord
- `test_tier_stamped_frozen` — mutation raises FrozenInstanceError
- `test_tier_stamped_nested_blocked` — double-wrap detected or documented
- `test_unstamp_returns_value` — unwraps TierStamped, passes through non-wrapped

**Checking:**
- `test_check_tier_boundary_passes` — tier 1, expected_min_tier=2 → OK (more trusted passes)
- `test_check_tier_boundary_exact_boundary` — tier 2, expected_min_tier=2 → OK
- `test_check_tier_boundary_fails_one_below` — tier 3, expected_min_tier=2 → raises
- `test_check_tier_boundary_no_tier` — no attribute → raises
- `test_check_tier_boundary_non_int_tier` — string tier → raises
- `test_check_tier_boundary_logs_before_raise` — caplog captures WARNING
- `test_check_tier_boundary_calls_on_violation` — callback invoked if set
- `test_check_validated_record_passes` — conforming object → OK
- `test_check_validated_record_accepts_set_groups` — set is accepted
- `test_check_validated_record_rejects_missing_tier` — no _wardline_tier → raises
- `test_check_validated_record_rejects_bad_tier_type` — non-int → raises
- `test_check_validated_record_logs_before_raise` — caplog captures WARNING
- `test_check_noop_when_disabled` — all checks no-ops when off (parameterized)
- `test_tier_violation_error_attributes` — obj, expected_tier, actual_tier present
- `test_tier_violation_error_is_not_type_error` — NOT catchable by `except TypeError`

**WardlineBase:**
- `test_init_cooperative_mro` — `class C(WardlineBase, SomeMixin)` with kwargs works
- `test_init_with_abc` — `class C(WardlineBase, SomeABC)` with abstract works
- `test_init_no_args_still_works` — bare `WardlineBase` subclass, no-arg init
- `test_enforce_construction_uses_real_attrs` — reads `_wardline_tier_source`
- `test_enforce_construction_warns_mixed_tiers` — caplog captures WARNING

**Enable/disable:**
- `test_enable_disable_latch` — disable() raises after first check
- `test_enable_idempotent` — multiple enable() calls OK
- `test_wardline_enforce_env_var` — subprocess test (not importlib.reload)
- `test_enable_disable_log_events` — caplog captures state transitions

### 9. Prerequisites and Files Changed

**Pre-implementation:** Audit and fix `DECORATOR_TAINT_MAP` inconsistencies with `_wardline_transition` for `validates_semantic` and `validates_external`.

| File | Change |
|---|---|
| `core/tiers.py` | Add `TAINT_TO_TIER` mapping |
| `scanner/taint/function_level.py` | Fix `DECORATOR_TAINT_MAP` for `validates_semantic` + `validates_external` |
| `decorators/_base.py` | Add post-call stamping hook (enforcement-gated) |
| `runtime/enforcement.py` | Full rewrite: stamping, checking, construction enforcement, call-once latch, on_violation callback |
| `runtime/base.py` | Fix `__init__` (cooperative MRO + enforcement) |
| `runtime/protocols.py` | Add docstring clarifying @property notation vs plain attributes |
| `runtime/__init__.py` | Export `stamp_tier`, `TierStamped`, `unstamp`, `enable`, `disable`, `is_enabled`, `on_violation` |
| `tests/unit/runtime/test_enforcement.py` | Full rewrite with ~45 tests |
| `tests/unit/core/test_tiers.py` | Add TAINT_TO_TIER tests |
