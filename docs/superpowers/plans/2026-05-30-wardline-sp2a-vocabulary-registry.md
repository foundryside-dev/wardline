# SP2a — Trust Vocabulary + Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the minimal generic trust vocabulary (`@external_boundary`, `@trust_boundary`, `@trusted`) as static-analysis marker decorators, plus the `wardline.core.registry` import surface Clarion's plugin depends on.

**Architecture:** Registry-backed marker decorators. Each decorator validates its arguments against `REGISTRY`, stamps `_wardline_*` attributes onto the target function, and returns it **unchanged** — no wrapper, no runtime tier-stamping, no enforcement (the deliberate lightweight departure from `wardline.old`'s runtime-enforcing factory; the analyzer reads decorators from the AST). Three decorators in one `group=1` ("trust") family.

**Tech Stack:** Python 3.12+, stdlib only (`dataclasses`, `types.MappingProxyType`, `enum`); `wardline.core.taints.TaintState` for level arguments.

**Gate (run after every task):** `.venv/bin/python -m pytest -q` (1 expected xfail in `tests/test_self_hosting.py`), `.venv/bin/ruff check src tests`, `.venv/bin/mypy src`.

---

### Task 1: Registry + import surface (`wardline.core.registry`)

**Files:**
- Create: `src/wardline/core/registry.py`
- Test: `tests/unit/core/test_registry.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_registry.py
from __future__ import annotations

import pytest

from wardline.core.registry import REGISTRY, REGISTRY_VERSION, RegistryEntry
from wardline.core.taints import TaintState


def test_public_import_surface_present() -> None:
    # The Loom contract: Clarion's plugin imports these three names.
    assert isinstance(REGISTRY_VERSION, str) and REGISTRY_VERSION
    assert isinstance(REGISTRY, type(REGISTRY))  # a mapping
    assert RegistryEntry.__name__ == "RegistryEntry"


def test_registry_holds_the_three_trust_decorators() -> None:
    assert set(REGISTRY) == {"external_boundary", "trust_boundary", "trusted"}
    for name, entry in REGISTRY.items():
        assert entry.canonical_name == name
        assert entry.group == 1


def test_registry_attrs_contract() -> None:
    assert dict(REGISTRY["external_boundary"].attrs) == {}
    assert REGISTRY["trust_boundary"].attrs["_wardline_to_level"] is TaintState
    assert REGISTRY["trusted"].attrs["_wardline_level"] is TaintState


def test_registry_entry_attrs_are_immutable() -> None:
    entry = REGISTRY["trusted"]
    with pytest.raises(TypeError):
        entry.attrs["_wardline_level"] = int  # type: ignore[index]


def test_registry_is_immutable() -> None:
    with pytest.raises(TypeError):
        REGISTRY["new"] = REGISTRY["trusted"]  # type: ignore[index]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/core/test_registry.py -q`
Expected: FAIL (`ModuleNotFoundError: wardline.core.registry`).

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/core/registry.py
"""Canonical decorator registry — the single source of truth for Wardline's
trust vocabulary, and the import surface Clarion's plugin depends on.

Public surface (do not break — integration brief §Round 1, asterisk 2):
``wardline.core.registry.{REGISTRY, REGISTRY_VERSION, RegistryEntry}``.
SP2d additionally exports this as a versioned NG-25 descriptor so consumers
can *read* instead of *import*.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from wardline.core.taints import TaintState

# Version line for the generic rebuild's vocabulary (distinct from wardline.old's
# "1.1"). Bumped when the vocabulary's declaration surface changes; the taint
# provider derives its cache-key fingerprint from this (SP2b).
REGISTRY_VERSION = "wardline-generic-1"


@dataclass(frozen=True)
class RegistryEntry:
    """A registered trust decorator and its expected ``_wardline_*`` attributes.

    ``attrs`` maps each stamped attribute name to its expected value *type*.
    It is wrapped in ``MappingProxyType`` at construction for deep immutability.
    """

    canonical_name: str
    group: int
    attrs: Mapping[str, type]

    def __post_init__(self) -> None:
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))


_ENTRIES: dict[str, RegistryEntry] = {
    "external_boundary": RegistryEntry(
        canonical_name="external_boundary", group=1, attrs={}
    ),
    "trust_boundary": RegistryEntry(
        canonical_name="trust_boundary",
        group=1,
        attrs={"_wardline_to_level": TaintState},
    ),
    "trusted": RegistryEntry(
        canonical_name="trusted",
        group=1,
        attrs={"_wardline_level": TaintState},
    ),
}

# Consistency invariant: every key equals its entry's canonical_name.
for _name, _entry in _ENTRIES.items():
    if _name != _entry.canonical_name:
        raise ValueError(
            f"REGISTRY key {_name!r} != canonical_name {_entry.canonical_name!r}"
        )
del _name, _entry

REGISTRY: MappingProxyType[str, RegistryEntry] = MappingProxyType(_ENTRIES)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/core/test_registry.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/registry.py tests/unit/core/test_registry.py
git commit -m "feat(sp2a): core.registry — trust vocabulary registry + import surface"
```

---

### Task 2: Marker factory (`wardline.decorators._base`)

**Files:**
- Create: `src/wardline/decorators/__init__.py` (package marker; final exports added in Task 3)
- Create: `src/wardline/decorators/_base.py`
- Test: `tests/unit/decorators/__init__.py` (empty) + `tests/unit/decorators/test_base.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/decorators/test_base.py
from __future__ import annotations

import pytest

from wardline.core.taints import TaintState
from wardline.decorators._base import apply_marker, coerce_level


def test_coerce_level_accepts_enum_and_name() -> None:
    allowed = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})
    assert coerce_level(TaintState.ASSURED, allowed=allowed, arg="level") is TaintState.ASSURED
    assert coerce_level("INTEGRAL", allowed=allowed, arg="level") is TaintState.INTEGRAL


def test_coerce_level_rejects_unknown_name() -> None:
    allowed = frozenset({TaintState.INTEGRAL})
    with pytest.raises(ValueError, match="not a valid TaintState"):
        coerce_level("NOPE", allowed=allowed, arg="level")


def test_coerce_level_rejects_disallowed_level() -> None:
    allowed = frozenset({TaintState.INTEGRAL})
    with pytest.raises(ValueError, match="must be one of"):
        coerce_level(TaintState.GUARDED, allowed=allowed, arg="level")


def test_apply_marker_stamps_group_and_attrs_and_returns_same_object() -> None:
    def f() -> int:
        return 1

    out = apply_marker(
        f, name="trusted", group=1, attrs={"_wardline_level": TaintState.INTEGRAL}
    )
    assert out is f  # unchanged identity — no wrapper
    assert f._wardline_groups == frozenset({1})  # type: ignore[attr-defined]
    assert f._wardline_level is TaintState.INTEGRAL  # type: ignore[attr-defined]
    assert f() == 1  # behavior preserved


def test_apply_marker_rejects_unknown_name() -> None:
    with pytest.raises(ValueError, match="not in wardline registry"):
        apply_marker(lambda: None, name="bogus", group=1, attrs={})


def test_apply_marker_rejects_group_mismatch() -> None:
    with pytest.raises(ValueError, match="Group mismatch"):
        apply_marker(lambda: None, name="trusted", group=2, attrs={})


def test_apply_marker_rejects_unknown_attr() -> None:
    with pytest.raises(ValueError, match="Unknown attribute"):
        apply_marker(lambda: None, name="trusted", group=1, attrs={"_wardline_bogus": 1})


def test_apply_marker_rejects_non_callable() -> None:
    with pytest.raises(TypeError, match="requires a callable"):
        apply_marker(5, name="trusted", group=1, attrs={"_wardline_level": TaintState.INTEGRAL})  # type: ignore[arg-type]


def test_apply_marker_accumulates_groups() -> None:
    def f() -> None: ...
    apply_marker(f, name="external_boundary", group=1, attrs={})
    apply_marker(f, name="trusted", group=1, attrs={"_wardline_level": TaintState.INTEGRAL})
    assert f._wardline_groups == frozenset({1})  # type: ignore[attr-defined]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/decorators/test_base.py -q`
Expected: FAIL (`ModuleNotFoundError: wardline.decorators._base`).

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/decorators/__init__.py
"""Wardline's generic trust-declaration decorators (static-analysis markers)."""

from __future__ import annotations
```

```python
# src/wardline/decorators/_base.py
"""Minimal marker factory for the generic trust vocabulary.

These decorators are STATIC-ANALYSIS markers: ``apply_marker`` validates the
(name, group, attrs) triple against ``REGISTRY``, stamps ``_wardline_*``
attributes onto the target function, and returns the function UNCHANGED. No
wrapper, no runtime tier-stamping, no enforcement — the analyzer reads the
decorators from the AST (the deliberate lightweight departure from
wardline.old's runtime-enforcing factory).
"""

from __future__ import annotations

from typing import Any

from wardline.core.registry import REGISTRY
from wardline.core.taints import TaintState


def coerce_level(
    value: TaintState | str, *, allowed: frozenset[TaintState], arg: str
) -> TaintState:
    """Normalise a level argument to a ``TaintState`` and check it is allowed.

    Accepts a ``TaintState`` or its exact name (e.g. ``"ASSURED"``). Raises
    ``ValueError`` on an unknown name or a level outside ``allowed``.
    """
    if isinstance(value, TaintState):
        level = value
    else:
        try:
            level = TaintState(value)
        except ValueError:
            raise ValueError(f"{arg}={value!r} is not a valid TaintState") from None
    if level not in allowed:
        permitted = sorted(t.value for t in allowed)
        raise ValueError(f"{arg} must be one of {permitted}, got {level.value}")
    return level


def apply_marker(
    fn: Any, *, name: str, group: int, attrs: dict[str, Any]
) -> Any:
    """Validate against ``REGISTRY`` and stamp marker attributes onto ``fn``.

    Returns ``fn`` unchanged (identity preserved). For ``staticmethod`` /
    ``classmethod`` the underlying function is stamped. Raises ``ValueError``
    for an unknown name / group mismatch / undeclared attribute, ``TypeError``
    for a non-callable target.
    """
    if name not in REGISTRY:
        raise ValueError(f"Unknown decorator {name!r} — not in wardline registry")
    entry = REGISTRY[name]
    if group != entry.group:
        raise ValueError(
            f"Group mismatch for {name!r}: passed {group}, "
            f"registry expects {entry.group}"
        )
    for attr_key in attrs:
        if attr_key not in entry.attrs:
            raise ValueError(
                f"Unknown attribute {attr_key!r} for {name!r}; "
                f"allowed: {sorted(entry.attrs)}"
            )

    if not callable(fn) and not isinstance(fn, (staticmethod, classmethod)):
        raise TypeError(
            f"wardline decorator {name!r} requires a callable, "
            f"got {type(fn).__name__!r}"
        )
    target = fn.__func__ if isinstance(fn, (staticmethod, classmethod)) else fn
    existing = getattr(target, "_wardline_groups", frozenset())
    target._wardline_groups = frozenset(existing) | {group}
    for key, value in attrs.items():
        setattr(target, key, value)
    return fn
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/decorators/test_base.py -q`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add src/wardline/decorators/__init__.py src/wardline/decorators/_base.py tests/unit/decorators/
git commit -m "feat(sp2a): decorators._base — registry-validated marker factory"
```

---

### Task 3: The three trust decorators (`wardline.decorators.trust`)

**Files:**
- Create: `src/wardline/decorators/trust.py`
- Modify: `src/wardline/decorators/__init__.py` (re-export the public names)
- Test: `tests/unit/decorators/test_trust.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/decorators/test_trust.py
from __future__ import annotations

import pytest

from wardline.core.taints import TaintState
from wardline.decorators import external_boundary, trust_boundary, trusted


def test_external_boundary_marks_group_only() -> None:
    @external_boundary
    def read(p: str) -> str:
        return p

    assert read._wardline_groups == frozenset({1})  # type: ignore[attr-defined]
    assert not hasattr(read, "_wardline_level")
    assert read("x") == "x"  # behaviour preserved


def test_trusted_bare_defaults_to_integral() -> None:
    @trusted
    def f() -> int:
        return 1

    assert f._wardline_level is TaintState.INTEGRAL  # type: ignore[attr-defined]
    assert f() == 1


def test_trusted_with_assured_name_and_enum() -> None:
    @trusted(level="ASSURED")
    def f() -> None: ...

    @trusted(level=TaintState.ASSURED)
    def g() -> None: ...

    assert f._wardline_level is TaintState.ASSURED  # type: ignore[attr-defined]
    assert g._wardline_level is TaintState.ASSURED  # type: ignore[attr-defined]


def test_trusted_rejects_disallowed_level() -> None:
    with pytest.raises(ValueError, match="must be one of"):
        @trusted(level="GUARDED")  # not a trusted-producer level
        def f() -> None: ...


def test_trust_boundary_records_to_level() -> None:
    @trust_boundary(to_level="ASSURED")
    def validate(x: str) -> str:
        return x

    assert validate._wardline_to_level is TaintState.ASSURED  # type: ignore[attr-defined]
    assert validate._wardline_groups == frozenset({1})  # type: ignore[attr-defined]
    assert validate("ok") == "ok"


def test_trust_boundary_accepts_guarded() -> None:
    @trust_boundary(to_level=TaintState.GUARDED)
    def shape(x: object) -> object:
        return x

    assert shape._wardline_to_level is TaintState.GUARDED  # type: ignore[attr-defined]


def test_trust_boundary_rejects_integral() -> None:
    with pytest.raises(ValueError, match="must be one of"):
        @trust_boundary(to_level="INTEGRAL")  # boundaries raise to GUARDED/ASSURED only
        def f(x: object) -> object:
            return x


def test_decorators_preserve_qualname() -> None:
    @trusted
    def named() -> None: ...
    assert named.__name__ == "named"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/decorators/test_trust.py -q`
Expected: FAIL (`ImportError: cannot import name 'external_boundary'`).

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/decorators/trust.py
"""The generic trust vocabulary — three static-analysis marker decorators.

- ``@external_boundary`` — untrusted source (return carries EXTERNAL_RAW).
- ``@trust_boundary(to_level=...)`` — validation boundary raising trust to
  ``to_level`` (GUARDED or ASSURED).
- ``@trusted(level=...)`` — trusted producer/sink (INTEGRAL by default; or
  ASSURED).

All three stamp ``_wardline_*`` markers and return the function unchanged; the
analyzer's ``DecoratorTaintSourceProvider`` (SP2b) reads them from the AST.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar, cast, overload

from wardline.core.taints import TaintState
from wardline.decorators._base import apply_marker, coerce_level

_F = TypeVar("_F", bound=Callable[..., Any])

_GROUP = 1
_BOUNDARY_LEVELS = frozenset({TaintState.GUARDED, TaintState.ASSURED})
_TRUSTED_LEVELS = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})


def external_boundary(fn: _F) -> _F:
    """Declare an external entry point; its return carries untrusted data."""
    return cast(_F, apply_marker(fn, name="external_boundary", group=_GROUP, attrs={}))


def trust_boundary(*, to_level: TaintState | str) -> Callable[[_F], _F]:
    """Declare a validation/sanitisation boundary that raises trust to ``to_level``."""
    level = coerce_level(to_level, allowed=_BOUNDARY_LEVELS, arg="to_level")

    def decorate(fn: _F) -> _F:
        return cast(
            _F,
            apply_marker(
                fn, name="trust_boundary", group=_GROUP,
                attrs={"_wardline_to_level": level},
            ),
        )

    return decorate


@overload
def trusted(fn: _F, /) -> _F: ...
@overload
def trusted(*, level: TaintState | str = ...) -> Callable[[_F], _F]: ...


def trusted(
    fn: _F | None = None, /, *, level: TaintState | str = TaintState.INTEGRAL
) -> _F | Callable[[_F], _F]:
    """Declare a trusted producer/sink operating on and returning trusted data."""
    coerced = coerce_level(level, allowed=_TRUSTED_LEVELS, arg="level")

    def decorate(target: _F) -> _F:
        return cast(
            _F,
            apply_marker(
                target, name="trusted", group=_GROUP,
                attrs={"_wardline_level": coerced},
            ),
        )

    if fn is None:
        return decorate
    return decorate(fn)
```

```python
# src/wardline/decorators/__init__.py
"""Wardline's generic trust-declaration decorators (static-analysis markers)."""

from __future__ import annotations

from wardline.decorators.trust import external_boundary, trust_boundary, trusted

__all__ = ["external_boundary", "trust_boundary", "trusted"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/decorators/test_trust.py -q`
Expected: PASS (8 tests).

- [ ] **Step 5: Full gate + commit**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: all green (1 xfail in `test_self_hosting.py`).

```bash
git add src/wardline/decorators/trust.py src/wardline/decorators/__init__.py tests/unit/decorators/test_trust.py
git commit -m "feat(sp2a): trust vocabulary — @external_boundary, @trust_boundary, @trusted"
```

---

## Self-Review

- **Spec coverage:** §2 (vocabulary, 3 decorators with the exact `(body,return)` roles) → Tasks 2-3; §6 (`core/registry.py` with `RegistryEntry`/`REGISTRY`/`REGISTRY_VERSION`, import surface preserved) → Task 1; §9 SP2a acceptance (importable, bad-level `ValueError`, registry surface present, entries consistent) → all tasks. SP2b+ (provider, rules, descriptor) are out of SP2a scope by design.
- **No placeholders:** every step has complete code.
- **Type consistency:** `apply_marker`/`coerce_level` signatures identical across `_base.py`, its test, and `trust.py`. `RegistryEntry.attrs` declared `Mapping[str, type]` (accepts dict literals; wrapped to `MappingProxyType` in `__post_init__`). `_wardline_to_level`/`_wardline_level` attr names match between registry contract, factory, decorators, and tests.
