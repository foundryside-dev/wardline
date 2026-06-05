"""Tiny runtime marker decorators for Loom/Wardline trust annotations."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Optional, TypeVar, overload

F = TypeVar("F", bound=Callable[..., Any])

INTEGRAL = "INTEGRAL"
ASSURED = "ASSURED"
GUARDED = "GUARDED"
EXTERNAL_RAW = "EXTERNAL_RAW"
UNKNOWN_RAW = "UNKNOWN_RAW"
MIXED_RAW = "MIXED_RAW"

_GROUP = 1
_BOUNDARY_LEVELS = frozenset({GUARDED, ASSURED})
_TRUSTED_LEVELS = frozenset({INTEGRAL, ASSURED})


def _coerce_level(value: object, *, allowed: frozenset[str], arg: str) -> str:
    level = getattr(value, "value", value)
    if not isinstance(level, str):
        raise ValueError(f"{arg}={value!r} is not a valid trust level")
    if level not in allowed:
        permitted = sorted(allowed)
        raise ValueError(f"{arg} must be one of {permitted}, got {level!r}")
    return level


def _apply_marker(fn: Any, *, attrs: dict[str, str]) -> Any:
    if not callable(fn) and not isinstance(fn, (staticmethod, classmethod)):
        raise TypeError(f"loom marker requires a callable, got {type(fn).__name__!r}")
    target: Any = fn.__func__ if isinstance(fn, (staticmethod, classmethod)) else fn
    existing: frozenset[int] = getattr(target, "_wardline_groups", frozenset())
    target._wardline_groups = existing | {_GROUP}
    for key, value in attrs.items():
        setattr(target, key, value)
    return fn


def external_boundary(fn: F) -> F:
    """Declare an external entry point; its return carries untrusted data."""
    return _apply_marker(fn, attrs={})


def trust_boundary(*, to_level: object) -> Callable[[Any], Any]:
    """Declare a validation boundary that raises trust to ``to_level``."""
    level = _coerce_level(to_level, allowed=_BOUNDARY_LEVELS, arg="to_level")

    def decorate(fn: Any) -> Any:
        return _apply_marker(fn, attrs={"_wardline_to_level": level})

    return decorate


@overload
def trusted(fn: F, /) -> F: ...


@overload
def trusted(*, level: object = ...) -> Callable[[Any], Any]: ...


def trusted(fn: Optional[F] = None, /, *, level: object = INTEGRAL) -> F | Callable[[Any], Any]:
    """Declare a trusted producer/sink operating on and returning trusted data."""
    coerced = _coerce_level(level, allowed=_TRUSTED_LEVELS, arg="level")

    def decorate(target: F) -> F:
        return _apply_marker(target, attrs={"_wardline_level": coerced})

    if fn is None:
        return decorate
    return decorate(fn)


__all__ = [
    "ASSURED",
    "EXTERNAL_RAW",
    "GUARDED",
    "INTEGRAL",
    "MIXED_RAW",
    "UNKNOWN_RAW",
    "external_boundary",
    "trust_boundary",
    "trusted",
]
