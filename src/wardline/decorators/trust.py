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
from typing import Any, cast, overload

from wardline.core.taints import TaintState
from wardline.decorators._base import apply_marker, coerce_level

_GROUP = 1
_BOUNDARY_LEVELS = frozenset({TaintState.GUARDED, TaintState.ASSURED})
_TRUSTED_LEVELS = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})

# The parameterised forms below return ``Callable[[Any], Any]`` rather than a
# ``Callable[[F], F]``: PEP 695 makes a precision-preserving factory return
# awkward here, and the annotation only *widens* the decorated function's type,
# never misreports it. The bare ``@trusted`` overload keeps full ``F`` precision.


def external_boundary[F: Callable[..., Any]](fn: F) -> F:
    """Declare an external entry point; its return carries untrusted data."""
    return cast(F, apply_marker(fn, name="external_boundary", group=_GROUP, attrs={}))


def trust_boundary(*, to_level: TaintState | str) -> Callable[[Any], Any]:
    """Declare a validation/sanitisation boundary that raises trust to ``to_level``."""
    level = coerce_level(to_level, allowed=_BOUNDARY_LEVELS, arg="to_level")

    def decorate(fn: Any) -> Any:
        return apply_marker(
            fn,
            name="trust_boundary",
            group=_GROUP,
            attrs={"_wardline_to_level": level},
        )

    return decorate


@overload
def trusted[F: Callable[..., Any]](fn: F, /) -> F: ...
@overload
def trusted(*, level: TaintState | str = ...) -> Callable[[Any], Any]: ...


def trusted[F: Callable[..., Any]](
    fn: F | None = None, /, *, level: TaintState | str = TaintState.INTEGRAL
) -> F | Callable[[Any], Any]:
    """Declare a trusted producer/sink operating on and returning trusted data."""
    coerced = coerce_level(level, allowed=_TRUSTED_LEVELS, arg="level")

    def decorate(target: F) -> F:
        return cast(
            F,
            apply_marker(
                target,
                name="trusted",
                group=_GROUP,
                attrs={"_wardline_level": coerced},
            ),
        )

    if fn is None:
        return decorate
    return decorate(fn)
