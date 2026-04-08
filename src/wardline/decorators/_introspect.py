"""Introspection helpers for arbitrary user objects.

These functions handle objects of unknown type returned by decorated
functions.  They live at GUARDED tier (not INTEGRAL) because the
objects they inspect are externally provided — the framework does not
control their type or structure.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _safe_name(obj: object) -> str:
    """Return __name__ if available, otherwise repr."""
    try:
        return obj.__name__  # type: ignore[attr-defined, no-any-return]
    except AttributeError:
        return repr(obj)


def is_pre_stamped(result: Any) -> bool:
    """Check whether *result* already carries a ``_wardline_tier`` attribute.

    Uses ``hasattr`` because the result is an arbitrary user object
    whose type is not controlled by the framework.
    """
    return hasattr(result, "_wardline_tier")


def try_stamp_tier(
    result: Any,
    output_tier: int,
    groups: tuple[int, ...],
    stamped_by: str,
) -> Any:
    """Attempt to stamp tier metadata on a result, auto-wrapping if needed.

    Returns the (possibly wrapped) result.

    - Tries setattr on the result directly.
    - On TypeError (frozen/slotted objects): logs WARNING,
      returns TierStamped wrapper instead.
    - On ValueError (pre-stamped result, overwrite=False): silently returns
      the pre-stamped result (innermost tier wins for stacked decorators).
    """
    from wardline.runtime.enforcement import TierStamped, stamp_tier

    # Pre-stamped by inner decorator — innermost tier wins.
    if hasattr(result, "_wardline_tier"):
        return result

    try:
        stamp_tier(
            result,
            output_tier,
            groups=groups,
            stamped_by=stamped_by,
            overwrite=False,
        )
        return result
    except TypeError:
        # stamp_tier already logged WARNING before raising TypeError
        return TierStamped(
            value=result,
            _wardline_tier=output_tier,
            _wardline_groups=groups,
            _wardline_stamped_by=stamped_by,
        )


def is_underlying_coroutine(fn: Any) -> bool:
    """Check if *fn* or any function in its ``__wrapped__`` chain is async.

    ``functools.wraps`` copies ``__wrapped__`` but not the ``CO_COROUTINE``
    code flag.  A sync third-party wrapper between two wardline decorators
    will hide the async nature from ``inspect.iscoroutinefunction``.  This
    function walks the ``__wrapped__`` chain to find the real answer.
    """
    current: Any = fn
    seen: set[int] = set()
    while current is not None:
        if id(current) in seen:
            break
        seen.add(id(current))
        if inspect.iscoroutinefunction(current):
            return True
        current = getattr(current, "__wrapped__", None)
    return False
