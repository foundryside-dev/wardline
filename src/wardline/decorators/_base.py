"""Decorator factory — creates wardline decorators from registry entries."""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Protocol, overload

from wardline.core.registry import REGISTRY

logger = logging.getLogger(__name__)


def _safe_name(obj: object) -> str:
    """Return __name__ if available, otherwise repr."""
    try:
        return obj.__name__  # type: ignore[attr-defined, no-any-return]
    except AttributeError:
        return repr(obj)


class _WardlineDecorated(Protocol):
    """Protocol for callables already marked with wardline metadata."""

    _wardline_groups: object


def _compute_output_tier(semantic_attrs: dict[str, Any]) -> int | None:
    """Derive output tier from semantic attrs at construction time.

    Uses _wardline_transition[1] (the "to" state) or _wardline_tier_source,
    mapped through TAINT_TO_TIER. Returns None for supplementary decorators
    that have neither attribute.
    """
    from wardline.core.tiers import TAINT_TO_TIER

    transition = semantic_attrs.get("_wardline_transition")
    if transition is not None and len(transition) >= 2:
        to_state = transition[1]
        tier = TAINT_TO_TIER.get(to_state)
        if tier is not None:
            return int(tier)

    tier_source = semantic_attrs.get("_wardline_tier_source")
    if tier_source is not None:
        tier = TAINT_TO_TIER.get(tier_source)
        if tier is not None:
            return int(tier)

    return None


def _try_stamp_tier(
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

    try:
        stamp_tier(
            result,
            output_tier,
            groups=groups,
            stamped_by=stamped_by,
            overwrite=False,
        )
        return result
    except ValueError:
        # Pre-stamped by inner decorator — innermost tier wins
        return result
    except TypeError:
        # stamp_tier already logged WARNING before raising TypeError
        return TierStamped(
            value=result,
            _wardline_tier=output_tier,
            _wardline_groups=groups,
            _wardline_stamped_by=stamped_by,
        )


def _is_underlying_coroutine(fn: Any) -> bool:
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


def wardline_decorator(
    group: int,
    name: str,
    **semantic_attrs: Any,
) -> Any:
    """Create a wardline decorator that marks functions with metadata.

    Args:
        group: Decorator group number (1=authority, 2=audit).
        name: Canonical decorator name (must be in REGISTRY).
        **semantic_attrs: Semantic attributes to set on the wrapper.
            Keys must match the registry entry's attrs contract.
    """
    # Registry enforcement
    if name not in REGISTRY:
        raise ValueError(
            f"Unknown decorator '{name}' — not in wardline registry"
        )

    entry = REGISTRY[name]

    # Validate group matches registry entry
    if group != entry.group:
        raise ValueError(
            f"Group mismatch for decorator '{name}': "
            f"passed group={group}, registry expects group={entry.group}"
        )
    for key in semantic_attrs:
        attr_key = f"_wardline_{key}" if not key.startswith("_wardline_") else key
        # Check against entry.attrs contract
        try:
            entry.attrs[attr_key]
        except KeyError:
            raise ValueError(
                f"Unknown attribute '{key}' for decorator '{name}'. "
                f"Allowed: {sorted(entry.attrs.keys())}"
            ) from None

    # Compute output tier at construction time from semantic_attrs
    output_tier = _compute_output_tier(semantic_attrs)

    def decorator(fn: Any) -> Any:
        # Handle staticmethod/classmethod — unwrap before applying.
        # Known limitation: callable() on descriptors that carry _wardline_*
        # attributes (e.g. AuthoritativeField instances) may return True even
        # though the descriptor is not intended to be decorated.  The
        # isinstance checks below cover the known descriptor types
        # (staticmethod, classmethod).  Arbitrary third-party descriptors
        # that happen to be callable are not guarded against — this is
        # accepted as a very unlikely edge case.
        unwrapped = fn
        wrapper_type: type | None = None
        if isinstance(fn, staticmethod):
            unwrapped = fn.__func__
            wrapper_type = staticmethod
        elif isinstance(fn, classmethod):
            unwrapped = fn.__func__
            wrapper_type = classmethod

        if _is_underlying_coroutine(unwrapped):
            @functools.wraps(unwrapped)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                result = await unwrapped(*args, **kwargs)
                if output_tier is not None:
                    from wardline.runtime.enforcement import is_enabled
                    if is_enabled() and result is not None:
                        try:
                            current_groups = tuple(sorted(wrapper._wardline_groups))  # type: ignore[attr-defined]
                        except AttributeError:
                            current_groups = ()
                        result = _try_stamp_tier(result, output_tier, current_groups, wrapper.__qualname__)
                return result
        else:
            @functools.wraps(unwrapped)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                result = unwrapped(*args, **kwargs)
                if output_tier is not None:
                    from wardline.runtime.enforcement import is_enabled
                    if is_enabled() and result is not None:
                        try:
                            current_groups = tuple(sorted(wrapper._wardline_groups))  # type: ignore[attr-defined]
                        except AttributeError:
                            current_groups = ()
                        result = _try_stamp_tier(result, output_tier, current_groups, wrapper.__qualname__)
                return result

        # CRITICAL: set _wardline_groups AFTER functools.wraps()
        # Copy-on-accumulate: don't mutate inner decorator's set
        try:
            existing_groups = wrapper._wardline_groups  # type: ignore[attr-defined]
        except AttributeError:
            existing_groups = frozenset()
        wrapper._wardline_groups = frozenset(existing_groups) | {group}  # type: ignore[attr-defined]

        # Set semantic attributes
        for key, value in semantic_attrs.items():
            attr_name = (
                f"_wardline_{key}" if not key.startswith("_wardline_") else key
            )
            setattr(wrapper, attr_name, value)

        # Re-wrap if staticmethod/classmethod
        if wrapper_type is not None:
            return wrapper_type(wrapper)

        return wrapper

    return decorator


@overload
def get_wardline_attrs(fn: _WardlineDecorated) -> dict[str, Any]: ...


@overload
def get_wardline_attrs(fn: Any) -> dict[str, Any] | None: ...


def get_wardline_attrs(fn: Any) -> dict[str, Any] | None:
    """Walk __wrapped__ chain to collect all wardline attributes.

    Returns dict of _wardline_* attributes, or None if chain is severed.
    """
    attrs: dict[str, Any] = {}
    current = fn
    seen: set[int] = set()

    while current is not None:
        current_id = id(current)
        # Cycle detection: frozenset.add() is not available, but we can
        # detect duplicates by checking set size before/after.
        prev_size = len(seen)
        seen.add(current_id)
        if len(seen) == prev_size:
            break

        # Collect wardline attrs from current level only (not inherited via MRO).
        # Use vars() when available; fall back to dir() for objects without __dict__.
        try:
            current_keys = vars(current)
        except TypeError:
            current_keys = dir(current)
        for key in current_keys:
            if not key.startswith("_wardline_"):
                continue
            try:
                attrs[key]
            except KeyError:
                attrs[key] = getattr(current, key)

        # Follow __wrapped__ chain
        try:
            next_fn = current.__wrapped__
        except AttributeError:
            next_fn = None
        if next_fn is None:
            # Only warn about severed chains when the wrapping function
            # is actually a wardline decorator (has _wardline_ attrs).
            # Third-party decorators also set __wrapped__ and should not
            # trigger this warning.
            if (
                current is not fn
                and not attrs
                and any(k.startswith("_wardline_") for k in vars(fn))
            ):
                logger.warning(
                    "Severed __wrapped__ chain on %s — "
                    "wardline attributes may be lost",
                    _safe_name(fn),
                )
                return None
            break
        current = next_fn

    return attrs if attrs else None
