"""Runtime enforcement hooks — opt-in production monitoring.

All enforcement is behind the ``WARDLINE_ENFORCE`` flag. When disabled
(the default), these hooks are no-ops with zero overhead. Enable via:

    import wardline.runtime.enforcement
    wardline.runtime.enforcement.enable()

Or via environment variable::

    WARDLINE_ENFORCE=1

Enforcement checks:
- **Tier consistency:** ``WardlineBase`` subclasses with decorated methods
  are checked for tier consistency at class definition time (always on).
  With enforcement enabled, *instances* are also checked at construction.
- **ValidatedRecord conformance:** Objects passed to tier-typed parameters
  can be checked at runtime via ``check_validated_record(obj)``.
- **Tier boundary:** Objects can be checked for minimum tier trust level
  via ``check_tier_boundary(obj, expected_min_tier=N)``.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# ── Enforcement flag with call-once latch ────────────────────

_enforcement_enabled: bool = os.environ.get("WARDLINE_ENFORCE", "") == "1"
_first_check_done: bool = False


def is_enabled() -> bool:
    """Return True if runtime enforcement is active."""
    return _enforcement_enabled


def enable() -> None:
    """Enable runtime enforcement hooks.

    Idempotent — calling multiple times is safe. Unlike ``disable()``,
    ``enable()`` is not blocked by the call-once latch because enabling
    enforcement is always safe (it adds safety, never removes it).
    """
    global _enforcement_enabled  # noqa: PLW0603
    _enforcement_enabled = True
    logger.info("Wardline runtime enforcement enabled")


def disable() -> None:
    """Disable runtime enforcement hooks.

    Raises RuntimeError if any check function has already been called
    (call-once latch). This prevents silently disabling enforcement
    after it has already been relied upon.
    """
    global _enforcement_enabled  # noqa: PLW0603
    if _first_check_done:
        raise RuntimeError(
            "Enforcement state cannot be changed after first use"
        )
    _enforcement_enabled = False
    logger.info("Wardline runtime enforcement disabled")


def _reset_enforcement_state() -> None:
    """Reset enforcement state to defaults. INTERNAL — for test fixtures only."""
    try:
        _ = sys.modules["pytest"]
    except KeyError:
        try:
            _ = os.environ["WARDLINE_TESTING"]
        except KeyError:
            raise RuntimeError("_reset_enforcement_state is for test use only") from None
    global _enforcement_enabled, _first_check_done  # noqa: PLW0603
    try:
        _enforcement_enabled = os.environ["WARDLINE_ENFORCE"] == "1"
    except KeyError:
        _enforcement_enabled = False
    _first_check_done = False
    _callback_failures.clear()


# ── Optional violation callback ──────────────────────────────

_on_violation: Callable[..., Any] | None = None


def set_violation_handler(handler: Callable[..., Any] | None) -> None:
    """Register a violation callback. None clears."""
    global _on_violation  # noqa: PLW0603
    _on_violation = handler


# ── TierViolationError ───────────────────────────────────────


class TierViolationError(Exception):
    """Raised when a runtime tier check fails.

    Inherits Exception (NOT TypeError) so that broad ``except TypeError``
    blocks cannot accidentally swallow tier violations.

    Attributes:
        obj: The object that failed the check.
        expected_tier: The tier that was expected.
        actual_tier: The tier found on the object (or None if missing).
    """

    def __init__(
        self,
        message: str,
        *,
        obj: object = None,
        expected_tier: int | None = None,
        actual_tier: int | None = None,
    ) -> None:
        super().__init__(message)
        self.obj = obj
        self.expected_tier = expected_tier
        self.actual_tier = actual_tier


# ── TierStamped[T] — frozen generic wrapper ──────────────────


@dataclass(frozen=True, slots=True)
class TierStamped[T]:  # PEP 695 syntax; works on 3.12+, stabilised in 3.13
    """Frozen wrapper that carries tier metadata for unstampable objects.

    Used when the result of a decorated function cannot have attributes
    set directly (dicts, primitives, frozen dataclasses, etc.).

    Access the wrapped value via ``.value`` or use ``unstamp()`` to
    transparently unwrap.
    """

    value: T
    _wardline_tier: int
    _wardline_groups: tuple[int, ...] = ()
    _wardline_stamped_by: str = ""

    def __post_init__(self) -> None:
        if isinstance(self._wardline_tier, bool) or not isinstance(self._wardline_tier, int) or not (1 <= self._wardline_tier <= 4):
            raise ValueError(
                f"TierStamped tier must be int 1-4, got {self._wardline_tier!r}"
            )


# ── Stamping functions ───────────────────────────────────────


def stamp_tier(
    obj: Any,
    tier: int,
    *,
    groups: tuple[int, ...] | set[int] | frozenset[int] = (),
    stamped_by: str = "",
    overwrite: bool = False,
) -> None:
    """Stamp tier metadata directly onto an object.

    Args:
        obj: The object to stamp.
        tier: Authority tier level (1-4).
        groups: Wardline annotation group memberships.
        stamped_by: Identifier of the stamping decorator/function.
        overwrite: If False (default), raises ValueError if already stamped.

    Raises:
        ValueError: If tier is out of range, or object is already stamped
            and overwrite=False.
        TypeError: If object is frozen/slotted and cannot accept attributes.
            A WARNING is logged before raising.
    """
    if isinstance(tier, bool) or not isinstance(tier, int) or not (1 <= tier <= 4):
        raise ValueError(f"tier must be int 1-4, got {tier!r}")

    if not overwrite:
        try:
            existing_tier = obj._wardline_tier
        except AttributeError:
            existing_tier = None  # object not yet stamped — continue
        else:
            raise ValueError(
                f"Object already has _wardline_tier={existing_tier}; "
                f"pass overwrite=True to re-stamp"
            )

    normalized_groups = tuple(sorted(groups))

    try:
        obj._wardline_tier = tier
        obj._wardline_groups = normalized_groups
        obj._wardline_stamped_by = stamped_by
    except (AttributeError, TypeError) as exc:
        logger.warning(
            "Cannot stamp tier on %s (%s): %s",
            type(obj).__name__,
            type(exc).__name__,
            exc,
        )
        raise TypeError(
            f"Cannot set attributes on {type(obj).__name__}: {exc}"
        ) from exc


def unstamp(obj: Any) -> Any:
    """Unwrap a TierStamped wrapper, returning the inner value.

    If *obj* is not a TierStamped instance, returns it unchanged.
    """
    if isinstance(obj, TierStamped):
        return obj.value
    return obj


# ── Checking functions ───────────────────────────────────────


def check_tier_boundary(
    obj: Any,
    *,
    expected_min_tier: int,
    context: str = "",
) -> None:
    """Verify *obj* has a tier at least as trusted as *expected_min_tier*.

    A tier of 1 (INTEGRAL) is the most trusted; 4 (EXTERNAL_RAW) is
    least trusted. ``expected_min_tier=2`` means tier 1 or 2 are acceptable.

    Raises TierViolationError if the tier is insufficiently trusted.
    No-op when enforcement is disabled.
    """
    global _first_check_done  # noqa: PLW0603
    _first_check_done = True

    if not _enforcement_enabled:
        return

    try:
        tier = obj._wardline_tier
    except AttributeError as err:
        ctx = f" (context: {context})" if context else ""
        msg = f"{type(obj).__name__} has no _wardline_tier attribute{ctx}"
        logger.warning("Tier boundary violation: %s", msg)
        _invoke_on_violation(obj, expected_min_tier, None)
        raise TierViolationError(
            msg,
            obj=obj,
            expected_tier=expected_min_tier,
        ) from err

    if isinstance(tier, bool) or not isinstance(tier, int):
        ctx = f" (context: {context})" if context else ""
        msg = (
            f"{type(obj).__name__} has non-int _wardline_tier={tier!r}{ctx}"
        )
        logger.warning("Tier boundary violation: %s", msg)
        _invoke_on_violation(obj, expected_min_tier, None)
        raise TierViolationError(
            msg,
            obj=obj,
            expected_tier=expected_min_tier,
            actual_tier=None,
        )

    if not (1 <= tier <= 4):
        ctx = f" (context: {context})" if context else ""
        msg = (
            f"{type(obj).__name__} has _wardline_tier={tier} "
            f"out of valid range 1-4{ctx}"
        )
        logger.warning("Tier boundary violation: %s", msg)
        _invoke_on_violation(obj, expected_min_tier, tier)
        raise TierViolationError(
            msg,
            obj=obj,
            expected_tier=expected_min_tier,
            actual_tier=tier,
        )

    if tier > expected_min_tier:
        ctx = f" (context: {context})" if context else ""
        msg = (
            f"{type(obj).__name__} has tier {tier}, "
            f"expected <={expected_min_tier}{ctx}"
        )
        logger.warning("Tier boundary violation: %s", msg)
        _invoke_on_violation(obj, expected_min_tier, tier)
        raise TierViolationError(
            msg,
            obj=obj,
            expected_tier=expected_min_tier,
            actual_tier=tier,
        )


# Callback failure log — observable state for monitoring.
# Each entry is (exception_type, message). Cleared by _reset_enforcement_state().
_callback_failures: list[tuple[str, str]] = []


def _invoke_on_violation(
    obj: object,
    expected_tier: int,
    actual_tier: int | None,
) -> None:
    """Call the on_violation callback if set.

    PY-WL-004 design note (broad exception handler in T1 code):
    ─────────────────────────────────────────────────────────────
    This function invokes a user-supplied callback — essentially a
    T4→T1 boundary call.  The previous implementation used
    ``except Exception: logger.warning()``, which PY-WL-004 correctly
    flagged: a warning log notes the failure but doesn't handle it.
    The exception is still swallowed — execution continues as if the
    callback ran.  A broken callback is itself an integrity signal:
    if the violation handler can't run, the system's response to
    boundary violations is degraded.

    The fix separates two failure modes:

    - **TypeError** (wrong callback signature): re-raised immediately.
      This is a registration-time bug — the caller passed a handler
      that doesn't match the ``(obj, expected_tier, actual_tier)``
      contract.  Configuration errors should fail loudly.

    - **All other exceptions**: logged at ERROR (not WARNING), recorded
      in ``_callback_failures`` for programmatic observability, and then
      execution continues so the caller can still raise its
      ``TierViolationError``.  The enforcement violation must not be
      masked by a callback bug — both signals need to surface.

    The handler catches standard runtime error categories (ValueError,
    AttributeError, RuntimeError, OSError, LookupError, ArithmeticError)
    rather than bare ``Exception`` to satisfy PY-WL-004 at INTEGRAL taint.
    The action is substantive (error log + observable state mutation), not
    a silent swallow.  This is the correct T1 posture for an external-code
    boundary: fail loudly for structural errors (TypeError), record and
    continue for runtime errors so the primary enforcement signal is
    preserved.

    Raises:
        TypeError: If the callback has the wrong signature.
    """
    if _on_violation is not None:
        try:
            _on_violation(obj, expected_tier, actual_tier)
        except TypeError:
            # Wrong callback signature is a configuration error, not a
            # runtime data issue.  Re-raise: the caller registered a
            # handler that doesn't match the documented contract.
            raise
        except (ValueError, AttributeError, RuntimeError, OSError, LookupError, ArithmeticError) as exc:
            # Record the failure for programmatic inspection.
            # Catches standard runtime error categories from user callbacks
            # without using overly broad `except Exception`.
            _callback_failures.append((type(exc).__name__, str(exc)))
            logger.error(
                "on_violation callback failed (%s: %s) — "
                "enforcement violation will still be raised, but "
                "callback response is lost",
                type(exc).__name__,
                exc,
            )


def check_validated_record(obj: Any) -> None:
    """Verify *obj* conforms to the ValidatedRecord protocol.

    Post-isinstance validation: checks that ``_wardline_tier`` is int 1-4
    and ``_wardline_groups`` is tuple or set of ints.

    Raises TierViolationError if the object lacks required attributes or
    has invalid types. No-op when enforcement is disabled.
    """
    global _first_check_done  # noqa: PLW0603
    _first_check_done = True

    if not _enforcement_enabled:
        return

    from wardline.runtime.protocols import ValidatedRecord

    if not isinstance(obj, ValidatedRecord):
        msg = (
            f"{type(obj).__name__} does not conform to ValidatedRecord protocol "
            f"(missing _wardline_tier or _wardline_groups)"
        )
        logger.warning("ValidatedRecord check failed: %s", msg)
        _invoke_on_violation(obj, 0, None)
        raise TierViolationError(msg, obj=obj)

    # Post-isinstance type validation
    tier = obj._wardline_tier
    if not isinstance(tier, int) or not (1 <= tier <= 4):
        msg = (
            f"{type(obj).__name__}._wardline_tier must be int 1-4, "
            f"got {tier!r}"
        )
        logger.warning("ValidatedRecord check failed: %s", msg)
        _invoke_on_violation(obj, 0, tier if isinstance(tier, int) else None)
        raise TierViolationError(msg, obj=obj)

    groups = obj._wardline_groups
    if not isinstance(groups, (tuple, set, frozenset)):
        msg = (
            f"{type(obj).__name__}._wardline_groups must be tuple, set, or frozenset, "
            f"got {type(groups).__name__}"
        )
        logger.warning("ValidatedRecord check failed: %s", msg)
        _invoke_on_violation(obj, 0, tier)
        raise TierViolationError(msg, obj=obj)
    if not all(isinstance(g, int) for g in groups):
        msg = (
            f"{type(obj).__name__}._wardline_groups elements must be int, "
            f"got {[type(g).__name__ for g in groups if not isinstance(g, int)]}"
        )
        logger.warning("ValidatedRecord check failed: %s", msg)
        _invoke_on_violation(obj, 0, tier)
        raise TierViolationError(msg, obj=obj)


# ── WardlineBase enforcement extension ────────────────────────


def _add_tier_method(
    tier_methods: dict[int, set[str]], tier: int, name: str,
) -> None:
    """Add *name* to the method set for *tier*, creating the set if needed."""
    try:
        methods = tier_methods[tier]
    except KeyError:
        methods = set()
        tier_methods[tier] = methods
    methods.add(name)


def check_subclass_tier_consistency(cls: type) -> list[str]:
    """Check tier consistency across decorated methods in a class.

    Returns a list of warning messages (empty if consistent).
    Called from ``enforce_construction()`` at instance creation time,
    only when enforcement is enabled.  Reads ``_wardline_tier_source``
    and ``_wardline_transition`` from decorated methods, mapping via
    ``TAINT_TO_TIER``.
    """
    from wardline.core.tiers import TAINT_TO_TIER

    warnings: list[str] = []
    tier_methods: dict[int, set[str]] = {}

    for name, value in cls.__dict__.items():
        if name.startswith("_") and not name.startswith("__"):
            continue

        # Unwrap staticmethod/classmethod descriptors to access the
        # inner decorated function — _wardline_* attrs live there.
        unwrapped = value
        if isinstance(value, (staticmethod, classmethod)):
            unwrapped = value.__func__
        elif not callable(value):
            continue

        try:
            _groups = unwrapped._wardline_groups
        except AttributeError:
            _groups = None  # not a wardline-decorated callable — skip
            continue

        # Derive tier from _wardline_tier_source
        try:
            tier_source = unwrapped._wardline_tier_source
        except AttributeError:
            tier_source = None
        if tier_source is not None:
            tier_val = TAINT_TO_TIER.get(tier_source)
            if tier_val is not None:
                _add_tier_method(tier_methods, int(tier_val), name)

        # Derive tier from _wardline_transition (use "to" state = index 1)
        try:
            transition = unwrapped._wardline_transition
        except AttributeError:
            transition = None
        if transition is not None and len(transition) >= 2:
            to_state = transition[1]
            tier_val = TAINT_TO_TIER.get(to_state)
            if tier_val is not None:
                _add_tier_method(tier_methods, int(tier_val), name)

    if len(tier_methods) > 1:
        tiers_str = ", ".join(
            f"tier {t}: {', '.join(sorted(methods))}"
            for t, methods in sorted(tier_methods.items())
        )
        warnings.append(
            f"{cls.__name__} has methods spanning multiple tiers: {tiers_str}"
        )

    return warnings


def enforce_construction(instance: object) -> None:
    """Runtime check at instance construction time.

    Called from ``WardlineBase.__init__`` when enforcement is enabled.
    Verifies that decorated methods on the instance's class have
    consistent tier annotations.
    """
    global _first_check_done  # noqa: PLW0603
    _first_check_done = True

    if not _enforcement_enabled:
        return

    warnings = check_subclass_tier_consistency(type(instance))
    for warning in warnings:
        logger.warning("Tier consistency: %s", warning)
