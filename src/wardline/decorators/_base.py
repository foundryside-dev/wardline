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


def coerce_level(value: TaintState | str, *, allowed: frozenset[TaintState], arg: str) -> TaintState:
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


def apply_marker(fn: Any, *, name: str, group: int, attrs: dict[str, Any]) -> Any:
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
        raise ValueError(f"Group mismatch for {name!r}: passed {group}, registry expects {entry.group}")
    for attr_key in attrs:
        if attr_key not in entry.attrs:
            raise ValueError(f"Unknown attribute {attr_key!r} for {name!r}; allowed: {sorted(entry.attrs)}")

    if not callable(fn) and not isinstance(fn, (staticmethod, classmethod)):
        raise TypeError(f"wardline decorator {name!r} requires a callable, got {type(fn).__name__!r}")
    target: Any = fn.__func__ if isinstance(fn, (staticmethod, classmethod)) else fn
    existing: frozenset[int] = getattr(target, "_wardline_groups", frozenset())
    target._wardline_groups = existing | {group}
    for key, value in attrs.items():
        setattr(target, key, value)
    return fn
