"""Group 9-10 decorators — operation and failure-mode semantics."""

from __future__ import annotations

from typing import Any

from wardline.decorators._base import wardline_decorator

__all__ = [
    "idempotent",
    "atomic",
    "compensatable",
    "fail_closed",
    "fail_open",
    "emits_or_explains",
    "exception_boundary",
    "must_propagate",
    "preserve_cause",
]

idempotent = wardline_decorator(9, "idempotent", _wardline_idempotent=True)
"""Assert a function can be called multiple times with the same effect. Enforced by SCN-021."""

atomic = wardline_decorator(9, "atomic", _wardline_atomic=True)
"""Assert a function completes entirely or has no effect (all-or-nothing). Enforced by SUP-001, SCN-021."""


def compensatable(*, rollback: object) -> Any:
    """Mark a function as compensatable with a rollback target."""
    return wardline_decorator(
        9,
        "compensatable",
        _wardline_compensatable=True,
        _wardline_rollback=rollback,
    )

fail_closed = wardline_decorator(
    10,
    "fail_closed",
    _wardline_fail_closed=True,
)
"""Assert a function denies access or halts on error (safe default). Contradicts @fail_open. Enforced by SCN-021."""

fail_open = wardline_decorator(
    10,
    "fail_open",
    _wardline_fail_open=True,
)
"""Assert a function permits access or continues on error. Contradicts @fail_closed. Enforced by SCN-021."""

emits_or_explains = wardline_decorator(
    10,
    "emits_or_explains",
    _wardline_emits_or_explains=True,
)
"""Assert a function either emits a result or explains why it cannot. Enforced by SCN-021."""

exception_boundary = wardline_decorator(
    10,
    "exception_boundary",
    _wardline_exception_boundary=True,
)
"""Mark a function as an exception boundary that handles or translates errors. Enforced by SCN-021."""

must_propagate = wardline_decorator(
    10,
    "must_propagate",
    _wardline_must_propagate=True,
)
"""Assert a function must propagate exceptions to callers (no silent swallowing). Enforced by SCN-021."""

preserve_cause = wardline_decorator(
    10,
    "preserve_cause",
    _wardline_preserve_cause=True,
)
"""Assert a function preserves the original exception cause when re-raising. Enforced by SCN-021."""
