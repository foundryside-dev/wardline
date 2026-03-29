"""Group 15 decorators — Lifecycle and scope."""

from __future__ import annotations

from typing import Any

from wardline.decorators._base import wardline_decorator

__all__ = [
    "test_only",
    "deprecated_by",
    "feature_gated",
]

test_only = wardline_decorator(15, "test_only", _wardline_test_only=True)
"""Mark a function as test-only — production code importing it triggers SUP-001. Enforced by SUP-001, SCN-021."""


def deprecated_by(*, date: str, replacement: str) -> Any:
    """Mark a callable as deprecated after a date with a replacement."""
    return wardline_decorator(
        15,
        "deprecated_by",
        _wardline_deprecated_by=True,
        _wardline_deprecation_date=date,
        _wardline_replacement=replacement,
    )


def feature_gated(*, flag: str) -> Any:
    """Mark a callable as controlled by a feature flag."""
    return wardline_decorator(
        15,
        "feature_gated",
        _wardline_feature_gated=True,
        _wardline_feature_flag=flag,
    )
