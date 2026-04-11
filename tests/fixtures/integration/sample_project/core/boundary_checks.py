"""Fixture: boundary checks with PY-WL-008 and PY-WL-009 patterns.

This file lives under core/ and triggers:
- PY-WL-008: @validates_shape decorated function with no raise statement
- PY-WL-009: @validates_semantic decorated function with subscript access
             and no prior shape validation
"""

from wardline.decorators import validates_semantic, validates_shape


@validates_shape
def check_format(data: object) -> bool:
    """PY-WL-008: boundary decorator present but no rejection path (no raise)."""
    return isinstance(data, dict) and "status" in data


@validates_semantic
def check_business_rules(data: dict) -> bool:
    """PY-WL-009: subscript access without prior shape validation.

    Intentionally uses if/return instead of the simplified `return expr` form:
    PY-WL-009 detects semantic checks via ast.If/ast.Assert nodes with subscript
    access. The simplified form contains no ast.If, so the rule doesn't fire and
    the integration test that depends on this fixture breaks. Do not "simplify".
    """
    if data["status"] == "active":  # noqa: SIM103 — see docstring
        return True
    return False
