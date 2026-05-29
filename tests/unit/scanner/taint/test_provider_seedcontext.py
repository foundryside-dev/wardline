# tests/unit/scanner/taint/test_provider_seedcontext.py
from __future__ import annotations

import pytest

from wardline.scanner.taint.provider import SeedContext


def test_seedcontext_defaults_to_empty_alias_map() -> None:
    ctx = SeedContext(module="m")
    assert ctx.module == "m"
    assert dict(ctx.alias_map) == {}


def test_seedcontext_carries_alias_map() -> None:
    ctx = SeedContext(module="m", alias_map={"t": "wardline.decorators.trusted"})
    assert ctx.alias_map["t"] == "wardline.decorators.trusted"


def test_seedcontext_is_frozen() -> None:
    ctx = SeedContext(module="m")
    with pytest.raises(AttributeError):
        ctx.module = "other"  # type: ignore[misc]
