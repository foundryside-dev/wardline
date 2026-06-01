# tests/unit/scanner/taint/test_provider.py
from __future__ import annotations

import ast
import dataclasses

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.index import discover_file_entities
from wardline.scanner.taint.provider import (
    DefaultTaintSourceProvider,
    FunctionTaint,
    SeedContext,
    SeedResult,
    TaintSourceProvider,
)


def _entity() -> object:
    tree = ast.parse("def f():\n    pass\n")
    return discover_file_entities(tree, module="demo", path="demo.py")[0]


def test_default_provider_has_no_opinion() -> None:
    provider = DefaultTaintSourceProvider()
    res = provider.taint_for(_entity(), SeedContext(module="demo"))  # type: ignore[arg-type]
    assert isinstance(res, SeedResult)
    assert res.taint is None
    assert res.unprovable_boundaries == ()  # builtins never signal (oracle-preserving)


def test_default_provider_satisfies_protocol() -> None:
    assert isinstance(DefaultTaintSourceProvider(), TaintSourceProvider)


def test_function_taint_is_frozen() -> None:
    taint = FunctionTaint(body_taint=TaintState.EXTERNAL_RAW, return_taint=TaintState.GUARDED)
    assert taint.body_taint == TaintState.EXTERNAL_RAW
    assert taint.return_taint == TaintState.GUARDED
    with pytest.raises(dataclasses.FrozenInstanceError):
        taint.body_taint = TaintState.INTEGRAL  # type: ignore[misc]


def test_seed_context_carries_module() -> None:
    assert SeedContext(module="pkg.sub").module == "pkg.sub"


def test_default_provider_fingerprint_is_stable() -> None:
    p = DefaultTaintSourceProvider()
    assert isinstance(p.fingerprint(), str)
    assert p.fingerprint() == DefaultTaintSourceProvider().fingerprint()


def test_provider_protocol_requires_fingerprint() -> None:
    assert isinstance(DefaultTaintSourceProvider(), TaintSourceProvider)
