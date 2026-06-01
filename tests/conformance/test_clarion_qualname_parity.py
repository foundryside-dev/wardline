# tests/conformance/test_clarion_qualname_parity.py
"""Pin Wardline's qualname producer against Clarion's normative parity fixture.

The reconciliation CONSUMER is unbuilt in clarion 1.0.0; this converts the
producer byte-equality from assumption to a committed CI test. Wardline returns
``None`` where Clarion returns ``""`` for a top-level ``__init__.py`` — the
``None <-> ""`` mapping below is the documented, semantically-equivalent boundary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from wardline.core.qualname import module_dotted_name

_FIXTURE = json.loads((Path(__file__).parent / "clarion_qualname_parity.json").read_text("utf-8"))


@pytest.mark.parametrize("vec", _FIXTURE["module_normalization_vectors"], ids=lambda v: v["file_path"])
def test_module_normalization(vec: dict[str, Any]) -> None:
    got = module_dotted_name(vec["file_path"])
    expected = vec["expected_module"]
    if expected == "":
        assert got is None  # Wardline's "emit no entity" sentinel == Clarion's empty+rejected
    else:
        assert got == expected


@pytest.mark.parametrize(
    "vec",
    [v for v in _FIXTURE["qualified_name_vectors"] if v["kind"] == "function"],
    ids=lambda v: v["expected_qualified_name"],
)
def test_function_qualified_name_composition(vec: dict[str, Any]) -> None:
    module = module_dotted_name(vec["file_path"])
    assert module is not None
    assert f"{module}.{vec['qualname']}" == vec["expected_qualified_name"]


def test_qualified_name_vector_kinds_are_known() -> None:
    # Guard against a resync introducing a new `kind` that the parametrized tests above
    # would silently skip, leaving a contract vector unexercised.
    kinds = {v["kind"] for v in _FIXTURE["qualified_name_vectors"]}
    assert kinds <= {"function", "module"}, f"unhandled qualname vector kinds: {kinds - {'function', 'module'}}"


def test_module_kind_vector_prefix_matches() -> None:
    # The single kind=="module" vector: Wardline emits no module ENTITY, but the
    # module dotted prefix it produces must equal the expected qualified_name.
    module_vecs = [v for v in _FIXTURE["qualified_name_vectors"] if v["kind"] == "module"]
    assert module_vecs  # guard: the fixture must contain at least one module vector
    for vec in module_vecs:
        assert module_dotted_name(vec["file_path"]) == vec["expected_qualified_name"]
