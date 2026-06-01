# tests/conformance/test_qualname_conformance.py
"""Drive the shared qualname conformance corpus through Wardline's producer.

The corpus (qualnames.json) is the cross-tool design-review artifact; Clarion
vendors a copy and runs the same assertions. Keep them in lockstep.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from wardline.core.qualname import module_dotted_name
from wardline.scanner.index import discover_file_entities

_CORPUS = json.loads((Path(__file__).parent / "qualnames.json").read_text("utf-8"))


@pytest.mark.parametrize("case", _CORPUS["module_dotted_name"], ids=lambda c: c["rel_path"])
def test_module_dotted_name(case: dict[str, Any]) -> None:
    assert module_dotted_name(case["rel_path"]) == case["expected"]


@pytest.mark.parametrize("case", _CORPUS["entities"], ids=lambda c: c["name"])
def test_entities(case: dict[str, Any]) -> None:
    module = module_dotted_name(case["rel_path"])
    if module is None:
        # A file with no module emits no entities (top-level __init__.py).
        assert case["expected"] == []
        return
    tree = ast.parse(case["source"])
    found = [
        {"qualname": e.qualname, "kind": e.kind}
        for e in discover_file_entities(tree, module=module, path=case["rel_path"])
    ]
    assert found == case["expected"]
