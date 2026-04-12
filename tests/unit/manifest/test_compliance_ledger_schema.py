"""Tests for the reference compliance-ledger schema."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).parents[3]
SCHEMA_PATH = ROOT / "src" / "wardline" / "manifest" / "schemas" / "compliance-ledger.schema.json"
LEDGER_PATH = ROOT / "wardline.compliance.json"


def _load_schema() -> dict[str, object]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))  # type: ignore[return-value]


def _load_ledger() -> dict[str, object]:
    return json.loads(LEDGER_PATH.read_text(encoding="utf-8"))  # type: ignore[return-value]


def test_schema_is_valid_json_schema() -> None:
    schema = _load_schema()
    jsonschema.Draft202012Validator.check_schema(schema)


def test_live_reference_ledger_validates() -> None:
    schema = _load_schema()
    ledger = _load_ledger()
    jsonschema.validate(ledger, schema)


def test_bootstrap_declaration_required_even_without_bootstrap_attested_rows() -> None:
    schema = _load_schema()
    ledger = copy.deepcopy(_load_ledger())
    del ledger["bootstrap_reference_declaration"]

    validator = jsonschema.Draft202012Validator(schema)
    errors = list(validator.iter_errors(ledger))

    assert any(list(error.absolute_path) == [] for error in errors)


def test_summary_slip_count_required_when_reference_declaration_present() -> None:
    schema = _load_schema()
    ledger = copy.deepcopy(_load_ledger())
    del ledger["summary"]["slip_count"]

    validator = jsonschema.Draft202012Validator(schema)
    errors = list(validator.iter_errors(ledger))

    assert any(list(error.absolute_path) == ["summary"] for error in errors)
