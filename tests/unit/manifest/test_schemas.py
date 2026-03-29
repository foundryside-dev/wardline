"""Tests for T-3.1 JSON Schemas — structural validity via Draft7Validator."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

SCHEMA_DIR = (
    Path(__file__).parents[3] / "src" / "wardline" / "manifest" / "schemas"
)

SCHEMA_FILES = [
    "wardline.schema.json",
    "overlay.schema.json",
    "exceptions.schema.json",
    "fingerprint.schema.json",
    "corpus-specimen.schema.json",
]


@pytest.fixture(params=SCHEMA_FILES, ids=lambda f: f.removesuffix(".json"))
def schema(request: pytest.FixtureRequest) -> dict[str, object]:
    path = SCHEMA_DIR / request.param
    return json.loads(path.read_text())  # type: ignore[return-value]


class TestSchemaValidity:
    """All 5 schemas are structurally valid JSON Schema Draft 7."""

    def test_schema_is_valid_json_schema(
        self, schema: dict[str, object]
    ) -> None:
        jsonschema.Draft7Validator.check_schema(schema)

    def test_schema_has_id_with_version(
        self, schema: dict[str, object]
    ) -> None:
        schema_id = schema.get("$id", "")
        assert isinstance(schema_id, str)
        assert "1.0" in schema_id
        assert schema_id.startswith("https://wardline.dev/schemas/")

    def test_schema_has_title(self, schema: dict[str, object]) -> None:
        assert "title" in schema

    def test_schema_has_additional_properties_false(
        self, schema: dict[str, object]
    ) -> None:
        assert schema.get("additionalProperties") is False


class TestWardlineSchema:
    """Wardline root manifest schema specifics."""

    @pytest.fixture()
    def schema(self) -> dict[str, object]:
        path = SCHEMA_DIR / "wardline.schema.json"
        return json.loads(path.read_text())  # type: ignore[return-value]

    def test_taint_enum_values(self, schema: dict[str, object]) -> None:
        props = schema["properties"]  # type: ignore[index]
        mt_items = props["module_tiers"]["items"]["properties"]
        taint_enum = mt_items["default_taint"]["enum"]
        assert "EXTERNAL_RAW" in taint_enum
        assert "MIXED_RAW" in taint_enum
        assert len(taint_enum) == 8

    def test_governance_profile_enum(self, schema: dict[str, object]) -> None:
        props = schema["properties"]  # type: ignore[index]
        assert set(props["governance_profile"]["enum"]) == {"lite", "assurance"}

    def test_tier_range(self, schema: dict[str, object]) -> None:
        props = schema["properties"]  # type: ignore[index]
        tier_props = props["tiers"]["items"]["properties"]["tier"]
        assert tier_props["minimum"] == 1
        assert tier_props["maximum"] == 4

    def test_valid_manifest_accepted(self, schema: dict[str, object]) -> None:
        doc = {
            "governance_profile": "lite",
            "metadata": {"organisation": "Test"},
            "tiers": [{"id": "db", "tier": 1}],
            "module_tiers": [
                {"path": "src/", "default_taint": "EXTERNAL_RAW"}
            ],
        }
        jsonschema.validate(doc, schema)

    def test_invalid_governance_profile_rejected(
        self, schema: dict[str, object]
    ) -> None:
        doc = {"governance_profile": "custom"}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, schema)

    def test_invalid_taint_rejected(self, schema: dict[str, object]) -> None:
        doc = {
            "module_tiers": [
                {"path": "src/", "default_taint": "INVALID_TAINT"}
            ],
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, schema)

    def test_valid_rule_override_accepted(self, schema: dict[str, object]) -> None:
        doc = {
            "rules": {
                "overrides": [
                    {"id": "PY-WL-001", "severity": "WARNING"}
                ]
            }
        }
        jsonschema.validate(doc, schema)

    def test_rule_override_unknown_field_rejected(
        self, schema: dict[str, object]
    ) -> None:
        doc = {
            "rules": {
                "overrides": [
                    {"id": "PY-WL-001", "severtiy": "WARNING"}
                ]
            }
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, schema)

    def test_additional_properties_rejected(
        self, schema: dict[str, object]
    ) -> None:
        doc = {"unknown_field": "value"}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, schema)


class TestExceptionsSchema:
    """Exceptions schema includes threat control fields."""

    @pytest.fixture()
    def schema(self) -> dict[str, object]:
        path = SCHEMA_DIR / "exceptions.schema.json"
        return json.loads(path.read_text())  # type: ignore[return-value]

    def test_has_agent_originated(self, schema: dict[str, object]) -> None:
        exc_props = schema["properties"]["exceptions"]["items"]["properties"]  # type: ignore[index]
        assert "agent_originated" in exc_props
        # Must accept null (provenance unknown)
        assert "null" in exc_props["agent_originated"]["type"]

    def test_has_recurrence_count(self, schema: dict[str, object]) -> None:
        exc_props = schema["properties"]["exceptions"]["items"]["properties"]  # type: ignore[index]
        assert "recurrence_count" in exc_props
        assert exc_props["recurrence_count"]["type"] == "integer"

    def test_has_governance_path(self, schema: dict[str, object]) -> None:
        exc_props = schema["properties"]["exceptions"]["items"]["properties"]  # type: ignore[index]
        assert "governance_path" in exc_props
        assert set(exc_props["governance_path"]["enum"]) == {
            "standard",
            "expedited",
        }


class TestOverlaySchema:
    """Overlay schema specifics."""

    @pytest.fixture()
    def schema(self) -> dict[str, object]:
        path = SCHEMA_DIR / "overlay.schema.json"
        return json.loads(path.read_text())  # type: ignore[return-value]

    def test_valid_rule_override_accepted(self, schema: dict[str, object]) -> None:
        doc = {
            "overlay_for": "adapters/",
            "rule_overrides": [
                {"id": "PY-WL-001", "severity": "WARNING"}
            ],
        }
        jsonschema.validate(doc, schema)

    def test_rule_override_unknown_field_rejected(
        self, schema: dict[str, object]
    ) -> None:
        doc = {
            "overlay_for": "adapters/",
            "rule_overrides": [
                {"id": "PY-WL-001", "severtiy": "WARNING"}
            ],
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, schema)


class TestCorpusSpecimenSchema:
    """Corpus specimen schema has verdict enum."""

    @pytest.fixture()
    def schema(self) -> dict[str, object]:
        path = SCHEMA_DIR / "corpus-specimen.schema.json"
        return json.loads(path.read_text())  # type: ignore[return-value]

    def test_verdict_enum(self, schema: dict[str, object]) -> None:
        verdict = schema["properties"]["verdict"]  # type: ignore[index]
        assert set(verdict["enum"]) == {
            "true_positive",
            "true_negative",
            "known_false_negative",
        }

    def test_valid_specimen_accepted(self, schema: dict[str, object]) -> None:
        doc = {
            "specimen_id": "tp-wl004-bare-except",
            "rule": "PY-WL-004",
            "fragment": "try:\\n    pass\\nexcept:\\n    pass",
            "taint_state": "EXTERNAL_RAW",
            "verdict": "true_positive",
        }
        jsonschema.validate(doc, schema)

    def test_optional_fields_specimen_accepted(
        self, schema: dict[str, object]
    ) -> None:
        doc = {
            "specimen_id": "tn-wl001-governed-schema-default",
            "rule": "PY-WL-001",
            "fragment": "def process(data):\\n    return schema_default(data.get('key', ''))",
            "taint_state": "EXTERNAL_RAW",
            "verdict": "true_negative",
            "boundaries": [
                {
                    "function": "process",
                    "transition": "shape_validation",
                }
            ],
            "optional_fields": [
                {
                    "field": "key",
                    "approved_default": "",
                    "rationale": "optional by contract",
                }
            ],
        }
        jsonschema.validate(doc, schema)
