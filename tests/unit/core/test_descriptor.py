# tests/unit/core/test_descriptor.py
from __future__ import annotations

import yaml

from wardline.core.descriptor import build_vocabulary_descriptor, descriptor_to_yaml
from wardline.core.registry import REGISTRY, REGISTRY_VERSION


def test_descriptor_carries_registry_version() -> None:
    assert build_vocabulary_descriptor()["version"] == REGISTRY_VERSION


def test_descriptor_round_trips_registry() -> None:
    descriptor = build_vocabulary_descriptor()
    reconstructed = {e["canonical_name"]: (e["group"], e["attrs"]) for e in descriptor["entries"]}
    expected = {
        name: (entry.group, {k: v.__name__ for k, v in entry.attrs.items()}) for name, entry in REGISTRY.items()
    }
    assert reconstructed == expected


def test_descriptor_entry_order_follows_registry() -> None:
    names = [e["canonical_name"] for e in build_vocabulary_descriptor()["entries"]]
    assert names == list(REGISTRY)


def test_descriptor_envelope_carries_schema_version_entries() -> None:
    # Pin the top-level contract surface: a future stray key (e.g. a signature
    # field) would silently expand the descriptor without this guard. `schema`
    # (the descriptor FORMAT version) is distinct from `version` (the REGISTRY
    # CONTENT version) — both are required cross-product contract fields.
    assert set(build_vocabulary_descriptor()) == {"schema", "version", "entries"}


def test_descriptor_carries_schema_identifier() -> None:
    assert build_vocabulary_descriptor()["schema"] == "wardline.vocabulary/v1"


def test_descriptor_entries_carry_exactly_three_fields() -> None:
    for entry in build_vocabulary_descriptor()["entries"]:
        assert set(entry) == {"canonical_name", "group", "attrs"}


def test_attrs_serialize_as_taint_type_names() -> None:
    by_name = {e["canonical_name"]: e for e in build_vocabulary_descriptor()["entries"]}
    assert by_name["external_boundary"]["attrs"] == {}
    assert by_name["trust_boundary"]["attrs"] == {"_wardline_to_level": "TaintState"}
    assert by_name["trusted"]["attrs"] == {"_wardline_level": "TaintState"}


def test_descriptor_to_yaml_round_trips_through_safe_load() -> None:
    text = descriptor_to_yaml()
    assert yaml.safe_load(text) == build_vocabulary_descriptor()


def test_committed_vocabulary_yaml_matches_registry() -> None:
    # The committed, wheel-shipped vocabulary.yaml must be BYTE-identical to the
    # serializer output — not merely parse-equal. Loomweave consumes the file's
    # bytes via the read-instead-of-import path, and the regen one-liner promises
    # byte-reproducibility, so byte-identity (not just content) is the contract.
    # If this fails, regenerate with:
    #   .venv/bin/wardline vocab > src/wardline/core/vocabulary.yaml
    from importlib.resources import files

    file_text = files("wardline.core").joinpath("vocabulary.yaml").read_text(encoding="utf-8")
    regen_hint = "vocabulary.yaml is stale; regenerate: .venv/bin/wardline vocab > src/wardline/core/vocabulary.yaml"
    # Content currency (catches a REGISTRY change the file didn't track)...
    assert yaml.safe_load(file_text) == build_vocabulary_descriptor(), regen_hint
    # ...and byte-identity (catches a reformat / emitter drift the parse misses).
    assert file_text == descriptor_to_yaml(), regen_hint


def test_committed_yaml_is_consumable_as_pure_data() -> None:
    # The whole point of the descriptor: a peer (Loomweave) reads the file's BYTES
    # and gates on `schema` — WITHOUT importing wardline.core.registry. This test
    # consumes only the committed YAML + stdlib/yaml, never touching REGISTRY.
    from importlib.resources import files

    text = files("wardline.core").joinpath("vocabulary.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    assert data["schema"] == "wardline.vocabulary/v1"
    assert isinstance(data["version"], str) and data["version"]
    names = {e["canonical_name"] for e in data["entries"]}
    assert {"external_boundary", "trust_boundary", "trusted"} <= names
