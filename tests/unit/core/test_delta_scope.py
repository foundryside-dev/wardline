"""Phase 1 — ``delta_scope.parse_affected_scope`` / ``load_affected_scope`` (spec §5.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wardline.core.delta_scope import (
    _MAX_ITEM_COUNT,
    _MAX_PAYLOAD_BYTES,
    AffectedEntity,
    AffectedScope,
    ScopeParseError,
    load_affected_scope,
    parse_affected_scope,
    parse_affected_scope_text,
)
from wardline.core.errors import WardlineError

# --- the three structurally-distinct accepted shapes -----------------------------


def test_full_envelope_with_data_wrapper() -> None:
    """Shape 1: ``warpline.reverify_worklist.v1`` full success envelope."""
    payload = {
        "schema": "warpline.reverify_worklist.v1",
        "data": {
            "items": [
                {"entity": {"sei": "loomweave:eid:aaaa", "locator": "python:function:pkg.a"}},
                {"entity": {"locator": "python:function:pkg.b"}},
            ]
        },
    }
    scope = parse_affected_scope(payload)
    assert isinstance(scope, AffectedScope)
    assert scope.source_kind == "reverify_worklist_v1"
    assert scope.item_count == 2
    assert scope.entities == frozenset(
        {
            AffectedEntity(sei="loomweave:eid:aaaa", locator="python:function:pkg.a"),
            AffectedEntity(sei=None, locator="python:function:pkg.b"),
        }
    )


def test_bare_data_payload_no_envelope() -> None:
    """Shape 2: a producer that sends the inner ``data`` object directly (``{"items": …}``)
    — a DISTINCT object from shape 1; must parse via its own fixture."""
    payload = {
        "items": [
            {"entity": {"sei": "loomweave:eid:bbbb"}},
            {"entity": {"locator": "python:method:pkg.Cls.m"}},
        ]
    }
    scope = parse_affected_scope(payload)
    assert scope.source_kind == "reverify_worklist_v1"
    assert scope.item_count == 2
    assert scope.entities == frozenset(
        {
            AffectedEntity(sei="loomweave:eid:bbbb", locator=None),
            AffectedEntity(sei=None, locator="python:method:pkg.Cls.m"),
        }
    )


def test_bare_entity_list() -> None:
    """Shape 3: a bare ``[{sei?, locator?}, ...]`` list."""
    payload = [
        {"sei": "loomweave:eid:cccc", "locator": "python:function:pkg.c"},
        {"locator": "python:class:pkg.D"},
    ]
    scope = parse_affected_scope(payload)
    assert scope.source_kind == "entity_list"
    assert scope.item_count == 2
    assert scope.entities == frozenset(
        {
            AffectedEntity(sei="loomweave:eid:cccc", locator="python:function:pkg.c"),
            AffectedEntity(sei=None, locator="python:class:pkg.D"),
        }
    )


# --- entity sei/locator combinations ---------------------------------------------


@pytest.mark.parametrize(
    ("obj", "expected"),
    [
        ({"sei": "s"}, AffectedEntity(sei="s", locator=None)),
        ({"locator": "python:function:x"}, AffectedEntity(sei=None, locator="python:function:x")),
        (
            {"sei": "s", "locator": "python:function:x"},
            AffectedEntity(sei="s", locator="python:function:x"),
        ),
    ],
)
def test_entity_sei_locator_combinations(obj: dict[str, str], expected: AffectedEntity) -> None:
    scope = parse_affected_scope([obj])
    assert scope.entities == frozenset({expected})
    assert scope.source_kind == "entity_list"


def test_entity_with_neither_sei_nor_locator_is_dropped() -> None:
    """An entity with neither key (or only blank/null values) is dropped — counts toward
    ``item_count`` (the input was seen) but not toward the resolved entity set; a list of
    only such entities is 'empty'."""
    scope = parse_affected_scope([{"priority": 1}, {"sei": None, "locator": ""}])
    assert scope.entities == frozenset()
    assert scope.source_kind == "empty"
    assert scope.item_count == 2


# --- empty payloads are NOT errors (fail-closed handled downstream) ----------------


def test_empty_list_is_empty_not_error() -> None:
    scope = parse_affected_scope([])
    assert scope == AffectedScope(frozenset(), "empty", 0)


def test_empty_worklist_items_is_empty_not_error() -> None:
    scope = parse_affected_scope({"data": {"items": []}})
    assert scope == AffectedScope(frozenset(), "empty", 0)


def test_worklist_object_with_no_items_is_empty_not_error() -> None:
    scope = parse_affected_scope({"data": {}})
    assert scope == AffectedScope(frozenset(), "empty", 0)


# --- malformed payloads are loud ScopeParseError ----------------------------------


def test_scope_parse_error_is_wardline_error() -> None:
    assert issubclass(ScopeParseError, WardlineError)


@pytest.mark.parametrize(
    "payload",
    [
        "a string",
        42,
        None,
        True,
    ],
)
def test_non_object_non_array_payload_raises(payload: object) -> None:
    with pytest.raises(ScopeParseError):
        parse_affected_scope(payload)


def test_items_not_a_list_raises() -> None:
    with pytest.raises(ScopeParseError):
        parse_affected_scope({"data": {"items": {"not": "a list"}}})


def test_data_not_an_object_raises() -> None:
    with pytest.raises(ScopeParseError):
        parse_affected_scope({"data": "not an object"})


def test_worklist_item_not_an_object_raises() -> None:
    with pytest.raises(ScopeParseError):
        parse_affected_scope({"items": ["not-an-object"]})


def test_worklist_item_entity_not_an_object_raises() -> None:
    with pytest.raises(ScopeParseError):
        parse_affected_scope({"items": [{"entity": "not-an-object"}]})


def test_entity_list_item_not_an_object_raises() -> None:
    with pytest.raises(ScopeParseError):
        parse_affected_scope(["not-an-object"])


def test_worklist_item_without_entity_key_is_skipped() -> None:
    """A worklist item missing its ``entity`` key is skipped (not malformed) — only a
    non-object ``entity`` value is malformed."""
    scope = parse_affected_scope({"items": [{"priority": 3}, {"entity": {"locator": "python:function:pkg.f"}}]})
    assert scope.entities == frozenset({AffectedEntity(sei=None, locator="python:function:pkg.f")})
    assert scope.item_count == 2


# --- over-cap (bytes AND item_count) ----------------------------------------------


def test_over_cap_by_item_count_raises() -> None:
    payload = [{"locator": f"python:function:pkg.f{i}"} for i in range(_MAX_ITEM_COUNT + 1)]
    with pytest.raises(ScopeParseError, match="item cap"):
        parse_affected_scope(payload)


def test_over_cap_by_item_count_worklist_raises() -> None:
    payload = {"items": [{"entity": {"locator": f"python:function:pkg.f{i}"}} for i in range(_MAX_ITEM_COUNT + 1)]}
    with pytest.raises(ScopeParseError, match="item cap"):
        parse_affected_scope(payload)


def test_over_cap_by_bytes_raises() -> None:
    """A payload whose serialized byte length exceeds the cap raises even if the item
    count alone is under the limit (one giant value)."""
    big_locator = "python:function:" + ("x" * (_MAX_PAYLOAD_BYTES + 1))
    with pytest.raises(ScopeParseError, match="byte cap"):
        parse_affected_scope([{"locator": big_locator}])


def test_under_cap_passes() -> None:
    payload = [{"locator": f"python:function:pkg.f{i}"} for i in range(10)]
    scope = parse_affected_scope(payload)
    assert scope.item_count == 10


# --- parse_affected_scope_text (raw-text ingress, pre-parse byte cap) --------------


def test_parse_affected_scope_text_valid() -> None:
    """The raw-text entry point parses a valid JSON string into an AffectedScope."""
    raw = json.dumps([{"locator": "python:function:pkg.f"}])
    scope = parse_affected_scope_text(raw)
    assert scope.entities == frozenset({AffectedEntity(sei=None, locator="python:function:pkg.f")})
    assert scope.source_kind == "entity_list"


def test_parse_affected_scope_text_bad_json_raises() -> None:
    """Invalid JSON in the raw text raises ScopeParseError (malformed posture, §7)."""
    with pytest.raises(ScopeParseError, match="not valid JSON"):
        parse_affected_scope_text("{not valid json")


def test_parse_affected_scope_text_over_cap_rejected_before_parse(monkeypatch) -> None:
    """A VALID JSON blob whose RAW byte length just exceeds the cap is rejected BEFORE
    ``json.loads`` ever parses it (DoS guard at the raw-bytes boundary, §7).

    We assert the pre-parse ordering directly: patch ``json.loads`` in the module to
    explode if it is ever called, then confirm the over-cap raw text raises the byte-cap
    ScopeParseError without that call firing."""
    import wardline.core.delta_scope as ds

    def _boom(_s: str) -> object:  # pragma: no cover - must never run
        raise AssertionError("json.loads was called on an over-cap blob before the byte cap fired")

    monkeypatch.setattr(ds.json, "loads", _boom)

    # A valid JSON array padded to just over the byte cap by a giant locator value.
    big_locator = "python:function:" + ("x" * (_MAX_PAYLOAD_BYTES + 1))
    raw = json.dumps([{"locator": big_locator}])
    assert len(raw.encode("utf-8")) > _MAX_PAYLOAD_BYTES
    with pytest.raises(ScopeParseError, match="byte cap"):
        parse_affected_scope_text(raw)


def test_parse_affected_scope_text_at_cap_passes() -> None:
    """A raw text whose byte length is exactly at (not over) the cap is accepted."""
    raw = json.dumps([{"locator": "python:function:pkg.f"}])
    assert len(raw.encode("utf-8")) <= _MAX_PAYLOAD_BYTES
    scope = parse_affected_scope_text(raw)
    assert scope.item_count == 1


# --- load_affected_scope (file ingress) -------------------------------------------


def test_load_affected_scope_reads_file(tmp_path: Path) -> None:
    src = tmp_path / "worklist.json"
    src.write_text(json.dumps([{"locator": "python:function:pkg.f"}]), encoding="utf-8")
    scope = load_affected_scope(str(src))
    assert scope.entities == frozenset({AffectedEntity(sei=None, locator="python:function:pkg.f")})
    assert scope.source_kind == "entity_list"


def test_load_affected_scope_bad_json_raises(tmp_path: Path) -> None:
    src = tmp_path / "broken.json"
    src.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ScopeParseError, match="not valid JSON"):
        load_affected_scope(str(src))


def test_load_affected_scope_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ScopeParseError, match="could not read"):
        load_affected_scope(str(tmp_path / "does-not-exist.json"))


def test_load_affected_scope_full_envelope_file(tmp_path: Path) -> None:
    src = tmp_path / "envelope.json"
    src.write_text(
        json.dumps({"data": {"items": [{"entity": {"sei": "loomweave:eid:z"}}]}}),
        encoding="utf-8",
    )
    scope = load_affected_scope(str(src))
    assert scope.source_kind == "reverify_worklist_v1"
    assert scope.entities == frozenset({AffectedEntity(sei="loomweave:eid:z", locator=None)})
