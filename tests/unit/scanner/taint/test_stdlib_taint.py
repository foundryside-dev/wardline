# tests/unit/scanner/taint/test_stdlib_taint.py
from __future__ import annotations

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.taint.stdlib_taint import (
    STDLIB_TAINT_VERSION,
    StdlibTaintEntry,
    _build_table,
    load_stdlib_taint,
    stdlib_taint_keys,
)


def test_known_entries_present() -> None:
    table = load_stdlib_taint()
    assert table[("json", "loads")].taint == TaintState.GUARDED
    assert table[("builtins", "open")].taint == TaintState.EXTERNAL_RAW
    assert table[("os", "environ.get")].taint == TaintState.EXTERNAL_RAW
    assert table[("ast", "literal_eval")].taint == TaintState.GUARDED


def test_every_entry_has_rationale() -> None:
    for entry in load_stdlib_taint().values():
        assert isinstance(entry, StdlibTaintEntry)
        assert entry.rationale


def test_table_is_immutable() -> None:
    table = load_stdlib_taint()
    with pytest.raises(TypeError):
        table[("x", "y")] = StdlibTaintEntry(TaintState.GUARDED, "x")  # type: ignore[index]


def test_keys_membership() -> None:
    keys = stdlib_taint_keys()
    assert ("json", "loads") in keys
    assert ("definitely", "missing") not in keys


def test_version_mismatch_raises() -> None:
    with pytest.raises(ValueError, match="version mismatch"):
        _build_table({"version": 999, "entries": []})


def test_entries_must_be_a_list() -> None:
    with pytest.raises(ValueError, match="entries"):
        _build_table({"version": STDLIB_TAINT_VERSION, "entries": "nope"})


def test_non_canonical_taint_token_raises() -> None:
    with pytest.raises(ValueError, match="canonical TaintState"):
        _build_table(
            {
                "version": STDLIB_TAINT_VERSION,
                "entries": [
                    {"package": "p", "function": "f", "returns_taint": "BOGUS"}
                ],
            }
        )


def test_valid_build_round_trips() -> None:
    table = _build_table(
        {
            "version": STDLIB_TAINT_VERSION,
            "entries": [
                {
                    "package": "p",
                    "function": "f",
                    "returns_taint": "GUARDED",
                    "rationale": "x",
                }
            ],
        }
    )
    assert table[("p", "f")] == StdlibTaintEntry(TaintState.GUARDED, "x")


def test_duplicate_key_raises() -> None:
    # A later entry must not silently shadow an earlier one — that would drop a
    # curated taint and the loaded table's len() would hide the loss.
    with pytest.raises(ValueError, match="duplicate"):
        _build_table(
            {
                "version": STDLIB_TAINT_VERSION,
                "entries": [
                    {"package": "p", "function": "f", "returns_taint": "GUARDED", "rationale": "a"},
                    {"package": "p", "function": "f", "returns_taint": "EXTERNAL_RAW", "rationale": "b"},
                ],
            }
        )


@pytest.mark.parametrize("rationale", [None, ""])
def test_missing_or_empty_rationale_raises(rationale: str | None) -> None:
    entry = {"package": "p", "function": "f", "returns_taint": "GUARDED"}
    if rationale is not None:
        entry["rationale"] = rationale
    with pytest.raises(ValueError, match="rationale"):
        _build_table({"version": STDLIB_TAINT_VERSION, "entries": [entry]})


def test_empty_entries_is_valid_empty_table() -> None:
    # A degenerate-but-valid table: no curated fallbacks, contributes nothing.
    assert dict(_build_table({"version": STDLIB_TAINT_VERSION, "entries": []})) == {}
