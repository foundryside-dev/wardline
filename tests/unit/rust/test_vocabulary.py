"""WP3: the bundled Rust trust vocabulary (sources + command sinks)."""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.core.taints import TaintState  # noqa: E402
from wardline.rust.vocabulary import (  # noqa: E402
    RUST_TAINT_VERSION,
    RustSink,
    RustSource,
    _build_tables,
    load_rust_taint,
)


def test_version_is_exported() -> None:
    assert isinstance(RUST_TAINT_VERSION, int) and RUST_TAINT_VERSION >= 1


def test_bundled_table_has_the_command_source_and_sink() -> None:
    tables = load_rust_taint()
    env_var = tables.sources[("std", "env::var")]
    assert isinstance(env_var, RustSource)
    assert env_var.returns_taint is TaintState.EXTERNAL_RAW

    cmd = tables.sinks[("std", "process::Command::new")]
    assert isinstance(cmd, RustSink)
    assert cmd.sink_kind == "command"


def test_returns_taint_constrained_to_legal_tiers() -> None:
    # INTEGRAL and the unreachable trio must never enter the pipeline (reachable-set
    # invariant); a source returning your-own-fully-trusted data is nonsensical.
    raw = {
        "version": RUST_TAINT_VERSION,
        "sources": [{"crate": "std", "path": "x::y", "returns_taint": "INTEGRAL", "rationale": "r"}],
        "sinks": [],
    }
    with pytest.raises(ValueError, match="legal"):
        _build_tables(raw)


def test_duplicate_source_key_rejected() -> None:
    raw = {
        "version": RUST_TAINT_VERSION,
        "sources": [
            {"crate": "std", "path": "env::var", "returns_taint": "EXTERNAL_RAW", "rationale": "a"},
            {"crate": "std", "path": "env::var", "returns_taint": "EXTERNAL_RAW", "rationale": "b"},
        ],
        "sinks": [],
    }
    with pytest.raises(ValueError, match="duplicate"):
        _build_tables(raw)


def test_unknown_sink_kind_rejected() -> None:
    raw = {
        "version": RUST_TAINT_VERSION,
        "sources": [],
        "sinks": [{"crate": "std", "path": "p::q", "sink_kind": "bogus", "rationale": "r"}],
    }
    with pytest.raises(ValueError, match="sink_kind"):
        _build_tables(raw)
