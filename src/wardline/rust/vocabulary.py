"""Loader for the bundled Rust trust vocabulary (``rust_taint.yaml``).

Two frozen tables keyed by ``(crate, path)``: ``sources`` (a std call's returned-value
taint) and ``sinks`` (a dangerous call target's ``sink_kind``). ``_build_tables`` is
separated from IO so its validation is unit-testable without a fixture on disk
(mirrors ``scanner/taint/stdlib_taint.py``). ``RUST_TAINT_VERSION`` folds into the
provider fingerprint so a vocab edit invalidates dependent summaries.
"""

from __future__ import annotations

from collections.abc import Mapping  # noqa: TC003  # runtime import for typing reflection
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from types import MappingProxyType
from typing import Any

from wardline.core.optional_deps import require_yaml
from wardline.core.taints import TaintState

# A source returns data the project did not produce, so INTEGRAL (your own fully
# trusted data) is nonsensical, and the unreachable trio {MIXED_RAW, UNKNOWN_GUARDED,
# UNKNOWN_ASSURED} must never enter the pipeline (reachable-set invariant). Same
# constraint as the Python stdlib table.
_LEGAL_RETURN: frozenset[TaintState] = frozenset(
    {TaintState.ASSURED, TaintState.GUARDED, TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW}
)
_LEGAL_SINK_KINDS: frozenset[str] = frozenset({"command"})

RUST_TAINT_VERSION: int = 3
"""Bumped when the table's shape or entries change materially; folded into the
provider fingerprint so changes invalidate dependent summaries. v2 dropped the inert
``io::stdin`` source (out-param reads are unmodelled in slice-1). v3 added the async-runtime
command sinks (``tokio::process::Command::new``, ``async_process::Command::new``) so the
crate-aware matcher admits them (a crate-blind suffix used to catch tokio by accident)."""

__all__ = [
    "RUST_TAINT_VERSION",
    "RustSink",
    "RustSource",
    "RustTaintTables",
    "load_rust_taint",
]


@dataclass(frozen=True, slots=True)
class RustSource:
    """A std call whose returned value carries the given taint."""

    returns_taint: TaintState
    rationale: str


@dataclass(frozen=True, slots=True)
class RustSink:
    """A dangerous call target, classified by ``sink_kind`` (slice-1: ``command``)."""

    sink_kind: str
    rationale: str


@dataclass(frozen=True, slots=True)
class RustTaintTables:
    sources: Mapping[tuple[str, str], RustSource]
    sinks: Mapping[tuple[str, str], RustSink]


def _require_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"rust_taint.yaml {where} must be a non-empty string")
    return value


def _build_tables(raw: Any) -> RustTaintTables:
    if not isinstance(raw, dict) or raw.get("version") != RUST_TAINT_VERSION:
        got = raw.get("version") if isinstance(raw, dict) else raw
        raise ValueError(f"rust_taint.yaml version mismatch: expected {RUST_TAINT_VERSION}, got {got!r}")

    sources: dict[tuple[str, str], RustSource] = {}
    for idx, entry in enumerate(_as_list(raw.get("sources"), "sources")):
        crate = _require_str(_get(entry, idx, "crate"), f"sources[{idx}].crate")
        path = _require_str(_get(entry, idx, "path"), f"sources[{idx}].path")
        returns_raw = _get(entry, idx, "returns_taint")
        if not isinstance(returns_raw, str):
            raise ValueError(f"rust_taint.yaml sources[{idx}].returns_taint must be a string")
        try:
            taint = TaintState(returns_raw)
        except ValueError as exc:
            raise ValueError(
                f"rust_taint.yaml sources[{idx}].returns_taint={returns_raw!r} is not a canonical TaintState"
            ) from exc
        if taint not in _LEGAL_RETURN:
            raise ValueError(
                f"rust_taint.yaml sources[{idx}].returns_taint={returns_raw!r} is not a legal source "
                f"return tier (allowed: {sorted(s.value for s in _LEGAL_RETURN)}); a state outside this "
                f"set would inject an otherwise-unreachable taint and break the reachable-set invariant"
            )
        rationale = _require_str(_get(entry, idx, "rationale"), f"sources[{idx}].rationale")
        key = (crate, path)
        if key in sources:
            raise ValueError(
                f"rust_taint.yaml sources[{idx}]: duplicate ({crate!r}, {path!r}) — "
                f"a later entry would silently shadow an earlier one"
            )
        sources[key] = RustSource(returns_taint=taint, rationale=rationale)

    sinks: dict[tuple[str, str], RustSink] = {}
    for idx, entry in enumerate(_as_list(raw.get("sinks"), "sinks")):
        crate = _require_str(_get(entry, idx, "crate"), f"sinks[{idx}].crate")
        path = _require_str(_get(entry, idx, "path"), f"sinks[{idx}].path")
        sink_kind = _require_str(_get(entry, idx, "sink_kind"), f"sinks[{idx}].sink_kind")
        if sink_kind not in _LEGAL_SINK_KINDS:
            raise ValueError(
                f"rust_taint.yaml sinks[{idx}].sink_kind={sink_kind!r} is not a known sink_kind "
                f"(allowed: {sorted(_LEGAL_SINK_KINDS)})"
            )
        rationale = _require_str(_get(entry, idx, "rationale"), f"sinks[{idx}].rationale")
        key = (crate, path)
        if key in sinks:
            raise ValueError(
                f"rust_taint.yaml sinks[{idx}]: duplicate ({crate!r}, {path!r}) — "
                f"a later entry would silently shadow an earlier one"
            )
        sinks[key] = RustSink(sink_kind=sink_kind, rationale=rationale)

    return RustTaintTables(sources=MappingProxyType(sources), sinks=MappingProxyType(sinks))


def _as_list(value: Any, name: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"rust_taint.yaml: {name!r} must be a list")
    return value


def _get(entry: Any, idx: int, field: str) -> Any:
    if not isinstance(entry, dict):
        raise ValueError(f"rust_taint.yaml entry[{idx}] must be a mapping")
    return entry.get(field)


@lru_cache(maxsize=1)
def load_rust_taint() -> RustTaintTables:
    """Return the bundled Rust trust vocabulary, immutable and cached once per process."""
    yaml = require_yaml("loading rust_taint.yaml")
    yaml_path = files("wardline.rust").joinpath("rust_taint.yaml")
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    return _build_tables(raw)
