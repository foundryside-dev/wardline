# src/wardline/scanner/taint/stdlib_taint.py
"""Loader for the bundled stdlib taint fallback table.

Curated ``(package, function) -> returned-value taint`` so common stdlib calls
do not inflate ``UNKNOWN_RAW`` rates. Consumed at call resolution (SP1c/SP1d),
not in L1 seeding. Source data + rationale live in ``stdlib_taint.yaml`` (same
package directory), loaded via ``importlib.resources``.
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

# Legal return tiers for a stdlib call. A stdlib function returns data the
# project did not produce, so INTEGRAL (your own fully-trusted data) is
# nonsensical here, and the unreachable trio {MIXED_RAW, UNKNOWN_GUARDED,
# UNKNOWN_ASSURED} must never enter the pipeline (see the reachable-set
# invariant in docs/concepts/taint-algebra.md and the taint-combination audit,
# F5). Constraining the parser to this set makes that invariant ENFORCED at the
# entry point rather than incidental.
_STDLIB_LEGAL_RETURN: frozenset[TaintState] = frozenset(
    {
        TaintState.ASSURED,
        TaintState.GUARDED,
        TaintState.EXTERNAL_RAW,
        TaintState.UNKNOWN_RAW,
    }
)

STDLIB_TAINT_VERSION: int = 1
"""Bumped when the table's shape or entries change materially; folded into the
SP1e summary cache key so changes invalidate dependent summaries."""


@dataclass(frozen=True)
class StdlibTaintEntry:
    """A single curated stdlib call's taint assumption."""

    taint: TaintState
    rationale: str


StdlibTaintTable = Mapping[tuple[str, str], StdlibTaintEntry]


def _build_table(raw: Any) -> StdlibTaintTable:
    """Validate parsed YAML into the immutable table.

    Separated from IO so the validation paths are unit-testable without a
    fixture file on disk.
    """
    if not isinstance(raw, dict) or raw.get("version") != STDLIB_TAINT_VERSION:
        got = raw.get("version") if isinstance(raw, dict) else raw
        raise ValueError(f"stdlib_taint.yaml version mismatch: expected {STDLIB_TAINT_VERSION}, got {got!r}")
    entries = raw.get("entries")
    if not isinstance(entries, list):
        raise ValueError("stdlib_taint.yaml: 'entries' must be a list")

    table: dict[tuple[str, str], StdlibTaintEntry] = {}
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"stdlib_taint.yaml entries[{idx}] must be a mapping")
        package = entry.get("package")
        function = entry.get("function")
        returns_taint_raw = entry.get("returns_taint")
        rationale = entry.get("rationale")
        if not isinstance(package, str) or not package:
            raise ValueError(f"stdlib_taint.yaml entries[{idx}].package must be a non-empty string")
        if not isinstance(function, str) or not function:
            raise ValueError(f"stdlib_taint.yaml entries[{idx}].function must be a non-empty string")
        if not isinstance(returns_taint_raw, str):
            raise ValueError(f"stdlib_taint.yaml entries[{idx}].returns_taint must be a string")
        try:
            taint = TaintState(returns_taint_raw)
        except ValueError as exc:
            raise ValueError(
                f"stdlib_taint.yaml entries[{idx}].returns_taint={returns_taint_raw!r} is not a canonical TaintState"
            ) from exc
        # Reject any state outside the stdlib-legal return set — both the
        # unreachable trio AND INTEGRAL (a stdlib call cannot produce your own
        # fully-trusted data). This keeps the reachable-set invariant enforced;
        # see docs/concepts/taint-algebra.md and the taint-combination audit (F5).
        if taint not in _STDLIB_LEGAL_RETURN:
            raise ValueError(
                f"stdlib_taint.yaml entries[{idx}].returns_taint={returns_taint_raw!r} "
                f"is not a legal stdlib return tier (allowed: "
                f"{sorted(s.value for s in _STDLIB_LEGAL_RETURN)}); states outside "
                f"this set would inject an otherwise-unreachable taint and break the "
                f"reachable-set invariant (see docs/concepts/taint-algebra.md, audit F5)"
            )
        # Every curated entry must justify itself — the table is meant to keep
        # UNKNOWN_RAW rates auditable, so a silent missing/empty rationale is a
        # curation defect, not a default.
        if not isinstance(rationale, str) or not rationale:
            raise ValueError(f"stdlib_taint.yaml entries[{idx}].rationale must be a non-empty string")
        key = (package, function)
        if key in table:
            raise ValueError(
                f"stdlib_taint.yaml entries[{idx}]: duplicate ({package!r}, {function!r}) — "
                f"a later entry would silently shadow an earlier one"
            )
        table[key] = StdlibTaintEntry(taint=taint, rationale=rationale)

    return MappingProxyType(table)


@lru_cache(maxsize=1)
def load_stdlib_taint() -> StdlibTaintTable:
    """Return the bundled ``(package, function) -> StdlibTaintEntry`` table.

    Immutable (``MappingProxyType``) and cached once per process.
    """
    yaml = require_yaml("loading stdlib_taint.yaml")
    yaml_path = files("wardline.scanner.taint").joinpath("stdlib_taint.yaml")
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    return _build_table(raw)


@lru_cache(maxsize=1)
def stdlib_taint_keys() -> frozenset[tuple[str, str]]:
    """Cached ``(package, function)`` key set over the table."""
    return frozenset(load_stdlib_taint().keys())
