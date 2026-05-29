# src/wardline/scanner/taint/provider.py
"""The pluggable taint-source seam consumed by L1 function seeding.

A ``TaintSourceProvider`` answers one question: what taint did the author
*declare* for this function (via decorators, annotations, or config)? SP1 ships
only the trivial ``DefaultTaintSourceProvider`` (no opinion on anything, so
callers fall back to ``UNKNOWN_RAW``). SP2 supplies the real
decorator-vocabulary provider via the rule registry.

The seam is intentionally extensible: SP2 may add fields to ``SeedContext`` and
``FunctionTaint`` without reshaping ``taint_for``. ``SeedContext`` is kept
minimal here (module name only) — fields like an import-alias map are added when
a provider actually consumes them, not speculatively.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from wardline.core.taints import TaintState
from wardline.scanner.index import Entity


@dataclass(frozen=True, slots=True)
class SeedContext:
    """Per-file context handed to a provider for each entity in that file."""

    module: str


@dataclass(frozen=True, slots=True)
class FunctionTaint:
    """A provider's declared taint for one function: the taint observed INSIDE
    the body (input tier) and the taint of its return value (output tier)."""

    body_taint: TaintState
    return_taint: TaintState


@runtime_checkable
class TaintSourceProvider(Protocol):
    """Maps a function entity to its declared taint, or ``None`` for 'no opinion'."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> FunctionTaint | None: ...


class DefaultTaintSourceProvider:
    """The trivial provider: declares nothing. With no decorator vocabulary in
    SP1, every function falls back to ``UNKNOWN_RAW`` (fail-closed)."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> FunctionTaint | None:
        return None
