# src/wardline/scanner/taint/function_level.py
"""L1 (function-level) taint seeding.

For each discovered function entity, ask the ``TaintSourceProvider`` for a
declared taint; when the provider has no opinion, fall back to ``UNKNOWN_RAW``
(fail-closed). That is the ENTIRE L1 precedence: ``provider > UNKNOWN_RAW``.

The stdlib taint table is a call-RETURN reference consumed downstream at call
resolution (SP1c/SP1d), NOT a function-body seeding input, so it is deliberately
absent here (matching ``.old``, whose ``function_level`` does not import it).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from wardline.core.taints import TaintState
from wardline.scanner.index import Entity
from wardline.scanner.taint.provider import SeedContext, TaintSourceProvider

_FALLBACK = TaintState.UNKNOWN_RAW


@dataclass(frozen=True, slots=True)
class FunctionSeed:
    """The L1 result for one function: its seeded body/return taint and the
    origin of that taint (``"provider"`` when declared, ``"default"`` when the
    provider was silent and the fail-closed fallback applied).

    ``unprovable_boundary`` carries the ``canonical_name`` of a matched-but-
    unprovable *custom* boundary type (Track 2 T2.4), which the analyzer turns into
    a ``WLN-ENGINE-UNPROVABLE-BOUNDARY`` FACT. ``None`` for builtins and for any
    function with no such match (the common case)."""

    qualname: str
    body_taint: TaintState
    return_taint: TaintState
    source: Literal["provider", "default"]
    unprovable_boundary: str | None = None


def seed_function_taints(
    entities: Sequence[Entity],
    *,
    ctx: SeedContext,
    provider: TaintSourceProvider,
) -> dict[str, FunctionSeed]:
    """Seed each entity's L1 taint, keyed by qualname.

    Entities are assumed already deduplicated by qualname (SP1a's
    ``discover_file_entities`` guarantees this); on any residual collision the
    last write wins, which is harmless because the seeds are identical inputs.
    """
    seeds: dict[str, FunctionSeed] = {}
    for entity in entities:
        res = provider.taint_for(entity, ctx)
        declared = res.taint
        if declared is None:
            seeds[entity.qualname] = FunctionSeed(
                qualname=entity.qualname,
                body_taint=_FALLBACK,
                return_taint=_FALLBACK,
                source="default",
                unprovable_boundary=res.unprovable_boundary,
            )
        else:
            seeds[entity.qualname] = FunctionSeed(
                qualname=entity.qualname,
                body_taint=declared.body_taint,
                return_taint=declared.return_taint,
                source="provider",
                unprovable_boundary=res.unprovable_boundary,
            )
    return seeds
