# src/wardline/scanner/grammar.py
"""The extensible trust grammar (Track 2).

Generalizes Wardline's three hardcoded trust decorators and four hardcoded rules
into one open meta-model an agent can extend WITHOUT editing engine source, while
the builtin vocabulary keeps producing byte-identical findings.

Layering (preserved, load-bearing): a :class:`BoundaryType` feeds L1 seeding
(declaration -> taint); rules read the RESOLVED taint state, not the decorator. The
grammar registers both; it does not couple them per-instance. (See the design spec
§2 for why tighter coupling is rejected.)

Zero-dep: no new third-party, runtime, or config dependency — the extension plane
is a *code* seam, the same shape as ``TaintSourceProvider``. The boundary primitives
(``BoundaryType``/``LevelArg``/``BUILTIN_BOUNDARY_TYPES`` and their
``core.taints``/``core.registry``/``FunctionTaint`` deps) live one module down in
:mod:`wardline.scanner.boundary_types` and are re-exported here; this module's own
direct imports are now just stdlib + that primitive module.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

# The boundary primitives live one module down (engine floor) so the rules and the
# decorator provider can import them without reaching back up into this module — that
# separation is what keeps the scanner import graph acyclic. They are re-exported here
# so ``grammar`` stays the single facade for the full vocabulary.
from wardline.scanner.boundary_types import (
    BUILTIN_BOUNDARY_TYPES,
    BoundaryType,
    LevelArg,
)

if TYPE_CHECKING:
    # Annotation-only (lazy under `from __future__ import annotations`); kept out of
    # the runtime import surface so the zero-dep contract above stays literally true.
    from wardline.core.finding import Finding
    from wardline.scanner.context import _RuleClass

__all__ = [
    "BUILTIN_BOUNDARY_TYPES",
    "BoundaryType",
    "LevelArg",
    "TrustGrammar",
    "build_sanitiser_collision_findings",
    "default_grammar",
]


@dataclass(frozen=True, slots=True)
class TrustGrammar:
    """The wiring object: boundary types (feed L1 seeding) + rule classes (enforcement).

    ``rules`` are rule CLASSES (not instances) — they are instantiated per-config
    downstream so ``weft.toml [wardline]`` severity overrides still apply.
    """

    boundary_types: tuple[BoundaryType, ...]
    rules: tuple[_RuleClass, ...]

    def extend(
        self,
        *,
        boundary_types: tuple[BoundaryType, ...] = (),
        rules: tuple[_RuleClass, ...] = (),
    ) -> TrustGrammar:
        """Append agent-defined types/rules to the defaults (append, never replace).

        Builtins are preloaded defaults (program spec T2.2); extensions are added
        after them, preserving builtin order and behavior.
        """
        return TrustGrammar(
            self.boundary_types + tuple(boundary_types),
            self.rules + tuple(rules),
        )


def build_sanitiser_collision_findings(sanitisers: Iterable[str]) -> list[Finding]:
    """WLN-CONFIG-* diagnostic: configured sanitisers shadowed by a serialisation sink.

    A config sanitiser whose dotted name IS a built-in serialisation sink (e.g.
    ``json.loads``) can never take effect: the sink override is inserted into the
    call-taint map before the config pass (which uses ``setdefault``), and
    ``_resolve_call`` consults the sink set ahead of the taint map. Yet the
    sanitiser still generates map keys and so counts as "matched", which
    suppresses ``WLN-CONFIG-UNUSED-SANITISER`` — the declaration becomes a silent
    no-op. This emits one ``WLN-CONFIG-SANITISER-SINK-COLLISION`` FACT per
    colliding sanitiser (sorted, deterministic), naming the collision so the user
    learns their suppression attempt was overridden, not honoured.

    Pure function of the config value (no scan state); the analyzer appends the
    result alongside the other ``WLN-CONFIG-*`` diagnostics.
    """
    # Local imports: keep this module's runtime import surface exactly the grammar
    # meta-model (same pattern as default_grammar's rules import).
    from wardline.core.finding import Finding, Kind, Location, Severity, compute_finding_fingerprint
    from wardline.scanner.taint.variable_level import _SERIALISATION_SINKS

    findings: list[Finding] = []
    for san in sorted(set(sanitisers) & _SERIALISATION_SINKS):
        findings.append(
            Finding(
                rule_id="WLN-CONFIG-SANITISER-SINK-COLLISION",
                message=(
                    f"Configuration error: sanitiser '{san}' collides with the built-in "
                    "serialisation sink of the same name; the conservative sink "
                    "classification (UNKNOWN_RAW) takes precedence, so this sanitiser "
                    "declaration has no effect"
                ),
                severity=Severity.NONE,
                kind=Kind.FACT,
                location=Location(path="weft.toml"),
                fingerprint=compute_finding_fingerprint(
                    rule_id="WLN-CONFIG-SANITISER-SINK-COLLISION",
                    path="weft.toml",
                    taint_path=san,
                ),
                properties={"sanitiser": san},
            )
        )
    return findings


def default_grammar() -> TrustGrammar:
    """The builtin grammar: the 3 boundary types + the 4 rule classes, in today's
    exact order. The byte-identity oracle (design spec §5) pins this == today."""
    # Lazy import: keeps this module's runtime import surface the grammar meta-model
    # (same intent as build_sanitiser_collision_findings above), so merely importing
    # ``grammar`` does not eagerly pull in all ~27 rule classes. This is NOT a cycle
    # breaker any more — wardline-a0eaa7dd12 moved the boundary primitives to
    # ``scanner.boundary_types``, so the rule modules no longer import ``grammar`` and
    # ``grammar -> rules`` is a one-way edge (proven acyclic by
    # tests/conformance/test_import_layering.py).
    from wardline.scanner.rules import BUILTIN_RULE_CLASSES

    return TrustGrammar(BUILTIN_BOUNDARY_TYPES, BUILTIN_RULE_CLASSES)
