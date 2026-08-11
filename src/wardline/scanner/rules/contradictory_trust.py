# src/wardline/scanner/rules/contradictory_trust.py
"""PY-WL-110 — contradictory / ambiguous trust declaration.

Fires on an anchored entity whose decorator list carries **two or more distinct**
grammar trust markers (e.g. ``@trusted`` + ``@external_boundary``, or ``@trusted`` +
``@trust_boundary``). Such a stack is self-contradictory: one marker claims the
function produces trusted data, another claims it is a raw source or a validator —
the engine silently resolves the clash to the least-trusted seed, so the more-trusted
claim is quietly ignored. Flagging it surfaces the ambiguity rather than letting a
silent resolution hide intent.

Declaration-gated (base severity, NOT tier-modulated). It reads RESOLVED provenance
for the gate (``prov.source == "anchored"``) and only COUNTS markers in the decorator
list that pass the provider's shared call-shape gate — it never infers taint from a
decorator, so the engine-layering discipline holds. Distinctness is by the grammar
boundary type's canonical name; two ``@trusted`` markers are not contradictory.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.registry import REGISTRY
from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES
from wardline.scanner.marker_reader import (
    ModuleCensus,
    alias_map_for_qualname,
    call_shape_offences,
    shadowed_builtin_roots,
)
from wardline.scanner.marker_reader import is_builtin_decorator_fqn as _is_builtin_decorator_fqn
from wardline.scanner.marker_reader import resolve_decorator_fqn as _resolve_decorator_fqn
from wardline.scanner.rules._fingerprint import entity_source_fingerprint
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

# A marker is recognised using the EXACT same predicate the engine's seeding uses
# (``marker_reader.is_builtin_decorator_fqn``), whose accepted-export table is
# ROOT-SPECIFIC: ``wardline.decorators.<name>`` and its real implementation-module
# export ``wardline.decorators.trust.<name>``, and a DIRECT ``weft_markers.<name>``
# only — there is no ``weft_markers.trust`` submodule, so that path is a ghost export
# neither seeding nor this rule may honour. The rule MUST NOT recognise a marker the engine's seeding
# rejects, or it counts a "clash" the engine never actually resolved — an arbitrarily-
# nested path like ``wardline.decorators.sub.external_boundary`` is seeded by NEITHER,
# so it must not be counted here either (wardline-09c09f14df). Keying off the shared
# seeding predicate (not a looser names+prefix heuristic) is how the rule cannot drift
# from the grammar, and recognises both ``wardline.decorators`` and the renamed
# ``weft_markers`` shim (wardline-d62845bb18).

METADATA = RuleMetadata(
    rule_id="PY-WL-110",
    base_severity=Severity.WARN,  # declaration hygiene, not a proven taint exploit (promote via weft.toml [wardline])
    kind=Kind.DEFECT,
    description=(
        "An entity carries two or more distinct trust markers (e.g. @trusted + "
        "@external_boundary) — a contradictory declaration the engine resolves silently."
    ),
    examples_violation=("@trusted\n@external_boundary\ndef f(p):\n    return p",),
    examples_clean=("@trust_boundary(to_level='ASSURED')\ndef f(p):\n    if not p: raise ValueError\n    return p",),
)


def _marker_canonical_name(
    deco: ast.expr,
    alias_map: Mapping[str, str],
    shadowed_roots: frozenset[str],
    *,
    census: ModuleCensus | None,
    reference_site: ast.stmt,
) -> str | None:
    """The canonical builtin marker name *deco* resolves to, or None.

    Recognition rides the SHARED engine-floor predicates and call-shape validator
    (P9), so this rule cannot recognise a marker the provider's seeding rejects. The
    shadow filter is applied PER MARKER ROOT, never as a global "any shadow disables
    all roots" switch: a scanned project defining its own top-level ``wardline``
    package must not suppress a genuine ``weft_markers`` marker, and vice versa
    (mirrors the provider's own per-root rejection in
    ``DecoratorTaintSourceProvider._match``).
    """
    fqn = _resolve_decorator_fqn(deco, alias_map, census=census, reference_site=reference_site)
    if fqn is None:
        return None
    for bt in BUILTIN_BOUNDARY_TYPES:
        if not bt.builtin:
            continue
        if bt.module_prefix.split(".")[0] in shadowed_roots:
            continue
        if _is_builtin_decorator_fqn(fqn, bt.canonical_name, bt.module_prefix):
            entry = REGISTRY[bt.canonical_name]
            required = frozenset(level.arg_name for level in bt.level_args if level.default is None)
            if call_shape_offences(
                deco,
                call_form=entry.call_form,
                declared=entry.kwargs,
                required=required,
            ):
                return None
            return bt.canonical_name
    return None


class ContradictoryTrust:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        # The scanned project's modules are the alias-map keys — the same input the
        # provider's shadow computation takes. PER-ROOT (see ``_marker_canonical_name``).
        shadowed_roots = shadowed_builtin_roots(frozenset(context.alias_maps))
        for qualname, entity in context.entities.items():
            prov = context.taint_provenance.get(qualname)
            if prov is None or prov.source != "anchored":
                continue  # opt-in: only where the engine confirmed a real trust marker

            # The alias map of the LONGEST module prefix that owns this entity — the one
            # shared lookup PY-WL-110/PY-WL-114/PY-WL-130 all use (engine floor, P9).
            alias_map = alias_map_for_qualname(qualname, context.alias_maps)
            module = next(
                (
                    name
                    for name in sorted(context.module_censuses, key=len, reverse=True)
                    if qualname == name or qualname.startswith(name + ".")
                ),
                None,
            )
            census = context.module_censuses.get(module) if module is not None else None

            markers = set()
            for deco in entity.node.decorator_list:
                name = _marker_canonical_name(
                    deco,
                    alias_map,
                    shadowed_roots,
                    census=census,
                    reference_site=entity.node,
                )
                if name is not None:
                    markers.add(name)

            if len(markers) < 2:
                continue
            markers_label = "+".join(sorted(markers))
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} carries contradictory trust markers ({markers_label}); the engine "
                        f"resolves the clash to the least-trusted seed, silently ignoring the rest"
                    ),
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        qualname=qualname,
                        # Line-independent source-body discriminator: one finding per anchored
                        # qualname, but a different same-qualname entity body must not inherit
                        # an old suppression.
                        taint_path=entity_source_fingerprint(entity.node),
                    ),
                    qualname=qualname,
                    properties={"markers": markers_label},
                )
            )
        return findings
