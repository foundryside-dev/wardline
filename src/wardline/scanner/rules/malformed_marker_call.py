# src/wardline/scanner/rules/malformed_marker_call.py
"""PY-WL-130 — builtin trust marker called with a malformed argument shape.

A builtin marker call that violates its registered bare/called form, carries a
positional argument, an undeclared or duplicated keyword, an invalid literal
** key, an unreadable ** splat, or misses a required keyword is
silently UN-DECLARED by the engine: ``call_shape_offences`` drops the seed, the
function falls out of ``declared_qualnames``, and every tier-modulated rule
goes quiet (wardline-4928b75782). This rule makes the shape a loud ERROR
DEFECT, using the SAME validator seeding uses. The diagnostic is truthful per
offence: it claims a runtime ``TypeError`` only where the shipped signatures
prove one (``call_required``, ``undeclared_kwarg``, ``duplicate_kwarg``,
``missing_kwarg``, ``invalid_splat_key``). ``unreadable_splat`` says only that
Wardline cannot statically read the mapping; ``call_not_allowed`` and
``positional_args`` state a Wardline declaration-grammar rule, because
``@external_boundary(some_callable)`` and ``@trusted(audit_fn)`` are runtime-valid
calls that are nonetheless not declarations Wardline will honour.

Deliberately NOT silenced by the builtin-stays-quiet convention: that
convention preserves the byte-identity oracle, and a NEW rule id appears in no
frozen golden. Value problems are out of scope for THIS rule, and none of them
is silence (spec §4.2.1): a bare ``Name`` satisfying P3 form 5 RESOLVES and
seeds; a readable-but-invalid token is ``PY-WL-114``'s DEFECT and takes no FACT;
and a value that stays unreadable takes the ``WLN-ENGINE-UNREADABLE-MARKER-VALUE``
FACT (``Severity.NONE``, builtin-only), never silence. SHAPE is decided first, so
a marker that is both shape-malformed and value-unreadable is rejected on shape
before its value is a question: it takes this rule alone and never also that FACT
(the drop-coverage matrix pins the partition).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.registry import REGISTRY
from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES, BoundaryType
from wardline.scanner.marker_reader import (
    ModuleCensus,
    alias_map_for_qualname,
    call_shape_offences,
    is_builtin_decorator_fqn,
    resolve_decorator_fqn,
    shadowed_builtin_roots,
)

# The REQUIRED keyword set, IMPORTED rather than re-derived. PY-WL-114 already owns
# this derivation (``LevelArg.default is None`` == REQUIRED) and seeding derives it a
# second time inline in ``decorator_provider._match``; a THIRD independent derivation
# here is the drift hazard a prior review flagged on this exact file. The collapse is
# lossless: ``_REQUIRED_KWARGS`` is keyed by ``canonical_name`` across BOTH builtin
# roots, and ``boundary_types.BUILTIN_BOUNDARY_TYPES`` carries identical ``level_args``
# for each canonical name under ``wardline.decorators`` and ``weft_markers``, so
# ``_REQUIRED_KWARGS[bt.canonical_name]`` equals the per-``BoundaryType`` derivation
# for every builtin marker this rule can match.
from wardline.scanner.rules.invalid_decorator_level import _REQUIRED_KWARGS
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-130",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "A builtin trust marker (@external_boundary/@trust_boundary/@trusted) is "
        "used with an illegal call form, a positional argument, an undeclared "
        "or duplicated keyword, an invalid/unreadable ** splat, or without a "
        "required keyword; the engine "
        "silently drops the declaration, disabling every tier-modulated rule on "
        "the function."
    ),
    examples_violation=(
        "@trusted(level='INTEGRAL', audit=True)\ndef f(p):\n    return p",
        "@trusted('INTEGRAL')\ndef g(p):\n    return p",
        "@trusted(level='ASSURED', to_level='ASSURED')\ndef legacy(p):\n    return p",
        "@external_boundary(source='http')\ndef r(p):\n    return p",
        "@trust_boundary\ndef b(p):\n    if not p: raise ValueError\n    return p",
    ),
    examples_clean=(
        "@trusted(level='INTEGRAL')\ndef f(p):\n    return p",
        "@trusted\ndef g(p):\n    return p",
        "@trust_boundary(to_level='ASSURED')\ndef b(p):\n    if not p: raise ValueError\n    return p",
        # A foreign decorator merely spelled like a marker is not the builtin.
        "import other_pkg\n@other_pkg.trusted(level='X', extra=1)\ndef f2(p):\n    return p",
    ),
)


def _builtin_marker(
    deco: ast.expr,
    alias_map: Mapping[str, str],
    shadowed_roots: frozenset[str],
    *,
    census: ModuleCensus | None,
    reference_site: ast.stmt,
) -> BoundaryType | None:
    """The matched builtin BoundaryType iff *deco* resolves to a builtin marker
    seeding would honour (exact known export, root not shadowed)."""
    fqn = resolve_decorator_fqn(deco, alias_map, census=census, reference_site=reference_site)
    if fqn is None:
        return None
    for bt in BUILTIN_BOUNDARY_TYPES:
        if not bt.builtin:
            continue
        if bt.module_prefix.split(".")[0] in shadowed_roots:
            continue
        if is_builtin_decorator_fqn(fqn, bt.canonical_name, bt.module_prefix):
            return bt
    return None


class MalformedMarkerCall:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        shadowed = shadowed_builtin_roots(frozenset(context.alias_maps))
        for qualname, entity in context.entities.items():
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
            for deco_ordinal, deco in enumerate(entity.node.decorator_list):
                bt = _builtin_marker(
                    deco,
                    alias_map,
                    shadowed,
                    census=census,
                    reference_site=entity.node,
                )
                if bt is None:
                    continue
                entry = REGISTRY[bt.canonical_name]
                declared = entry.kwargs
                required = _REQUIRED_KWARGS[bt.canonical_name]
                offences = call_shape_offences(
                    deco,
                    call_form=entry.call_form,
                    declared=declared,
                    required=required,
                )
                for offence_ordinal, (offender, reason) in enumerate(offences):
                    # (predicate, clause). The clause is TRUTHFUL BY CONSTRUCTION: the
                    # runtime-invalid claim is asserted ONLY where a TypeError is proved
                    # from the shipped signatures in src/wardline/decorators/trust.py
                    # (each proved case verified at the REPL 2026-08-09). Plan Global
                    # Constraints + spec §4.2: "PY-WL-130 may call a shape runtime-invalid
                    # only for a proved runtime-invalid reason."
                    #
                    # NOT proved, and therefore NOT claimed:
                    #   call_not_allowed  — external_boundary(some_callable) is a VALID
                    #                       call (signature external_boundary(fn)); it is
                    #                       simply not a decorator-factory form.
                    #   positional_args   — trusted(audit_fn) is a VALID call (fn=None, /)
                    #                       and trusted(*()) binds zero arguments.
                    #   unreadable_splat  — trusted(**{'lev' + 'el': 'ASSURED'}) is VALID;
                    #                       Wardline just cannot read the mapping.
                    predicate, clause = {
                        "call_not_allowed": (
                            "is written as a call",
                            "; this marker has no decorator-factory form, so either the "
                            "call raises TypeError or the marker attaches to its argument "
                            "and this function is left with no _wardline_* attributes — "
                            "either way nothing is declared here. Write it bare",
                        ),
                        "call_required": (
                            "is written bare",
                            "; this call is invalid for the shipped runtime signature",
                        ),
                        "positional_args": (
                            "is called with a positional argument or ``*`` expansion",
                            "; a positional argument makes the marker attach to that "
                            "argument instead of to this function, leaving it with no "
                            "_wardline_* attributes (or raising TypeError if the argument "
                            "is not callable) — either way nothing is declared here. "
                            "Wardline's declaration grammar accepts keyword arguments "
                            "only (spec §4.2)",
                        ),
                        "undeclared_kwarg": (
                            f"is called with the undeclared keyword {offender!r}",
                            "; this call is invalid for the shipped runtime signature",
                        ),
                        "invalid_splat_key": (
                            "is called with a non-string constant ``**`` key",
                            "; this call is invalid for the shipped runtime signature",
                        ),
                        "unreadable_splat": (
                            "is called with a ``**`` mapping Wardline cannot statically read",
                            "; Wardline cannot statically prove this mapping satisfies the marker grammar",
                        ),
                        "duplicate_kwarg": (
                            f"is called with keyword {offender!r} more than once",
                            "; this call is invalid for the shipped runtime signature",
                        ),
                        "missing_kwarg": (
                            f"is called without a statically-readable required {offender!r} argument",
                            "; this call is invalid for the shipped runtime signature",
                        ),
                    }[reason]
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            message=(
                                f"{qualname}: builtin marker @{bt.canonical_name} "
                                f"{predicate} — the engine drops this declaration "
                                f"(no seed; every tier-modulated rule is disabled on "
                                f"this function){clause}"
                            ),
                            severity=self.base_severity,
                            kind=Kind.DEFECT,
                            location=entity.location,
                            fingerprint=_fp(
                                rule_id=self.rule_id,
                                path=entity.location.path,
                                qualname=qualname,
                                # PY-WL-114's move-stable ordinal discipline (wardline-377b896a87):
                                # within-def ordinals only; offence_ordinal splits co-located offences.
                                taint_path=f"{bt.canonical_name}:{offender}#{deco_ordinal}.{offence_ordinal}",
                            ),
                            taint_path_v0=f"{bt.canonical_name}:{offender}#{deco_ordinal}.{offence_ordinal}",
                            qualname=qualname,
                            properties={"decorator": bt.canonical_name, "offender": offender, "reason": reason},
                        )
                    )
        return findings
