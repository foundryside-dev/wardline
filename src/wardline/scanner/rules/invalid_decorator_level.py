# src/wardline/scanner/rules/invalid_decorator_level.py
"""PY-WL-114 — builtin trust decorator whose level is statically readable but invalid or out-of-range.

Fires on any entity carrying a builtin trust decorator (@trusted or @trust_boundary)
where the level argument is statically readable but not a valid TaintState or not within
the decorator's allowed set. This is a critical safety defect: a typo (e.g. 'ASURED')
causes the engine to silently drop the decorator, disabling all taint gates on that function.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.registry import REGISTRY
from wardline.core.taints import TaintState
from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES

# ``ModuleCensus`` is imported only for typing: ``check`` reads the REAL per-module
# census off ``context.module_censuses`` and never constructs one here.
# ``alias_map_for_qualname`` likewise dropped — see ``_owning_module`` below, which
# performs the ONE longest-owning-module resolution that serves both the alias map and
# the census, so the two keys cannot drift. Each ``as``-aliased name gets its own
# statement because ruff runs with the default ``combine-as-imports = false``.
from wardline.scanner.marker_reader import call_shape_offences, extract_keywords
from wardline.scanner.marker_reader import is_builtin_decorator_fqn as _is_builtin_decorator_fqn
from wardline.scanner.marker_reader import level_token as _level_token
from wardline.scanner.marker_reader import resolve_decorator_fqn as _resolve_decorator_fqn
from wardline.scanner.marker_reader import shadowed_builtin_roots as _shadowed_builtin_roots
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from wardline.scanner.context import AnalysisContext
    from wardline.scanner.marker_reader import ModuleCensus

_BOUNDARY_LEVELS = frozenset({TaintState.GUARDED, TaintState.ASSURED})
_TRUSTED_LEVELS = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})

# PY-WL-114 polices the LEVEL-bearing builtin markers only — ``trusted`` (``level=``)
# and ``trust_boundary`` (``to_level=``). Recognition uses the engine's OWN seeding
# predicate (``_is_builtin_decorator_fqn`` + shadowed-root fail-closed rejection), so
# the rule cannot recognise a marker the seeding rejects (wardline-09c09f14df).
_LEVEL_MARKER_NAMES: frozenset[str] = frozenset({"trusted", "trust_boundary"})

# The REQUIRED keyword set per builtin marker, for the registry-owned shape gate.
# ``call_form`` and the DECLARED keyword set come from ``REGISTRY`` (the declaration
# contract); required-ness is not a ``RegistryEntry`` field and must not become one
# (``REGISTRY_VERSION`` is pinned and the vocabulary descriptor golden keys off it), so
# it is derived from the grammar's own ``LevelArg.default is None`` convention — the
# same "default=None means REQUIRED" rule the provider seeds on. Both builtin roots
# carry identical rows for each canonical name, so the collapse is lossless.
_REQUIRED_KWARGS: dict[str, frozenset[str]] = {
    bt.canonical_name: frozenset(la.arg_name for la in bt.level_args if la.default is None)
    for bt in BUILTIN_BOUNDARY_TYPES
    if bt.builtin
}

METADATA = RuleMetadata(
    rule_id="PY-WL-114",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "A builtin trust decorator (@trusted or @trust_boundary) has a level argument "
        "that is statically readable but invalid or out-of-range."
    ),
    examples_violation=(
        "@trusted(level='ASURED')\ndef f(p):\n    return p",
        "@trust_boundary(to_level='INTEGRAL')\ndef g(p):\n    if not p: raise ValueError\n    return p",
        # An ALIASED builtin decorator with a typo'd level must still fire (the alias resolves
        # to the builtin FQN) — otherwise the typo silently disables the gate (wardline-0267c31cd8).
        "from wardline.decorators import trusted as t\n@t(level='ASURED')\ndef f(p):\n    return p",
        # An aliased genuine TaintState with a typo: the provider reads it (alias-
        # resolved) and drops the seed, so the rule must fire (shared reader, P9).
        "from wardline.core.taints import TaintState as T\n@trusted(level=T.ASURED)\ndef f(p):\n    return p",
    ),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f(p):\n    return p",
        "@trust_boundary(to_level='ASSURED')\ndef g(p):\n    if not p: raise ValueError\n    return p",
        # NOTE: ``@trusted(level=cfg.LEVEL)`` was DELETED from this tuple, not re-annotated.
        # ``cfg.LEVEL`` is a dotted Attribute held out of P3 form 5 by design, so under
        # design spec rev 6 it is an UNREADABLE builtin LEVEL value that takes the
        # ``WLN-ENGINE-UNREADABLE-MARKER-VALUE`` FACT. A ``Severity.NONE`` FACT does not
        # convert a fail-open construct into a legitimate CLEAN exemplar, and a shipped
        # exemplar teaching that an unreadable level value is exemplary is exactly the
        # trap this program removed one rule over. Do not re-add it, and do not add a
        # ``myconfig.TaintState.ASURED`` sibling either: its receiver does not
        # alias-resolve to the exact known export, so it is likewise unreadable. The
        # foreign-receiver SILENCE property is pinned as a unit assertion in
        # tests/unit/scanner/rules/test_invalid_decorator_level.py instead.
        # A FOREIGN decorator that merely happens to be spelled ``trusted`` is not the builtin
        # marker, so an invalid level on it is not PY-WL-114's concern (no FP) (wardline-0267c31cd8).
        "import other_pkg\n@other_pkg.trusted(level='BOGUS')\ndef f(p):\n    return p",
    ),
)


def _builtin_level_marker(
    deco: ast.expr,
    alias_map: Mapping[str, str],
    shadowed_roots: frozenset[str],
    *,
    census: ModuleCensus | None,
    reference_site: ast.stmt,
) -> str | None:
    """The canonical builtin marker name (``trusted`` / ``trust_boundary``) iff *deco*
    resolves to a builtin level-bearing trust decorator THE ENGINE'S SEEDING WOULD HONOUR.
    Gating on the resolved FQN (not the trailing identifier) fixes both the alias-blind FN —
    ``@t(level=...)`` where ``t`` aliases the builtin — and the foreign-name FP — a
    non-wardline / locally-defined decorator that merely happens to be spelled ``trusted``
    (wardline-0267c31cd8). Matching uses the seeding predicate itself, whose accepted-export
    table is ROOT-SPECIFIC: ``wardline.decorators.<name>`` plus its real implementation-module
    export ``wardline.decorators.trust.<name>``, and a DIRECT ``weft_markers.<name>`` only
    (there is no ``weft_markers.trust`` submodule, so that path is a ghost export). An
    arbitrarily-nested path like ``wardline.decorators.evil.trusted`` is seeded by NEITHER,
    so a bad level on it never disabled any gate; and a marker whose root the scanned project shadows is rejected
    fail-closed exactly as the provider rejects it. PY-WL-110 sidesteps shadows via its
    anchored-provenance gate; this rule fires precisely where seeding FAILED, so it must
    thread the shadow set explicitly."""
    fqn = _resolve_decorator_fqn(deco, alias_map, census=census, reference_site=reference_site)
    if fqn is None:
        return None
    for bt in BUILTIN_BOUNDARY_TYPES:
        if not bt.builtin or bt.canonical_name not in _LEVEL_MARKER_NAMES:
            continue
        if bt.module_prefix.split(".")[0] in shadowed_roots:
            continue
        if _is_builtin_decorator_fqn(fqn, bt.canonical_name, bt.module_prefix):
            return bt.canonical_name
    return None


def _owning_module(qualname: str, modules: Iterable[str]) -> str | None:
    """The LONGEST module prefix that owns *qualname*, or None.

    The SINGLE resolution behind both of ``check``'s per-entity module lookups —
    the alias map and the form-5 census — because a naive ``qualname.rsplit('.', 1)``
    yields ``svc.C`` for the method ``svc.C.method``, which is a MISS in
    ``context.module_censuses``; a miss is the absent sentinel, so the shared reader
    would RAISE (``WLN-ENGINE-RULE-FAILED``) on legitimate code where correct keying
    gives census-present -> ineligible reference site -> ``None`` -> unreadable. That
    is fail-loud-and-wrong on precisely the method shape spec §4.2.1 refuses.

    Identical resolution to ``marker_reader.alias_map_for_qualname``'s, which is the
    engine floor's shipped answer for ``alias_maps``; it is spelled here because that
    helper returns the MAP, not the KEY, and the census lookup needs the key. Deriving
    both from this one call is what makes the two impossible to drift apart.
    """
    return next(
        (
            name
            for name in sorted(modules, key=len, reverse=True)
            if qualname == name or qualname.startswith(name + ".")
        ),
        None,
    )


class InvalidDecoratorLevel:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        # The scanned project's modules are the alias-map keys; the same shadow
        # computation the provider runs (a project-local top-level ``wardline`` /
        # ``weft_markers`` rejects every builtin marker under that root).
        shadowed_roots = _shadowed_builtin_roots(frozenset(context.alias_maps))
        for qualname, entity in context.entities.items():
            # The LONGEST module prefix that owns this entity, resolved ONCE and used for
            # BOTH module-keyed lookups below — the alias map (needed to resolve an aliased
            # builtin decorator to its FQN) and the form-5 census. ``AnalysisContext``
            # keys both mappings the same way, so one resolution serving both is what
            # stops the two keys drifting apart.
            mod_name = _owning_module(qualname, context.alias_maps)
            alias_map = context.alias_maps.get(mod_name, {}) if mod_name is not None else {}
            # The REAL per-module census, replacing the inert one this rule used to
            # construct inline: PY-WL-114 stops being form-5-blind here. A MISS yields
            # ``None`` — the ABSENT sentinel — and the shared reader raises on it, which
            # is the loud plumbing-defect channel, never a quiet unreadable.
            census = context.module_censuses.get(mod_name) if mod_name is not None else None
            for deco_ordinal, deco in enumerate(entity.node.decorator_list):
                name = _builtin_level_marker(
                    deco,
                    alias_map,
                    shadowed_roots,
                    census=census,
                    reference_site=entity.node,
                )
                if name is None:
                    continue

                # SHAPE IS DECIDED FIRST AND SHORT-CIRCUITS (design spec rev 6 §4.2.1).
                # The registry owns the call form and the declared keyword set; a marker
                # whose CALL SHAPE is malformed drops its seed at the shape gate and its
                # LEVEL value is never read, so PY-WL-114 must go silent on it rather than
                # claim to have read a value the engine did not. Running this BEFORE the
                # value loop is also what keeps at most ONE finding per decorator: a
                # literal splat can supply a second ``level=``/``to_level=`` item, and two
                # findings on one decorator would share ``deco_ordinal`` and therefore
                # collide on the fingerprint. ``duplicate_kwarg`` silences that here.
                entry = REGISTRY[name]
                if call_shape_offences(
                    deco,
                    call_form=entry.call_form,
                    declared=entry.kwargs,
                    required=_REQUIRED_KWARGS[name],
                ):
                    continue

                # For trusted, check keyword 'level'
                # For trust_boundary, check keyword 'to_level'
                target_kw = "level" if name == "trusted" else "to_level"
                allowed_set = _TRUSTED_LEVELS if name == "trusted" else _BOUNDARY_LEVELS

                for kw_name, kw_value in extract_keywords(deco).items:
                    if kw_name != target_kw:
                        continue

                    token = _level_token(
                        kw_value,
                        alias_map,
                        # The module's REAL census, built once in the parse loop and only
                        # GATHERED onto the context — the rule side holds neither the
                        # module AST nor the star-export map and therefore cannot build
                        # one, which is exactly the pressure that keeps form 5 to a single
                        # evaluation point. ``None`` here is the ABSENT sentinel, not an
                        # empty census, and the reader raises on it.
                        census=census,
                        # This rule already iterates ``entity.node.decorator_list``, so it
                        # holds the decorated statement and can PRESENT a reference site
                        # even though it cannot CLASSIFY one.
                        reference_site=entity.node,
                        shadowed_roots=shadowed_roots,
                        # PY-WL-114 polices builtin level-bearing markers only.
                        builtin=True,
                    )
                    if token is None:
                        continue  # not statically readable (e.g. dynamic variable)

                    is_invalid = False
                    try:
                        level = TaintState(token)
                        if level not in allowed_set:
                            is_invalid = True
                    except ValueError:
                        is_invalid = True

                    if is_invalid:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                message=(
                                    f"{qualname} has an invalid or out-of-range trust level "
                                    f"{token!r} on decorator @{name}"
                                ),
                                severity=self.base_severity,
                                kind=Kind.DEFECT,
                                location=entity.location,
                                fingerprint=_fp(
                                    rule_id=self.rule_id,
                                    path=entity.location.path,
                                    qualname=qualname,
                                    # Join-key collision (wardline-377b896a87): this rule emits >1
                                    # finding per (rule, path, qualname) — one per invalid decorator on a
                                    # def. With ``line_start`` no longer hashed (wlfp2), the decorator's
                                    # position must come ENTIRELY from the discriminator. Two STACKED
                                    # IDENTICAL decorators share name AND token, so the only thing that
                                    # tells them apart is their
                                    # POSITION in the def's decorator_list. The load-bearing
                                    # discriminator is that ORDINAL (``#<i>``): a within-def index that
                                    # is move-stable (invariant to the def moving vertically AND to
                                    # column shifts — unlike an absolute line/column span) and
                                    # collision-complete (at most one finding per decorator; a repeated
                                    # ``level=``/``to_level=`` kwarg is a SyntaxError, so the inner
                                    # kw-loop yields <=1 match per decorator). ``{name}:{token}`` is
                                    # retained as informative source text only. Source-only (no resolved
                                    # tier), honouring the §8 invariant (weft-4a9d0f863c). Forward-
                                    # compatible with a future relative-span discriminator.
                                    taint_path=f"{name}:{token}#{deco_ordinal}",
                                ),
                                # OLD (wlfp1) taint_path == NEW (P3 unchanged) but ephemeral — recompute for rekey (P4).
                                taint_path_v0=f"{name}:{token}#{deco_ordinal}",
                                qualname=qualname,
                                properties={"decorator": name, "token": token},
                            )
                        )
        return findings
