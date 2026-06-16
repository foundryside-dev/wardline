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
from wardline.core.taints import TaintState
from wardline.scanner.grammar import BUILTIN_BOUNDARY_TYPES
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.taint.decorator_provider import _is_builtin_decorator_fqn, _shadowed_builtin_roots

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.scanner.context import AnalysisContext

_BOUNDARY_LEVELS = frozenset({TaintState.GUARDED, TaintState.ASSURED})
_TRUSTED_LEVELS = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})

# PY-WL-114 polices the LEVEL-bearing builtin markers only — ``trusted`` (``level=``)
# and ``trust_boundary`` (``to_level=``). Recognition uses the engine's OWN seeding
# predicate (``_is_builtin_decorator_fqn`` + shadowed-root fail-closed rejection), so
# the rule cannot recognise a marker the seeding rejects (wardline-09c09f14df).
_LEVEL_MARKER_NAMES: frozenset[str] = frozenset({"trusted", "trust_boundary"})

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
    ),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f(p):\n    return p",
        "@trust_boundary(to_level='ASSURED')\ndef g(p):\n    if not p: raise ValueError\n    return p",
        "@trusted(level=cfg.LEVEL)\ndef h(p):\n    return p",
        # A FOREIGN decorator that merely happens to be spelled ``trusted`` is not the builtin
        # marker, so an invalid level on it is not PY-WL-114's concern (no FP) (wardline-0267c31cd8).
        "import other_pkg\n@other_pkg.trusted(level='BOGUS')\ndef f(p):\n    return p",
    ),
)


def _dotted_name(node: ast.expr) -> str | None:
    """Reconstruct a dotted name (a.b.c) from a Name/Attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _level_token(value: ast.expr) -> str | None:
    """Extract a level token from a Constant string or an Attribute name."""
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.Attribute):
        base = _dotted_name(value.value)
        if base is not None and (base == "TaintState" or base.endswith(".TaintState")):
            return value.attr
    return None


def _resolve_decorator_fqn(deco: ast.expr, alias_map: Mapping[str, str]) -> str | None:
    """Resolve a decorator to its fully-qualified name through the module's import alias
    map (mirrors PY-WL-110's resolver), so ``@t`` from ``import trusted as t`` resolves to
    ``wardline.decorators.trusted``."""
    func = deco.func if isinstance(deco, ast.Call) else deco
    dotted = _dotted_name(func)
    if dotted is None:
        return None
    head, _, rest = dotted.partition(".")
    head_fqn = alias_map.get(head, head)
    return f"{head_fqn}.{rest}" if rest else head_fqn


def _builtin_level_marker(deco: ast.expr, alias_map: Mapping[str, str], shadowed_roots: frozenset[str]) -> str | None:
    """The canonical builtin marker name (``trusted`` / ``trust_boundary``) iff *deco*
    resolves to a builtin level-bearing trust decorator THE ENGINE'S SEEDING WOULD HONOUR.
    Gating on the resolved FQN (not the trailing identifier) fixes both the alias-blind FN —
    ``@t(level=...)`` where ``t`` aliases the builtin — and the foreign-name FP — a
    non-wardline / locally-defined decorator that merely happens to be spelled ``trusted``
    (wardline-0267c31cd8). Matching uses the seeding predicate itself: only the exact
    exports ``P.<name>`` / ``P.trust.<name>`` count (an arbitrarily-nested path like
    ``wardline.decorators.evil.trusted`` is seeded by NEITHER, so a bad level on it never
    disabled any gate), and a marker whose root the scanned project shadows is rejected
    fail-closed exactly as the provider rejects it. PY-WL-110 sidesteps shadows via its
    anchored-provenance gate; this rule fires precisely where seeding FAILED, so it must
    thread the shadow set explicitly."""
    fqn = _resolve_decorator_fqn(deco, alias_map)
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


class InvalidDecoratorLevel:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        modules = list(context.alias_maps.keys())
        # The scanned project's modules are the alias-map keys; the same shadow
        # computation the provider runs (a project-local top-level ``wardline`` /
        # ``weft_markers`` rejects every builtin marker under that root).
        shadowed_roots = _shadowed_builtin_roots(frozenset(modules))
        for qualname, entity in context.entities.items():
            # The alias map for the module that owns this entity — needed to resolve an
            # aliased builtin decorator to its FQN (mirrors PY-WL-110).
            mod_name = next(
                (m for m in sorted(modules, key=len, reverse=True) if qualname == m or qualname.startswith(m + ".")),
                None,
            )
            alias_map = (context.alias_maps.get(mod_name) if mod_name is not None else None) or {}
            for deco_ordinal, deco in enumerate(entity.node.decorator_list):
                name = _builtin_level_marker(deco, alias_map, shadowed_roots)
                if name is None:
                    continue

                if not isinstance(deco, ast.Call):
                    continue

                # For trusted, check keyword 'level'
                # For trust_boundary, check keyword 'to_level'
                target_kw = "level" if name == "trusted" else "to_level"
                allowed_set = _TRUSTED_LEVELS if name == "trusted" else _BOUNDARY_LEVELS

                for kw in deco.keywords:
                    if kw.arg != target_kw:
                        continue

                    token = _level_token(kw.value)
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
