"""Acceptance fixture (Track 2 DoD): an agent defines a NEW boundary type + a NEW
rule entirely OUTSIDE ``src/wardline`` and registers them on the grammar.

This is the litmus artifact: making this fire requires ZERO edits to
``decorator_provider._match``, ``rules/__init__._ALL_RULE_CLASSES``, and
``core/registry._ENTRIES`` — only new files here. If that ever stops being true,
the grammar has regressed from open to closed.

- ``SANITIZED`` — a custom trusted-producer boundary ``@myproj.trust.sanitized(to_level=...)``
  in the agent's OWN module namespace (not ``wardline.decorators``). Shaped like
  ``@trusted`` (body == return == declared tier), so its actual return is policed
  against its declaration.
- ``SanitizerReturnsRaw`` (``MYPROJ-001``) — a NEW rule: a ``@sanitized`` producer
  must never actually return RAW data. Reads only the resolved taint state (the
  preserved layering), exactly as the builtin rules do.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.grammar import BoundaryType, LevelArg, default_grammar
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.taint.provider import FunctionTaint

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

# A custom boundary type in the agent's own module namespace.
SANITIZED = BoundaryType(
    canonical_name="sanitized",
    module_prefix="myproj.trust",
    group=1,
    level_args=(LevelArg("to_level", frozenset({TaintState.GUARDED, TaintState.ASSURED}), default=None),),
    # Trusted-producer shape: body == return == declared tier (policed by the rule).
    seed=lambda levels: FunctionTaint(levels["to_level"], levels["to_level"]),
    builtin=False,
)

_RAW = frozenset({TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW})

_METADATA = RuleMetadata(
    rule_id="MYPROJ-001",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description="A @sanitized producer must never actually return raw (untrusted) data.",
)


class SanitizerReturnsRaw:
    """MYPROJ-001 — a ``@sanitized`` producer whose actual return is raw."""

    rule_id = _METADATA.rule_id
    metadata = _METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or _METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            prov = context.taint_provenance.get(qualname)
            if prov is None or prov.source != "anchored":
                continue
            declared = context.project_return_taints.get(qualname)
            actual = context.function_return_taints.get(qualname)
            if declared is None or declared in _RAW or actual is None:
                continue
            # Policing PRODUCERS only (body == declared). A trust-RAISING transition
            # (a @trust_boundary validator: body less trusted than its declared
            # return) is a different shape — its L2 actual return is the raw body by
            # construction, so it would always trip this check. Exclude it, exactly as
            # the builtin PY-WL-101 does, so MYPROJ-001 polices @sanitized producers.
            body = context.project_taints.get(qualname)
            if body is not None and TRUST_RANK[body] > TRUST_RANK[declared]:
                continue
            if actual not in _RAW:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=f"{qualname}: sanitizer returns raw data ({actual.value}), declared {declared.value}",
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        qualname=qualname,
                        taint_path=f"{actual.value}->{declared.value}",
                    ),
                    qualname=qualname,
                    properties={"declared_return": declared.value, "actual_return": actual.value},
                )
            )
        return findings


# The agent's grammar = builtins + the custom boundary type and rule.
GRAMMAR = default_grammar().extend(boundary_types=(SANITIZED,), rules=(SanitizerReturnsRaw,))
