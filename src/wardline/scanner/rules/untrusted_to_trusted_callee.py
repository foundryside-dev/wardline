# src/wardline/scanner/rules/untrusted_to_trusted_callee.py
"""PY-WL-105 — untrusted data passed to a trusted callee at a call site.

The call-site analogue of PY-WL-101 (which polices the return site). When a function
passes PROVABLY-untrusted data (``EXTERNAL_RAW`` from a declared ``@external_boundary``
source, or ``MIXED_RAW``) as an argument to a trusted producer — a same-module entity
whose body operates on trusted data (``@trusted``-style, body tier NOT in the raw
zone) — untrusted data crosses into the trusted producer (CWE-501 trust-boundary
violation).

Declaration-gated on the CALLEE (base ERROR): the callee's trust declaration is the
opt-in, so the caller need not be anchored. FP-safe by construction:
  - fires only on **provably-untrusted** args (``EXTERNAL_RAW``/``MIXED_RAW``), NOT the
    merely-unprovable ``UNKNOWN_RAW`` freedom zone — passing unknown-trust data is not a
    proven violation, and firing on it would flood findings;
  - the callee must resolve to a **same-module** anchored entity with a trusted body
    (``@external_boundary`` / ``@trust_boundary`` callees are excluded — their body is
    raw, so raw input is expected); unresolved/cross-module callees are skipped;
  - argument-taint resolution is the conservative shared ``worst_arg_taint``.

Subsumption: distinct from PY-WL-101 (return anchor vs call-site anchor); a function
that *returns* such a call is 101, the *pass-in* is 105 even if the result is discarded.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TaintState
from wardline.scanner.rules._sink_helpers import (
    RAW_ZONE,
    _own_calls,
    call_site_var_taints,
    dotted_name,
    worst_arg_taint,
)
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

# PROVABLY untrusted (came through a declared boundary), NOT merely-unprovable UNKNOWN_RAW.
_PROVABLY_UNTRUSTED: frozenset[TaintState] = frozenset({TaintState.EXTERNAL_RAW, TaintState.MIXED_RAW})

METADATA = RuleMetadata(
    rule_id="PY-WL-105",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description="Untrusted data is passed as an argument to a trusted producer at a call site.",
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef store(x):\n    return 1\n"
        "def h(p):\n    store(read_raw(p))",
    ),
    examples_clean=("def h(p):\n    store(validate(read_raw(p)))",),
)


def _resolve_callee(call: ast.Call, module: str, context: AnalysisContext, *, caller_qualname: str = "") -> str | None:
    """The callee's entity qualname, resolved using call_site_callees or falling back to local heuristic."""
    # 1. Use the project-wide call site callee map if available
    callee = context.call_site_callees.get(id(call))
    if callee is not None and callee in context.entities:
        return callee

    # 2. Fall back to local same-module or self/cls heuristic
    if (
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in {"self", "cls"}
        and caller_qualname
    ):
        caller_entity = context.entities.get(caller_qualname)
        if caller_entity is not None and caller_entity.kind == "method":
            enclosing_class = caller_qualname.rsplit(".", 1)[0]
            candidate = f"{enclosing_class}.{call.func.attr}"
            if candidate in context.entities:
                return candidate

    dotted = dotted_name(call.func)
    if dotted is None:
        return None
    if "." not in dotted:
        candidate = f"{module}.{dotted}" if module else dotted
        return candidate if candidate in context.entities else None
    return dotted if dotted in context.entities else None


class UntrustedReachesTrustedCallee:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        from wardline.core.qualname import module_dotted_name

        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            module = module_dotted_name(entity.location.path) or ""
            site_taints = call_site_var_taints(entity.node, qualname, context)
            final = context.function_var_taints.get(qualname, {})
            for call in _own_calls(entity.node):
                callee = _resolve_callee(call, module, context, caller_qualname=qualname)
                if callee is None:
                    continue
                prov = context.taint_provenance.get(callee)
                if prov is None or prov.source != "anchored":
                    continue  # callee is not a trust-declared producer
                callee_body = context.project_taints.get(callee)
                if callee_body is None or callee_body in RAW_ZONE:
                    continue  # @external_boundary / @trust_boundary body is raw — raw input expected
                worst = worst_arg_taint(call, qualname, context, site_taints.get(id(call), final))
                if worst is None or worst not in _PROVABLY_UNTRUSTED:
                    continue
                line = call.lineno
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message=(
                            f"{qualname}: {worst.value} (untrusted) data passed to trusted producer "
                            f"{callee}() at line {line}"
                        ),
                        severity=self.base_severity,
                        kind=Kind.DEFECT,
                        location=Location(path=entity.location.path, line_start=line),
                        fingerprint=_fp(
                            rule_id=self.rule_id,
                            path=entity.location.path,
                            line_start=line,
                            qualname=qualname,
                            taint_path=f"{worst.value}->{callee}",
                        ),
                        qualname=qualname,
                        properties={"callee": callee, "arg_taint": worst.value, "callee_body": callee_body.value},
                    )
                )
        return findings
