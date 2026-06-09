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
  - argument-taint resolution fires when **any** resolved arg is provably untrusted,
    not the single ``worst_arg_taint``: the ``_PROVABLY_UNTRUSTED`` predicate is not
    upward-closed (a hole at ``UNKNOWN_RAW`` sits between ``EXTERNAL_RAW`` and
    ``MIXED_RAW``), so a max-rank collapse would let an ``UNKNOWN_RAW`` co-arg mask a
    provably-untrusted argument.

Subsumption: distinct from PY-WL-101 (return anchor vs call-site anchor); a function
that *returns* such a call is 101, the *pass-in* is 105 even if the result is discarded.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.rules._sink_helpers import (
    RAW_ZONE,
    _own_calls,
    dotted_name,
    resolved_arg_taints,
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


def _resolve_callees(call: ast.Call, module: str, context: AnalysisContext, *, caller_qualname: str = "") -> set[str]:
    """The SET of candidate callee qualnames for a call site. For a branch-conditional
    receiver (``o`` assigned a project class in >1 arm), this is the full candidate set
    so the rule fires on any trusted-sink candidate regardless of AST order
    (wardline-499c22bbdd); otherwise it is the single ``_resolve_callee`` result."""
    candidates = context.call_site_candidate_callees.get(id(call))
    if candidates:
        resolved = {c for c in candidates if c in context.entities}
        if resolved:
            return resolved
    single = _resolve_callee(call, module, context, caller_qualname=caller_qualname)
    return {single} if single is not None else set()


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
            for call in _own_calls(entity.node):
                callees = _resolve_callees(call, module, context, caller_qualname=qualname)
                if not callees:
                    continue
                # Arg gate (independent of which callee): fire when ANY resolved arg is
                # provably untrusted. worst_arg_taint (max TRUST_RANK) is unsound here:
                # _PROVABLY_UNTRUSTED is NOT upward-closed (hole at UNKNOWN_RAW=6 between
                # EXTERNAL_RAW=5 and MIXED_RAW=7), so an UNKNOWN_RAW co-arg would mask a
                # provably-untrusted arg by bumping the max into the hole. Computed once;
                # only the callee-trust gate varies across branch-conditional candidates.
                arg_taints = resolved_arg_taints(call, qualname, context).values()
                untrusted = [ts for ts in arg_taints if ts in _PROVABLY_UNTRUSTED]
                if not untrusted:
                    continue
                worst = max(untrusted, key=lambda ts: TRUST_RANK[ts])
                line = call.lineno
                # Collect every candidate callee that is a trust-declared producer. A
                # branch-conditional receiver may have >1 trusted candidate at one call
                # site; emit ONE finding per call site (not one per candidate) so a single
                # taint flow is a single defect, deterministically keyed on the first
                # candidate (wardline-499c22bbdd panel: avoid duplicate findings/fingerprints).
                firing = []
                for callee in sorted(callees):
                    prov = context.taint_provenance.get(callee)
                    if prov is None or prov.source != "anchored":
                        continue  # callee is not a trust-declared producer
                    callee_body = context.project_taints.get(callee)
                    if callee_body is None or callee_body in RAW_ZONE:
                        continue  # @external_boundary / @trust_boundary body is raw — raw input expected
                    firing.append((callee, callee_body))
                if not firing:
                    continue
                callee, callee_body = firing[0]
                others = [c for c, _ in firing[1:]]
                also = f" (branch-conditional; also reaches {', '.join(others)})" if others else ""
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message=(
                            f"{qualname}: {worst.value} (untrusted) data passed to trusted producer "
                            f"{callee}() at line {line}{also}"
                        ),
                        severity=self.base_severity,
                        kind=Kind.DEFECT,
                        location=Location(path=entity.location.path, line_start=line),
                        fingerprint=_fp(
                            rule_id=self.rule_id,
                            path=entity.location.path,
                            qualname=qualname,
                            # Call-site-anchored, >1 finding per (rule, path, qualname) possible (several
                            # calls in one function). Discriminate SOURCE-only: an ENTITY-RELATIVE line
                            # offset (call line - def line, invariant to a comment ABOVE the function:
                            # wlfp2/wardline-8654423823) + the call's full lexical SPAN + the callee spelling
                            # AS WRITTEN. Never the resolved arg taint or resolved callee qualname (both
                            # drift). The span (start:end) separates a chain's outer/inner calls.
                            taint_path=f"{line - (entity.location.line_start or 0)}:{call.col_offset}:{call.end_col_offset}:{dotted_name(call.func)}",  # noqa: E501
                        ),
                        qualname=qualname,
                        properties={
                            "callee": callee,
                            "arg_taint": worst.value,
                            "callee_body": callee_body.value,
                            **({"candidate_callees": [c for c, _ in firing]} if others else {}),
                        },
                    )
                )
        return findings
