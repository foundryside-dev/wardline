# src/wardline/scanner/rules/stored_taint.py
"""PY-WL-120 — stored/persisted taint reaches trusted state without validation.

Fires when raw data loaded from persistent storage (such as file reads via ``open``/
``read_text`` or database cursor fetches) reaches a trusted state (returned by a
``@trusted`` function or passed to a ``@trusted`` callee) without being validated
(e.g., through a ``@trust_boundary``).

**Receiver-aware matching.** The storage-read matcher is binding-aware (the shared
``_sink_helpers`` class-tracking): an ``io.StringIO``/``io.BytesIO`` receiver is an
in-memory buffer whose ``.read()`` returns data the process itself put there — never
*persistent* storage — so it is exempt (wardline-66b2c91470: the receiver-blind
``.read()`` match mislabeled an in-memory constant as "stored/persisted data"). Any
taint flowing THROUGH such a buffer is still tracked by the engine (the buffer var
itself propagates via ``_collect_stored_vars``), and PY-WL-101 still polices the
producer's return claim.

**PY-WL-101 de-confliction on the return arm (documented winner: 101).** A matched
return whose taint is ``UNKNOWN_RAW``/``MIXED_RAW`` has UNRESOLVED provenance — the
"stored/persisted" label rests solely on the AST name match, which cannot justify
it — so when PY-WL-101 fires on the same producer this rule SUPPRESSES its return
finding and delegates to 101 (the mature, gate-eligible trust-claim check; this rule
is PREVIEW). A return whose taint is ``EXTERNAL_RAW`` is SUBSTANTIATED storage
provenance (the open()/Path.read_*/fetch* seeds), and there the deliberate
complementary pair stands: 101 reports the trust-claim violation, 120 adds the
storage-provenance annotation (pinned by the frozen identity corpus and the wlfp1
migration oracle). The call-argument arm is untouched — 101 never covers it.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Maturity, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import RAW_ZONE, TRUST_RANK, TaintState
from wardline.scanner.rules._ast_helpers import own_nodes
from wardline.scanner.rules._sink_helpers import (
    SinkBindings,
    collect_sink_bindings,
    dotted_name,
    entity_relative_span,
    module_alias_map,
    resolve_bound_call_fqn,
    worst_arg_taint,
)
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.scanner.context import AnalysisContext

_READ_ATTR_METHODS = frozenset({"read", "read_text", "read_bytes", "fetchone", "fetchall", "fetchmany"})
# In-memory buffer classes: a ``.read()`` on one returns data the PROCESS itself put
# there — never persistent storage — so the storage-provenance label cannot apply.
# Canonical FQNs (the binding machinery resolves ``from io import StringIO`` /
# ``import io as x`` spellings through the module alias map before the lookup).
_IN_MEMORY_BUFFER_FQNS = frozenset({"io.StringIO", "io.BytesIO"})


def _is_storage_read_call(node: ast.AST, bindings: SinkBindings, alias_map: Mapping[str, str]) -> bool:
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id in ("open", "read"):
                return True
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in _READ_ATTR_METHODS:
                # Receiver-awareness (wardline-66b2c91470): a statically-known
                # in-memory buffer receiver (bound var / with-target / chained
                # ctor, via the shared binding machinery) is NOT a storage read.
                # An unresolvable receiver stays conservatively matched.
                bound = resolve_bound_call_fqn(node, bindings, alias_map)
                return not (bound is not None and bound.rsplit(".", 1)[0] in _IN_MEMORY_BUFFER_FQNS)
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr in ("open", "read")
            ):
                return True
    return False


def _collect_stored_vars(node: ast.AST, bindings: SinkBindings, alias_map: Mapping[str, str]) -> set[str]:
    stored_vars: set[str] = set()
    for child in own_nodes(node):
        if isinstance(child, ast.Assign):
            is_storage = False
            for val_node in own_nodes(child.value):
                if _is_storage_read_call(val_node, bindings, alias_map):
                    is_storage = True
                    break
            if not is_storage:
                for val_node in own_nodes(child.value):
                    if isinstance(val_node, ast.Name) and val_node.id in stored_vars:
                        is_storage = True
                        break
            if is_storage:
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        stored_vars.add(target.id)
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                stored_vars.add(elt.id)
        elif isinstance(child, ast.AnnAssign) and child.value is not None:
            is_storage = False
            for val_node in own_nodes(child.value):
                if _is_storage_read_call(val_node, bindings, alias_map):
                    is_storage = True
                    break
            if not is_storage:
                for val_node in own_nodes(child.value):
                    if isinstance(val_node, ast.Name) and val_node.id in stored_vars:
                        is_storage = True
                        break
            if is_storage and isinstance(child.target, ast.Name):
                stored_vars.add(child.target.id)
    return stored_vars


def _return_delegated_to_101(qualname: str, context: AnalysisContext) -> bool:
    """True when PY-WL-101 fires on *qualname*'s return (mirrors 101's gate).

    Deliberate coupling: this must stay in lockstep with
    ``untrusted_reaches_trusted.UntrustedReachesTrusted.check`` — suppression is
    only sound when the delegate actually picks the defect up (otherwise the
    return finding must stand, e.g. a non-anchored tier 101 cannot police).
    That includes ENABLEMENT: under ``rules.enable`` without PY-WL-101 the
    delegate never runs, so suppressing here would drop the raw-storage-return
    defect from the scan entirely (review 2026-06-10). ``None`` (a direct
    construction / duck-typed registry seam) preserves the historical
    assume-enabled behavior.
    """
    if context.enabled_rule_ids is not None and "PY-WL-101" not in context.enabled_rule_ids:
        return False
    prov = context.taint_provenance.get(qualname)
    if prov is None or prov.source != "anchored":
        return False
    declared = context.project_return_taints.get(qualname)
    if declared is None or declared in RAW_ZONE:
        return False  # 101's trust-claim gate
    body = context.project_taints.get(qualname)
    if body is not None and TRUST_RANK[body] > TRUST_RANK[declared]:
        return False  # trust-raising shape — 101 delegates that to PY-WL-102
    actual = context.function_return_taints.get(qualname)
    return actual is not None and TRUST_RANK[actual] > TRUST_RANK[declared]


METADATA = RuleMetadata(
    rule_id="PY-WL-120",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description="Stored/persisted taint reaches trusted state without validation.",
    examples_violation=(
        "@trusted(level='ASSURED')\ndef get_config():\n    data = open('config.txt').read()\n    return data",
    ),
    examples_clean=(
        # validate must be a REAL @trust_boundary: an undefined bare name no longer
        # launders to the caller's seed, so the example defines its own validator.
        "@trust_boundary(to_level='ASSURED')\ndef validate(x):\n    if not x:\n        raise ValueError\n    return x\n"
        "@trusted(level='ASSURED')\ndef get_config():\n    data = validate(open('config.txt').read())\n    return data",
    ),
    maturity=Maturity.PREVIEW,
)


class StoredTaint:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            # Only check if the function itself is a trusted producer or boundary
            tier = context.project_taints.get(qualname, TaintState.UNKNOWN_RAW)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue

            alias_map = module_alias_map(qualname, context)
            bindings = collect_sink_bindings(entity.node, alias_map)
            stored_vars = _collect_stored_vars(entity.node, bindings, alias_map)
            if not stored_vars:
                # Check if there is a direct return of a storage read call
                has_direct_read = False
                for node in own_nodes(entity.node):
                    if isinstance(node, ast.Return) and node.value is not None:
                        for val_node in own_nodes(node.value):
                            if _is_storage_read_call(val_node, bindings, alias_map):
                                has_direct_read = True
                                break
                if not has_direct_read:
                    continue

            # 1. Check return statements
            for node in own_nodes(entity.node):
                if isinstance(node, ast.Return) and node.value is not None:
                    is_stored_return = False
                    if _is_storage_read_call(node.value, bindings, alias_map):
                        is_stored_return = True
                    else:
                        for val_node in own_nodes(node.value):
                            if isinstance(val_node, ast.Name) and val_node.id in stored_vars:
                                is_stored_return = True
                                break
                            if _is_storage_read_call(val_node, bindings, alias_map):
                                is_stored_return = True
                                break

                    if is_stored_return:
                        # Check return taint
                        ret_taint = context.function_return_taints.get(qualname)
                        if (
                            ret_taint is not None
                            and ret_taint is not TaintState.EXTERNAL_RAW
                            and ret_taint in RAW_ZONE
                            and _return_delegated_to_101(qualname, context)
                        ):
                            # UNKNOWN/MIXED_RAW return: provenance UNRESOLVED, so the
                            # "stored/persisted" label is unsubstantiated — suppress and
                            # delegate the trust-claim violation to PY-WL-101 (101 wins;
                            # module docstring). EXTERNAL_RAW (a recognized storage seed)
                            # keeps the documented complementary 120+101 pair.
                            continue
                        if ret_taint is not None and ret_taint in RAW_ZONE:
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    message=(
                                        f"{qualname} returns stored/persisted data "
                                        f"({ret_taint.value}) without validation at line {node.lineno}"
                                    ),
                                    severity=severity,
                                    kind=Kind.DEFECT,
                                    location=Location(path=entity.location.path, line_start=node.lineno),
                                    fingerprint=_fp(
                                        rule_id=self.rule_id,
                                        path=entity.location.path,
                                        qualname=qualname,
                                        # >1 return per function is possible. Discriminate with the
                                        # ENTITY-RELATIVE full lexical span + a ``return`` token. The
                                        # ``:return`` token keeps this DISJOINT from the call-arg site below
                                        # (which ends in a callee name), so the two never collide.
                                        taint_path=f"{entity_relative_span(node, entity.location.line_start)}:return",
                                    ),
                                    qualname=qualname,
                                    properties={"return_taint": ret_taint.value},
                                )
                            )

            # 2. Check call arguments to trusted/modulated callees
            for node in own_nodes(entity.node):
                if isinstance(node, ast.Call):
                    # Check if any argument is a stored variable or storage read
                    has_stored_arg = False
                    for arg in (*node.args, *(kw.value for kw in node.keywords)):
                        for val_node in own_nodes(arg):
                            if isinstance(val_node, ast.Name) and val_node.id in stored_vars:
                                has_stored_arg = True
                                break
                            if _is_storage_read_call(val_node, bindings, alias_map):
                                has_stored_arg = True
                                break

                    if has_stored_arg:
                        # Resolve callee FQN(s). For a branch-conditional receiver, consult
                        # the full candidate set so this fires on any trusted candidate
                        # regardless of AST order (shares wardline-499c22bbdd's root cause);
                        # otherwise the single call_site_callees entry.
                        candidate_qns = context.call_site_candidate_callees.get(id(node))
                        if candidate_qns:
                            callee_qns: list[str] = sorted(candidate_qns)
                        else:
                            single = context.call_site_callees.get(id(node))
                            callee_qns = [single] if single is not None else []
                        # Keep only candidates that are trusted producers/boundaries; emit
                        # ONE finding per call site (not one per candidate) deterministically
                        # keyed on the first, so a branch-conditional receiver with several
                        # trusted candidates is one defect (wardline-499c22bbdd panel).
                        firing_qns = [
                            qn
                            for qn in callee_qns
                            if (ct := context.project_taints.get(qn)) is not None and ct not in RAW_ZONE
                        ]
                        if firing_qns:
                            worst = worst_arg_taint(node, qualname, context)
                            if worst is not None and worst in RAW_ZONE:
                                callee_qn = firing_qns[0]
                                others = firing_qns[1:]
                                also = f" (branch-conditional; also reaches {', '.join(others)})" if others else ""
                                findings.append(
                                    Finding(
                                        rule_id=self.rule_id,
                                        message=(
                                            f"{qualname} passes stored/persisted data "
                                            f"({worst.value}) to trusted callee {callee_qn} "
                                            f"without validation at line {node.lineno}{also}"
                                        ),
                                        severity=severity,
                                        kind=Kind.DEFECT,
                                        location=Location(path=entity.location.path, line_start=node.lineno),
                                        fingerprint=_fp(
                                            rule_id=self.rule_id,
                                            path=entity.location.path,
                                            qualname=qualname,
                                            # Call-site-anchored, >1 finding per (rule, path, qualname)
                                            # possible. Discriminate SOURCE-only: an ENTITY-RELATIVE line
                                            # offset (call line - def line, invariant to a comment ABOVE the
                                            # function: wlfp2/wardline-8654423823) + the call's full lexical
                                            # SPAN + the callee spelling AS WRITTEN. Never the RESOLVED callee
                                            # qualname (drifts). The span separates multiline chain calls that
                                            # differ only by end line.
                                            taint_path=f"{entity_relative_span(node, entity.location.line_start)}:{dotted_name(node.func)}",  # noqa: E501
                                        ),
                                        # OLD (wlfp1) taint_path, byte-exact, for `wardline rekey` (P4).
                                        taint_path_v0=f"{dotted_name(node.func)}@{node.col_offset}:{node.end_col_offset}",
                                        qualname=qualname,
                                        properties={"callee": callee_qn, "arg_taint": worst.value},
                                    )
                                )
        return findings
