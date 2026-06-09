# src/wardline/scanner/rules/silent_exception.py
"""PY-WL-104 — silently swallowed exception in a trusted-tier function.

A handler whose body is only ``pass``/``...``/``continue``/``break`` or a bare
constant expression (a string literal or number) discards the error with no
logging, re-raise, or recovery. Tier-modulated (§5) — silent on undecorated
code, downgraded one step on partial tiers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TaintState
from wardline.scanner.rules._ast_helpers import is_silent_handler, own_except_handlers
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-104",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description="An exception handler that silently swallows the error — body is "
    "only pass/.../continue/break or a bare constant expression (e.g. a "
    "docstring-like string literal or a number). Tier-modulated: fires on "
    "trusted tiers, downgraded to INFO on partial tiers.",
    examples_violation=("@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        pass",),
    examples_clean=("@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        log(e)",),
)


class SilentException:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            lookup_name = qualname.split(".<locals>.")[0]
            tier = context.project_taints.get(lookup_name, TaintState.UNKNOWN_RAW)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue
            for handler in own_except_handlers(entity.node):
                if not is_silent_handler(handler):
                    continue
                line = handler.lineno
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message=f"{qualname}: exception silently swallowed at line {line}",
                        severity=severity,
                        kind=Kind.DEFECT,
                        # Location.line_start stays the HANDLER line (display/SARIF + the P4
                        # migration's old-fp derivation), NOT the def line.
                        location=Location(path=entity.location.path, line_start=line),
                        fingerprint=_fp(
                            rule_id=self.rule_id,
                            path=entity.location.path,
                            qualname=qualname,
                            # Multi-emit: >1 silent handler per function. Discriminate ENTITY-RELATIVE
                            # (handler line - def line) + the handler's lexical span, so two handlers stay
                            # distinct after line_start left the hash (wlfp2/wardline-6102d4c833) yet a
                            # comment ABOVE the function does not churn it. Source-only; tier never joins.
                            taint_path=f"{handler.lineno - (entity.location.line_start or 0)}:{handler.col_offset}:{handler.end_col_offset}:except",  # noqa: E501
                        ),
                        qualname=qualname,
                        properties={"tier": tier.value},
                    )
                )
        return findings
