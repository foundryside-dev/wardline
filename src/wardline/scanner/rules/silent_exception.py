# src/wardline/scanner/rules/silent_exception.py
"""PY-WL-104 — silently swallowed exception in a trusted-tier function.

A handler whose body only ``pass``/``...``/``continue``/``break`` discards the
error with no logging, re-raise, or recovery. Tier-modulated (§5) — silent on
undecorated code.
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
    description="An exception handler that silently swallows the error "
    "(only pass/.../continue/break) in a trusted-tier function.",
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
            tier = context.project_taints.get(qualname, TaintState.UNKNOWN_RAW)
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
                        location=Location(path=entity.location.path, line_start=line),
                        fingerprint=_fp(
                            rule_id=self.rule_id,
                            path=entity.location.path,
                            line_start=line,
                            qualname=qualname,
                            taint_path=tier.value,
                        ),
                        qualname=qualname,
                        properties={"tier": tier.value},
                    )
                )
        return findings
