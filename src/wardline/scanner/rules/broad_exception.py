# src/wardline/scanner/rules/broad_exception.py
"""PY-WL-103 — broad exception handler in a trusted-tier function.

``except:`` / ``except Exception`` / ``except BaseException`` swallows error
classes indiscriminately. Tier-modulated: the function's own body taint scales
the base severity (§5), so it is silent on undecorated (``UNKNOWN_RAW``) code and
only speaks where trust is declared.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.scanner.rules._ast_helpers import is_broad_except, own_except_handlers
from wardline.scanner.rules._sink_helpers import enclosing_declared_tier
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-103",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    multi_emit=True,
    description="A broad exception handler (bare except / Exception / BaseException) in a trusted-tier function.",
    examples_violation=("@trusted\ndef f():\n    try:\n        g()\n    except Exception:\n        h()",),
    examples_clean=("@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        h()",),
)


class BroadException:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            # Nearest DECLARED enclosing scope governs a nested def (a nested def's own
            # trust decorator wins; undeclared nested defs inherit) — the same
            # enclosing_declared_tier semantics as the sink rule family, NOT the
            # outermost-function strip (wardline-bb8396f96e / wardline-9b88ec5419).
            tier = enclosing_declared_tier(qualname, context.project_taints, context.declared_qualnames)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue  # suppressed outside trusted/partial tiers
            for handler in own_except_handlers(entity.node):
                if not is_broad_except(handler):
                    continue
                line = handler.lineno
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message=f"{qualname}: broad exception handler at line {line}",
                        severity=severity,
                        kind=Kind.DEFECT,
                        # Location.line_start stays the HANDLER line (display/SARIF + the P4
                        # migration's old-fp derivation), NOT the def line.
                        location=Location(path=entity.location.path, line_start=line),
                        fingerprint=_fp(
                            rule_id=self.rule_id,
                            path=entity.location.path,
                            qualname=qualname,
                            # Multi-emit: >1 broad handler per function. Discriminate ENTITY-RELATIVE
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
