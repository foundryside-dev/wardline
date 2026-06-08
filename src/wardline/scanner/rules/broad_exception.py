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
from wardline.core.taints import TaintState
from wardline.scanner.rules._ast_helpers import is_broad_except, own_except_handlers
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-103",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
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
            lookup_name = qualname.split(".<locals>.")[0]
            tier = context.project_taints.get(lookup_name, TaintState.UNKNOWN_RAW)
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
                        location=Location(path=entity.location.path, line_start=line),
                        fingerprint=_fp(
                            rule_id=self.rule_id,
                            path=entity.location.path,
                            line_start=line,
                            qualname=qualname,
                            # Join-key stability (weft-4a9d0f863c): anchored at the handler line, which
                            # is unique per finding within a qualname. The tier is a resolved value
                            # (hoisted per-entity, never a discriminator) — keep it off the join key.
                            taint_path=None,
                        ),
                        qualname=qualname,
                        properties={"tier": tier.value},
                    )
                )
        return findings
