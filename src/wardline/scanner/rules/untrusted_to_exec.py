# src/wardline/scanner/rules/untrusted_to_exec.py
"""PY-WL-107 — untrusted data reaches a dynamic-code-execution sink.

``eval`` / ``exec`` / ``compile`` on untrusted input is arbitrary code execution
(CWE-95). Tier-modulated; fires only where trust is declared. Matches the bare
builtins (``eval(x)``) as well as ``builtins.eval`` forms.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Severity
from wardline.scanner.rules._sink_helpers import TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

_SINKS = frozenset({"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"})

METADATA = RuleMetadata(
    rule_id="PY-WL-107",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    multi_emit=True,
    description="Untrusted data reaches a dynamic-code-execution sink (eval/exec/compile) in a trusted-tier function.",
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    eval(read_raw(p))",
    ),
    examples_clean=("@trusted(level='ASSURED')\ndef f():\n    return eval('1 + 1')",),
)


class UntrustedToExec(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "dynamic-code-execution"
