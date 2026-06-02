# src/wardline/scanner/rules/untrusted_to_command.py
"""PY-WL-108 — untrusted data reaches an OS-command sink.

Passing untrusted data to ``os.system`` / ``os.popen`` / ``subprocess.*`` is OS command
injection (CWE-78). Tier-modulated; fires only where trust is declared. (The presence
of ``shell=True`` aggravates the risk but is not required to fire — any untrusted
argument to these sinks in a trusted-tier function is reported.)
"""

from __future__ import annotations

from wardline.core.finding import Kind, Severity
from wardline.scanner.rules._sink_helpers import TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

_SINKS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.getoutput",
    }
)

METADATA = RuleMetadata(
    rule_id="PY-WL-108",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description="Untrusted data reaches an OS-command sink (os.system/subprocess.*) in a trusted-tier function.",
    examples_violation=("@trusted\ndef f(p):\n    cmd = read_raw(p)\n    os.system(cmd)",),
    examples_clean=("@trusted\ndef f():\n    os.system('ls -la')",),
)


class UntrustedToCommand(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "OS-command"
