# src/wardline/scanner/rules/untrusted_to_command.py
"""PY-WL-108 — untrusted data reaches an OS-command sink.

Passing untrusted data to an **always-shell** OS-command API — ``os.system``,
``os.popen``, ``subprocess.getoutput`` / ``getstatusoutput`` — is OS command injection
(CWE-78): these take a shell *string*, so an untrusted argument is directly injectable.
Tier-modulated; fires only where trust is declared.

**Scope (FP-safe):** the ``subprocess.run`` / ``call`` / ``Popen`` / ``check_*`` family
is intentionally NOT in the sink set — with the default ``shell=False`` an argv-LIST is
safe (no shell), so firing on them floods false positives; only ``shell=True`` makes them
injectable, and detecting that keyword reliably is policed separately by PY-WL-112.
Covering the always-shell APIs catches the unambiguous case without the argv-list FP.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Severity
from wardline.scanner.rules._sink_helpers import TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

_SINKS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
)

METADATA = RuleMetadata(
    rule_id="PY-WL-108",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description="Untrusted data reaches an always-shell OS-command sink (os.system/os.popen/subprocess.getoutput).",
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    os.system(read_raw(p))",
    ),
    examples_clean=("@trusted(level='ASSURED')\ndef f():\n    os.system('ls -la')",),
)


class UntrustedToCommand(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "OS-command"
