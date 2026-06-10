# src/wardline/scanner/rules/untrusted_to_log.py
"""PY-WL-125 — untrusted data as the log MESSAGE format string (CWE-117).

Charter: log injection / log forging — a tainted value used as the message
FORMAT string of ``logging.debug/info/warning/error/critical/exception`` (the
module-level functions or the Logger-method form via the construct-then-method
machinery: ``logger = logging.getLogger(...); logger.info(raw)``) inside a
trusted-tier function. Newline-spoofed entries forge audit lines and seed
log-viewer XSS downstream.

Only the message slot (position 0 / ``msg``) is dangerous. Tainted data in the
lazy ``%``-args parameters (``logging.info('user=%s', raw)``) is logging's OWN
parameterization — the canonical safe idiom — and must NOT fire; flagging it
would be an FP factory. ``logging.log(level, msg)`` is deliberately out of
scope for v1 (its message sits at position 1; charter names the fixed-level
methods only).

Severity calibration: INFO (below the task ceiling of WARN). CWE-117 is a
recognised weakness class but is high-noise by nature — almost every service
logs request-derived data somewhere — and its blast radius is forgery/foothold,
not execution. INFO keeps the finding visible to agents (and to an explicit
``--fail-on INFO`` gate) without ever tripping the default gate; peer tools
(bandit, CodeQL) rate the class LOW for the same reason.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Maturity, Severity
from wardline.scanner.rules._sink_helpers import ArgSpec, TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

_METHODS = ("debug", "info", "warning", "error", "critical", "exception")
_MSG_SPEC = ArgSpec(positions=(0,), keywords=("msg",))

# Module-level functions + the Logger-method form. The binding machinery records
# a constructor FQN without verifying it names a class, so ``logging.getLogger.info``
# is the canonical name a ``logger = logging.getLogger(...)`` method call resolves
# to; ``logging.Logger.info`` covers the ``log: logging.Logger`` annotation form.
_SINK_SPECS: dict[str, ArgSpec | None] = {
    f"{prefix}.{method}": _MSG_SPEC
    for prefix in ("logging", "logging.getLogger", "logging.Logger")
    for method in _METHODS
}

METADATA = RuleMetadata(
    rule_id="PY-WL-125",
    base_severity=Severity.INFO,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data is used as the log MESSAGE format string "
        "(logging.* / Logger methods) in a trusted-tier function (log injection)."
    ),
    examples_violation=(
        "import logging\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    logging.info(read_raw(p))\n    return 1",
    ),
    examples_clean=(
        # Lazy %-parameterization is logging's own safe idiom — never a finding.
        "import logging\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    logging.info('user input = %s', read_raw(p))\n    return 1",
    ),
    maturity=Maturity.PREVIEW,
)


class UntrustedToLog(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = frozenset(_SINK_SPECS)
    SINK_SPECS = _SINK_SPECS
    sink_label = "log-message"
