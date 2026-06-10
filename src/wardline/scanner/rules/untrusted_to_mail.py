# src/wardline/scanner/rules/untrusted_to_mail.py
"""PY-WL-126 — untrusted recipient/message reaches SMTP.sendmail (CWE-93).

Charter: mail (CRLF/header) injection — tainted data in the ``to_addrs``
(position 1) or ``msg`` (position 2) argument of ``smtplib.SMTP.sendmail`` /
``smtplib.SMTP_SSL.sendmail`` inside a trusted-tier function. The receiver is
matched through the construct-then-method machinery (``s = smtplib.SMTP(h)``,
``with smtplib.SMTP(h) as s``, ``s: smtplib.SMTP``, the chained form).
Newlines in a recipient or message inject spoofed headers / BCC recipients.

Calibration: ``from_addr`` (position 0) is deliberately NOT a dangerous slot in
v1 — the recipient set and message body are the canonical CWE-93 injection
surfaces the gap report names; widening to the envelope sender can ride a later
calibration pass. ``send_message`` is out of scope (it takes an
``email.message.Message``, whose header serialization already rejects bare
newlines on supported Pythons).

Severity: WARN. Real injection, but bounded blast radius (spam/spoofing, not
code execution) and gated on a constructed SMTP client — the mass-assignment
class, not the RCE class.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Maturity, Severity
from wardline.scanner.rules._sink_helpers import ArgSpec, TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

# sendmail(from_addr, to_addrs, msg, ...) — recipient + message are the slots.
_SENDMAIL_SPEC = ArgSpec(positions=(1, 2), keywords=("to_addrs", "msg"))

_SINK_SPECS: dict[str, ArgSpec | None] = {
    "smtplib.SMTP.sendmail": _SENDMAIL_SPEC,
    "smtplib.SMTP_SSL.sendmail": _SENDMAIL_SPEC,
}

METADATA = RuleMetadata(
    rule_id="PY-WL-126",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data reaches the recipient/message of smtplib SMTP.sendmail "
        "in a trusted-tier function (mail/header injection)."
    ),
    examples_violation=(
        "import smtplib\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n"
        "    s = smtplib.SMTP('localhost')\n"
        "    s.sendmail('from@example.com', 'to@example.com', read_raw(p))\n"
        "    return 1",
    ),
    examples_clean=(
        "import smtplib\n"
        "@trusted(level='ASSURED')\ndef f():\n"
        "    s = smtplib.SMTP('localhost')\n"
        "    s.sendmail('from@example.com', 'to@example.com', 'body')\n"
        "    return 1",
    ),
    maturity=Maturity.PREVIEW,
)


class UntrustedToMail(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = frozenset(_SINK_SPECS)
    SINK_SPECS = _SINK_SPECS
    sink_label = "SMTP-send"
