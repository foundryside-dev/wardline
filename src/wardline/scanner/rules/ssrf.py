# src/wardline/scanner/rules/ssrf.py
"""PY-WL-117 — untrusted data reaches an HTTP client sink.

Passing untrusted data to HTTP clients (``requests``, ``httpx``, ``urllib``) without
validation can lead to Server-Side Request Forgery (SSRF) (CWE-918).
Tier-modulated; fires only where trust is declared.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Maturity, Severity
from wardline.scanner.rules._sink_helpers import TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

_SINKS = frozenset(
    {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.request",
        "httpx.Client",
        "httpx.AsyncClient",
        "urllib.request.urlopen",
    }
)

METADATA = RuleMetadata(
    rule_id="PY-WL-117",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description=(
        "Untrusted data reaches an HTTP client sink (SSRF, requests/httpx/urllib) in a trusted-tier function."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    requests.get(read_raw(p))",
    ),
    examples_clean=("@trusted(level='ASSURED')\ndef f():\n    requests.get('https://example.com')",),
    maturity=Maturity.PREVIEW,
)


class SSRF(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "HTTP-client"
