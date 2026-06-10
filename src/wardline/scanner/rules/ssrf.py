# src/wardline/scanner/rules/ssrf.py
"""PY-WL-117 — untrusted data reaches an HTTP client sink.

Passing untrusted data to HTTP clients (``requests``, ``httpx``, ``aiohttp``,
``urllib``) without validation can lead to Server-Side Request Forgery (SSRF)
(CWE-918). Tier-modulated; fires only where trust is declared.

Two sharpenings over the generic :class:`TaintedSinkRule` machinery
(wardline-3002f63969 / wardline-66b2c91470):

* **Construct-then-method** — production code overwhelmingly pools requests
  through a constructed client (``client = httpx.Client(); client.get(url)``,
  ``async with httpx.AsyncClient() as c``, ``requests.Session().get(url)``,
  ``aiohttp.ClientSession``). Sink matching goes through
  :func:`resolved_sink_calls`, which layers name-binding resolution over the
  direct dotted/import-aliased spelling.

* **URL-slot precision** — for an HTTP client, only the request-target slot is
  an SSRF vector. Every sink carries an :class:`ArgSpec` naming its URL slot
  (``base_url=`` for client constructors), so a tainted ``timeout=``/
  ``verify=``/``headers=`` with a clean literal URL no longer fires
  (:func:`worst_dangerous_arg_taint` keeps the fail-closed splat widening).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Kind, Maturity, Severity
from wardline.scanner.rules._sink_helpers import ArgSpec, TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from collections.abc import Mapping

# The URL is the first positional / the ``url`` keyword (requests.get, client.get, ...).
_URL_FIRST = ArgSpec(positions=(0,), keywords=("url",))
# ``(method, url, ...)`` signatures: the URL is the SECOND slot; a tainted method verb
# cannot redirect the request target (requests.request, client.request, client.stream).
_URL_SECOND = ArgSpec(positions=(1,), keywords=("url",))
# httpx client constructors: the first positional is NOT a URL; ``base_url`` is the
# only SSRF-relevant constructor argument (and is keyword-only).
_BASE_URL_ONLY = ArgSpec(keywords=("base_url",))

_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_CLIENT_CLASSES = ("httpx.Client", "httpx.AsyncClient", "requests.Session", "aiohttp.ClientSession")


def _build_sink_specs() -> dict[str, ArgSpec]:
    specs: dict[str, ArgSpec] = {}
    for mod in ("requests", "httpx"):
        for verb in _HTTP_VERBS:
            specs[f"{mod}.{verb}"] = _URL_FIRST
        specs[f"{mod}.request"] = _URL_SECOND
    specs["httpx.stream"] = _URL_SECOND
    specs["urllib.request.urlopen"] = _URL_FIRST
    specs["urllib.request.Request"] = _URL_FIRST  # carries the tainted URL into urlopen
    specs["httpx.Client"] = _BASE_URL_ONLY
    specs["httpx.AsyncClient"] = _BASE_URL_ONLY
    # aiohttp.ClientSession(base_url=...) — base_url IS the first positional there.
    specs["aiohttp.ClientSession"] = ArgSpec(positions=(0,), keywords=("base_url",))
    # Instance methods on a constructed client/session (requests.Session() itself
    # takes no arguments, so the constructor is not a sink — only its methods are).
    for cls in _CLIENT_CLASSES:
        for verb in _HTTP_VERBS:
            specs[f"{cls}.{verb}"] = _URL_FIRST
        specs[f"{cls}.request"] = _URL_SECOND
    for cls in ("httpx.Client", "httpx.AsyncClient"):
        specs[f"{cls}.stream"] = _URL_SECOND
    return specs


_SINK_SPECS: Mapping[str, ArgSpec] = _build_sink_specs()
_SINKS = frozenset(_SINK_SPECS)

METADATA = RuleMetadata(
    rule_id="PY-WL-117",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data reaches the URL slot of an HTTP client sink "
        "(SSRF, requests/httpx/aiohttp/urllib — module-level calls, constructed "
        "client/session methods, and client base_url=) in a trusted-tier function."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    requests.get(read_raw(p))",
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n"
        "    client = httpx.Client()\n    client.get(read_raw(p))",
    ),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f():\n    requests.get('https://example.com')",
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n"
        "    requests.get('https://example.com', timeout=read_raw(p))",
    ),
    maturity=Maturity.PREVIEW,
)


class SSRF(TaintedSinkRule):
    # Attribute-only since the 2026-06-10 consolidation: the base check IS the
    # binding-aware loop, and SINK_SPECS carries the URL-slot precision.
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    SINK_SPECS = _SINK_SPECS
    sink_label = "HTTP-client"
