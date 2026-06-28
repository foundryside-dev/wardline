"""Small HTTP transport helpers shared by stdlib urllib clients."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

MAX_RESPONSE_BODY_BYTES = 64 * 1024
_TRUNCATION_MARKER = "... [truncated]"

_DEFAULT_ALLOWED_SCHEMES = ("http", "https")


class _Readable(Protocol):
    def read(self, size: int = -1) -> bytes: ...


def read_response_text(stream: _Readable, *, limit: int = MAX_RESPONSE_BODY_BYTES) -> str:
    """Read a bounded response/error body and decode it for diagnostics."""
    data = stream.read(limit + 1)
    truncated = len(data) > limit
    if truncated:
        data = data[:limit]
    text = data.decode("utf-8", "replace")
    return f"{text}{_TRUNCATION_MARKER}" if truncated else text


@dataclass(frozen=True, slots=True)
class HttpResult:
    """The status + bounded body of one HTTP round trip.

    An HTTP response — INCLUDING a 4xx/5xx (HTTPError) — yields an HttpResult so the
    caller classifies the outcome by status band. A transport-level failure
    (URLError / OSError: connection refused / DNS / timeout) is NOT caught here; it
    propagates to the caller, whose own fail-soft policy decides what an outage means.
    Each federation client wraps this in its own module-local ``Response`` dataclass.
    """

    status: int
    body: str


class WeftHttp:
    """Shared stdlib-urllib transport for the Weft federation clients.

    Encapsulates the one-true round-trip discipline every hand-rolled client repeated:
    a parameterized scheme gate, Request construction, ``urlopen`` with a request
    timeout, the HTTPError → :class:`HttpResult` conversion (a status reached us, so it
    is a protocol outcome, not an outage — the socket is closed), and a bounded body
    read (``read_response_text``, the 64 KiB :data:`MAX_RESPONSE_BODY_BYTES` cap).

    Confinement is PARAMETERIZED so each client keeps its exact gating, not unified away:

    * ``allowed_schemes`` — the scheme allow-list (default http/https). The gate is a
      THREAT-001-class confinement: a stray ``file://`` / ``ftp://`` / ``data:`` URL is a
      loud caller error, never an ingest target (and what justifies the ``urlopen`` S310).
    * ``scheme_error`` — a per-call-site builder ``(scheme, url) -> Exception`` so each
      client raises its OWN exception type and message (``FiligreeEmitError`` vs
      ``LoomweaveError``; ``--filigree-url`` vs ``--loomweave-url`` wording) verbatim.
    * ``timeout`` — the per-request ``urlopen`` timeout, unchanged per client.
    * ``max_body_bytes`` — the response-body read bound.

    ``URLError`` / ``OSError`` are deliberately NOT swallowed: each client's distinct
    policy is applied by the caller, so wire/error semantics stay identical after
    migration. filigree_emit and loomweave fail-HARD on a >=400 (``protocol_errors_loud``
    ``FiligreeEmitError`` / ``_require_ok`` ``LoomweaveError``); the dossier fail-SOFTs
    every non-2xx and every ``URLError`` / ``OSError`` to an ``unavailable`` section.

    The ``urlopen`` symbol is resolved as a live module attribute at call time (not
    bound at import/def), so a test that monkeypatches ``urllib.request.urlopen``
    keeps its injection seam.
    """

    def __init__(
        self,
        *,
        timeout: float = 30.0,
        allowed_schemes: tuple[str, ...] = _DEFAULT_ALLOWED_SCHEMES,
        scheme_error: Callable[[str, str], Exception] | None = None,
        max_body_bytes: int = MAX_RESPONSE_BODY_BYTES,
    ) -> None:
        self._timeout = timeout
        self._allowed_schemes = allowed_schemes
        self._scheme_error = scheme_error
        self._max_body_bytes = max_body_bytes

    def fetch(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> HttpResult:
        """One round trip: scheme-gate, build, ``urlopen``-with-timeout, bounded read.

        Returns an :class:`HttpResult` for any HTTP status (2xx..5xx, via the HTTPError
        branch). A ``URLError`` / ``OSError`` propagates — the caller owns that policy.
        """
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in self._allowed_schemes:
            raise self._build_scheme_error(scheme, url)
        request = urllib.request.Request(url, data=body, headers=dict(headers or {}), method=method)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:  # noqa: S310
                return HttpResult(status=resp.status, body=read_response_text(resp, limit=self._max_body_bytes))
        except urllib.error.HTTPError as exc:
            # An HTTP status reached us — a protocol-level outcome, not an outage. Convert
            # it to an HttpResult so the caller classifies by status band, and close the
            # underlying socket (the ``with exc`` context).
            with exc:
                return HttpResult(status=exc.code, body=read_response_text(exc, limit=self._max_body_bytes))

    def _build_scheme_error(self, scheme: str, url: str) -> Exception:
        if self._scheme_error is not None:
            return self._scheme_error(scheme, url)
        return ValueError(f"URL must use one of {self._allowed_schemes}; got scheme {scheme!r} in {url!r}")
