# src/wardline/core/filigree_issue.py
"""WS-A2: file ONE finding (by fingerprint) into a tracked Filigree issue, fail-soft.

Sibling of core/filigree_emit.py: same injectable-transport, same fail-soft charter
(sibling-absent / 5xx warn-and-continue; a 4xx other than 404 is a Wardline-bad-payload
bug and is loud). Talks the Loom HTTP promote-by-fingerprint route; imports no Filigree
package. A 404 means the fingerprint was never ingested for this scan_source (the agent
should emit findings to Filigree first) — surfaced as `not_found`, not an exception."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from wardline.core.errors import FiligreeEmitError
from wardline.core.http import read_response_text

_ALLOWED_SCHEMES = ("http", "https")
_LOOM_MARKER = "/api/loom/"


def promote_url_from_loom(loom_url: str) -> str:
    """Derive the promote route from the configured Loom scan-results URL — both
    live under /api/loom/. Reject a URL that isn't a Loom endpoint (a clear config
    error rather than a 404 against a wrong host)."""
    idx = loom_url.find(_LOOM_MARKER)
    if idx == -1:
        raise FiligreeEmitError(f"filigree URL must be a Loom endpoint containing {_LOOM_MARKER!r}: {loom_url!r}")
    base = loom_url[: idx + len(_LOOM_MARKER)]
    return base + "findings/promote"


def build_promote_body(
    *,
    fingerprint: str,
    scan_source: str = "wardline",
    priority: str | None = None,
    labels: Sequence[str] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"scan_source": scan_source, "fingerprint": fingerprint}
    if priority is not None:
        body["priority"] = priority
    if labels:
        body["labels"] = list(labels)
    return body


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: str


@dataclass(frozen=True, slots=True)
class FileResult:
    reachable: bool
    issue_id: str | None = None
    created: bool = False
    not_found: bool = False  # reachable, but the fingerprint isn't known to Filigree
    disabled_reason: str | None = None


class Transport(Protocol):
    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response: ...


class UrllibTransport:
    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response:
        # Restrict to http(s): a stray file://, ftp:// or data: URL is a user error, not
        # an ingest target — turn it into a clean loud failure (and justify the S310 below).
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise FiligreeEmitError(f"filigree URL must use http or https; got scheme {scheme!r} in {url!r}")
        request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:  # noqa: S310
                return Response(status=resp.status, body=read_response_text(resp))
        except urllib.error.HTTPError as exc:
            with exc:
                return Response(status=exc.code, body=read_response_text(exc))


class FiligreeIssueFiler:
    """POST a single fingerprint to the Loom promote route; return the issue id."""

    def __init__(self, loom_url: str, *, transport: Transport | None = None) -> None:
        self._url = promote_url_from_loom(loom_url)
        self._transport: Transport = transport if transport is not None else UrllibTransport()

    def file(
        self,
        fingerprint: str,
        *,
        scan_source: str = "wardline",
        priority: str | None = None,
        labels: Sequence[str] | None = None,
    ) -> FileResult:
        body = json.dumps(
            build_promote_body(fingerprint=fingerprint, scan_source=scan_source, priority=priority, labels=labels)
        ).encode("utf-8")
        try:
            resp = self._transport.post(self._url, body, {"Content-Type": "application/json"})
        except (urllib.error.URLError, OSError):
            return FileResult(reachable=False, disabled_reason="filigree unreachable")
        if resp.status >= 500:
            return FileResult(reachable=False, disabled_reason=f"filigree {resp.status}")
        if resp.status == 404:
            return FileResult(reachable=True, not_found=True)
        if not 200 <= resp.status < 300:
            raise FiligreeEmitError(f"Filigree rejected promote ({resp.status}) at {self._url}: {resp.body}")
        try:
            payload = json.loads(resp.body) if resp.body else {}
        except json.JSONDecodeError:
            payload = {}
        issue_id = payload.get("issue_id") if isinstance(payload, dict) else None
        created = bool(payload.get("created")) if isinstance(payload, dict) else False
        return FileResult(reachable=True, issue_id=issue_id, created=created)
