# src/wardline/filigree/dossier_client.py
"""Track 4 (T4.3) — the live Filigree source for the dossier's open-work section.

A small, dep-free urllib reader for ADR-029 entity-associations, behind the
``WorkProvider`` seam (``core/dossier.py``). Filigree is ``done``/frozen and
deliberately computes NO drift — the consumer does — so this provider IS that
consumer: it reads each association's ``content_hash_at_attach`` and compares it
(same entity-body granularity as Loomweave's ``resolve`` content hash, SEI conformance
§2 note) against the binding's current content hash to set per-ticket DRIFT and the
section's content axis. Fail-soft: an outage / a no-SEI binding yields an honest
``unavailable`` section, never a crash and never fabricated work.

The two freshness axes stay orthogonal: the IDENTITY axis is carried from the binding
(alive / orphaned), and the CONTENT axis is FRESH unless an association drifted.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from wardline.core.dossier import TicketRef, WorkSection
from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_emit import filigree_api_base_url
from wardline.core.http import read_response_text
from wardline.core.identity import ContentStatus, EntityBinding, content_status

_ALLOWED_SCHEMES = ("http", "https")


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: str


class Transport(Protocol):
    def get(self, url: str, headers: Mapping[str, str]) -> Response: ...


class UrllibTransport:
    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def get(self, url: str, headers: Mapping[str, str]) -> Response:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise FiligreeEmitError(f"filigree dossier URL must use http or https; got scheme {scheme!r} in {url!r}")
        req = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                return Response(status=resp.status, body=read_response_text(resp))
        except urllib.error.HTTPError as exc:
            # Mirror loomweave/client.UrllibTransport: surface the HTTP status to the
            # caller (a >=400 band) rather than letting HTTPError (a URLError subclass)
            # collapse into the "unreachable" branch — so a 4xx/5xx is classified, not
            # mistaken for an outage.
            with exc:
                return Response(status=exc.code, body=read_response_text(exc))


def _rows_of(parsed: Any) -> list[dict[str, Any]]:
    """Extract association rows defensively. Filigree may serve a bare list or a dict
    keyed under ``associations`` / ``rows`` / ``results``; anything else → no rows
    (honest empty, never a crash on an unexpected envelope shape)."""
    if isinstance(parsed, list):
        candidate = parsed
    elif isinstance(parsed, dict):
        candidate = next(
            (parsed[k] for k in ("associations", "rows", "results") if isinstance(parsed.get(k), list)),
            [],
        )
    else:
        candidate = []
    return [r for r in candidate if isinstance(r, dict)]


def _api_base_url(url: str) -> str:
    """Normalize an origin/API/scan-results URL (classic or project-scoped, either
    dialect) to the Filigree API base, via the shared parser in
    ``core/filigree_emit.py``. Dogfood-4 A4 was this function appending ``/api`` to a
    project-scoped endpoint, 404ing every work-join on the wired-up repo."""
    return filigree_api_base_url(url)


class FiligreeWorkProvider:
    """A ``WorkProvider`` (``core/dossier.py``) backed by a live Filigree HTTP server."""

    def __init__(self, base_url: str, *, transport: Transport | None = None, token: str | None = None) -> None:
        self._base = _api_base_url(base_url)
        self._transport: Transport = transport if transport is not None else UrllibTransport()
        self._token = token

    def work(self, binding: EntityBinding) -> WorkSection:
        if binding.sei is None:
            return WorkSection.unavailable("no SEI: cannot key Filigree associations")
        query = urllib.parse.urlencode({"entity_id": binding.sei})
        url = f"{self._base}/entity-associations?{query}"
        headers = {"Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            resp = self._transport.get(url, headers)
        except (urllib.error.URLError, OSError) as exc:
            return WorkSection.unavailable(f"filigree unreachable: {exc}")
        if not 200 <= resp.status < 300:
            return WorkSection.unavailable(f"filigree returned HTTP {resp.status}")
        try:
            parsed = json.loads(resp.body) if resp.body else []
        except json.JSONDecodeError:
            return WorkSection.unavailable("filigree returned a non-JSON body")

        tickets: list[TicketRef] = []
        any_drift = False
        any_unknown = False
        for row in _rows_of(parsed):
            issue_id = row.get("issue_id")
            if not isinstance(issue_id, str):
                continue
            attach_hash = row.get("content_hash_at_attach")
            attach_hash = attach_hash if isinstance(attach_hash, str) else None
            status = content_status(attach_hash, binding.content_hash)
            drift = status is ContentStatus.STALE
            any_drift = any_drift or drift
            # An UNKNOWN compare (no attach hash, or no current binding hash) is NOT
            # FRESH — surfacing it as FRESH would be a false-green. TicketRef.drift is a
            # bool (STALE-or-not), so the honest UNKNOWN lives on the section axis.
            any_unknown = any_unknown or status is ContentStatus.UNKNOWN
            status_v = row.get("status")
            priority_v = row.get("priority")
            title_v = row.get("title")
            tickets.append(
                TicketRef(
                    issue_id=issue_id,
                    status=status_v if isinstance(status_v, str) else None,
                    priority=priority_v if isinstance(priority_v, str) else None,
                    title=title_v if isinstance(title_v, str) else None,
                    drift=drift,
                )
            )
        if any_drift:
            section_content = ContentStatus.STALE
        elif any_unknown:
            section_content = ContentStatus.UNKNOWN  # could not compare — never guess FRESH
        else:
            section_content = ContentStatus.FRESH
        return WorkSection(
            available=True,
            tickets=tickets,
            identity_status=binding.identity,  # SEI axis, from the resolved binding
            content_status=section_content,
            reason=None,
        )
