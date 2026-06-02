# src/wardline/filigree/dossier_client.py
"""Track 4 (T4.3) — the live Filigree source for the dossier's open-work section.

A small, dep-free urllib reader for ADR-029 entity-associations, behind the
``WorkProvider`` seam (``core/dossier.py``). Filigree is ``done``/frozen and
deliberately computes NO drift — the consumer does — so this provider IS that
consumer: it reads each association's ``content_hash_at_attach`` and compares it
(same entity-body granularity as Clarion's ``resolve`` content hash, SEI conformance
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

from wardline.clarion.identity import ContentStatus, EntityBinding, content_status
from wardline.core.dossier import TicketRef, WorkSection


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
        req = urllib.request.Request(url, headers=dict(headers), method="GET")
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
            return Response(status=resp.status, body=resp.read().decode("utf-8", "replace"))


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


class FiligreeWorkProvider:
    """A ``WorkProvider`` (``core/dossier.py``) backed by a live Filigree HTTP server."""

    def __init__(self, base_url: str, *, transport: Transport | None = None) -> None:
        self._base = base_url.rstrip("/")
        self._transport: Transport = transport if transport is not None else UrllibTransport()

    def work(self, binding: EntityBinding) -> WorkSection:
        if binding.sei is None:
            return WorkSection.unavailable("no SEI: cannot key Filigree associations")
        query = urllib.parse.urlencode({"entity_id": binding.sei})
        url = f"{self._base}/api/entity-associations?{query}"
        try:
            resp = self._transport.get(url, {"Accept": "application/json"})
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
        for row in _rows_of(parsed):
            issue_id = row.get("issue_id")
            if not isinstance(issue_id, str):
                continue
            attach_hash = row.get("content_hash_at_attach")
            attach_hash = attach_hash if isinstance(attach_hash, str) else None
            drift = content_status(attach_hash, binding.content_hash) is ContentStatus.STALE
            any_drift = any_drift or drift
            tickets.append(
                TicketRef(
                    issue_id=issue_id,
                    status=row.get("status") if isinstance(row.get("status"), str) else None,
                    priority=row.get("priority") if isinstance(row.get("priority"), str) else None,
                    title=row.get("title") if isinstance(row.get("title"), str) else None,
                    drift=drift,
                )
            )
        return WorkSection(
            available=True,
            tickets=tickets,
            identity_status=binding.identity,  # SEI axis, from the resolved binding
            content_status=ContentStatus.STALE if any_drift else ContentStatus.FRESH,
            reason=None,
        )
