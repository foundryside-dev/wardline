# src/wardline/core/filigree_emit.py
"""Native Filigree scan-results emission (SP4b).

A pure body builder (``build_scan_results_body``) plus an injectable-transport
HTTP emitter (``FiligreeEmitter``). stdlib-only; no runtime dependency on Filigree.
Federation discipline: a *sibling-absent* network failure warns and continues; an
HTTP *protocol error* (4xx/5xx) is a Wardline-built-a-bad-payload bug and fails loud.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from wardline.core.errors import FiligreeEmitError
from wardline.core.finding import Finding, severity_to_filigree, to_filigree_metadata

_SUGGESTION_LIMIT = 10000


def _cap_suggestion(suggestion: str | None) -> str | None:
    if suggestion is None:
        return None
    return suggestion if len(suggestion) <= _SUGGESTION_LIMIT else suggestion[:_SUGGESTION_LIMIT]


def _finding_to_wire(finding: Finding) -> dict[str, Any]:
    wire: dict[str, Any] = {
        "path": finding.location.path,
        "rule_id": finding.rule_id,
        "message": finding.message,
        "severity": severity_to_filigree(finding.severity),
        "line_start": finding.location.line_start,
        "line_end": finding.location.line_end,
        "fingerprint": finding.fingerprint,
        "metadata": to_filigree_metadata(finding),
        "language": "python",
    }
    suggestion = _cap_suggestion(finding.suggestion)
    if suggestion is not None:
        wire["suggestion"] = suggestion
    return wire


def build_scan_results_body(
    findings: Sequence[Finding], *, scan_source: str = "wardline"
) -> dict[str, Any]:
    """Build the ``POST /api/loom/scan-results`` request body. Emits ALL finding kinds."""
    return {
        "scan_source": scan_source,
        "findings": [_finding_to_wire(f) for f in findings],
    }


# --- transport + emitter -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: str


@dataclass(frozen=True, slots=True)
class EmitResult:
    reachable: bool
    created: int = 0
    updated: int = 0
    warnings: tuple[str, ...] = field(default_factory=tuple)


class Transport(Protocol):
    def post(self, url: str, body: bytes, headers: dict[str, str]) -> Response: ...


class UrllibTransport:
    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> Response:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:  # noqa: S310
                return Response(status=resp.status, body=resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # An HTTP status reached us — protocol-level outcome, not an outage.
            return Response(status=exc.code, body=exc.read().decode("utf-8", "replace"))


class FiligreeEmitter:
    """POST findings to a Filigree Loom scan-results URL with an injectable transport."""

    def __init__(self, url: str, *, transport: Transport | None = None) -> None:
        self._url = url
        self._transport: Transport = transport if transport is not None else UrllibTransport()

    def emit(self, findings: Sequence[Finding]) -> EmitResult:
        body = json.dumps(build_scan_results_body(findings)).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        try:
            resp = self._transport.post(self._url, body, headers)
        except (urllib.error.URLError, OSError):
            # Connection refused / DNS / timeout — sibling absent. Enrichment is
            # non-load-bearing: warn (at the CLI) and continue.
            return EmitResult(reachable=False)
        if resp.status >= 400:
            raise FiligreeEmitError(
                f"Filigree rejected scan-results ({resp.status}) at {self._url}: {resp.body}"
            )
        payload = json.loads(resp.body) if resp.body else {}
        stats = payload.get("stats", {}) or {}
        return EmitResult(
            reachable=True,
            created=int(stats.get("findings_created", 0)),
            updated=int(stats.get("findings_updated", 0)),
            warnings=tuple(payload.get("warnings", []) or ()),
        )
