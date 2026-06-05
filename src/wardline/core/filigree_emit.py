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
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from wardline.core.errors import FiligreeEmitError
from wardline.core.finding import Finding, severity_to_filigree, to_filigree_metadata
from wardline.core.http import read_response_text

_SUGGESTION_LIMIT = 10000
_ALLOWED_SCHEMES = ("http", "https")


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


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
    findings: Sequence[Finding],
    *,
    scan_source: str = "wardline",
    scanned_paths: Sequence[str] = (),
) -> dict[str, Any]:
    """Build the ``POST /api/weft/scan-results`` request body. Emits ALL finding kinds.
    ``mark_unseen`` opts into Filigree's per-(file, scan_source) absent-fingerprint sweep:
    a fingerprint seen before but absent now in a scanned file enters
    ``unseen_in_latest``. Clean files are represented by ``scanned_paths`` so
    close-on-fixed can reconcile a file whose last finding disappeared."""
    findings_wire = [_finding_to_wire(f) for f in findings]
    scanned = list(dict.fromkeys(p for p in scanned_paths if p))
    body = {
        "scan_source": scan_source,
        "mark_unseen": bool(findings_wire or scanned),
        "findings": findings_wire,
    }
    if scanned:
        body["scanned_paths"] = scanned
    return body


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
    failed: int = 0
    warnings: tuple[str, ...] = ()


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
            raise FiligreeEmitError(f"--filigree-url must use http or https; got scheme {scheme!r} in {url!r}")
        request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:  # noqa: S310
                return Response(status=resp.status, body=read_response_text(resp))
        except urllib.error.HTTPError as exc:
            # An HTTP status reached us — a protocol-level outcome, not an outage. Convert it
            # to a Response so emit() classifies by status (4xx loud / 5xx soft), and close
            # the underlying socket.
            with exc:
                return Response(status=exc.code, body=read_response_text(exc))


class FiligreeEmitter:
    """POST findings to a Filigree Weft scan-results URL with an injectable transport."""

    def __init__(self, url: str, *, transport: Transport | None = None) -> None:
        self._url = url
        self._transport: Transport = transport if transport is not None else UrllibTransport()

    def emit(self, findings: Sequence[Finding], *, scanned_paths: Sequence[str] = ()) -> EmitResult:
        body = json.dumps(build_scan_results_body(findings, scanned_paths=scanned_paths)).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        try:
            resp = self._transport.post(self._url, body, headers)
        except (urllib.error.URLError, OSError):
            # Connection refused / DNS / timeout — sibling absent. Enrichment is
            # non-load-bearing: warn (at the CLI) and continue.
            return EmitResult(reachable=False)
        if resp.status >= 500:
            # Server-side outage — the sibling is degraded, not a Wardline bug. Treat like
            # absent (warn + continue) so a Filigree 503 never makes the gate load-bearing.
            return EmitResult(reachable=False)
        if not 200 <= resp.status < 300:
            # 3xx (a redirect reached the client) or 4xx (request rejected): Wardline sent a
            # request the server would not accept — bad payload / wrong endpoint / auth. Loud.
            raise FiligreeEmitError(f"Filigree rejected scan-results ({resp.status}) at {self._url}: {resp.body}")
        # 2xx success. Parse defensively: a 2xx with an unreadable body means the POST was
        # accepted but the report is unparseable — surface a warning, never crash (charter).
        warnings: list[str] = []
        try:
            parsed = json.loads(resp.body) if resp.body else {}
        except json.JSONDecodeError:
            parsed = None
        payload: dict[str, Any] = parsed if isinstance(parsed, dict) else {}
        if not isinstance(parsed, dict):
            warnings.append(f"Filigree returned {resp.status} with a non-JSON-object body; stats unavailable.")
        raw_stats = payload.get("stats")
        stats: dict[str, Any] = raw_stats if isinstance(raw_stats, dict) else {}
        raw_warnings = payload.get("warnings")
        if isinstance(raw_warnings, list):
            warnings.extend(str(w) for w in raw_warnings)
        failed = payload.get("failed") or []
        return EmitResult(
            reachable=True,
            created=_safe_int(stats.get("findings_created")),
            updated=_safe_int(stats.get("findings_updated")),
            failed=len(failed) if isinstance(failed, list) else 0,
            warnings=tuple(warnings),
        )
