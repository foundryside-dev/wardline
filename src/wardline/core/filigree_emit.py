# src/wardline/core/filigree_emit.py
"""Native Filigree scan-results emission (SP4b).

A pure body builder (``build_scan_results_body``) plus an injectable-transport
HTTP emitter (``FiligreeEmitter``). stdlib-only; no runtime dependency on Filigree.
Federation discipline: a *sibling-absent* network failure warns and continues; a 5xx
outage and a 401/403 (Filigree present but refusing bearer auth) are likewise treated
as *enrichment unavailable* (warn + continue). A 400 (Wardline built a bad payload) is
the one loud band — that is our own bug, not the sibling's posture.
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
from wardline.core.finding import (
    FINGERPRINT_SCHEME,
    UNANALYZED_RULE_IDS,
    Finding,
    format_fingerprint,
    severity_to_filigree,
    to_filigree_metadata,
)
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
        "fingerprint": format_fingerprint(FINGERPRINT_SCHEME, finding.fingerprint),
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
    close-on-fixed can reconcile a file whose last finding disappeared.

    If any file was discovered but not analyzed, do not run the absent-fingerprint
    sweep: a parse/file failure means missing findings are not proof of a fix.
    """
    findings_wire = [_finding_to_wire(f) for f in findings]
    scanned = list(dict.fromkeys(p for p in scanned_paths if p))
    has_unanalyzed = any(f.rule_id in UNANALYZED_RULE_IDS for f in findings)
    body = {
        "scan_source": scan_source,
        "fingerprint_scheme": FINGERPRINT_SCHEME,
        "mark_unseen": bool(findings_wire or scanned) and not has_unanalyzed,
        "findings": findings_wire,
    }
    if scanned:
        body["scanned_paths"] = scanned
    return body


# --- destination echo (N1 / C-10(a)) -----------------------------------------


def filigree_url_project(url: str | None) -> str | None:
    """The destination project pinned in a Filigree Weft URL, or None when none is pinned.

    An unpinned URL means Filigree resolves the project server-side (ambient/default) — the
    silent-misroute shape behind the lacuna→filigree contamination. Recognizes both the
    ``?project=<p>`` query and the ``/api/p/<p>/`` path conventions."""
    if not url:
        return None
    parts = urllib.parse.urlsplit(url)
    project = urllib.parse.parse_qs(parts.query).get("project", [None])[0]
    if project:
        return project
    segments = [s for s in parts.path.split("/") if s]
    for i, seg in enumerate(segments):
        if seg == "p" and i + 1 < len(segments):
            return segments[i + 1]
    return None


def filigree_destination(url: str | None) -> dict[str, Any]:
    """The destination echo for the emit status block (N1 / C-10(a)): name where findings
    were sent so a wrong-project write is visible at the caller instead of reading as
    success. ``project_pinned`` is False when Filigree will resolve the project itself."""
    project = filigree_url_project(url)
    return {"url": url, "project": project, "project_pinned": project is not None}


def filigree_api_base_url(url: str) -> str:
    """Normalize any accepted Filigree URL form — bare origin, ``/api`` base, or a
    classic / project-scoped ``…/weft/scan-results`` endpoint, with or without
    ``?project=`` — to the API base every sibling route derives from.

    When the input pins a project (either dialect), the base is the path-scoped
    ``…/api/p/<key>`` form: Filigree dual-mounts every route under it, whereas the
    ``?project=`` query is honored only on weft-scoped paths — so the path dialect is
    the only one that also scopes classic routes (entity-associations, the dossier
    work-join). The single parser exists so the emit echo, the promote route, and the
    work-join can never disagree about what one configured URL means (dogfood-4 A3/A4)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        raise FiligreeEmitError(f"filigree URL must use http or https; got scheme {parts.scheme!r} in {url!r}")
    segments = [s for s in parts.path.split("/") if s]
    base = segments[: segments.index("api") + 1] if "api" in segments else [*segments, "api"]
    project = filigree_url_project(url)
    if project is not None and base[-2:] != ["p", project]:
        base += ["p", project]
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, "/" + "/".join(base), "", ""))


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
    # Discriminate WHY enrichment was unavailable so the caller can say the actionable
    # thing instead of a flat "could not reach" (dogfood #5). ``status`` is the HTTP status
    # for the SOFT-failure sub-cases — 401/403 (auth refused) or 5xx (outage) — and None for
    # both a transport failure (connection refused / DNS / timeout — genuinely unreachable)
    # and a 2xx success. It is the *error* status: a reached/success result carries none.
    # All of these stay SOFT (reachable=False); only the message differs.
    status: int | None = None
    # Whether a bearer token was actually sent on the attempt. A 401 means different things
    # by this flag: token_sent=False → none configured (set one); token_sent=True → the value
    # was REJECTED (it is wrong; align it to the canonical source). The original "set
    # WEFT_FEDERATION_TOKEN" message implied absence and is what steered F1's wrong root-cause
    # (weft-23574069a1 / C-7). ``url`` is the endpoint attempted, so the actionable message can
    # name WHERE it tried without the caller threading it separately.
    token_sent: bool = False
    url: str | None = None

    @property
    def auth_rejected(self) -> bool:
        # The 401/403 case: present-but-refusing-bearer-auth. Derived from ``status`` rather
        # than stored as an independent field so the two can never disagree (an
        # "auth-rejected (200)" is unrepresentable, not merely unbuilt by the producer).
        return self.status in (401, 403)

    def __post_init__(self) -> None:
        # Mirror GateDecision's construction-time guard so a second constructor cannot
        # express a contradictory outcome: a reached/success result carries no error status,
        # and a soft-failure (unreachable) created/updated/failed nothing.
        if self.reachable and self.status is not None:
            raise ValueError(f"a reachable EmitResult carries no error status (got {self.status})")
        if not self.reachable and (self.created or self.updated or self.failed):
            raise ValueError("an unreachable EmitResult must have zero created/updated/failed")


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Outcome of an auth probe (verify_token). ``accepted`` is True when the daemon
    authenticated the bearer (any non-401/403 status, e.g. a 400 from the sentinel body).
    ``reachable`` is False only on a transport failure (connection refused / timeout)."""

    reachable: bool
    accepted: bool
    status: int | None = None


def filigree_disabled_reason(
    *, reachable: bool, status: int | None, token_sent: bool = False, url: str | None = None
) -> str | None:
    """The ``disabled_reason`` for an emit attempt, or None when Filigree was reached.

    Single source of the auth-rejected (401/403) vs server-error (5xx) vs unreachable
    (transport failure) ladder (dogfood #5), shared by the CLI and MCP status blocks so
    the two surfaces can never drift. The CLI's human stderr wording (which embeds the
    URL and ".env" hint) is intentionally separate.

    Auth-rejection is DERIVED from ``status`` here exactly as :attr:`EmitResult.auth_rejected`
    derives it, so the helper cannot be handed a contradictory ``auth_rejected`` flag that
    disagrees with the status (the inconsistent triple the standalone signature once allowed).
    ``reachable`` remains an input because ``status is None`` is ambiguous on its own — it
    means EITHER a 2xx success (reachable) OR a transport failure (unreachable).
    """
    if reachable:
        return None
    at = f" at {url}" if url else ""
    if status in (401, 403):
        # 403 → token present but lacks access (a token won't help). 401 → split by whether a
        # token was actually SENT: absent (set one) vs rejected (the value is wrong). The old
        # flat "set WEFT_FEDERATION_TOKEN" implied absence even when a token was sent and
        # rejected — the C-7 misdiagnosis (weft-23574069a1).
        if status == 403:
            return f"filigree forbidden (403){at}; token present but lacks access / blocked"
        if token_sent:
            return (
                f"filigree rejected the token (401){at}; a token WAS sent but its value is wrong — "
                "align WEFT_FEDERATION_TOKEN (env or .env) to the canonical federation token"
            )
        return f"filigree auth-rejected (401){at}; no token sent — set WEFT_FEDERATION_TOKEN (env or .env)"
    if status is not None:
        return f"filigree server error ({status}){at}"
    return f"filigree unreachable{at}"


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

    def __init__(self, url: str, *, transport: Transport | None = None, token: str | None = None) -> None:
        self._url = url
        self._transport: Transport = transport if transport is not None else UrllibTransport()
        self._token = token

    def emit(self, findings: Sequence[Finding], *, scanned_paths: Sequence[str] = ()) -> EmitResult:
        body = json.dumps(build_scan_results_body(findings, scanned_paths=scanned_paths)).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        token_sent = bool(self._token)
        if token_sent:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            resp = self._transport.post(self._url, body, headers)
        except (urllib.error.URLError, OSError):
            # Connection refused / DNS / timeout — sibling absent. Enrichment is
            # non-load-bearing: warn (at the CLI) and continue. No status reached us, so
            # this is the genuine "could not reach" case (status=None).
            return EmitResult(reachable=False, token_sent=token_sent, url=self._url)
        if resp.status in (401, 403):
            # Filigree is present but its opt-in bearer auth is on and refusing us. Stays
            # SOFT (enrichment unavailable, never exit-2) — but distinguished as auth (and by
            # token_sent: no-token vs token-rejected) so the caller can say the actionable
            # thing instead of "could not reach".
            return EmitResult(reachable=False, status=resp.status, token_sent=token_sent, url=self._url)
        if resp.status >= 500:
            # Server-side outage (5xx) — the sibling is degraded, not a Wardline payload bug.
            # Treat like absent (warn + continue), carrying the status for an honest message.
            return EmitResult(reachable=False, status=resp.status, token_sent=token_sent, url=self._url)
        if not 200 <= resp.status < 300:
            # 3xx (a redirect reached the client) or any remaining 4xx (notably 400): Wardline
            # sent a request the server would not accept — bad payload / wrong endpoint. Loud.
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
            token_sent=token_sent,
            url=self._url,
        )

    def verify_token(self) -> ProbeResult:
        """Probe whether the daemon accepts this emitter's bearer token, WITHOUT
        recording anything. Auth runs in middleware before body validation, so a
        deliberately-incomplete sentinel body yields 400 (auth passed) or 401/403
        (rejected). Never reuses emit() — that would POST a valid empty scan."""
        body = b"{}"  # parses as JSON, missing required scan-results fields => 400 when authed
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            resp = self._transport.post(self._url, body, headers)
        except (urllib.error.URLError, OSError):
            return ProbeResult(reachable=False, accepted=False)
        accepted = resp.status not in (401, 403)
        return ProbeResult(reachable=True, accepted=accepted, status=resp.status)
