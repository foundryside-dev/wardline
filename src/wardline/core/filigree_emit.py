# src/wardline/core/filigree_emit.py
"""Native Filigree scan-results emission (SP4b).

A pure body builder (``build_scan_results_body``) plus an injectable-transport
HTTP emitter (``FiligreeEmitter``). stdlib-only; no runtime dependency on Filigree.
Federation discipline: a *sibling-absent* network failure warns and continues; a 5xx
outage and a 401/403 (Filigree present but refusing bearer auth) are likewise treated
as *enrichment unavailable* (warn + continue). Client/protocol errors default loud
for callers that need strict reconciliation, but `wardline scan` opts into fail-soft
enrichment so an upload reject cannot preempt the local gate verdict.
"""

from __future__ import annotations

import json
import os
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
_DEFAULT_MAX_FINDINGS_PER_REQUEST = 1000
_MAX_FINDINGS_ENV = "WARDLINE_FILIGREE_MAX_FINDINGS_PER_REQUEST"


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
    mark_unseen: bool | None = None,
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
    if mark_unseen is None:
        mark_unseen = bool(findings_wire or scanned) and not has_unanalyzed
    body = {
        "scan_source": scan_source,
        "fingerprint_scheme": FINGERPRINT_SCHEME,
        "mark_unseen": bool(mark_unseen) and not has_unanalyzed,
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


# The machine-readable reason vocabulary for a per-finding emit failure (PDR-0023, the
# honesty invariant). A degraded ``failed`` entry MUST distinguish these cases so a caller
# can tell "M of N emitted, K rejected because <reason>" from a clean true-negative — a bare
# count cannot. The set mirrors the invariant's emit-side cases:
#   rejected         — Filigree accepted the request but refused this finding (its own report).
#   validation_error — the finding body was malformed/unprocessable (Filigree said why).
#   scheme_mismatch  — the fingerprint scheme Filigree expects differs from what we sent
#                      (a wlfp2→wlfp3 drift would join-miss; never read as a real true-negative).
#   partial          — the whole chunk was rejected at the protocol layer (fail-soft emit), so
#                      every finding in it is un-ingested; the cause is the chunk, not the body.
_FAILURE_REASONS = frozenset({"rejected", "validation_error", "scheme_mismatch", "partial"})

# --- weft-reason vocabulary conformance (G1) ---------------------------------
# The canonical, cross-member reason vocabulary is the closed set of 11 reason_classes
# defined in /home/john/weft/contracts/weft-reason-vocab.json (relative to the suite hub:
# contracts/weft-reason-vocab.json). Every NON-clean federation carrier MUST emit a
# reason_class drawn from that closed set, plus a cause and a fix; a clean carrier omits
# cause+fix. wardline's shipped emit-failure ``reason`` field predates the canonical
# vocabulary and is NOT renamed (it is on the wire and consumed by the CLI/MCP/scan-job
# status blocks). Instead each shipped ``reason`` maps ADDITIVELY onto a canonical
# reason_class, keeping the domain term in ``reason``/``cause`` so the wire stays
# backward-compatible while becoming G1-conformant.
#
#   rejected         -> rejected         (peer reached, refused the item)
#   validation_error -> rejected         (peer reached, refused a malformed body — peer-side
#                                         refusal, not an internal wardline fault, so 'rejected'
#                                         not 'error'; the domain term survives in cause)
#   scheme_mismatch  -> scheme_mismatch  (identity/fingerprint scheme drift — join-miss risk)
#   partial          -> partial          (chunk-wide bounded/some-failed ingest)
_REASON_CLASS_BY_REASON: dict[str, str] = {
    "rejected": "rejected",
    "validation_error": "rejected",
    "scheme_mismatch": "scheme_mismatch",
    "partial": "partial",
}

# The mandatory ``fix`` for each canonical class a FailedFinding can carry (carrier rule:
# every non-clean carrier includes a fix). Keyed by the domain ``reason`` so a more specific
# remedy can be given than the class alone allows (validation_error vs a bare rejection).
_FIX_BY_REASON: dict[str, str] = {
    "rejected": "inspect the per-finding reject cause in Filigree's report and re-emit once the finding is acceptable",
    "validation_error": "correct the malformed finding body Filigree reported, then re-emit",
    "scheme_mismatch": "align the wardline fingerprint scheme to the scheme Filigree expects, then re-emit (a drift join-misses)",
    "partial": "resolve the chunk-level rejection (see cause/status), then re-emit the un-ingested findings",
}


@dataclass(frozen=True, slots=True)
class FailedFinding:
    """One finding that did not land in Filigree, with a machine-readable reason.

    PDR-0023: the honesty surface of the emit seam. A clean run yields an empty
    ``failures`` tuple — but that emptiness is now EARNED (no finding failed) rather
    than a hardwired count, and a partial ingest names which findings failed and why,
    so "all N emitted" is distinguishable from "M of N emitted, K rejected because R".
    ``fingerprint`` is the wardline join key when Filigree reported it (None when the
    failure is chunk-wide and not attributable to a single finding).

    weft-reason (G1): a FailedFinding is always a NON-clean carrier, so it exposes the
    canonical carrier triple {reason_class, cause, fix} (see ``to_wire``) ALONGSIDE the
    shipped domain ``reason``/``detail`` fields. ``reason_class`` is one of the canonical
    11 (contracts/weft-reason-vocab.json); the domain term stays in ``reason``/``cause``."""

    reason: str
    detail: str = ""
    fingerprint: str | None = None

    def __post_init__(self) -> None:
        if self.reason not in _FAILURE_REASONS:
            raise ValueError(f"unknown emit-failure reason {self.reason!r}; expected one of {sorted(_FAILURE_REASONS)}")

    @property
    def reason_class(self) -> str:
        """The canonical weft-reason class (one of the 11) this domain ``reason`` maps to."""
        return _REASON_CLASS_BY_REASON[self.reason]

    @property
    def cause(self) -> str:
        """The carrier ``cause``: the human-readable why. Filigree's ``detail`` when present,
        else the domain ``reason`` itself (a FailedFinding is never clean, so cause is always
        non-empty)."""
        return self.detail or self.reason

    @property
    def fix(self) -> str:
        """The carrier ``fix`` (MANDATORY on a non-clean carrier): the remedial action."""
        return _FIX_BY_REASON[self.reason]

    def to_wire(self) -> dict[str, Any]:
        # Shipped fields (reason/detail) are preserved verbatim; the canonical weft-reason
        # carrier triple {reason_class, cause, fix} is ADDED alongside (G1, additive/non-breaking).
        wire: dict[str, Any] = {
            "reason": self.reason,
            "detail": self.detail,
            "reason_class": self.reason_class,
            "cause": self.cause,
            "fix": self.fix,
        }
        if self.fingerprint is not None:
            wire["fingerprint"] = self.fingerprint
        return wire


@dataclass(frozen=True, slots=True)
class EmitResult:
    reachable: bool
    created: int = 0
    updated: int = 0
    # Per-finding emit failures, each carrying a machine-readable reason (PDR-0023). The
    # scalar ``failed`` count is DERIVED from this so the two can never disagree — the same
    # construction-time-consistency idiom as ``auth_rejected`` over ``status`` below. A
    # hardwired ``failed=0`` is now unrepresentable: the count is earned from real records.
    failures: tuple[FailedFinding, ...] = ()
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
    def failed(self) -> int:
        # The count of findings that did not land, DERIVED from ``failures`` so a caller's
        # "K failed" can never disagree with "here are the K reasons". Preserves every existing
        # integer-count consumer (CLI line, status blocks, scan-job enrichment gate) while the
        # honest detail lives in ``failures``.
        return len(self.failures)

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


@dataclass(frozen=True, slots=True)
class _ScanResultChunk:
    findings: tuple[Finding, ...]
    scanned_paths: tuple[str, ...]
    mark_unseen: bool


def _scan_result_chunks(
    findings: Sequence[Finding],
    scanned_paths: Sequence[str],
    max_findings_per_request: int,
) -> tuple[_ScanResultChunk, ...]:
    """Split large emits without corrupting Filigree's per-file unseen sweep.

    Filigree's ``mark_unseen`` reconciliation is scoped to scanned file paths, so a
    chunk must carry a complete set of findings for every path it names. Most large
    scans can be chunked by whole-file groups. If one file alone exceeds the cap, the
    file has to be split and reconciliation is disabled only for those chunks.
    """
    if max_findings_per_request < 1:
        raise ValueError("max_findings_per_request must be at least 1")

    deduped_scanned_paths = tuple(dict.fromkeys(p for p in scanned_paths if p))
    can_mark_unseen = not any(f.rule_id in UNANALYZED_RULE_IDS for f in findings)
    if len(findings) <= max_findings_per_request:
        return (
            _ScanResultChunk(
                tuple(findings),
                deduped_scanned_paths,
                bool(findings or deduped_scanned_paths) and can_mark_unseen,
            ),
        )

    by_path: dict[str, list[Finding]] = {}
    path_order: list[str] = []
    for finding in findings:
        path = finding.location.path or ""
        if path not in by_path:
            by_path[path] = []
            path_order.append(path)
        by_path[path].append(finding)

    chunks: list[_ScanResultChunk] = []
    current_findings: list[Finding] = []
    current_paths: list[str] = []
    paths_with_findings = set(path_order)
    clean_scanned_paths = [p for p in deduped_scanned_paths if p not in paths_with_findings]

    def flush_current() -> None:
        nonlocal current_findings, current_paths
        if current_findings or current_paths:
            chunks.append(
                _ScanResultChunk(
                    tuple(current_findings),
                    tuple(dict.fromkeys(current_paths)),
                    bool(current_findings or current_paths) and can_mark_unseen,
                )
            )
        current_findings = []
        current_paths = []

    for path in path_order:
        group = by_path[path]
        if len(group) > max_findings_per_request:
            flush_current()
            for start in range(0, len(group), max_findings_per_request):
                # Complete-file reconciliation is impossible for this path under the cap.
                chunks.append(_ScanResultChunk(tuple(group[start : start + max_findings_per_request]), (path,), False))
            continue
        if current_findings and len(current_findings) + len(group) > max_findings_per_request:
            flush_current()
        current_findings.extend(group)
        if path:
            current_paths.append(path)

    current_paths.extend(clean_scanned_paths)
    flush_current()
    return tuple(chunks)


def _normalize_failure_reason(raw: Any) -> str:
    """Map a Filigree-reported per-finding reason onto the honesty vocabulary.

    Filigree's reject report is not contractually frozen to our reason set, so an
    unrecognized (or absent) reason degrades to ``rejected`` — the honest "Filigree
    refused this finding but did not say a more specific why" — rather than being
    dropped. A drift-shaped reason (the scheme-mismatch the seam-health map flags as
    the join-miss that cascade-closes issues) is recognized so an agent can tell a
    fingerprint-scheme drift from a routine rejection."""
    if not isinstance(raw, str):
        return "rejected"
    token = raw.strip().lower().replace("-", "_").replace(" ", "_")
    if token in _FAILURE_REASONS:
        return token
    if "scheme" in token and ("mismatch" in token or "drift" in token or "unknown" in token):
        return "scheme_mismatch"
    if "valid" in token or "schema" in token or "unprocessable" in token:
        return "validation_error"
    return "rejected"


def _parse_failed_entry(entry: Any) -> FailedFinding:
    """Coerce one element of Filigree's ``failed`` array into a FailedFinding.

    Filigree reports rejects as objects (``{"fingerprint": ..., "reason": ..., ...}``)
    but tolerates a bare id string for forward/backward wire compatibility. Either way a
    machine-readable reason is preserved (defaulting to ``rejected``) so a partial ingest
    is never flattened back into an opaque count."""
    if isinstance(entry, Mapping):
        fingerprint = entry.get("fingerprint") or entry.get("id")
        detail = entry.get("detail") or entry.get("message") or entry.get("error") or ""
        return FailedFinding(
            reason=_normalize_failure_reason(entry.get("reason")),
            detail=str(detail),
            fingerprint=str(fingerprint) if fingerprint is not None else None,
        )
    # A bare scalar (id string): Filigree refused it but gave no structured reason.
    return FailedFinding(reason="rejected", fingerprint=str(entry) if entry is not None else None)


def _parse_success_response(resp: Response) -> EmitResult:
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
    raw_failed = payload.get("failed")
    # PDR-0023: preserve Filigree's PER-FINDING reject reasons instead of flattening to a
    # count. A 2xx where Filigree silently dropped K findings is now distinguishable from a
    # clean emit — the empty ``failures`` tuple is earned, not assumed.
    failures = tuple(_parse_failed_entry(e) for e in raw_failed) if isinstance(raw_failed, list) else ()
    return EmitResult(
        reachable=True,
        created=_safe_int(stats.get("findings_created")),
        updated=_safe_int(stats.get("findings_updated")),
        failures=failures,
        warnings=tuple(warnings),
    )


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

    def get(self, url: str, headers: Mapping[str, str]) -> Response:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise FiligreeEmitError(f"filigree URL must use http or https; got scheme {scheme!r} in {url!r}")
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:  # noqa: S310
                return Response(status=resp.status, body=read_response_text(resp))
        except urllib.error.HTTPError as exc:
            with exc:
                return Response(status=exc.code, body=read_response_text(exc))


def _resolve_operator_max_findings_per_request(explicit: int | None) -> int | None:
    if explicit is not None:
        if explicit < 1:
            raise ValueError("max_findings_per_request must be at least 1")
        return explicit
    raw = os.environ.get(_MAX_FINDINGS_ENV)
    if raw:
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError(f"{_MAX_FINDINGS_ENV} must be an integer") from exc
        if value < 1:
            raise ValueError(f"{_MAX_FINDINGS_ENV} must be at least 1")
        return value
    return None


def _limit_from_mapping(node: Mapping[str, Any]) -> int | None:
    for key in (
        "max_findings_per_request",
        "max_findings",
        "findings_per_request",
        "findings_per_request_limit",
        "finding_limit",
        "findings_limit",
    ):
        value = node.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    for nested_key in ("limits", "request_limits", "chunking_guidance", "scan_results"):
        nested = node.get(nested_key)
        if isinstance(nested, Mapping):
            found = _limit_from_mapping(nested)
            if found is not None:
                return found
    return None


def _is_scan_results_node(key: str, node: Mapping[str, Any]) -> bool:
    haystacks = [key]
    for field in ("path", "url", "endpoint", "route", "name"):
        value = node.get(field)
        if isinstance(value, str):
            haystacks.append(value)
    return any("scan-results" in item or "scan_results" in item for item in haystacks)


def _extract_scan_results_limit(schema: Mapping[str, Any]) -> int | None:
    for key in ("scan_results", "scan-results", "scan_results_limits", "scan-results-limits"):
        value = schema.get(key)
        if isinstance(value, Mapping):
            found = _limit_from_mapping(value)
            if found is not None:
                return found

    endpoints = schema.get("endpoints")
    if isinstance(endpoints, Mapping):
        for key, value in endpoints.items():
            if isinstance(value, Mapping) and _is_scan_results_node(str(key), value):
                found = _limit_from_mapping(value)
                if found is not None:
                    return found
    elif isinstance(endpoints, list):
        for value in endpoints:
            if isinstance(value, Mapping) and _is_scan_results_node("", value):
                found = _limit_from_mapping(value)
                if found is not None:
                    return found
    return None


def _scan_results_schema_url(url: str) -> str:
    return f"{filigree_api_base_url(url).rstrip('/')}/files/_schema"


def _fetch_scan_results_limit(url: str, transport: Transport, headers: Mapping[str, str]) -> int | None:
    get = getattr(transport, "get", None)
    if get is None:
        return None
    try:
        resp = get(_scan_results_schema_url(url), headers)
    except (FiligreeEmitError, urllib.error.URLError, OSError, json.JSONDecodeError):
        return None
    if not 200 <= resp.status < 300:
        return None
    try:
        parsed = json.loads(resp.body) if resp.body else {}
    except json.JSONDecodeError:
        return None
    return _extract_scan_results_limit(parsed) if isinstance(parsed, Mapping) else None


class FiligreeEmitter:
    """POST findings to a Filigree Weft scan-results URL with an injectable transport."""

    def __init__(
        self,
        url: str,
        *,
        transport: Transport | None = None,
        token: str | None = None,
        max_findings_per_request: int | None = None,
        protocol_errors_loud: bool = True,
    ) -> None:
        self._url = url
        self._transport: Transport = transport if transport is not None else UrllibTransport()
        self._token = token
        self._operator_max_findings_per_request = _resolve_operator_max_findings_per_request(max_findings_per_request)
        self._protocol_errors_loud = protocol_errors_loud

    def emit(self, findings: Sequence[Finding], *, scanned_paths: Sequence[str] = ()) -> EmitResult:
        headers = {"Content-Type": "application/json"}
        token_sent = bool(self._token)
        if token_sent:
            headers["Authorization"] = f"Bearer {self._token}"
        max_findings_per_request = (
            self._operator_max_findings_per_request
            or _fetch_scan_results_limit(self._url, self._transport, headers)
            or _DEFAULT_MAX_FINDINGS_PER_REQUEST
        )
        chunks = list(_scan_result_chunks(findings, scanned_paths, max_findings_per_request))
        created = 0
        updated = 0
        failures: list[FailedFinding] = []
        warnings: list[str] = []
        try:
            for chunk_index, chunk in enumerate(chunks, start=1):
                body = json.dumps(
                    build_scan_results_body(
                        chunk.findings,
                        scanned_paths=chunk.scanned_paths,
                        mark_unseen=chunk.mark_unseen,
                    )
                ).encode("utf-8")
                resp = self._transport.post(self._url, body, headers)
                if resp.status in (401, 403):
                    # Filigree is present but its opt-in bearer auth is on and refusing us.
                    # Stays SOFT (enrichment unavailable, never exit-2) — but distinguished
                    # as auth so the caller can say the actionable thing.
                    return EmitResult(reachable=False, status=resp.status, token_sent=token_sent, url=self._url)
                if resp.status >= 500:
                    # Server-side outage (5xx) — the sibling is degraded, not a Wardline
                    # payload bug. Treat like absent (warn + continue), carrying the status.
                    return EmitResult(reachable=False, status=resp.status, token_sent=token_sent, url=self._url)
                if not 200 <= resp.status < 300:
                    message = f"Filigree rejected scan-results ({resp.status}) at {self._url}: {resp.body}"
                    if self._protocol_errors_loud:
                        raise FiligreeEmitError(message)
                    # Fail-soft: the chunk (and every chunk after it) is un-ingested. PDR-0023 —
                    # record EACH still-pending finding as a ``partial`` failure carrying the
                    # rejecting status, so the caller reads "K findings failed because the chunk
                    # was rejected (<status>)" instead of an opaque count that looks like success
                    # minus a number. ``partial`` (chunk-wide) is named distinctly from a
                    # per-finding ``rejected`` because the cause is the request, not the body.
                    detail = f"chunk rejected at protocol layer ({resp.status}): {resp.body}"
                    for pending_chunk in chunks[chunk_index - 1 :]:
                        for finding in pending_chunk.findings:
                            failures.append(
                                FailedFinding(
                                    reason="partial",
                                    detail=detail,
                                    fingerprint=format_fingerprint(FINGERPRINT_SCHEME, finding.fingerprint),
                                )
                            )
                    warnings.append(message)
                    break
                chunk_result = _parse_success_response(resp)
                created += chunk_result.created
                updated += chunk_result.updated
                failures.extend(chunk_result.failures)
                warnings.extend(chunk_result.warnings)
        except (urllib.error.URLError, OSError):
            # Connection refused / DNS / timeout — sibling absent. Enrichment is
            # non-load-bearing: warn (at the CLI) and continue. No status reached us, so
            # this is the genuine "could not reach" case (status=None).
            return EmitResult(reachable=False, token_sent=token_sent, url=self._url)
        return EmitResult(
            reachable=True,
            created=created,
            updated=updated,
            failures=tuple(failures),
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
