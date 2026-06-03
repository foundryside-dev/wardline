# src/wardline/clarion/client.py
"""SP9: the dep-light HTTP+JSON client for Clarion's /api/wardline/* routes.

Mirrors core/filigree_emit's transport discipline: an injectable Transport (no
test touches the network), and status bands where a sibling-absent/5xx outage is
SOFT (the caller degrades to the SP8 re-run) while a 4xx is a LOUD ClarionError
(Wardline sent a bad request). The split adds: 403 WRITE_DISABLED/PROJECT_MISMATCH
are soft (the store is off / wrong project — not a Wardline bug). The client routes
on the HTTP status band (``>= 500`` and ``403`` are soft; other non-2xx are a loud
ClarionError); the envelope `code` is surfaced only as a label (``disabled_reason``)
and in error-message text, never as the soft-vs-loud decision.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from wardline.clarion._hmac import sign_request
from wardline.core.errors import ClarionError

logger = logging.getLogger(__name__)


_ALLOWED_SCHEMES = ("http", "https")


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: str


class Transport(Protocol):
    def request(self, method: str, url: str, body: bytes, headers: Mapping[str, str]) -> Response: ...


class UrllibTransport:
    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def request(self, method: str, url: str, body: bytes, headers: Mapping[str, str]) -> Response:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise ClarionError(f"--clarion-url must use http or https; got scheme {scheme!r} in {url!r}")
        data = body if body else None
        req = urllib.request.Request(url, data=data, headers=dict(headers), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                return Response(status=resp.status, body=resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            with exc:
                return Response(status=exc.code, body=exc.read().decode("utf-8", "replace"))


@dataclass(frozen=True, slots=True)
class ResolveResult:
    resolved: dict[str, str]
    unresolved: list[str]


@dataclass(frozen=True, slots=True)
class WriteResult:
    reachable: bool
    written: int = 0
    unresolved_qualnames: tuple[str, ...] = ()
    disabled_reason: str | None = None  # "WRITE_DISABLED" / "PROJECT_MISMATCH" when soft-off


@dataclass(frozen=True, slots=True)
class LinkageResult:
    """One entity's call-graph neighbours on one side (callers OR callees), as read
    live from Clarion. ``neighbours`` are Clarion entity ids (locators); ``truncated``
    is Clarion's own pagination flag (surfaced, never silently dropped)."""

    neighbours: tuple[str, ...]
    total: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class TaintFactView:
    qualname: str
    exists: bool
    wardline_json: dict[str, Any] | None = None
    current_content_hash: str | None = None

    @classmethod
    def from_wire(cls, obj: Mapping[str, Any]) -> TaintFactView:
        return cls(
            qualname=str(obj.get("qualname", "")),
            exists=bool(obj.get("exists", False)),
            wardline_json=obj.get("wardline_json"),  # field-absent → None
            current_content_hash=obj.get("current_content_hash"),  # field-absent → None
        )


@dataclass(frozen=True, slots=True)
class TaintFactBySeiView:
    """One row of the T3.4 read-by-SEI response. Keyed on the opaque SEI (not a
    qualname): the rename-stable retrieval surface. The SEI is carried verbatim,
    never parsed."""

    sei: str
    exists: bool
    wardline_json: dict[str, Any] | None = None
    current_content_hash: str | None = None

    @classmethod
    def from_wire(cls, obj: Mapping[str, Any]) -> TaintFactBySeiView:
        return cls(
            sei=str(obj.get("sei", "")),
            exists=bool(obj.get("exists", False)),
            wardline_json=obj.get("wardline_json"),  # field-absent → None
            current_content_hash=obj.get("current_content_hash"),  # field-absent → None
        )


def _chunks(seq: Sequence[Any], size: int) -> Iterator[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _error_code(body: str) -> str | None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    return parsed.get("code") if isinstance(parsed, dict) else None


class ClarionClient:
    def __init__(
        self,
        base_url: str,
        *,
        secret: str | None,
        project: str,
        transport: Transport | None = None,
        batch_max: int = 2000,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._secret = secret
        self._project = project
        self._transport: Transport = transport if transport is not None else UrllibTransport()
        self._batch_max = batch_max

    def _send(self, method: str, path_and_query: str, payload: dict[str, Any] | None) -> Response | None:
        """Sign + send. Returns the Response, or None on a SOFT failure (outage/5xx)."""
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        headers: dict[str, str] = {}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if self._secret:
            sig = sign_request(self._secret, method, path_and_query, body)
            headers["X-Loom-Component"] = f"clarion:{sig}"
        url = f"{self._base}{path_and_query}"
        try:
            resp = self._transport.request(method, url, body, headers)
        except (urllib.error.URLError, OSError):
            return None  # sibling absent — soft
        if resp.status >= 500:
            return None  # server outage — soft
        return resp

    def _require_ok(self, resp: Response, path: str) -> dict[str, Any]:
        """For routes with no soft 4xx: 2xx → parsed dict; anything else → loud."""
        if not 200 <= resp.status < 300:
            raise ClarionError(f"Clarion rejected {path} ({resp.status}; code={_error_code(resp.body)}): {resp.body}")
        try:
            parsed = json.loads(resp.body) if resp.body else {}
        except json.JSONDecodeError:
            parsed = {}
        # A non-dict 2xx body would be a Clarion bug, not a Wardline one; degrade to
        # an empty envelope rather than raising (mirrors filigree_emit's defensiveness).
        return parsed if isinstance(parsed, dict) else {}

    def resolve(self, qualnames: list[str]) -> ResolveResult | None:
        resolved: dict[str, str] = {}
        unresolved: list[str] = []
        for chunk in _chunks(qualnames, self._batch_max):
            payload = {"project": self._project, "qualnames": list(chunk)}
            resp = self._send("POST", "/api/wardline/resolve", payload)
            if resp is None:
                return None
            data = self._require_ok(resp, "/api/wardline/resolve")
            r = data.get("resolved")
            if isinstance(r, dict):
                resolved.update(r)
            u = data.get("unresolved")
            if isinstance(u, list):
                unresolved.extend(str(x) for x in u)
        return ResolveResult(resolved=resolved, unresolved=unresolved)

    def write_taint_facts(self, facts: list[dict[str, Any]]) -> WriteResult:
        """Write facts in 2000-item chunks. Fail-soft: an outage or a 403
        (WRITE_DISABLED/PROJECT_MISMATCH) on any chunk returns a not-reachable
        WriteResult immediately. The write is whole-batch idempotent (per-entity
        replace), so on a mid-batch soft failure earlier chunks may already be
        committed and `written` reflects only chunks that succeeded before the
        first failure — the caller's remedy is to re-run the whole scan/write."""
        written = 0
        unresolved: list[str] = []
        for chunk in _chunks(facts, self._batch_max):
            payload = {"project": self._project, "facts": list(chunk)}
            resp = self._send("POST", "/api/wardline/taint-facts", payload)
            if resp is None:
                return WriteResult(reachable=False)  # soft outage
            if resp.status == 403:
                return WriteResult(reachable=False, disabled_reason=_error_code(resp.body) or "WRITE_DISABLED")
            data = self._require_ok(resp, "/api/wardline/taint-facts")
            written += int(data.get("written", 0) or 0)
            uq = data.get("unresolved_qualnames")
            if isinstance(uq, list):
                unresolved.extend(str(x) for x in uq)
        return WriteResult(reachable=True, written=written, unresolved_qualnames=tuple(unresolved))

    def get_taint_fact(self, qualname: str) -> TaintFactView | None:
        query = urllib.parse.urlencode({"project": self._project, "qualname": qualname})
        paq = f"/api/wardline/taint-facts?{query}"
        resp = self._send("GET", paq, None)
        if resp is None:
            return None
        if resp.status == 403:
            return None  # PROJECT_MISMATCH — soft
        data = self._require_ok(resp, paq)
        return TaintFactView.from_wire(data)

    def batch_get(self, qualnames: list[str]) -> list[TaintFactView] | None:
        views: list[TaintFactView] = []
        for chunk in _chunks(qualnames, self._batch_max):
            payload = {"project": self._project, "qualnames": list(chunk)}
            resp = self._send("POST", "/api/wardline/taint-facts:batch-get", payload)
            if resp is None:
                return None
            if resp.status == 403:
                return None  # PROJECT_MISMATCH — soft
            try:
                parsed = json.loads(resp.body) if resp.body else []
            except json.JSONDecodeError:
                parsed = []
            if not 200 <= resp.status < 300 or not isinstance(parsed, list):
                raise ClarionError(f"Clarion rejected batch-get ({resp.status}; code={_error_code(resp.body)})")
            views.extend(TaintFactView.from_wire(o) for o in parsed if isinstance(o, dict))
        return views

    def batch_get_by_sei(self, seis: list[str]) -> list[TaintFactBySeiView] | None:
        """Read taint facts by their stable opaque SEI (T3.4, migration 0006). The
        rename-survival surface: a fact written under a former locator is retrievable
        here after a rename. Fail-soft like ``batch_get`` — outage/5xx or 403
        PROJECT_MISMATCH → None; a 404 (an older SEI Clarion lacks the route) or other
        non-2xx → loud ClarionError (read-skew). SEIs are sent verbatim, never parsed.

        Gate on :meth:`wardline.clarion.identity.TaintStoreCapability` before calling —
        the route is absent on a pre-0006 Clarion."""
        views: list[TaintFactBySeiView] = []
        for chunk in _chunks(seis, self._batch_max):
            payload = {"project": self._project, "seis": list(chunk)}
            resp = self._send("POST", "/api/wardline/taint-facts/by-sei", payload)
            if resp is None:
                return None
            if resp.status == 403:
                return None  # PROJECT_MISMATCH — soft
            try:
                parsed = json.loads(resp.body) if resp.body else []
            except json.JSONDecodeError:
                parsed = []
            if not 200 <= resp.status < 300 or not isinstance(parsed, list):
                raise ClarionError(f"Clarion rejected by-sei ({resp.status}; code={_error_code(resp.body)})")
            views.extend(TaintFactBySeiView.from_wire(o) for o in parsed if isinstance(o, dict))
        return views

    # --- SEI identity wire (Track 3 T3.1) ------------------------------------
    # The pinned /api/v1/identity/* + /api/v1/_capabilities routes (SEI standard §4,
    # Clarion ADR-038). These are the IDENTITY READ path: they FAIL-SOFT on every
    # non-happy band (a pre-SEI Clarion 404s the routes / advertises no `sei` cap), so
    # a consumer can detect a non-SEI Clarion and DEGRADE rather than guess or crash.
    # Distinct from the WRITE path, where a 4xx is a loud Wardline bug.

    def _send_json_soft(
        self, method: str, path_and_query: str, payload: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        """Send + parse a JSON object, FAIL-SOFT on every non-happy band. Returns the
        parsed dict on a 2xx with a JSON-object body; None on outage/5xx (``_send``),
        any other non-2xx (e.g. a pre-SEI Clarion's 404, a 4xx), or a non-object/bad
        body. Never routes through ``_require_ok`` (which raises on non-2xx)."""
        resp = self._send(method, path_and_query, payload)
        if resp is None:
            return None
        if not 200 <= resp.status < 300:
            if resp.status != 404:
                logger.warning(
                    "Clarion identity read returned status %d for path %s: %s",
                    resp.status,
                    path_and_query,
                    resp.body,
                )
            return None
        try:
            parsed = json.loads(resp.body) if resp.body else {}
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def capabilities(self) -> dict[str, Any] | None:
        """GET /api/v1/_capabilities → the parsed capability dict, or None when the
        probe fails for ANY reason (a pre-SEI Clarion 404s the route). Lets a consumer
        detect a non-SEI Clarion and degrade rather than guess."""
        return self._send_json_soft("GET", "/api/v1/_capabilities", None)

    def resolve_identity(self, locator: str) -> dict[str, Any] | None:
        """POST /api/v1/identity/resolve {locator} → {sei, current_locator,
        content_hash, alive:true} or {alive:false}; None on a soft failure. ``locator``
        is a Wardline-side address (qualname-form), never an SEI."""
        return self._send_json_soft("POST", "/api/v1/identity/resolve", {"locator": locator})

    def resolve_sei(self, sei: str) -> dict[str, Any] | None:
        """GET /api/v1/identity/sei/{sei} → {current_locator, content_hash, alive:true}
        or {alive:false, lineage:[...]}; None on a soft failure. ``sei`` is OPAQUE — it
        is only URL-escaped for the path segment, never parsed or interpreted."""
        quoted = urllib.parse.quote(sei, safe="")
        return self._send_json_soft("GET", f"/api/v1/identity/sei/{quoted}", None)

    # --- call-graph linkages (Track 4 T4.3) ----------------------------------
    # GET /api/v1/entities/{entity_id}/callers|callees (Clarion Wave 0 / WS2). HMAC-
    # gated like /api/v1/files; FAIL-SOFT on every non-happy band (a pre-linkage
    # Clarion 404s the route; an unknown entity 404s; an outage 5xx → None), so the
    # dossier degrades to an honest `unavailable` linkages section rather than crashing.

    def _get_linkages(self, entity_id: str, direction: str, limit: int) -> LinkageResult | None:
        quoted = urllib.parse.quote(entity_id, safe="")
        query = urllib.parse.urlencode({"limit": limit})
        data = self._send_json_soft("GET", f"/api/v1/entities/{quoted}/{direction}?{query}", None)
        if data is None:
            return None
        rows = data.get(direction)
        rows = rows if isinstance(rows, list) else []
        neighbours = tuple(
            str(r["entity_id"]) for r in rows if isinstance(r, dict) and isinstance(r.get("entity_id"), str)
        )
        total = data.get("total")
        return LinkageResult(
            neighbours=neighbours,
            # accept int or a JSON float; any other shape → fall back to the count read
            total=int(total) if isinstance(total, (int, float)) and not isinstance(total, bool) else len(neighbours),
            truncated=bool(data.get("truncated", False)),
        )

    def get_callers(self, entity_id: str, *, limit: int = 50) -> LinkageResult | None:
        """Inbound callers of ``entity_id`` (a Clarion locator), or None on a soft
        failure / unknown entity / pre-linkage Clarion. ``entity_id`` is URL-escaped
        into the path, never parsed."""
        return self._get_linkages(entity_id, "callers", limit)

    def get_callees(self, entity_id: str, *, limit: int = 50) -> LinkageResult | None:
        """Outbound callees of ``entity_id``; same fail-soft contract as
        :meth:`get_callers`."""
        return self._get_linkages(entity_id, "callees", limit)
