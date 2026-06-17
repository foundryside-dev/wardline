# src/wardline/core/filigree_issue.py
"""WS-A2: file ONE finding (by fingerprint) into a tracked Filigree issue, fail-soft.

Sibling of core/filigree_emit.py: same injectable-transport, same fail-soft charter
(sibling-absent / 5xx / 401 / 403 warn-and-continue; a 400 is a Wardline-bad-payload bug
and is loud). Talks the Weft HTTP promote-by-fingerprint route; imports no Filigree
package. A 404 means the fingerprint was never ingested for this scan_source (the agent
should emit findings to Filigree first) — surfaced as `not_found`, not an exception. A
401/403 means Filigree's opt-in bearer auth is on and refusing us — enrichment is
unavailable (like an outage), surfaced as not-reachable, not an exception."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_emit import filigree_api_base_url
from wardline.core.finding import FINGERPRINT_SCHEME, format_fingerprint
from wardline.core.http import read_response_text
from wardline.loomweave.identity import SeiResolver

_ALLOWED_SCHEMES = ("http", "https")


def promote_url_from_weft(weft_url: str) -> str:
    """Derive the promote route from the configured Filigree URL. Accepts every form
    ``filigree_api_base_url`` does; a pinned project (``/api/p/<key>/…`` path or
    ``?project=`` query) is preserved as the path-scoped dialect, so a scoped emit
    config can no longer promote into the default project (dogfood-4 A3)."""
    return api_base_url_from_weft(weft_url) + "/weft/findings/promote"


def api_base_url_from_weft(weft_url: str) -> str:
    """Normalize the configured Filigree URL to its API base — project-scoped when the
    input pins a project. Thin alias over the shared dialect parser in
    ``core/filigree_emit.py`` so every derived route agrees with the emit destination."""
    return filigree_api_base_url(weft_url)


def build_promote_body(
    *,
    fingerprint: str,
    scan_source: str = "wardline",
    priority: str | None = None,
    labels: Sequence[str] | None = None,
) -> dict[str, Any]:
    # The promote join key MUST match the form the scan-results INGEST wire writes
    # (filigree_emit._finding_to_wire emits the scheme-prefixed value), or Filigree's
    # exact-match promote lookup 404s against the finding it just ingested. Callers
    # pass the BARE in-memory fingerprint (agent_summary / CLI arg); we prefix it here
    # at the wire boundary, symmetric with ingest.
    body: dict[str, Any] = {
        "scan_source": scan_source,
        "fingerprint": format_fingerprint(FINGERPRINT_SCHEME, fingerprint),
    }
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


@dataclass(frozen=True, slots=True)
class IdentityAttachResult:
    attempted: bool
    attached: bool = False
    entity_id: str | None = None
    content_hash: str | None = None
    binding_kind: str | None = None
    reason: str | None = None

    @classmethod
    def not_attempted(cls, reason: str) -> IdentityAttachResult:
        return cls(attempted=False, reason=reason)

    @classmethod
    def skipped(
        cls,
        reason: str,
        *,
        entity_id: str | None = None,
        content_hash: str | None = None,
        binding_kind: str | None = None,
    ) -> IdentityAttachResult:
        return cls(
            attempted=True,
            attached=False,
            entity_id=entity_id,
            content_hash=content_hash,
            binding_kind=binding_kind,
            reason=reason,
        )

    @classmethod
    def success(cls, *, entity_id: str, content_hash: str, binding_kind: str) -> IdentityAttachResult:
        return cls(
            attempted=True,
            attached=True,
            entity_id=entity_id,
            content_hash=content_hash,
            binding_kind=binding_kind,
        )


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
    """POST a single fingerprint to the Weft promote route; return the issue id."""

    def __init__(self, weft_url: str, *, transport: Transport | None = None, token: str | None = None) -> None:
        self._url = promote_url_from_weft(weft_url)
        self._api_base = api_base_url_from_weft(weft_url)
        self._transport: Transport = transport if transport is not None else UrllibTransport()
        self._token = token

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

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
            resp = self._transport.post(self._url, body, self._headers())
        except (urllib.error.URLError, OSError):
            return FileResult(reachable=False, disabled_reason="filigree unreachable")
        if resp.status >= 500 or resp.status in (401, 403):
            # 5xx outage or 401/403 auth refusal (Filigree's opt-in bearer auth is on and
            # rejecting us): enrichment unavailable, not a Wardline payload bug. Soft.
            return FileResult(reachable=False, disabled_reason=f"filigree {resp.status}")
        if resp.status == 404:
            return FileResult(reachable=True, not_found=True)
        if not 200 <= resp.status < 300:
            raise FiligreeEmitError(f"Filigree rejected promote ({resp.status}) at {self._url}: {resp.body}")
        try:
            payload = json.loads(resp.body) if resp.body else {}
        except json.JSONDecodeError:
            payload = {}
        # Type-narrow at the wire boundary like the emit path does (_safe_int): a 2xx
        # body carrying a non-string issue_id must not flow verbatim into tool payloads
        # that publish issue_id as string|null in their MCP outputSchema.
        raw_issue_id = payload.get("issue_id") if isinstance(payload, dict) else None
        issue_id = raw_issue_id if isinstance(raw_issue_id, str) else None
        created = bool(payload.get("created")) if isinstance(payload, dict) else False
        return FileResult(reachable=True, issue_id=issue_id, created=created)

    def attach_entity_association(
        self,
        *,
        issue_id: str,
        entity_id: str,
        content_hash: str,
        entity_kind: str | None = None,
        actor: str = "wardline",
    ) -> IdentityAttachResult:
        url = f"{self._api_base}/issue/{urllib.parse.quote(issue_id, safe='')}/entity-associations"
        body_dict: dict[str, Any] = {
            "entity_id": entity_id,
            "content_hash": content_hash,
            "actor": actor,
        }
        if entity_kind:
            body_dict["entity_kind"] = entity_kind
        body = json.dumps(body_dict).encode("utf-8")
        try:
            resp = self._transport.post(url, body, self._headers())
        except (urllib.error.URLError, OSError) as exc:
            return IdentityAttachResult.skipped(
                f"filigree association unreachable: {exc}",
                entity_id=entity_id,
                content_hash=content_hash,
                binding_kind="sei" if entity_id.startswith("loomweave:eid:") else "locator",
            )
        if not 200 <= resp.status < 300:
            return IdentityAttachResult.skipped(
                f"filigree association returned HTTP {resp.status}",
                entity_id=entity_id,
                content_hash=content_hash,
                binding_kind="sei" if entity_id.startswith("loomweave:eid:") else "locator",
            )
        return IdentityAttachResult.success(
            entity_id=entity_id,
            content_hash=content_hash,
            binding_kind="sei" if entity_id.startswith("loomweave:eid:") else "locator",
        )


def identity_attach_result_to_json(result: IdentityAttachResult) -> dict[str, Any]:
    return {
        "attempted": result.attempted,
        "attached": result.attached,
        "entity_id": result.entity_id,
        "content_hash": result.content_hash,
        "binding_kind": result.binding_kind,
        "reason": result.reason,
    }


def plugin_for_finding(finding: Any) -> str:
    """The ADR-049 plugin id that minted ``finding`` — the resolve-hint discriminator
    (ADR-036). Rust rules are the ``RS-WL-`` family; everything else with a qualname is
    the Python frontend. Derived from the rule id (findings carry no ``lang`` field;
    the rule family IS the producer)."""
    rule_id = getattr(finding, "rule_id", "") or ""
    return "rust" if rule_id.startswith("RS-WL-") else "python"


def _locator_for_finding_qualname(qualname: str, plugin: str) -> str:
    # Both frontends' callable findings carry function-kind qualnames (Wardline's
    # semantic `method` maps to the id-kind `function` in both dialects).
    return f"{plugin}:function:{qualname}"


def _finding_for_fingerprint(
    fingerprint: str,
    root: Path,
    config_path: Path | None,
    *,
    lang: str = "python",
) -> Any | None:
    from wardline.core.run import run_scan

    result = run_scan(root, config_path=config_path, lang=lang)
    return next((finding for finding in result.findings if finding.fingerprint == fingerprint), None)


@dataclass(frozen=True, slots=True)
class EntityBindingInput:
    """Outcome of resolving an inline entity reference supplied at a manual-entry surface
    (the doctrine ``entity_id`` L1 / ``entity_symbol`` L2 inputs). On success ``entity_id``
    is the binding key (a ``loomweave:eid:`` SEI when one resolved, else the opaque value /
    locator the caller supplied) and ``locator`` is the human-readable name. On failure the
    weft-reason triple is populated and the caller MUST create nothing."""

    resolved: bool
    entity_id: str | None = None
    locator: str | None = None
    content_hash: str | None = None
    binding_kind: str | None = None  # "sei" | "locator"
    # weft-reason carrier (unresolved_input); populated only when resolved is False.
    reason_class: str | None = None
    cause: str | None = None
    fix: str | None = None

    @classmethod
    def from_opaque(cls, entity_id: str) -> EntityBindingInput:
        """L1: an opaque id the caller already holds. Carried verbatim, never re-resolved."""
        return cls(
            resolved=True,
            entity_id=entity_id,
            locator=entity_id,
            binding_kind="sei" if entity_id.startswith("loomweave:eid:") else "locator",
        )

    @classmethod
    def unresolved(cls, *, cause: str, fix: str) -> EntityBindingInput:
        return cls(resolved=False, reason_class="unresolved_input", cause=cause, fix=fix)


def resolve_entity_binding_input(
    *,
    entity_id: str | None,
    entity_symbol: str | None,
    loomweave_client: Any,
    plugin: str = "python",
) -> EntityBindingInput | None:
    """Resolve an inline entity reference for a manual-entry surface, doctrine-style.

    Returns ``None`` when NEITHER input was supplied (the surface stays entity-free,
    fully back-compatible). With ``entity_id`` (L1) the value is carried opaque, no
    transport touched. With ``entity_symbol`` (L2) the symbol is resolved to a SEI via
    Loomweave (the existing :class:`SeiResolver` transport); a symbol that does not
    resolve to a live SEI returns an ``unresolved_input`` carrier so the caller can
    refuse to write a looks-bound-but-isn't record. ``entity_id`` wins if both given.
    """
    if entity_id:
        return EntityBindingInput.from_opaque(entity_id)
    if not entity_symbol:
        return None
    if loomweave_client is None:
        return EntityBindingInput.unresolved(
            cause=f"entity_symbol {entity_symbol!r} supplied but no Loomweave URL is configured to resolve it",
            fix="configure a Loomweave URL (--loomweave-url / loomweave.url), or pass an already-resolved entity_id",
        )
    locator = _locator_for_finding_qualname(entity_symbol, plugin)
    try:
        resolver = SeiResolver.detect(loomweave_client)
        binding = resolver.resolve_locator(locator)
    except Exception as exc:
        return EntityBindingInput.unresolved(
            cause=f"Loomweave resolve of entity_symbol {entity_symbol!r} failed: {exc}",
            fix="check Loomweave reachability, or pass an already-resolved entity_id",
        )
    if binding.sei and binding.content_hash:
        return EntityBindingInput(
            resolved=True,
            entity_id=binding.sei,
            locator=binding.locator or locator,
            content_hash=binding.content_hash,
            binding_kind="sei",
        )
    return EntityBindingInput.unresolved(
        cause=f"Loomweave did not resolve entity_symbol {entity_symbol!r} to a live SEI "
        f"(plugin={plugin}); the symbol may be unknown, renamed, or this Loomweave predates SEI",
        fix="verify the qualname is indexed in Loomweave, or pass an already-resolved entity_id",
    )


def attach_loomweave_identity_for_finding(
    *,
    fingerprint: str,
    issue_id: str | None,
    root: Path,
    filer: FiligreeIssueFiler,
    loomweave_client: Any,
    config_path: Path | None = None,
    lang: str = "python",
) -> IdentityAttachResult:
    if not issue_id:
        return IdentityAttachResult.not_attempted("no issue_id from Filigree promote")
    if loomweave_client is None:
        return IdentityAttachResult.not_attempted("no Loomweave URL configured")

    try:
        finding = _finding_for_fingerprint(fingerprint, root, config_path, lang=lang)
    except Exception as exc:
        return IdentityAttachResult.skipped(f"scan failed while resolving finding identity: {exc}")
    if finding is None:
        return IdentityAttachResult.skipped("finding fingerprint not present in current scan")
    qualname = getattr(finding, "qualname", None)
    if not isinstance(qualname, str) or not qualname:
        return IdentityAttachResult.skipped("finding has no qualname")
    return attach_loomweave_identity_for_qualname(
        qualname=qualname,
        issue_id=issue_id,
        filer=filer,
        loomweave_client=loomweave_client,
        plugin=plugin_for_finding(finding),
    )


def attach_loomweave_identity_for_qualname(
    *,
    qualname: str,
    issue_id: str | None,
    filer: FiligreeIssueFiler,
    loomweave_client: Any,
    plugin: str = "python",
) -> IdentityAttachResult:
    if not issue_id:
        return IdentityAttachResult.not_attempted("no issue_id from Filigree promote")
    if loomweave_client is None:
        return IdentityAttachResult.not_attempted("no Loomweave URL configured")
    locator = _locator_for_finding_qualname(qualname, plugin)
    try:
        resolver = SeiResolver.detect(loomweave_client)
        binding = resolver.resolve_locator(locator)
    except Exception as exc:
        return IdentityAttachResult.skipped(f"Loomweave identity resolve failed: {exc}", entity_id=locator)

    if binding.sei and binding.content_hash:
        return filer.attach_entity_association(
            issue_id=issue_id,
            entity_id=binding.sei,
            content_hash=binding.content_hash,
            entity_kind=f"{plugin}:function",
        )

    legacy = _legacy_locator_binding(
        loomweave_client, qualname, fallback_locator=binding.locator or locator, plugin=plugin
    )
    if legacy.entity_id and legacy.content_hash:
        return filer.attach_entity_association(
            issue_id=issue_id,
            entity_id=legacy.entity_id,
            content_hash=legacy.content_hash,
            entity_kind=f"{plugin}:function",
        )
    return legacy


def _legacy_locator_binding(
    loomweave_client: Any, qualname: str, *, fallback_locator: str, plugin: str = "python"
) -> IdentityAttachResult:
    entity_id: str | None = fallback_locator
    content_hash: str | None = None
    try:
        resolved = loomweave_client.resolve([qualname], plugin=plugin)
    except Exception as exc:
        return IdentityAttachResult.skipped(
            f"Loomweave legacy locator resolve failed: {exc}",
            entity_id=entity_id,
            binding_kind="locator",
        )
    if resolved is None:
        return IdentityAttachResult.skipped(
            "Loomweave unavailable while resolving legacy locator",
            entity_id=entity_id,
            binding_kind="locator",
        )
    resolved_map = getattr(resolved, "resolved", {})
    if isinstance(resolved_map, Mapping):
        resolved_value = resolved_map.get(qualname)
        if isinstance(resolved_value, str) and resolved_value:
            entity_id = resolved_value

    try:
        fact = loomweave_client.get_taint_fact(qualname)
    except Exception as exc:
        return IdentityAttachResult.skipped(
            f"Loomweave legacy content hash lookup failed: {exc}",
            entity_id=entity_id,
            binding_kind="locator",
        )
    if fact is not None:
        fact_hash = getattr(fact, "current_content_hash", None)
        if isinstance(fact_hash, str) and fact_hash:
            content_hash = fact_hash

    return IdentityAttachResult.skipped(
        "Loomweave resolved only a legacy locator without a current content hash; association not attached"
        if content_hash is None
        else "Loomweave resolved legacy locator binding",
        entity_id=entity_id,
        content_hash=content_hash,
        binding_kind="locator",
    )
