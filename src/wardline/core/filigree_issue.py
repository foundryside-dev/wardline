# src/wardline/core/filigree_issue.py
"""WS-A2: file ONE finding (by fingerprint) into a tracked Filigree issue, fail-soft.

Sibling of core/filigree_emit.py: same injectable-transport, same fail-soft charter
(sibling-absent / 5xx warn-and-continue; a 4xx other than 404 is a Wardline-bad-payload
bug and is loud). Talks the Weft HTTP promote-by-fingerprint route; imports no Filigree
package. A 404 means the fingerprint was never ingested for this scan_source (the agent
should emit findings to Filigree first) — surfaced as `not_found`, not an exception."""

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
from wardline.core.http import read_response_text
from wardline.loomweave.identity import SeiResolver

_ALLOWED_SCHEMES = ("http", "https")
_WEFT_MARKER = "/api/weft/"


def promote_url_from_weft(weft_url: str) -> str:
    """Derive the promote route from the configured Weft scan-results URL — both
    live under /api/weft/. Reject a URL that isn't a Weft endpoint (a clear config
    error rather than a 404 against a wrong host)."""
    idx = weft_url.find(_WEFT_MARKER)
    if idx == -1:
        raise FiligreeEmitError(f"filigree URL must be a Weft endpoint containing {_WEFT_MARKER!r}: {weft_url!r}")
    base = weft_url[: idx + len(_WEFT_MARKER)]
    return base + "findings/promote"


def api_base_url_from_weft(weft_url: str) -> str:
    """Normalize a Weft scan-results URL to Filigree's ``/api`` base."""
    idx = weft_url.find(_WEFT_MARKER)
    if idx == -1:
        raise FiligreeEmitError(f"filigree URL must be a Weft endpoint containing {_WEFT_MARKER!r}: {weft_url!r}")
    return weft_url[:idx].rstrip("/") + "/api"


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

    def __init__(self, weft_url: str, *, transport: Transport | None = None) -> None:
        self._url = promote_url_from_weft(weft_url)
        self._api_base = api_base_url_from_weft(weft_url)
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
            resp = self._transport.post(url, body, {"Content-Type": "application/json"})
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


def _locator_for_finding_qualname(qualname: str) -> str:
    return f"python:function:{qualname}"


def _finding_for_fingerprint(fingerprint: str, root: Path, config_path: Path | None) -> Any | None:
    from wardline.core.run import run_scan

    result = run_scan(root, config_path=config_path)
    return next((finding for finding in result.findings if finding.fingerprint == fingerprint), None)


def attach_loomweave_identity_for_finding(
    *,
    fingerprint: str,
    issue_id: str | None,
    root: Path,
    filer: FiligreeIssueFiler,
    loomweave_client: Any,
    config_path: Path | None = None,
) -> IdentityAttachResult:
    if not issue_id:
        return IdentityAttachResult.not_attempted("no issue_id from Filigree promote")
    if loomweave_client is None:
        return IdentityAttachResult.not_attempted("no Loomweave URL configured")

    try:
        finding = _finding_for_fingerprint(fingerprint, root, config_path)
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
    )


def attach_loomweave_identity_for_qualname(
    *,
    qualname: str,
    issue_id: str | None,
    filer: FiligreeIssueFiler,
    loomweave_client: Any,
) -> IdentityAttachResult:
    if not issue_id:
        return IdentityAttachResult.not_attempted("no issue_id from Filigree promote")
    if loomweave_client is None:
        return IdentityAttachResult.not_attempted("no Loomweave URL configured")
    locator = _locator_for_finding_qualname(qualname)
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
            entity_kind="python:function",
        )

    legacy = _legacy_locator_binding(loomweave_client, qualname, fallback_locator=binding.locator or locator)
    if legacy.entity_id and legacy.content_hash:
        return filer.attach_entity_association(
            issue_id=issue_id,
            entity_id=legacy.entity_id,
            content_hash=legacy.content_hash,
            entity_kind="python:function",
        )
    return legacy


def _legacy_locator_binding(loomweave_client: Any, qualname: str, *, fallback_locator: str) -> IdentityAttachResult:
    entity_id: str | None = fallback_locator
    content_hash: str | None = None
    try:
        resolved = loomweave_client.resolve([qualname])
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
