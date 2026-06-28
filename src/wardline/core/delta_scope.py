"""Affected-entity scope parsing for the ``--affected`` delta scan (stdlib-only).

This module is the **scope input** seam (spec §5.1). It parses a producer-supplied
affected-entity scope from one of three structurally-distinct shapes and normalizes
it into an :class:`AffectedScope` value. It also defines the :class:`DeltaScopeReport`
honesty block (spec §5.4) that ``run_scan`` attaches to a delta result.

The scope input is **untrusted/unauthenticated** (a warpline reverify worklist derived
from filigree/loomweave state, or a hand-supplied JSON blob — no signature, producer
identity, or freshness binding). Parsing is therefore defensive: structurally malformed
payloads fail LOUD (``ScopeParseError`` → exit 2), oversized payloads are rejected
(DoS guard on the uncapped stdin/inline ingress), but an *empty* or zero-entity payload
is **not** an error — it returns ``source_kind="empty"`` and the fail-closed full-fallback
rule (spec §5.4, applied in ``run_scan``) takes over. The trust level of the scope never
turns a clean subset into an authoritative pass: the entity filter cannot narrow the
analyzed gate population (INV-4), and skipped files keep a true delta advisory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from wardline.core.errors import WardlineError

# DoS guards on the new (previously uncapped) stdin/inline ingress (spec §7). Both are
# generous — large enough never to bite a real worklist, small enough to bound a hostile
# blob handed to a long-running ``wardline mcp`` server.
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024  # 4 MiB
_MAX_ITEM_COUNT = 50_000


class ScopeParseError(WardlineError):
    """A ``--affected`` scope payload is structurally malformed or oversized.

    Loud (CLI → exit 2; MCP → ``ToolError``/isError) — an agent payload bug, NOT a
    degrade. An *empty* or zero-entity payload is NOT this error; it is reported via
    ``source_kind="empty"`` so the caller can apply the fail-closed full-fallback rule
    (spec §5.4). This covers: a payload that is not an object/array, an ``items`` value
    that is not a list, an entity that is not an object, invalid JSON (from
    :func:`load_affected_scope`), and a payload exceeding the byte / item-count cap.
    """


@dataclass(frozen=True, slots=True)
class AffectedEntity:
    """One affected entity from the producer scope. At least one of ``sei`` / ``locator``
    is non-``None`` (entities with neither are dropped during parsing). ``locator`` is an
    opaque-ish warpline locator, e.g. ``python:function:pkg.mod.f``."""

    sei: str | None
    locator: str | None


@dataclass(frozen=True, slots=True)
class AffectedScope:
    """A normalized affected-entity scope plus provenance.

    ``source_kind`` records which shape was parsed: ``"reverify_worklist_v1"`` (either
    the full ``{"data": {"items": …}}`` envelope or its bare ``{"items": …}`` payload),
    ``"entity_list"`` (a bare ``[…]`` list), or ``"empty"`` (a parseable payload that
    yielded zero usable entities). ``item_count`` is the number of *input* items seen
    (before dropping entities with neither ``sei`` nor ``locator``), used for the
    item-count DoS cap and for the ``entities_requested`` scope-block field."""

    entities: frozenset[AffectedEntity]
    source_kind: str
    item_count: int
    producer_completeness: dict[str, object] | None = None


def parse_affected_scope(payload: object) -> AffectedScope:
    """Parse an already-decoded JSON ``payload`` into an :class:`AffectedScope`.

    Sole public entry point. Accepts (spec §5.1):

    1. ``warpline.reverify_worklist.v1`` full envelope — ``{"data": {"items": [...]}}``.
    2. ``warpline.reverify_worklist.v1`` bare ``data`` payload — ``{"items": [...]}``.
    3. A bare entity list — ``[{"sei"?: str, "locator"?: str}, ...]``.

    Worklist items (shapes 1/2) read ``items[].entity.{sei, locator}``; bare-list items
    (shape 3) read ``{sei, locator}`` directly. An entity with neither ``sei`` nor
    ``locator`` is dropped (counts toward neither resolution path). A structurally
    malformed payload raises :class:`ScopeParseError`; a parseable-but-empty payload
    returns ``source_kind="empty"``.
    """
    _enforce_byte_cap(payload)

    if isinstance(payload, list):
        return _parse_entity_list(payload)
    if isinstance(payload, dict):
        return _parse_worklist(payload)
    raise ScopeParseError(
        f"affected scope payload must be a JSON object (worklist) or array (entity list), got {type(payload).__name__}"
    )


def parse_affected_scope_text(raw: str) -> AffectedScope:
    """Parse untrusted raw JSON *text* into an :class:`AffectedScope`, capping RAW INPUT
    BYTES *before* ``json.loads`` (DoS guard at the bytes boundary, spec §7).

    This is the entry point for every path where untrusted text enters from outside the
    process (a file or a stdin stream): the byte cap is enforced on ``len(raw bytes)``
    BEFORE the blob is parsed, so a huge VALID JSON payload cannot force a full
    parse/allocation before the cap fires. Invalid JSON raises :class:`ScopeParseError`
    (the same malformed-payload posture as :func:`load_affected_scope`).

    The already-decoded :func:`parse_affected_scope` entry point keeps its own post-parse
    byte cap as defense-in-depth for the MCP inline path, where the object arrives
    pre-parsed by the JSON-RPC transport and the raw-bytes guard does not apply."""
    if len(raw.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
        raise ScopeParseError(f"affected scope payload exceeds the {_MAX_PAYLOAD_BYTES}-byte cap")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ScopeParseError(f"affected scope payload is not valid JSON: {exc}") from exc
    return parse_affected_scope(payload)


def load_affected_scope(source: str) -> AffectedScope:
    """Read the JSON file at ``source`` (a real filesystem path) and parse it.

    Internal helper for callers that hold a path rather than already-read text. It does
    **not** handle stdin — the CLI owns the stdin handle via ``click.File('-')`` and
    routes already-read text to :func:`parse_affected_scope_text` directly. Invalid JSON,
    an over-cap blob, or an unreadable file raises :class:`ScopeParseError` (the
    malformed-payload posture, §7).

    The read is itself bounded: at most ``_MAX_PAYLOAD_BYTES + 1`` bytes are read, never
    the whole file unbounded. Reading cap+1 and checking the length is a sufficient *bound*
    (we do not need to stream): if the read returns more than the cap we reject; if it
    returns at-or-under the cap we have the complete payload. The text is then routed
    through :func:`parse_affected_scope_text`, which re-checks the byte cap before parse."""
    try:
        with open(source, encoding="utf-8") as fh:
            # Read at most cap+1 bytes: enough to detect an over-cap file without an
            # unbounded read/allocation. (text-mode read(n) counts characters; for ASCII
            # JSON that equals bytes, and the byte-accurate cap is re-checked downstream.)
            raw = fh.read(_MAX_PAYLOAD_BYTES + 1)
    except OSError as exc:
        raise ScopeParseError(f"could not read affected scope file {source!r}: {exc}") from exc
    try:
        return parse_affected_scope_text(raw)
    except ScopeParseError as exc:
        if "not valid JSON" in str(exc):
            raise ScopeParseError(f"affected scope file {source!r} is not valid JSON: {exc}") from exc
        raise


def _enforce_byte_cap(payload: object) -> None:
    """Reject an oversized payload by re-serialized byte length (DoS guard, §7).

    The item-count cap is enforced once the item list is known (it is cheaper to count
    items than to re-serialize, but the byte cap bounds a payload that is one giant value
    rather than many items)."""
    try:
        encoded = json.dumps(payload, separators=(",", ":"))
    except (TypeError, ValueError):
        # Non-serializable payloads are not valid scope inputs anyway; let the shape
        # checks below raise a precise ScopeParseError instead of swallowing here.
        return
    if len(encoded.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
        raise ScopeParseError(f"affected scope payload exceeds the {_MAX_PAYLOAD_BYTES}-byte cap")


def _enforce_item_cap(count: int) -> None:
    if count > _MAX_ITEM_COUNT:
        raise ScopeParseError(f"affected scope has {count} items, exceeding the {_MAX_ITEM_COUNT}-item cap")


def _parse_worklist(payload: dict[object, object]) -> AffectedScope:
    """Parse a ``warpline.reverify_worklist.v1`` envelope (full or bare-data)."""
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        raise ScopeParseError(f"affected scope 'data' must be an object, got {type(data).__name__}")
    producer_completeness = _producer_completeness(data)
    items = data.get("items")
    if items is None:
        # An object with no 'items' is a parseable but empty worklist — not malformed.
        return AffectedScope(frozenset(), "empty", 0, producer_completeness=producer_completeness)
    if not isinstance(items, list):
        raise ScopeParseError(f"affected scope 'items' must be a list, got {type(items).__name__}")
    _enforce_item_cap(len(items))
    entities: set[AffectedEntity] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ScopeParseError(f"affected scope worklist item must be an object, got {type(item).__name__}")
        entity_obj = item.get("entity")
        if entity_obj is None:
            continue
        if not isinstance(entity_obj, dict):
            raise ScopeParseError(f"affected scope item 'entity' must be an object, got {type(entity_obj).__name__}")
        entity = _coerce_entity(entity_obj)
        if entity is not None:
            entities.add(entity)
    if not entities:
        return AffectedScope(frozenset(), "empty", len(items), producer_completeness=producer_completeness)
    return AffectedScope(
        frozenset(entities), "reverify_worklist_v1", len(items), producer_completeness=producer_completeness
    )


def _producer_completeness(data: dict[object, object]) -> dict[str, object] | None:
    """Capture Warpline's unverified completeness claim without vouching for it.

    Current Warpline producer output carries the claim as sibling fields
    ``data.completeness`` and ``data.staleness``. Older delta fixtures carried a single
    ``data.impact_completeness`` object; keep that as a compatibility fallback.
    """
    completeness = data.get("completeness")
    staleness = data.get("staleness")
    published: dict[str, object] = {}
    if isinstance(completeness, str):
        published["completeness"] = completeness
    if isinstance(staleness, dict):
        published["staleness"] = dict(staleness)
    if published:
        return published
    ic = data.get("impact_completeness")
    return dict(ic) if isinstance(ic, dict) else None


def _parse_entity_list(payload: list[object]) -> AffectedScope:
    """Parse a bare ``[{"sei"?, "locator"?}, ...]`` entity list."""
    _enforce_item_cap(len(payload))
    entities: set[AffectedEntity] = set()
    for item in payload:
        if not isinstance(item, dict):
            raise ScopeParseError(f"affected scope entity-list item must be an object, got {type(item).__name__}")
        entity = _coerce_entity(item)
        if entity is not None:
            entities.add(entity)
    if not entities:
        return AffectedScope(frozenset(), "empty", len(payload))
    return AffectedScope(frozenset(entities), "entity_list", len(payload))


def _coerce_entity(obj: dict[object, object]) -> AffectedEntity | None:
    """Coerce a ``{sei?, locator?}`` object into an :class:`AffectedEntity`, or ``None``
    if it carries neither a usable ``sei`` nor ``locator`` (such entities are dropped)."""
    sei = _coerce_str(obj.get("sei"))
    locator = _coerce_str(obj.get("locator"))
    if sei is None and locator is None:
        return None
    return AffectedEntity(sei=sei, locator=locator)


def _coerce_str(value: object) -> str | None:
    """Return a non-empty string, else ``None``. Non-string/blank values are treated as
    absent (a producer that emits ``"sei": null`` or ``""`` means 'no SEI')."""
    if isinstance(value, str) and value:
        return value
    return None


# --- Phase 5: the scope honesty block (spec §5.4) ---------------------------------

BOUNDARY_CAVEAT = (
    "Delta scan analyzes only files containing the affected entities. Findings here "
    "may be incomplete OR absent: cross-file taint whose source lies outside the "
    "analyzed set is not computed, so an in-scope entity can read clean without being "
    "clean. Advisory inner-loop signal, not a verdict — the full scan is the gate of record."
)


@dataclass(frozen=True, slots=True)
class DeltaScopeReport:
    """The honesty/provenance block attached to a delta-scan :class:`ScanResult`.

    ``mode`` is ``"delta"`` when a scoped subset was analyzed, or ``"full-fallback"``
    when the scope resolved zero files (empty / all-unresolvable / loomweave-absent +
    qualname-miss) and ``run_scan`` fell back to a full scan (fail-closed honesty,
    INV-3). ``gate_authority`` is the **machine-readable** companion an automated
    consumer can gate on without parsing prose: ``"advisory"`` in delta mode (only the
    scoped files were analyzed, so a clean delta is not a full-tree pass), ``"gate-of-record"``
    in full-fallback.

    ``scope_source`` records the parsed producer shape (``reverify_worklist_v1`` /
    ``entity_list`` / ``empty``); ``producer_completeness`` is warpline's UNVERIFIED
    completeness claim from ``data.completeness`` / ``data.staleness`` (or legacy
    ``data.impact_completeness`` when the published fields are absent), never
    wardline-vouched.

    ``fell_back_count`` / ``stale_sei_count`` surface how much of the scope rests on the
    spoofable qualname-locator path or a stale SEI, so a consumer can judge trust without
    treating fell-back entities as SEI-equivalent. ``unresolved_entities`` lists every
    entity that did not resolve even in delta mode."""

    mode: str
    gate_authority: str
    scope_source: str
    entities_requested: int
    files_discovered: int
    files_analyzed: int
    in_scope_findings: int
    fell_back_count: int
    stale_sei_count: int
    unresolved_entities: tuple[dict[str, str | None], ...]
    loomweave_used: bool
    producer_completeness: dict[str, object] | None = None
    boundary_caveat: str = field(default=BOUNDARY_CAVEAT)

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-ready mapping for the agent-summary / SARIF / MCP channels.

        Return type is ``dict[str, object]`` (not ``dict[str, Any]``) so it stays sound
        under ``mypy --strict`` — the inner ``unresolved_entities`` items are
        ``dict[str, str | None]``, which is not assignable to ``dict[str, Any]``."""
        return {
            "mode": self.mode,
            "gate_authority": self.gate_authority,
            "scope_source": self.scope_source,
            "entities_requested": self.entities_requested,
            "files_discovered": self.files_discovered,
            "files_analyzed": self.files_analyzed,
            "in_scope_findings": self.in_scope_findings,
            "fell_back_count": self.fell_back_count,
            "stale_sei_count": self.stale_sei_count,
            "unresolved_entities": [dict(e) for e in self.unresolved_entities],
            "loomweave_used": self.loomweave_used,
            "producer_completeness": self.producer_completeness,
            "boundary_caveat": self.boundary_caveat,
        }
