"""Federation-status envelope parity: ONE builder + ONE schema source.

The ``{"filigree_emit": <status>, "loomweave_write": <status>}`` blocks (and their
JSON-schema ``$defs``) were hand-duplicated across cli/scan, core/scan_jobs,
core/scan_file_workflow, core/agent_summary, and mcp/server. They are now sourced
from ``core/federation_status``. This test pins that consolidation:

1. Every surface delegates to the canonical builder (its bytes ARE the builder's
   bytes) — proven by string equality on representative inputs.
2. The MCP ``$defs`` (and the self-contained scan_file_findings schema) equal the
   ONE schema-source. Drift either side reds.
3. The shared required-key contract holds across MCP / CLI / scan-job surfaces.

Surfaces legitimately differ in CONTEXT — the MCP block is WIDER (discriminated
transport detail; disabled_reason second) and the scan_file block has no
``destination`` and no ``loomweave_write``. Those differences are preserved, not
collapsed, so the assertions below pin the achievable contract (shared keys + same
source), never false cross-surface key-set equality.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from wardline.core import federation_status as fs
from wardline.core import scan_file_workflow as sfw
from wardline.core import scan_jobs
from wardline.core.filigree_emit import EmitResult, FailedFinding, filigree_destination
from wardline.loomweave.client import WriteResult
from wardline.mcp import server
from wardline.mcp.server import WardlineMCPServer

# --- representative emit results spanning the soft-failure ladder -----------
_OK = EmitResult(reachable=True, created=2, updated=1)
_AUTH = EmitResult(reachable=False, status=401, token_sent=True, url="http://x/api?project=p")
_PARTIAL = EmitResult(
    reachable=False,
    status=422,
    token_sent=True,
    url="http://x",
    failures=(FailedFinding(reason="rejected", detail="nope", fingerprint="abc"),),
)


def _mcp_block(er: EmitResult) -> dict[str, Any]:
    """The raw block the MCP scan path (``_emit_filigree``) hands the status builder."""
    return {
        "reachable": er.reachable,
        "created": er.created,
        "updated": er.updated,
        "failed": er.failed,
        "failures": [f.to_wire() for f in er.failures],
        "warnings": list(er.warnings),
        "status": er.status,
        "auth_rejected": er.auth_rejected,
        "token_sent": er.token_sent,
        "url": er.url,
        "destination": filigree_destination(er.url),
    }


def _eq(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Byte-identity in the only sense the wire cares about: same JSON (key order included)."""
    return json.dumps(a, sort_keys=False) == json.dumps(b, sort_keys=False)


# ---------------------------------------------------------------------------
# 1. Every surface IS the canonical builder (byte-for-byte)
# ---------------------------------------------------------------------------


def test_cli_filigree_status_is_canonical_builder() -> None:
    from wardline.cli import scan as cliscan

    for er in (None, _OK, _AUTH, _PARTIAL):
        expected = fs.filigree_emit_status(er, configured=er is not None, include_destination=True)
        assert _eq(cliscan._filigree_status(er), expected)


def test_scan_job_filigree_status_is_canonical_builder() -> None:
    for er in (None, _OK, _AUTH, _PARTIAL):
        expected = fs.filigree_emit_status(er, configured=er is not None, include_destination=True)
        assert _eq(scan_jobs._filigree_status(er), expected)


def test_scan_file_filigree_status_is_canonical_builder() -> None:
    # scan_file is the no-destination variant; configured is explicit (dry-run keeps it on).
    def canon(er: EmitResult | None, *, configured: bool) -> dict[str, Any]:
        return fs.filigree_emit_status(er, configured=configured, include_destination=False)

    assert _eq(sfw._emit_to_dict(None, configured=False), canon(None, configured=False))
    assert _eq(sfw._emit_to_dict(None, configured=True), canon(None, configured=True))
    for er in (_OK, _AUTH, _PARTIAL):
        assert _eq(sfw._emit_to_dict(er, configured=True), canon(er, configured=True))


def test_mcp_filigree_status_is_canonical_builder() -> None:
    assert _eq(server._filigree_emit_status(None), fs.filigree_emit_status_from_block(None))
    for er in (_OK, _AUTH, _PARTIAL):
        block = _mcp_block(er)
        assert _eq(server._filigree_emit_status(block), fs.filigree_emit_status_from_block(block))


def test_loomweave_status_is_canonical_builder_across_surfaces() -> None:
    from wardline.cli import scan as cliscan

    class WR:
        reachable = True
        written = 3
        unresolved_qualnames = ("a.b",)
        disabled_reason = None

    block = {"reachable": True, "written": 3, "unresolved_qualnames": ["a.b"], "disabled_reason": None}
    # not-configured default is shared by every surface
    assert _eq(cliscan._loomweave_status(None), fs.default_loomweave_write_status())
    assert _eq(server._loomweave_write_status(None), fs.default_loomweave_write_status())
    # configured CLI (result) and MCP (block) builders agree byte-for-byte
    assert _eq(cliscan._loomweave_status(WR()), fs.loomweave_write_status(WR()))
    assert _eq(server._loomweave_write_status(block), fs.loomweave_write_status_from_block(block))
    assert _eq(cliscan._loomweave_status(WR()), server._loomweave_write_status(block))


def test_agent_summary_defaults_are_canonical_builder() -> None:
    from wardline.core import agent_summary as asm

    assert _eq(asm._default_filigree_status(), fs.default_filigree_emit_status(include_destination=False))
    assert _eq(asm._default_loomweave_status(), fs.default_loomweave_write_status())


# ---------------------------------------------------------------------------
# 2. The MCP $defs / scan_file schema equal the ONE schema-source
# ---------------------------------------------------------------------------


def test_mcp_defs_equal_schema_source() -> None:
    defs = server._SCAN_OUTPUT_SCHEMA["$defs"]
    assert _eq(defs["filigree_emit_status"], fs.filigree_emit_status_schema(include_transport_detail=True))
    assert _eq(defs["loomweave_write_status"], fs.loomweave_write_status_schema())


def test_scan_file_schema_equals_schema_source() -> None:
    block = server._SCAN_FILE_FINDINGS_OUTPUT_SCHEMA["properties"]["filigree_emit"]
    assert _eq(block, fs.SCAN_FILE_FINDINGS_FILIGREE_EMIT_SCHEMA)


def test_scan_file_schema_is_the_no_transport_detail_shape() -> None:
    # The scan_file block omits the discriminated transport detail and destination — its
    # required/property contract matches include_transport_detail=False.
    narrow = fs.filigree_emit_status_schema(include_transport_detail=False)
    block = fs.SCAN_FILE_FINDINGS_FILIGREE_EMIT_SCHEMA
    assert set(block["properties"]) == set(narrow["properties"])
    assert block["required"] == narrow["required"]
    assert "destination" not in block["properties"]
    assert "status" not in block["properties"]


# ---------------------------------------------------------------------------
# 3. Shared required-key contract across surfaces
# ---------------------------------------------------------------------------

_SHARED_FILIGREE_KEYS = {
    "configured",
    "reachable",
    "created",
    "updated",
    "failed",
    "failures",
    "warnings",
    "disabled_reason",
}


def test_shared_filigree_required_keys_present_on_every_surface() -> None:
    from wardline.cli import scan as cliscan

    surfaces = [
        cliscan._filigree_status(_OK),
        scan_jobs._filigree_status(_OK),
        sfw._emit_to_dict(_OK, configured=True),
        server._filigree_emit_status(_mcp_block(_OK)),
    ]
    for block in surfaces:
        assert set(block) >= _SHARED_FILIGREE_KEYS, block
    # The $defs contract names exactly the shared keys as required (plus destination on the
    # transport-detailed variant); the narrow variant requires exactly the shared keys.
    narrow_required = set(fs.filigree_emit_status_schema(include_transport_detail=False)["required"])
    assert narrow_required == _SHARED_FILIGREE_KEYS


def test_mcp_filigree_block_is_wider_but_shares_the_contract() -> None:
    # MCP carries the transport detail; CLI/scan-job/scan_file do not. The shared keys are a
    # subset of the MCP block — pinning that the divergence is additive, never a key rename.
    mcp = server._filigree_emit_status(_mcp_block(_AUTH))
    assert set(mcp) >= _SHARED_FILIGREE_KEYS
    assert set(mcp) >= {"status", "auth_rejected", "token_sent", "url", "destination"}


# ---------------------------------------------------------------------------
# 4. The REAL configured MCP producer -> builder -> schema chain (W2-HIGH)
#
# The block-builder parity above feeds the builder a TEST-LOCAL ``_mcp_block`` hand-copy
# and asserts ``server._filigree_emit_status`` (a one-line delegate) == the builder — a
# tautology that cannot catch a field the REAL producer (``_emit_filigree`` / the inline
# loomweave block) adds, nor a `{**block}` passthrough propagating an unknown key past the
# canonical schema's ``additionalProperties: False``. This section drives a CONFIGURED scan
# end-to-end — real ``_emit_filigree`` and real inline loomweave producer run, their output
# lands in ``structuredContent``, and we ``jsonschema.validate`` it against the scan tool's
# OWN advertised outputSchema. A stray producer key now REDS here (it violates the schema).
# ---------------------------------------------------------------------------

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _leaky_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


class _FakeEmitter:
    """Duck-typed FiligreeEmitter: ``_emit_filigree`` only calls ``.emit(...)``."""

    def __init__(self, result: EmitResult) -> None:
        self._result = result

    def emit(self, findings: Any, **kwargs: Any) -> EmitResult:
        return self._result


def _scan_structured(server_obj: WardlineMCPServer, arguments: dict[str, Any]) -> dict[str, Any]:
    """tools/call scan -> structuredContent validated against the scan tool's OWN advertised
    outputSchema (the dual-emission text block is byte-identical). Mirrors the ``_validated``
    helper in test_mcp_structured_output.py without touching that file."""
    resp = server_obj.rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "scan", "arguments": arguments},
        }
    )
    assert "error" not in resp, resp
    result: dict[str, Any] = resp["result"]
    assert result.get("isError") is not True, result
    listed = server_obj.rpc.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    schema = {t["name"]: t for t in listed["result"]["tools"]}["scan"]["outputSchema"]
    structured: dict[str, Any] = result["structuredContent"]
    jsonschema.validate(structured, schema)
    assert json.loads(result["content"][0]["text"]) == structured, "scan: dual emission diverged"
    return structured


# Emit results spanning the soft-failure ladder, each exercising the configured filigree_emit
# block: OK (created/updated), AUTH (401, token rejected), PARTIAL (422 + a per-finding failure
# that drives the failures-array `$def` on the REAL configured path — the first test to do so).
_CONFIGURED_EMIT_RESULTS = (
    ("ok", _OK),
    ("auth", _AUTH),
    ("partial", _PARTIAL),
)


@pytest.mark.parametrize("label,emit_result", _CONFIGURED_EMIT_RESULTS, ids=[c[0] for c in _CONFIGURED_EMIT_RESULTS])
def test_configured_filigree_emit_real_producer_validates_against_schema(
    tmp_path: Path, label: str, emit_result: EmitResult
) -> None:
    """The widest, most drift-prone surface: a CONFIGURED MCP scan whose REAL ``_emit_filigree``
    producer ran. The resulting ``filigree_emit`` carries the transport detail and MUST validate
    against the canonical (transport-detailed) ``$def`` — a stray producer key reds here."""
    server_obj = WardlineMCPServer(root=_leaky_project(tmp_path))
    # Inject through the SAME seam the registered scan lambda resolves the emitter through, so the
    # real _emit_filigree runs against our fake. _loomweave_client stays None (separate twin below).
    server_obj._filigree_emitter = lambda *a, **k: _FakeEmitter(emit_result)  # type: ignore[method-assign]
    out = _scan_structured(server_obj, {})
    emit = out["filigree_emit"]
    assert emit["configured"] is True
    # The transport-detail keys are PRESENT (this is the wide MCP block, not the narrow one).
    assert set(emit) >= {"status", "auth_rejected", "token_sent", "url", "destination"}
    if label == "ok":
        assert emit["reachable"] is True
        assert emit["created"] == 2 and emit["updated"] == 1
        assert emit["disabled_reason"] is None
    elif label == "auth":
        assert emit["auth_rejected"] is True
        assert emit["status"] == 401
    else:  # partial
        assert emit["failed"] == 1
        # The failures array on the REAL configured path validated against the `$def` above.
        assert emit["failures"][0]["reason"] == "rejected"
        assert emit["failures"][0]["fingerprint"] == "abc"


def test_configured_loomweave_write_real_producer_validates_against_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The loomweave twin: a CONFIGURED scan whose REAL inline loomweave producer ran. We patch the
    write call (not the builder) to a populated WriteResult so ``written`` is non-zero, then validate
    the whole scan envelope — the ``loomweave_write`` block must satisfy the canonical schema."""
    populated = WriteResult(reachable=True, written=3, unresolved_qualnames=("pkg.mod.fn",), disabled_reason=None)
    monkeypatch.setattr("wardline.loomweave.write.write_facts_to_loomweave", lambda result, root, client: populated)
    server_obj = WardlineMCPServer(root=_leaky_project(tmp_path))
    # Non-None client trips the `if loomweave is not None` producer guard; the patched write
    # supplies the populated result the inline block maps into loomweave_write.
    server_obj._loomweave_client = lambda *a, **k: object()  # type: ignore[method-assign]
    out = _scan_structured(server_obj, {})
    lw = out["loomweave_write"]
    assert lw["configured"] is True
    assert lw["reachable"] is True
    assert lw["written"] == 3
    assert lw["unresolved_qualnames"] == ["pkg.mod.fn"]
    assert lw["disabled_reason"] is None


# ---------------------------------------------------------------------------
# 5. The RAW filigree/loomweave $defs cannot drift from the canonical field schemas
#    (W2-MEDIUM — second surviving hand-enumerated schema pair)
#
# The raw debug-echo `filigree`/`loomweave` $defs (server.py) hand-enumerate the SAME field
# semantics the canonical filigree_emit_status_schema()/loomweave_write_status_schema() own.
# They are a live second source of truth (both raw and normalized blocks ship in one scan
# response). The two legitimately differ in DESCRIPTION prose (the raw blocks carry their own
# debug-echo wording) and the raw block, existing only when CONFIGURED, types ``reachable`` as a
# plain boolean (no null) — so we pin STRUCTURE (type/enum/$ref), description-insensitive, on the
# overlapping fields. A future type/enum/ref edit to one now reds against the other.
# ---------------------------------------------------------------------------


def _strip_descriptions(node: Any) -> Any:
    """A deep copy of a JSON-schema node with every ``description`` removed, so structural
    comparison (type/enum/$ref/required) ignores legitimately-divergent prose."""
    if isinstance(node, dict):
        return {k: _strip_descriptions(v) for k, v in node.items() if k != "description"}
    if isinstance(node, list):
        return [_strip_descriptions(v) for v in node]
    return node


def _raw_object_schema(prop_name: str) -> dict[str, Any]:
    """The non-null arm of a raw debug-echo ``oneOf`` property (the object schema). The raw
    ``filigree``/``loomweave`` debug-echo blocks live under the scan output schema's
    ``properties`` (a nullable ``oneOf``), distinct from the normalized ``$defs`` $refs."""
    one_of = server._SCAN_OUTPUT_SCHEMA["properties"][prop_name]["oneOf"]
    obj = next(arm for arm in one_of if arm.get("type") == "object")
    return copy.deepcopy(obj)


def test_raw_filigree_def_shares_structure_with_canonical() -> None:
    raw = _raw_object_schema("filigree")
    canonical = fs.filigree_emit_status_schema(include_transport_detail=True)
    raw_props = raw["properties"]
    canon_props = canonical["properties"]
    # Every field the raw debug-echo block declares (it omits `configured`/`disabled_reason`, which
    # the NORMALIZED block adds) must structurally equal its canonical counterpart.
    shared = {"created", "updated", "failed", "failures", "warnings", "status", "auth_rejected", "token_sent", "url",
              "destination"}
    assert shared <= set(raw_props), f"raw filigree $def lost a field: {shared - set(raw_props)}"
    for field in shared:
        assert _strip_descriptions(raw_props[field]) == _strip_descriptions(canon_props[field]), (
            f"raw vs canonical filigree drift on {field!r}"
        )
    # `reachable` legitimately differs in nullability (raw exists only when configured -> non-null),
    # so we pin only that BOTH declare it, not that the types match.
    assert "reachable" in raw_props and "reachable" in canon_props


def test_raw_loomweave_def_shares_structure_with_canonical() -> None:
    raw = _raw_object_schema("loomweave")
    canonical = fs.loomweave_write_status_schema()
    raw_props = raw["properties"]
    canon_props = canonical["properties"]
    shared = {"written", "unresolved_qualnames", "disabled_reason"}
    assert shared <= set(raw_props)
    for field in shared:
        assert _strip_descriptions(raw_props[field]) == _strip_descriptions(canon_props[field]), (
            f"raw vs canonical loomweave drift on {field!r}"
        )
    # `reachable` again differs only in nullability (raw block is configured-only).
    assert "reachable" in raw_props and "reachable" in canon_props


# ---------------------------------------------------------------------------
# 6. Frozen golden snapshots of the canonical builders (W2-LOW)
#
# Sections 1-2 pin "each surface tracks the builder" and "$defs track the schema source" — but a
# future edit that changed a surface helper AND the shared builder in LOCKSTEP (a reordered key, a
# renamed `disabled_reason`) would keep every relative assertion green while the WIRE bytes drift.
# These HAND-FROZEN literals (never re-derived from the builder) convert "surface tracks builder"
# into "builder bytes are frozen": the runtime envelope now has an absolute snapshot on this side,
# the way test_mcp_structured_output.py absolutely pins the MCP schema side.
# ---------------------------------------------------------------------------

_GOLDEN_FILIGREE_NONE: dict[str, Any] = {
    "configured": False,
    "reachable": None,
    "created": 0,
    "updated": 0,
    "failed": 0,
    "failures": [],
    "warnings": [],
    "disabled_reason": "not configured",
    "destination": {"url": None, "project": None, "project_pinned": False},
}

_GOLDEN_FILIGREE_OK: dict[str, Any] = {
    "configured": True,
    "reachable": True,
    "created": 2,
    "updated": 1,
    "failed": 0,
    "failures": [],
    "warnings": [],
    "disabled_reason": None,
    "destination": {"url": None, "project": None, "project_pinned": False},
}

_GOLDEN_FILIGREE_FROM_BLOCK_AUTH: dict[str, Any] = {
    "configured": True,
    "disabled_reason": "filigree rejected the token (401) at http://x/api?project=p; a token WAS sent but "
    "its value is wrong — align WEFT_FEDERATION_TOKEN (env or .env) to the canonical federation token",
    "reachable": False,
    "created": 0,
    "updated": 0,
    "failed": 0,
    "failures": [],
    "warnings": [],
    "status": 401,
    "auth_rejected": True,
    "token_sent": True,
    "url": "http://x/api?project=p",
    "destination": {"url": "http://x/api?project=p", "project": "p", "project_pinned": True},
}

# The richest, most drift-prone shape: the PARTIAL block's failures array carries the full
# weft-reason carrier triple (reason_class/cause/fix). Bytes pulled from the builder once and
# frozen here verbatim (NOT re-derived at call time), so a lockstep edit to the builder reds.
_GOLDEN_FILIGREE_FROM_BLOCK_PARTIAL: dict[str, Any] = {
    "configured": True,
    "disabled_reason": "filigree server error (422) at http://x",
    "reachable": False,
    "created": 0,
    "updated": 0,
    "failed": 1,
    "failures": [
        {
            "reason": "rejected",
            "detail": "nope",
            "reason_class": "rejected",
            "cause": "nope",
            "fix": "inspect the per-finding reject cause in Filigree's report and re-emit once the "
            "finding is acceptable",
            "fingerprint": "abc",
        }
    ],
    "warnings": [],
    "status": 422,
    "auth_rejected": False,
    "token_sent": True,
    "url": "http://x",
    "destination": {"url": "http://x", "project": None, "project_pinned": False},
}

_GOLDEN_LOOMWEAVE_DEFAULT: dict[str, Any] = {
    "configured": False,
    "reachable": None,
    "written": 0,
    "unresolved_qualnames": [],
    "disabled_reason": "not configured",
}


def test_filigree_builder_bytes_are_frozen() -> None:
    assert _eq(fs.filigree_emit_status(None, configured=False, include_destination=True), _GOLDEN_FILIGREE_NONE)
    assert _eq(fs.filigree_emit_status(_OK, configured=True, include_destination=True), _GOLDEN_FILIGREE_OK)
    assert _eq(fs.filigree_emit_status_from_block(_mcp_block(_AUTH)), _GOLDEN_FILIGREE_FROM_BLOCK_AUTH)
    assert _eq(fs.filigree_emit_status_from_block(_mcp_block(_PARTIAL)), _GOLDEN_FILIGREE_FROM_BLOCK_PARTIAL)


def test_loomweave_builder_bytes_are_frozen() -> None:
    assert _eq(fs.default_loomweave_write_status(), _GOLDEN_LOOMWEAVE_DEFAULT)
