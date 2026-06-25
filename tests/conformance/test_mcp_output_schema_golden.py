"""B1/B2 freeze: the MCP tool ``outputSchema`` surface is pinned to a COMMITTED golden.

The sibling oracle (``test_mcp_structured_output.py``) validates each tool's live
``structuredContent`` against *that same tool's live ``outputSchema``* — a CIRCULAR
gate. It proves the emission is internally consistent with whatever schema the code
currently declares, but it cannot catch a schema that silently DRIFTS: loosen
``_SCAN_OUTPUT_SCHEMA`` (drop a required field, widen a type, add a property) and the
circular oracle stays green because the payload is re-validated against the loosened
copy.

This module breaks the circle. The 18 declared tool output schemas are frozen to a
committed golden file; any change to the live in-code schema — intended or not — is
forced to land as a deliberate, reviewable re-vendor of the golden bytes.

Two layers, both in the DEFAULT suite (one-sided seam — Wardline is the sole producer
of its own outputSchema, so there is no upstream peer to drift-check against; the golden
IS the contract):

1. BYTE-PIN — ``VENDORED_BLOB_SHA`` pins the golden file's git blob hash. ANY byte
   change to ``mcp_output_schemas.golden.json`` fails loudly. The pin is updated in the
   SAME commit as a deliberate re-freeze.
2. LIVE-EQUALS-GOLDEN — the live ``tools/list`` ``outputSchema`` map must equal the
   committed golden exactly. This is the non-circular assertion: the schemas are
   compared against a frozen artifact, not against themselves.

RE-FREEZE PROCEDURE — when a tool's outputSchema legitimately changes:
    1. Regenerate the golden from the live surface (canonical JSON: ``json.dumps(
       schemas, indent=2, sort_keys=True) + "\n"``).
    2. Update ``VENDORED_BLOB_SHA`` to ``git hash-object
       tests/conformance/mcp_output_schemas.golden.json`` in the SAME commit.
    3. Re-run conformance and confirm the sibling structured-output oracle stays green.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from wardline.mcp.server import WardlineMCPServer

_GOLDEN_PATH = Path(__file__).parent / "mcp_output_schemas.golden.json"
_GOLDEN: dict[str, Any] = json.loads(_GOLDEN_PATH.read_text("utf-8"))

# git blob hash of the committed golden (``git hash-object``). A deliberate re-freeze
# updates this constant in the SAME commit as the new bytes — see the RE-FREEZE
# PROCEDURE in this module's header.
VENDORED_BLOB_SHA = "8341a594e22755adfe7f3dfdb7e345086d7378e8"

# The published 18-tool surface (advertisement order), pinned independently of the
# sibling oracle so a surface change is caught here too.
EXPECTED_TOOLS = (
    "scan",
    "scan_job_start",
    "scan_job_status",
    "scan_job_cancel",
    "explain_taint",
    "dossier",
    "assure",
    "decorator_coverage",
    "attest",
    "verify_attestation",
    "file_finding",
    "scan_file_findings",
    "judge",
    "baseline",
    "waiver_add",
    "fix",
    "doctor",
    "rekey",
)

_FIXTURE = Path("tests/fixtures/sample_project")


def _live_output_schemas() -> dict[str, Any]:
    """The live ``outputSchema`` map keyed by tool name, straight off ``tools/list``."""
    server = WardlineMCPServer(root=_FIXTURE)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert "error" not in resp, resp
    tools = resp["result"]["tools"]
    return {t["name"]: t["outputSchema"] for t in tools}


# --------------------------------------------------------------------------- #
# Structural self-tests on the golden — a malformed / truncated re-freeze fails loudly.
# --------------------------------------------------------------------------- #


def test_golden_covers_exactly_the_published_surface() -> None:
    # The golden is canonical-sorted JSON (sort_keys), so compare the surface as a SET;
    # advertisement order is pinned separately by the live-bytes / byte-pin layers.
    assert set(_GOLDEN) == set(EXPECTED_TOOLS)


def test_golden_schemas_are_object_typed() -> None:
    # Every frozen schema is a non-empty object schema (the 2025-06-18 structured-output
    # contract) — a golden that froze a ``None`` or scalar would be vacuous.
    for name, schema in _GOLDEN.items():
        assert isinstance(schema, dict) and schema, f"{name}: golden schema is not a non-empty object"
        assert schema["type"] == "object", f"{name}: golden schema is not object-typed"


# --------------------------------------------------------------------------- #
# Layer 1 — byte-pin the committed golden.
# --------------------------------------------------------------------------- #


def test_golden_matches_vendored_blob_pin() -> None:
    assert len(VENDORED_BLOB_SHA) == 40 and set(VENDORED_BLOB_SHA) <= set("0123456789abcdef"), (
        f"VENDORED_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {VENDORED_BLOB_SHA!r}"
    )
    data = _GOLDEN_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == VENDORED_BLOB_SHA, (
        f"the frozen golden changed (git blob {actual}, pinned {VENDORED_BLOB_SHA}) — "
        "if this was a deliberate re-freeze, update VENDORED_BLOB_SHA in the same commit "
        "and re-run conformance; if not, someone edited the golden by hand (forbidden — "
        "regenerate it from the live surface; see the RE-FREEZE PROCEDURE in this module's header)"
    )


# --------------------------------------------------------------------------- #
# Layer 2 — the live in-code schemas must EQUAL the frozen golden (breaks the
# circular self-validation in test_mcp_structured_output.py).
# --------------------------------------------------------------------------- #


def test_live_output_schemas_equal_the_frozen_golden() -> None:
    live = _live_output_schemas()
    assert live == _GOLDEN, (
        "the live MCP tool outputSchema surface has drifted from the committed golden "
        "(tests/conformance/mcp_output_schemas.golden.json) — a schema was added, removed, "
        "or changed. If this is a deliberate, reviewed change, re-freeze the golden and bump "
        "VENDORED_BLOB_SHA in the same commit (see the RE-FREEZE PROCEDURE); otherwise revert "
        "the schema change."
    )


def test_live_canonical_bytes_match_the_golden_file_bytes() -> None:
    # Stronger than dict-equality: the canonical serialization of the live surface must
    # be byte-identical to the committed file, so the byte-pin above genuinely tracks the
    # live schemas (no whitespace / ordering escape hatch).
    live = _live_output_schemas()
    canonical = json.dumps(live, indent=2, sort_keys=True) + "\n"
    assert canonical.encode("utf-8") == _GOLDEN_PATH.read_bytes(), (
        "the canonical serialization of the live outputSchema surface is not byte-identical "
        "to the committed golden — re-freeze per the RE-FREEZE PROCEDURE."
    )
