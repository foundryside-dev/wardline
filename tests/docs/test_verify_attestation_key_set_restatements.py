"""The verify_attestation result key set is restated by hand in two places outside
the frozen golden — the MCP tool's own description tail and the MCP reference guide.

The golden freezes ``outputSchema`` only, so a future required key must be moved at
THREE sites and, until this module existed, only one of them was gated: measured, a
runtime mutation reverting the tool description to its pre-dual-read tail (dropping
``schema_recognized``) left the entire suite green.

These assertions compare prose against the schema constant, never against the golden,
so they cost no re-freeze budget and cannot go stale independently of the code.
"""

from __future__ import annotations

import re
from pathlib import Path

from wardline.mcp.server import _VERIFY_ATTESTATION_OUTPUT_SCHEMA, _VERIFY_ATTESTATION_TOOL

ROOT = Path(__file__).resolve().parents[2]

_REQUIRED = tuple(_VERIFY_ATTESTATION_OUTPUT_SCHEMA["required"])


def _brace_set(text: str) -> tuple[str, ...]:
    """The `{a, b, c}` key list a `Returns` sentence recites, in written order."""
    match = re.search(r"Returns[^{]*\{([^}]*)\}", text)
    assert match is not None, f"no `Returns {{...}}` key list found in: {text!r}"
    return tuple(part.strip() for part in match.group(1).split(","))


def test_tool_description_recites_exactly_the_declared_required_keys() -> None:
    assert _brace_set(_VERIFY_ATTESTATION_TOOL["description"]) == _REQUIRED


def test_mcp_reference_recites_exactly_the_declared_required_keys() -> None:
    mcp = (ROOT / "docs/reference/mcp.md").read_text(encoding="utf-8")
    section = mcp.split("## `verify_attestation`", 1)[1]
    assert _brace_set(section) == _REQUIRED


def test_mcp_reference_bundle_requirement_names_all_three_top_level_keys() -> None:
    # A bundle satisfying a `payload` + `signature` requirement alone can NEVER
    # verify: schema_recognized is a conjunct of signature_valid, so a missing
    # top-level tag forces both false. The guide said exactly that for a while.
    #
    # Anchored to the REQUIREMENT clause, not to the section: an earlier version of
    # this assertion searched the whole section for "`schema`" and passed under the
    # very mutation it exists to catch, because the explanatory sentence that
    # follows also mentions the tag. Scope a guard to the datum it is guarding.
    mcp = (ROOT / "docs/reference/mcp.md").read_text(encoding="utf-8")
    section = mcp.split("## `verify_attestation`", 1)[1].split("\n## ", 1)[0]
    match = re.search(r"`bundle` \(required — must contain ([^;)]*)", section)
    assert match is not None, "no `bundle` (required — must contain ...) clause found"
    required_clause = match.group(1)
    for key in ("`schema`", "`payload`", "`signature`"):
        assert key in required_clause, f"{key} missing from: {required_clause!r}"
