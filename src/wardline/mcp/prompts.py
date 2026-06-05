"""MCP prompt catalog for Wardline."""

from __future__ import annotations

from typing import Any

from wardline.mcp.protocol import _INVALID_PARAMS, McpError

LOOP_PROMPT = (
    "Wardline is whole-program and on-disk. The loop:\n"
    "1. Call `scan` with `explain: true` (whole project). Each active defect carries an "
    "inline `explanation` (immediate tainted callee, source boundary, trust tiers) - no "
    "per-finding round-trip. Read `summary.active` and `gate.tripped`.\n"
    "2. For the FULL N-hop chain to the originating boundary (needs a configured Loomweave "
    "store), call `explain_taint` with the finding's `qualname` as `sink_qualname` and "
    "`chain: true`.\n"
    "3. Fix at the BOUNDARY, not the sink - add validation/rejection at the right hop.\n"
    "4. Re-`scan`. Only baseline/waiver a finding you have judged a true non-issue, with a reason."
)


def list_prompts() -> list[dict[str, str]]:
    return [{"name": "wardline:loop", "description": "The intended scan->explain->fix->rescan loop."}]


def get_prompt(name: str | None) -> dict[str, Any]:
    if name != "wardline:loop":
        raise McpError(f"unknown prompt: {name}", code=_INVALID_PARAMS)
    return {
        "description": "The intended scan->explain->fix->rescan loop.",
        "messages": [{"role": "user", "content": {"type": "text", "text": LOOP_PROMPT}}],
    }
