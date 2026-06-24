"""Shared MCP tool plumbing: schemas, path guards, and output helpers."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from wardline.core.finding import Finding


class ToolError(Exception):
    """Tool-execution error returned to the MCP client as an isError result."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ToolCapability(StrEnum):
    """Capability classes enforced centrally before MCP tool handlers run."""

    READ = "read"
    WRITE = "write"
    NETWORK = "network"


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    """Server-side policy for tool side effects."""

    allow_write: bool = True
    allow_network: bool = True

    def denial(self, tool_name: str, capabilities: frozenset[ToolCapability]) -> str | None:
        if ToolCapability.NETWORK in capabilities and not self.allow_network:
            return f"tool {tool_name!r} requires network capability, but network tools are disabled"
        if ToolCapability.WRITE in capabilities and not self.allow_write:
            return f"tool {tool_name!r} requires write capability, but write tools are disabled"
        return None


@dataclass(frozen=True, slots=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any], Path], Any]
    network: bool = False
    capabilities: frozenset[ToolCapability] = frozenset({ToolCapability.READ})
    # B1/B2 (wardline-47ff226ebe / wardline-e63204176b): MCP rev 2025-06-18 structured
    # output + 2025-03-26 display metadata. ``annotations`` is the standard MCP
    # ToolAnnotations object (title, readOnlyHint, destructiveHint, idempotentHint,
    # openWorldHint). CONVENTION: the public hints and legacy ``capabilities`` entry may
    # conservatively describe possible integration side effects (for example ``scan`` can
    # write to Filigree/Loomweave when those URLs resolve). ToolPolicy must enforce the
    # actual per-call capability set from _effective_tool_capabilities, not assume this
    # static advertisement is the whole runtime truth.
    title: str | None = None
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        capabilities = set(self.capabilities) or {ToolCapability.READ}
        if self.network:
            capabilities.add(ToolCapability.NETWORK)
        object.__setattr__(self, "capabilities", frozenset(capabilities))


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(finding.to_jsonl())
    return parsed


def resolve_under_root(root: Path, arg: str) -> Path:
    """Resolve a caller-supplied path/config arg against root and refuse escapes."""
    candidate = (root / arg).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ToolError(f"path must be within the project root: {arg!r}")
    return candidate


def cfg(args: dict[str, Any], root: Path) -> Path | None:
    return resolve_under_root(root, args["config"]) if args.get("config") else None


def require(args: dict[str, Any], key: str) -> Any:
    val = args.get(key)
    if val is None or (isinstance(val, str) and not val.strip()):
        raise ToolError(f"{key} is required")
    return val
