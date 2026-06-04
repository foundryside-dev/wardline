"""Shared MCP tool plumbing: schemas, path guards, and output helpers."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wardline.core.finding import Finding

if TYPE_CHECKING:
    from wardline.core.explain import TaintExplanation


class ToolError(Exception):
    """Tool-execution error returned to the MCP client as an isError result."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True, slots=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any], Path], Any]
    network: bool = False


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(finding.to_jsonl())
    return parsed


def explanation_to_dict(exp: TaintExplanation) -> dict[str, Any]:
    return {
        "tier_in": exp.tier_in,
        "tier_out": exp.tier_out,
        "immediate_tainted_callee": exp.immediate_tainted_callee,
        "source_boundary_qualname": exp.source_boundary_qualname,
        "resolved_call_count": exp.resolved_call_count,
        "unresolved_call_count": exp.unresolved_call_count,
    }


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
