"""Shared MCP tool plumbing: schemas, path guards, and output helpers."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
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

    def __post_init__(self) -> None:
        capabilities = set(self.capabilities) or {ToolCapability.READ}
        if self.network:
            capabilities.add(ToolCapability.NETWORK)
        object.__setattr__(self, "capabilities", frozenset(capabilities))


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
        "remediation": remediation_to_dict(exp),
    }


def remediation_to_dict(exp: TaintExplanation) -> dict[str, Any]:
    if exp.rule_id != "PY-WL-101":
        return {
            "kind": "review_required",
            "rule_id": exp.rule_id,
            "summary": (
                "Review the finding and apply the rule-specific fix; no automated remediation hint is available."
            ),
            "sink_qualname": exp.sink_qualname,
            "source_qualname": exp.source_boundary_qualname,
            "caveat": "This hint is advisory and does not replace the factual taint explanation.",
        }

    source = exp.source_boundary_qualname or exp.immediate_tainted_callee
    sink = exp.sink_qualname
    if source and sink:
        summary = (
            f"Validate or normalize data from {source} before it reaches trusted producer {sink}. "
            "Add or repair a @trust_boundary only on the function that actually rejects invalid data."
        )
    elif sink:
        summary = (
            f"Validate or normalize the raw input before it reaches trusted producer {sink}; "
            "the taint source is unresolved in this explanation. Add or repair a @trust_boundary only where "
            "the code actually rejects invalid data."
        )
    else:
        summary = (
            "Validate or normalize the raw input before it reaches the trusted producer; the taint source is "
            "unresolved in this explanation. Add or repair a @trust_boundary only where the code actually "
            "rejects invalid data."
        )
    return {
        "kind": "boundary_placement",
        "rule_id": exp.rule_id,
        "summary": summary,
        "sink_qualname": sink,
        "source_qualname": source,
        "caveat": (
            "Do not use blind decorator insertion; mark a trust boundary only on code that validates "
            "and rejects invalid data."
        ),
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
