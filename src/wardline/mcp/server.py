"""SP8: the Wardline MCP server — tools/resources/prompts wired to core/.

Stateless: every tool call is a pure function of (disk + config). Rooted at a
project path (launch cwd by default)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wardline._version import __version__
from wardline.core import config as config_mod
from wardline.core.config_schema import WARDLINE_SCHEMA
from wardline.core.descriptor import descriptor_to_yaml
from wardline.core.errors import WardlineError
from wardline.core.explain import explain_finding
from wardline.core.finding import Finding, Severity
from wardline.core.run import gate_decision, run_scan
from wardline.mcp.protocol import JsonRpcServer, McpError
from wardline.scanner.rules import _ALL_RULE_CLASSES


class ToolError(Exception):
    """Raised by a tool handler for a tool-EXECUTION error the agent must read
    and act on. Returned as an ``isError`` result (content the client reliably
    surfaces to the model), NOT a JSON-RPC error. Tasks 8/9 reuse it (e.g. the
    judge tool's missing-API-key remediation)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass(frozen=True, slots=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any], Path], Any]
    network: bool = False  # advertised in description for the judge tool


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(f.to_jsonl())
    return parsed


def _cfg(args: dict[str, Any], root: Path) -> Path | None:
    return root / args["config"] if args.get("config") else None


def _scan(args: dict[str, Any], root: Path) -> dict[str, Any]:
    path = root / args["path"] if args.get("path") else root
    fail_on = args.get("fail_on")
    result = run_scan(path, config_path=_cfg(args, root))
    decision = gate_decision(result, Severity(fail_on) if fail_on else None)
    return {
        "files_scanned": result.files_scanned,
        "findings": [_finding_to_dict(f) for f in result.findings],
        "summary": {
            "total": result.summary.total,
            "active": result.summary.active,
            "baselined": result.summary.baselined,
            "waived": result.summary.waived,
            "judged": result.summary.judged,
        },
        "gate": {"tripped": decision.tripped, "fail_on": decision.fail_on,
                 "exit_class": decision.exit_class},
    }


def _explain_taint(args: dict[str, Any], root: Path) -> dict[str, Any]:
    # path+line identify a source location of an existing finding (not a scan
    # subdir): pass path through only when a line is also given.
    exp = explain_finding(
        root,
        fingerprint=args.get("fingerprint"),
        path=args.get("path") if args.get("line") is not None else None,
        line=args.get("line"),
        config_path=_cfg(args, root),
    )
    if exp is None:
        raise ToolError(
            "fingerprint not in current scan; your code changed since the scan that "
            "produced it — re-scan.",
        )
    return {
        "fingerprint": exp.fingerprint,
        "rule_id": exp.rule_id,
        "sink_qualname": exp.sink_qualname,
        "location": {"path": exp.path, "line": exp.line},
        "tier_in": exp.tier_in,
        "tier_out": exp.tier_out,
        "immediate_tainted_callee": exp.immediate_tainted_callee,
        "source_boundary_qualname": exp.source_boundary_qualname,
        "resolved_call_count": exp.resolved_call_count,
        "unresolved_call_count": exp.unresolved_call_count,
    }


# Gate thresholds are the four defect severities. Severity also defines NONE
# (the "facts carry no defect severity" sentinel), deliberately excluded here:
# fail_on=NONE is not a meaningful gate threshold.
_SEVERITY_ENUM = ["CRITICAL", "ERROR", "WARN", "INFO"]


class WardlineMCPServer:
    def __init__(self, *, root: Path) -> None:
        self.root = Path(root)
        self.rpc = JsonRpcServer(server_name="wardline", server_version=__version__)
        self._tools: dict[str, Tool] = {}
        self._register_tools()
        self._wire()

    def _register_tools(self) -> None:
        self.add_tool(Tool(
            name="scan",
            description="Whole-program taint scan of the project. Returns structured "
                        "findings, the suppression summary (active = the gate population), "
                        "and the gate verdict.",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "subdir relative to project root"},
                    "fail_on": {"type": "string", "enum": _SEVERITY_ENUM},
                    "config": {"type": "string"},
                },
            },
            handler=_scan,
        ))
        self.add_tool(Tool(
            name="explain_taint",
            description="Explain ONE finding's taint: the immediate tainted callee, the "
                        "originating boundary, and the trust tiers at the sink. Call right "
                        "after scan and before editing — a stale fingerprint returns an error.",
            input_schema={
                "type": "object",
                "properties": {
                    "fingerprint": {"type": "string"},
                    "path": {"type": "string"},
                    "line": {"type": "integer"},
                    "config": {"type": "string"},
                },
            },
            handler=_explain_taint,
        ))

    def add_tool(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    # Four STABLE resources: their content is a pure function of (vocab + rule
    # catalog + effective config + schema), so it does NOT drift as the agent
    # edits code. Findings are deliberately excluded — they go stale on every
    # edit and come back only from a fresh `scan` tool call.
    _RESOURCES = (
        ("wardline://vocab", "Trust vocabulary descriptor", "text/yaml"),
        ("wardline://rules", "Rule catalog", "application/json"),
        ("wardline://config", "Effective project config", "application/json"),
        ("wardline://config-schema", "Config JSON Schema", "application/json"),
    )

    def _read_resource(self, uri: str | None) -> tuple[str, str]:
        """Return (text, mime_type) for a resource URI."""
        if uri == "wardline://vocab":
            return descriptor_to_yaml(), "text/yaml"
        if uri == "wardline://config-schema":
            return json.dumps(WARDLINE_SCHEMA, ensure_ascii=False), "application/json"
        if uri == "wardline://rules":
            # rule_id is a class attr; base_severity is set in __init__, so
            # instantiate cls() (its default base_severity = METADATA.base_severity).
            rules: list[dict[str, Any]] = []
            for cls in _ALL_RULE_CLASSES:
                inst = cls()
                # The human-meaningful description lives on the rule's METADATA, not
                # the class docstring (the rule classes carry module-level docstrings,
                # so cls.__doc__ is None) — use the real metadata field.
                rules.append({
                    "rule_id": inst.rule_id,
                    "base_severity": inst.base_severity.value,
                    "description": cls.metadata.description,
                })
            return json.dumps({"rules": rules}, ensure_ascii=False), "application/json"
        if uri == "wardline://config":
            cfg = config_mod.load(self.root / "wardline.yaml")
            return json.dumps({
                "source_roots": list(cfg.source_roots),
                "exclude": list(cfg.exclude),
                "rules_enable": list(cfg.rules_enable),
                "rules_severity": dict(cfg.rules_severity),
            }, ensure_ascii=False), "application/json"
        raise McpError(f"unknown resource: {uri}")

    def _wire(self) -> None:
        self.rpc.capabilities["tools"] = {"listChanged": False}
        self.rpc.register("tools/list", self._tools_list)
        self.rpc.register("tools/call", self._tools_call)
        self.rpc.capabilities["resources"] = {"listChanged": False}
        self.rpc.register("resources/list", self._resources_list)
        self.rpc.register("resources/read", self._resources_read)

    def _tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"tools": [
            {"name": t.name, "description": t.description, "inputSchema": t.input_schema}
            for t in self._tools.values()
        ]}

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        tool = self._tools.get(name) if name is not None else None
        if tool is None:
            # Protocol fault (caller bug) → JSON-RPC error, not an agent-actionable
            # tool-execution outcome.
            raise McpError(f"unknown tool: {name}")
        try:
            payload = tool.handler(arguments, self.root)
        except ToolError as exc:
            return self._is_error(exc.message)
        except WardlineError as exc:
            # Bad config / unreadable path during a tool call: a tool-execution
            # error the agent must read and act on → isError result.
            return self._is_error(str(exc))
        return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]}

    def _resources_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"resources": [
            {"uri": uri, "name": name, "mimeType": mime}
            for uri, name, mime in self._RESOURCES
        ]}

    def _resources_read(self, params: dict[str, Any]) -> dict[str, Any]:
        uri = params.get("uri")
        text, mime = self._read_resource(uri)
        return {"contents": [{"uri": uri, "mimeType": mime, "text": text}]}

    @staticmethod
    def _is_error(text: str) -> dict[str, Any]:
        return {"content": [{"type": "text", "text": text}], "isError": True}
