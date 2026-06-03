"""Merge a `wardline` stdio server into a project's .mcp.json, preserving siblings."""

from __future__ import annotations

import json
from pathlib import Path

from wardline.core.errors import WardlineError
from wardline.core.safe_paths import safe_project_file

_ENTRY = {"type": "stdio", "command": "wardline", "args": ["mcp", "--root", "."]}


def merge_mcp_entry(root: Path) -> str:
    """Add/replace the `wardline` entry under mcpServers. Returns created|updated|unchanged."""
    path = safe_project_file(root, root / ".mcp.json", label=".mcp.json")
    if not path.exists():
        payload = {"mcpServers": {"wardline": dict(_ENTRY)}}
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return "created"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WardlineError(f"malformed .mcp.json: {exc}") from exc
    if not isinstance(data, dict):
        raise WardlineError(".mcp.json must be a JSON object")
    servers = data.get("mcpServers")
    if servers is None:
        servers = {}
        data["mcpServers"] = servers
    if not isinstance(servers, dict):
        raise WardlineError(".mcp.json mcpServers must be an object")
    if servers.get("wardline") == _ENTRY:
        return "unchanged"
    servers["wardline"] = dict(_ENTRY)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return "updated"
