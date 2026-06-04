"""Health checks and repair for Wardline's agent-install artifacts."""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path

from wardline.install.block import inject_block
from wardline.install.detect import _already_recorded, _detect_clarion, _detect_filigree, record_bindings
from wardline.install.mcp_json import (
    _codex_config_path,
    _codex_mcp_entry,
    _local_mcp_entry,
    install_codex_mcp,
    merge_mcp_entry,
)
from wardline.install.skill import install_skill


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    message: str


def _has_instruction_block(path: Path) -> bool:
    if not path.is_file():
        return False
    return "wardline:instructions:" in path.read_text(encoding="utf-8", errors="replace")


def _has_skill(root: Path, base: str) -> bool:
    return (root / base / "skills" / "wardline-gate" / "SKILL.md").is_file()


def _check_project_mcp(root: Path) -> CheckResult:
    path = root / ".mcp.json"
    if not path.is_file():
        return CheckResult(".mcp.json", False, "missing wardline server")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return CheckResult(".mcp.json", False, "invalid JSON")
    if not isinstance(raw, dict):
        return CheckResult(".mcp.json", False, "must be a JSON object")
    servers = raw.get("mcpServers")
    if not isinstance(servers, dict):
        return CheckResult(".mcp.json", False, "missing mcpServers object")
    entry = servers.get("wardline")
    if entry != _local_mcp_entry():
        return CheckResult(".mcp.json", False, "missing wardline server")
    return CheckResult(".mcp.json", True, "configured")


def _check_codex_mcp() -> CheckResult:
    path = _codex_config_path()
    if not path.is_file():
        return CheckResult("Codex MCP", False, "missing wardline server")
    try:
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return CheckResult("Codex MCP", False, "invalid TOML")
    servers = parsed.get("mcp_servers")
    entry = servers.get("wardline") if isinstance(servers, dict) else None
    if entry != _codex_mcp_entry():
        return CheckResult("Codex MCP", False, "missing wardline server")
    return CheckResult("Codex MCP", True, "configured")


def _check_bindings(root: Path) -> CheckResult:
    cfg = root / "wardline.yaml"
    text = cfg.read_text(encoding="utf-8", errors="replace") if cfg.is_file() else ""
    missing: list[str] = []
    for key, detector in (("clarion", _detect_clarion), ("filigree", _detect_filigree)):
        present, _url, _source = detector(root)
        if present and not _already_recorded(text, key):
            missing.append(key)
    if missing:
        return CheckResult("bindings", False, "missing " + ", ".join(missing))
    return CheckResult("bindings", True, "configured" if cfg.is_file() else "no siblings detected")


def check_install(root: Path) -> list[CheckResult]:
    """Return install health checks without mutating the project."""
    return [
        CheckResult("CLAUDE.md", _has_instruction_block(root / "CLAUDE.md"), "configured")
        if _has_instruction_block(root / "CLAUDE.md")
        else CheckResult("CLAUDE.md", False, "missing"),
        CheckResult("AGENTS.md", _has_instruction_block(root / "AGENTS.md"), "configured")
        if _has_instruction_block(root / "AGENTS.md")
        else CheckResult("AGENTS.md", False, "missing"),
        CheckResult(".claude skill", _has_skill(root, ".claude"), "configured")
        if _has_skill(root, ".claude")
        else CheckResult(".claude skill", False, "missing"),
        CheckResult(".agents skill", _has_skill(root, ".agents"), "configured")
        if _has_skill(root, ".agents")
        else CheckResult(".agents skill", False, "missing"),
        _check_project_mcp(root),
        _check_codex_mcp(),
        _check_bindings(root),
    ]


def repair_install(root: Path) -> dict[str, str]:
    """Repair agent-install artifacts and return per-check repair status."""
    statuses: dict[str, str] = {}
    for filename in ("CLAUDE.md", "AGENTS.md"):
        inject_block(root / filename)
        statuses[filename] = "repaired"
    install_skill(root)
    statuses[".claude skill"] = "repaired"
    statuses[".agents skill"] = "repaired"
    merge_mcp_entry(root)
    statuses[".mcp.json"] = "repaired"
    install_codex_mcp(root)
    statuses["Codex MCP"] = "repaired"
    record_bindings(root)
    statuses["bindings"] = "repaired"
    return statuses
