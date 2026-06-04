"""Health checks and repair for Wardline's agent-install artifacts."""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from wardline.clarion.config import load_clarion_token
from wardline.core.config import load
from wardline.core.errors import ConfigError
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


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    id: str
    status: str
    fixed: bool = False
    message: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"id": self.id, "status": self.status, "fixed": self.fixed}
        if self.message:
            data["message"] = self.message
        return data


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


def _check_config(root: Path, *, fixed: bool) -> DoctorCheck:
    try:
        load(root / "wardline.yaml")
    except ConfigError as exc:
        return DoctorCheck("wardline.config", "error", fixed=False, message=str(exc))
    return DoctorCheck("wardline.config", "ok", fixed=fixed)


def _check_mcp_registration(root: Path, *, before: dict[str, CheckResult]) -> DoctorCheck:
    project = _check_project_mcp(root)
    codex = _check_codex_mcp()
    fixed = any(not before.get(name, CheckResult(name, True, "")).ok for name in (".mcp.json", "Codex MCP")) and (
        project.ok and codex.ok
    )
    if project.ok and codex.ok:
        return DoctorCheck("mcp.registration", "ok", fixed=fixed)
    missing = ", ".join(f"{c.name}: {c.message}" for c in (project, codex) if not c.ok)
    return DoctorCheck("mcp.registration", "error", fixed=False, message=missing)


def _check_marker_package() -> DoctorCheck:
    try:
        decorators = import_module("wardline.decorators")
    except Exception as exc:
        return DoctorCheck("marker_package", "error", message=f"wardline.decorators not importable: {exc}")
    missing = [name for name in ("external_boundary", "trust_boundary", "trusted") if not hasattr(decorators, name)]
    if missing:
        return DoctorCheck("marker_package", "error", message="missing " + ", ".join(missing))
    return DoctorCheck("marker_package", "ok")


def _valid_http_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except Exception:
        return False
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def _config_url(root: Path, key: str) -> str | None:
    cfg = load(root / "wardline.yaml")
    value = cfg.clarion_url if key == "clarion" else cfg.filigree_url
    return value


def _check_url(root: Path, key: str, *, fixed: bool) -> DoctorCheck:
    env_key = "WARDLINE_CLARION_URL" if key == "clarion" else "WARDLINE_FILIGREE_URL"
    url = os.environ.get(env_key) or _config_url(root, key)
    check_id = f"{key}.url"
    if not url:
        return DoctorCheck(check_id, "ok", fixed=fixed, message="not configured")
    if _valid_http_url(url):
        return DoctorCheck(check_id, "ok", fixed=fixed)
    return DoctorCheck(check_id, "error", fixed=False, message=f"invalid URL: {url!r}")


def _check_decorator_grammar() -> DoctorCheck:
    try:
        from wardline.core.registry import REGISTRY
        from wardline.scanner.grammar import BUILTIN_BOUNDARY_TYPES
    except Exception as exc:
        return DoctorCheck("decorator_grammar", "error", message=f"cannot load grammar: {exc}")

    expected = {("wardline.decorators", name) for name in REGISTRY} | {("loom_markers", name) for name in REGISTRY}
    actual = {(bt.module_prefix, bt.canonical_name) for bt in BUILTIN_BOUNDARY_TYPES}
    missing = sorted(expected - actual)
    if missing:
        return DoctorCheck("decorator_grammar", "error", message=f"missing builtin boundary types: {missing}")
    return DoctorCheck("decorator_grammar", "ok")


def _check_scan_output_path(root: Path) -> DoctorCheck:
    output = root / "findings.jsonl"
    if output.exists() and output.is_dir():
        return DoctorCheck("scan.output_path", "error", message=f"{output} is a directory")
    if not root.exists() or not root.is_dir():
        return DoctorCheck("scan.output_path", "error", message=f"{root} is not a directory")
    if not os.access(root, os.W_OK):
        return DoctorCheck("scan.output_path", "error", message=f"{root} is not writable")
    return DoctorCheck("scan.output_path", "ok")


def _check_auth_token(root: Path) -> DoctorCheck:
    try:
        token = load_clarion_token(root)
    except OSError as exc:
        return DoctorCheck("auth.token", "error", message=f"cannot read auth token wiring: {exc}")
    if token:
        return DoctorCheck("auth.token", "ok")
    return DoctorCheck("auth.token", "ok", message="optional Clarion token not configured")


def machine_readable_doctor(root: Path, *, fix: bool = False) -> dict[str, Any]:
    """Return the shared machine-readable doctor shape, optionally repairing install bindings."""
    before = {check.name: check for check in check_install(root)}
    bindings_fixed = False
    if fix:
        repair_install(root)
        bindings_fixed = not before.get("bindings", CheckResult("bindings", True, "")).ok

    checks: list[DoctorCheck] = []
    checks.append(_check_config(root, fixed=fix and not (root / "wardline.yaml").exists()))
    checks.append(_check_mcp_registration(root, before=before))
    checks.append(_check_marker_package())
    try:
        checks.append(_check_url(root, "clarion", fixed=bindings_fixed))
    except ConfigError as exc:
        checks.append(DoctorCheck("clarion.url", "error", message=str(exc)))
    try:
        checks.append(_check_url(root, "filigree", fixed=bindings_fixed))
    except ConfigError as exc:
        checks.append(DoctorCheck("filigree.url", "error", message=str(exc)))
    checks.append(_check_decorator_grammar())
    checks.append(_check_scan_output_path(root))
    checks.append(_check_auth_token(root))

    next_actions = [f"{check.id}: {check.message}" for check in checks if not check.ok and check.message]
    return {
        "ok": all(check.ok for check in checks),
        "checks": [check.to_dict() for check in checks],
        "next_actions": next_actions,
    }


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
