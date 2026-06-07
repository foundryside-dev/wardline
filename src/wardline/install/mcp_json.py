"""Install Wardline MCP entries for Claude Code and Codex."""

from __future__ import annotations

import json
import re
import shutil
import sys
import tomllib
from pathlib import Path
from typing import Any

from wardline.core.errors import WardlineError
from wardline.core.safe_paths import safe_project_file


def _find_wardline_command() -> str:
    """Find the Wardline executable, preferring stable absolute paths."""
    uv_tool_dir = Path.home() / ".local" / "bin"
    for name in ("wardline", "wardline.exe"):
        uv_tool_bin = uv_tool_dir / name
        if uv_tool_bin.is_file():
            return str(uv_tool_bin)
    which = shutil.which("wardline")
    if which:
        return which
    for name in ("wardline", "wardline.exe"):
        candidate = Path(sys.executable).parent / name
        if candidate.is_file():
            return str(candidate)
    return "wardline"


def _local_mcp_entry() -> dict[str, object]:
    return {"type": "stdio", "command": _find_wardline_command(), "args": ["mcp", "--root", "."]}


# Operator-pinned sibling-endpoint flags. When an existing .mcp.json entry carries
# these (e.g. a fixed-port / server-mode filigree whose URL the published-port rung
# cannot reconstruct), they ARE the runtime emit/discovery target — repair must keep
# them, not normalize them away.
_PRESERVED_ARG_FLAGS = ("--filigree-url", "--loomweave-url")


def _preserved_sibling_args(entry: object) -> list[str]:
    """Extract operator-pinned ``--filigree-url``/``--loomweave-url`` flag pairs from an
    existing wardline entry's args, in the order the operator wrote them. Returns ``[]``
    for any shape that isn't a list-of-args (a malformed entry contributes nothing to
    preserve). Original order is kept so an already-correct entry is recognized as
    ``unchanged`` and is never needlessly reordered on repair."""
    if not isinstance(entry, dict):
        return []
    args = entry.get("args")
    if not isinstance(args, list):
        return []
    preserved: list[str] = []
    i = 0
    while i < len(args):
        flag = args[i]
        if flag in _PRESERVED_ARG_FLAGS and i + 1 < len(args) and isinstance(args[i + 1], str):
            preserved.extend((flag, args[i + 1]))
            i += 2
            continue
        i += 1
    return preserved


def _desired_local_entry(existing: object) -> dict[str, object]:
    """The canonical local entry, augmented with any operator-pinned sibling-URL args
    carried by *existing*. Idempotent: re-running over the desired entry reproduces it."""
    entry = _local_mcp_entry()
    preserved = _preserved_sibling_args(existing)
    if preserved:
        base_args = entry["args"]
        assert isinstance(base_args, list)
        entry["args"] = [*base_args, *preserved]
    return entry


def merge_mcp_entry(root: Path) -> str:
    """Add/replace the `wardline` entry under mcpServers. Returns created|updated|unchanged.

    An existing entry's operator-pinned ``--filigree-url``/``--loomweave-url`` args are
    preserved (they are the runtime emit/discovery target when the published-port rung
    cannot reconstruct it)."""
    path = safe_project_file(root, root / ".mcp.json", label=".mcp.json")
    if not path.exists():
        payload = {"mcpServers": {"wardline": _local_mcp_entry()}}
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
    entry = _desired_local_entry(servers.get("wardline"))
    if servers.get("wardline") == entry:
        return "unchanged"
    servers["wardline"] = entry
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return "updated"


def _codex_config_path() -> Path:
    return Path.home() / ".codex" / "config.toml"


def _toml_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _codex_mcp_entry() -> dict[str, object]:
    # Codex MCP config is global. Do not pin a project root; let Codex launch
    # Wardline in the active workspace so cross-project use behaves correctly.
    return {"command": _find_wardline_command(), "args": ["mcp"]}


def _codex_server_block(server_config: dict[str, object]) -> str:
    args = server_config.get("args", [])
    if not isinstance(args, list):
        args = []
    rendered_args = ", ".join(f'"{_toml_quote(str(arg))}"' for arg in args)
    return (
        f'[mcp_servers.wardline]\ncommand = "{_toml_quote(str(server_config["command"]))}"\nargs = [{rendered_args}]\n'
    )


_TOML_HEADER_RE = re.compile(r"(?m)^\[([^\r\n\]]+)\][ \t]*(?:#[^\r\n]*)?(?:\r\n|\n|\r)")


def _parse_toml_header_path(inner: str) -> tuple[str, ...] | None:
    try:
        parsed = tomllib.loads(f"[{inner}]\n")
    except tomllib.TOMLDecodeError:
        return None
    path: list[str] = []
    cur: Any = parsed
    while True:
        if not isinstance(cur, dict):
            return None
        if not cur:
            return tuple(path) if path else None
        if len(cur) != 1:
            return None
        key, value = next(iter(cur.items()))
        path.append(key)
        cur = value


def _upsert_toml_table(content: str, table_name: str, table_block: str) -> str:
    newline_match = re.search(r"\r\n|\n|\r", content)
    newline = newline_match.group(0) if newline_match else "\n"
    rendered_block = newline.join(table_block.splitlines())
    if table_block.endswith(("\r\n", "\n", "\r")):
        rendered_block += newline

    target_path = tuple(table_name.split("."))
    match_span: tuple[int, int] | None = None
    for header in _TOML_HEADER_RE.finditer(content):
        if _parse_toml_header_path(header.group(1)) != target_path:
            continue
        next_header = _TOML_HEADER_RE.search(content, header.end())
        end = next_header.start() if next_header else len(content)
        match_span = (header.start(), end)
        break

    if match_span is not None:
        start, end = match_span
        updated = content[:start] + rendered_block + content[end:]
    else:
        updated = content
        if updated and not updated.endswith(("\r\n", "\n", "\r")):
            updated += newline
        updated += newline
        updated += rendered_block
    if not updated.endswith(("\r\n", "\n", "\r")):
        updated += newline
    return updated


def install_codex_mcp(root: Path) -> str:
    """Add/replace Wardline's global Codex MCP entry. Returns created|updated|unchanged."""
    del root  # Global Codex config uses runtime workspace discovery.
    config_path = _codex_config_path()
    existed = config_path.exists()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    desired = _codex_mcp_entry()

    existing = ""
    if existed:
        try:
            with config_path.open(newline="") as handle:
                existing = handle.read()
        except OSError as exc:
            raise WardlineError(f"cannot read {config_path}: {exc}") from exc

    if existing.strip():
        try:
            parsed = tomllib.loads(existing)
        except tomllib.TOMLDecodeError as exc:
            raise WardlineError(f"malformed {config_path}: {exc}") from exc
        mcp_servers = parsed.get("mcp_servers", {})
        wardline_server = mcp_servers.get("wardline") if isinstance(mcp_servers, dict) else None
        if isinstance(wardline_server, dict) and wardline_server == desired:
            return "unchanged"

    updated = _upsert_toml_table(existing, "mcp_servers.wardline", _codex_server_block(desired))
    try:
        with config_path.open("w", newline="") as handle:
            handle.write(updated)
    except OSError as exc:
        raise WardlineError(f"cannot write {config_path}: {exc}") from exc
    return "updated" if existed else "created"
