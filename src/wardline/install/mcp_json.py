"""Install Wardline MCP entries for Claude Code and Codex."""

from __future__ import annotations

import json
import re
import shutil
import sys
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from wardline.core.config import (
    filigree_server_scoped_url,
)
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


# Sibling-endpoint flags found in project `.mcp.json`, reconciled on repair (see
# _desired_sibling_url). The file is repository-controlled input, so remote/non-loopback
# pins are not trusted as operator intent and are dropped during canonicalization.
#   - a loopback pin is preserved because repair cannot prove a sibling daemon is
#     live from repository-owned `.weft/<sibling>/ephemeral.port` alone, unless
#     Filigree SERVER mode provides a scoped target from Filigree's home registry.
#   - a loopback pin with no live daemon is preserved verbatim (cannot be improved).
_PRESERVED_ARG_FLAGS = ("--filigree-url", "--loomweave-url")

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _flag_pairs(entry: object) -> list[tuple[str, str]]:
    """Operator-pinned ``(flag, value)`` pairs from an existing wardline entry's args,
    in the order the operator wrote them. Returns ``[]`` for any shape that isn't a
    list-of-args. Original order is preserved so an already-correct entry is recognized
    as ``unchanged`` and is never needlessly reordered on repair."""
    if not isinstance(entry, dict):
        return []
    args = entry.get("args")
    if not isinstance(args, list):
        return []
    pairs: list[tuple[str, str]] = []
    i = 0
    while i < len(args):
        flag = args[i]
        if flag in _PRESERVED_ARG_FLAGS and i + 1 < len(args) and isinstance(args[i + 1], str):
            pairs.append((flag, args[i + 1]))
            i += 2
            continue
        i += 1
    return pairs


def _same_scope_target(a: str, b: str) -> bool:
    """True when two URLs name the same Filigree write target up to loopback host
    spelling — identical port and path (the scope-bearing parts). Lets an already-
    correct entry that merely spells the host ``127.0.0.1`` (vs our ``localhost``) be
    recognised as correct and preserved verbatim, rather than churned every repair."""
    try:
        pa, pb = urlsplit(a), urlsplit(b)
        # .port lazily parses the authority; a malformed literal (http://localhost:notaport)
        # raises ValueError HERE, not at urlsplit. Parse both inside the guard so a bad
        # preserved URL reads as non-matching (and gets replaced) instead of crashing repair.
        a_port, b_port = pa.port, pb.port
    except ValueError:
        return False
    if pa.hostname not in _LOOPBACK_HOSTS or pb.hostname not in _LOOPBACK_HOSTS:
        return False
    return (a_port, pa.path) == (b_port, pb.path)


def _is_loopback_url(value: str) -> bool:
    """True when *value* is a loopback HTTP URL (a default-shaped, locally-rebuildable
    target). Non-loopback project-config endpoints are not treated as trusted repair
    input."""
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return False
    return host in _LOOPBACK_HOSTS


def _desired_sibling_url(flag: str, existing: str | None, root: Path) -> str | None:
    """The value to write for *flag* (``--filigree-url`` / ``--loomweave-url``), or
    ``None`` to DROP the flag entirely.

    Project `.mcp.json` is repo-controlled input. Non-loopback pins found there are
    dropped, not preserved, because repair cannot distinguish operator intent from a
    committed exfil endpoint. A loopback pin is preserved verbatim unless Filigree
    server mode supplies a home-registry-scoped target: repository-owned published
    port files are not live/identity proof, so they are not enough to delete or replace
    an explicit local pin. A fresh entry (no pin) only gains a flag in Filigree server
    mode, where the scoped target must be baked."""
    if existing is not None and not _is_loopback_url(existing):
        existing = None  # untrusted remote pin from repo config; treat as absent
    if flag == "--filigree-url":
        scope = filigree_server_scoped_url(root)
        if scope is not None:
            if existing is None:
                return scope  # fresh server-mode install lands a working scoped target
            return existing if _same_scope_target(existing, scope) else scope
    return existing


def _desired_sibling_args(entry: object, root: Path) -> list[str]:
    """Sibling-URL args for the desired entry: each operator-pinned ``--filigree-url``
    / ``--loomweave-url`` reconciled by :func:`_desired_sibling_url` (preserved,
    repaired-to-scope, or DROPPED) in the operator's original order. A Filigree
    server-mode scope with no existing flag is appended so a fresh install lands a
    working scoped target out of the box."""
    pairs = _flag_pairs(entry)
    existing = {flag: value for flag, value in pairs}
    desired = {flag: _desired_sibling_url(flag, existing.get(flag), root) for flag in _PRESERVED_ARG_FLAGS}

    out: list[str] = []
    seen: set[str] = set()
    for flag, _value in pairs:
        seen.add(flag)
        value = desired[flag]
        if value is not None:
            out.extend((flag, value))
    for flag in _PRESERVED_ARG_FLAGS:
        if flag not in seen:
            value = desired[flag]
            if value is not None:
                out.extend((flag, value))
    return out


def _desired_local_entry(existing: object, root: Path) -> dict[str, object]:
    """The canonical local entry, augmented with the desired sibling-URL args (see
    :func:`_desired_sibling_args`). Idempotent: re-running over the desired entry
    reproduces it."""
    entry = _local_mcp_entry()
    extra = _desired_sibling_args(existing, root)
    if extra:
        base_args = entry["args"]
        assert isinstance(base_args, list)
        entry["args"] = [*base_args, *extra]
    return entry


def merge_mcp_entry(root: Path) -> str:
    """Add/replace the `wardline` entry under mcpServers. Returns created|updated|unchanged.

    Existing sibling URL args are reconciled from repository-controlled `.mcp.json`
    input: remote/non-loopback values are dropped, and loopback values are preserved
    unless Filigree server mode supplies a scoped home-registry target. When Filigree
    runs in server mode for *root*, a default-shaped (loopback) or absent
    ``--filigree-url`` is set/repaired to the live project scope so a fresh install
    lands a working, fail-close-safe emit target out of the box."""
    path = safe_project_file(root, root / ".mcp.json", label=".mcp.json")
    if not path.exists():
        payload = {"mcpServers": {"wardline": _desired_local_entry(None, root)}}
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
    entry = _desired_local_entry(servers.get("wardline"), root)
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
