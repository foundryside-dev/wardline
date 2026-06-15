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

from wardline.core.config import filigree_server_scoped_url
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
# these (e.g. a fixed-port / remote filigree whose URL the published-port rung cannot
# reconstruct), they ARE the runtime emit/discovery target — repair preserves them.
# The one exception is a default-shaped (loopback) --filigree-url, which is repaired
# to the live server-mode project scope when one is discovered (see
# _desired_filigree_url): an unscoped loopback write fail-closes under a multi-project
# daemon, so leaving it would ship a broken out-of-the-box config.
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
    target). A non-loopback host is an operator's deliberate remote endpoint and is
    never rewritten."""
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return False
    return host in _LOOPBACK_HOSTS


def _desired_filigree_url(existing: str | None, discovered: str | None) -> str | None:
    """The ``--filigree-url`` to write. A discovered server-mode scoped URL is
    authoritative and replaces an absent or *wrongly-targeted* loopback value —
    repairing a stale, unscoped, or wrong-scoped local target — but it never overrides
    an operator's non-loopback (remote) endpoint, and it never churns a loopback entry
    that already names the correct port+scope (only the host spelling might differ;
    that is left as the operator wrote it). Absent a discovery, preserve verbatim."""
    if discovered is None:
        return existing
    if existing is None:
        return discovered
    if _is_loopback_url(existing) and not _same_scope_target(existing, discovered):
        return discovered
    return existing


def _desired_sibling_args(entry: object, root: Path) -> list[str]:
    """Sibling-URL args for the desired entry: operator-pinned ``--loomweave-url`` /
    ``--filigree-url`` preserved in original order, with the filigree target repaired
    to the live server-mode project scope when one is discovered (see
    :func:`_desired_filigree_url`). A discovered scope with no existing flag is
    appended so a fresh install lands a working scoped target out of the box."""
    pairs = _flag_pairs(entry)
    existing_filigree = next((v for f, v in pairs if f == "--filigree-url"), None)
    desired_filigree = _desired_filigree_url(existing_filigree, filigree_server_scoped_url(root))

    out: list[str] = []
    saw_filigree = False
    for flag, value in pairs:
        if flag == "--filigree-url":
            saw_filigree = True
            if desired_filigree is not None:
                out.extend(("--filigree-url", desired_filigree))
        else:
            out.extend((flag, value))
    if not saw_filigree and desired_filigree is not None:
        out.extend(("--filigree-url", desired_filigree))
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

    An existing entry's operator-pinned ``--loomweave-url`` and (remote)
    ``--filigree-url`` args are preserved (they are the runtime emit/discovery target
    when the published-port rung cannot reconstruct them). When Filigree runs in
    server mode for *root*, a default-shaped (loopback) or absent ``--filigree-url`` is
    set/repaired to the live project scope so a fresh install lands a working,
    fail-close-safe emit target out of the box."""
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
