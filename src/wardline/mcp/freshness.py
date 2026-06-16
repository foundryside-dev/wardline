"""Server self-identification + source-freshness verdict for the MCP `doctor` tool.

The 2026-06-06 stale-server incident: long-lived `wardline mcp` processes (editable
install) kept serving code that predated the tree being edited, and nothing on the
wire said so — `initialize` reports only name+version, which does not change on an
editable re-install. The freshness verdict here is the mtime test that DOES catch it:
if any file under the imported ``wardline`` package is newer than this process's
start time, the running server is serving old code and must be restarted.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wardline._version import __version__

__all__ = ["attach_server_identity", "server_identity"]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


def _latest_source_mtime() -> tuple[float | None, str | None]:
    """(mtime, relative path) of the newest ``*.py`` under the imported wardline
    package, or (None, None) when nothing is statable. Walking the package the
    PROCESS imported (not the project root) is the point: that is the code this
    server is actually serving, wherever it is installed."""
    import wardline

    pkg_dir = Path(wardline.__file__).resolve().parent
    latest: float | None = None
    latest_path: str | None = None
    for p in pkg_dir.rglob("*.py"):
        try:
            mtime = p.stat().st_mtime
        except OSError:
            continue
        if latest is None or mtime > latest:
            latest = mtime
            latest_path = str(p.relative_to(pkg_dir))
    return latest, latest_path


def server_identity(*, root: Path, started_at: float) -> dict[str, Any]:
    """The running server's self-identification block. ``fresh`` is False when the
    on-disk package source changed after this process started."""
    latest, latest_path = _latest_source_mtime()
    fresh = latest is None or latest <= started_at
    identity: dict[str, Any] = {
        "package_version": __version__,
        "pid": os.getpid(),
        "project_root": str(root),
        "started_at": _iso(started_at),
        "source_latest_mtime": _iso(latest) if latest is not None else None,
        "source_latest_path": latest_path,
        "fresh": fresh,
    }
    return identity


def attach_server_identity(payload: dict[str, Any], *, root: Path, started_at: float) -> dict[str, Any]:
    """Merge the server block + a ``server.freshness`` check into a
    ``machine_readable_doctor`` envelope (same check shape, so the agent reads one
    uniform list). A stale server flips ``ok`` and lands in ``next_actions`` — it is
    a health failure: every other verdict in the payload came from old code."""
    identity = server_identity(root=root, started_at=started_at)
    payload["server"] = identity
    if identity["fresh"]:
        payload["checks"].append({"id": "server.freshness", "status": "ok", "fixed": False})
        return payload
    message = (
        f"wardline source changed after this MCP server started "
        f"({identity['source_latest_path']} at {identity['source_latest_mtime']}, "
        f"server started {identity['started_at']}) — this server is serving OLD code; "
        f"restart the wardline MCP server"
    )
    payload["checks"].append({"id": "server.freshness", "status": "error", "fixed": False, "message": message})
    payload["ok"] = False
    payload["next_actions"].append(f"server.freshness: {message}")
    return payload
