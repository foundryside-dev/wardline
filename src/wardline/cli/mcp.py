# src/wardline/cli/mcp.py
"""`wardline mcp` — launch the dependency-free stdio MCP server (SP8)."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.mcp.server import WardlineMCPServer


@click.command()
@click.option("--root", type=click.Path(exists=True, file_okay=False, path_type=Path),
              default=".", help="Project root the server scans (default: cwd).")
@click.option("--clarion-url", "clarion_url", default=None,
              help="Clarion taint-store URL: `scan` writes facts; `explain_taint` queries it.")
def mcp(root: Path, clarion_url: str | None) -> None:
    """Run the Wardline MCP server over stdio (JSON-RPC 2.0)."""
    WardlineMCPServer(root=root, clarion_url=clarion_url).rpc.run_stdio()
