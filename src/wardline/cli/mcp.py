# src/wardline/cli/mcp.py
"""`wardline mcp` — launch the dependency-free stdio MCP server (SP8)."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.mcp.server import WardlineMCPServer


@click.command()
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    help="Project root the server scans (default: cwd).",
)
@click.option(
    "--loomweave-url",
    "loomweave_url",
    default=None,
    help="Loomweave taint-store URL: `scan` writes facts; `explain_taint`/`dossier` query it.",
)
@click.option(
    "--filigree-url",
    "filigree_url",
    default=None,
    help=(
        "Filigree URL: `scan` POSTs findings to it (fail-soft); "
        "`dossier` reads entity-associations (open work) from it."
    ),
)
def mcp(root: Path, loomweave_url: str | None, filigree_url: str | None) -> None:
    """Run the Wardline MCP server over stdio (JSON-RPC 2.0)."""
    from wardline.core.config import resolve_filigree_url, resolve_loomweave_url

    loomweave_url = resolve_loomweave_url(loomweave_url, root, None)
    filigree_url = resolve_filigree_url(filigree_url, root, None)
    WardlineMCPServer(root=root, loomweave_url=loomweave_url, filigree_url=filigree_url).rpc.run_stdio()
