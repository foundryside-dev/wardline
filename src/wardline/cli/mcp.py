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
@click.option("--read-only", is_flag=True, help="Disable MCP tools that require write capability.")
@click.option("--no-network", is_flag=True, help="Disable MCP tools that require network capability.")
def mcp(
    root: Path,
    loomweave_url: str | None,
    filigree_url: str | None,
    read_only: bool,
    no_network: bool,
) -> None:
    """Run the Wardline MCP server over stdio (JSON-RPC 2.0)."""
    from wardline.core.config import resolve_filigree_url, resolve_loomweave_url

    # 3rd positional (config_path) is the reserved hook for the pending hub
    # sibling-endpoint key (weft-a2f4cf95c7); not read today. We pass None here whereas the
    # CLI scan path threads weft_config_path(root) — harmless until the hook lands, at which
    # point thread the real path here too for parity. See resolve_loomweave_url's docstring.
    loomweave_url = resolve_loomweave_url(loomweave_url, root, None)
    filigree_url = resolve_filigree_url(filigree_url, root, None)
    WardlineMCPServer(
        root=root,
        loomweave_url=loomweave_url,
        filigree_url=filigree_url,
        allow_write=not read_only,
        allow_network=not no_network,
    ).rpc.run_stdio()
