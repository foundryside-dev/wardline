# src/wardline/cli/lsp.py
"""`wardline lsp` — launch the dependency-free stdio LSP server (WP16)."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.lsp import LspServer


@click.command()
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    help="Project root the server scans (default: cwd).",
)
def lsp(root: Path) -> None:
    """Run the Wardline LSP diagnostics server over stdio (JSON-RPC 2.0)."""
    LspServer(root=root).run()
