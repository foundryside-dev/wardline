# src/wardline/cli/dossier.py
"""`wardline dossier` — the one-call entity dossier (Track 4).

Thin delegator to ``weft_dossier.build_weft_dossier`` (the same function the MCP
``dossier`` tool calls — CLI and MCP identical by construction). Prints the
freshness-honest, SEI-keyed envelope as JSON: Wardline's own trust posture plus
Loomweave linkages and Filigree open work, each degrading to an honest ``unavailable``
when its source is absent.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.config import resolve_filigree_url, resolve_loomweave_url
from wardline.core.errors import WardlineError


@click.command()
@click.argument("entity", type=str)
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--loomweave-url",
    "loomweave_url",
    default=None,
    help="Loomweave URL: resolve the entity's SEI + read call-graph linkages (opt-in, fail-soft).",
)
@click.option(
    "--filigree-url",
    "filigree_url",
    default=None,
    help="Filigree URL: read entity-associations (open work) keyed on the SEI (opt-in, fail-soft).",
)
def dossier(
    entity: str,
    path: Path,
    config_path: Path | None,
    loomweave_url: str | None,
    filigree_url: str | None,
) -> None:
    """Assemble the one-call dossier for ENTITY (a function qualname) under PATH."""
    from wardline.weft_dossier import build_weft_dossier

    try:
        loomweave_url = resolve_loomweave_url(loomweave_url, path, config_path)
        filigree_url = resolve_filigree_url(filigree_url, path, config_path)
        loomweave_client = None
        if loomweave_url is not None:
            from wardline.loomweave.client import LoomweaveClient
            from wardline.loomweave.config import load_loomweave_token, resolve_project_name

            loomweave_client = LoomweaveClient(
                loomweave_url,
                secret=load_loomweave_token(path),
                project=resolve_project_name(path),
            )
        result = build_weft_dossier(
            entity,
            root=path,
            loomweave_client=loomweave_client,
            filigree_url=filigree_url,
            config_path=config_path,
            confine_to_root=True,
        )
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
