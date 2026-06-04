"""`wardline decorator-coverage` — row-level trust decorator inventory."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.config import resolve_clarion_url, resolve_filigree_url
from wardline.core.errors import WardlineError


@click.command(name="decorator-coverage")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--clarion-url", default=None, help="Clarion URL for optional SEI/content status.")
@click.option("--filigree-url", default=None, help="Filigree URL for optional linked issue/open-work status.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "human"]),
    default="json",
    help="Output format: json (default) or human-readable table.",
)
def decorator_coverage(
    path: Path,
    config_path: Path | None,
    clarion_url: str | None,
    filigree_url: str | None,
    output_format: str,
) -> None:
    """List every Wardline trust-decorated entity under PATH."""
    from wardline.loom_decorator_coverage import build_loom_decorator_coverage

    try:
        clarion_url = resolve_clarion_url(clarion_url, path, config_path)
        filigree_url = resolve_filigree_url(filigree_url, path, config_path)
        clarion_client = None
        if clarion_url is not None:
            from wardline.clarion.client import ClarionClient
            from wardline.clarion.config import load_clarion_token, resolve_project_name

            clarion_client = ClarionClient(
                clarion_url,
                secret=load_clarion_token(path),
                project=resolve_project_name(path),
            )
        report = build_loom_decorator_coverage(
            path,
            clarion_client=clarion_client,
            filigree_url=filigree_url,
            config_path=config_path,
            confine_to_root=True,
        )
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    if output_format == "json":
        click.echo(json.dumps(report.to_dict(), sort_keys=True))
    else:
        _render_human(report.to_dict())


def _render_human(report: dict[str, object]) -> None:
    summary = report["summary"]
    assert isinstance(summary, dict)
    click.echo(
        "Decorator coverage: "
        f"{summary['total']} total, {summary['clean']} clean, {summary['defect']} defect, "
        f"{summary['unknown']} unknown, {summary['suppressed']} suppressed"
    )
    rows = report["rows"]
    assert isinstance(rows, list)
    for row in rows:
        assert isinstance(row, dict)
        tickets = row.get("work", {}).get("tickets", []) if isinstance(row.get("work"), dict) else []
        click.echo(
            f"{row['qualname']}  {row['path']}:{row['line']}  "
            f"{row['finding_state']}  declared={row['declared_tier']} actual={row['actual_tier']}  "
            f"tickets={len(tickets)}"
        )
