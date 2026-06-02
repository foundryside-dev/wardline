# src/wardline/cli/findings.py
"""`wardline findings` — read-only: scan and print filtered findings as JSONL.

The CLI counterpart of the MCP `scan(where=)` query, sharing core/finding_query
so the capability is identical across surfaces. No file output, no Filigree/Clarion
emission — a pure read lens for an agent driving the CLI."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.finding_query import filter_findings
from wardline.core.run import run_scan


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--where", "where_json", default=None, help='JSON filter object, e.g. \'{"rule_id":"PY-WL-106"}\'.')
def findings(path: Path, config_path: Path | None, where_json: str | None) -> None:
    """Scan PATH and print filtered findings as JSONL (read-only)."""
    where = None
    if where_json is not None:
        try:
            where = json.loads(where_json)
        except json.JSONDecodeError as exc:
            click.echo(f"error: --where must be valid JSON: {exc}", err=True)
            raise SystemExit(2) from exc
        if not isinstance(where, dict):
            click.echo("error: --where must be a JSON object", err=True)
            raise SystemExit(2)
    result = run_scan(path, config_path=config_path)
    try:
        selected = filter_findings(result.findings, where)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    for f in selected:
        click.echo(f.to_jsonl())
