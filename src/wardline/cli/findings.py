# src/wardline/cli/findings.py
"""`wardline findings` — read-only: scan and print filtered findings as JSONL.

The CLI counterpart of the MCP `scan(where=)` query, sharing core/finding_query
so the capability is identical across surfaces. No file output, no Filigree/Loomweave
emission — a pure read lens for an agent driving the CLI."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.errors import WardlineError
from wardline.core.finding_query import filter_findings
from wardline.core.run import run_scan
from wardline.core.sei_resolution import resolve_query_filters


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--where", "where_json", default=None, help='JSON filter object, e.g. \'{"rule_id":"PY-WL-106"}\'.')
# N-5 / X-5 (wardline-dc6f44707d): the common filters as first-class flat flags so
# an agent does not need the JSON --where blob (filigree-style flag shape).
@click.option(
    "--rule-id", "rule_id", default=None, help='Filter by rule id, e.g. PY-WL-101 (same as --where {"rule_id":...}).'
)
@click.option("--severity", default=None, help="Filter by severity (case-insensitive): CRITICAL/ERROR/WARN/INFO/NONE.")
@click.option("--sink", default=None, help="Filter by the finding's sink property, e.g. subprocess.run.")
def findings(
    path: Path,
    config_path: Path | None,
    where_json: str | None,
    rule_id: str | None,
    severity: str | None,
    sink: str | None,
) -> None:
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
    flat = {k: v for k, v in {"rule_id": rule_id, "severity": severity, "sink": sink}.items() if v is not None}
    if flat:
        # A flag and a --where key naming the same filter is ambiguous — refuse
        # rather than silently prefer one (the silent-override anti-pattern).
        overlap = sorted(set(flat) & set(where or {}))
        if overlap:
            click.echo(
                f"error: {', '.join(overlap)} given both as a flag and inside --where; pass each filter once",
                err=True,
            )
            raise SystemExit(2)
        where = {**(where or {}), **flat}
    result = run_scan(path, config_path=config_path)
    try:
        resolved_where = resolve_query_filters(where, path, config_path)
        selected = filter_findings(result.findings, resolved_where)
    except (ValueError, WardlineError) as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    for f in selected:
        click.echo(f.to_jsonl())
