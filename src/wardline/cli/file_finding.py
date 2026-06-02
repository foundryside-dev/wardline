# src/wardline/cli/file_finding.py
"""`wardline file-finding` — file ONE finding (by fingerprint) into a Filigree issue.

CLI counterpart of the MCP `file_finding` tool; both go through FiligreeIssueFiler."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.config import resolve_filigree_url
from wardline.core.errors import WardlineError
from wardline.core.filigree_issue import FiligreeIssueFiler


@click.command(name="file-finding")
@click.argument("fingerprint", type=str)
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--filigree-url", "filigree_url", default=None, help="Filigree Loom URL (else env/wardline.yaml).")
@click.option("--priority", default=None, help="Filigree priority, e.g. P2.")
@click.option("--label", "labels", multiple=True, help="Label to attach (repeatable).")
def file_finding(
    fingerprint: str,
    path: Path,
    config_path: Path | None,
    filigree_url: str | None,
    priority: str | None,
    labels: tuple[str, ...],
) -> None:
    """File the finding identified by FINGERPRINT into a tracked Filigree issue."""
    url = resolve_filigree_url(filigree_url, path, config_path)
    if url is None:
        click.echo("error: no Filigree URL (pass --filigree-url, set the env var, or wardline.yaml)", err=True)
        raise SystemExit(2)
    try:
        res = FiligreeIssueFiler(url).file(fingerprint, priority=priority, labels=list(labels) or None)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo(
        json.dumps(
            {
                "reachable": res.reachable,
                "issue_id": res.issue_id,
                "created": res.created,
                "not_found": res.not_found,
                "fingerprint": fingerprint,
                "disabled_reason": res.disabled_reason,
            }
        )
    )
    if not res.reachable:
        raise SystemExit(1)  # sibling absent — soft, but non-zero so a script notices
