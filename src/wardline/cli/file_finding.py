# src/wardline/cli/file_finding.py
"""`wardline file-finding` — file ONE finding (by fingerprint) into a Filigree issue.

CLI counterpart of the MCP `file_finding` tool; both go through FiligreeIssueFiler."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from wardline.core.config import resolve_clarion_url, resolve_filigree_url
from wardline.core.errors import WardlineError
from wardline.core.filigree_issue import (
    FiligreeIssueFiler,
    attach_clarion_identity_for_finding,
    identity_attach_result_to_json,
)


@click.command(name="file-finding")
@click.argument("fingerprint", type=str)
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--filigree-url", "filigree_url", default=None, help="Filigree Loom URL (else env/wardline.yaml).")
@click.option("--clarion-url", "clarion_url", default=None, help="Clarion URL used with --attach-clarion-identity.")
@click.option(
    "--attach-clarion-identity",
    is_flag=True,
    help="After filing, resolve the finding qualname through Clarion and attach a Filigree entity association.",
)
@click.option("--priority", default=None, help="Filigree priority, e.g. P2.")
@click.option("--label", "labels", multiple=True, help="Label to attach (repeatable).")
def file_finding(
    fingerprint: str,
    path: Path,
    config_path: Path | None,
    filigree_url: str | None,
    clarion_url: str | None,
    attach_clarion_identity: bool,
    priority: str | None,
    labels: tuple[str, ...],
) -> None:
    """File the finding identified by FINGERPRINT into a tracked Filigree issue."""
    url = resolve_filigree_url(filigree_url, path, config_path)
    if url is None:
        click.echo("error: no Filigree URL (pass --filigree-url, set the env var, or wardline.yaml)", err=True)
        raise SystemExit(2)
    try:
        filer = FiligreeIssueFiler(url)
        res = filer.file(fingerprint, priority=priority, labels=list(labels) or None)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    identity_attach = None
    if attach_clarion_identity:
        try:
            resolved_clarion_url = resolve_clarion_url(clarion_url, path, config_path)
            clarion_client = None
            if resolved_clarion_url is not None:
                from wardline.clarion.client import ClarionClient
                from wardline.clarion.config import load_clarion_token, resolve_project_name

                clarion_client = ClarionClient(
                    resolved_clarion_url,
                    secret=load_clarion_token(path),
                    project=resolve_project_name(path),
                )
            identity_attach = attach_clarion_identity_for_finding(
                fingerprint=fingerprint,
                issue_id=res.issue_id,
                root=path,
                filer=filer,
                clarion_client=clarion_client,
                config_path=config_path,
            )
        except WardlineError as exc:
            click.echo(f"error: {exc}", err=True)
            raise SystemExit(2) from exc
    payload: dict[str, Any] = {
        "reachable": res.reachable,
        "issue_id": res.issue_id,
        "created": res.created,
        "not_found": res.not_found,
        "fingerprint": fingerprint,
        "disabled_reason": res.disabled_reason,
    }
    if identity_attach is not None:
        payload["identity_attach"] = identity_attach_result_to_json(identity_attach)
    click.echo(json.dumps(payload))
    if not res.reachable:
        raise SystemExit(1)  # sibling absent — soft, but non-zero so a script notices
