"""`wardline scan-file-findings` — scan, summarize, and optionally file active defects."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.config import resolve_filigree_url, resolve_loomweave_url
from wardline.core.errors import WardlineError
from wardline.core.filigree_emit import FiligreeEmitter
from wardline.core.filigree_issue import FiligreeIssueFiler
from wardline.core.scan_file_workflow import scan_file_findings as scan_file_findings_core
from wardline.filigree.config import load_filigree_token
from wardline.loomweave.client import LoomweaveClient
from wardline.loomweave.config import load_loomweave_token, resolve_project_name


@click.command(name="scan-file-findings")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path))
@click.option("--fail-on", type=click.Choice(["CRITICAL", "ERROR", "WARN", "INFO"]), default=None)
@click.option("--cache-dir", type=click.Path(path_type=Path), default=None)
@click.option("--filigree-url", "filigree_url", default=None, help="Filigree Weft URL (else flag/env).")
@click.option("--loomweave-url", "loomweave_url", default=None, help="Loomweave URL for optional identity attachment.")
@click.option("--fingerprint", "fingerprints", multiple=True, help="Active finding fingerprint to promote.")
@click.option("--all-active", is_flag=True, help="Promote every active defect from this scan.")
@click.option("--dry-run", is_flag=True, help="Only summarize active defects; do not emit or promote.")
@click.option("--priority", default=None, help="Filigree priority for promoted findings, e.g. P2.")
@click.option("--label", "labels", multiple=True, help="Label to attach to promoted findings.")
@click.option("--trust-pack", "trusted_packs", multiple=True)
@click.option("--allow-custom-packs", "trust_local_packs", is_flag=True, default=False)
@click.option("--strict-defaults", is_flag=True, default=False)
def scan_file_findings(
    path: Path,
    config_path: Path | None,
    fail_on: str | None,
    cache_dir: Path | None,
    filigree_url: str | None,
    loomweave_url: str | None,
    fingerprints: tuple[str, ...],
    all_active: bool,
    dry_run: bool,
    priority: str | None,
    labels: tuple[str, ...],
    trusted_packs: tuple[str, ...],
    trust_local_packs: bool,
    strict_defaults: bool,
) -> None:
    """Run the agent workflow from scan to optionally filed Filigree issues."""
    dry = dry_run or (not fingerprints and not all_active)
    try:
        resolved_filigree_url = resolve_filigree_url(
            filigree_url,
            path,
            config_path,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
        )
        resolved_loomweave_url = resolve_loomweave_url(
            loomweave_url,
            path,
            config_path,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
        )
        filigree_emitter = None
        filigree_filer = None
        if resolved_filigree_url is not None:
            filigree_token = load_filigree_token(path)
            filigree_emitter = FiligreeEmitter(resolved_filigree_url, token=filigree_token)
            filigree_filer = FiligreeIssueFiler(resolved_filigree_url, token=filigree_token)

        loomweave_client = None
        if resolved_loomweave_url is not None:
            loomweave_client = LoomweaveClient(
                resolved_loomweave_url,
                secret=load_loomweave_token(path),
                project=resolve_project_name(path),
            )
        result = scan_file_findings_core(
            root=path,
            config_path=config_path,
            cache_dir=cache_dir,
            fail_on=fail_on,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
            fingerprints=fingerprints,
            all_active=all_active,
            dry_run=dry,
            priority=priority,
            labels=labels,
            filigree_emitter=filigree_emitter,
            filigree_filer=filigree_filer,
            loomweave_client=loomweave_client,
        )
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo(json.dumps(result))
