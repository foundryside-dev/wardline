"""`wardline scan-job` — file-backed start/status surface for long scans."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.errors import WardlineError
from wardline.core.scan_jobs import (
    DEFAULT_SCAN_JOB_TIMEOUT_SECONDS,
    cancel_scan_job,
    read_scan_job_status,
    start_scan_job,
)


@click.group(name="scan-job")
def scan_job() -> None:
    """Start and poll file-backed Wardline scan jobs."""


@scan_job.command("start")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["jsonl", "sarif", "agent-summary"]), default="jsonl")
@click.option("--output", type=click.Path(path_type=Path), default=None)
@click.option("--fail-on", type=click.Choice(["CRITICAL", "ERROR", "WARN", "INFO"], case_sensitive=False), default=None)
@click.option("--fail-on-unanalyzed/--no-fail-on-unanalyzed", default=False)
@click.option("--cache-dir", type=click.Path(path_type=Path), default=None)
@click.option("--filigree-url", "filigree_url", default=None)
@click.option("--local-only", "--no-emit", "local_only", is_flag=True, default=False)
@click.option("--filigree-max-findings-per-request", type=click.IntRange(min=1), default=None)
@click.option(
    "--timeout",
    "timeout_seconds",
    type=click.FloatRange(min=0.0),
    default=None,
    help=f"Fail the job after SECONDS; defaults to {DEFAULT_SCAN_JOB_TIMEOUT_SECONDS}. Use 0 to disable.",
)
@click.option("--lang", type=click.Choice(["python", "rust"]), default="python")
@click.option("--new-since", type=str, default=None)
@click.option("--trust-pack", "trusted_packs", multiple=True)
@click.option("--allow-custom-packs", "trust_local_packs", is_flag=True, default=False)
@click.option("--strict-defaults", is_flag=True, default=False)
@click.option("--trust-suppressions", is_flag=True, default=False)
@click.option("--foreground", is_flag=True, hidden=True, default=False)
def start(
    path: Path,
    config_path: Path | None,
    fmt: str,
    output: Path | None,
    fail_on: str | None,
    fail_on_unanalyzed: bool,
    cache_dir: Path | None,
    filigree_url: str | None,
    local_only: bool,
    filigree_max_findings_per_request: int | None,
    timeout_seconds: float | None,
    lang: str,
    new_since: str | None,
    trusted_packs: tuple[str, ...],
    trust_local_packs: bool,
    strict_defaults: bool,
    trust_suppressions: bool,
    foreground: bool,
) -> None:
    """Start a scan job and print its status JSON."""
    request = {
        "config": str(config_path) if config_path else None,
        "format": fmt,
        "output": str(output) if output else None,
        "fail_on": fail_on.upper() if fail_on else None,
        "fail_on_unanalyzed": fail_on_unanalyzed,
        "cache_dir": str(cache_dir) if cache_dir else None,
        "filigree_url": filigree_url,
        "local_only": local_only,
        "filigree_max_findings_per_request": filigree_max_findings_per_request,
        "timeout_seconds": timeout_seconds,
        "lang": lang,
        "new_since": new_since,
        "trusted_packs": list(trusted_packs),
        "trust_local_packs": trust_local_packs,
        "strict_defaults": strict_defaults,
        "trust_suppressions": trust_suppressions,
    }
    try:
        status = start_scan_job(path, request, foreground=foreground)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo(json.dumps(status, sort_keys=True))


@scan_job.command("status")
@click.argument("job_id")
@click.option("--path", "path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
def status(job_id: str, path: Path) -> None:
    """Print status JSON for a scan job."""
    try:
        payload = read_scan_job_status(path, job_id)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo(json.dumps(payload, sort_keys=True))


@scan_job.command("cancel")
@click.argument("job_id")
@click.option("--path", "path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
def cancel(job_id: str, path: Path) -> None:
    """Cancel a running scan job and print its terminal status JSON."""
    try:
        payload = cancel_scan_job(path, job_id)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo(json.dumps(payload, sort_keys=True))
