# src/wardline/cli/fix.py
"""`wardline fix` — apply mechanical autofixes to findings."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core.autofix import run_autofix
from wardline.core.errors import WardlineError
from wardline.core.finding import Finding
from wardline.core.run import run_scan


@click.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Automatically apply all fixes without prompting.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Print the changes that would be made without modifying files.",
)
def fix(path: Path, config_path: Path | None, yes: bool, dry_run: bool) -> None:
    """Scan PATH and apply autofixes interactively."""
    from wardline.core.config import load
    from wardline.core.paths import weft_config_path

    cfg_path = config_path or weft_config_path(path)
    try:
        cfg = load(cfg_path, explicit=config_path is not None)
        result = run_scan(path, config_path=config_path)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    findings = [f for f in result.findings if f.rule_id == "PY-WL-111"]
    if not findings:
        click.echo("No fixable findings found.")
        return

    def confirm_cb(rel_path: str, orig: str, replacement: str, f: Finding) -> bool:
        if yes:
            return True
        click.echo(f"\n[PY-WL-111] Suggesting boundary fix in {rel_path} (line {f.location.line_start}):")
        click.echo(f"  - {click.style(orig, fg='red')}")
        click.echo(f"  + {click.style(replacement, fg='green')}")
        return click.confirm("Apply this fix?", default=True)

    try:
        applied = run_autofix(findings, cfg, path, dry_run=dry_run, confirm_cb=confirm_cb)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    if not applied:
        click.echo("No fixes applied.")
        return

    for filepath, fixes in applied.items():
        click.echo(f"\nFixed {filepath}:")
        for fx in fixes:
            click.echo(f"  {fx}")
