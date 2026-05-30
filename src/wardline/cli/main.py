# src/wardline/cli/main.py
"""Wardline CLI entry point."""

from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path

import click

from wardline._version import __version__
from wardline.cli.scan import scan
from wardline.core import config as config_mod
from wardline.core.baseline import write_baseline
from wardline.core.descriptor import descriptor_to_yaml
from wardline.core.discovery import discover
from wardline.core.errors import WardlineError
from wardline.core.finding import Kind
from wardline.core.waivers import WaiverSet, parse_waivers
from wardline.scanner.analyzer import WardlineAnalyzer


@click.group()
@click.version_option(version=__version__, prog_name="wardline")
def cli() -> None:
    """Wardline — generic semantic-tainting static analyzer."""


cli.add_command(scan)


@cli.command()
def vocab() -> None:
    """Emit the NG-25 trust-vocabulary descriptor as YAML (read-instead-of-import)."""
    click.echo(descriptor_to_yaml(), nl=False)


def _generate_baseline(path: Path, *, overwrite: bool) -> None:
    baseline_path = path / ".wardline" / "baseline.yaml"
    if baseline_path.exists() and not overwrite:
        click.echo(
            f"{baseline_path} already exists; use `wardline baseline update` to overwrite.", err=True
        )
        raise SystemExit(2)
    try:
        cfg = config_mod.load(path / "wardline.yaml")
        waivers = WaiverSet(parse_waivers(cfg.waivers))
        today = date.today()
        files = discover(path, cfg)
        findings = WardlineAnalyzer().analyze(files, cfg, root=path)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    # Capture current DEFECTs, EXCLUDING any with an active waiver (else the
    # baseline swallows them and their expiry never resurfaces — spec §8).
    to_baseline = [
        f for f in findings
        if f.kind is Kind.DEFECT and waivers.match(f.fingerprint, today) is None
    ]
    write_baseline(baseline_path, to_baseline)
    counts = Counter(f.severity.value for f in to_baseline)
    breakdown = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items()))
    click.echo(f"baselined {len(to_baseline)} finding(s) -> {baseline_path}" + (f": {breakdown}" if breakdown else ""))


@cli.group(invoke_without_command=True)
@click.pass_context
def baseline(ctx: click.Context) -> None:
    """Manage the finding baseline (.wardline/baseline.yaml)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@baseline.command("create")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
def baseline_create(path: Path) -> None:
    """Write a new baseline from current findings (refuses if one exists)."""
    _generate_baseline(path, overwrite=False)


@baseline.command("update")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
def baseline_update(path: Path) -> None:
    """Re-derive and overwrite the baseline from current findings."""
    _generate_baseline(path, overwrite=True)


@cli.command()
def judge() -> None:
    """Run the opt-in LLM judge (not yet implemented — SP5)."""
    click.echo("`wardline judge` is not yet implemented (SP5).", err=True)
    raise SystemExit(2)
