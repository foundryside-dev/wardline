# src/wardline/cli/main.py
"""Wardline CLI entry point."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import click

from wardline._version import __version__
from wardline.cli.judge import judge as judge_command
from wardline.cli.scan import scan
from wardline.core.baseline import collect_and_write_baseline
from wardline.core.descriptor import descriptor_to_yaml
from wardline.core.errors import WardlineError
from wardline.core.finding import Severity


@click.group()
@click.version_option(version=__version__, prog_name="wardline")
def cli() -> None:
    """Wardline — generic semantic-tainting static analyzer."""


cli.add_command(scan)
cli.add_command(judge_command)


@cli.command()
def vocab() -> None:
    """Emit the NG-25 trust-vocabulary descriptor as YAML (read-instead-of-import)."""
    click.echo(descriptor_to_yaml(), nl=False)


# Print the severity breakdown in declaration order (CRITICAL first), matching the
# severity-sorted baseline file rather than alphabetical.
_SEV_PRINT_ORDER: dict[str, int] = {s.value: i for i, s in enumerate(Severity)}


def _generate_baseline(path: Path, *, overwrite: bool, config_path: Path | None) -> None:
    baseline_path = path / ".wardline" / "baseline.yaml"
    try:
        to_baseline = collect_and_write_baseline(
            path, overwrite=overwrite, config_path=config_path
        )
    except FileExistsError:
        click.echo(
            f"{baseline_path} already exists; use `wardline baseline update` to overwrite.", err=True
        )
        raise SystemExit(2) from None
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    counts = Counter(f.severity.value for f in to_baseline)
    breakdown = ", ".join(
        f"{n} {sev}" for sev, n in sorted(counts.items(), key=lambda kv: _SEV_PRINT_ORDER[kv[0]])
    )
    click.echo(f"baselined {len(to_baseline)} finding(s) -> {baseline_path}" + (f": {breakdown}" if breakdown else ""))


@cli.group(invoke_without_command=True)
@click.pass_context
def baseline(ctx: click.Context) -> None:
    """Manage the finding baseline (.wardline/baseline.yaml)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@baseline.command("create")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
def baseline_create(path: Path, config_path: Path | None) -> None:
    """Write a new baseline from current findings (refuses if one exists)."""
    _generate_baseline(path, overwrite=False, config_path=config_path)


@baseline.command("update")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
def baseline_update(path: Path, config_path: Path | None) -> None:
    """Re-derive and overwrite the baseline from current findings."""
    _generate_baseline(path, overwrite=True, config_path=config_path)


