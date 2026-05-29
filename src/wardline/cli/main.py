# src/wardline/cli/main.py
"""Wardline CLI entry point."""

from __future__ import annotations

import click

from wardline._version import __version__
from wardline.cli.scan import scan
from wardline.core.descriptor import descriptor_to_yaml


@click.group()
@click.version_option(version=__version__, prog_name="wardline")
def cli() -> None:
    """Wardline — generic semantic-tainting static analyzer."""


cli.add_command(scan)


@cli.command()
def vocab() -> None:
    """Emit the NG-25 trust-vocabulary descriptor as YAML (read-instead-of-import)."""
    click.echo(descriptor_to_yaml(), nl=False)


@cli.command()
def baseline() -> None:
    """Manage the finding baseline (not yet implemented — SP3)."""
    click.echo("`wardline baseline` is not yet implemented (SP3).", err=True)
    raise SystemExit(2)


@cli.command()
def judge() -> None:
    """Run the opt-in LLM judge (not yet implemented — SP5)."""
    click.echo("`wardline judge` is not yet implemented (SP5).", err=True)
    raise SystemExit(2)
