# src/wardline/cli/scan.py
"""`wardline scan` — SP0 wires discovery → no-op analyzer → JSONL sink."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core import config as config_mod
from wardline.core.discovery import discover
from wardline.core.emit import JsonlSink
from wardline.core.errors import WardlineError
from wardline.scanner import NoOpAnalyzer


@click.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--format", "fmt", type=click.Choice(["jsonl", "sarif"]), default="jsonl")
@click.option("--output", type=click.Path(path_type=Path), default=None)
# reserved for SP3; inert in SP0
@click.option("--fail-on", type=click.Choice(["CRITICAL", "ERROR", "WARN", "INFO"]), default=None)
def scan(
    path: Path,
    config_path: Path | None,
    fmt: str,
    output: Path | None,
    fail_on: str | None,
) -> None:
    """Scan PATH for findings (SP0: discovery + no-op analyzer)."""
    if fmt == "sarif":
        click.echo("SARIF output is not yet implemented (SP4).", err=True)
        raise SystemExit(2)
    output = output if output is not None else (path / "findings.jsonl")
    try:
        cfg_path = config_path or (path / "wardline.yaml")
        cfg = config_mod.load(cfg_path)
        files = discover(path, cfg)
        findings = NoOpAnalyzer().analyze(files, cfg, root=path)
        JsonlSink(output).write(findings)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo(f"scanned {len(files)} file(s); {len(findings)} finding(s) -> {output}")
