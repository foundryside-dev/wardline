# src/wardline/cli/scan.py
"""`wardline scan` — SP1 wires discovery → WardlineAnalyzer → JSONL sink."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import click

from wardline.core import config as config_mod
from wardline.core.baseline import load_baseline
from wardline.core.discovery import discover
from wardline.core.emit import JsonlSink
from wardline.core.errors import WardlineError
from wardline.core.finding import Kind, Severity, SuppressionState
from wardline.core.suppression import apply_suppressions, gate_trips
from wardline.core.waivers import WaiverSet, parse_waivers
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.taint.summary_cache import SummaryCache


@click.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--format", "fmt", type=click.Choice(["jsonl", "sarif"]), default="jsonl")
@click.option("--output", type=click.Path(path_type=Path), default=None)
# exit 1 if any non-suppressed DEFECT has severity >= this threshold (SP3b)
@click.option("--fail-on", type=click.Choice(["CRITICAL", "ERROR", "WARN", "INFO"]), default=None)
@click.option("--cache-dir", type=click.Path(path_type=Path), default=None,
              help="Persist L3 summary cache here for faster incremental scans.")
def scan(
    path: Path,
    config_path: Path | None,
    fmt: str,
    output: Path | None,
    fail_on: str | None,
    cache_dir: Path | None,
) -> None:
    """Scan PATH for findings."""
    if fmt == "sarif":
        click.echo("SARIF output is not yet implemented (SP4).", err=True)
        raise SystemExit(2)
    output = output if output is not None else (path / "findings.jsonl")
    try:
        cfg_path = config_path or (path / "wardline.yaml")
        cfg = config_mod.load(cfg_path)
        cache = None
        if cache_dir is not None:
            cache = SummaryCache(cache_dir=cache_dir)
            cache.load()
        files = discover(path, cfg)
        findings = WardlineAnalyzer(summary_cache=cache).analyze(files, cfg, root=path)
        if cache is not None:
            cache.save()
        baseline = load_baseline(path / ".wardline" / "baseline.yaml")
        waivers = WaiverSet(parse_waivers(cfg.waivers))
        findings = apply_suppressions(findings, baseline, waivers, today=date.today())
        JsonlSink(output).write(findings)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    baselined = sum(1 for f in defects if f.suppressed is SuppressionState.BASELINED)
    waived = sum(1 for f in defects if f.suppressed is SuppressionState.WAIVED)
    new = sum(1 for f in defects if f.suppressed is SuppressionState.ACTIVE)
    click.echo(
        f"scanned {len(files)} file(s); {len(findings)} finding(s) — "
        f"{baselined + waived} suppressed ({baselined} baseline / {waived} waiver), {new} new -> {output}"
    )
    if fail_on is not None and gate_trips(findings, Severity(fail_on)):
        raise SystemExit(1)
