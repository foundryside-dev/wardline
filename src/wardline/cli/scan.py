# src/wardline/cli/scan.py
"""`wardline scan` — SP1 wires discovery → WardlineAnalyzer → JSONL sink."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core.emit import JsonlSink
from wardline.core.errors import WardlineError
from wardline.core.filigree_emit import EmitResult, FiligreeEmitter
from wardline.core.finding import Severity
from wardline.core.run import gate_decision, run_scan
from wardline.core.sarif import SarifSink


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
@click.option("--filigree-url", "filigree_url", default=None,
              help="POST findings to this Filigree Loom scan-results URL (opt-in).")
@click.option("--clarion-url", "clarion_url", default=None,
              help="Persist per-entity taint facts to this Clarion taint-store URL (opt-in, fail-soft).")
def scan(
    path: Path,
    config_path: Path | None,
    fmt: str,
    output: Path | None,
    fail_on: str | None,
    cache_dir: Path | None,
    filigree_url: str | None,
    clarion_url: str | None,
) -> None:
    """Scan PATH for findings."""
    default_name = "findings.sarif" if fmt == "sarif" else "findings.jsonl"
    output = output if output is not None else (path / default_name)
    emit_result: EmitResult | None = None
    clarion_result = None
    try:
        result = run_scan(path, config_path=config_path, cache_dir=cache_dir)
        findings = result.findings
        sink = SarifSink(output) if fmt == "sarif" else JsonlSink(output)
        sink.write(findings)
        # Loom emission is additive: a FiligreeEmitError (HTTP >= 400) is a Wardline
        # payload bug -> caught below -> exit 2; an unreachable sibling warns + continues.
        if filigree_url is not None:
            emit_result = FiligreeEmitter(filigree_url).emit(findings)
        # Clarion taint-store write is fail-soft: an outage/403 returns a not-reachable
        # WriteResult (reported below); a ClarionError (missing extra, 4xx, bad scheme)
        # is a WardlineError → caught here → exit 2, exactly as Filigree errors do.
        if clarion_url is not None:
            from wardline.clarion.client import ClarionClient
            from wardline.clarion.config import load_clarion_token, resolve_project_name
            from wardline.clarion.write import write_facts_to_clarion

            client = ClarionClient(
                clarion_url,
                secret=load_clarion_token(path),
                project=resolve_project_name(path),
            )
            clarion_result = write_facts_to_clarion(result, path, client)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    if emit_result is not None:
        if not emit_result.reachable:
            click.echo(
                f"warning: could not reach Filigree at {filigree_url}; "
                f"findings written locally only.",
                err=True,
            )
        else:
            line = (
                f"emitted {len(findings)} finding(s) to {filigree_url} — "
                f"{emit_result.created} created / {emit_result.updated} updated"
            )
            if emit_result.failed:
                line += f" / {emit_result.failed} failed"
            if emit_result.warnings:
                line += f"; {len(emit_result.warnings)} warning(s): " + "; ".join(emit_result.warnings)
            click.echo(line)
    if clarion_result is not None:
        if not clarion_result.reachable:
            reason = clarion_result.disabled_reason or "unreachable"
            click.echo(
                f"warning: Clarion taint store not written ({reason}); scan unaffected.",
                err=True,
            )
        else:
            line = f"wrote {clarion_result.written} taint fact(s) to {clarion_url}"
            if clarion_result.unresolved_qualnames:
                line += f"; {len(clarion_result.unresolved_qualnames)} qualname(s) unresolved (not indexed by Clarion)"
            click.echo(line)
    s = result.summary
    click.echo(
        f"scanned {result.files_scanned} file(s); {s.total} finding(s) — "
        f"{s.baselined + s.waived + s.judged} suppressed "
        f"({s.baselined} baseline / {s.waived} waiver / {s.judged} judged), {s.active} new -> {output}"
    )
    if fail_on is not None and gate_decision(result, Severity(fail_on)).tripped:
        raise SystemExit(1)
