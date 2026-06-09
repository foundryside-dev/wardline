"""``wardline rekey`` — one-shot fingerprint migration (P4).

Carries baseline/judged/waiver verdicts (+ best-effort Filigree) across the
wlfp1->wlfp2 value-rekey from a single scan. ``--probe`` is a read-only dry run;
``--resume`` finishes an interrupted run WITHOUT re-scanning; ``--rollback`` restores
the pre-migration stores. A thin shell over ``core.rekey``.
"""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core.config import resolve_filigree_url
from wardline.core.errors import WardlineError
from wardline.core.filigree_emit import FiligreeEmitter
from wardline.core.rekey import Journal, ProbeReport, probe, resume_rekey, rollback, run_rekey
from wardline.core.run import run_scan

# Why a verdict can orphan (NOT only a source move) — shared by --probe and --resume output.
_ORPHAN_CAUSE = "source moved/deleted, or a custom multi-emit rule not surfacing taint_path_v0"


def _print_prescheme_caution() -> None:
    click.echo(
        "  note: a store here predates the fingerprint-scheme stamp (pre-P1). If its "
        "fingerprints also predate the taint-resolution-drift fix, a HIGH orphan rate is a "
        "fingerprint-formula change, NOT source churn — re-baseline rather than assume the "
        "code moved.",
        err=True,
    )


def _print_probe(report: ProbeReport) -> None:
    click.echo(f"probe: {report.scanned_findings} finding(s) scanned; {report.matched} verdict(s) will carry.")
    if report.orphaned:
        click.echo(f"  {len(report.orphaned)} orphaned ({_ORPHAN_CAUSE}) — verdict will NOT carry:", err=True)
        for of in report.orphaned:
            click.echo(f"    {of}", err=True)
    for c in report.collisions:
        click.echo(f"  COLLISION: {c.message}", err=True)
    if report.prescheme:
        _print_prescheme_caution()
    if report.clean:
        click.echo("probe: clean — every stored verdict will carry.")


def _print_journal(journal: Journal) -> None:
    for leg in journal.legs:
        if leg.name == "filigree":
            if leg.debt:
                click.echo(f"  filigree: DEFERRED — {leg.debt}", err=True)
            elif leg.done:
                click.echo("  filigree: reconciled.")
            continue
        status = "done" if leg.done else "PENDING"
        click.echo(f"  {leg.name}: {status} ({len(leg.carried)} carried, {len(leg.orphaned)} orphaned)")
        # Surface the orphaned fingerprints, not just the count — a dropped verdict must
        # never be silent (the original is recoverable from .rekey_snapshot/ until rollback).
        for of in leg.orphaned:
            click.echo(f"    orphaned ({_ORPHAN_CAUSE}) — verdict NOT carried: {of}", err=True)
    for c in journal.collisions:
        click.echo(f"  COLLISION: {c.message}", err=True)
    if journal.snapshot_prescheme:
        _print_prescheme_caution()
    if journal.complete:
        click.echo("rekey complete — stores load clean under the new scheme.")
    else:
        click.echo("rekey incomplete — re-run `wardline rekey` to finish pending leg(s).", err=True)


@click.command("rekey")
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None)
@click.option("--cache-dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--trust-pack", "trusted_packs", multiple=True, help="Allow a trust-grammar pack from weft.toml. Repeatable."
)
@click.option(
    "--allow-custom-packs",
    "trust_local_packs",
    is_flag=True,
    default=False,
    help="Allow local custom trust-grammar packs.",
)
@click.option(
    "--strict-defaults", is_flag=True, default=False, help="Ignore repository-supplied configuration overrides."
)
@click.option(
    "--filigree-url",
    "filigree_url",
    default=None,
    help="Re-emit findings under the new fingerprints to this Filigree URL (last leg, best-effort).",
)
@click.option(
    "--probe",
    "probe_only",
    is_flag=True,
    default=False,
    help="Read-only dry run: report match/orphans/collisions, write nothing.",
)
@click.option(
    "--resume", "do_resume", is_flag=True, default=False, help="Finish an interrupted migration WITHOUT re-scanning."
)
@click.option(
    "--rollback", "do_rollback", is_flag=True, default=False, help="Restore the pre-migration stores from the snapshot."
)
def rekey(
    path: Path,
    config_path: Path | None,
    cache_dir: Path | None,
    trusted_packs: tuple[str, ...],
    trust_local_packs: bool,
    strict_defaults: bool,
    filigree_url: str | None,
    probe_only: bool,
    do_resume: bool,
    do_rollback: bool,
) -> None:
    """Re-key baseline/waiver/judge verdicts across a fingerprint-scheme change."""
    if sum((probe_only, do_resume, do_rollback)) > 1:
        click.echo("error: --probe, --resume and --rollback are mutually exclusive.", err=True)
        raise SystemExit(2)
    try:
        if do_rollback:
            rolled = rollback(path)
            click.echo(f"rolled back {len(rolled.restored)} store(s): {', '.join(rolled.restored) or '(none)'}.")
            click.echo(
                "note: Filigree associations from the forward run are NOT reversed (no remap endpoint); "
                "reconcile manually if needed.",
                err=True,
            )
            return

        if do_resume:
            # Resume NEVER re-scans — YAML legs re-carry from the snapshot; a pending
            # Filigree leg is deferred (re-run `wardline rekey` to retry it).
            journal = resume_rekey(path, findings=None, filigree=None)
            _print_journal(journal)
            raise SystemExit(0 if journal.complete else 1)

        resolved_url = resolve_filigree_url(filigree_url, path, config_path, strict_defaults=strict_defaults)
        result = run_scan(
            path,
            config_path=config_path,
            cache_dir=cache_dir,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
            confine_to_root=True,
            # Migration scans the project WITHOUT loading the stores it is about to
            # rekey — they are still old-scheme and would SCHEME_MISMATCH.
            skip_suppression=True,
        )
        findings = result.findings

        if probe_only:
            report = probe(path, findings)
            _print_probe(report)
            raise SystemExit(0 if report.clean else 1)

        emitter = None
        if resolved_url is not None:
            from wardline.filigree.config import load_filigree_token

            emitter = FiligreeEmitter(resolved_url, token=load_filigree_token(path))
        journal = run_rekey(path, findings, filigree=emitter)
        _print_journal(journal)
        raise SystemExit(0 if journal.complete else 1)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
