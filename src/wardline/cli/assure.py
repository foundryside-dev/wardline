# src/wardline/cli/assure.py
"""`wardline assure` — trust-surface coverage posture.

Thin delegator to :func:`wardline.core.assure.build_posture` (the same function
the MCP ``assure`` tool calls — CLI and MCP identical by construction). Emits the
coverage rollup as JSON (default) or a compact human-readable summary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from wardline.core.errors import WardlineError


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "human"]),
    default="json",
    help="Output format: json (default) or human-readable summary.",
)
def assure(path: Path, config_path: Path | None, output_format: str) -> None:
    """Report the trust-surface coverage posture for PATH."""
    from wardline.core.assure import build_posture

    try:
        posture = build_posture(path, config_path=config_path, confine_to_root=True)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    if output_format == "json":
        click.echo(json.dumps(posture.to_dict()))
    else:
        _render_human(posture)


def _render_human(posture: object) -> None:
    """Render a compact, honest human-readable summary of the assurance posture."""
    from wardline.core.assure import AssurancePosture

    assert isinstance(posture, AssurancePosture)
    d = posture.to_dict()
    boundary_total: int = d["boundaries_total"]
    unanalyzed_total: int = d["unanalyzed_total"]
    coverage_total = boundary_total + unanalyzed_total
    unknown_list: list[dict[str, Any]] = d["unknown"]
    waiver_debt: list[dict[str, Any]] = d["waiver_debt"]

    if coverage_total == 0:
        click.echo("No trust surface declared (0 trust-annotated boundaries) — nothing to assure.")
    else:
        pct: float = d["coverage_pct"]
        proven: int = d["proven"]
        defect: int = d["defect_total"]
        unknown_count = len(unknown_list)
        engine_limited: int = d["engine_limited"]

        definite = boundary_total - unknown_count
        click.echo(
            f"Trust-surface coverage: {pct}% ({definite}/{coverage_total} surface item(s) reached a definite verdict)"
        )
        click.echo(f"  proven:   {proven}")
        click.echo(f"  defect:   {defect}")
        engine_note = f"  ({engine_limited} engine-limited)" if engine_limited else ""
        click.echo(f"  unknown:  {unknown_count + unanalyzed_total}{engine_note}")
        if unanalyzed_total:
            click.echo(f"  unanalyzed files: {unanalyzed_total}")

        if unknown_list:
            click.echo("  Unknown boundaries:")
            for u in unknown_list:
                loc = u.get("location") or {}
                loc_str = f"  {loc.get('path', '?')}:{loc.get('line', '?')}"
                reason_str = f"  [{u['reason']}]" if u.get("reason") else ""
                tier_str = f"  (tier: {u['tier']})" if u.get("tier") else ""
                click.echo(f"    {u['qualname']}{tier_str}{loc_str}{reason_str}")

    _render_waiver_debt(waiver_debt)


def _render_waiver_debt(waiver_debt: list[dict[str, Any]]) -> None:
    """Render the waiver-debt summary line."""
    if not waiver_debt:
        click.echo("  no waivers")
        return
    # Find the entry expiring soonest (ignoring None / no-expiry entries).
    with_expiry = [w for w in waiver_debt if w.get("days_left") is not None]
    soonest = min(with_expiry, key=lambda w: w["days_left"]) if with_expiry else None
    if soonest is not None:
        days: int = soonest["days_left"]
        if days < 0:
            click.echo(f"  {len(waiver_debt)} waiver(s); expired {-days} day(s) ago")
        else:
            click.echo(f"  {len(waiver_debt)} waiver(s); {days} day(s) until earliest expiry")
    else:
        click.echo(f"  {len(waiver_debt)} waiver(s); no expiry set")
