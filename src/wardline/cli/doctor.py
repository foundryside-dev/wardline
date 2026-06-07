"""`wardline doctor` — inspect and repair agent-install wiring."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.errors import WardlineError
from wardline.install.doctor import (
    _check_filigree_auth,
    _resolve_probe_url,
    check_install,
    machine_readable_doctor,
    repair_install,
)


@click.command()
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    help="Project root to inspect (default: cwd).",
)
@click.option("--repair", is_flag=True, help="Repair missing or stale install artifacts.")
@click.option("--fix", "fix_json", is_flag=True, help="Repair install bindings and emit machine-readable JSON.")
@click.option(
    "--filigree-url", default=None, help="Filigree Weft URL to probe (default: resolve from .mcp.json/env)."
)
def doctor(root: Path, repair: bool, fix_json: bool, filigree_url: str | None) -> None:
    """Check Wardline agent install artifacts and sibling bindings."""
    if repair and fix_json:
        click.echo("error: use only one of --repair or --fix", err=True)
        raise SystemExit(2)
    if fix_json:
        try:
            payload = machine_readable_doctor(root, fix=True, filigree_url=filigree_url)
        except WardlineError as exc:
            click.echo(f"error: {exc}", err=True)
            raise SystemExit(2) from exc
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        if payload["ok"]:
            return
        raise SystemExit(1)

    if repair:
        # Resolve the probe URL BEFORE repair_install rewrites .mcp.json (which would
        # erase a configured --filigree-url arg), so repair can still probe/recover.
        probe_url = _resolve_probe_url(root, filigree_url)
        try:
            statuses = repair_install(root)
        except WardlineError as exc:
            click.echo(f"error: {exc}", err=True)
            raise SystemExit(2) from exc
        after = check_install(root)
        click.echo("wardline doctor:")
        for check in after:
            status = statuses.get(check.name, "checked") if check.ok else f"failed ({check.message})"
            click.echo(f"  {check.name}: {status}")
        fcheck = _check_filigree_auth(root, repair=True, filigree_url=probe_url)
        fstatus = ("fixed" if fcheck.fixed else fcheck.message) if fcheck.ok else f"failed ({fcheck.message})"
        click.echo(f"  filigree.auth: {fstatus}")
        if not all(check.ok for check in after) or not fcheck.ok:
            raise SystemExit(1)
        return

    checks = check_install(root)
    fcheck = _check_filigree_auth(root, repair=False, filigree_url=filigree_url)
    ok = all(check.ok for check in checks) and fcheck.ok
    click.echo("wardline doctor: ok" if ok else "wardline doctor:")
    for check in checks:
        if not check.ok:
            click.echo(f"  {check.name}: {check.message}")
    fmsg = fcheck.message or ("ok" if fcheck.ok else "error")
    click.echo(f"  filigree.auth: {fmsg}")
    if not ok:
        raise SystemExit(1)
