"""`wardline doctor` — inspect and repair agent-install wiring."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core.errors import WardlineError
from wardline.install.doctor import check_install, repair_install


@click.command()
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    help="Project root to inspect (default: cwd).",
)
@click.option("--repair", is_flag=True, help="Repair missing or stale install artifacts.")
def doctor(root: Path, repair: bool) -> None:
    """Check Wardline agent install artifacts and sibling bindings."""
    if repair:
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
        if all(check.ok for check in after):
            return
        raise SystemExit(1)

    checks = check_install(root)
    ok = all(check.ok for check in checks)
    click.echo("wardline doctor: ok" if ok else "wardline doctor:")
    for check in checks:
        if ok:
            continue
        click.echo(f"  {check.name}: {check.message}")
    if not ok:
        raise SystemExit(1)
