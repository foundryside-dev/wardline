"""`wardline doctor` — inspect and repair agent-install wiring."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.errors import WardlineError
from wardline.core.paths import project_root_for
from wardline.install.doctor import (
    _check_config,
    _check_engine_selftest,
    _check_filigree_auth,
    _check_gitignore,
    _check_loomweave_dep,
    _check_stale_sibling_ports,
    _resolve_probe_target,
    _sweep_stray_artifacts,
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
@click.option("--filigree-url", default=None, help="Filigree Weft URL to probe (default: resolve from .mcp.json/env).")
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
        proj = project_root_for(root)
        # Resolve the probe URL BEFORE repair_install rewrites .mcp.json (which would
        # erase a configured --filigree-url arg), so repair can still probe/recover.
        probe_target = _resolve_probe_target(root, filigree_url)
        try:
            statuses = repair_install(root)
        except WardlineError as exc:
            click.echo(f"error: {exc}", err=True)
            raise SystemExit(2) from exc
        after = check_install(root)
        config_check = _check_config(root, fixed=statuses.get("weft.toml") == "created")
        click.echo("wardline doctor:")
        for check in after:
            status = statuses.get(check.name, "checked") if check.ok else f"failed ({check.message})"
            click.echo(f"  {check.name}: {status}")
        config_status = statuses.get("weft.toml", "checked") if config_check.ok else f"failed ({config_check.message})"
        click.echo(f"  weft.toml: {config_status}")
        fcheck = _check_filigree_auth(root, repair=True, probe_target=probe_target)
        fstatus = ("fixed" if fcheck.fixed else fcheck.message) if fcheck.ok else f"failed ({fcheck.message})"
        click.echo(f"  filigree.auth: {fstatus}")
        gi = _check_gitignore(proj, fix=True)
        click.echo(f"  gitignore: {gi.status}" + (f" ({gi.message})" if gi.message else ""))
        sw = _sweep_stray_artifacts(proj, fix=True)
        click.echo(f"  stray artifacts: removed {len(sw.removed)}, review {len(sw.review)}")
        for r in sw.review:
            click.echo(f"    REVIEW   {r}  (unstamped/bare — remove by hand if it's a stray scan)")
        sp = _check_stale_sibling_ports(proj, fix=True)
        click.echo(f"  stale sibling ports: {sp.message}")
        selftest = _check_engine_selftest()
        click.echo(f"  engine.selftest: {selftest.message or ('ok' if selftest.ok else 'error')}")
        lw_dep = _check_loomweave_dep(root)
        if not lw_dep.ok:
            click.echo(f"  loomweave.dep: {lw_dep.message}")
        if (
            not all(check.ok for check in after)
            or not config_check.ok
            or not fcheck.ok
            or gi.status == "error"
            or not selftest.ok
            or not lw_dep.ok
        ):
            raise SystemExit(1)
        return

    proj = project_root_for(root)
    checks = check_install(root)
    config_check = _check_config(root, fixed=False)
    fcheck = _check_filigree_auth(root, repair=False, filigree_url=filigree_url)
    selftest = _check_engine_selftest()
    lw_dep = _check_loomweave_dep(root)
    ok = all(check.ok for check in checks) and config_check.ok and fcheck.ok and selftest.ok and lw_dep.ok
    click.echo("wardline doctor: ok" if ok else "wardline doctor:")
    for check in checks:
        if not check.ok:
            click.echo(f"  {check.name}: {check.message}")
    if not config_check.ok:
        click.echo(f"  weft.toml: {config_check.message}")
    fmsg = fcheck.message or ("ok" if fcheck.ok else "error")
    click.echo(f"  filigree.auth: {fmsg}")
    # engine self-test: always show — a green here is the agent's proof the analyzer
    # actually fires in this install (NOT that the user's scans enforce — see Part A).
    click.echo(f"  engine.selftest: {selftest.message or ('ok' if selftest.ok else 'error')}")
    if not lw_dep.ok:
        click.echo(f"  loomweave.dep: {lw_dep.message}")
    gi = _check_gitignore(proj, fix=False)
    # gi.status is advisory-"ok" even with a gap, so render on the message, not gi.ok.
    if gi.status == "error" or "missing" in (gi.message or ""):
        click.echo(f"  gitignore: {gi.message}")
    sw = _sweep_stray_artifacts(proj, fix=False)
    if sw.removed or sw.review:
        click.echo(f"  stray artifacts: {sw.message}")
    sp = _check_stale_sibling_ports(proj, fix=False)
    if sp.removed:
        click.echo(f"  stale sibling ports: {sp.message}")
    if not ok:
        raise SystemExit(1)
