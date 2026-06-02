# src/wardline/cli/attest.py
"""`wardline attest` — build / verify a signed, reproducible evidence bundle.

Thin delegator to :func:`wardline.core.attest.build_attestation` /
:func:`wardline.core.attest.verify_attestation`. The signature is HMAC-SHA256 under
a shared project key (minted by ``wardline install`` into ``.env``); see the core
module's threat model — it is tamper-evidence within a key-holding trust domain, not
asymmetric proof of authorship.

The CLI default is fail-closed on a dirty tree (``--allow-dirty`` to override), which
flips the *core* default so a bundle's ``commit`` truthfully pins its source. Clarion
SEI enrichment is opt-in (``--clarion-url``) and fail-soft; its client is lazy-imported
only when the flag is set, so the zero-dependency base is untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.attest_key import load_attest_key
from wardline.core.config import resolve_clarion_url
from wardline.core.errors import WardlineError


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option(
    "--clarion-url",
    "clarion_url",
    default=None,
    help="Clarion URL to SEI-key the boundaries (opt-in, fail-soft).",
)
@click.option("--allow-dirty", is_flag=True, help="Attest even with uncommitted changes (records dirty: true).")
@click.option(
    "--verify",
    "verify_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Verify the bundle at this path instead of building one.",
)
@click.option(
    "--reproduce", is_flag=True, help="With --verify: also re-derive the payload at the current tree and compare."
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write the bundle JSON to this file (also printed).",
)
def attest(
    path: Path,
    config_path: Path | None,
    clarion_url: str | None,
    allow_dirty: bool,
    verify_path: Path | None,
    reproduce: bool,
    out_path: Path | None,
) -> None:
    """Build a signed evidence bundle for PATH (or verify one with --verify)."""
    key = load_attest_key(path)
    if key is None:
        click.echo(
            "error: no attest key — run `wardline install` to mint one (or set WARDLINE_ATTEST_KEY)",
            err=True,
        )
        raise SystemExit(2)

    clarion_url = resolve_clarion_url(clarion_url, path, config_path)
    clarion_client = None
    if clarion_url is not None:
        from wardline.clarion.client import ClarionClient
        from wardline.clarion.config import load_clarion_token, resolve_project_name

        clarion_client = ClarionClient(
            clarion_url,
            secret=load_clarion_token(path),
            project=resolve_project_name(path),
        )

    if verify_path is not None:
        from wardline.core.attest import verify_attestation

        try:
            bundle = json.loads(verify_path.read_text(encoding="utf-8"))
            result = verify_attestation(
                bundle,
                key,
                root=path,
                reproduce=reproduce,
                config_path=config_path,
                clarion_client=clarion_client,
            )
        except (json.JSONDecodeError, KeyError, ValueError, WardlineError) as exc:
            click.echo(f"error: invalid attestation bundle: {exc}", err=True)
            raise SystemExit(2) from exc
        click.echo(json.dumps(result))
        raise SystemExit(0 if result["signature_valid"] else 1)

    from wardline.core.attest import build_attestation

    try:
        bundle = build_attestation(
            path,
            key,
            config_path=config_path,
            clarion_client=clarion_client,
            allow_dirty=allow_dirty,
        )
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    out = json.dumps(bundle)
    click.echo(out)
    if out_path is not None:
        out_path.write_text(out + "\n", encoding="utf-8")
