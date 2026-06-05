# src/wardline/cli/attest.py
"""`wardline attest` — build / verify a signed, reproducible evidence bundle.

Thin delegator to :func:`wardline.core.attest.build_attestation` /
:func:`wardline.core.attest.verify_attestation`. The signature is HMAC-SHA256 under
a shared project key (minted by ``wardline install`` into ``.env``); see the core
module's threat model — it is tamper-evidence within a key-holding trust domain, not
asymmetric proof of authorship.

The CLI default is fail-closed on a dirty tree (``--allow-dirty`` to override), which
flips the *core* default so a bundle's ``commit`` truthfully pins its source. Loomweave
SEI enrichment is opt-in (``--loomweave-url``) and fail-soft; its client is lazy-imported
only when the flag is set, so the zero-dependency base is untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.attest_key import load_attest_key
from wardline.core.config import resolve_loomweave_url
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
    "--loomweave-url",
    "loomweave_url",
    default=None,
    help="Loomweave URL to SEI-key the boundaries (opt-in, fail-soft).",
)
@click.option(
    "--cache-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Persist L3 summary cache here for faster reproducible scans.",
)
@click.option(
    "--trust-pack",
    "trusted_packs",
    multiple=True,
    help="Allow importing this trust-grammar pack from wardline.yaml. May be repeated.",
)
@click.option(
    "--allow-custom-packs",
    "trust_local_packs",
    is_flag=True,
    default=False,
    help="Allow loading custom trust-grammar packs from the local project directory.",
)
@click.option(
    "--strict-defaults",
    is_flag=True,
    default=False,
    help="Ignore repository-supplied custom configuration overrides (wardline.yaml).",
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
    loomweave_url: str | None,
    cache_dir: Path | None,
    trusted_packs: tuple[str, ...],
    trust_local_packs: bool,
    strict_defaults: bool,
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

    loomweave_url = resolve_loomweave_url(
        loomweave_url,
        path,
        config_path,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    loomweave_client = None
    if loomweave_url is not None:
        from wardline.loomweave.client import LoomweaveClient
        from wardline.loomweave.config import load_loomweave_token, resolve_project_name

        loomweave_client = LoomweaveClient(
            loomweave_url,
            secret=load_loomweave_token(path),
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
                cache_dir=cache_dir,
                loomweave_client=loomweave_client,
                confine_to_root=True,
                trust_local_packs=trust_local_packs,
                trusted_packs=trusted_packs,
                strict_defaults=strict_defaults,
            )
        except (json.JSONDecodeError, KeyError, ValueError, TypeError, WardlineError) as exc:
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
            cache_dir=cache_dir,
            loomweave_client=loomweave_client,
            confine_to_root=True,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
            allow_dirty=allow_dirty,
        )
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    out = json.dumps(bundle)
    click.echo(out)
    if out_path is not None:
        out_path.write_text(out + "\n", encoding="utf-8")
