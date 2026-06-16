# src/wardline/cli/explain_taint.py
"""`wardline explain-taint` — the CLI twin of the MCP `explain_taint` tool (N-2).

Thin delegator to ``core.explain.explain_taint_result`` (the same builder the
MCP handler calls — CLI and MCP identical by construction), so a CLI-only agent
can run the full scan -> explain -> fix-at-the-boundary -> rescan loop without
an MCP server."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.config import resolve_loomweave_url
from wardline.core.errors import WardlineError


@click.command("explain-taint")
@click.argument("fingerprint", type=str)
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--sink-qualname",
    default=None,
    help=(
        "The finding's qualname: with a configured Loomweave store this serves "
        "the explanation from the store (no re-scan)."
    ),
)
@click.option(
    "--chain",
    is_flag=True,
    default=False,
    help=(
        "Also walk the full taint chain to the originating boundary (needs a "
        "Loomweave store; degrades to single-hop without one)."
    ),
)
@click.option("--max-hops", type=int, default=20, show_default=True, help="Chain-walk hop budget.")
@click.option(
    "--loomweave-url",
    "loomweave_url",
    default=None,
    help="Loomweave taint-store URL (opt-in; also resolved from env/published port).",
)
def explain_taint(
    fingerprint: str,
    path: Path,
    config_path: Path | None,
    sink_qualname: str | None,
    chain: bool,
    max_hops: int,
    loomweave_url: str | None,
) -> None:
    """Explain ONE finding's taint provenance by FINGERPRINT under PATH.

    Prints the immediate tainted callee, the originating boundary, the trust
    tiers at the sink, and a remediation hint — the same JSON the MCP
    `explain_taint` tool returns. Call right after a scan and before editing:
    a fingerprint from a stale scan errors (exit 2) and asks for a re-scan.
    PATH is the scan root and must match the scan that minted the fingerprint.
    """
    try:
        loomweave_url = resolve_loomweave_url(loomweave_url, path, config_path)
        loomweave = None
        if loomweave_url is not None:
            from wardline.loomweave.client import LoomweaveClient
            from wardline.loomweave.config import load_loomweave_token, resolve_project_name

            loomweave = LoomweaveClient(
                loomweave_url,
                secret=load_loomweave_token(path),
                project=resolve_project_name(path),
            )
        from wardline.core.explain import explain_taint_result

        result = explain_taint_result(
            path,
            fingerprint=fingerprint,
            config_path=config_path,
            confine_to_root=True,
            loomweave=loomweave,
            sink_qualname=sink_qualname,
            chain=chain,
            max_hops=max_hops,
        )
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    if result is None:
        click.echo(
            "error: fingerprint not in current scan; your code changed since the scan that produced it — re-scan.",
            err=True,
        )
        raise SystemExit(2)
    click.echo(json.dumps(result, indent=2, ensure_ascii=False))
