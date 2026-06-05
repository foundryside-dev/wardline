# src/wardline/cli/install.py
"""`wardline install` — push agent-enablement artifacts into a project."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core.errors import WardlineError
from wardline.install.block import inject_block
from wardline.install.detect import record_bindings
from wardline.install.mcp_json import install_codex_mcp, merge_mcp_entry
from wardline.install.pack import activate_pack
from wardline.install.skill import install_skill


@click.command()
@click.argument("pack", required=False, default=None)
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    help="Project root to install into (default: cwd).",
)
@click.option("--no-claude-md", is_flag=True, help="Skip the CLAUDE.md instruction block.")
@click.option("--no-agents-md", is_flag=True, help="Skip the AGENTS.md instruction block.")
@click.option("--no-skill", is_flag=True, help="Skip the wardline-gate skill.")
@click.option("--no-mcp", is_flag=True, help="Skip wiring .mcp.json and Codex MCP config.")
@click.option("--no-bindings", is_flag=True, help="Skip Loomweave/Filigree detection.")
@click.option("--no-attest-key", is_flag=True, help="Skip minting the attest signing key.")
@click.option("--no-pre-commit", is_flag=True, help="Skip adding pre-commit hook config.")
def install(
    pack: str | None,
    root: Path,
    no_claude_md: bool,
    no_agents_md: bool,
    no_skill: bool,
    no_mcp: bool,
    no_bindings: bool,
    no_attest_key: bool,
    no_pre_commit: bool,
) -> None:
    """Install wardline's agent-facing guidance and sibling bindings into ROOT.

    Idempotent; re-running is safe (and refreshes stale artifacts). If a step
    fails (e.g. a malformed .mcp.json), earlier artifacts may already be written
    — fix the cause and re-run.
    """
    lines: list[str] = []
    try:
        if not no_claude_md:
            lines.append(f"CLAUDE.md: {inject_block(root / 'CLAUDE.md')}")
        if not no_agents_md:
            lines.append(f"AGENTS.md: {inject_block(root / 'AGENTS.md')}")
        if not no_skill:
            for base, status in install_skill(root).items():
                lines.append(f"skill {base}/skills/wardline-gate: {status}")
        if not no_mcp:
            lines.append(f".mcp.json (wardline entry): {merge_mcp_entry(root)}")
            lines.append(f"Codex MCP (wardline entry): {install_codex_mcp(root)}")
        if not no_bindings:
            for name, status in record_bindings(root).items():
                lines.append(f"{name}: {status}")
        if not no_attest_key:
            from wardline.core.attest_key import mint_attest_key

            _key, status = mint_attest_key(root)
            lines.append(f"attest key: {status}")
        if (
            not no_pre_commit
            and (root / ".pre-commit-config.yaml").exists()
            and click.confirm("Add wardline-scan pre-commit hook to .pre-commit-config.yaml?", default=True)
        ):
            from wardline.install.pre_commit import install_pre_commit_hook

            lines.append(f"pre-commit hook: {install_pre_commit_hook(root)}")
        if pack is not None:
            try:
                import importlib

                importlib.import_module(pack)
            except ImportError:
                click.echo(f"warning: trust-grammar pack {pack!r} is not installed or importable locally", err=True)
            status = activate_pack(root, pack)
            lines.append(f"packs: {status}")
        lines.append("runtime markers: install `weft-markers` and import from `weft_markers`")
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo("wardline install:")
    for line in lines:
        click.echo(f"  {line}")
