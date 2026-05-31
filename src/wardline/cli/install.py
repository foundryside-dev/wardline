# src/wardline/cli/install.py
"""`wardline install` — push agent-enablement artifacts into a project."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core.errors import WardlineError
from wardline.install.block import inject_block
from wardline.install.detect import record_bindings
from wardline.install.mcp_json import merge_mcp_entry
from wardline.install.skill import install_skill


@click.command()
@click.option("--root", type=click.Path(exists=True, file_okay=False, path_type=Path),
              default=".", help="Project root to install into (default: cwd).")
@click.option("--no-claude-md", is_flag=True, help="Skip the CLAUDE.md instruction block.")
@click.option("--no-agents-md", is_flag=True, help="Skip the AGENTS.md instruction block.")
@click.option("--no-skill", is_flag=True, help="Skip the wardline-gate skill.")
@click.option("--no-mcp", is_flag=True, help="Skip wiring .mcp.json.")
@click.option("--no-bindings", is_flag=True, help="Skip Clarion/Filigree detection.")
def install(
    root: Path,
    no_claude_md: bool,
    no_agents_md: bool,
    no_skill: bool,
    no_mcp: bool,
    no_bindings: bool,
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
        if not no_bindings:
            for name, status in record_bindings(root).items():
                lines.append(f"{name}: {status}")
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo("wardline install:")
    for line in lines:
        click.echo(f"  {line}")
