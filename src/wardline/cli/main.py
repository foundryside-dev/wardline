"""Wardline CLI — Click-based command-line interface.

Entry point: ``wardline = "wardline.cli.main:cli"`` (pyproject.toml).
"""

from __future__ import annotations

import click


@click.group()
def cli() -> None:
    """Wardline — semantic boundary enforcement for Python."""


# --- Register subcommands ---
from wardline.cli.coherence_cmd import coherence  # noqa: E402
from wardline.cli.corpus_cmds import corpus  # noqa: E402
from wardline.cli.exception_cmds import exception  # noqa: E402
from wardline.cli.explain_cmd import explain  # noqa: E402
from wardline.cli.fingerprint_cmd import fingerprint  # noqa: E402
from wardline.cli.manifest_cmds import manifest  # noqa: E402
from wardline.cli.project_cmd import project  # noqa: E402
from wardline.cli.regime_cmd import regime  # noqa: E402
from wardline.cli.resolve_cmd import resolve  # noqa: E402
from wardline.cli.scan import scan  # noqa: E402

cli.add_command(coherence)
cli.add_command(corpus)
cli.add_command(exception)
cli.add_command(explain)
cli.add_command(fingerprint)
cli.add_command(manifest)
cli.add_command(project)
cli.add_command(regime)
cli.add_command(resolve)
cli.add_command(scan)
