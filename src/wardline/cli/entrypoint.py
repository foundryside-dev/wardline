"""Dependency-light console-script shim."""

from __future__ import annotations

import sys

_SCANNER_EXTRA_IMPORTS = frozenset({"click", "jsonschema", "yaml"})


def main() -> None:
    try:
        from wardline.cli.main import cli
    except ModuleNotFoundError as exc:
        if exc.name in _SCANNER_EXTRA_IMPORTS:
            from wardline.core.optional_deps import extra_install_hint

            print(
                f"error: the wardline CLI requires the scanner extra — install {extra_install_hint('scanner')}.",
                file=sys.stderr,
            )
            raise SystemExit(2) from exc
        raise
    cli()
