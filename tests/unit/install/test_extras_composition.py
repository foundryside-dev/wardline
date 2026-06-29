"""Extras-composition invariant: scan-pipeline extras must be self-sufficient.

``uv tool install`` REPLACES the tool environment with exactly the named extras — it
does NOT merge. So ``uv tool install 'wardline[loomweave]'`` that resolved to *only*
``blake3`` would silently drop the scanner deps the CLI requires, and the user would
whack-a-mole scanner<->loomweave with each reinstall (the CLI then errors
"requires the scanner extra"). Any extra that powers a feature riding the scan pipeline
(``rust`` frontend, ``loomweave`` taint-store writes) must therefore self-include
``wardline[scanner]`` so a single-extra install carries the scanner deps with it —
exactly as the ``rust`` extra already does.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_PYPROJECT = Path(__file__).resolve().parents[3] / "pyproject.toml"


def _optional_dependencies() -> dict[str, list[str]]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return data["project"]["optional-dependencies"]


def test_scan_pipeline_extras_self_include_scanner() -> None:
    extras = _optional_dependencies()
    for name in ("rust", "loomweave"):
        assert name in extras, f"expected a `{name}` extra in [project.optional-dependencies]"
        assert any("wardline[scanner]" in dep for dep in extras[name]), (
            f"the `{name}` extra must self-include `wardline[scanner]` — uv tool install "
            f"replaces extras, so a single-extra install must carry the scanner deps the "
            f"CLI needs (else `wardline init`/`scan` break after installing `wardline[{name}]`)"
        )
