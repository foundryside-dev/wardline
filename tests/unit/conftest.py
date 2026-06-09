"""Unit-test isolation shared across ``tests/unit``."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_filigree_server_config(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Default every unit test to an ABSENT Filigree server-mode registry.

    ``wardline.core.config._filigree_server_config_path`` resolves to the real
    ``~/.config/filigree/server.json`` in production; a unit test must never read the
    dev machine's copy (it would make filigree-URL resolution and ``.mcp.json`` repair
    machine-dependent). Tests that exercise server mode override this by writing their
    own registry and re-pointing the resolver."""
    absent = tmp_path_factory.mktemp("no_filigree_server") / "server.json"
    monkeypatch.setattr("wardline.core.config._filigree_server_config_path", lambda: absent)
