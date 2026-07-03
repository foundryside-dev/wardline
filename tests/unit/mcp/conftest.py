"""MCP unit-test configuration.

The MCP initialize-handshake gate is REQUIRED by default in production
(wardline-5e4a4ee246 removed the old ``"pytest" in sys.modules`` sniff that
silently disabled it). The unit tests in this package drive tool handlers
directly through ``JsonRpcServer.dispatch()`` without a client handshake, so
this autouse fixture re-defaults ``JsonRpcServer(require_handshake=...)`` to
``False`` for them — an EXPLICIT, test-layer opt-out, visible in test code
instead of forked inside production code.

A test that passes ``require_handshake`` explicitly (the gate tests in
``test_protocol.py``) always wins over this default, and the true production
default (gate enabled) is pinned end-to-end in
``tests/conformance/test_mcp_handshake.py``, which this fixture deliberately
does NOT cover.
"""

from __future__ import annotations

import pytest

from wardline.mcp.protocol import JsonRpcServer

_ORIG_INIT = JsonRpcServer.__init__


@pytest.fixture(autouse=True)
def _handshake_preopened(monkeypatch: pytest.MonkeyPatch) -> None:
    def _init(
        self: JsonRpcServer,
        *,
        server_name: str,
        server_version: str,
        require_handshake: bool = False,
    ) -> None:
        _ORIG_INIT(
            self,
            server_name=server_name,
            server_version=server_version,
            require_handshake=require_handshake,
        )

    monkeypatch.setattr(JsonRpcServer, "__init__", _init)
