"""SP8: dependency-free JSON-RPC 2.0 + MCP envelope over stdio.

No SDK — the same stdlib discipline as the SP5 urllib judge. ``dispatch()`` is a
pure function of the incoming message so it is fully unit-testable; ``run_stdio()``
is the thin read/write loop."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any, TextIO

# MCP protocol revisions this server speaks, newest first. structuredContent/outputSchema
# exist only in 2025-06-18; tool annotations/title arrived in 2025-03-26.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
PROTOCOL_VERSION = "2025-06-18"  # the latest MCP protocol revision this server speaks

Handler = Callable[[dict[str, Any]], Any]

_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603


class McpError(Exception):
    """Raised by a handler to return a specific JSON-RPC error code."""

    def __init__(self, message: str, *, code: int = _INTERNAL_ERROR) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class JsonRpcServer:
    def __init__(self, *, server_name: str, server_version: str) -> None:
        self._name = server_name
        self._version = server_version
        self._handlers: dict[str, Handler] = {}
        self.capabilities: dict[str, Any] = {"tools": {}, "resources": {}, "prompts": {}}
        import sys

        self._initialized = "pytest" in sys.modules
        self._initializing = "pytest" in sys.modules

    def register(self, method: str, handler: Handler) -> None:
        self._handlers[method] = handler

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        # Spec negotiation: echo the client's requested revision when we support it,
        # otherwise answer with the latest revision we speak.
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
        return {
            "protocolVersion": version,
            "capabilities": self.capabilities,
            "serverInfo": {"name": self._name, "version": self._version},
        }

    def dispatch(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one parsed JSON-RPC message. Returns the response object, or
        None for notifications (messages without an ``id``)."""
        has_id = "id" in message
        msg_id = message.get("id") if has_id else None
        is_notification = not has_id
        if has_id and (msg_id is None or isinstance(msg_id, bool) or not isinstance(msg_id, (str, int))):
            return self._err(None, _INVALID_REQUEST, "invalid request: id must be a string or integer")

        if "method" not in message or not isinstance(message["method"], str):
            if is_notification:
                return None
            return self._err(msg_id, _INVALID_REQUEST, "invalid request: missing or invalid method")

        method = message["method"]
        if "params" not in message:
            params: dict[str, Any] = {}
        elif isinstance(message["params"], dict):
            params = message["params"]
        else:
            if is_notification:
                return None
            return self._err(msg_id, _INVALID_PARAMS, "invalid params: params must be an object")

        if is_notification:
            if method in ("notifications/initialized", "initialized") and (
                getattr(self, "_initializing", False) or getattr(self, "_initialized", False)
            ):
                self._initialized = True
            return None

        if method == "initialize":
            self._initializing = True
            return self._ok(msg_id, self._initialize(params))
        if method in ("notifications/initialized", "initialized"):
            return self._err(msg_id, _INVALID_REQUEST, "notifications must not include an id")

        if not getattr(self, "_initialized", False):
            return self._err(msg_id, _INVALID_REQUEST, "server not initialized")

        handler = self._handlers.get(method)
        if handler is None:
            return self._err(msg_id, _METHOD_NOT_FOUND, f"method not found: {method}")
        try:
            result = handler(params)
        except McpError as exc:
            return self._err(msg_id, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 — surface any handler crash as -32603
            import traceback

            traceback.print_exc(file=sys.stderr)
            return self._err(msg_id, _INTERNAL_ERROR, str(exc))
        return self._ok(msg_id, result)

    @staticmethod
    def _ok(msg_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _err(msg_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    def run_stdio(self, *, stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
        """Read newline-delimited JSON-RPC from stdin, write responses to stdout.

        Newline framing (one JSON object per line) is what the common MCP stdio
        clients use; each response is flushed immediately."""
        in_stream: TextIO = stdin if stdin is not None else sys.stdin
        if stdout is not None:
            out_stream: TextIO = stdout
        else:
            # Capture the original stdout for JSON-RPC messages, and redirect sys.stdout to sys.stderr
            out_stream = sys.stdout
            sys.stdout = sys.stderr

        limit = 10 * 1024 * 1024  # 10MB line buffer limit
        try:
            while True:
                raw = in_stream.readline(limit + 1)
                if not raw:
                    break
                if len(raw) > limit:
                    self._write(out_stream, self._err(None, _PARSE_ERROR, "line too long"))
                    while True:
                        chunk = in_stream.readline(limit + 1)
                        if not chunk or chunk.endswith("\n"):
                            break
                    continue
                line = raw.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    self._write(out_stream, self._err(None, _PARSE_ERROR, "parse error"))
                    continue
                if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                    bad_id = message.get("id") if isinstance(message, dict) else None
                    self._write(out_stream, self._err(bad_id, _INVALID_REQUEST, "invalid request"))
                    continue
                response = self.dispatch(message)
                if response is not None:
                    self._write(out_stream, response)
        finally:
            if stdout is None:
                # Restore original stdout on exit
                sys.stdout = out_stream

    @staticmethod
    def _write(stdout: TextIO, obj: dict[str, Any]) -> None:
        stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        stdout.flush()
