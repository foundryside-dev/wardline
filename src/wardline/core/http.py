"""Small HTTP transport helpers shared by stdlib urllib clients."""

from __future__ import annotations

from typing import Protocol

MAX_RESPONSE_BODY_BYTES = 64 * 1024
_TRUNCATION_MARKER = "... [truncated]"


class _Readable(Protocol):
    def read(self, size: int = -1) -> bytes: ...


def read_response_text(stream: _Readable, *, limit: int = MAX_RESPONSE_BODY_BYTES) -> str:
    """Read a bounded response/error body and decode it for diagnostics."""
    data = stream.read(limit + 1)
    truncated = len(data) > limit
    if truncated:
        data = data[:limit]
    text = data.decode("utf-8", "replace")
    return f"{text}{_TRUNCATION_MARKER}" if truncated else text
