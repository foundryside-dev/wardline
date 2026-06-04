from __future__ import annotations

from wardline.core.http import MAX_RESPONSE_BODY_BYTES, read_response_text


class _HugeStream:
    def __init__(self) -> None:
        self.requested_size: int | None = None

    def read(self, size: int = -1) -> bytes:
        self.requested_size = size
        return b"x" * (MAX_RESPONSE_BODY_BYTES + 1)


def test_read_response_text_reads_at_most_limit_plus_sentinel() -> None:
    stream = _HugeStream()

    text = read_response_text(stream)

    assert stream.requested_size == MAX_RESPONSE_BODY_BYTES + 1
    assert len(text) < MAX_RESPONSE_BODY_BYTES + 128
    assert text.endswith("[truncated]")
