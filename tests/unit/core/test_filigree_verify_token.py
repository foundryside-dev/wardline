# tests/unit/core/test_filigree_verify_token.py
from collections.abc import Mapping

from wardline.core.filigree_emit import FiligreeEmitter, Response


class _FakeTransport:
    """Records the last POST and returns a canned Response or raises."""

    def __init__(self, *, status: int | None = None, exc: Exception | None = None) -> None:
        self._status = status
        self._exc = exc
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response:
        self.calls.append((url, body, dict(headers)))
        if self._exc is not None:
            raise self._exc
        assert self._status is not None
        return Response(status=self._status, body="")


def test_verify_token_401_is_rejected() -> None:
    t = _FakeTransport(status=401)
    result = FiligreeEmitter("http://127.0.0.1:8749/api/weft/scan-results", transport=t, token="bad").verify_token()
    assert result.reachable is True
    assert result.accepted is False
    assert result.status == 401


def test_verify_token_400_is_accepted() -> None:
    # Auth middleware runs before body validation: a good token + sentinel body => 400.
    t = _FakeTransport(status=400)
    result = FiligreeEmitter("http://127.0.0.1:8749/api/weft/scan-results", transport=t, token="good").verify_token()
    assert result.accepted is True
    assert result.status == 400
    # Sentinel body present; bearer attached. The body MUST be the deliberately-incomplete
    # b"{}" sentinel, NOT a real scan-results body — a regression to emit()-style content
    # (build_scan_results_body([]) is also truthy) would register an empty scan on the
    # daemon every doctor probe. Pin the exact content so that regression fails here.
    url, body, headers = t.calls[0]
    assert headers["Authorization"] == "Bearer good"
    assert body == b"{}"  # sentinel only; no findings/scan_source body
    assert b"findings" not in body and b"scan_source" not in body


def test_verify_token_403_is_rejected() -> None:
    result = FiligreeEmitter("http://x/y", transport=_FakeTransport(status=403), token="t").verify_token()
    assert result.accepted is False


def test_verify_token_transport_error_is_unreachable() -> None:
    t = _FakeTransport(exc=OSError("connection refused"))
    result = FiligreeEmitter("http://127.0.0.1:8749/api/weft/scan-results", transport=t, token="t").verify_token()
    assert result.reachable is False
    assert result.accepted is False
    assert result.status is None
