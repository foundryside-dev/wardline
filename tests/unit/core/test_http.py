from __future__ import annotations

import io
import urllib.error
import urllib.request

import pytest

from wardline.core.http import MAX_RESPONSE_BODY_BYTES, HttpResult, WeftHttp, read_response_text


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


# --- WeftHttp shared transport ----------------------------------------------


class _Resp(io.BytesIO):
    """A urlopen() return value: a context-managed body stream with a ``status``."""

    def __init__(self, data: bytes, status: int = 200) -> None:
        super().__init__(data)
        self.status = status

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> None:
        self.close()


def test_fetch_round_trips_status_and_body(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["method"] = req.get_method()
        seen["timeout"] = timeout
        seen["body"] = req.data
        seen["headers"] = dict(req.header_items())
        return _Resp(b'{"ok":true}', status=200)

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    http = WeftHttp(timeout=12.5)
    result = http.fetch("POST", "http://h/api", body=b"payload", headers={"Content-Type": "application/json"})

    assert isinstance(result, HttpResult)
    assert result.status == 200
    assert result.body == '{"ok":true}'
    # timeout is threaded through to urlopen unchanged
    assert seen["timeout"] == 12.5
    assert seen["method"] == "POST"
    assert seen["body"] == b"payload"
    # header is carried through Request construction (urllib title-cases the key)
    assert seen["headers"].get("Content-type") == "application/json"


def test_fetch_surfaces_http_error_as_result_not_raise(monkeypatch) -> None:
    # an HTTP 4xx/5xx (HTTPError, a URLError subclass) is converted to an HttpResult
    # carrying its status — never re-raised as an outage, so callers classify by band.
    def _raise(req, timeout=None):  # noqa: ARG001
        raise urllib.error.HTTPError("http://h", 503, "down", {}, io.BytesIO(b"boom"))

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    result = WeftHttp().fetch("GET", "http://h/api")
    assert result.status == 503
    assert result.body == "boom"


def test_fetch_does_not_swallow_urlerror(monkeypatch) -> None:
    # URLError (a transport outage, NOT an HTTP status) propagates to the caller, whose
    # own fail-soft policy decides what an outage means. WeftHttp must not catch it.
    def _raise(req, timeout=None):  # noqa: ARG001
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    with pytest.raises(urllib.error.URLError):
        WeftHttp().fetch("GET", "http://h/api")


def test_fetch_does_not_swallow_oserror(monkeypatch) -> None:
    def _raise(req, timeout=None):  # noqa: ARG001
        raise OSError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    with pytest.raises(OSError, match="timed out"):
        WeftHttp().fetch("GET", "http://h/api")


def test_fetch_bounds_success_body(monkeypatch) -> None:
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=None: _Resp(b"x" * (MAX_RESPONSE_BODY_BYTES + 9), status=200),  # noqa: ARG005
    )
    result = WeftHttp().fetch("GET", "http://h/api")
    assert len(result.body) < MAX_RESPONSE_BODY_BYTES + 128
    assert result.body.endswith("[truncated]")


def test_fetch_bounds_http_error_body(monkeypatch) -> None:
    def _raise(req, timeout=None):  # noqa: ARG001
        raise urllib.error.HTTPError(
            "http://h", 400, "bad", {}, io.BytesIO(b"x" * (MAX_RESPONSE_BODY_BYTES + 9))
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    result = WeftHttp().fetch("POST", "http://h/api", body=b"{}")
    assert len(result.body) < MAX_RESPONSE_BODY_BYTES + 128
    assert result.body.endswith("[truncated]")


def test_fetch_honors_custom_max_body_bytes(monkeypatch) -> None:
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=None: _Resp(b"y" * 1000, status=200),  # noqa: ARG005
    )
    result = WeftHttp(max_body_bytes=64).fetch("GET", "http://h/api")
    assert result.body.endswith("[truncated]")
    # the visible text is bounded to the custom cap (plus the sentinel marker)
    assert len(result.body) < 64 + 32


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://h/x", "data:text/plain,hi"])
def test_fetch_rejects_disallowed_scheme_default_error(url: str) -> None:
    # the default gate raises ValueError naming the scheme; no urlopen is reached
    with pytest.raises(ValueError, match="must use"):
        WeftHttp().fetch("GET", url)


def test_fetch_scheme_error_builder_is_used_verbatim() -> None:
    # each client supplies its own exception type + message; WeftHttp raises it verbatim
    class _ClientError(Exception):
        pass

    http = WeftHttp(scheme_error=lambda scheme, url: _ClientError(f"bad {scheme} in {url}"))
    with pytest.raises(_ClientError, match="bad file in file:///x"):
        http.fetch("GET", "file:///x")


def test_fetch_allowed_schemes_is_parameterizable(monkeypatch) -> None:
    # a client that only permits https must reject http even though it is a default scheme
    http = WeftHttp(allowed_schemes=("https",))
    with pytest.raises(ValueError, match="must use"):
        http.fetch("GET", "http://h/api")

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _Resp(b"ok", status=200))  # noqa: ARG005
    assert http.fetch("GET", "https://h/api").status == 200


def test_fetch_uses_call_time_urlopen_lookup(monkeypatch) -> None:
    # the monkeypatch seam the federation client tests rely on: WeftHttp must resolve
    # urllib.request.urlopen at call time, not bind it at import/def time.
    http = WeftHttp()
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _Resp(b"late", status=201))  # noqa: ARG005
    assert http.fetch("GET", "http://h/api").status == 201
