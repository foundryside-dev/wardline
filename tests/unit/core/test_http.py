from __future__ import annotations

import contextlib
import http.server
import io
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest

from wardline.core.http import (
    MAX_RESPONSE_BODY_BYTES,
    HttpResult,
    WeftHttp,
    WeftRedirectError,
    read_response_text,
)


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
        raise urllib.error.HTTPError("http://h", 400, "bad", {}, io.BytesIO(b"x" * (MAX_RESPONSE_BODY_BYTES + 9)))

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


# --- redirect refusal (fail-closed transport) --------------------------------
#
# No federation peer (Filigree, Loomweave, legis) legitimately redirects, and urllib's
# default redirect handler re-sends EVERY non-Content-* header — Authorization: Bearer
# and the X-Weft-* HMAC trio included — to the redirect target, cross-origin included,
# while rewriting a redirected POST into a body-less GET (whose 200 would parse as a
# clean, reachable emit: silent false-green telemetry). WeftHttp must therefore surface
# a 3xx as a protocol outcome (an HttpResult the caller classifies by status band) and
# NEVER dial the redirect target. These tests use REAL sockets and the REAL urlopen —
# no monkeypatch — because the defect lives in the default opener's handler chain.


class _ScriptedHandler(http.server.BaseHTTPRequestHandler):
    """Serves one scripted (status, headers, body) reply and records every request."""

    def _reply(self) -> None:
        server = self.server
        server.requests.append((self.command, self.path, dict(self.headers)))  # type: ignore[attr-defined]
        status, extra_headers, payload = server.script  # type: ignore[attr-defined]
        self.send_response(status)
        for key, value in extra_headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _reply
    do_POST = _reply

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # keep pytest output clean


@contextlib.contextmanager
def _live_server(script: tuple[int, dict[str, str], bytes]) -> Iterator[http.server.HTTPServer]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _ScriptedHandler)
    server.script = script  # type: ignore[attr-defined]
    server.requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_fetch_refuses_redirect_and_never_resends_credentials() -> None:
    # THE fail-closed pin: a 302 on a credentialed POST surfaces as HttpResult(302);
    # the redirect target is NEVER dialed, so the bearer/HMAC headers are never re-sent
    # and the POST is never rewritten into a body-less GET that would 200 as a clean emit.
    with _live_server((200, {}, b'{"ok": true}')) as target:
        target_url = f"http://127.0.0.1:{target.server_address[1]}/api/scan-results"
        with _live_server((302, {"Location": target_url}, b"moved")) as redirector:
            origin_url = f"http://127.0.0.1:{redirector.server_address[1]}/api/scan-results"
            result = WeftHttp(timeout=5.0).fetch(
                "POST",
                origin_url,
                body=b'{"findings": []}',
                headers={
                    "Authorization": "Bearer SECRET-TOKEN",
                    "X-Weft-Component": "wardline",
                    "Content-Type": "application/json",
                },
            )
    assert result.status == 302
    assert result.body == "moved"
    # the redirect target received NOTHING — no cross-origin credential forwarding
    assert target.requests == []  # type: ignore[attr-defined]
    # and exactly one round trip went to the origin we actually dialed
    assert len(redirector.requests) == 1  # type: ignore[attr-defined]
    assert redirector.requests[0][0] == "POST"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("status", "method"),
    [(301, "GET"), (302, "GET"), (303, "POST"), (307, "POST"), (308, "POST")],
)
def test_fetch_surfaces_every_redirect_status_without_following(status: int, method: str) -> None:
    # every redirect band member is a protocol outcome, never a follow. Location points
    # at a port nothing listens on: an attempted follow would raise URLError and fail
    # the test loudly instead of returning the 3xx.
    with _live_server((status, {"Location": "http://127.0.0.1:1/elsewhere"}, b"nope")) as server:
        url = f"http://127.0.0.1:{server.server_address[1]}/api"
        body = b"{}" if method == "POST" else None
        result = WeftHttp(timeout=5.0).fetch(method, url, body=body)
    assert result.status == status
    assert len(server.requests) == 1  # type: ignore[attr-defined]


def test_fetch_surfaces_location_less_3xx_as_result() -> None:
    # a 3xx WITHOUT a Location header (e.g. a bogus 300) still surfaces by status band
    with _live_server((300, {}, b"choose")) as server:
        url = f"http://127.0.0.1:{server.server_address[1]}/api"
        result = WeftHttp(timeout=5.0).fetch("GET", url)
    assert result.status == 300


def test_fetch_live_success_passes_the_final_url_guard() -> None:
    # a REAL non-redirected 2xx round trip (query string included) must sail through the
    # followed-redirect backstop: the response's final URL matches the dialed URL.
    with _live_server((200, {}, b'{"ok": true}')) as server:
        url = f"http://127.0.0.1:{server.server_address[1]}/api/items?page=2&size=10"
        result = WeftHttp(timeout=5.0).fetch("GET", url)
        post = WeftHttp(timeout=5.0).fetch("POST", url, body=b"{}")
    assert result.status == 200
    assert result.body == '{"ok": true}'
    assert post.status == 200


def test_fetch_rejects_followed_redirect_response_defense_in_depth(monkeypatch) -> None:
    # backstop for the never-follow guard: if a response ever arrives from a URL other
    # than the one we dialed (i.e. a redirect WAS followed), fetch fails closed with a
    # typed URLError subclass — every caller's outage policy carries a signal — and the
    # message redacts the target to scheme+host (no path/query/userinfo leakage).
    resp = _Resp(b"stolen", status=200)
    resp.url = "https://alice:hunter2@evil.example:8443/collect?token=SECRET"  # type: ignore[attr-defined]
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: resp)  # noqa: ARG005
    with pytest.raises(WeftRedirectError) as exc_info:
        WeftHttp().fetch("POST", "http://h/api", body=b"{}")
    assert isinstance(exc_info.value, urllib.error.URLError)
    message = str(exc_info.value)
    assert "https://evil.example:8443" in message
    for leaked in ("collect", "token", "SECRET", "alice", "hunter2"):
        assert leaked not in message


def test_fetch_accepts_response_reporting_the_requested_url(monkeypatch) -> None:
    # a response whose final URL matches the request is NOT a followed redirect
    resp = _Resp(b"ok", status=200)
    resp.url = "http://h/api"  # type: ignore[attr-defined]
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: resp)  # noqa: ARG005
    assert WeftHttp().fetch("GET", "http://h/api").status == 200
