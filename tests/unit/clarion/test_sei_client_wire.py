"""Track 3 T3.1 — ClarionClient SEI wire methods: correct routes/payloads, HMAC
signing, and fail-soft on every non-happy band. Built against the pinned
/api/v1/identity/* + /api/v1/_capabilities routes (Clarion delivery plan T2.4)."""

from __future__ import annotations

import json

from wardline.clarion._hmac import sign_request
from wardline.clarion.client import ClarionClient, Response


class FakeTransport:
    def __init__(self, responses=None):
        self.calls = []
        self._responses = list(responses or [])

    def request(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))
        if self._responses:
            return self._responses.pop(0)
        return Response(status=200, body="{}")


def _client(transport, **kw):
    return ClarionClient("http://clarion.example", secret="s3cr3t", project="proj", transport=transport, **kw)


def test_capabilities_gets_route_and_parses() -> None:
    body = json.dumps({"sei": {"supported": True, "version": 1}})
    t = FakeTransport([Response(status=200, body=body)])
    caps = _client(t).capabilities()
    assert caps == {"sei": {"supported": True, "version": 1}}
    method, url, sent_body, headers = t.calls[0]
    assert method == "GET"
    assert url == "http://clarion.example/api/v1/_capabilities"
    # GET routes are signed too (empty body) — the shared _send path signs everything.
    assert headers["X-Loom-Component"] == f"clarion:{sign_request('s3cr3t', 'GET', '/api/v1/_capabilities', sent_body)}"


def test_capabilities_soft_none_on_404() -> None:
    # A pre-SEI Clarion 404s the route — must degrade to None, never raise.
    t = FakeTransport([Response(status=404, body="not found")])
    assert _client(t).capabilities() is None


def test_capabilities_soft_none_on_bad_body() -> None:
    t = FakeTransport([Response(status=200, body="<<not json>>")])
    assert _client(t).capabilities() is None


def test_resolve_identity_posts_locator_and_signs() -> None:
    body = json.dumps(
        {"sei": "clarion:eid:abc", "current_locator": "python:function:m.f", "content_hash": "h", "alive": True}
    )
    t = FakeTransport([Response(status=200, body=body)])
    data = _client(t).resolve_identity("python:function:m.f")
    assert data["alive"] is True and data["sei"] == "clarion:eid:abc"
    method, url, sent_body, headers = t.calls[0]
    assert method == "POST"
    assert url == "http://clarion.example/api/v1/identity/resolve"
    assert json.loads(sent_body) == {"locator": "python:function:m.f"}
    expected = sign_request("s3cr3t", "POST", "/api/v1/identity/resolve", sent_body)
    assert headers["X-Loom-Component"] == f"clarion:{expected}"


def test_resolve_identity_alive_false_is_a_value_not_an_error() -> None:
    t = FakeTransport([Response(status=200, body='{"alive": false}')])
    assert _client(t).resolve_identity("python:function:gone") == {"alive": False}


def test_resolve_identity_soft_none_on_4xx() -> None:
    t = FakeTransport([Response(status=400, body='{"code":"NOT_A_LOCATOR"}')])
    assert _client(t).resolve_identity("python:function:m.f") is None


def test_resolve_sei_gets_escaped_opaque_token() -> None:
    body = json.dumps({"current_locator": "python:function:m.f", "alive": True})
    t = FakeTransport([Response(status=200, body=body)])
    # A token with URL-significant chars proves it is escaped, never interpreted.
    data = _client(t).resolve_sei("clarion:eid:a/b c?d")
    assert data["alive"] is True
    method, url, sent_body, headers = t.calls[0]
    assert method == "GET"
    paq = "/api/v1/identity/sei/clarion%3Aeid%3Aa%2Fb%20c%3Fd"
    assert url == f"http://clarion.example{paq}"
    # HMAC is signed over the ESCAPED path-and-query exactly as sent (no double-encoding).
    assert headers["X-Loom-Component"] == f"clarion:{sign_request('s3cr3t', 'GET', paq, sent_body)}"


def test_resolve_sei_orphaned_returns_lineage_value() -> None:
    t = FakeTransport([Response(status=200, body='{"alive": false, "lineage": []}')])
    assert _client(t).resolve_sei("clarion:eid:orph") == {"alive": False, "lineage": []}


def test_resolve_sei_soft_none_on_outage() -> None:
    t = FakeTransport([Response(status=503, body="")])
    assert _client(t).resolve_sei("clarion:eid:x") is None
