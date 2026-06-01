import json

import pytest

from wardline.clarion._hmac import sign_request
from wardline.clarion.client import ClarionClient, Response
from wardline.core.errors import ClarionError


class FakeTransport:
    """Records requests; returns queued responses (or a default 200)."""

    def __init__(self, responses=None):
        self.calls = []  # list of (method, url, body, headers)
        self._responses = list(responses or [])

    def request(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))
        if self._responses:
            return self._responses.pop(0)
        return Response(status=200, body="{}")


def _client(transport, **kw):
    return ClarionClient(
        "http://clarion.example",
        secret="s3cr3t",
        project="proj",
        transport=transport,
        **kw,
    )


def test_resolve_signs_and_parses():
    body = json.dumps({"resolved": {"a.b": "python:function:a.b"}, "unresolved": ["c.d"]})
    t = FakeTransport([Response(status=200, body=body)])
    result = _client(t).resolve(["a.b", "c.d"])
    assert result.resolved == {"a.b": "python:function:a.b"}
    assert result.unresolved == ["c.d"]
    method, url, sent_body, headers = t.calls[0]
    assert method == "POST"
    assert url == "http://clarion.example/api/wardline/resolve"
    assert json.loads(sent_body)["project"] == "proj"
    expected = sign_request("s3cr3t", "POST", "/api/wardline/resolve", sent_body)
    assert headers["X-Loom-Component"] == f"clarion:{expected}"


def test_no_secret_sends_no_auth_header():
    t = FakeTransport([Response(status=200, body='{"resolved":{},"unresolved":[]}')])
    ClarionClient("http://c", secret=None, project="proj", transport=t).resolve(["a.b"])
    assert "X-Loom-Component" not in t.calls[0][3]


def test_write_chunks_against_batch_max():
    t = FakeTransport([Response(status=200, body='{"written":2,"unresolved_qualnames":[]}')] * 3)
    facts = [{"qualname": f"m.f{i}", "wardline_json": {}} for i in range(5)]
    result = _client(t, batch_max=2).write_taint_facts(facts)
    assert len(t.calls) == 3
    assert result.written == 6


def test_batch_get_chunks_and_preserves_input_order():
    r1 = json.dumps([{"qualname": "a", "exists": False}, {"qualname": "b", "exists": False}])
    r2 = json.dumps([{"qualname": "c", "exists": True, "wardline_json": {"x": 1}, "current_content_hash": "deadbeef"}])
    t = FakeTransport([Response(status=200, body=r1), Response(status=200, body=r2)])
    views = _client(t, batch_max=2).batch_get(["a", "b", "c"])
    assert [v.qualname for v in views] == ["a", "b", "c"]
    assert views[2].exists is True
    assert views[2].current_content_hash == "deadbeef"
    assert views[0].current_content_hash is None


def test_5xx_is_soft_returns_none_sentinel():
    t = FakeTransport([Response(status=503, body='{"code":"STORAGE_ERROR"}')])
    result = _client(t).batch_get(["a"])
    assert result is None


def test_403_write_disabled_is_soft_on_write():
    t = FakeTransport([Response(status=403, body='{"code":"WRITE_DISABLED"}')])
    result = _client(t).write_taint_facts([{"qualname": "m.f", "wardline_json": {}}])
    assert result.reachable is False
    assert result.disabled_reason == "WRITE_DISABLED"


def test_4xx_invalid_path_is_loud():
    t = FakeTransport([Response(status=400, body='{"code":"INVALID_PATH"}')])
    with pytest.raises(ClarionError, match="INVALID_PATH"):
        _client(t).resolve(["a.b"])


def test_connection_error_is_soft():
    class Boom:
        def request(self, *a, **k):
            raise OSError("connection refused")

    assert _client(Boom()).batch_get(["a"]) is None
