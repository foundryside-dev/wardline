import json
import urllib.error
import urllib.request

import pytest

from wardline.core.errors import LoomweaveError
from wardline.loomweave._hmac import sign_request
from wardline.loomweave.client import LoomweaveClient, Response


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
    return LoomweaveClient(
        "http://loomweave.example",
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
    assert url == "http://loomweave.example/api/wardline/resolve"
    assert json.loads(sent_body)["project"] == "proj"
    expected = sign_request(
        "s3cr3t",
        "POST",
        "/api/wardline/resolve",
        sent_body,
        timestamp=headers["X-Weft-Timestamp"],
        nonce=headers["X-Weft-Nonce"],
    )
    assert headers["X-Weft-Component"] == f"loomweave:{expected}"


def test_no_secret_sends_no_auth_header():
    t = FakeTransport([Response(status=200, body='{"resolved":{},"unresolved":[]}')])
    LoomweaveClient("http://c", secret=None, project="proj", transport=t).resolve(["a.b"])
    assert "X-Weft-Component" not in t.calls[0][3]


def test_write_chunks_against_batch_max():
    t = FakeTransport([Response(status=200, body='{"written":2,"unresolved_qualnames":[]}')] * 3)
    facts = [{"qualname": f"m.f{i}", "wardline_json": {}} for i in range(5)]
    result = _client(t, batch_max=2).write_taint_facts(facts)
    assert len(t.calls) == 3
    assert result.written == 6


def test_write_chunks_against_serialized_body_size():
    t = FakeTransport([Response(status=200, body='{"written":1,"unresolved_qualnames":[]}')] * 3)
    facts = [{"qualname": f"m.f{i}", "wardline_json": {"payload": "x" * 30}} for i in range(3)]

    result = _client(t, batch_max=100, max_body_bytes=180).write_taint_facts(facts)

    assert result.reachable is True
    assert len(t.calls) > 1
    assert all(len(body) <= 180 for _method, _url, body, _headers in t.calls)


def test_write_oversized_single_fact_is_fail_soft_without_sending():
    t = FakeTransport()
    fact = {"qualname": "m.big", "wardline_json": {"payload": "x" * 300}}

    result = _client(t, max_body_bytes=120).write_taint_facts([fact])

    assert result.reachable is False
    assert t.calls == []


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
    with pytest.raises(LoomweaveError, match="INVALID_PATH"):
        _client(t).resolve(["a.b"])


def test_urllib_transport_bounds_http_error_body(monkeypatch) -> None:
    import io

    from wardline.core.http import MAX_RESPONSE_BODY_BYTES
    from wardline.loomweave.client import UrllibTransport

    def _raise(req, timeout=None):  # noqa: ARG001
        raise urllib.error.HTTPError(
            url="http://loomweave.example/api/wardline/resolve",
            code=400,
            msg="Bad Request",
            hdrs=None,
            fp=io.BytesIO(b"x" * (MAX_RESPONSE_BODY_BYTES + 9)),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    resp = UrllibTransport().request("POST", "http://loomweave.example/api/wardline/resolve", b"{}", {})
    assert len(resp.body) < MAX_RESPONSE_BODY_BYTES + 128
    assert resp.body.endswith("[truncated]")


def test_urllib_transport_bounds_success_body(monkeypatch) -> None:
    import io

    from wardline.core.http import MAX_RESPONSE_BODY_BYTES
    from wardline.loomweave.client import UrllibTransport

    class HugeResponse(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=None: HugeResponse(b"x" * (MAX_RESPONSE_BODY_BYTES + 9)),  # noqa: ARG005
    )

    resp = UrllibTransport().request("POST", "http://loomweave.example/api/wardline/resolve", b"{}", {})

    assert len(resp.body) < MAX_RESPONSE_BODY_BYTES + 128
    assert resp.body.endswith("[truncated]")


def test_connection_error_is_soft():
    class Boom:
        def request(self, *a, **k):
            raise OSError("connection refused")

    assert _client(Boom()).batch_get(["a"]) is None


def test_resolve_sends_batch_scoped_plugin_hint():
    # ADR-036 plugin-aware resolution: the OPTIONAL batch-scoped hint rides the
    # request verbatim (docs/integration/2026-06-11-wardline-resolve-plugin-hint-
    # proposal.md). One hint per request — never per qualname.
    t = FakeTransport([Response(status=200, body='{"resolved":{},"unresolved":["m.f"]}')])
    _client(t).resolve(["m.f"], plugin="rust")
    assert json.loads(t.calls[0][2])["plugin"] == "rust"


def test_resolve_omits_plugin_field_when_unhinted():
    # Omission is today's behavior FOREVER (the contract never fabricates a hint) —
    # and an absent field is what keeps unhinted requests valid against any server
    # version under deny_unknown_fields.
    t = FakeTransport([Response(status=200, body='{"resolved":{},"unresolved":["m.f"]}')])
    _client(t).resolve(["m.f"])
    assert "plugin" not in json.loads(t.calls[0][2])


def test_resolve_hinted_4xx_downgrades_chunk_to_unresolved():
    # Fail-soft: an older Loomweave whose ResolveRequest is deny_unknown_fields 400s
    # on the hint field — identity enrichment must degrade to unresolved, not crash
    # the dossier/attach path.
    t = FakeTransport([Response(status=400, body='{"error":"unknown field `plugin`"}')])
    result = _client(t).resolve(["m.f", "m.g"], plugin="rust")
    assert result is not None
    assert result.resolved == {}
    assert result.unresolved == ["m.f", "m.g"]


def test_resolve_unhinted_4xx_stays_loud():
    # An unhinted 4xx cannot be hint-field version skew — it is a real request bug
    # and must stay diagnosable (the pre-existing INVALID_PATH pin, re-asserted
    # against the hint-conditional soft band).
    t = FakeTransport([Response(status=400, body='{"code":"INVALID_PATH"}')])
    with pytest.raises(LoomweaveError, match="INVALID_PATH"):
        _client(t).resolve(["m.f"])
