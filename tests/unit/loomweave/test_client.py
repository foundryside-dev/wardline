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


def test_write_mid_batch_outage_preserves_partial_written_count():
    # The documented contract: on a mid-batch soft failure earlier chunks may already
    # be committed and `written` reflects the chunks that succeeded before the first
    # failure — never a fabricated written=0 for facts the store now holds.
    t = FakeTransport(
        [
            Response(status=200, body='{"written":2,"unresolved_qualnames":["m.gone"]}'),
            Response(status=503, body='{"code":"STORAGE_ERROR"}'),
        ]
    )
    facts = [{"qualname": f"m.f{i}", "wardline_json": {}} for i in range(4)]
    result = _client(t, batch_max=2).write_taint_facts(facts)
    assert result.reachable is False
    assert result.written == 2
    assert result.unresolved_qualnames == ("m.gone",)


def test_write_mid_batch_403_preserves_partial_written_count_and_reason():
    t = FakeTransport(
        [
            Response(status=200, body='{"written":2,"unresolved_qualnames":[]}'),
            Response(status=403, body='{"code":"WRITE_DISABLED"}'),
        ]
    )
    facts = [{"qualname": f"m.f{i}", "wardline_json": {}} for i in range(4)]
    result = _client(t, batch_max=2).write_taint_facts(facts)
    assert result.reachable is False
    assert result.written == 2
    assert result.disabled_reason == "WRITE_DISABLED"


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


def test_urllib_transport_rejects_non_http_scheme() -> None:
    # The scheme allow-list is a THREAT-001-class confinement: a file:///ftp:///data:
    # --loomweave-url is a loud LoomweaveError naming the flag, never an ingest target.
    # Pins loomweave's OWN scheme-error wording (--loomweave-url), not just the type.
    from wardline.loomweave.client import UrllibTransport

    with pytest.raises(LoomweaveError, match="--loomweave-url"):
        UrllibTransport().request("POST", "file:///etc/passwd", b"{}", {})


def test_urllib_transport_scheme_error_redacts_credentials() -> None:
    # The scheme-error text is captured verbatim into WriteResult.disabled_reason and
    # persisted in the agent-summary / MCP scan envelopes (cli/scan.py, mcp/server.py),
    # so a credential-bearing operator URL must be redacted at exception formation —
    # filigree_emit's redact_url_for_diagnostics discipline, applied to this transport.
    from wardline.loomweave.client import UrllibTransport

    with pytest.raises(LoomweaveError) as excinfo:
        UrllibTransport().request("POST", "ftps://user:hunter2@host/x?token=tok123", b"{}", {})
    message = str(excinfo.value)
    assert "hunter2" not in message
    assert "tok123" not in message
    assert "user" not in message.replace("<redacted>", "")
    assert "<redacted>@host" in message
    assert "'ftps'" in message  # the scheme itself stays diagnosable


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


def test_resolve_hinted_legacy_plugin_field_rejection_downgrades_chunk_to_unresolved():
    # Fail-soft: an older Loomweave whose ResolveRequest is deny_unknown_fields 400s
    # on the hint field — identity enrichment must degrade to unresolved, not crash
    # the dossier/attach path.
    t = FakeTransport(
        [
            Response(
                status=400,
                body='{"code":"INVALID_PATH","error":"unknown field `plugin`, expected `project` or `qualnames`"}',
            )
        ]
    )
    result = _client(t).resolve(["m.f", "m.g"], plugin="rust")
    assert result is not None
    assert result.resolved == {}
    assert result.unresolved == ["m.f", "m.g"]


@pytest.mark.parametrize("status", [404, 409, 422, 429])
def test_resolve_hinted_noncompatibility_4xx_stays_loud(status: int):
    t = FakeTransport([Response(status=status, body='{"code":"REAL_ERROR"}')])

    with pytest.raises(LoomweaveError, match=str(status)):
        _client(t).resolve(["m.f"], plugin="rust")


def test_resolve_hinted_noncompatibility_400_stays_loud():
    # Modern Loomweave uses the same status/code for malformed resolve requests.
    # Only the old-server unknown-plugin-field envelope is version skew.
    t = FakeTransport(
        [Response(status=400, body='{"code":"INVALID_PATH","error":"plugin must not be blank when present"}')]
    )

    with pytest.raises(LoomweaveError, match="plugin must not be blank"):
        _client(t).resolve(["m.f"], plugin="rust")


def test_resolve_unhinted_4xx_stays_loud():
    # An unhinted 4xx cannot be hint-field version skew — it is a real request bug
    # and must stay diagnosable (the pre-existing INVALID_PATH pin, re-asserted
    # against the hint-conditional soft band).
    t = FakeTransport([Response(status=400, body='{"code":"INVALID_PATH"}')])
    with pytest.raises(LoomweaveError, match="INVALID_PATH"):
        _client(t).resolve(["m.f"])


def test_resolve_hinted_401_is_auth_rejection_not_unresolved(caplog):
    # Auth rejection (stale/wrong WEFT_FEDERATION_TOKEN, HMAC mismatch, clock skew) is
    # NOT hint-field version skew (an older deny_unknown_fields Loomweave 400s, never
    # 401s) and must never be misreported as "qualname unresolved" — the dogfood-#5 /
    # C-7 misdiagnosis class. Fail-soft with a DISTINCT signal, never silent.
    import logging

    t = FakeTransport([Response(status=401, body='{"code":"AUTH"}')])
    with caplog.at_level(logging.WARNING, logger="wardline.loomweave.client"):
        result = _client(t).resolve(["m.f", "m.g"], plugin="python")
    assert result is not None
    assert result.resolved == {}
    assert result.unresolved == []  # NOT reported as entity nonexistence
    assert result.auth_status == 401
    assert result.auth_rejected is True
    assert any("401" in rec.message for rec in caplog.records)  # a signal, never silent


def test_resolve_hinted_403_is_auth_rejection_not_unresolved():
    t = FakeTransport([Response(status=403, body='{"code":"FORBIDDEN"}')])
    result = _client(t).resolve(["m.f"], plugin="python")
    assert result is not None
    assert result.unresolved == []
    assert result.auth_status == 403
    assert result.auth_rejected is True


def test_resolve_hinted_auth_rejection_keeps_earlier_chunk_results():
    # Chunk 1 resolves; chunk 2 is auth-rejected mid-batch. What resolved before the
    # rejection is kept, and the rejected chunk is not smeared into `unresolved`.
    t = FakeTransport(
        [
            Response(status=200, body='{"resolved":{"a.b":"python:function:a.b"},"unresolved":["c.d"]}'),
            Response(status=401, body='{"code":"AUTH"}'),
        ]
    )
    result = _client(t, batch_max=2).resolve(["a.b", "c.d", "e.f", "g.h"], plugin="python")
    assert result is not None
    assert result.resolved == {"a.b": "python:function:a.b"}
    assert result.unresolved == ["c.d"]
    assert result.auth_status == 401


def test_resolve_auth_warning_counts_current_and_later_chunks(caplog):
    import logging

    t = FakeTransport(
        [
            Response(status=200, body='{"resolved":{},"unresolved":["a","b"]}'),
            Response(status=403, body='{"code":"FORBIDDEN"}'),
        ]
    )
    with caplog.at_level(logging.WARNING, logger="wardline.loomweave.client"):
        result = _client(t, batch_max=2).resolve(["a", "b", "c", "d", "e"])

    assert result is not None and result.auth_status == 403
    assert any("3 qualname(s) left unprobed" in record.message for record in caplog.records)


def test_resolve_default_has_no_auth_rejection():
    t = FakeTransport([Response(status=200, body='{"resolved":{},"unresolved":["m.f"]}')])
    result = _client(t).resolve(["m.f"], plugin="python")
    assert result.auth_status is None
    assert result.auth_rejected is False


@pytest.mark.parametrize("status", [401, 403])
def test_resolve_unhinted_auth_rejection_is_fail_soft_and_distinct(status: int):
    # Authentication and authorization failures are independent of the optional
    # plugin hint. An unhinted consumer must receive the same actionable signal as a
    # hinted one, never a loud exception or a fabricated unresolved identity.
    t = FakeTransport([Response(status=status, body='{"code":"AUTH"}')])

    result = _client(t).resolve(["m.f"])

    assert result is not None
    assert result.resolved == {}
    assert result.unresolved == []
    assert result.auth_status == status
    assert result.auth_rejected is True
