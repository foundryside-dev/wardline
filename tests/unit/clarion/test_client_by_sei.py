"""T3.4 — ClarionClient.batch_get_by_sei (POST /api/wardline/taint-facts/by-sei).

The rename-stable READ surface: a fact written under a former locator is retrievable
by its stable opaque SEI. Thin HMAC-gated wrapper; fail-soft on every non-happy band
(outage/5xx -> soft via ``_send``; 403 PROJECT_MISMATCH -> None; route-absent 404 /
4xx -> loud ClarionError, mirroring batch_get). The SEI is OPAQUE — sent verbatim in
the body, never parsed.
"""

import json

import pytest

from wardline.clarion._hmac import sign_request
from wardline.clarion.client import ClarionClient, Response
from wardline.core.errors import ClarionError


class FakeTransport:
    def __init__(self, responses=None):
        self.calls = []
        self._responses = list(responses or [])

    def request(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))
        if self._responses:
            return self._responses.pop(0)
        return Response(status=200, body="[]")


def _client(transport, *, batch_max=2000):
    return ClarionClient(
        "http://clarion.example", secret="s3cr3t", project="proj", transport=transport, batch_max=batch_max
    )


_SEI = "clarion:eid:deadbeefcafef00ddeadbeefcafef00d"
_BODY = json.dumps(
    [
        {
            "sei": _SEI,
            "wardline_json": {"schema_version": "wardline-taint-1", "taint": {"actual_return": "EXTERNAL_RAW"}},
            "current_content_hash": "abc123",
            "exists": True,
        }
    ]
)


def test_batch_get_by_sei_parses_views_and_signs():
    t = FakeTransport([Response(status=200, body=_BODY)])
    views = _client(t).batch_get_by_sei([_SEI])
    assert views is not None
    assert len(views) == 1
    v = views[0]
    assert v.sei == _SEI
    assert v.exists is True
    assert v.current_content_hash == "abc123"
    assert v.wardline_json["taint"]["actual_return"] == "EXTERNAL_RAW"
    method, url, body, headers = t.calls[0]
    assert method == "POST"
    assert url == "http://clarion.example/api/wardline/taint-facts/by-sei"
    # the SEI is carried verbatim in the JSON body, opaque
    assert json.loads(body) == {"project": "proj", "seis": [_SEI]}
    paq = "/api/wardline/taint-facts/by-sei"
    assert headers["X-Loom-Component"] == f"clarion:{sign_request('s3cr3t', 'POST', paq, body)}"


def test_batch_get_by_sei_unknown_sei_is_exists_false():
    body = json.dumps([{"sei": "clarion:eid:nope", "exists": False}])
    views = _client(FakeTransport([Response(status=200, body=body)])).batch_get_by_sei(["clarion:eid:nope"])
    assert views is not None and len(views) == 1
    assert views[0].sei == "clarion:eid:nope"
    assert views[0].exists is False
    assert views[0].wardline_json is None
    assert views[0].current_content_hash is None


def test_batch_get_by_sei_outage_is_soft_none():
    # _send returns None on a 5xx -> soft outage -> None, never raises.
    views = _client(FakeTransport([Response(status=503, body="")])).batch_get_by_sei([_SEI])
    assert views is None


def test_batch_get_by_sei_project_mismatch_is_soft_none():
    views = _client(FakeTransport([Response(status=403, body='{"code":"PROJECT_MISMATCH"}')])).batch_get_by_sei([_SEI])
    assert views is None


def test_batch_get_by_sei_route_absent_is_loud():
    # A 404 (older SEI Clarion lacks the route) is a loud read-skew, like batch_get's 4xx.
    t = FakeTransport([Response(status=404, body='{"code":"NOT_FOUND"}')])
    with pytest.raises(ClarionError):
        _client(t).batch_get_by_sei([_SEI])


def test_batch_get_by_sei_chunks_large_input():
    # Two chunks at batch_max=1 -> two POSTs, views concatenated in order.
    r1 = json.dumps([{"sei": "clarion:eid:a", "exists": False}])
    r2 = json.dumps([{"sei": "clarion:eid:b", "exists": False}])
    t = FakeTransport([Response(status=200, body=r1), Response(status=200, body=r2)])
    views = _client(t, batch_max=1).batch_get_by_sei(["clarion:eid:a", "clarion:eid:b"])
    assert views is not None
    assert [v.sei for v in views] == ["clarion:eid:a", "clarion:eid:b"]
    assert len(t.calls) == 2


def test_batch_get_by_sei_malformed_200_body_is_empty():
    # A 2xx with a non-JSON body degrades to [] (defensive: a Clarion bug, not ours),
    # never raises — mirrors batch_get's tolerance of a malformed-but-2xx response.
    t = FakeTransport([Response(status=200, body="not json")])
    assert _client(t).batch_get_by_sei([_SEI]) == []


def test_batch_get_by_sei_empty_input_no_call():
    t = FakeTransport([])
    assert _client(t).batch_get_by_sei([]) == []
    assert t.calls == []


class RenameStateTransport:
    """A content-routing double that models Clarion's store across a rename, so the
    SEI is genuinely the bridge (not a queued-by-position outcome): the stored fact is
    keyed ONLY by its stable SEI ``stored_sei`` and was written under the OLD qualname.
    A by-qualname read matches on the request's qualname (the renamed entity is absent);
    a by-SEI read matches on the request's SEI. A request carrying the wrong key — e.g.
    a by-SEI call that sent a qualname, or the renamed qualname — correctly misses."""

    def __init__(self, *, stored_sei: str, old_qualname: str):
        self._stored_sei = stored_sei
        self._old_qualname = old_qualname
        self.calls: list[tuple[str, str, bytes]] = []

    def request(self, method, url, body, headers):
        self.calls.append((method, url, body))
        payload = json.loads(body)
        if url.endswith("/api/wardline/taint-facts/by-sei"):
            rows = [
                {"sei": s, "exists": True, "wardline_json": {"taint": {"actual_return": "EXTERNAL_RAW"}}}
                if s == self._stored_sei
                else {"sei": s, "exists": False}
                for s in payload["seis"]
            ]
        else:  # :batch-get keyed by qualname — the fact lives under the OLD qualname only
            rows = [{"qualname": q, "exists": q == self._old_qualname} for q in payload["qualnames"]]
        return Response(status=200, body=json.dumps(rows))


def test_fact_survives_a_rename_via_sei():
    """The T3.4 DoD oracle, deterministic half: a fact written under the old qualname is
    retrievable by its stable SEI S after the entity is renamed.

    The store double keys the fact by S alone. Reading the RENAMED qualname misses
    (the fact was never written there); reading by S returns it — and because the
    transport routes on request CONTENT, this would fail if ``batch_get_by_sei`` sent
    the wrong key or hit the wrong route. (The live binding-flip leg is Clarion's own
    oracle; here the SEI provably does the bridging.)"""
    t = RenameStateTransport(stored_sei=_SEI, old_qualname="svc.original")
    client = _client(t)

    # by the NEW (renamed) qualname -> honest miss: nothing was written under it
    by_locator = client.batch_get(["svc.renamed"])
    assert by_locator is not None and by_locator[0].exists is False

    # by the STABLE SEI -> the original fact survives the rename (the SEI is the key)
    by_sei = client.batch_get_by_sei([_SEI])
    assert by_sei is not None and by_sei[0].exists is True
    assert by_sei[0].wardline_json["taint"]["actual_return"] == "EXTERNAL_RAW"

    # control: a by-SEI read of a DIFFERENT SEI misses — proves matching is on the SEI,
    # not an unconditional "first row wins"
    other = client.batch_get_by_sei(["clarion:eid:something-else"])
    assert other is not None and other[0].exists is False
