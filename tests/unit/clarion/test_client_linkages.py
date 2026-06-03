"""T4.3 — ClarionClient call-graph linkage reads (GET /api/v1/entities/{id}/callers|callees).

Thin HMAC-gated wrappers; fail-soft on every non-happy band (outage/5xx → soft via
``_send``; 404 entity-unknown / route-absent / 4xx → None), mirroring the SEI read path.
"""

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


def _client(transport):
    return ClarionClient("http://clarion.example", secret="s3cr3t", project="proj", transport=transport)


_CALLERS_BODY = json.dumps(
    {
        "entity_id": "python:function:svc.leaky",
        "callers": [
            {"entity_id": "python:function:svc.caller_a", "confidence": "resolved", "call_site_count": 2},
            {"entity_id": "python:function:svc.caller_b", "confidence": "inferred", "call_site_count": 1},
        ],
        "total": 2,
        "truncated": False,
    }
)


def test_get_callers_parses_neighbours_and_signs():
    t = FakeTransport([Response(status=200, body=_CALLERS_BODY)])
    res = _client(t).get_callers("python:function:svc.leaky")
    assert res is not None
    assert res.neighbours == ("python:function:svc.caller_a", "python:function:svc.caller_b")
    assert res.total == 2
    assert res.truncated is False
    method, url, _, headers = t.calls[0]
    assert method == "GET"
    # the locator is URL-escaped into the path segment, never parsed
    assert url == "http://clarion.example/api/v1/entities/python%3Afunction%3Asvc.leaky/callers?limit=50"
    paq = "/api/v1/entities/python%3Afunction%3Asvc.leaky/callers?limit=50"
    expected = sign_request("s3cr3t", "GET", paq, b"", timestamp=headers["X-Wardline-Timestamp"])
    assert headers["X-Loom-Component"] == f"clarion:{expected}"


def test_get_callees_reads_the_callees_field():
    body = json.dumps(
        {
            "entity_id": "x",
            "callees": [{"entity_id": "python:function:svc.mid", "confidence": "resolved", "call_site_count": 1}],
            "total": 1,
            "truncated": True,
        }
    )
    res = _client(FakeTransport([Response(status=200, body=body)])).get_callees("x")
    assert res is not None
    assert res.neighbours == ("python:function:svc.mid",)
    assert res.truncated is True


def test_linkage_404_entity_unknown_is_soft_none():
    # entity not known to Clarion → 404 → honest None (caller degrades), never a crash
    t = FakeTransport([Response(status=404, body='{"code":"NOT_FOUND","error":"unknown"}')])
    assert _client(t).get_callers("python:function:missing") is None


def test_linkage_outage_is_soft_none():
    t = FakeTransport([Response(status=503, body="")])
    assert _client(t).get_callees("x") is None


def test_linkage_custom_limit_is_sent():
    t = FakeTransport([Response(status=200, body=_CALLERS_BODY)])
    _client(t).get_callers("x", limit=10)
    _, url, _, _ = t.calls[0]
    assert "limit=10" in url
