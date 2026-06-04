"""T4.3 — FiligreeWorkProvider: the dossier's open-work source.

Dep-free urllib read of ADR-029 entity-associations, keyed on the opaque SEI. Each
association's ``content_hash_at_attach`` is compared (same entity-body granularity as
Clarion's resolve) against the binding's current content hash to set per-ticket DRIFT
and the section's content axis. Fail-soft: an outage / no-SEI yields honest unavailable.
"""

from __future__ import annotations

import json

import pytest

from wardline.clarion.identity import ContentStatus, EntityBinding, IdentityStatus
from wardline.core.errors import FiligreeEmitError
from wardline.filigree.dossier_client import FiligreeWorkProvider, Response


class FakeTransport:
    def __init__(self, response=None, raise_exc=None):
        self.calls = []
        self._response = response
        self._raise = raise_exc

    def get(self, url, headers):
        self.calls.append((url, headers))
        if self._raise is not None:
            raise self._raise
        return self._response


def _rows(*rows):
    return json.dumps({"associations": list(rows)})


_BINDING = EntityBinding(
    locator="python:function:svc.leaky",
    sei="clarion:eid:abc",
    identity=IdentityStatus.ALIVE,
    content_hash="current-hash",
)


def test_associations_become_tickets_fresh_when_hash_matches() -> None:
    body = _rows(
        {"issue_id": "wardline-1", "clarion_entity_id": "clarion:eid:abc", "content_hash_at_attach": "current-hash"}
    )
    t = FakeTransport(Response(status=200, body=body))
    sec = FiligreeWorkProvider("http://filigree.example", transport=t).work(_BINDING)
    assert sec.available is True
    assert [tk.issue_id for tk in sec.tickets] == ["wardline-1"]
    assert sec.tickets[0].drift is False
    assert sec.identity_status is IdentityStatus.ALIVE
    assert sec.content_status is ContentStatus.FRESH
    # keyed on the opaque SEI, url-escaped, never parsed
    url = t.calls[0][0]
    assert "entity_id=clarion%3Aeid%3Aabc" in url
    assert url.startswith("http://filigree.example/api/entity-associations?")


def test_scan_results_url_is_normalized_to_api_origin_for_associations() -> None:
    t = FakeTransport(Response(status=200, body=_rows()))

    FiligreeWorkProvider("http://filigree.example/api/loom/scan-results", transport=t).work(_BINDING)

    assert t.calls[0][0].startswith("http://filigree.example/api/entity-associations?")


@pytest.mark.parametrize(
    "url",
    [
        "file://localhost/tmp/associations.json",
        "ftp://localhost/api",
        "localhost:8628/api",
    ],
)
def test_work_provider_rejects_non_http_urls(url: str) -> None:
    with pytest.raises(FiligreeEmitError, match="http or https"):
        FiligreeWorkProvider(url, transport=FakeTransport(Response(status=200, body=_rows())))


def test_drifted_association_is_flagged_per_ticket_and_section_stale() -> None:
    body = _rows(
        {"issue_id": "wardline-1", "content_hash_at_attach": "OLD-hash"},
        {"issue_id": "wardline-2", "content_hash_at_attach": "current-hash"},
    )
    sec = FiligreeWorkProvider("http://f", transport=FakeTransport(Response(status=200, body=body))).work(_BINDING)
    by_id = {tk.issue_id: tk for tk in sec.tickets}
    assert by_id["wardline-1"].drift is True
    assert by_id["wardline-2"].drift is False
    # any drift → section content axis STALE (identity stays ALIVE — axes independent)
    assert sec.content_status is ContentStatus.STALE
    assert sec.identity_status is IdentityStatus.ALIVE


def test_unknown_compare_is_unknown_not_fresh_when_binding_hash_absent() -> None:
    # binding has no current content hash → the compare is UNKNOWN, never FRESH
    # (surfacing FRESH would be a false-green: nothing was actually compared).
    binding = EntityBinding(locator="x", sei="clarion:eid:abc", identity=IdentityStatus.ALIVE, content_hash=None)
    body = _rows({"issue_id": "wardline-1", "content_hash_at_attach": "some-hash"})
    sec = FiligreeWorkProvider("http://f", transport=FakeTransport(Response(status=200, body=body))).work(binding)
    assert sec.available is True
    assert sec.tickets[0].drift is False  # bool axis: not provably stale
    assert sec.content_status is ContentStatus.UNKNOWN  # but honestly unknown, not FRESH


def test_unknown_compare_when_row_lacks_attach_hash() -> None:
    body = _rows({"issue_id": "wardline-1"})  # no content_hash_at_attach
    sec = FiligreeWorkProvider("http://f", transport=FakeTransport(Response(status=200, body=body))).work(_BINDING)
    assert sec.content_status is ContentStatus.UNKNOWN


def test_no_sei_is_honest_unavailable_without_a_wire_call() -> None:
    t = FakeTransport(Response(status=200, body=_rows()))
    binding = EntityBinding(locator="svc.leaky")  # no SEI
    sec = FiligreeWorkProvider("http://f", transport=t).work(binding)
    assert sec.available is False
    assert "sei" in (sec.reason or "").lower()
    assert t.calls == []  # never queried — cannot key associations without a SEI


def test_outage_is_honest_unavailable() -> None:
    sec = FiligreeWorkProvider("http://f", transport=FakeTransport(Response(status=503, body=""))).work(_BINDING)
    assert sec.available is False
    assert sec.reason is not None


def test_transport_error_is_honest_unavailable() -> None:
    sec = FiligreeWorkProvider("http://f", transport=FakeTransport(raise_exc=OSError("connection refused"))).work(
        _BINDING
    )
    assert sec.available is False
    assert sec.reason is not None


def test_empty_associations_is_available_and_clean() -> None:
    # the entity is known to have NO open work — that is a real, available answer,
    # distinct from "filigree unavailable"
    sec = FiligreeWorkProvider("http://f", transport=FakeTransport(Response(status=200, body=_rows()))).work(_BINDING)
    assert sec.available is True
    assert sec.tickets == []
    assert sec.content_status is ContentStatus.FRESH


def test_bare_list_body_is_also_accepted() -> None:
    body = json.dumps([{"issue_id": "wardline-9", "content_hash_at_attach": "current-hash"}])
    sec = FiligreeWorkProvider("http://f", transport=FakeTransport(Response(status=200, body=body))).work(_BINDING)
    assert [tk.issue_id for tk in sec.tickets] == ["wardline-9"]


def test_non_json_body_is_honest_unavailable() -> None:
    sec = FiligreeWorkProvider("http://f", transport=FakeTransport(Response(status=200, body="<html>nope"))).work(
        _BINDING
    )
    assert sec.available is False
    assert "non-JSON" in (sec.reason or "")


def test_unexpected_envelope_shape_yields_no_tickets_not_a_crash() -> None:
    # a body that is neither a list nor a recognised dict → honest empty (available),
    # never a crash on an unexpected Filigree envelope
    sec = FiligreeWorkProvider("http://f", transport=FakeTransport(Response(status=200, body="42"))).work(_BINDING)
    assert sec.available is True
    assert sec.tickets == []


def test_rows_without_issue_id_are_skipped_and_detail_fields_carried() -> None:
    body = _rows(
        {"content_hash_at_attach": "current-hash"},  # no issue_id → skipped
        {
            "issue_id": "wardline-3",
            "content_hash_at_attach": "current-hash",
            "status": "open",
            "priority": "P1",
            "title": "fix the leak",
        },
    )
    sec = FiligreeWorkProvider("http://f", transport=FakeTransport(Response(status=200, body=body))).work(_BINDING)
    assert [tk.issue_id for tk in sec.tickets] == ["wardline-3"]
    tk = sec.tickets[0]
    assert (tk.status, tk.priority, tk.title) == ("open", "P1", "fix the leak")


def test_urllib_transport_get_round_trips(monkeypatch) -> None:
    # exercise the real stdlib transport (mirrors the filigree_emit UrllibTransport test)
    import io
    import urllib.request

    from wardline.filigree.dossier_client import UrllibTransport

    class _Resp(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.close()

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _Resp(b'{"associations": []}'))
    resp = UrllibTransport().get("http://filigree.example/api/entity-associations?entity_id=x", {})
    assert resp.status == 200
    assert resp.body == '{"associations": []}'


def test_urllib_transport_get_surfaces_http_error_status(monkeypatch) -> None:
    # an HTTP 4xx/5xx must be converted to a Response with the status (mirrors
    # clarion's transport), NOT raised as an outage — so work() classifies it by band.
    import io
    import urllib.error
    import urllib.request

    from wardline.filigree.dossier_client import UrllibTransport

    def _raise(req, timeout=None):
        raise urllib.error.HTTPError("http://f", 503, "Service Unavailable", {}, io.BytesIO(b"down"))

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    resp = UrllibTransport().get("http://f/api/entity-associations?entity_id=x", {})
    assert resp.status == 503


def test_urllib_transport_get_bounds_http_error_body(monkeypatch) -> None:
    import io
    import urllib.error
    import urllib.request

    from wardline.core.http import MAX_RESPONSE_BODY_BYTES
    from wardline.filigree.dossier_client import UrllibTransport

    def _raise(req, timeout=None):
        raise urllib.error.HTTPError(
            "http://f",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(b"x" * (MAX_RESPONSE_BODY_BYTES + 9)),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    resp = UrllibTransport().get("http://f/api/entity-associations?entity_id=x", {})
    assert len(resp.body) < MAX_RESPONSE_BODY_BYTES + 128
    assert resp.body.endswith("[truncated]")
