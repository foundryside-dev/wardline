"""WS-A2: FiligreeIssueFiler — fail-soft HTTP promote-by-fingerprint. Mirrors the
FiligreeEmitter test shape: an injectable transport, no live Filigree needed."""

from types import SimpleNamespace

import pytest

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_issue import (
    FileResult,
    FiligreeIssueFiler,
    IdentityAttachResult,
    Response,
    api_base_url_from_loom,
    attach_clarion_identity_for_finding,
    promote_url_from_loom,
)


class FakeTransport:
    def __init__(self, status, body):
        self._status, self._body = status, body
        self.last = None

    def post(self, url, body, headers):
        import json

        self.last = {"url": url, "body": json.loads(body.decode()), "headers": dict(headers)}
        return Response(status=self._status, body=self._body)


class RecordingTransport:
    def __init__(self, status=201, body='{"ok": true}'):
        self._status = status
        self._body = body
        self.calls = []

    def post(self, url, body, headers):
        import json

        self.calls.append({"url": url, "body": json.loads(body.decode()), "headers": dict(headers)})
        return Response(status=self._status, body=self._body)


def test_promote_url_derived_from_scan_results_url():
    assert promote_url_from_loom("http://h:8628/api/loom/scan-results") == "http://h:8628/api/loom/findings/promote"


def test_api_base_url_derived_from_scan_results_url():
    assert api_base_url_from_loom("http://h:8628/api/loom/scan-results") == "http://h:8628/api"


def test_promote_url_rejects_non_loom_url():
    with pytest.raises(FiligreeEmitError, match="/api/loom/"):
        promote_url_from_loom("http://h/api/something/else")


def test_file_returns_issue_id_on_200():
    t = FakeTransport(200, '{"issue_id": "wardline-abc", "created": true}')
    filer = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=t)
    res = filer.file("fp123", priority="P2")
    assert res == FileResult(reachable=True, issue_id="wardline-abc", created=True)
    # The request carried the fingerprint + scan_source to the promote route.
    assert t.last["url"].endswith("/api/loom/findings/promote")
    assert t.last["body"] == {"scan_source": "wardline", "fingerprint": "fp123", "priority": "P2"}


def test_file_already_linked_created_false():
    t = FakeTransport(200, '{"issue_id": "wardline-abc", "created": false}')
    res = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=t).file("fp123")
    assert res.reachable and res.issue_id == "wardline-abc" and res.created is False


def test_file_404_unknown_fingerprint_is_reachable_not_found():
    t = FakeTransport(404, '{"error": "no finding", "code": "NOT_FOUND"}')
    res = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=t).file("missing")
    assert res.reachable is True and res.issue_id is None and res.not_found is True


def test_file_unreachable_is_soft():
    import urllib.error

    class Down:
        def post(self, url, body, headers):
            raise urllib.error.URLError("refused")

    res = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=Down()).file("fp")
    assert res.reachable is False and res.issue_id is None


def test_file_5xx_is_soft():
    res = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=FakeTransport(503, "")).file("fp")
    assert res.reachable is False


def test_file_4xx_other_than_404_is_loud():
    # A 400 means Wardline sent a bad payload — loud, like the emitter's 4xx.
    t = FakeTransport(400, "bad request")
    with pytest.raises(FiligreeEmitError):
        FiligreeIssueFiler("http://h/api/loom/scan-results", transport=t).file("fp")


def test_urllib_transport_bounds_http_error_body(monkeypatch):
    import io
    import urllib.error
    import urllib.request

    from wardline.core.filigree_issue import UrllibTransport
    from wardline.core.http import MAX_RESPONSE_BODY_BYTES

    def _raise(req, timeout=None):
        raise urllib.error.HTTPError(
            "http://h/api/loom/findings/promote",
            400,
            "Bad Request",
            {},
            io.BytesIO(b"x" * (MAX_RESPONSE_BODY_BYTES + 9)),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    resp = UrllibTransport().post("http://h/api/loom/findings/promote", b"{}", {})
    assert len(resp.body) < MAX_RESPONSE_BODY_BYTES + 128
    assert resp.body.endswith("[truncated]")


def test_file_2xx_non_json_body_does_not_crash():
    # A 2xx with an unparseable body: accepted but unreadable — no issue id, never crash.
    t = FakeTransport(200, "not json")
    res = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=t).file("fp")
    assert res.reachable is True and res.issue_id is None and res.created is False


def test_file_2xx_json_non_dict_body_does_not_crash():
    # A 2xx whose JSON is valid but not an object (e.g. a list): no fields to read.
    t = FakeTransport(200, "[]")
    res = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=t).file("fp")
    assert res.reachable is True and res.issue_id is None and res.created is False


class FakeFinding:
    def __init__(self, qualname):
        self.qualname = qualname


class SeiClarion:
    def capabilities(self):
        return {"sei": {"supported": True, "version": 1}}

    def resolve_identity(self, locator):
        return {
            "alive": True,
            "sei": "clarion:eid:abc",
            "current_locator": locator,
            "content_hash": "hash-v1",
        }

    def resolve_sei(self, sei):
        return {"alive": True}


class DownClarion:
    def capabilities(self):
        return None

    def resolve(self, qualnames):
        return None


class LegacyClarion:
    def capabilities(self):
        return None

    def resolve(self, qualnames):
        return SimpleNamespace(resolved={qualnames[0]: "python:function:pkg.mod.leaky"}, unresolved=[])

    def get_taint_fact(self, qualname):
        return SimpleNamespace(current_content_hash="legacy-hash")


def test_attach_clarion_identity_attaches_resolved_sei(monkeypatch, tmp_path):
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: FakeFinding("pkg.mod.leaky"))
    transport = RecordingTransport()
    filer = FiligreeIssueFiler("http://f/api/loom/scan-results", transport=transport)

    res = attach_clarion_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        clarion_client=SeiClarion(),
    )

    assert res == IdentityAttachResult.success(
        entity_id="clarion:eid:abc",
        content_hash="hash-v1",
        binding_kind="sei",
    )
    assert transport.calls == [
        {
            "url": "http://f/api/issue/wardline-1/entity-associations",
            "body": {
                "entity_id": "clarion:eid:abc",
                "content_hash": "hash-v1",
                "actor": "wardline",
                "entity_kind": "python:function",
            },
            "headers": {"Content-Type": "application/json"},
        }
    ]


def test_attach_clarion_identity_reports_missing_qualname(monkeypatch, tmp_path):
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: FakeFinding(None))
    filer = FiligreeIssueFiler("http://f/api/loom/scan-results", transport=RecordingTransport())

    res = attach_clarion_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        clarion_client=SeiClarion(),
    )

    assert res.attempted is True
    assert res.attached is False
    assert res.reason == "finding has no qualname"


def test_attach_clarion_identity_reports_unavailable_clarion(monkeypatch, tmp_path):
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: FakeFinding("pkg.mod.leaky"))
    filer = FiligreeIssueFiler("http://f/api/loom/scan-results", transport=RecordingTransport())

    res = attach_clarion_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        clarion_client=DownClarion(),
    )

    assert res.attempted is True
    assert res.attached is False
    assert res.binding_kind == "locator"
    assert res.reason == "Clarion unavailable while resolving legacy locator"


def test_attach_clarion_identity_can_attach_legacy_locator_with_hash(monkeypatch, tmp_path):
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: FakeFinding("pkg.mod.leaky"))
    transport = RecordingTransport()
    filer = FiligreeIssueFiler("http://f/api/loom/scan-results", transport=transport)

    res = attach_clarion_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        clarion_client=LegacyClarion(),
    )

    assert res == IdentityAttachResult.success(
        entity_id="python:function:pkg.mod.leaky",
        content_hash="legacy-hash",
        binding_kind="locator",
    )
    assert transport.calls[0]["body"]["entity_id"] == "python:function:pkg.mod.leaky"
    assert transport.calls[0]["body"]["content_hash"] == "legacy-hash"


def test_attach_clarion_identity_reports_association_failure(monkeypatch, tmp_path):
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: FakeFinding("pkg.mod.leaky"))
    filer = FiligreeIssueFiler("http://f/api/loom/scan-results", transport=RecordingTransport(status=500, body="down"))

    res = attach_clarion_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        clarion_client=SeiClarion(),
    )

    assert res.attempted is True
    assert res.attached is False
    assert res.entity_id == "clarion:eid:abc"
    assert res.reason == "filigree association returned HTTP 500"
