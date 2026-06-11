"""WS-A2: FiligreeIssueFiler — fail-soft HTTP promote-by-fingerprint. Mirrors the
FiligreeEmitter test shape: an injectable transport, no live Filigree needed."""

from types import SimpleNamespace

import pytest

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_emit import build_scan_results_body
from wardline.core.filigree_issue import (
    FileResult,
    FiligreeIssueFiler,
    IdentityAttachResult,
    Response,
    api_base_url_from_weft,
    attach_loomweave_identity_for_finding,
    build_promote_body,
    promote_url_from_weft,
)
from wardline.core.finding import Finding, Kind, Location, Severity


def test_promote_wire_fingerprint_matches_ingest_wire() -> None:
    # The promote join key MUST equal the value scan-results ingested, or Filigree's
    # exact-match lookup 404s against the finding it just stored. Lock the two wires
    # symmetric: both carry the scheme-prefixed form for the same bare fingerprint.
    f = Finding(
        rule_id="PY-WL-101",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="svc.py", line_start=1),
        fingerprint="a" * 64,
    )
    ingested = build_scan_results_body([f])["findings"][0]["fingerprint"]
    promoted = build_promote_body(fingerprint=f.fingerprint)["fingerprint"]
    assert promoted == ingested == "wlfp2:" + "a" * 64


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
    assert promote_url_from_weft("http://h:8628/api/weft/scan-results") == "http://h:8628/api/weft/findings/promote"


def test_api_base_url_derived_from_scan_results_url():
    assert api_base_url_from_weft("http://h:8628/api/weft/scan-results") == "http://h:8628/api"


def test_promote_url_rejects_non_weft_url():
    with pytest.raises(FiligreeEmitError, match="/api/weft/"):
        promote_url_from_weft("http://h/api/something/else")


def test_file_returns_issue_id_on_200():
    t = FakeTransport(200, '{"issue_id": "wardline-abc", "created": true}')
    filer = FiligreeIssueFiler("http://h/api/weft/scan-results", transport=t)
    res = filer.file("fp123", priority="P2")
    assert res == FileResult(reachable=True, issue_id="wardline-abc", created=True)
    # The request carried the fingerprint + scan_source to the promote route. The wire
    # value is scheme-PREFIXED (symmetric with the ingest wire) so the promote join
    # matches what scan-results stored; the caller passed the bare in-memory value.
    assert t.last["url"].endswith("/api/weft/findings/promote")
    assert t.last["body"] == {"scan_source": "wardline", "fingerprint": "wlfp2:fp123", "priority": "P2"}


def test_file_already_linked_created_false():
    t = FakeTransport(200, '{"issue_id": "wardline-abc", "created": false}')
    res = FiligreeIssueFiler("http://h/api/weft/scan-results", transport=t).file("fp123")
    assert res.reachable and res.issue_id == "wardline-abc" and res.created is False


def test_file_404_unknown_fingerprint_is_reachable_not_found():
    t = FakeTransport(404, '{"error": "no finding", "code": "NOT_FOUND"}')
    res = FiligreeIssueFiler("http://h/api/weft/scan-results", transport=t).file("missing")
    assert res.reachable is True and res.issue_id is None and res.not_found is True


def test_file_unreachable_is_soft():
    import urllib.error

    class Down:
        def post(self, url, body, headers):
            raise urllib.error.URLError("refused")

    res = FiligreeIssueFiler("http://h/api/weft/scan-results", transport=Down()).file("fp")
    assert res.reachable is False and res.issue_id is None


def test_file_5xx_is_soft():
    res = FiligreeIssueFiler("http://h/api/weft/scan-results", transport=FakeTransport(503, "")).file("fp")
    assert res.reachable is False


def test_file_4xx_other_than_404_is_loud():
    # A 400 means Wardline sent a bad payload — loud, like the emitter's 4xx.
    t = FakeTransport(400, "bad request")
    with pytest.raises(FiligreeEmitError):
        FiligreeIssueFiler("http://h/api/weft/scan-results", transport=t).file("fp")


@pytest.mark.parametrize("status", [401, 403])
def test_file_auth_refused_is_soft(status):
    # Filigree's opt-in bearer auth is on and refusing us (401/403): enrichment
    # unavailable, like a 5xx outage — soft (reachable=False), never loud.
    res = FiligreeIssueFiler("http://h/api/weft/scan-results", transport=FakeTransport(status, "")).file("fp")
    assert res.reachable is False and res.disabled_reason == f"filigree {status}"


def test_file_carries_bearer_token_when_provided():
    t = FakeTransport(200, '{"issue_id": "wardline-abc", "created": true}')
    FiligreeIssueFiler("http://h/api/weft/scan-results", transport=t, token="sekret").file("fp")
    assert t.last["headers"]["Authorization"] == "Bearer sekret"


def test_file_sends_no_authorization_header_when_no_token():
    t = FakeTransport(200, '{"issue_id": "wardline-abc", "created": true}')
    FiligreeIssueFiler("http://h/api/weft/scan-results", transport=t).file("fp")
    assert "Authorization" not in t.last["headers"]


def test_urllib_transport_bounds_http_error_body(monkeypatch):
    import io
    import urllib.error
    import urllib.request

    from wardline.core.filigree_issue import UrllibTransport
    from wardline.core.http import MAX_RESPONSE_BODY_BYTES

    def _raise(req, timeout=None):
        raise urllib.error.HTTPError(
            "http://h/api/weft/findings/promote",
            400,
            "Bad Request",
            {},
            io.BytesIO(b"x" * (MAX_RESPONSE_BODY_BYTES + 9)),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    resp = UrllibTransport().post("http://h/api/weft/findings/promote", b"{}", {})
    assert len(resp.body) < MAX_RESPONSE_BODY_BYTES + 128
    assert resp.body.endswith("[truncated]")


def test_file_2xx_non_json_body_does_not_crash():
    # A 2xx with an unparseable body: accepted but unreadable — no issue id, never crash.
    t = FakeTransport(200, "not json")
    res = FiligreeIssueFiler("http://h/api/weft/scan-results", transport=t).file("fp")
    assert res.reachable is True and res.issue_id is None and res.created is False


def test_file_2xx_json_non_dict_body_does_not_crash():
    # A 2xx whose JSON is valid but not an object (e.g. a list): no fields to read.
    t = FakeTransport(200, "[]")
    res = FiligreeIssueFiler("http://h/api/weft/scan-results", transport=t).file("fp")
    assert res.reachable is True and res.issue_id is None and res.created is False


class FakeFinding:
    def __init__(self, qualname):
        self.qualname = qualname


class SeiLoomweave:
    def capabilities(self):
        return {"sei": {"supported": True, "version": 1}}

    def resolve_identity(self, locator):
        return {
            "alive": True,
            "sei": "loomweave:eid:abc",
            "current_locator": locator,
            "content_hash": "hash-v1",
        }

    def resolve_sei(self, sei):
        return {"alive": True}


class DownLoomweave:
    def capabilities(self):
        return None

    def resolve(self, qualnames, *, plugin=None):
        self.plugin_hints = [*getattr(self, "plugin_hints", []), plugin]
        return None


class LegacyLoomweave:
    def capabilities(self):
        return None

    def resolve(self, qualnames, *, plugin=None):
        self.plugin_hints = [*getattr(self, "plugin_hints", []), plugin]
        return SimpleNamespace(resolved={qualnames[0]: "python:function:pkg.mod.leaky"}, unresolved=[])

    def get_taint_fact(self, qualname):
        return SimpleNamespace(current_content_hash="legacy-hash")


def test_attach_loomweave_identity_attaches_resolved_sei(monkeypatch, tmp_path):
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: FakeFinding("pkg.mod.leaky"))
    transport = RecordingTransport()
    filer = FiligreeIssueFiler("http://f/api/weft/scan-results", transport=transport)

    res = attach_loomweave_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        loomweave_client=SeiLoomweave(),
    )

    assert res == IdentityAttachResult.success(
        entity_id="loomweave:eid:abc",
        content_hash="hash-v1",
        binding_kind="sei",
    )
    assert transport.calls == [
        {
            "url": "http://f/api/issue/wardline-1/entity-associations",
            "body": {
                "entity_id": "loomweave:eid:abc",
                "content_hash": "hash-v1",
                "actor": "wardline",
                "entity_kind": "python:function",
            },
            "headers": {"Content-Type": "application/json"},
        }
    ]


def test_attach_loomweave_identity_reports_missing_qualname(monkeypatch, tmp_path):
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: FakeFinding(None))
    filer = FiligreeIssueFiler("http://f/api/weft/scan-results", transport=RecordingTransport())

    res = attach_loomweave_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        loomweave_client=SeiLoomweave(),
    )

    assert res.attempted is True
    assert res.attached is False
    assert res.reason == "finding has no qualname"


def test_attach_loomweave_identity_reports_unavailable_loomweave(monkeypatch, tmp_path):
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: FakeFinding("pkg.mod.leaky"))
    filer = FiligreeIssueFiler("http://f/api/weft/scan-results", transport=RecordingTransport())

    res = attach_loomweave_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        loomweave_client=DownLoomweave(),
    )

    assert res.attempted is True
    assert res.attached is False
    assert res.binding_kind == "locator"
    assert res.reason == "Loomweave unavailable while resolving legacy locator"


def test_attach_loomweave_identity_can_attach_legacy_locator_with_hash(monkeypatch, tmp_path):
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: FakeFinding("pkg.mod.leaky"))
    transport = RecordingTransport()
    filer = FiligreeIssueFiler("http://f/api/weft/scan-results", transport=transport)

    res = attach_loomweave_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        loomweave_client=LegacyLoomweave(),
    )

    assert res == IdentityAttachResult.success(
        entity_id="python:function:pkg.mod.leaky",
        content_hash="legacy-hash",
        binding_kind="locator",
    )
    assert transport.calls[0]["body"]["entity_id"] == "python:function:pkg.mod.leaky"
    assert transport.calls[0]["body"]["content_hash"] == "legacy-hash"


def test_attach_loomweave_identity_reports_association_failure(monkeypatch, tmp_path):
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: FakeFinding("pkg.mod.leaky"))
    filer = FiligreeIssueFiler("http://f/api/weft/scan-results", transport=RecordingTransport(status=500, body="down"))

    res = attach_loomweave_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        loomweave_client=SeiLoomweave(),
    )

    assert res.attempted is True
    assert res.attached is False
    assert res.entity_id == "loomweave:eid:abc"
    assert res.reason == "filigree association returned HTTP 500"


class RustFakeFinding:
    def __init__(self, qualname):
        self.qualname = qualname
        self.rule_id = "RS-WL-101"


def test_plugin_for_finding_discriminates_by_rule_family():
    from wardline.core.filigree_issue import plugin_for_finding

    assert plugin_for_finding(RustFakeFinding("demo.m.f")) == "rust"
    assert plugin_for_finding(FakeFinding("pkg.mod.leaky")) == "python"  # no rule_id attr -> python
    assert plugin_for_finding(SimpleNamespace(rule_id="PY-WL-101")) == "python"


def test_attach_threads_rust_plugin_through_locator_resolve_and_entity_kind(monkeypatch, tmp_path):
    # ADR-036 plugin hint, end to end on the Wardline side: a Rust finding mints a
    # rust: locator for the SEI hop, sends plugin="rust" on the legacy resolve hop,
    # and stamps the association entity_kind as rust:function.
    from wardline.core import filigree_issue as mod

    monkeypatch.setattr(mod, "_finding_for_fingerprint", lambda fp, root, cfg: RustFakeFinding("demo.m.leaky"))

    class RustLegacyLoomweave:
        def __init__(self):
            self.identity_locators = []
            self.plugin_hints = []

        def capabilities(self):
            return None  # pre-SEI -> the legacy locator path

        def resolve(self, qualnames, *, plugin=None):
            self.plugin_hints.append(plugin)
            return SimpleNamespace(resolved={qualnames[0]: "rust:function:demo.m.leaky"}, unresolved=[])

        def resolve_identity(self, locator):
            self.identity_locators.append(locator)
            return None

        def get_taint_fact(self, qualname):
            return SimpleNamespace(current_content_hash="rust-hash")

    client = RustLegacyLoomweave()
    transport = RecordingTransport()
    filer = FiligreeIssueFiler("http://f/api/weft/scan-results", transport=transport)

    res = attach_loomweave_identity_for_finding(
        fingerprint="fp1",
        issue_id="wardline-1",
        root=tmp_path,
        filer=filer,
        loomweave_client=client,
    )

    assert client.plugin_hints == ["rust"]
    assert res.attached is True
    assert transport.calls[0]["body"]["entity_id"] == "rust:function:demo.m.leaky"
    assert transport.calls[0]["body"]["entity_kind"] == "rust:function"


def test_file_2xx_non_string_issue_id_is_normalized_to_none():
    # Filigree's promote response is external input: a non-string issue_id (e.g. an
    # integer) must not flow verbatim into tool payloads that publish issue_id as
    # string|null in their MCP outputSchema — type-narrow at the wire boundary.
    t = FakeTransport(200, '{"issue_id": 123, "created": true}')
    res = FiligreeIssueFiler("http://h/api/weft/scan-results", transport=t).file("fp")
    assert res.reachable is True and res.issue_id is None and res.created is True
