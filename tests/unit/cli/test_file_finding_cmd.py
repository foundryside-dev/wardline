"""WS-A2 CLI parity: `wardline file-finding <fp>` over an injected filer."""

import json

from click.testing import CliRunner

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_issue import FileResult, IdentityAttachResult


def test_file_finding_prints_issue_id(tmp_path, monkeypatch):
    from wardline.cli import file_finding as mod

    class FakeFiler:
        def __init__(self, url, **kw):
            pass

        def file(self, fingerprint, *, scan_source="wardline", priority=None, labels=None):
            return FileResult(reachable=True, issue_id="wardline-xyz", created=True)

    monkeypatch.setattr(mod, "FiligreeIssueFiler", FakeFiler)
    monkeypatch.setattr(mod, "resolve_filigree_url", lambda flag, root, cfg: "http://h/api/weft/scan-results")
    res = CliRunner().invoke(mod.file_finding, ["fp1", str(tmp_path)])
    assert res.exit_code == 0
    assert json.loads(res.output)["issue_id"] == "wardline-xyz"


def test_file_finding_no_url_exits_2(tmp_path, monkeypatch):
    from wardline.cli import file_finding as mod

    monkeypatch.setattr(mod, "resolve_filigree_url", lambda flag, root, cfg: None)
    res = CliRunner().invoke(mod.file_finding, ["fp1", str(tmp_path)])
    assert res.exit_code == 2
    assert "Filigree URL" in res.output


def test_file_finding_loud_4xx_exits_2_no_traceback(tmp_path, monkeypatch):
    # A loud FiligreeEmitError (4xx bad payload) must surface as a clean `error:` echo
    # + exit 2, NOT escape click as a raw traceback (which would be exit 1).
    from wardline.cli import file_finding as mod

    class FakeFiler:
        def __init__(self, url, **kw):
            pass

        def file(self, fingerprint, *, scan_source="wardline", priority=None, labels=None):
            raise FiligreeEmitError("Filigree rejected promote (400) at ...: bad payload")

    monkeypatch.setattr(mod, "FiligreeIssueFiler", FakeFiler)
    monkeypatch.setattr(mod, "resolve_filigree_url", lambda flag, root, cfg: "http://h/api/weft/scan-results")
    res = CliRunner().invoke(mod.file_finding, ["fp1", str(tmp_path)])
    assert res.exit_code == 2
    assert "error:" in res.output
    # No traceback leaked: the surfaced exception is the clean SystemExit, not the raw error.
    assert isinstance(res.exception, SystemExit)
    assert not isinstance(res.exception, FiligreeEmitError)


def test_file_finding_can_attach_loomweave_identity(tmp_path, monkeypatch):
    from wardline.cli import file_finding as mod

    class FakeFiler:
        def __init__(self, url, **kw):
            pass

        def file(self, fingerprint, *, scan_source="wardline", priority=None, labels=None):
            return FileResult(reachable=True, issue_id="wardline-xyz", created=True)

    monkeypatch.setattr(mod, "FiligreeIssueFiler", FakeFiler)
    monkeypatch.setattr(mod, "resolve_filigree_url", lambda flag, root, cfg: "http://h/api/weft/scan-results")
    monkeypatch.setattr(mod, "resolve_loomweave_url", lambda flag, root, cfg: "http://loomweave")
    seen = {}

    def fake_attach(**kw):
        seen.update(kw)
        return IdentityAttachResult.success(
            entity_id="loomweave:eid:abc",
            content_hash="hash-v1",
            binding_kind="sei",
        )

    monkeypatch.setattr(mod, "attach_loomweave_identity_for_finding", fake_attach)

    res = CliRunner().invoke(mod.file_finding, ["fp1", str(tmp_path), "--attach-loomweave-identity", "--lang", "rust"])

    assert res.exit_code == 0
    assert seen["lang"] == "rust"
    payload = json.loads(res.output)
    assert payload["issue_id"] == "wardline-xyz"
    assert payload["identity_attach"] == {
        "attempted": True,
        "attached": True,
        "entity_id": "loomweave:eid:abc",
        "content_hash": "hash-v1",
        "binding_kind": "sei",
        "reason": None,
    }
