"""CLI parity for the one-shot scan-file workflow."""

from __future__ import annotations

import json

from click.testing import CliRunner

from wardline.cli.main import cli


def test_scan_file_findings_cli_defaults_to_dry_run(tmp_path, monkeypatch):
    from wardline.cli import scan_file_findings as mod

    monkeypatch.setattr(
        mod,
        "scan_file_findings_core",
        lambda **kw: {"mode": "dry_run", "summary": {"active": 1}, "active_defects": [], "selected_count": 0},
    )
    monkeypatch.setattr(mod, "resolve_filigree_url", lambda *args, **kwargs: None)
    monkeypatch.setattr(mod, "resolve_clarion_url", lambda *args, **kwargs: None)

    res = CliRunner().invoke(cli, ["scan-file-findings", str(tmp_path)])

    assert res.exit_code == 0
    assert json.loads(res.output)["mode"] == "dry_run"


def test_scan_file_findings_cli_selected_fingerprint_wires_urls(tmp_path, monkeypatch):
    from wardline.cli import scan_file_findings as mod

    seen = {}

    def fake_workflow(**kw):
        seen.update(kw)
        return {"mode": "fingerprints", "summary": {"active": 1}, "active_defects": [], "selected_count": 1}

    monkeypatch.setattr(mod, "scan_file_findings_core", fake_workflow)
    monkeypatch.setattr(mod, "resolve_filigree_url", lambda *args, **kwargs: "http://f/api/loom/scan-results")
    monkeypatch.setattr(mod, "resolve_clarion_url", lambda *args, **kwargs: "http://c")
    monkeypatch.setattr(mod, "FiligreeEmitter", lambda url: ("emitter", url))
    monkeypatch.setattr(mod, "FiligreeIssueFiler", lambda url: ("filer", url))

    class FakeClarion:
        def __init__(self, url, *, secret, project):
            self.url = url

    monkeypatch.setattr(mod, "ClarionClient", FakeClarion)
    monkeypatch.setattr(mod, "load_clarion_token", lambda root: None)
    monkeypatch.setattr(mod, "resolve_project_name", lambda root: "proj")

    res = CliRunner().invoke(cli, ["scan-file-findings", str(tmp_path), "--fingerprint", "f" * 64])

    assert res.exit_code == 0
    assert seen["fingerprints"] == ("f" * 64,)
    assert seen["dry_run"] is False
    assert seen["filigree_emitter"] == ("emitter", "http://f/api/loom/scan-results")
    assert isinstance(seen["clarion_client"], FakeClarion)
