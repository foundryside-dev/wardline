"""MCP one-shot scan_file_findings workflow."""

from __future__ import annotations

import pytest

from wardline.mcp.server import ToolError, _scan_file_findings


def test_scan_file_findings_defaults_to_dry_run(tmp_path, monkeypatch):
    from wardline.core import scan_file_workflow as mod

    monkeypatch.setattr(
        mod,
        "scan_file_findings",
        lambda **kw: {"mode": "dry_run", "summary": {"active": 1}, "active_defects": [], "selected_count": 0},
    )

    out = _scan_file_findings({}, tmp_path)

    assert out["mode"] == "dry_run"


def test_scan_file_findings_rejects_bad_fingerprints(tmp_path):
    with pytest.raises(ToolError, match="fingerprints must be an array of strings"):
        _scan_file_findings({"fingerprints": "not-a-list"}, tmp_path)


def test_scan_file_findings_selected_wires_dependencies(tmp_path, monkeypatch):
    from wardline.core import scan_file_workflow as mod

    seen = {}

    def fake_workflow(**kw):
        seen.update(kw)
        return {"mode": "fingerprints", "summary": {"active": 1}, "active_defects": [], "selected_count": 1}

    monkeypatch.setattr(mod, "scan_file_findings", fake_workflow)

    out = _scan_file_findings(
        {"fingerprints": ["f" * 64], "priority": "P2", "labels": ["x"]},
        tmp_path,
        filigree_emitter=object(),
        filigree_filer=object(),
        clarion=object(),
    )

    assert out["mode"] == "fingerprints"
    assert seen["fingerprints"] == ("f" * 64,)
    assert seen["dry_run"] is False
    assert seen["priority"] == "P2"
    assert seen["labels"] == ("x",)
