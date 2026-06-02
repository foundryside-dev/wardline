"""WS-A2: MCP file_finding tool — fail-soft, returns the issue id."""

import pytest

from wardline.core.filigree_issue import FileResult
from wardline.mcp.server import ToolError, WardlineMCPServer, _file_finding


class FakeFiler:
    def __init__(self, result):
        self._result = result
        self.seen = None

    def file(self, fingerprint, *, scan_source="wardline", priority=None, labels=None):
        self.seen = {"fingerprint": fingerprint, "priority": priority, "labels": labels}
        return self._result


def test_file_finding_returns_issue_id(tmp_path):
    out = _file_finding(
        {"fingerprint": "fp1", "priority": "P2"},
        tmp_path,
        FakeFiler(FileResult(reachable=True, issue_id="wardline-abc", created=True)),
    )
    assert out == {
        "reachable": True,
        "issue_id": "wardline-abc",
        "created": True,
        "not_found": False,
        "fingerprint": "fp1",
        "disabled_reason": None,
    }


def test_file_finding_requires_fingerprint(tmp_path):
    with pytest.raises(ToolError, match="fingerprint is required"):
        _file_finding({}, tmp_path, FakeFiler(FileResult(reachable=True)))


def test_file_finding_no_filer_is_toolerror(tmp_path):
    # No Filigree URL configured -> agent-actionable.
    with pytest.raises(ToolError, match="no Filigree URL"):
        _file_finding({"fingerprint": "fp1"}, tmp_path, None)


def test_file_finding_not_found_surfaces(tmp_path):
    out = _file_finding({"fingerprint": "ghost"}, tmp_path, FakeFiler(FileResult(reachable=True, not_found=True)))
    assert out["not_found"] is True and out["issue_id"] is None


def test_server_filer_none_without_url(tmp_path):
    assert WardlineMCPServer(root=tmp_path)._filigree_filer() is None


def test_server_filer_built_with_url(tmp_path):
    from wardline.core.filigree_issue import FiligreeIssueFiler

    srv = WardlineMCPServer(root=tmp_path, filigree_url="http://h/api/loom/scan-results")
    assert isinstance(srv._filigree_filer(), FiligreeIssueFiler)
