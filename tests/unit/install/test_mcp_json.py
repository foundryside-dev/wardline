import json
from pathlib import Path

import pytest

from wardline.core.errors import WardlineError
from wardline.install.mcp_json import merge_mcp_entry

_WARDLINE_ENTRY = {"type": "stdio", "command": "wardline", "args": ["mcp", "--root", "."]}


def test_create_when_absent(tmp_path: Path) -> None:
    assert merge_mcp_entry(tmp_path) == "created"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["wardline"] == _WARDLINE_ENTRY


def test_merge_preserves_siblings(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"filigree": {"type": "stdio", "command": "filigree-mcp", "args": []}}}),
        encoding="utf-8",
    )
    assert merge_mcp_entry(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["filigree"]["command"] == "filigree-mcp"
    assert data["mcpServers"]["wardline"] == _WARDLINE_ENTRY


def test_idempotent_when_entry_matches(tmp_path: Path) -> None:
    merge_mcp_entry(tmp_path)
    assert merge_mcp_entry(tmp_path) == "unchanged"


def test_malformed_json_raises_without_clobbering(tmp_path: Path) -> None:
    bad = tmp_path / ".mcp.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(WardlineError):
        merge_mcp_entry(tmp_path)
    assert bad.read_text(encoding="utf-8") == "{not json"


def test_mcpservers_non_dict_raises(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": []}), encoding="utf-8"
    )
    with pytest.raises(WardlineError):
        merge_mcp_entry(tmp_path)


def test_mcpservers_null_is_treated_as_absent(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": None, "other": 1}), encoding="utf-8"
    )
    assert merge_mcp_entry(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["wardline"] == _WARDLINE_ENTRY
    assert data["other"] == 1  # unrelated top-level keys preserved


def test_replaces_stale_wardline_entry(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"wardline": {"type": "stdio", "command": "OLD", "args": []}}}),
        encoding="utf-8",
    )
    assert merge_mcp_entry(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["wardline"] == _WARDLINE_ENTRY  # stale entry replaced
