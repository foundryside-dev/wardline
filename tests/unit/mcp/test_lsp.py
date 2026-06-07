from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from wardline.core.errors import ConfigError
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.run import ScanResult, ScanSummary
from wardline.lsp import LspServer


class MockBytesIO(io.BytesIO):
    """A helper class to mock the raw binary stdin/stdout streams."""

    def read(self, size: int = -1) -> bytes:
        return super().read(size)


def _lsp_messages(output: str) -> list[dict]:
    messages = []
    for part in output.split("Content-Length:"):
        if not part.strip():
            continue
        subparts = part.split("\r\n\r\n", 1)
        if len(subparts) == 2:
            messages.append(json.loads(subparts[1]))
    return messages


def _frame(body: str) -> str:
    return f"Content-Length: {len(body)}\r\n\r\n{body}"


def test_lsp_handshake() -> None:
    req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"rootUri": "file:///my/project"}}
    body = json.dumps(req)
    raw_input = f"Content-Length: {len(body)}\r\n\r\n{body}"

    stdin = io.StringIO(raw_input)
    stdout = io.StringIO()

    # We patch buffer to handle text streams if needed, or we just pass stdin/stdout
    server = LspServer(root=Path("/my/project"), stdin=stdin, stdout=stdout)
    server.run()

    output = stdout.getvalue()
    assert "Content-Length:" in output

    # Find JSON payload
    parts = output.split("\r\n\r\n", 1)
    assert len(parts) == 2
    res = json.loads(parts[1])
    assert res["id"] == 1
    assert "capabilities" in res["result"]
    assert res["result"]["capabilities"]["textDocumentSync"]["openClose"] is True
    assert res["result"]["capabilities"]["textDocumentSync"]["change"] == 0
    assert res["result"]["capabilities"]["textDocumentSync"]["save"] == {"includeText": True}


def test_lsp_accepts_frame_at_content_length_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    body = json.dumps(req)
    monkeypatch.setattr("wardline.lsp.MAX_LSP_CONTENT_LENGTH", len(body))

    stdout = io.StringIO()
    LspServer(root=Path("/my/project"), stdin=io.StringIO(_frame(body)), stdout=stdout).run()

    messages = _lsp_messages(stdout.getvalue())
    assert messages[0]["id"] == 1


def test_lsp_oversized_frame_is_drained_and_next_message_processed(monkeypatch: pytest.MonkeyPatch) -> None:
    oversized = json.dumps(
        {"jsonrpc": "2.0", "id": 99, "method": "initialize", "params": {"rootUri": "file:///too-large"}}
    )
    shutdown = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "shutdown"})
    monkeypatch.setattr("wardline.lsp.MAX_LSP_CONTENT_LENGTH", len(oversized) - 1)

    stdout = io.StringIO()
    LspServer(root=Path("/my/project"), stdin=io.StringIO(_frame(oversized) + _frame(shutdown)), stdout=stdout).run()

    messages = _lsp_messages(stdout.getvalue())
    assert [message["id"] for message in messages] == [2]


def test_lsp_diagnostics_flow(tmp_path: Path) -> None:
    # Set up a fake file in tmp_path
    file_path = tmp_path / "foo.py"
    file_path.write_text("assert x > 0\n", encoding="utf-8")

    # We can mock run_scan to return a predictable finding
    finding = Finding(
        rule_id="PY-WL-111",
        message="assert-only boundary check",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="foo.py", line_start=1, col_start=4, col_end=12),
        fingerprint="test_fp",
    )
    scan_res = ScanResult(
        findings=[finding],
        summary=ScanSummary(total=1, active=1, baselined=0, waived=0, judged=0, unanalyzed=0),
        files_scanned=1,
        context=None,
    )

    req_open = {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {"uri": file_path.as_uri(), "languageId": "python", "version": 1, "text": "assert x > 0\n"}
        },
    }
    body_open = json.dumps(req_open)
    raw_input = f"Content-Length: {len(body_open)}\r\n\r\n{body_open}"

    stdin = io.StringIO(raw_input)
    stdout = io.StringIO()

    server = LspServer(root=tmp_path, stdin=stdin, stdout=stdout)

    with patch("wardline.lsp.run_scan", return_value=scan_res) as mock_run:
        server.run()
        mock_run.assert_called_once_with(tmp_path, confine_to_root=True)

    output = stdout.getvalue()
    assert "textDocument/publishDiagnostics" in output

    # Parse notifications
    notifications = []
    for part in output.split("Content-Length:"):
        if not part.strip():
            continue
        subparts = part.split("\r\n\r\n", 1)
        if len(subparts) == 2:
            notifications.append(json.loads(subparts[1]))

    assert len(notifications) == 1
    notif = notifications[0]
    assert notif["method"] == "textDocument/publishDiagnostics"
    params = notif["params"]
    assert params["uri"] == file_path.as_uri()
    assert len(params["diagnostics"]) == 1
    diag = params["diagnostics"][0]
    assert diag["code"] == "PY-WL-111"
    assert diag["severity"] == 1  # Severity.ERROR -> 1
    assert diag["range"]["start"]["line"] == 0
    assert diag["range"]["start"]["character"] == 4
    assert diag["range"]["end"]["line"] == 0
    assert diag["range"]["end"]["character"] == 12


def test_lsp_scan_config_error_publishes_visible_diagnostic(tmp_path: Path) -> None:
    file_path = tmp_path / "foo.py"
    file_path.write_text("def f():\n    return 1\n", encoding="utf-8")

    req_open = {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {"uri": file_path.as_uri(), "languageId": "python", "version": 1, "text": "def f():\n"}
        },
    }
    body_open = json.dumps(req_open)
    raw_input = f"Content-Length: {len(body_open)}\r\n\r\n{body_open}"

    stdout = io.StringIO()
    server = LspServer(root=tmp_path, stdin=io.StringIO(raw_input), stdout=stdout)

    with patch("wardline.lsp.run_scan", side_effect=ConfigError("bad weft.toml")):
        server.run()

    messages = _lsp_messages(stdout.getvalue())
    assert any(msg["method"] == "window/showMessage" for msg in messages)
    diagnostics = [msg for msg in messages if msg["method"] == "textDocument/publishDiagnostics"]
    assert len(diagnostics) == 1
    diag = diagnostics[0]["params"]["diagnostics"][0]
    assert diag["code"] == "WLN-ENGINE-LSP-SCAN-FAILED"
    assert diag["severity"] == 1
    assert "bad weft.toml" in diag["message"]


def test_lsp_unexpected_scan_error_is_not_silent(tmp_path: Path) -> None:
    file_path = tmp_path / "foo.py"
    file_path.write_text("def f():\n    return 1\n", encoding="utf-8")

    req_open = {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {"uri": file_path.as_uri(), "languageId": "python", "version": 1, "text": "def f():\n"}
        },
    }
    body_open = json.dumps(req_open)
    raw_input = f"Content-Length: {len(body_open)}\r\n\r\n{body_open}"

    stdout = io.StringIO()
    server = LspServer(root=tmp_path, stdin=io.StringIO(raw_input), stdout=stdout)

    with patch("wardline.lsp.run_scan", side_effect=RuntimeError("engine broke")):
        server.run()

    messages = _lsp_messages(stdout.getvalue())
    assert any(msg["method"] == "window/logMessage" for msg in messages)
    diagnostics = [msg for msg in messages if msg["method"] == "textDocument/publishDiagnostics"]
    assert len(diagnostics) == 1
    diag = diagnostics[0]["params"]["diagnostics"][0]
    assert diag["code"] == "WLN-ENGINE-LSP-SCAN-FAILED"
    assert "unexpected Wardline scan failure" in diag["message"]


def test_lsp_publishes_under_scan_engine_facts_as_info_diagnostics(tmp_path: Path) -> None:
    file_path = tmp_path / "foo.py"
    file_path.write_text("def f(:\n", encoding="utf-8")

    finding = Finding(
        rule_id="WLN-ENGINE-PARSE-ERROR",
        message="foo.py: could not be parsed",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=Location(path="foo.py", line_start=1, col_start=0, col_end=1),
        fingerprint="fp-engine",
    )
    scan_res = ScanResult(
        findings=[finding],
        summary=ScanSummary(total=1, active=0, baselined=0, waived=0, judged=0, unanalyzed=1),
        files_scanned=1,
        context=None,
    )

    req_open = {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {"uri": file_path.as_uri(), "languageId": "python", "version": 1, "text": "def f(:\n"}
        },
    }
    body_open = json.dumps(req_open)
    raw_input = f"Content-Length: {len(body_open)}\r\n\r\n{body_open}"

    stdout = io.StringIO()
    server = LspServer(root=tmp_path, stdin=io.StringIO(raw_input), stdout=stdout)

    with patch("wardline.lsp.run_scan", return_value=scan_res):
        server.run()

    messages = _lsp_messages(stdout.getvalue())
    assert any(
        msg["method"] == "window/logMessage" and "could not analyze" in msg["params"]["message"] for msg in messages
    )
    diagnostics = [msg for msg in messages if msg["method"] == "textDocument/publishDiagnostics"]
    assert len(diagnostics) == 1
    diag = diagnostics[0]["params"]["diagnostics"][0]
    assert diag["code"] == "WLN-ENGINE-PARSE-ERROR"
    assert diag["severity"] == 4


def test_lsp_did_change_does_not_rescan_unsaved_buffers(tmp_path: Path) -> None:
    file_path = tmp_path / "foo.py"
    file_path.write_text("def f():\n    return 1\n", encoding="utf-8")
    scan_res = ScanResult(
        findings=[],
        summary=ScanSummary(total=0, active=0, baselined=0, waived=0, judged=0, unanalyzed=0),
        files_scanned=1,
        context=None,
    )
    req_open = {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {"uri": file_path.as_uri(), "languageId": "python", "version": 1, "text": "def f():\n"}
        },
    }
    req_change = {
        "jsonrpc": "2.0",
        "method": "textDocument/didChange",
        "params": {
            "textDocument": {"uri": file_path.as_uri(), "version": 2},
            "contentChanges": [{"text": "@trusted\ndef f():\n    return raw()\n"}],
        },
    }
    body_open = json.dumps(req_open)
    body_change = json.dumps(req_change)
    raw_input = (
        f"Content-Length: {len(body_open)}\r\n\r\n{body_open}Content-Length: {len(body_change)}\r\n\r\n{body_change}"
    )

    server = LspServer(root=tmp_path, stdin=io.StringIO(raw_input), stdout=io.StringIO())

    with patch("wardline.lsp.run_scan", return_value=scan_res) as mock_run:
        server.run()

    mock_run.assert_called_once_with(tmp_path, confine_to_root=True)


def test_lsp_did_save_triggers_rescan(tmp_path: Path) -> None:
    file_path = tmp_path / "foo.py"
    file_path.write_text("def f():\n    return 1\n", encoding="utf-8")
    scan_res = ScanResult(
        findings=[],
        summary=ScanSummary(total=0, active=0, baselined=0, waived=0, judged=0, unanalyzed=0),
        files_scanned=1,
        context=None,
    )
    req_open = {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {"uri": file_path.as_uri(), "languageId": "python", "version": 1, "text": "def f():\n"}
        },
    }
    req_save = {
        "jsonrpc": "2.0",
        "method": "textDocument/didSave",
        "params": {"textDocument": {"uri": file_path.as_uri()}, "text": "def f():\n    return 2\n"},
    }
    body_open = json.dumps(req_open)
    body_save = json.dumps(req_save)
    raw_input = (
        f"Content-Length: {len(body_open)}\r\n\r\n{body_open}Content-Length: {len(body_save)}\r\n\r\n{body_save}"
    )

    server = LspServer(root=tmp_path, stdin=io.StringIO(raw_input), stdout=io.StringIO())

    with patch("wardline.lsp.run_scan", return_value=scan_res) as mock_run:
        server.run()

    assert mock_run.call_count == 2


def test_lsp_initialize_root_uri_escape_is_ignored(tmp_path: Path) -> None:
    launch_root = tmp_path / "safe"
    launch_root.mkdir()
    outside_root = tmp_path / "outside"
    outside_root.mkdir()

    server = LspServer(root=launch_root, stdin=io.StringIO(), stdout=io.StringIO())
    server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"rootUri": outside_root.as_uri()},
        }
    )

    assert server.root == launch_root.resolve()


def test_lsp_initialize_root_path_escape_is_ignored(tmp_path: Path) -> None:
    launch_root = tmp_path / "safe"
    launch_root.mkdir()
    outside_root = tmp_path / "outside"
    outside_root.mkdir()

    server = LspServer(root=launch_root, stdin=io.StringIO(), stdout=io.StringIO())
    server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"rootPath": str(outside_root)},
        }
    )

    assert server.root == launch_root.resolve()


def test_lsp_did_open_outside_launch_root_is_ignored(tmp_path: Path) -> None:
    launch_root = tmp_path / "safe"
    launch_root.mkdir()
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    outside_file = outside_root / "evil.py"
    outside_file.write_text("print('outside')\n", encoding="utf-8")

    server = LspServer(root=launch_root, stdin=io.StringIO(), stdout=io.StringIO())
    with patch("wardline.lsp.run_scan") as mock_run:
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": outside_file.as_uri(),
                        "languageId": "python",
                        "version": 1,
                        "text": "print('outside')\n",
                    }
                },
            }
        )

    assert outside_file.resolve() not in server.open_documents
    mock_run.assert_not_called()


def test_lsp_did_close_clears_diagnostics(tmp_path: Path) -> None:
    file_path = tmp_path / "foo.py"
    file_path.write_text("assert x > 0\n", encoding="utf-8")

    finding = Finding(
        rule_id="PY-WL-111",
        message="assert-only boundary check",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="foo.py", line_start=1, col_start=4, col_end=12),
        fingerprint="test_fp",
    )
    scan_res = ScanResult(
        findings=[finding],
        summary=ScanSummary(total=1, active=1, baselined=0, waived=0, judged=0, unanalyzed=0),
        files_scanned=1,
        context=None,
    )

    req_open = {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {"uri": file_path.as_uri(), "languageId": "python", "version": 1, "text": "assert x > 0\n"}
        },
    }
    req_close = {
        "jsonrpc": "2.0",
        "method": "textDocument/didClose",
        "params": {"textDocument": {"uri": file_path.as_uri()}},
    }

    body_open = json.dumps(req_open)
    body_close = json.dumps(req_close)
    raw_input = (
        f"Content-Length: {len(body_open)}\r\n\r\n{body_open}Content-Length: {len(body_close)}\r\n\r\n{body_close}"
    )

    stdin = io.StringIO(raw_input)
    stdout = io.StringIO()

    server = LspServer(root=tmp_path, stdin=stdin, stdout=stdout)

    with patch("wardline.lsp.run_scan", return_value=scan_res):
        server.run()

    output = stdout.getvalue()
    notifications = []
    for part in output.split("Content-Length:"):
        if not part.strip():
            continue
        subparts = part.split("\r\n\r\n", 1)
        if len(subparts) == 2:
            notifications.append(json.loads(subparts[1]))

    assert len(notifications) == 2
    assert notifications[0]["method"] == "textDocument/publishDiagnostics"
    assert len(notifications[0]["params"]["diagnostics"]) == 1

    assert notifications[1]["method"] == "textDocument/publishDiagnostics"
    assert notifications[1]["params"]["uri"] == file_path.as_uri()
    assert len(notifications[1]["params"]["diagnostics"]) == 0


def test_lsp_ignores_suppressed_findings(tmp_path: Path) -> None:
    file_path = tmp_path / "foo.py"
    file_path.write_text("assert x > 0\n", encoding="utf-8")

    active_finding = Finding(
        rule_id="PY-WL-111",
        message="active check",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="foo.py", line_start=1, col_start=4, col_end=12),
        fingerprint="fp1",
        suppressed=SuppressionState.ACTIVE,
    )
    suppressed_finding = Finding(
        rule_id="PY-WL-111",
        message="suppressed check",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="foo.py", line_start=1, col_start=4, col_end=12),
        fingerprint="fp2",
        suppressed=SuppressionState.BASELINED,
    )
    fact_finding = Finding(
        rule_id="WLN-ENGINE-NO-MODULE",
        message="fact about code",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=Location(path="foo.py", line_start=1, col_start=4, col_end=12),
        fingerprint="fp3",
        suppressed=SuppressionState.ACTIVE,
    )
    scan_res = ScanResult(
        findings=[active_finding, suppressed_finding, fact_finding],
        summary=ScanSummary(total=3, active=1, baselined=1, waived=0, judged=0, unanalyzed=0),
        files_scanned=1,
        context=None,
    )

    req_open = {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {"uri": file_path.as_uri(), "languageId": "python", "version": 1, "text": "assert x > 0\n"}
        },
    }
    body_open = json.dumps(req_open)
    raw_input = f"Content-Length: {len(body_open)}\r\n\r\n{body_open}"

    stdin = io.StringIO(raw_input)
    stdout = io.StringIO()

    server = LspServer(root=tmp_path, stdin=stdin, stdout=stdout)

    with patch("wardline.lsp.run_scan", return_value=scan_res):
        server.run()

    output = stdout.getvalue()
    parts = output.split("Content-Length:")
    assert len(parts) > 1
    subparts = parts[-1].split("\r\n\r\n", 1)
    notif = json.loads(subparts[1])
    diags = notif["params"]["diagnostics"]

    # We only want active defects to be published
    assert len(diags) == 1
    assert diags[0]["message"] == "active check"


def test_lsp_shutdown_and_exit() -> None:
    req_shutdown = {"jsonrpc": "2.0", "id": 2, "method": "shutdown"}
    req_exit = {"jsonrpc": "2.0", "method": "exit"}
    body_shutdown = json.dumps(req_shutdown)
    body_exit = json.dumps(req_exit)
    raw_input = (
        f"Content-Length: {len(body_shutdown)}\r\n\r\n{body_shutdown}"
        f"Content-Length: {len(body_exit)}\r\n\r\n{body_exit}"
    )

    stdin = io.StringIO(raw_input)
    stdout = io.StringIO()

    server = LspServer(root=Path("/my/project"), stdin=stdin, stdout=stdout)
    with pytest.raises(SystemExit) as excinfo:
        server.run()

    assert excinfo.value.code == 0

    output = stdout.getvalue()
    parts = output.split("Content-Length:")
    assert len(parts) > 1
    subparts = parts[-1].split("\r\n\r\n", 1)
    res = json.loads(subparts[1])
    assert res["id"] == 2
    assert res["result"] is None
