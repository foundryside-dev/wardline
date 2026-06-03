# src/wardline/mcp/lsp.py
"""LSP diagnostics server implementation (stdlib-only)."""

from __future__ import annotations

import contextlib
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any, TextIO

from wardline.core.errors import WardlineError
from wardline.core.finding import ENGINE_PATH, UNANALYZED_RULE_IDS, Finding, Kind, Severity, SuppressionState


def run_scan(*args: Any, **kwargs: Any) -> Any:
    from wardline.core.run import run_scan as _run_scan

    return _run_scan(*args, **kwargs)


class LspServer:
    def __init__(
        self,
        root: Path,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        self.launch_root = root.resolve()
        self.root = self.launch_root
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.open_documents: set[Path] = set()
        self.is_initialized = False

    def send_notification(self, method: str, params: Any) -> None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        self.write_message(payload)

    def write_message(self, message: Any) -> None:
        body = json.dumps(message, ensure_ascii=False)
        body_bytes = body.encode("utf-8")
        headers = f"Content-Length: {len(body_bytes)}\r\n\r\n"
        try:
            self.stdout.buffer.write(headers.encode("ascii") + body_bytes)
            self.stdout.buffer.flush()
        except AttributeError:
            content = headers + body
            self.stdout.write(content)
            self.stdout.flush()

    def run(self) -> None:
        """Process LSP messages from stdin and write responses to stdout."""
        try:
            stdin_binary = self.stdin.buffer
        except AttributeError:
            # Fallback if stdin is a Mock/StringIO in tests
            stdin_binary = self.stdin

        while True:
            content_length = None
            while True:
                line = stdin_binary.readline()
                if not line:
                    return
                line_bytes = line.encode("utf-8") if isinstance(line, str) else line

                if line_bytes == b"\r\n" or line_bytes == b"\n":
                    break

                if line_bytes.lower().startswith(b"content-length:"):
                    with contextlib.suppress(ValueError):
                        content_length = int(line_bytes.split(b":", 1)[1].strip())

            if content_length is None:
                continue

            body_bytes = b""
            while len(body_bytes) < content_length:
                to_read = content_length - len(body_bytes)
                chunk = stdin_binary.read(to_read)
                if not chunk:
                    return
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                body_bytes += chunk

            try:
                message = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                continue

            self.handle_message(message)

    def handle_message(self, message: dict[str, Any]) -> None:
        msg_id = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}

        if method == "initialize":
            root_uri = params.get("rootUri")
            if root_uri:
                extracted_root = self.uri_to_path(root_uri)
                if extracted_root is not None and self._is_allowed_root(extracted_root):
                    self.root = extracted_root
            elif params.get("rootPath"):
                extracted_root = Path(params["rootPath"]).resolve()
                if self._is_allowed_root(extracted_root):
                    self.root = extracted_root

            self.write_message(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "capabilities": {
                            "textDocumentSync": {
                                "openClose": True,
                                "change": 0,
                                "save": {"includeText": True},
                            }
                        }
                    },
                }
            )
        elif method == "initialized":
            self.is_initialized = True
        elif method == "shutdown":
            self.write_message({"jsonrpc": "2.0", "id": msg_id, "result": None})
        elif method == "exit":
            sys.exit(0)
        elif method == "textDocument/didOpen":
            uri = params.get("textDocument", {}).get("uri", "")
            path = self.uri_to_path(uri)
            if path is not None and self._is_under_launch_root(path):
                self.open_documents.add(path)
                self.run_and_publish()
        elif method == "textDocument/didClose":
            uri = params.get("textDocument", {}).get("uri", "")
            path = self.uri_to_path(uri)
            if path in self.open_documents:
                self.open_documents.remove(path)
                self.send_notification(
                    "textDocument/publishDiagnostics",
                    {
                        "uri": self.path_to_uri(path),
                        "diagnostics": [],
                    },
                )
        elif method == "textDocument/didSave":
            self.run_and_publish()

    def run_and_publish(self) -> None:
        """Run project scan and publish diagnostics for all open documents."""
        try:
            res = run_scan(self.root, confine_to_root=True)
        except WardlineError as exc:
            self._publish_scan_failure(f"Wardline scan failed: {exc}", notification_method="window/showMessage")
            return
        except Exception as exc:  # noqa: BLE001
            self._publish_scan_failure(
                f"unexpected Wardline scan failure: {exc}",
                notification_method="window/logMessage",
            )
            return

        if res.summary.unanalyzed:
            self.send_notification(
                "window/logMessage",
                {
                    "type": 2,
                    "message": f"Wardline could not analyze {res.summary.unanalyzed} file/source root(s).",
                },
            )

        findings_by_file: dict[Path, list[Finding]] = {}
        for f in res.findings:
            if not self._should_publish_finding(f):
                continue
            if f.location.path and f.location.path != ENGINE_PATH:
                abs_path = (self.root / f.location.path).resolve()
                if abs_path not in findings_by_file:
                    findings_by_file[abs_path] = []
                findings_by_file[abs_path].append(f)

        for open_path in self.open_documents:
            diagnostics = []
            file_findings = findings_by_file.get(open_path, [])
            for f in file_findings:
                diagnostics.append(self._finding_to_diagnostic(f))

            self.send_notification(
                "textDocument/publishDiagnostics",
                {
                    "uri": self.path_to_uri(open_path),
                    "diagnostics": diagnostics,
                },
            )

    def _should_publish_finding(self, finding: Finding) -> bool:
        if finding.suppressed is not SuppressionState.ACTIVE:
            return False
        if finding.kind is Kind.DEFECT:
            return True
        return finding.kind is Kind.FACT and finding.rule_id in UNANALYZED_RULE_IDS

    def _finding_to_diagnostic(self, finding: Finding) -> dict[str, Any]:
        loc = finding.location
        line_start = (loc.line_start or 1) - 1
        col_start = loc.col_start or 0
        line_end = (loc.line_end or loc.line_start or 1) - 1
        col_end = loc.col_end if loc.col_end is not None else (col_start + 1)

        severity = 4  # Hint
        if finding.severity == Severity.CRITICAL or finding.severity == Severity.ERROR:
            severity = 1
        elif finding.severity == Severity.WARN:
            severity = 2
        elif finding.severity == Severity.INFO:
            severity = 3

        return {
            "range": {
                "start": {"line": line_start, "character": col_start},
                "end": {"line": line_end, "character": col_end},
            },
            "severity": severity,
            "code": finding.rule_id,
            "message": finding.message,
        }

    def _publish_scan_failure(self, message: str, *, notification_method: str) -> None:
        self.send_notification(
            notification_method,
            {
                "type": 1,
                "message": message,
            },
        )
        diagnostic = {
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": 0, "character": 1},
            },
            "severity": 1,
            "code": "WLN-ENGINE-LSP-SCAN-FAILED",
            "message": message,
        }
        for open_path in self.open_documents:
            self.send_notification(
                "textDocument/publishDiagnostics",
                {
                    "uri": self.path_to_uri(open_path),
                    "diagnostics": [diagnostic],
                },
            )

    def uri_to_path(self, uri: str) -> Path | None:
        if not uri.startswith("file://"):
            return None
        path_str = uri[7:]
        if path_str.startswith("/") and len(path_str) > 2 and path_str[2] == ":":
            path_str = path_str[1:]
        decoded = urllib.parse.unquote(path_str)
        return Path(decoded).resolve()

    def path_to_uri(self, path: Path) -> str:
        return path.as_uri()

    def _is_allowed_root(self, path: Path) -> bool:
        resolved = path.resolve()
        return resolved.exists() and self._is_under_launch_root(resolved)

    def _is_under_launch_root(self, path: Path) -> bool:
        resolved = path.resolve()
        return resolved == self.launch_root or resolved.is_relative_to(self.launch_root)
