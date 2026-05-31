from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli


def test_scan_reads_filigree_url_from_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wardline.yaml").write_text(
        'filigree:\n  url: "http://configured-filigree"\n', encoding="utf-8"
    )
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    captured: dict[str, object] = {}

    class _FakeEmitter:
        def __init__(self, url: str) -> None:
            captured["url"] = url

        def emit(self, findings):  # noqa: ANN001
            from wardline.core.filigree_emit import EmitResult

            return EmitResult(reachable=False)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _FakeEmitter)
    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["url"] == "http://configured-filigree"


def test_mcp_resolves_clarion_url_from_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wardline.yaml").write_text(
        'clarion:\n  url: "http://configured-clarion"\n', encoding="utf-8"
    )
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, *, root: Path, clarion_url: str | None = None) -> None:
            captured["clarion_url"] = clarion_url
            self.rpc = self

        def run_stdio(self) -> None:
            captured["ran"] = True

    monkeypatch.setattr("wardline.cli.mcp.WardlineMCPServer", _FakeServer)
    result = CliRunner().invoke(cli, ["mcp", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["clarion_url"] == "http://configured-clarion"
