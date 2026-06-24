import io
import json

from click.testing import CliRunner

from wardline.install.doctor import DoctorCheck
from wardline.mcp.server import WardlineMCPServer


def _mcp_doctor_payload(result_output: str) -> dict:
    lines = [json.loads(ln) for ln in result_output.splitlines() if ln.strip()]
    response = lines[-1]
    return json.loads(response["result"]["content"][0]["text"])


def test_stdio_loop_handles_initialize_then_tools_list(tmp_path) -> None:
    server = WardlineMCPServer(root=tmp_path)
    stdin = io.StringIO(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
            }
        )
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        + "\n"
    )
    stdout = io.StringIO()
    server.rpc.run_stdio(stdin=stdin, stdout=stdout)
    lines = [json.loads(ln) for ln in stdout.getvalue().splitlines() if ln.strip()]
    # initialize -> response; initialized -> no response; tools/list -> response
    assert len(lines) == 2
    assert lines[0]["result"]["serverInfo"]["name"] == "wardline"
    assert any(t["name"] == "scan" for t in lines[1]["result"]["tools"])


def test_mcp_command_is_registered() -> None:
    from wardline.cli.main import cli

    result = CliRunner().invoke(cli, ["mcp", "--help"])
    assert result.exit_code == 0
    assert "stdio" in result.output.lower() or "mcp" in result.output.lower()
    assert "--read-only" in result.output
    assert "--no-network" in result.output


def test_mcp_command_passes_policy_flags(tmp_path, monkeypatch) -> None:
    import wardline.cli.mcp as mcp_cli
    from wardline.cli.main import cli

    captured: dict[str, object] = {}

    class FakeRpc:
        def run_stdio(self) -> None:
            captured["ran"] = True

    class FakeServer:
        def __init__(
            self,
            *,
            root,
            loomweave_url=None,
            loomweave_url_source=None,
            filigree_url=None,
            filigree_url_source=None,
            allow_write=True,
            allow_network=True,
        ) -> None:
            captured.update(
                {
                    "root": root,
                    "loomweave_url": loomweave_url,
                    "loomweave_url_source": loomweave_url_source,
                    "filigree_url": filigree_url,
                    "filigree_url_source": filigree_url_source,
                    "allow_write": allow_write,
                    "allow_network": allow_network,
                }
            )
            self.rpc = FakeRpc()

    monkeypatch.setattr(mcp_cli, "WardlineMCPServer", FakeServer)

    result = CliRunner().invoke(
        cli,
        [
            "mcp",
            "--root",
            str(tmp_path),
            "--loomweave-url",
            "http://localhost:9100",
            "--filigree-url",
            "http://localhost:8628/api/weft/scan-results",
            "--read-only",
            "--no-network",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["root"] == tmp_path
    assert captured["loomweave_url"] == "http://localhost:9100"
    assert captured["loomweave_url_source"] == "--loomweave-url launch flag"
    assert captured["filigree_url"] == "http://localhost:8628/api/weft/scan-results"
    assert captured["filigree_url_source"] == "--filigree-url launch flag"
    assert captured["allow_write"] is False
    assert captured["allow_network"] is False
    assert captured["ran"] is True


def test_mcp_doctor_preserves_env_url_provenance(tmp_path, monkeypatch) -> None:
    from wardline.cli.main import cli

    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://localhost:9100")
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://localhost:8628/api/weft/scan-results")
    monkeypatch.setattr(
        "wardline.install.doctor._check_filigree_auth",
        lambda *args, **kwargs: DoctorCheck("filigree.auth", "ok"),
    )

    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "doctor"}}) + "\n"
    result = CliRunner().invoke(cli, ["mcp", "--root", str(tmp_path)], input=request)

    assert result.exit_code == 0, result.output
    by_id = {c["id"]: c for c in _mcp_doctor_payload(result.output)["checks"]}
    assert by_id["loomweave.url"]["message"] == "from env WARDLINE_LOOMWEAVE_URL"
    assert by_id["filigree.url"]["message"] == "from env WARDLINE_FILIGREE_URL"


def test_mcp_doctor_preserves_published_port_url_provenance(tmp_path, monkeypatch) -> None:
    from wardline.cli.main import cli

    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    (tmp_path / ".weft" / "loomweave").mkdir(parents=True)
    (tmp_path / ".weft" / "loomweave" / "ephemeral.port").write_text("9100", encoding="ascii")
    (tmp_path / ".weft" / "filigree").mkdir(parents=True)
    (tmp_path / ".weft" / "filigree" / "ephemeral.port").write_text("8628", encoding="ascii")
    monkeypatch.setattr(
        "wardline.install.doctor._check_filigree_auth",
        lambda *args, **kwargs: DoctorCheck("filigree.auth", "ok"),
    )

    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "doctor"}}) + "\n"
    result = CliRunner().invoke(cli, ["mcp", "--root", str(tmp_path)], input=request)

    assert result.exit_code == 0, result.output
    by_id = {c["id"]: c for c in _mcp_doctor_payload(result.output)["checks"]}
    assert by_id["loomweave.url"]["message"] == "from published .weft/loomweave/ephemeral.port"
    assert by_id["filigree.url"]["message"] == "from published .weft/filigree/ephemeral.port"


def test_mcp_command_runs_stdio_end_to_end(tmp_path) -> None:
    """Drive the real `mcp` command through click, exercising
    `WardlineMCPServer(root=root).rpc.run_stdio()` for real. Using --root tmp_path
    proves the option is wired (not a hardcoded path)."""
    from wardline.cli.main import cli

    stdin = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
            }
        )
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        + "\n"
    )
    result = CliRunner().invoke(cli, ["mcp", "--root", str(tmp_path)], input=stdin)
    assert result.exit_code == 0, result.output
    lines = [json.loads(ln) for ln in result.output.splitlines() if ln.strip()]
    assert len(lines) == 2
    assert lines[0]["result"]["serverInfo"]["name"] == "wardline"
    assert any(t["name"] == "scan" for t in lines[1]["result"]["tools"])
