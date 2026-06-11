import io
import json

from wardline.mcp.server import WardlineMCPServer


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
    from click.testing import CliRunner

    from wardline.cli.main import cli

    result = CliRunner().invoke(cli, ["mcp", "--help"])
    assert result.exit_code == 0
    assert "stdio" in result.output.lower() or "mcp" in result.output.lower()
    assert "--read-only" in result.output
    assert "--no-network" in result.output


def test_mcp_command_passes_policy_flags(tmp_path, monkeypatch) -> None:
    from click.testing import CliRunner

    import wardline.cli.mcp as mcp_cli
    from wardline.cli.main import cli

    captured = {}

    class FakeRpc:
        def run_stdio(self) -> None:
            captured["ran"] = True

    class FakeServer:
        def __init__(
            self,
            *,
            root,
            loomweave_url=None,
            filigree_url=None,
            allow_write=True,
            allow_network=True,
        ) -> None:
            captured.update(
                {
                    "root": root,
                    "loomweave_url": loomweave_url,
                    "filigree_url": filigree_url,
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
    assert captured["filigree_url"] == "http://localhost:8628/api/weft/scan-results"
    assert captured["allow_write"] is False
    assert captured["allow_network"] is False
    assert captured["ran"] is True


def test_mcp_command_runs_stdio_end_to_end(tmp_path) -> None:
    """Drive the real `mcp` command through click, exercising
    `WardlineMCPServer(root=root).rpc.run_stdio()` for real. Using --root tmp_path
    proves the option is wired (not a hardcoded path)."""
    from click.testing import CliRunner

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
