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
