from pathlib import Path

from wardline.mcp.server import WardlineMCPServer

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = Path("tests/fixtures/sample_project")


def test_resource_and_prompt_catalogs_are_not_embedded_in_server_module() -> None:
    server_text = (ROOT / "src" / "wardline" / "mcp" / "server.py").read_text(encoding="utf-8")

    assert "_RESOURCES =" not in server_text
    assert "_LOOP_PROMPT =" not in server_text
    assert "class ToolError" not in server_text
    assert "def _resolve_under_root" not in server_text
    assert "def _require" not in server_text


def test_mcp_advertisement_snapshot() -> None:
    server = WardlineMCPServer(root=FIXTURE)

    tools = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    resources = server.rpc.dispatch({"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}})
    prompts = server.rpc.dispatch({"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}})

    assert [tool["name"] for tool in tools["result"]["tools"]] == [
        "scan",
        "explain_taint",
        "dossier",
        "assure",
        "decorator_coverage",
        "attest",
        "verify_attestation",
        "file_finding",
        "scan_file_findings",
        "judge",
        "baseline",
        "waiver_add",
        "fix",
        "doctor",
    ]
    assert [resource["uri"] for resource in resources["result"]["resources"]] == [
        "wardline://vocab",
        "wardline://rules",
        "wardline://config",
        "wardline://config-schema",
    ]
    assert [prompt["name"] for prompt in prompts["result"]["prompts"]] == ["wardline:loop"]
