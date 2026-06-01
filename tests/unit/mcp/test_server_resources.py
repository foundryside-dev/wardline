import json
from pathlib import Path

from wardline.mcp.server import WardlineMCPServer

FIXTURE = Path("tests/fixtures/sample_project")


def test_resources_list_has_the_four_stable_resources() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {}})
    resources = resp["result"]["resources"]
    uris = {r["uri"] for r in resources}
    assert uris == {"wardline://vocab", "wardline://rules", "wardline://config", "wardline://config-schema"}
    for r in resources:
        assert r["name"].strip()
        assert r["mimeType"].strip()


def test_findings_are_not_a_resource() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {}})
    uris = {r["uri"] for r in resp["result"]["resources"]}
    assert not any("finding" in u for u in uris)


def test_read_config_schema_returns_json_schema() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": "wardline://config-schema"}}
    )
    contents = resp["result"]["contents"][0]
    schema = json.loads(contents["text"])
    assert schema["$schema"].startswith("https://json-schema.org/")


def test_read_rules_lists_rule_ids() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "wardline://rules"}}
    )
    payload = json.loads(resp["result"]["contents"][0]["text"])
    assert isinstance(payload["rules"], list) and payload["rules"]
    for r in payload["rules"]:
        assert "rule_id" in r
        # description must be the real METADATA.description, not an empty
        # cls.__doc__ (which is None for every rule class) — guards the
        # regression that prompted switching off the docstring.
        assert r["description"].strip()
        assert "base_severity" in r
        assert isinstance(r["base_severity"], str) and r["base_severity"].strip()
    ids = {r["rule_id"] for r in payload["rules"]}
    assert {"PY-WL-101", "PY-WL-102", "PY-WL-103", "PY-WL-104"} <= ids


def test_read_config_returns_effective_fields() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 5, "method": "resources/read", "params": {"uri": "wardline://config"}}
    )
    payload = json.loads(resp["result"]["contents"][0]["text"])
    for key in ("source_roots", "exclude", "rules_enable", "rules_severity"):
        assert key in payload
    assert isinstance(payload["source_roots"], list)


def test_read_unknown_uri_errors() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "wardline://nope"}}
    )
    assert "error" in resp
