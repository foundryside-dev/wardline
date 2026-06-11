"""B1+B2 conformance: MCP structured output + display metadata across all 15 tools.

Three layers, each pinned for EVERY registered tool:

1. ADVERTISEMENT — every tools/list entry carries a non-empty ``title``, a complete
   standard ``annotations`` object (2025-03-26), an object-typed ``outputSchema``
   (2025-06-18), AND the legacy homegrown ``capabilities`` key (mapped, not replaced).
   The annotation hints must be consistent with the declared capability sets.
2. EXECUTION — a representative SUCCESSFUL tools/call per tool: the returned
   ``structuredContent`` validates against that tool's own declared outputSchema and
   equals ``json.loads(content[0].text)`` (dual emission, byte-compatible text block).
   isError results carry NO structuredContent.
3. NEGOTIATION — initialize echoes any supported protocolVersion verbatim and answers
   the latest revision for an unknown one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from wardline.core.judge import JudgeResponse, JudgeVerdict
from wardline.mcp.protocol import PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS
from wardline.mcp.server import WardlineMCPServer
from wardline.mcp.tooling import ToolCapability

FIXTURE = Path("tests/fixtures/sample_project")

# The published 15-tool surface, in advertisement order.
EXPECTED_TOOLS = (
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
    "rekey",
)

# B2 acceptance: the pure-read surface advertises readOnlyHint: true.
READ_ONLY_TOOLS = frozenset(
    {"scan", "explain_taint", "dossier", "assure", "decorator_coverage", "attest", "verify_attestation"}
)

_ANNOTATION_KEYS = {"title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
_HINT_KEYS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _leaky_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def _entries(server: WardlineMCPServer) -> dict[str, dict[str, Any]]:
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert "error" not in resp, resp
    return {t["name"]: t for t in resp["result"]["tools"]}


def _call(server: WardlineMCPServer, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )
    assert "error" not in resp, resp
    result: dict[str, Any] = resp["result"]
    return result


def _validated(server: WardlineMCPServer, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """tools/call success → structuredContent validates against the tool's OWN declared
    outputSchema AND equals the parsed text block (dual emission)."""
    result = _call(server, name, arguments)
    assert result.get("isError") is not True, result
    schema = _entries(server)[name]["outputSchema"]
    assert "structuredContent" in result, f"{name}: success result missing structuredContent"
    structured: dict[str, Any] = result["structuredContent"]
    jsonschema.validate(structured, schema)
    assert json.loads(result["content"][0]["text"]) == structured, f"{name}: dual emission diverged"
    return structured


@pytest.fixture(scope="module")
def fixture_server() -> WardlineMCPServer:
    return WardlineMCPServer(root=FIXTURE)


# ---------------------------------------------------------------------------
# 1. Advertisement conformance
# ---------------------------------------------------------------------------


def test_advertises_exactly_the_published_surface(fixture_server: WardlineMCPServer) -> None:
    assert tuple(_entries(fixture_server)) == EXPECTED_TOOLS


@pytest.mark.parametrize("name", EXPECTED_TOOLS)
def test_tools_list_entry_carries_b1_b2_metadata(fixture_server: WardlineMCPServer, name: str) -> None:
    entry = _entries(fixture_server)[name]
    # title: present and non-empty
    assert isinstance(entry["title"], str) and entry["title"]
    # annotations: the COMPLETE standard ToolAnnotations object, nothing else
    ann = entry["annotations"]
    assert set(ann) == _ANNOTATION_KEYS
    for hint in _HINT_KEYS:
        assert isinstance(ann[hint], bool), f"{name}.{hint} must be a bool"
    assert ann["title"] == entry["title"]
    # outputSchema: an object schema (2025-06-18 structured output contract)
    out = entry["outputSchema"]
    assert isinstance(out, dict)
    assert out["type"] == "object"
    # the legacy homegrown capabilities key is mapped, NOT replaced
    assert isinstance(entry["capabilities"], list) and entry["capabilities"]


@pytest.mark.parametrize("name", EXPECTED_TOOLS)
def test_annotations_consistent_with_declared_capabilities(fixture_server: WardlineMCPServer, name: str) -> None:
    """The standard hints must never CONTRADICT the homegrown capability declaration."""
    tool = fixture_server._tools[name]
    ann = _entries(fixture_server)[name]["annotations"]
    if ToolCapability.WRITE in tool.capabilities:
        assert ann["readOnlyHint"] is False, f"{name}: WRITE capability with readOnlyHint true"
    if ToolCapability.NETWORK in tool.capabilities:
        assert ann["openWorldHint"] is True, f"{name}: NETWORK capability with openWorldHint false"
    if ann["readOnlyHint"]:
        assert ann["destructiveHint"] is False, f"{name}: read-only tools cannot be destructive"


def test_pure_read_surface_advertises_read_only(fixture_server: WardlineMCPServer) -> None:
    entries = _entries(fixture_server)
    for name in EXPECTED_TOOLS:
        expected = name in READ_ONLY_TOOLS
        assert entries[name]["annotations"]["readOnlyHint"] is expected, name


# ---------------------------------------------------------------------------
# 2. Execution conformance — one representative SUCCESS per tool
# ---------------------------------------------------------------------------


def test_scan_structured_output(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    out = _validated(server, "scan", {"fail_on": "ERROR"})
    assert out["gate"]["tripped"] is True


def test_explain_taint_structured_output(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    scan_out = _validated(server, "scan", {})
    fp = next(e["fingerprint"] for e in scan_out["agent_summary"]["active_defects"] if e["rule_id"] == "PY-WL-101")
    out = _validated(server, "explain_taint", {"fingerprint": fp})
    assert out["fingerprint"] == fp


def test_dossier_structured_output(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    out = _validated(server, "dossier", {"entity": "svc.leaky"})
    assert out["identity"]["qualname"] == "svc.leaky"


def test_assure_structured_output(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    out = _validated(server, "assure", {})
    assert out["boundaries_total"] >= 1


def test_decorator_coverage_structured_output(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    out = _validated(server, "decorator_coverage", {})
    assert out["summary"]["total"] >= 1


def test_attest_and_verify_attestation_structured_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from wardline.core.attest_key import WARDLINE_ATTEST_KEY_ENV, mint_attest_key

    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    proj = _leaky_project(tmp_path)
    mint_attest_key(proj)  # minted into proj/.env (non-git tree → dirty=False, strict default still builds)
    server = WardlineMCPServer(root=proj)

    bundle = _validated(server, "attest", {})
    assert bundle["signature"]["key_id"]

    verified = _validated(server, "verify_attestation", {"bundle": bundle})
    assert verified["signature_valid"] is True


def test_file_finding_structured_output(tmp_path: Path) -> None:
    from wardline.core.filigree_issue import FileResult

    class FakeFiler:
        def file(self, fingerprint: str, *, scan_source: str = "wardline", priority=None, labels=None) -> FileResult:
            return FileResult(reachable=True, issue_id="wardline-abc", created=True)

    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    # Inject the fake filer through the same seam the registered lambda resolves it.
    server._filigree_filer = lambda *a, **k: FakeFiler()  # type: ignore[method-assign]
    out = _validated(server, "file_finding", {"fingerprint": "f" * 64})
    assert out["issue_id"] == "wardline-abc"


def test_scan_file_findings_structured_output(tmp_path: Path) -> None:
    # Default invocation is a REAL dry-run scan (no Filigree configured): the
    # fail-soft emit/file blocks report 'not configured'.
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    out = _validated(server, "scan_file_findings", {})
    assert out["mode"] == "dry_run"


def test_judge_structured_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Network-fenced: patch the caller the default run_judge path imports.
    fake = JudgeResponse(
        verdict=JudgeVerdict.TRUE_POSITIVE,
        rationale="genuinely reaches a trusted sink",
        confidence=0.91,
        model_id="fake/model",
        recorded_at=datetime.now(UTC),
        prompt_tokens_total=128,
        prompt_tokens_cached=None,
        policy_hash="deadbeef",
    )
    monkeypatch.setattr("wardline.core.judge_run.call_judge", lambda *a, **k: fake)
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "sk-or-test")
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    out = _validated(server, "judge", {})
    assert out["verdicts"], out


def test_baseline_structured_output(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    out = _validated(server, "baseline", {"reason": "accept current debt"})
    assert out["baselined_count"] >= 1


def test_waiver_add_structured_output(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    out = _validated(
        server, "waiver_add", {"fingerprint": "a" * 64, "reason": "validated upstream", "expires": "2026-12-31"}
    )
    assert out["fingerprint"] == "a" * 64


def test_fix_structured_output(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "weft.toml").write_text('[wardline.autofix]\nboundary_exception = "ValueError"\n', encoding="utf-8")
    (proj / "svc.py").write_text(
        "from wardline.decorators import trust_boundary\n"
        "@trust_boundary(to_level='ASSURED')\n"
        "def check(val):\n"
        "    assert val is not None\n"
        "    return val\n",
        encoding="utf-8",
    )
    server = WardlineMCPServer(root=proj)
    out = _validated(server, "fix", {"dry_run": True})
    assert "svc.py" in out["fixed"]
    assert out["applied"] is False


def test_doctor_structured_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Hermetic: never read the real HOME or probe a real federation endpoint.
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: tmp_path / "home")
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    proj = tmp_path / "proj"
    proj.mkdir()
    server = WardlineMCPServer(root=proj)
    out = _validated(server, "doctor", {})
    assert out["checks"][-1]["id"] == "server.freshness"
    assert out["server"]["fresh"] is True


def test_rekey_structured_output(tmp_path: Path) -> None:
    # Probe-by-default: read-only report on a store-less project — writes nothing.
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    out = _validated(server, "rekey", {})
    assert out["mode"] == "probe"
    assert out["clean"] is True


def test_execution_conformance_covers_every_advertised_tool(fixture_server: WardlineMCPServer) -> None:
    """Tripwire: a 16th tool must add an execution-conformance case above."""
    assert set(_entries(fixture_server)) == set(EXPECTED_TOOLS)


def test_doctor_freshness_check_appears_in_structured_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A STALE server (started before the on-disk source changed) must still produce a
    # schema-valid payload: the error branch of the freshness check is schema-pinned too.
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: tmp_path / "home")
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    proj = tmp_path / "proj"
    proj.mkdir()
    server = WardlineMCPServer(root=proj)
    server.started_at = 1.0  # 1970 — everything on disk is newer
    out = _validated(server, "doctor", {})
    assert out["server"]["fresh"] is False
    assert out["ok"] is False


# ---------------------------------------------------------------------------
# isError results never carry structuredContent
# ---------------------------------------------------------------------------


def test_tool_execution_error_has_no_structured_content() -> None:
    # Stale/unknown fingerprint → isError result, text-only.
    server = WardlineMCPServer(root=FIXTURE)
    result = _call(server, "explain_taint", {"fingerprint": "0" * 64})
    assert result["isError"] is True
    assert "structuredContent" not in result


def test_invalid_arguments_error_has_no_structured_content(tmp_path: Path) -> None:
    # jsonschema argument rejection → isError result, text-only.
    server = WardlineMCPServer(root=tmp_path)
    result = _call(
        server,
        "waiver_add",
        {"fingerprint": "a" * 64, "reason": "ok", "expires": "2026-12-31", "apply": True},
    )
    assert result["isError"] is True
    assert "additional properties" in result["content"][0]["text"].lower()
    assert "structuredContent" not in result


# ---------------------------------------------------------------------------
# 3. Protocol version negotiation
# ---------------------------------------------------------------------------


def test_supported_protocol_versions_are_pinned() -> None:
    assert SUPPORTED_PROTOCOL_VERSIONS == ("2025-06-18", "2025-03-26", "2024-11-05")
    assert PROTOCOL_VERSION == "2025-06-18"


def _initialize(server: WardlineMCPServer, requested: str) -> str:
    resp = server.rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": requested, "capabilities": {}},
        }
    )
    assert "error" not in resp, resp
    version: str = resp["result"]["protocolVersion"]
    return version


@pytest.mark.parametrize("requested", SUPPORTED_PROTOCOL_VERSIONS)
def test_initialize_echoes_each_supported_protocol_version(requested: str) -> None:
    server = WardlineMCPServer(root=FIXTURE)
    assert _initialize(server, requested) == requested


def test_initialize_answers_latest_for_unknown_protocol_version() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    assert _initialize(server, "1999-01-01") == "2025-06-18"
