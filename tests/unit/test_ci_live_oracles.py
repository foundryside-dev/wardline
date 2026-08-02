import ast
import re
import tomllib
from pathlib import Path

import pytest

from wardline._live_oracle import LIVE_ORACLE_REQUIRED_ENV, should_fail_live_oracle_skip

ROOT = Path(__file__).resolve().parents[2]


def test_ci_exposes_scheduled_and_manual_live_oracles() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "network:" in workflow
    assert "Live judge e2e (weekly)" in workflow
    assert "if: github.event_name == 'schedule'" in workflow
    assert "run: uv run pytest -m network -v" in workflow
    for key in (
        "WARDLINE_OPENROUTER_API_KEY",
        "WARDLINE_LOOMWEAVE_BIN",
        "WARDLINE_LEGIS_URL",
        "WARDLINE_FILIGREE_URL",
        "WARDLINE_WARPLINE_BIN",
    ):
        assert f"{key}: ${{{{ secrets.{key} }}}}" in workflow
    assert f'{LIVE_ORACLE_REQUIRED_ENV}: "1"' in workflow
    assert "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'" in workflow
    for marker in ("loomweave_e2e", "legis_e2e", "filigree_e2e", "warpline_e2e"):
        assert "-m ${{ matrix.marker }}" in workflow
        assert marker in workflow
    assert "warpline_e2e" in workflow
    assert "WARDLINE_WARPLINE_BIN" in workflow
    assert "GITHUB_STEP_SUMMARY" in workflow
    assert "fail this required oracle run" in workflow


def test_live_judge_oracle_only_claims_schema_contract() -> None:
    live_judge = (ROOT / "tests" / "e2e" / "test_judge_live.py").read_text(encoding="utf-8")

    assert "hits cache" not in live_judge
    assert "prompt_tokens_cached" not in live_judge


def test_codex_live_oracle_is_registered_and_default_excluded() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    pytest_options = pyproject["tool"]["pytest"]["ini_options"]
    marker_names = {marker.partition(":")[0] for marker in pytest_options["markers"]}
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "codex_live" in marker_names
    assert re.search(r"\bnot\s+codex_live\b", pytest_options["addopts"])
    assert "codex_live" not in workflow
    assert "WARDLINE_CODEX_LIVE" not in workflow


def test_codex_live_oracle_proves_tool_use_without_logging_model_output() -> None:
    source = (ROOT / "tests" / "e2e" / "test_judge_codex_live.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)

    assert "codex_process_runner=" in source
    assert "mcp_tool_call" in source
    assert "read_file" in source
    assert "judge_helper.py" in source
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert):
            continue
        assert not any(
            isinstance(test_node, ast.Name)
            and test_node.id in {"captured_stdout", "response"}
            for test_node in ast.walk(node.test)
        )
        if node.msg is not None:
            assert not any(
                (
                    isinstance(message_node, ast.Attribute)
                    and message_node.attr == "rationale"
                )
                or (
                    isinstance(message_node, ast.Name)
                    and message_node.id in {"captured_stdout", "response"}
                )
                for message_node in ast.walk(node.msg)
            )


def test_live_oracle_required_mode_forbids_live_oracle_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(LIVE_ORACLE_REQUIRED_ENV, raising=False)
    assert should_fail_live_oracle_skip(["network"], "skipped") is False

    monkeypatch.setenv(LIVE_ORACLE_REQUIRED_ENV, "1")
    assert should_fail_live_oracle_skip(["network"], "skipped") is True
    assert should_fail_live_oracle_skip(["legis_e2e"], "skipped") is True
    assert should_fail_live_oracle_skip(["unit"], "skipped") is False
    assert should_fail_live_oracle_skip(["network"], "passed") is False

    monkeypatch.setenv(LIVE_ORACLE_REQUIRED_ENV, "true")
    assert should_fail_live_oracle_skip(["filigree_e2e"], "skipped") is True
