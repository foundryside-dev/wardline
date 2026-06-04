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
        "WARDLINE_CLARION_BIN",
        "WARDLINE_LEGIS_URL",
        "WARDLINE_FILIGREE_URL",
    ):
        assert f"{key}: ${{{{ secrets.{key} }}}}" in workflow
    assert f'{LIVE_ORACLE_REQUIRED_ENV}: "1"' in workflow
    assert "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'" in workflow
    for marker in ("clarion_e2e", "legis_e2e", "filigree_e2e"):
        assert "-m ${{ matrix.marker }}" in workflow
        assert marker in workflow
    assert "GITHUB_STEP_SUMMARY" in workflow
    assert "fail this required oracle run" in workflow


def test_live_judge_oracle_only_claims_schema_contract() -> None:
    live_judge = (ROOT / "tests" / "e2e" / "test_judge_live.py").read_text(encoding="utf-8")

    assert "hits cache" not in live_judge
    assert "prompt_tokens_cached" not in live_judge


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
