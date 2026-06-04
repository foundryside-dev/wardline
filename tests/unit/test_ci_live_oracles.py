from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_ci_exposes_scheduled_and_manual_live_oracles() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'" in workflow
    for marker in ("clarion_e2e", "legis_e2e", "filigree_e2e"):
        assert "-m ${{ matrix.marker }}" in workflow
        assert marker in workflow
    assert "GITHUB_STEP_SUMMARY" in workflow
