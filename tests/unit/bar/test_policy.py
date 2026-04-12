"""Tests for BAR policy-tree loading and verification."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from wardline.bar.policy import BarPolicyError, describe_policy_runtime, load_policy_tree

_REPO_ROOT = Path(__file__).resolve().parents[3]
_POLICY_TREES_ROOT = _REPO_ROOT / "docs" / "governance" / "bar-policy"
_ACTIVE_POLICY_VERSION = "2026.04.12"
_ACTIVE_POLICY_ROOT = _POLICY_TREES_ROOT / _ACTIVE_POLICY_VERSION


def test_load_policy_tree_reads_version_json_and_model_pin() -> None:
    loaded = load_policy_tree(_ACTIVE_POLICY_VERSION)

    assert loaded.version == _ACTIVE_POLICY_VERSION
    assert loaded.root == _ACTIVE_POLICY_ROOT
    assert loaded.pipeline_name == "wardline-bar-panel"
    assert loaded.policy_hash == "aba51a4ca81ccf4f31e1540db3fab28972607a6778bb1da33cba975e33c23287"
    assert loaded.model_pin["model_id"] == "openrouter/anthropic/claude-opus-4.6"
    assert loaded.model_pin["temperature"] == 0
    assert loaded.model_pin["top_p"] == 1
    assert loaded.model_pin["timeout_seconds"] == 180
    assert loaded.model_pin["max_retries"] == 1
    assert loaded.skill_pack.skill_pack_id == "wardline.bar.panel.core"
    assert loaded.skill_pack.skill_pack_version == _ACTIVE_POLICY_VERSION
    assert loaded.skill_pack.assets == (
        "skill-pack/shared-discipline.md",
        "skill-pack/citation-contract.md",
    )


def test_load_policy_tree_imports_aggregation_module() -> None:
    loaded = load_policy_tree(_ACTIVE_POLICY_VERSION)

    assert Path(loaded.aggregation_module.__file__) == _ACTIVE_POLICY_ROOT / "aggregation.py"
    reviewer_verdicts = {role: "pass" for role in loaded.aggregation_module.PANEL_ROLES}
    assert loaded.aggregation_module.aggregate(reviewer_verdicts) == "pass"


def test_load_policy_tree_rejects_hash_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    copied_policy_root = tmp_path / _ACTIVE_POLICY_VERSION
    shutil.copytree(_ACTIVE_POLICY_ROOT, copied_policy_root)
    (copied_policy_root / "shared-preamble.md").write_text(
        "tampered policy tree\n",
        encoding="utf-8",
    )

    import wardline.bar.policy as policy_mod

    monkeypatch.setattr(policy_mod, "_POLICY_TREES_ROOT", tmp_path)

    with pytest.raises(BarPolicyError, match="policy hash mismatch"):
        load_policy_tree(_ACTIVE_POLICY_VERSION)


def test_active_policy_tree_exposes_panel_roles_from_aggregation_module() -> None:
    loaded = load_policy_tree()

    assert loaded.version == _ACTIVE_POLICY_VERSION
    assert loaded.panel_roles == (
        "solution-architect",
        "systems-thinker",
        "python-engineer",
        "quality-engineer",
        "security-architect",
        "static-analysis-engineer",
        "irap-assessor",
    )
    assert loaded.panel_roles == tuple(loaded.aggregation_module.PANEL_ROLES)


def test_describe_policy_runtime_projects_cli_status_fields() -> None:
    loaded = load_policy_tree(_ACTIVE_POLICY_VERSION)

    runtime = describe_policy_runtime(loaded)

    assert runtime == {
        "pipeline_name": "wardline-bar-panel",
        "policy_version": "2026.04.12",
        "policy_hash": "aba51a4ca81ccf4f31e1540db3fab28972607a6778bb1da33cba975e33c23287",
        "skill_pack": {
            "skill_pack_id": "wardline.bar.panel.core",
            "skill_pack_version": "2026.04.12",
            "assets": [
                "skill-pack/shared-discipline.md",
                "skill-pack/citation-contract.md",
            ],
        },
        "model": {
            "provider": "openrouter",
            "model_id": "openrouter/anthropic/claude-opus-4.6",
            "temperature": 0,
            "top_p": 1,
            "seed": None,
            "max_output_tokens": 16384,
        },
        "guardrails": {
            "timeout_seconds": 180,
            "max_retries": 1,
        },
    }
