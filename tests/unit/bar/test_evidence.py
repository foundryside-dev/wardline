"""Tests for BAR evidence artefact writing."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from wardline.bar.adapters import ReviewerResult
from wardline.bar.evidence import (
    BarEvidenceArtifact,
    BarEvidenceArtifactError,
    build_bar_evidence_artifact,
    write_bar_evidence_artifact,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_write_run_artefact_is_immutable(tmp_path: Path) -> None:
    artifact = _make_artifact(stability_run_index=1)

    written_path = write_bar_evidence_artifact(artifact, artifact_root=tmp_path)

    assert written_path == tmp_path / "2026-04-12" / "R-BAR-BUNDLE-EXAMPLE" / "run-1.json"
    with pytest.raises(BarEvidenceArtifactError, match="already exists"):
        write_bar_evidence_artifact(artifact, artifact_root=tmp_path)


def test_write_audit_rerun_artefact_uses_normative_path(tmp_path: Path) -> None:
    artifact = _make_artifact(stability_run_index="audit")

    written_path = write_bar_evidence_artifact(artifact, artifact_root=tmp_path)

    assert written_path == tmp_path / "2026-04-12" / "R-BAR-BUNDLE-EXAMPLE" / "audit-rerun.json"
    data = json.loads(written_path.read_text(encoding="utf-8"))
    assert data["stability_run_index"] == "audit"
    assert data["skill_pack"] == {
        "skill_pack_id": "wardline.bar.panel.core",
        "skill_pack_version": "2026.04.12",
        "assets": [
            "skill-pack/shared-discipline.md",
            "skill-pack/citation-contract.md",
        ],
    }
    assert data["reviewer_verdicts"]["python-engineer"]["citations"] == [
        "src/example_impl.py:3",
        "evidence_class_outputs:unit_tests",
    ]
    assert data["reviewer_verdicts"]["python-engineer"]["citation_validation"] == {
        "raw_citations": [
            "src/example_impl.py:3",
            "evidence_class_outputs:unit_tests",
        ],
        "dropped_citations": [],
    }
    assert data["reviewer_verdicts"]["irap-assessor"]["citation_validation"] == {
        "raw_citations": [
            "wardline.compliance.json",
            "free-form extra",
        ],
        "dropped_citations": [
            "free-form extra",
        ],
    }


def _make_artifact(*, stability_run_index: int | str) -> BarEvidenceArtifact:
    return build_bar_evidence_artifact(
        obligation_id="R-BAR-BUNDLE-EXAMPLE",
        pipeline_name="wardline-bar-panel",
        pipeline_version="2026.04.12",
        policy_hash="sha256:test-policy",
        commit_ref="deadbeef",
        manifest_hash="sha256:test-manifest",
        corpus_hash="sha256:test-corpus",
        model_pin={
            "model_id": "openrouter/anthropic/claude-opus-4.6",
            "temperature": 0,
            "top_p": 1,
            "seed": None,
        },
        skill_pack={
            "skill_pack_id": "wardline.bar.panel.core",
            "skill_pack_version": "2026.04.12",
            "assets": [
                "skill-pack/shared-discipline.md",
                "skill-pack/citation-contract.md",
            ],
        },
        reviewed_at=datetime(2026, 4, 12, 8, 30, tzinfo=UTC),
        stability_run_index=stability_run_index,
        reviewer_results={
            "python-engineer": ReviewerResult(
                verdict="pass",
                rationale="Looks correct.",
                citations=("src/example_impl.py:3", "evidence_class_outputs:unit_tests"),
                raw_citations=("src/example_impl.py:3", "evidence_class_outputs:unit_tests"),
            ),
            "irap-assessor": ReviewerResult(
                verdict="pass",
                rationale="Audit-defensible.",
                citations=("wardline.compliance.json",),
                raw_citations=("wardline.compliance.json", "free-form extra"),
            ),
        },
        aggregate_verdict="pass",
        pipeline_duration_seconds=1.25,
    )
