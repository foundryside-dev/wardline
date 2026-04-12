"""Tests for the BAR CLI review and rerun commands."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from wardline import __version__ as _WARDLINE_VERSION
from wardline.bar.adapters import ReviewerResult
from wardline.cli.corpus_cmds import _compute_corpus_hash

_FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "bar" / "ledger"
_FIXED_REVIEWED_AT = datetime(2026, 4, 12, 8, 30, tzinfo=UTC)
_OBLIGATION_ID = "R-BAR-BUNDLE-EXAMPLE"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def bar_fixture_repo(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo"
    shutil.copytree(_FIXTURE_ROOT, repo_root)

    _git(repo_root, "init")
    _git(repo_root, "config", "user.email", "fixture@example.com")
    _git(repo_root, "config", "user.name", "Fixture User")
    _git(repo_root, "add", ".")
    _git(repo_root, "commit", "-m", "fixture snapshot")
    commit_ref = _git(repo_root, "rev-parse", "HEAD")

    template_path = repo_root / "ledger-template.json"
    template = json.loads(template_path.read_text(encoding="utf-8"))
    freshness_binding = template["obligations"][0]["freshness_binding"]
    manifest_hash = _sha256(repo_root / "wardline.yaml")
    corpus_hash = _compute_corpus_hash(repo_root / "corpus")
    freshness_binding["commit_ref"] = commit_ref
    freshness_binding["manifest_hash"] = manifest_hash
    freshness_binding["corpus_hash"] = corpus_hash
    (repo_root / "wardline.compliance.json").write_text(
        json.dumps(template, indent=2) + "\n",
        encoding="utf-8",
    )
    (repo_root / "wardline.conformance.json").write_text(
        json.dumps(
            {
                "cells_below_precision_floor": [],
                "cells_below_recall_floor": [],
                "gaps": [],
                "inputs": {
                    "tool_version": _WARDLINE_VERSION,
                    "commit_ref": commit_ref,
                    "manifest_hash": manifest_hash,
                    "corpus_hash": corpus_hash,
                },
                "summary": {
                    "failing_cells": 0,
                },
                "status": "pass",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    return repo_root


class FakeReviewerAdapter:
    """Deterministic fake BAR adapter for CLI tests."""

    def review(self, *, role: str, prompt: str, model_pin: dict[str, object]) -> ReviewerResult:
        del role, prompt, model_pin
        return ReviewerResult(
            verdict="pass",
            rationale="Evidence is sufficient and compliant.",
            citations=("src/example_impl.py",),
        )


def test_bar_status_json_reports_active_runtime_config(runner: CliRunner) -> None:
    import wardline.cli.bar_cmd as bar_cmd

    result = runner.invoke(
        bar_cmd.bar,
        [
            "status",
            "--json",
        ],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data == {
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


def test_bar_status_text_renders_runtime_summary(runner: CliRunner) -> None:
    import wardline.cli.bar_cmd as bar_cmd

    result = runner.invoke(
        bar_cmd.bar,
        [
            "status",
        ],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    assert "Wardline BAR Status" in result.output
    assert "Policy version:         2026.04.12" in result.output
    assert "Policy hash:            aba51a4ca81ccf4f31e1540db3fab28972607a6778bb1da33cba975e33c23287" in result.output
    assert "Skill pack:             wardline.bar.panel.core @ 2026.04.12" in result.output
    assert "Model provider:         openrouter" in result.output
    assert "Timeout seconds:        180" in result.output
    assert "Max retries:            1" in result.output


def test_bar_review_writes_three_run_artefacts_with_fake_adapter(
    runner: CliRunner,
    bar_fixture_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import wardline.cli.bar_cmd as bar_cmd

    monkeypatch.setattr(bar_cmd, "_load_reviewer_adapter", lambda _model_pin: FakeReviewerAdapter())
    monkeypatch.setattr(bar_cmd, "_reviewed_at", lambda: _FIXED_REVIEWED_AT)

    result = runner.invoke(
        bar_cmd.bar,
        [
            "review",
            "--ledger",
            str(bar_fixture_repo / "wardline.compliance.json"),
            "--obligation",
            _OBLIGATION_ID,
            "--path",
            str(bar_fixture_repo),
            "--json",
        ],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    expected_paths = [
        "docs/verification/bar-pipeline-runs/2026-04-12/R-BAR-BUNDLE-EXAMPLE/run-1.json",
        "docs/verification/bar-pipeline-runs/2026-04-12/R-BAR-BUNDLE-EXAMPLE/run-2.json",
        "docs/verification/bar-pipeline-runs/2026-04-12/R-BAR-BUNDLE-EXAMPLE/run-3.json",
    ]
    assert data == {
        "obligation_id": _OBLIGATION_ID,
        "aggregate_verdict": "pass",
        "stable": True,
        "stability_reason": "stable unanimous aggregate across required runs",
        "recommended_state": "verified",
        "recommended_independence": "bootstrap_attested",
        "artifacts": expected_paths,
        "policy_version": "2026.04.12",
    }

    for relpath in expected_paths:
        assert (bar_fixture_repo / relpath).is_file()


def test_bar_review_refuses_dirty_commit(
    runner: CliRunner,
    bar_fixture_repo: Path,
) -> None:
    import wardline.cli.bar_cmd as bar_cmd

    ledger_path = bar_fixture_repo / "wardline.compliance.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    commit_ref = ledger["obligations"][0]["freshness_binding"]["commit_ref"]
    ledger["obligations"][0]["freshness_binding"]["commit_ref"] = f"{commit_ref}-dirty"
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")

    result = runner.invoke(
        bar_cmd.bar,
        [
            "review",
            "--ledger",
            str(ledger_path),
            "--obligation",
            _OBLIGATION_ID,
            "--path",
            str(bar_fixture_repo),
        ],
        catch_exceptions=True,
    )

    assert result.exit_code == 1
    assert "dirty commit refs" in result.output


def test_bar_rerun_writes_audit_artefact(
    runner: CliRunner,
    bar_fixture_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import wardline.cli.bar_cmd as bar_cmd

    monkeypatch.setattr(bar_cmd, "_load_reviewer_adapter", lambda _model_pin: FakeReviewerAdapter())
    monkeypatch.setattr(bar_cmd, "_reviewed_at", lambda: _FIXED_REVIEWED_AT)

    review_result = runner.invoke(
        bar_cmd.bar,
        [
            "review",
            "--ledger",
            str(bar_fixture_repo / "wardline.compliance.json"),
            "--obligation",
            _OBLIGATION_ID,
            "--path",
            str(bar_fixture_repo),
            "--json",
        ],
        catch_exceptions=True,
    )
    assert review_result.exit_code == 0, review_result.output

    ledger_path = bar_fixture_repo / "wardline.compliance.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    reviewer_metadata = ledger["obligations"][0]["reviewer_metadata"]
    reviewer_metadata["independence"] = "bootstrap_attested"
    reviewer_metadata["review_pipeline"] = "wardline-bar-panel"
    reviewer_metadata["review_pipeline_version"] = "2026.04.12"
    reviewer_metadata["review_policy_hash"] = (
        "aba51a4ca81ccf4f31e1540db3fab28972607a6778bb1da33cba975e33c23287"
    )
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")

    result = runner.invoke(
        bar_cmd.bar,
        [
            "rerun",
            "--ledger",
            str(bar_fixture_repo / "wardline.compliance.json"),
            "--artifact",
            str(
                bar_fixture_repo
                / "docs/verification/bar-pipeline-runs/2026-04-12/R-BAR-BUNDLE-EXAMPLE/run-1.json"
            ),
            "--obligation",
            _OBLIGATION_ID,
            "--path",
            str(bar_fixture_repo),
            "--json",
        ],
        catch_exceptions=True,
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    expected_path = (
        "docs/verification/bar-pipeline-runs/2026-04-12/"
        "R-BAR-BUNDLE-EXAMPLE/audit-rerun.json"
    )
    assert data == {
        "obligation_id": _OBLIGATION_ID,
        "captured_aggregate_verdict": "pass",
        "rerun_aggregate_verdict": "pass",
        "verdict_match": True,
        "source_artifact": (
            "docs/verification/bar-pipeline-runs/2026-04-12/"
            "R-BAR-BUNDLE-EXAMPLE/run-1.json"
        ),
        "rerun_artifact": expected_path,
        "policy_version": "2026.04.12",
    }
    written_path = bar_fixture_repo / expected_path
    assert written_path.is_file()
    artifact = json.loads(written_path.read_text(encoding="utf-8"))
    assert artifact["stability_run_index"] == "audit"
    assert artifact["aggregate_verdict"] == "pass"


def test_bar_rerun_refuses_binding_mismatch(
    runner: CliRunner,
    bar_fixture_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import wardline.cli.bar_cmd as bar_cmd

    monkeypatch.setattr(bar_cmd, "_load_reviewer_adapter", lambda _model_pin: FakeReviewerAdapter())
    monkeypatch.setattr(bar_cmd, "_reviewed_at", lambda: _FIXED_REVIEWED_AT)

    review_result = runner.invoke(
        bar_cmd.bar,
        [
            "review",
            "--ledger",
            str(bar_fixture_repo / "wardline.compliance.json"),
            "--obligation",
            _OBLIGATION_ID,
            "--path",
            str(bar_fixture_repo),
            "--json",
        ],
        catch_exceptions=True,
    )
    assert review_result.exit_code == 0, review_result.output

    ledger_path = bar_fixture_repo / "wardline.compliance.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    reviewer_metadata = ledger["obligations"][0]["reviewer_metadata"]
    reviewer_metadata["independence"] = "bootstrap_attested"
    reviewer_metadata["review_pipeline"] = "wardline-bar-panel"
    reviewer_metadata["review_pipeline_version"] = "2026.04.12"
    reviewer_metadata["review_policy_hash"] = "sha256:wrong"
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")

    result = runner.invoke(
        bar_cmd.bar,
        [
            "rerun",
            "--ledger",
            str(ledger_path),
            "--artifact",
            str(
                bar_fixture_repo
                / "docs/verification/bar-pipeline-runs/2026-04-12/R-BAR-BUNDLE-EXAMPLE/run-1.json"
            ),
            "--obligation",
            _OBLIGATION_ID,
            "--path",
            str(bar_fixture_repo),
        ],
        catch_exceptions=True,
    )

    assert result.exit_code == 1
    assert "reviewer_metadata.review_policy_hash" in result.output


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
