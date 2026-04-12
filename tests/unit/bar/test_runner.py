"""Tests for BAR runner execution."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from wardline.bar import assemble_review_bundle, build_reviewer_prompt, load_policy_tree
from wardline.bar.adapters import ReviewerResult
from wardline.bar.runner import run_bar_review

if TYPE_CHECKING:
    from pathlib import Path


_POLICY_VERSION = "2026.04.12"
_FIXTURE_OBLIGATION_ID = "R-BAR-BUNDLE-EXAMPLE"
_FIXED_REVIEWED_AT = datetime(2026, 4, 12, 8, 30, tzinfo=UTC)


class FakeReviewerAdapter:
    """Deterministic fake BAR reviewer adapter for unit tests."""

    def __init__(
        self,
        *,
        panel_roles: tuple[str, ...],
        run_results: list[dict[str, ReviewerResult]],
    ) -> None:
        self._panel_roles = panel_roles
        self._run_results = run_results
        self.calls: list[dict[str, object]] = []
        self._call_count = 0

    def review(self, *, role: str, prompt: str, model_pin: dict[str, object]) -> ReviewerResult:
        run_index = self._call_count // len(self._panel_roles)
        self._call_count += 1
        self.calls.append(
            {
                "role": role,
                "prompt": prompt,
                "model_pin": model_pin,
            }
        )
        return self._run_results[run_index][role]


def test_runner_executes_all_seven_roles_for_three_runs(bar_fixture_repo: Path, tmp_path: Path) -> None:
    policy = load_policy_tree(_POLICY_VERSION)
    bundle = _build_bundle(bar_fixture_repo, policy.policy_hash)
    adapter = FakeReviewerAdapter(
        panel_roles=policy.panel_roles,
        run_results=[_pass_results(policy.panel_roles) for _ in range(3)],
    )

    outcome = run_bar_review(
        bundle,
        policy,
        adapter,
        artifact_root=tmp_path,
        reviewed_at_factory=lambda: _FIXED_REVIEWED_AT,
        repo_root=bar_fixture_repo,
    )

    assert len(adapter.calls) == len(policy.panel_roles) * 3
    assert sorted(call["role"] for call in adapter.calls[: len(policy.panel_roles)]) == sorted(policy.panel_roles)
    assert outcome.final_verdict == "pass"
    assert outcome.recommended_state == "verified"
    assert outcome.recommended_independence == "bootstrap_attested"
    assert outcome.stable is True
    assert outcome.aggregate_verdicts == ("pass", "pass", "pass")


def test_runner_uses_policy_aggregation_module(
    bar_fixture_repo: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    policy = load_policy_tree(_POLICY_VERSION)
    bundle = _build_bundle(bar_fixture_repo, policy.policy_hash)
    adapter = FakeReviewerAdapter(
        panel_roles=policy.panel_roles,
        run_results=[_pass_results(policy.panel_roles) for _ in range(3)],
    )

    aggregate_calls: list[dict[str, str]] = []
    stability_calls = 0
    original_aggregate = policy.aggregation_module.aggregate
    original_check_stability = policy.aggregation_module.check_stability

    def tracking_aggregate(reviewer_verdicts: dict[str, str]) -> str:
        aggregate_calls.append(dict(reviewer_verdicts))
        return original_aggregate(reviewer_verdicts)

    def tracking_check_stability(run_verdicts: list[dict[str, str]]) -> tuple[bool, str]:
        nonlocal stability_calls
        stability_calls += 1
        return original_check_stability(run_verdicts)

    monkeypatch.setattr(policy.aggregation_module, "aggregate", tracking_aggregate)
    monkeypatch.setattr(policy.aggregation_module, "check_stability", tracking_check_stability)

    outcome = run_bar_review(
        bundle,
        policy,
        adapter,
        artifact_root=tmp_path,
        reviewed_at_factory=lambda: _FIXED_REVIEWED_AT,
        repo_root=bar_fixture_repo,
    )

    assert outcome.final_verdict == "pass"
    assert stability_calls == 1
    assert len(aggregate_calls) >= 3
    assert all(set(call.keys()) == set(policy.panel_roles) for call in aggregate_calls[:3])


def test_runner_writes_run_artefacts_with_run_specific_paths(
    bar_fixture_repo: Path,
    tmp_path: Path,
) -> None:
    policy = load_policy_tree(_POLICY_VERSION)
    bundle = _build_bundle(bar_fixture_repo, policy.policy_hash)
    adapter = FakeReviewerAdapter(
        panel_roles=policy.panel_roles,
        run_results=[_pass_results(policy.panel_roles) for _ in range(3)],
    )

    outcome = run_bar_review(
        bundle,
        policy,
        adapter,
        artifact_root=tmp_path,
        reviewed_at_factory=lambda: _FIXED_REVIEWED_AT,
        repo_root=bar_fixture_repo,
    )

    expected_dir = tmp_path / "2026-04-12" / bundle.obligation_id
    assert outcome.artifact_paths == (
        expected_dir / "run-1.json",
        expected_dir / "run-2.json",
        expected_dir / "run-3.json",
    )
    for expected_path in outcome.artifact_paths:
        assert expected_path.is_file()

    data = json.loads((expected_dir / "run-1.json").read_text(encoding="utf-8"))
    assert data["obligation_id"] == bundle.obligation_id
    assert data["pipeline_name"] == policy.pipeline_name
    assert data["pipeline_version"] == policy.version
    assert data["policy_hash"] == policy.policy_hash
    assert data["skill_pack"] == {
        "skill_pack_id": "wardline.bar.panel.core",
        "skill_pack_version": policy.version,
        "assets": [
            "skill-pack/shared-discipline.md",
            "skill-pack/citation-contract.md",
        ],
    }
    assert data["stability_run_index"] == 1
    assert data["aggregate_verdict"] == "pass"
    assert list(data["reviewer_verdicts"].keys()) == list(policy.panel_roles)
    assert data["reviewer_verdicts"]["python-engineer"]["citation_validation"] == {
        "raw_citations": [
            "src/example_impl.py",
            "source_ref:§15.2(5)",
        ],
        "dropped_citations": [],
    }


def test_runner_refuses_unstable_pass(bar_fixture_repo: Path, tmp_path: Path) -> None:
    policy = load_policy_tree(_POLICY_VERSION)
    bundle = _build_bundle(bar_fixture_repo, policy.policy_hash)

    unstable_results = [
        _pass_results(policy.panel_roles),
        _pass_results(policy.panel_roles),
        _pass_results(
            policy.panel_roles,
            override={
                "security-architect": ReviewerResult(
                    verdict="fail",
                    rationale="Contradiction.",
                    citations=("src/example_impl.py",),
                )
            },
        ),
    ]
    adapter = FakeReviewerAdapter(panel_roles=policy.panel_roles, run_results=unstable_results)

    outcome = run_bar_review(
        bundle,
        policy,
        adapter,
        artifact_root=tmp_path,
        reviewed_at_factory=lambda: _FIXED_REVIEWED_AT,
        repo_root=bar_fixture_repo,
    )

    assert outcome.stable is False
    assert outcome.final_verdict == "insufficient_evidence"
    assert outcome.recommended_state == "implemented_no_evidence"
    assert outcome.recommended_independence == "pending"
    assert "aggregate mismatch" in outcome.stability_reason


def test_runner_returns_non_compliant_when_any_role_fails(bar_fixture_repo: Path, tmp_path: Path) -> None:
    policy = load_policy_tree(_POLICY_VERSION)
    bundle = _build_bundle(bar_fixture_repo, policy.policy_hash)
    fail_result = ReviewerResult(
        verdict="fail",
        rationale="The implementation contradicts the obligation.",
        citations=("src/example_impl.py",),
    )
    adapter = FakeReviewerAdapter(
        panel_roles=policy.panel_roles,
        run_results=[
            _pass_results(policy.panel_roles, override={"python-engineer": fail_result})
            for _ in range(3)
        ],
    )

    outcome = run_bar_review(
        bundle,
        policy,
        adapter,
        artifact_root=tmp_path,
        reviewed_at_factory=lambda: _FIXED_REVIEWED_AT,
        repo_root=bar_fixture_repo,
    )

    assert outcome.stable is True
    assert outcome.final_verdict == "fail"
    assert outcome.recommended_state == "non_compliant"
    assert outcome.recommended_independence == "pending"


def test_runner_persists_only_allowed_citation_tokens(bar_fixture_repo: Path, tmp_path: Path) -> None:
    policy = load_policy_tree(_POLICY_VERSION)
    bundle = _build_bundle(bar_fixture_repo, policy.policy_hash)
    adapter = FakeReviewerAdapter(
        panel_roles=policy.panel_roles,
        run_results=[
            _pass_results(
                policy.panel_roles,
                override={
                    "python-engineer": ReviewerResult(
                        verdict="pass",
                        rationale=(
                            "Satisfied by `src/example_impl.py` and `source_ref:§15.2(5)` "
                            "with extra noise."
                        ),
                        citations=(
                            "src/example_impl.py",
                            "source_ref:§15.2(5)",
                            "free-form prose fragment",
                            "wardline.compliance.json",
                        ),
                    )
                },
            )
            for _ in range(3)
        ],
    )

    outcome = run_bar_review(
        bundle,
        policy,
        adapter,
        artifact_root=tmp_path,
        reviewed_at_factory=lambda: _FIXED_REVIEWED_AT,
        repo_root=bar_fixture_repo,
    )

    assert outcome.final_verdict == "pass"
    artifact = json.loads(outcome.artifact_paths[0].read_text(encoding="utf-8"))
    assert artifact["reviewer_verdicts"]["python-engineer"]["citations"] == [
        "src/example_impl.py",
        "source_ref:§15.2(5)",
    ]
    assert artifact["reviewer_verdicts"]["python-engineer"]["citation_validation"] == {
        "raw_citations": [
            "src/example_impl.py",
            "source_ref:§15.2(5)",
            "free-form prose fragment",
            "wardline.compliance.json",
        ],
        "dropped_citations": [
            "free-form prose fragment",
            "wardline.compliance.json",
        ],
    }


def test_runner_downgrades_pass_without_valid_citations(bar_fixture_repo: Path, tmp_path: Path) -> None:
    policy = load_policy_tree(_POLICY_VERSION)
    bundle = _build_bundle(bar_fixture_repo, policy.policy_hash)
    adapter = FakeReviewerAdapter(
        panel_roles=policy.panel_roles,
        run_results=[
            _pass_results(
                policy.panel_roles,
                override={
                    "python-engineer": ReviewerResult(
                        verdict="pass",
                        rationale="Claims success without grounded citations.",
                        citations=("src/example_impl.py:3", "free-form prose fragment"),
                    )
                },
            )
            for _ in range(3)
        ],
    )

    outcome = run_bar_review(
        bundle,
        policy,
        adapter,
        artifact_root=tmp_path,
        reviewed_at_factory=lambda: _FIXED_REVIEWED_AT,
        repo_root=bar_fixture_repo,
    )

    assert outcome.final_verdict == "insufficient_evidence"
    artifact = json.loads(outcome.artifact_paths[0].read_text(encoding="utf-8"))
    assert artifact["reviewer_verdicts"]["python-engineer"]["verdict"] == "insufficient_evidence"
    assert artifact["reviewer_verdicts"]["python-engineer"]["citations"] == []
    assert artifact["reviewer_verdicts"]["python-engineer"]["citation_validation"] == {
        "raw_citations": [
            "src/example_impl.py:3",
            "free-form prose fragment",
        ],
        "dropped_citations": [
            "src/example_impl.py:3",
            "free-form prose fragment",
        ],
    }


def test_runner_downgrades_fail_without_valid_citations(bar_fixture_repo: Path, tmp_path: Path) -> None:
    policy = load_policy_tree(_POLICY_VERSION)
    bundle = _build_bundle(bar_fixture_repo, policy.policy_hash)
    adapter = FakeReviewerAdapter(
        panel_roles=policy.panel_roles,
        run_results=[
            _pass_results(
                policy.panel_roles,
                override={
                    "python-engineer": ReviewerResult(
                        verdict="fail",
                        rationale="Claims contradiction without grounded citations.",
                        citations=("src/example_impl.py:3", "free-form prose fragment"),
                    )
                },
            )
            for _ in range(3)
        ],
    )

    outcome = run_bar_review(
        bundle,
        policy,
        adapter,
        artifact_root=tmp_path,
        reviewed_at_factory=lambda: _FIXED_REVIEWED_AT,
        repo_root=bar_fixture_repo,
    )

    assert outcome.final_verdict == "insufficient_evidence"
    artifact = json.loads(outcome.artifact_paths[0].read_text(encoding="utf-8"))
    assert artifact["reviewer_verdicts"]["python-engineer"]["verdict"] == "insufficient_evidence"
    assert artifact["reviewer_verdicts"]["python-engineer"]["citations"] == []
    assert artifact["reviewer_verdicts"]["python-engineer"]["citation_validation"] == {
        "raw_citations": [
            "src/example_impl.py:3",
            "free-form prose fragment",
        ],
        "dropped_citations": [
            "src/example_impl.py:3",
            "free-form prose fragment",
        ],
    }


def test_build_reviewer_prompt_injects_skill_pack_and_allowed_citations(bar_fixture_repo: Path) -> None:
    policy = load_policy_tree(_POLICY_VERSION)
    bundle = _build_bundle(bar_fixture_repo, policy.policy_hash)

    prompt = build_reviewer_prompt(bundle, policy, "python-engineer")

    assert "BAR skill pack — shared discipline" in prompt
    assert "BAR skill pack — citation contract" in prompt
    assert "Allowed citation tokens for this review:" in prompt
    assert "`source_ref:§15.2(5)`" in prompt
    assert "`src/example_impl.py`" in prompt
    assert "`evidence_class_outputs:unit_tests`" in prompt


def _build_bundle(repo_root: Path, policy_hash: str):
    return assemble_review_bundle(
        repo_root=repo_root,
        ledger_path=repo_root / "wardline.compliance.json",
        obligation_id=_FIXTURE_OBLIGATION_ID,
        policy_hash=policy_hash,
    )


def _pass_results(
    panel_roles: tuple[str, ...],
    *,
    override: dict[str, ReviewerResult] | None = None,
) -> dict[str, ReviewerResult]:
    results = {
        role: ReviewerResult(
            verdict="pass",
            rationale=f"{role} found the obligation satisfied.",
            citations=("src/example_impl.py", "source_ref:§15.2(5)"),
        )
        for role in panel_roles
    }
    if override is not None:
        results.update(override)
    return results
