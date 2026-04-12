"""BAR runner orchestration and prompt rendering."""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING

from wardline.bar.adapters import ReviewerResult
from wardline.bar.evidence import (
    build_bar_evidence_artifact,
    default_artifact_root,
    write_bar_evidence_artifact,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from wardline.bar.adapters import ReviewerAdapter
    from wardline.bar.models import BarReviewBundle, LoadedBarPolicy


@dataclass(frozen=True)
class BarReviewOutcome:
    """Structured BAR runner outcome returned to callers and future CLI code."""

    obligation_id: str
    final_verdict: str
    aggregate_verdicts: tuple[str, ...]
    stable: bool
    stability_reason: str
    recommended_state: str
    recommended_independence: str
    artifact_paths: tuple[Path, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "aggregate_verdicts", tuple(self.aggregate_verdicts))
        object.__setattr__(self, "artifact_paths", tuple(self.artifact_paths))


class BarRunnerError(Exception):
    """Raised when a BAR review cannot be run safely."""


def run_bar_review(
    bundle: BarReviewBundle,
    policy: LoadedBarPolicy,
    adapter: ReviewerAdapter,
    *,
    artifact_root: Path | None = None,
    reviewed_at_factory: Callable[[], datetime] | None = None,
    repo_root: Path | None = None,
) -> BarReviewOutcome:
    """Run the BAR self-assessment stability check for one obligation."""
    if reviewed_at_factory is None:
        reviewed_at_factory = _utc_now
    resolved_repo_root = repo_root if repo_root is not None else _repo_root_from_policy(policy)
    _ensure_review_commit_isolation(resolved_repo_root, bundle, policy)

    output_root = artifact_root if artifact_root is not None else default_artifact_root(resolved_repo_root)
    required_runs = int(getattr(policy.aggregation_module, "STABILITY_REQUIRED_RUNS", 3))

    run_verdicts: list[dict[str, str]] = []
    aggregate_verdicts: list[str] = []
    artifact_paths: list[Path] = []

    for run_index in range(1, required_runs + 1):
        started = time.perf_counter()
        reviewer_results = _run_panel_once(bundle, policy, adapter)
        aggregate_verdict = policy.aggregation_module.aggregate(
            {role: result.verdict for role, result in reviewer_results.items()}
        )
        run_verdicts.append({role: result.verdict for role, result in reviewer_results.items()})
        aggregate_verdicts.append(aggregate_verdict)

        artifact = build_bar_evidence_artifact(
            obligation_id=bundle.obligation_id,
            pipeline_name=policy.pipeline_name,
            pipeline_version=policy.version,
            policy_hash=policy.policy_hash,
            commit_ref=bundle.commit_ref,
            manifest_hash=bundle.manifest_hash,
            corpus_hash=bundle.corpus_hash,
            model_pin=dict(policy.model_pin),
            skill_pack=_skill_pack_identity(policy),
            reviewed_at=reviewed_at_factory(),
            stability_run_index=run_index,
            reviewer_results=reviewer_results,
            aggregate_verdict=aggregate_verdict,
            pipeline_duration_seconds=time.perf_counter() - started,
        )
        artifact_paths.append(write_bar_evidence_artifact(artifact, artifact_root=output_root))

    stable, stability_reason = policy.aggregation_module.check_stability(run_verdicts)
    final_verdict, recommended_state, recommended_independence = _summarize_outcome(
        aggregate_verdicts=tuple(aggregate_verdicts),
        stable=stable,
    )
    return BarReviewOutcome(
        obligation_id=bundle.obligation_id,
        final_verdict=final_verdict,
        aggregate_verdicts=tuple(aggregate_verdicts),
        stable=stable,
        stability_reason=stability_reason,
        recommended_state=recommended_state,
        recommended_independence=recommended_independence,
        artifact_paths=tuple(artifact_paths),
    )


def run_bar_audit_rerun(
    bundle: BarReviewBundle,
    policy: LoadedBarPolicy,
    adapter: ReviewerAdapter,
    *,
    artifact_root: Path | None = None,
    reviewed_at_factory: Callable[[], datetime] | None = None,
    repo_root: Path | None = None,
) -> BarReviewOutcome:
    """Run the single assessor re-run path and write ``audit-rerun.json``."""
    if reviewed_at_factory is None:
        reviewed_at_factory = _utc_now
    resolved_repo_root = repo_root if repo_root is not None else _repo_root_from_policy(policy)
    _ensure_review_commit_isolation(resolved_repo_root, bundle, policy)

    output_root = artifact_root if artifact_root is not None else default_artifact_root(resolved_repo_root)
    started = time.perf_counter()
    reviewer_results = _run_panel_once(bundle, policy, adapter)
    aggregate_verdict = policy.aggregation_module.aggregate(
        {role: result.verdict for role, result in reviewer_results.items()}
    )
    artifact = build_bar_evidence_artifact(
        obligation_id=bundle.obligation_id,
        pipeline_name=policy.pipeline_name,
        pipeline_version=policy.version,
        policy_hash=policy.policy_hash,
        commit_ref=bundle.commit_ref,
        manifest_hash=bundle.manifest_hash,
        corpus_hash=bundle.corpus_hash,
        model_pin=dict(policy.model_pin),
        skill_pack=_skill_pack_identity(policy),
        reviewed_at=reviewed_at_factory(),
        stability_run_index="audit",
        reviewer_results=reviewer_results,
        aggregate_verdict=aggregate_verdict,
        pipeline_duration_seconds=time.perf_counter() - started,
    )
    artifact_path = write_bar_evidence_artifact(artifact, artifact_root=output_root)

    final_verdict, recommended_state, recommended_independence = _summarize_outcome(
        aggregate_verdicts=(aggregate_verdict,),
        stable=True,
    )
    return BarReviewOutcome(
        obligation_id=bundle.obligation_id,
        final_verdict=final_verdict,
        aggregate_verdicts=(aggregate_verdict,),
        stable=True,
        stability_reason="audit rerun executes a single panel run",
        recommended_state=recommended_state,
        recommended_independence=recommended_independence,
        artifact_paths=(artifact_path,),
    )


def build_reviewer_prompt(bundle: BarReviewBundle, policy: LoadedBarPolicy, role: str) -> str:
    """Render one reviewer prompt from the active BAR policy tree."""
    shared_preamble = _read_text(policy.root / "shared-preamble.md")
    role_spec = _read_text(policy.root / "persona-specs" / f"{role}.md")
    role_instructions, prompt_template = _split_role_spec(role_spec, role=role)

    prompt_context = {
        "obligation_id": bundle.obligation_id,
        "obligation_record_json": json.dumps(_thaw_value(bundle.obligation_record), indent=2, ensure_ascii=False),
        "source_refs_content": _format_source_refs(bundle),
        "implementation_surface_content": _format_implementation_surface(bundle),
        "evidence_class_outputs": _format_evidence_outputs(bundle),
        "allowed_citations_content": _format_allowed_citations(bundle),
        "commit_ref": bundle.commit_ref,
        "manifest_hash": bundle.manifest_hash,
        "corpus_hash": bundle.corpus_hash,
        "policy_hash": bundle.policy_hash,
        "pipeline_version": policy.version,
        "skill_pack_id": policy.skill_pack.skill_pack_id,
        "skill_pack_version": policy.skill_pack.skill_pack_version,
        "model_pin_json": json.dumps(dict(policy.model_pin), indent=2, ensure_ascii=False),
    }
    rendered_skill_pack = _render_prompt_text(
        policy.skill_pack.content,
        prompt_context=prompt_context,
        label=f"BAR skill pack {policy.skill_pack.skill_pack_id!r}",
    )
    rendered_prompt_template = _render_prompt_text(
        prompt_template,
        prompt_context=prompt_context,
        label=f"BAR role specification for {role!r}",
    )

    return (
        f"{shared_preamble}\n\n"
        f"{rendered_skill_pack}\n\n"
        f"{role_instructions}\n\n"
        f"{rendered_prompt_template}\n\n"
        "Model pin:\n"
        f"{prompt_context['model_pin_json']}\n"
    )


def _run_panel_once(
    bundle: BarReviewBundle,
    policy: LoadedBarPolicy,
    adapter: ReviewerAdapter,
) -> dict[str, ReviewerResult]:
    allowed_citation_tokens = _allowed_citation_tokens(bundle)
    results: dict[str, ReviewerResult] = {}
    for role in policy.panel_roles:
        prompt = build_reviewer_prompt(bundle, policy, role)
        raw_result = adapter.review(
            role=role,
            prompt=prompt,
            model_pin=dict(policy.model_pin),
        )
        results[role] = _normalize_reviewer_result(
            raw_result,
            allowed_citation_tokens=allowed_citation_tokens,
        )
    return results


def _skill_pack_identity(policy: LoadedBarPolicy) -> dict[str, object]:
    return {
        "skill_pack_id": policy.skill_pack.skill_pack_id,
        "skill_pack_version": policy.skill_pack.skill_pack_version,
        "assets": list(policy.skill_pack.assets),
    }


def _summarize_outcome(
    *,
    aggregate_verdicts: tuple[str, ...],
    stable: bool,
) -> tuple[str, str, str]:
    final_verdict = aggregate_verdicts[0] if stable else "insufficient_evidence"

    if final_verdict == "pass":
        return (final_verdict, "verified", "bootstrap_attested")
    if final_verdict == "fail":
        return (final_verdict, "non_compliant", "pending")
    if final_verdict == "refer":
        return (final_verdict, "unassessed", "pending")
    return (final_verdict, "implemented_no_evidence", "pending")


def _format_source_refs(bundle: BarReviewBundle) -> str:
    chunks = []
    for source_ref in bundle.source_refs_content:
        chunks.append(
            "\n".join(
                [
                    f"Source ref: {source_ref.source_ref}",
                    f"Path: {source_ref.path}",
                    f"Selector: {source_ref.selector}",
                    source_ref.excerpt,
                ]
            )
        )
    return "\n\n---\n\n".join(chunks)


def _format_implementation_surface(bundle: BarReviewBundle) -> str:
    chunks = []
    for entry in bundle.implementation_surface_content:
        chunks.append(
            "\n".join(
                [
                    f"Path: {entry.path}",
                    entry.content,
                ]
            )
        )
    return "\n\n---\n\n".join(chunks)


def _format_evidence_outputs(bundle: BarReviewBundle) -> str:
    chunks = []
    for evidence in bundle.evidence_class_outputs:
        lines = [
            f"Class: {evidence.class_name}",
            f"Target: {evidence.target}",
            f"Status: {evidence.status}",
            f"Mode: {evidence.mode}",
            f"Summary: {evidence.summary}",
        ]
        if evidence.note is not None:
            lines.append(f"Note: {evidence.note}")
        if evidence.command:
            lines.append(f"Command: {' '.join(evidence.command)}")
        if evidence.exit_code is not None:
            lines.append(f"Exit code: {evidence.exit_code}")
        if evidence.content:
            lines.extend(["Content:", evidence.content])
        chunks.append("\n".join(lines))
    return "\n\n---\n\n".join(chunks)


def _allowed_citation_tokens(bundle: BarReviewBundle) -> tuple[str, ...]:
    tokens: list[str] = []
    seen: set[str] = set()

    def add(token: str) -> None:
        if token and token not in seen:
            tokens.append(token)
            seen.add(token)

    for source_ref in bundle.source_refs_content:
        add(f"source_ref:{source_ref.selector}")
        add(source_ref.path)
    for entry in bundle.implementation_surface_content:
        add(entry.path)
    for evidence in bundle.evidence_class_outputs:
        add(f"evidence_class_outputs:{evidence.class_name}")
        add(f"evidence_class_outputs:{evidence.class_name}:{evidence.target}")

    return tuple(tokens)


def _format_allowed_citations(bundle: BarReviewBundle) -> str:
    tokens = _allowed_citation_tokens(bundle)
    return "\n".join(f"- `{token}`" for token in tokens)


def _normalize_reviewer_result(
    result: ReviewerResult,
    *,
    allowed_citation_tokens: tuple[str, ...],
) -> ReviewerResult:
    allowed = set(allowed_citation_tokens)
    normalized_citations: list[str] = []
    seen: set[str] = set()
    for citation in result.citations:
        if citation in allowed and citation not in seen:
            normalized_citations.append(citation)
            seen.add(citation)

    if result.verdict in {"pass", "fail"} and not normalized_citations:
        return ReviewerResult(
            verdict="insufficient_evidence",
            rationale=(
                "BAR runner invalidated a strong verdict because no valid allowed citation "
                "tokens were present in the CITATIONS section."
            ),
            citations=(),
            raw_citations=result.raw_citations,
            raw_response=result.raw_response,
        )

    if tuple(normalized_citations) == result.citations:
        return result
    return ReviewerResult(
        verdict=result.verdict,
        rationale=result.rationale,
        citations=tuple(normalized_citations),
        raw_citations=result.raw_citations,
        raw_response=result.raw_response,
    )


def _ensure_review_commit_isolation(repo_root: Path, bundle: BarReviewBundle, policy: LoadedBarPolicy) -> None:
    try:
        changed_paths = _changed_paths_for_commit(repo_root, bundle.commit_ref)
    except OSError as exc:
        raise BarRunnerError(f"unable to inspect reviewed commit {bundle.commit_ref}: {exc}") from exc

    try:
        policy_relpath = policy.root.relative_to(repo_root).as_posix()
    except ValueError:
        return
    touches_policy = any(path == policy_relpath or path.startswith(f"{policy_relpath}/") for path in changed_paths)
    implementation_paths = [entry.path for entry in bundle.implementation_surface_content]
    touches_implementation = any(path in implementation_paths for path in changed_paths)

    if touches_policy and touches_implementation:
        raise BarRunnerError(
            "BAR review commit violates author-isolation: the reviewed commit modifies both "
            "the active BAR policy tree and the obligation implementation surface."
        )


def _changed_paths_for_commit(repo_root: Path, commit_ref: str) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit_ref],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise OSError(result.stderr.strip())
    return tuple(line.strip() for line in result.stdout.splitlines() if line.strip())


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BarRunnerError(f"unable to read BAR prompt asset {path}: {exc}") from exc


def _render_prompt_text(template: str, *, prompt_context: Mapping[str, object], label: str) -> str:
    try:
        return template.format(**prompt_context)
    except KeyError as exc:
        raise BarRunnerError(f"{label} referenced missing placeholder {exc}") from exc


def _split_role_spec(role_spec: str, *, role: str) -> tuple[str, str]:
    marker = "## Prompt template"
    marker_index = role_spec.find(marker)
    if marker_index == -1:
        raise BarRunnerError(f"BAR role specification for {role!r} is missing a prompt template section")

    role_instructions = role_spec[:marker_index].strip()
    template_section = role_spec[marker_index + len(marker):]
    match = re.search(r"```(?:[A-Za-z0-9_-]+)?\n(.*?)\n```", template_section, flags=re.DOTALL)
    if match is None:
        raise BarRunnerError(f"BAR role specification for {role!r} is missing a fenced prompt template block")
    return (role_instructions, match.group(1).strip())


def _repo_root_from_policy(policy: LoadedBarPolicy) -> Path:
    return policy.root.parents[3]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _thaw_value(value: object) -> object:
    if isinstance(value, MappingProxyType):
        return {key: _thaw_value(inner) for key, inner in value.items()}
    if isinstance(value, tuple):
        return [_thaw_value(inner) for inner in value]
    return value
