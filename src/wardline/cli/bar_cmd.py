"""wardline bar review / wardline bar rerun — BAR runner CLI."""

from __future__ import annotations

import importlib
import json as json_mod
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import click

from wardline.bar.adapters import LiteLLMReviewerAdapter
from wardline.bar.evidence import (
    BarEvidenceArtifact,
    BarEvidenceArtifactError,
    load_bar_evidence_artifact,
)
from wardline.bar.inputs import BarInputError, assemble_review_bundle
from wardline.bar.ledger import BarLedgerError, load_obligation_from_compliance_ledger
from wardline.bar.policy import (
    BarPolicyError,
    describe_policy_runtime,
    load_policy_tree,
    provider_name_for_model_id,
)
from wardline.bar.runner import (
    BarReviewOutcome,
    BarRunnerError,
    run_bar_audit_rerun,
    run_bar_review,
)
from wardline.cli._helpers import cli_error

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.bar.adapters import ReviewerAdapter
    from wardline.bar.models import BarReviewBundle


@dataclass(frozen=True)
class BarRerunVerification:
    """Outcome of verifying a BAR audit rerun against a prior artefact."""

    obligation_id: str
    captured_aggregate_verdict: str
    rerun_aggregate_verdict: str
    verdict_match: bool
    source_artifact_path: Path
    rerun_artifact_path: Path


@click.group()
def bar() -> None:
    """Bootstrap Assurance Reference review runner."""


@bar.command("status")
@click.option("--policy-version", help="Explicit BAR policy version to load.")
@click.option("--json", "output_json", is_flag=True, help="JSON output.")
def status(
    policy_version: str | None,
    output_json: bool,
) -> None:
    """Show the active BAR runtime configuration."""
    try:
        policy = load_policy_tree(policy_version)
    except BarPolicyError as exc:
        cli_error(str(exc))
        sys.exit(1)

    runtime = describe_policy_runtime(policy)
    if output_json:
        click.echo(json_mod.dumps(runtime, indent=2))
    else:
        _status_text(runtime)


@bar.command("review")
@click.option("--ledger", type=click.Path(exists=True), required=True, help="Path to wardline.compliance.json.")
@click.option("--obligation", required=True, help="Compliance-ledger obligation ID to review.")
@click.option("--policy-version", help="Explicit BAR policy version to load.")
@click.option("--path", "project_path", type=click.Path(exists=True), required=True, help="Project root to review.")
@click.option("--json", "output_json", is_flag=True, help="JSON output.")
def review(
    ledger: str,
    obligation: str,
    policy_version: str | None,
    project_path: str,
    output_json: bool,
) -> None:
    """Run the three-pass BAR self-assessment pipeline."""
    project_root = Path(project_path).resolve()
    ledger_path = Path(ledger).resolve()

    try:
        policy = load_policy_tree(policy_version)
        bundle = assemble_review_bundle(
            repo_root=project_root,
            ledger_path=ledger_path,
            obligation_id=obligation,
            policy_hash=policy.policy_hash,
        )
        outcome = run_bar_review(
            bundle,
            policy,
            _load_reviewer_adapter(policy.model_pin),
            reviewed_at_factory=_reviewed_at,
            repo_root=project_root,
        )
    except (BarPolicyError, BarInputError, BarRunnerError, BarEvidenceArtifactError, BarLedgerError) as exc:
        cli_error(str(exc))
        sys.exit(1)

    if output_json:
        _review_json(project_root, policy.version, outcome)
    else:
        _review_text(project_root, policy.version, outcome)


@bar.command("rerun")
@click.option("--ledger", type=click.Path(exists=True), required=True, help="Path to wardline.compliance.json.")
@click.option("--artifact", type=click.Path(exists=True), required=True, help="Path to a prior BAR evidence artefact.")
@click.option("--obligation", required=True, help="Compliance-ledger obligation ID to re-run.")
@click.option("--policy-version", help="Explicit BAR policy version to load.")
@click.option("--path", "project_path", type=click.Path(exists=True), required=True, help="Project root to review.")
@click.option("--json", "output_json", is_flag=True, help="JSON output.")
def rerun(
    ledger: str,
    artifact: str,
    obligation: str,
    policy_version: str | None,
    project_path: str,
    output_json: bool,
) -> None:
    """Run the single assessor BAR re-run path."""
    project_root = Path(project_path).resolve()
    ledger_path = Path(ledger).resolve()
    artifact_path = Path(artifact).resolve()

    try:
        prior_artifact = load_bar_evidence_artifact(artifact_path)
        if prior_artifact.obligation_id != obligation:
            raise BarRunnerError(
                "BAR rerun obligation mismatch: "
                f"artifact records {prior_artifact.obligation_id!r} but CLI requested {obligation!r}"
            )

        policy = load_policy_tree(policy_version or prior_artifact.pipeline_version)
        if policy.version != prior_artifact.pipeline_version:
            raise BarRunnerError(
                "BAR rerun must load the same policy version captured by the prior artefact: "
                f"expected {prior_artifact.pipeline_version!r}, got {policy.version!r}"
            )
        if policy.policy_hash != prior_artifact.policy_hash:
            raise BarRunnerError(
                "BAR rerun policy hash mismatch: "
                f"artifact records {prior_artifact.policy_hash!r}, active policy resolved to {policy.policy_hash!r}"
            )

        raw_obligation = load_obligation_from_compliance_ledger(ledger_path, obligation)
        bundle = assemble_review_bundle(
            repo_root=project_root,
            ledger_path=ledger_path,
            obligation_id=obligation,
            policy_hash=policy.policy_hash,
        )
        _validate_rerun_binding(
            prior_artifact=prior_artifact,
            raw_obligation=raw_obligation,
            bundle=bundle,
        )
        outcome = run_bar_audit_rerun(
            bundle,
            policy,
            _load_reviewer_adapter(policy.model_pin),
            reviewed_at_factory=_reviewed_at,
            repo_root=project_root,
        )
        verification = BarRerunVerification(
            obligation_id=obligation,
            captured_aggregate_verdict=prior_artifact.aggregate_verdict,
            rerun_aggregate_verdict=outcome.final_verdict,
            verdict_match=prior_artifact.aggregate_verdict == outcome.final_verdict,
            source_artifact_path=artifact_path,
            rerun_artifact_path=outcome.artifact_paths[0],
        )
    except (BarPolicyError, BarInputError, BarRunnerError, BarEvidenceArtifactError) as exc:
        cli_error(str(exc))
        sys.exit(1)

    if output_json:
        _rerun_json(project_root, policy.version, verification)
    else:
        _rerun_text(project_root, policy.version, verification)

    if not verification.verdict_match:
        sys.exit(1)


def _load_reviewer_adapter(model_pin: Mapping[str, object]) -> ReviewerAdapter:
    try:
        litellm_module = importlib.import_module("litellm")
    except ImportError as exc:
        raise BarRunnerError(
            "BAR review requires the optional 'bar' dependency group "
            "(for example: uv sync --extra bar)."
        ) from exc

    model_id = str(model_pin["model_id"])
    provider = _provider_name(litellm_module, model_id)
    credential_env = _credential_env_for_provider(provider)
    if credential_env is not None and not os.getenv(credential_env):
        raise BarRunnerError(
            "BAR review requires provider credentials for the configured BAR model. "
            f"For the current model pin, set {credential_env}."
        )

    completion = getattr(litellm_module, "completion", None)
    if not callable(completion):
        raise BarRunnerError("installed litellm package does not expose completion(...)")
    return LiteLLMReviewerAdapter(completion)


def _provider_name(litellm_module: object, model_id: str) -> str | None:
    get_llm_provider = getattr(litellm_module, "get_llm_provider", None)
    if callable(get_llm_provider):
        try:
            _resolved_model, provider, _dynamic_api_key, _api_base = get_llm_provider(model_id)
            return None if provider is None else str(provider)
        except Exception:
            pass
    return provider_name_for_model_id(model_id)


def _credential_env_for_provider(provider: str | None) -> str | None:
    if provider == "openrouter":
        return "OPENROUTER_API_KEY"
    if provider == "anthropic":
        return "ANTHROPIC_API_KEY"
    if provider == "openai":
        return "OPENAI_API_KEY"
    return None


def _reviewed_at() -> datetime:
    return datetime.now(UTC)


def _status_text(runtime: Mapping[str, object]) -> None:
    skill_pack = _mapping_value(runtime, "skill_pack")
    model = _mapping_value(runtime, "model")
    guardrails = _mapping_value(runtime, "guardrails")

    click.echo("Wardline BAR Status")
    click.echo("\u2500" * 19)
    click.echo()
    click.echo(f"Pipeline:               {runtime['pipeline_name']}")
    click.echo(f"Policy version:         {runtime['policy_version']}")
    click.echo(f"Policy hash:            {runtime['policy_hash']}")
    click.echo(
        "Skill pack:             "
        f"{skill_pack['skill_pack_id']} @ {skill_pack['skill_pack_version']}"
    )
    click.echo("Skill-pack assets:")
    for asset in _list_value(skill_pack, "assets"):
        click.echo(f"  {asset}")
    provider = model.get("provider") or "unknown"
    click.echo(f"Model provider:         {provider}")
    click.echo(f"Model id:               {model.get('model_id')}")
    click.echo(f"Temperature:            {model.get('temperature')}")
    click.echo(f"Top-p:                  {model.get('top_p')}")
    click.echo(f"Seed:                   {_format_scalar(model.get('seed'))}")
    click.echo(f"Max output tokens:      {model.get('max_output_tokens')}")
    click.echo(f"Timeout seconds:        {guardrails.get('timeout_seconds')}")
    click.echo(f"Max retries:            {guardrails.get('max_retries')}")


def _review_text(project_root: Path, policy_version: str, outcome: BarReviewOutcome) -> None:
    click.echo("Wardline BAR Review")
    click.echo("\u2500" * 19)
    click.echo()
    click.echo(f"Obligation:             {outcome.obligation_id}")
    click.echo(f"Policy version:         {policy_version}")
    click.echo(f"Aggregate verdict:      {outcome.final_verdict}")
    click.echo(f"Stable:                 {'yes' if outcome.stable else 'no'}")
    click.echo(f"Stability reason:       {_stability_reason(outcome)}")
    click.echo(f"Recommended state:      {outcome.recommended_state}")
    click.echo(f"Recommended independence: {outcome.recommended_independence}")
    click.echo("Artefacts:")
    for artifact_path in outcome.artifact_paths:
        click.echo(f"  {_display_path(project_root, artifact_path)}")


def _review_json(project_root: Path, policy_version: str, outcome: BarReviewOutcome) -> None:
    click.echo(
        json_mod.dumps(
            {
                "obligation_id": outcome.obligation_id,
                "aggregate_verdict": outcome.final_verdict,
                "stable": outcome.stable,
                "stability_reason": _stability_reason(outcome),
                "recommended_state": outcome.recommended_state,
                "recommended_independence": outcome.recommended_independence,
                "artifacts": [
                    _display_path(project_root, artifact_path)
                    for artifact_path in outcome.artifact_paths
                ],
                "policy_version": policy_version,
            },
            indent=2,
        )
    )


def _rerun_text(project_root: Path, policy_version: str, verification: BarRerunVerification) -> None:
    click.echo("Wardline BAR Audit Rerun")
    click.echo("\u2500" * 24)
    click.echo()
    click.echo(f"Obligation:             {verification.obligation_id}")
    click.echo(f"Policy version:         {policy_version}")
    click.echo(f"Captured verdict:       {verification.captured_aggregate_verdict}")
    click.echo(f"Rerun verdict:          {verification.rerun_aggregate_verdict}")
    click.echo(f"Verdict match:          {'yes' if verification.verdict_match else 'no'}")
    click.echo(f"Source artefact:        {_display_path(project_root, verification.source_artifact_path)}")
    click.echo(f"Rerun artefact:         {_display_path(project_root, verification.rerun_artifact_path)}")


def _rerun_json(project_root: Path, policy_version: str, verification: BarRerunVerification) -> None:
    click.echo(
        json_mod.dumps(
            {
                "obligation_id": verification.obligation_id,
                "captured_aggregate_verdict": verification.captured_aggregate_verdict,
                "rerun_aggregate_verdict": verification.rerun_aggregate_verdict,
                "verdict_match": verification.verdict_match,
                "source_artifact": _display_path(project_root, verification.source_artifact_path),
                "rerun_artifact": _display_path(project_root, verification.rerun_artifact_path),
                "policy_version": policy_version,
            },
            indent=2,
        )
    )


def _display_path(project_root: Path, path: Path) -> str:
    try:
        return path.relative_to(project_root).as_posix()
    except ValueError:
        return str(path)


def _stability_reason(outcome: BarReviewOutcome) -> str:
    if outcome.stability_reason:
        return outcome.stability_reason
    return "stable unanimous aggregate across required runs"


def _mapping_value(data: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = data[key]
    if not isinstance(value, dict):
        raise BarRunnerError(f"BAR runtime metadata field {key!r} was not a JSON object")
    return value


def _list_value(data: Mapping[str, object], key: str) -> list[object]:
    value = data[key]
    if not isinstance(value, list):
        raise BarRunnerError(f"BAR runtime metadata field {key!r} was not a JSON array")
    return value


def _format_scalar(value: object) -> str:
    if value is None:
        return "unset"
    return str(value)


def _validate_rerun_binding(
    *,
    prior_artifact: BarEvidenceArtifact,
    raw_obligation: dict[str, object],
    bundle: BarReviewBundle,
) -> None:
    reviewer_metadata = raw_obligation.get("reviewer_metadata")
    if not isinstance(reviewer_metadata, dict):
        raise BarRunnerError("BAR rerun requires reviewer_metadata in the compliance ledger")

    if reviewer_metadata.get("independence") != "bootstrap_attested":
        raise BarRunnerError(
            "BAR rerun requires a bootstrap_attested obligation in the compliance ledger"
        )
    _require_matching_field(
        label="reviewer_metadata.review_pipeline",
        expected=prior_artifact.pipeline_name,
        actual=reviewer_metadata.get("review_pipeline"),
    )
    _require_matching_field(
        label="reviewer_metadata.review_pipeline_version",
        expected=prior_artifact.pipeline_version,
        actual=reviewer_metadata.get("review_pipeline_version"),
    )
    _require_matching_field(
        label="reviewer_metadata.review_policy_hash",
        expected=prior_artifact.policy_hash,
        actual=reviewer_metadata.get("review_policy_hash"),
    )

    _require_matching_field(
        label="freshness_binding.commit_ref",
        expected=prior_artifact.commit_ref,
        actual=bundle.commit_ref,
    )
    _require_matching_field(
        label="freshness_binding.manifest_hash",
        expected=prior_artifact.manifest_hash,
        actual=bundle.manifest_hash,
    )
    if prior_artifact.corpus_hash is None:
        if bundle.corpus_hash is not None:
            raise BarRunnerError(
                "BAR rerun corpus binding mismatch: artefact records null corpus_hash "
                f"but reviewed inputs resolved to {bundle.corpus_hash!r}"
            )
    else:
        _require_matching_field(
            label="freshness_binding.corpus_hash",
            expected=prior_artifact.corpus_hash,
            actual=bundle.corpus_hash,
        )


def _require_matching_field(*, label: str, expected: object, actual: object) -> None:
    if expected != actual:
        raise BarRunnerError(
            f"BAR rerun binding mismatch for {label}: expected {expected!r}, got {actual!r}"
        )
