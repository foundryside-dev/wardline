"""BAR evidence artefact models and writer."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.bar.adapters import ReviewerResult


@dataclass(frozen=True)
class BarCitationValidationArtifact:
    """Citation-normalization details stored alongside a reviewer verdict."""

    raw_citations: tuple[str, ...] = ()
    dropped_citations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_citations", tuple(self.raw_citations))
        object.__setattr__(self, "dropped_citations", tuple(self.dropped_citations))


@dataclass(frozen=True)
class BarReviewerVerdictArtifact:
    """Reviewer verdict payload stored in a BAR evidence artefact."""

    verdict: Literal["pass", "fail", "insufficient_evidence", "refer"]
    rationale: str
    citations: tuple[str, ...] = ()
    citation_validation: BarCitationValidationArtifact | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "citations", tuple(self.citations))


@dataclass(frozen=True)
class BarEvidenceArtifact:
    """Immutable JSON artefact emitted by a BAR runner invocation."""

    obligation_id: str
    pipeline_name: str
    pipeline_version: str
    policy_hash: str
    commit_ref: str
    manifest_hash: str
    corpus_hash: str | None
    model_pin: MappingProxyType[str, object] | dict[str, object]
    skill_pack: MappingProxyType[str, object] | dict[str, object]
    reviewed_at: str
    stability_run_index: int | Literal["audit"]
    reviewer_verdicts: MappingProxyType[str, BarReviewerVerdictArtifact] | dict[str, BarReviewerVerdictArtifact]
    aggregate_verdict: str
    pipeline_duration_seconds: float

    def __post_init__(self) -> None:
        if isinstance(self.model_pin, dict):
            object.__setattr__(self, "model_pin", MappingProxyType(dict(self.model_pin)))
        if isinstance(self.skill_pack, dict):
            object.__setattr__(self, "skill_pack", MappingProxyType(dict(self.skill_pack)))
        if isinstance(self.reviewer_verdicts, dict):
            object.__setattr__(
                self,
                "reviewer_verdicts",
                MappingProxyType(dict(self.reviewer_verdicts)),
            )


class BarEvidenceArtifactError(Exception):
    """Raised when a BAR evidence artefact cannot be written safely."""


def build_bar_evidence_artifact(
    *,
    obligation_id: str,
    pipeline_name: str,
    pipeline_version: str,
    policy_hash: str,
    commit_ref: str,
    manifest_hash: str,
    corpus_hash: str | None,
    model_pin: Mapping[str, object],
    skill_pack: Mapping[str, object],
    reviewed_at: datetime | str,
    stability_run_index: int | Literal["audit"],
    reviewer_results: Mapping[str, ReviewerResult],
    aggregate_verdict: str,
    pipeline_duration_seconds: float,
) -> BarEvidenceArtifact:
    """Build an immutable BAR evidence artefact from runner outputs."""
    reviewer_verdicts = {
        role: BarReviewerVerdictArtifact(
            verdict=result.verdict,
            rationale=result.rationale,
            citations=result.citations,
            citation_validation=BarCitationValidationArtifact(
                raw_citations=result.raw_citations,
                dropped_citations=_dropped_citations(
                    raw_citations=result.raw_citations,
                    persisted_citations=result.citations,
                ),
            ),
        )
        for role, result in reviewer_results.items()
    }
    return BarEvidenceArtifact(
        obligation_id=obligation_id,
        pipeline_name=pipeline_name,
        pipeline_version=pipeline_version,
        policy_hash=policy_hash,
        commit_ref=commit_ref,
        manifest_hash=manifest_hash,
        corpus_hash=corpus_hash,
        model_pin=dict(model_pin),
        skill_pack=dict(skill_pack),
        reviewed_at=_normalize_reviewed_at(reviewed_at),
        stability_run_index=stability_run_index,
        reviewer_verdicts=reviewer_verdicts,
        aggregate_verdict=aggregate_verdict,
        pipeline_duration_seconds=round(pipeline_duration_seconds, 6),
    )


def default_artifact_root(repo_root: Path) -> Path:
    """Return the normative BAR evidence artefact root for a repository."""
    return repo_root / "docs" / "verification" / "bar-pipeline-runs"


def artifact_relative_path(artifact: BarEvidenceArtifact) -> Path:
    """Return the normative relative path for a BAR evidence artefact."""
    date_component = artifact.reviewed_at[:10]
    filename = (
        "audit-rerun.json"
        if artifact.stability_run_index == "audit"
        else f"run-{artifact.stability_run_index}.json"
    )
    return Path(date_component) / artifact.obligation_id / filename


def write_bar_evidence_artifact(
    artifact: BarEvidenceArtifact,
    *,
    artifact_root: Path,
) -> Path:
    """Write an immutable BAR evidence artefact to disk."""
    output_path = artifact_root / artifact_relative_path(artifact)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        raise BarEvidenceArtifactError(f"BAR evidence artefact already exists: {output_path}")
    output_path.write_text(json.dumps(_artifact_to_dict(artifact), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return output_path


def load_bar_evidence_artifact(path: Path) -> BarEvidenceArtifact:
    """Load a BAR evidence artefact from disk."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BarEvidenceArtifactError(f"unable to read BAR evidence artefact at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise BarEvidenceArtifactError(f"BAR evidence artefact at {path} must contain a JSON object")
    return _artifact_from_dict(data, path=path)


def _artifact_to_dict(artifact: BarEvidenceArtifact) -> dict[str, object]:
    reviewer_verdicts = {
        role: {
            "verdict": verdict.verdict,
            "rationale": verdict.rationale,
            "citations": list(verdict.citations),
            "citation_validation": {
                "raw_citations": list(verdict.citation_validation.raw_citations),
                "dropped_citations": list(verdict.citation_validation.dropped_citations),
            }
            if verdict.citation_validation is not None
            else None,
        }
        for role, verdict in artifact.reviewer_verdicts.items()
    }
    return {
        "obligation_id": artifact.obligation_id,
        "pipeline_name": artifact.pipeline_name,
        "pipeline_version": artifact.pipeline_version,
        "policy_hash": artifact.policy_hash,
        "commit_ref": artifact.commit_ref,
        "manifest_hash": artifact.manifest_hash,
        "corpus_hash": artifact.corpus_hash,
        "model_pin": dict(artifact.model_pin),
        "skill_pack": dict(artifact.skill_pack),
        "reviewed_at": artifact.reviewed_at,
        "stability_run_index": artifact.stability_run_index,
        "reviewer_verdicts": reviewer_verdicts,
        "aggregate_verdict": artifact.aggregate_verdict,
        "pipeline_duration_seconds": artifact.pipeline_duration_seconds,
    }


def _artifact_from_dict(data: dict[str, object], *, path: Path) -> BarEvidenceArtifact:
    reviewer_verdicts_value = data.get("reviewer_verdicts")
    if not isinstance(reviewer_verdicts_value, dict):
        raise BarEvidenceArtifactError(f"{path} must define object field 'reviewer_verdicts'")

    reviewer_verdicts: dict[str, BarReviewerVerdictArtifact] = {}
    for role, value in reviewer_verdicts_value.items():
        if not isinstance(role, str) or not isinstance(value, dict):
            raise BarEvidenceArtifactError(
                f"{path} reviewer_verdicts must map string role names to JSON objects"
            )
        reviewer_verdicts[role] = _reviewer_verdict_from_dict(value, path=path, role=role)

    return BarEvidenceArtifact(
        obligation_id=_require_str(data, "obligation_id", path=path),
        pipeline_name=_require_str(data, "pipeline_name", path=path),
        pipeline_version=_require_str(data, "pipeline_version", path=path),
        policy_hash=_require_str(data, "policy_hash", path=path),
        commit_ref=_require_str(data, "commit_ref", path=path),
        manifest_hash=_require_str(data, "manifest_hash", path=path),
        corpus_hash=_optional_str(data.get("corpus_hash"), path=path, field="corpus_hash"),
        model_pin=_require_object(data, "model_pin", path=path),
        skill_pack=_require_object(data, "skill_pack", path=path),
        reviewed_at=_require_str(data, "reviewed_at", path=path),
        stability_run_index=_parse_stability_run_index(data.get("stability_run_index"), path=path),
        reviewer_verdicts=reviewer_verdicts,
        aggregate_verdict=_require_str(data, "aggregate_verdict", path=path),
        pipeline_duration_seconds=_require_float(data, "pipeline_duration_seconds", path=path),
    )


def _normalize_reviewed_at(reviewed_at: datetime | str) -> str:
    if isinstance(reviewed_at, str):
        return reviewed_at
    if reviewed_at.tzinfo is None:
        reviewed_at = reviewed_at.replace(tzinfo=UTC)
    return reviewed_at.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _dropped_citations(*, raw_citations: tuple[str, ...], persisted_citations: tuple[str, ...]) -> tuple[str, ...]:
    remaining: dict[str, int] = {}
    for citation in persisted_citations:
        remaining[citation] = remaining.get(citation, 0) + 1

    dropped: list[str] = []
    for citation in raw_citations:
        if remaining.get(citation, 0) > 0:
            remaining[citation] -= 1
            continue
        dropped.append(citation)
    return tuple(dropped)


def _reviewer_verdict_from_dict(
    data: dict[str, object],
    *,
    path: Path,
    role: str,
) -> BarReviewerVerdictArtifact:
    citation_validation_value = data.get("citation_validation")
    citation_validation: BarCitationValidationArtifact | None = None
    if citation_validation_value is not None:
        if not isinstance(citation_validation_value, dict):
            raise BarEvidenceArtifactError(
                f"{path} reviewer_verdicts[{role!r}].citation_validation must be an object or null"
            )
        citation_validation = BarCitationValidationArtifact(
            raw_citations=_require_str_list(
                citation_validation_value,
                "raw_citations",
                path=path,
                prefix=f"reviewer_verdicts[{role!r}].citation_validation",
            ),
            dropped_citations=_require_str_list(
                citation_validation_value,
                "dropped_citations",
                path=path,
                prefix=f"reviewer_verdicts[{role!r}].citation_validation",
            ),
        )

    return BarReviewerVerdictArtifact(
        verdict=_parse_verdict(_require_str(data, "verdict", path=path), path=path, role=role),
        rationale=_require_str(data, "rationale", path=path),
        citations=_require_str_list(data, "citations", path=path, prefix=f"reviewer_verdicts[{role!r}]"),
        citation_validation=citation_validation,
    )


def _require_object(data: dict[str, object], key: str, *, path: Path) -> dict[str, object]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise BarEvidenceArtifactError(f"{path} must define object field {key!r}")
    return value


def _require_str(data: dict[str, object], key: str, *, path: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or value == "":
        raise BarEvidenceArtifactError(f"{path} must define non-empty string field {key!r}")
    return value


def _optional_str(value: object, *, path: Path, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value == "":
        raise BarEvidenceArtifactError(f"{path} field {field!r} must be null or non-empty string")
    return value


def _require_str_list(
    data: dict[str, object],
    key: str,
    *,
    path: Path,
    prefix: str,
) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise BarEvidenceArtifactError(f"{path} field {prefix}.{key} must be array[string]")
    return tuple(value)


def _require_float(data: dict[str, object], key: str, *, path: Path) -> float:
    value = data.get(key)
    if isinstance(value, (int, float)):
        return float(value)
    raise BarEvidenceArtifactError(f"{path} field {key!r} must be numeric")


def _parse_stability_run_index(value: object, *, path: Path) -> int | Literal["audit"]:
    if value == "audit":
        return "audit"
    if isinstance(value, int):
        return value
    raise BarEvidenceArtifactError(
        f"{path} field 'stability_run_index' must be an integer or 'audit'"
    )


def _parse_verdict(
    verdict: str,
    *,
    path: Path,
    role: str,
) -> Literal["pass", "fail", "insufficient_evidence", "refer"]:
    if verdict not in {"pass", "fail", "insufficient_evidence", "refer"}:
        raise BarEvidenceArtifactError(
            f"{path} reviewer_verdicts[{role!r}].verdict has invalid value {verdict!r}"
        )
    return cast("Literal['pass', 'fail', 'insufficient_evidence', 'refer']", verdict)
