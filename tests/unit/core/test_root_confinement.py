from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.assure import build_posture
from wardline.core.attest import build_attestation, verify_attestation
from wardline.core.baseline import generate_baseline
from wardline.core.dossier import build_dossier
from wardline.core.errors import ConfigError
from wardline.core.judge import JudgeRequest, JudgeResponse, JudgeVerdict
from wardline.core.judge_run import run_judge

_KEY = "0" * 64

_OUTSIDE_LEAK = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _poisoned_project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text(_OUTSIDE_LEAK, encoding="utf-8")
    (project / "wardline.yaml").write_text('source_roots: ["../outside"]\n', encoding="utf-8")
    return project


def _false_positive(_req: JudgeRequest) -> JudgeResponse:
    from datetime import UTC, datetime

    return JudgeResponse(
        verdict=JudgeVerdict.FALSE_POSITIVE,
        rationale="not relevant",
        confidence=0.9,
        model_id="fake/model",
        recorded_at=datetime.now(UTC),
        prompt_tokens_total=1,
        prompt_tokens_cached=None,
        policy_hash="deadbeef",
    )


def test_build_posture_refuses_escaping_source_roots_by_default(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="outside the project root"):
        build_posture(_poisoned_project(tmp_path))


def test_build_attestation_refuses_escaping_source_roots_by_default(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="outside the project root"):
        build_attestation(_poisoned_project(tmp_path), _KEY)


def test_verify_attestation_reproduce_refuses_escaping_source_roots_by_default(tmp_path: Path) -> None:
    project = _poisoned_project(tmp_path)
    legacy_bundle = build_attestation(project, _KEY, confine_to_root=False)

    with pytest.raises(ConfigError, match="outside the project root"):
        verify_attestation(legacy_bundle, _KEY, root=project, reproduce=True)


def test_build_dossier_refuses_escaping_source_roots_by_default(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="outside the project root"):
        build_dossier("secret.leaky", root=_poisoned_project(tmp_path))


def test_run_judge_refuses_escaping_source_roots_by_default(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="outside the project root"):
        run_judge(_poisoned_project(tmp_path), judge_caller=_false_positive)


@pytest.mark.parametrize("overwrite", [False, True])
def test_generate_baseline_refuses_escaping_source_roots_by_default(tmp_path: Path, overwrite: bool) -> None:
    with pytest.raises(ConfigError, match="outside the project root"):
        generate_baseline(_poisoned_project(tmp_path), overwrite=overwrite)
