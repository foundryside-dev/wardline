# tests/unit/core/test_judge_run.py
"""SP8: core.judge_run — the shared judge pipeline (no network, injected caller)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from wardline.core.judge import JudgeRequest, JudgeResponse, JudgeVerdict
from wardline.core.judge_run import JudgeOutcome, run_judge

# A @trust_boundary(to_level=GUARDED) validator that returns its input unchanged
# (no rejection path) -> an active PY-WL-102 defect. Mirrors the proven CLI fixture.
_LEAKY = (
    "from wardline.decorators.trust import trust_boundary\n"
    "from wardline.core.taints import TaintState\n"
    "@trust_boundary(to_level=TaintState.GUARDED)\n"
    "def validate(x):\n    return x\n"
)


def _leaky_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    (proj / "svc").mkdir(parents=True)
    (proj / "svc" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "svc" / "v.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def _tp_caller(_req: JudgeRequest) -> JudgeResponse:
    return JudgeResponse(
        verdict=JudgeVerdict.TRUE_POSITIVE,
        rationale="genuinely reaches a trusted sink",
        confidence=0.91,
        model_id="fake/model",
        recorded_at=datetime.now(UTC),
        prompt_tokens_total=128,
        prompt_tokens_cached=None,
        policy_hash="deadbeef",
    )


def _fp_caller(conf: float):  # type: ignore[no-untyped-def]
    def _caller(_req: JudgeRequest) -> JudgeResponse:
        return JudgeResponse(
            verdict=JudgeVerdict.FALSE_POSITIVE,
            rationale="analyzer over-approximation",
            confidence=conf,
            model_id="fake/model",
            recorded_at=datetime.now(UTC),
            prompt_tokens_total=64,
            prompt_tokens_cached=None,
            policy_hash="deadbeef",
        )

    return _caller


def test_run_judge_dry_run_returns_verdicts(tmp_path: Path) -> None:
    root = _leaky_project(tmp_path)
    outcome = run_judge(root, judge_caller=_tp_caller, write=False)
    assert isinstance(outcome, JudgeOutcome)
    assert outcome.verdicts  # at least one active defect triaged
    v = outcome.verdicts[0]
    assert v.fingerprint
    assert v.label in {"TRUE_POSITIVE", "FALSE_POSITIVE"}
    assert 0.0 <= v.confidence <= 1.0
    assert outcome.wrote == 0  # dry run never writes
    assert not (root / ".wardline" / "judged.yaml").exists()


def test_run_judge_write_persists_high_confidence_fp(tmp_path: Path) -> None:
    root = _leaky_project(tmp_path)
    outcome = run_judge(root, judge_caller=_fp_caller(0.9), write=True)
    assert outcome.wrote >= 1
    assert outcome.held_back == 0
    judged = root / ".wardline" / "judged.yaml"
    assert judged.exists()


def test_run_judge_write_holds_back_low_confidence_fp(tmp_path: Path) -> None:
    root = _leaky_project(tmp_path)
    outcome = run_judge(root, judge_caller=_fp_caller(0.3), write=True)
    assert outcome.wrote == 0
    assert outcome.held_back >= 1
    assert not (root / ".wardline" / "judged.yaml").exists()
