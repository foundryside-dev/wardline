# tests/unit/core/test_judge_run.py
"""SP8: core.judge_run — the shared judge pipeline (no network, injected caller)."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

from wardline.core.finding import Kind, SuppressionState
from wardline.core.judge import JudgeRequest, JudgeResponse, JudgeVerdict
from wardline.core.judge_run import JudgeOutcome, run_judge
from wardline.core.run import run_scan

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


def test_run_judge_triages_same_active_defect_fingerprints_as_scan_with_packs(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[3]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from tests.unit.install.mock_pack import grammar as mock_grammar

    fake_pack = ModuleType("judge_parity_pack")
    fake_pack.grammar = mock_grammar  # type: ignore[attr-defined]
    sys.modules["judge_parity_pack"] = fake_pack

    try:
        root = tmp_path / "proj"
        root.mkdir()
        (root / "wardline.yaml").write_text("packs:\n  - judge_parity_pack\n", encoding="utf-8")
        (root / "svc.py").write_text("def violator():\n    pass\n", encoding="utf-8")

        scan = run_scan(root)
        scan_candidate_fps = {
            finding.fingerprint
            for finding in scan.findings
            if finding.kind is Kind.DEFECT and finding.suppressed is SuppressionState.ACTIVE
        }

        seen_requests: list[str] = []

        def _recording_caller(req: JudgeRequest) -> JudgeResponse:
            seen_requests.append(req.fingerprint)
            return _tp_caller(req)

        outcome = run_judge(root, judge_caller=_recording_caller, write=False)

        assert {verdict.fingerprint for verdict in outcome.verdicts} == scan_candidate_fps
        assert set(seen_requests) == scan_candidate_fps
        assert scan_candidate_fps == {"PY-WL-901:svc.py:1"}
    finally:
        sys.modules.pop("judge_parity_pack", None)


def test_parse_verdict_payload_with_markdown() -> None:
    from wardline.core.judge import _parse_verdict_payload

    raw_markdown = (
        "```json\n"
        "{\n"
        '  "verdict": "FALSE_POSITIVE",\n'
        '  "rationale": " benign over-approximation in loop",\n'
        '  "confidence": 0.85\n'
        "}\n"
        "```"
    )
    res = _parse_verdict_payload(raw_markdown)
    assert res["verdict"] == "FALSE_POSITIVE"
    assert res["rationale"] == " benign over-approximation in loop"
    assert res["confidence"] == 0.85
