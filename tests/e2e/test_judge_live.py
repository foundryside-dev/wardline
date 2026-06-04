from __future__ import annotations

import os

import pytest

from wardline.core.judge import JudgeRequest, JudgeVerdict, call_judge

pytestmark = pytest.mark.network


@pytest.mark.skipif(not os.environ.get("WARDLINE_OPENROUTER_API_KEY"), reason="no API key")
def test_live_triage_round_trip() -> None:
    """One real OpenRouter call returns a schema-valid verdict."""
    req = JudgeRequest(
        rule_id="PY-WL-101",
        message="untrusted reaches trusted",
        severity="ERROR",
        file_path="svc/v.py",
        line=4,
        qualname="svc.v.validate",
        fingerprint="a" * 64,
        taint_summary="declared_return=GUARDED, actual_return=MIXED_RAW",
        surrounding_code=(
            "1: @trust_boundary(to_level=TaintState.GUARDED)\n"
            "2: def validate(x):\n"
            "3:     # passes raw input straight through — a real defect\n"
            "4:     return x\n"
        ),
    )
    first = call_judge(req)
    assert first.verdict in (JudgeVerdict.TRUE_POSITIVE, JudgeVerdict.FALSE_POSITIVE)
    assert 0.0 <= first.confidence <= 1.0
    assert first.rationale.strip()
    assert first.policy_hash.startswith("sha256:")
