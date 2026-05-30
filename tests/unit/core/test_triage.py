from __future__ import annotations

from datetime import UTC, datetime

from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.judge import JudgeRequest, JudgeResponse, JudgeVerdict
from wardline.core.triage import finding_to_request, run_triage


def _defect(fp: str, *, rule: str = "PY-WL-101", active: bool = True) -> Finding:
    return Finding(
        rule_id=rule, message="m", severity=Severity.ERROR, kind=Kind.DEFECT,
        location=Location(path="src/m.py", line_start=5, line_end=5), fingerprint=fp,
        properties={"declared_return": "GUARDED", "actual_return": "MIXED_RAW"},
        suppressed=SuppressionState.ACTIVE if active else SuppressionState.WAIVED,
    )


def _resp(v: JudgeVerdict, conf: float = 0.9) -> JudgeResponse:
    return JudgeResponse(verdict=v, rationale="r", confidence=conf, model_id="m",
                         recorded_at=datetime.now(UTC), prompt_tokens_total=1,
                         prompt_tokens_cached=None, policy_hash="sha256:x")


def test_finding_to_request_builds_taint_summary() -> None:
    req = finding_to_request(_defect("a" * 64), excerpt="def f(): ...")
    assert isinstance(req, JudgeRequest)
    assert req.rule_id == "PY-WL-101" and req.line == 5
    assert "actual_return=MIXED_RAW" in req.taint_summary
    assert req.surrounding_code == "def f(): ..."


def test_run_triage_splits_tp_and_fp() -> None:
    findings = [_defect("a" * 64), _defect("b" * 64)]
    verdicts = {"a" * 64: _resp(JudgeVerdict.FALSE_POSITIVE), "b" * 64: _resp(JudgeVerdict.TRUE_POSITIVE)}
    result = run_triage(
        findings,
        read_excerpt=lambda f: "code",
        judge_caller=lambda req: verdicts[req.fingerprint],
    )
    assert result.n_true == 1 and result.n_false == 1
    assert [v.finding.fingerprint for v in result.verdicts] == ["a" * 64, "b" * 64]
    fps = result.false_positives()
    assert len(fps) == 1 and fps[0].finding.fingerprint == "a" * 64


def test_run_triage_only_triages_active_defects() -> None:
    findings = [_defect("a" * 64, active=False)]
    result = run_triage(findings, read_excerpt=lambda f: "c",
                        judge_caller=lambda req: _resp(JudgeVerdict.FALSE_POSITIVE))
    assert result.verdicts == [] and result.n_true == 0 and result.n_false == 0


def test_run_triage_respects_max_findings() -> None:
    findings = [_defect("a" * 64), _defect("b" * 64), _defect("c" * 64)]
    calls: list[str] = []

    def caller(req: JudgeRequest) -> JudgeResponse:
        calls.append(req.fingerprint)
        return _resp(JudgeVerdict.TRUE_POSITIVE)

    result = run_triage(findings, read_excerpt=lambda f: "c", judge_caller=caller, max_findings=2)
    assert len(calls) == 2 and result.n_skipped_cap == 1


def test_run_triage_counts_transport_skips() -> None:
    from wardline.core.errors import JudgeTransportError

    def caller(req: JudgeRequest) -> JudgeResponse:
        raise JudgeTransportError("sibling down")

    result = run_triage([_defect("a" * 64)], read_excerpt=lambda f: "c", judge_caller=caller)
    assert result.n_skipped_transport == 1 and result.verdicts == []


def test_run_triage_contract_error_propagates() -> None:
    from wardline.core.errors import JudgeContractError

    def caller(req: JudgeRequest) -> JudgeResponse:
        raise JudgeContractError("model returned garbage")

    import pytest
    with pytest.raises(JudgeContractError):
        run_triage([_defect("a" * 64)], read_excerpt=lambda f: "c", judge_caller=caller)


def test_run_triage_excerpt_error_skips_and_counts() -> None:
    from wardline.core.errors import DiscoveryError

    def bad_excerpt(f):  # type: ignore[no-untyped-def]
        raise DiscoveryError("unreadable")

    result = run_triage([_defect("a" * 64)], read_excerpt=bad_excerpt,
                        judge_caller=lambda req: _resp(JudgeVerdict.TRUE_POSITIVE))
    assert result.n_skipped_excerpt == 1 and result.verdicts == []


def test_run_triage_rejects_nonpositive_max_findings() -> None:
    import pytest
    with pytest.raises(ValueError):
        run_triage([_defect("a" * 64)], read_excerpt=lambda f: "c",
                   judge_caller=lambda req: _resp(JudgeVerdict.TRUE_POSITIVE), max_findings=0)
