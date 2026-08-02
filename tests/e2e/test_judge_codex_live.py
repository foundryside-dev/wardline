from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from wardline.core.judge import JudgeRequest, JudgeVerdict, call_judge
from wardline.core.judge_transport import probe_codex_cli, resolve_judge_transport
from wardline.core.judge_types import CodexToolScope, JudgeTransport

pytestmark = pytest.mark.codex_live


@pytest.mark.skipif(os.environ.get("WARDLINE_CODEX_LIVE") != "1", reason="set WARDLINE_CODEX_LIVE=1")
def test_live_codex_triage_round_trip(tmp_path: Path) -> None:
    availability = probe_codex_cli()
    assert availability.is_available, availability
    assert (
        resolve_judge_transport(JudgeTransport.AUTO, probe=lambda: availability)
        is JudgeTransport.CODEX_CLI
    )
    (tmp_path / "svc.py").write_text("def validate(x):\n    return x\n", encoding="utf-8")
    request = JudgeRequest(
        rule_id="PY-WL-102",
        message="boundary has no rejection path",
        severity="ERROR",
        file_path="svc.py",
        line=2,
        qualname="svc.validate",
        fingerprint="a" * 64,
        taint_summary="declared_return=GUARDED, actual_return=EXTERNAL_RAW",
        surrounding_code="1: def validate(x):\n2:     return x",
    )

    response = call_judge(
        request,
        judge_transport=JudgeTransport.CODEX_CLI,
        codex_tool_scope=CodexToolScope(root=tmp_path.resolve()),
    )

    assert response.judge_transport is JudgeTransport.CODEX_CLI
    assert response.verdict in (JudgeVerdict.TRUE_POSITIVE, JudgeVerdict.FALSE_POSITIVE)
    assert response.rationale.strip()
    assert 0.0 <= response.confidence <= 1.0


@pytest.mark.skipif(os.environ.get("WARDLINE_CODEX_LIVE") != "1", reason="set WARDLINE_CODEX_LIVE=1")
def test_live_codex_explores_helper_for_load_bearing_context(tmp_path: Path) -> None:
    helper_source = (
        "def accepts_only_live_sentinel(value):\n"
        '    if value != "WARDLINE_CODEX_LIVE_SAFE_SENTINEL":\n'
        '        raise ValueError("untrusted value rejected")\n'
        "    return value\n"
    )
    helper_path = tmp_path / "judge_helper.py"
    helper_path.write_text(helper_source, encoding="utf-8")
    sentinel_line = next(
        index
        for index, line in enumerate(helper_source.splitlines(), start=1)
        if "WARDLINE_CODEX_LIVE_SAFE_SENTINEL" in line
    )
    (tmp_path / "svc.py").write_text(
        "from judge_helper import accepts_only_live_sentinel\n"
        "def validate(value):\n"
        "    return accepts_only_live_sentinel(value)\n",
        encoding="utf-8",
    )
    request = JudgeRequest(
        rule_id="PY-WL-102",
        message="boundary helper may not reject untrusted values",
        severity="ERROR",
        file_path="svc.py",
        line=3,
        qualname="svc.validate",
        fingerprint="b" * 64,
        taint_summary="declared_return=GUARDED, actual_return=EXTERNAL_RAW",
        surrounding_code=(
            "1: from judge_helper import accepts_only_live_sentinel\n"
            "2: def validate(value):\n"
            "3:     return accepts_only_live_sentinel(value)"
        ),
    )

    response = call_judge(
        request,
        judge_transport=JudgeTransport.CODEX_CLI,
        codex_tool_scope=CodexToolScope(root=tmp_path.resolve()),
    )

    citation = re.compile(r"(?i)(?<![\w./-])judge_helper\.py:(\d+)(?:-(\d+))?\b")
    match = citation.search(response.rationale)
    assert match is not None, response.rationale
    cited_first = int(match.group(1))
    cited_last = int(match.group(2) or match.group(1))
    assert cited_first <= sentinel_line <= cited_last, response.rationale
    assert response.verdict is JudgeVerdict.FALSE_POSITIVE
    assert response.judge_transport is JudgeTransport.CODEX_CLI
