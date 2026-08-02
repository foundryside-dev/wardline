from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path

import pytest

from wardline.core.judge import JudgeRequest, JudgeVerdict, call_judge
from wardline.core.judge_transport import (
    _BoundedProcessResult,
    _run_bounded_process,
    probe_codex_cli,
    resolve_judge_transport,
)
from wardline.core.judge_types import CodexToolScope, JudgeTransport

pytestmark = pytest.mark.codex_live


def _completed_read_file_paths(stdout: str) -> set[str]:
    paths: set[str] = set()
    for raw_line in stdout.splitlines():
        try:
            event = json.loads(raw_line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(event, dict) or event.get("type") != "item.completed":
            continue
        item = event.get("item")
        if not isinstance(item, dict):
            continue
        if not (
            item.get("type") == "mcp_tool_call"
            and item.get("server") == "wardline_judge_tools"
            and item.get("tool") == "read_file"
            and item.get("status") == "completed"
        ):
            continue
        arguments = item.get("arguments")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                continue
        if isinstance(arguments, dict) and isinstance(arguments.get("file_path"), str):
            paths.add(arguments["file_path"])
    return paths


@pytest.mark.skipif(os.environ.get("WARDLINE_CODEX_LIVE") != "1", reason="set WARDLINE_CODEX_LIVE=1")
def test_live_codex_triage_round_trip(tmp_path: Path) -> None:
    availability = probe_codex_cli()
    assert availability.is_available, availability
    assert resolve_judge_transport(JudgeTransport.AUTO, probe=lambda: availability) is JudgeTransport.CODEX_CLI
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

    transport = response.judge_transport
    verdict = response.verdict
    has_rationale = bool(response.rationale.strip())
    confidence = response.confidence
    del response
    assert transport is JudgeTransport.CODEX_CLI
    assert verdict in (JudgeVerdict.TRUE_POSITIVE, JudgeVerdict.FALSE_POSITIVE)
    assert has_rationale, "Codex returned an empty rationale"
    assert 0.0 <= confidence <= 1.0


@pytest.mark.skipif(os.environ.get("WARDLINE_CODEX_LIVE") != "1", reason="set WARDLINE_CODEX_LIVE=1")
def test_live_codex_explores_helper_for_load_bearing_context(tmp_path: Path) -> None:
    helper_source = (
        "def evaluate_value(value):\n"
        '    if value != "WARDLINE_CODEX_LIVE_SAFE_SENTINEL":\n'
        '        raise ValueError("untrusted value rejected")\n'
        "    return value\n"
    )
    helper_path = tmp_path / "judge_helper.py"
    helper_path.write_text(helper_source, encoding="utf-8")
    (tmp_path / "svc.py").write_text(
        "from judge_helper import evaluate_value\ndef validate(value):\n    return evaluate_value(value)\n",
        encoding="utf-8",
    )
    request = JudgeRequest(
        rule_id="PY-WL-102",
        message=(
            "helper behavior is load-bearing and omitted from the excerpt; inspect "
            "judge_helper.py before deciding whether untrusted values are rejected"
        ),
        severity="ERROR",
        file_path="svc.py",
        line=3,
        qualname="svc.validate",
        fingerprint="b" * 64,
        taint_summary="declared_return=GUARDED, actual_return=EXTERNAL_RAW",
        surrounding_code=(
            "1: from judge_helper import evaluate_value\n2: def validate(value):\n3:     return evaluate_value(value)"
        ),
    )

    captured_stdout: list[str] = []

    def recording_runner(
        args: list[str],
        *,
        input_text: str | None,
        timeout: float,
        env: Mapping[str, str],
        cwd: Path | None,
        stdout_limit: int,
        stderr_limit: int,
    ) -> _BoundedProcessResult:
        result = _run_bounded_process(
            args,
            input_text=input_text,
            timeout=timeout,
            env=env,
            cwd=cwd,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )
        captured_stdout.append(result.stdout)
        return result

    response = call_judge(
        request,
        judge_transport=JudgeTransport.CODEX_CLI,
        codex_tool_scope=CodexToolScope(root=tmp_path.resolve()),
        codex_process_runner=recording_runner,
    )

    # The completed JSONL tool event is the transport oracle. Citation wording is
    # prompt guidance, not a structured response field, and is model-nondeterministic.
    process_count = len(captured_stdout)
    helper_read_completed = process_count == 1 and "judge_helper.py" in _completed_read_file_paths(captured_stdout[0])
    has_rationale = bool(response.rationale.strip())
    verdict = response.verdict
    transport = response.judge_transport
    del response
    captured_stdout.clear()
    assert process_count == 1, "Codex process runner did not complete exactly once"
    assert helper_read_completed, "Codex did not complete a read_file call for the helper"
    assert verdict is JudgeVerdict.FALSE_POSITIVE
    assert transport is JudgeTransport.CODEX_CLI
    assert has_rationale, "Codex returned an empty rationale"
