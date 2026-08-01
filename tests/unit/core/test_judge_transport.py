from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.judge_types import (
    CODEX_JUDGE_REASONING_EFFORT,
    CONCRETE_JUDGE_TRANSPORTS,
    DEFAULT_CODEX_JUDGE_MODEL,
    DEFAULT_OPENROUTER_JUDGE_MODEL,
    CodexToolScope,
    JudgeTransport,
)


def test_judge_transport_values_are_closed_and_ordered() -> None:
    assert [transport.value for transport in JudgeTransport] == [
        "auto",
        "codex-cli",
        "openrouter",
    ]
    assert frozenset({JudgeTransport.CODEX_CLI, JudgeTransport.OPENROUTER}) == CONCRETE_JUDGE_TRANSPORTS


def test_transport_model_defaults_use_separate_namespaces() -> None:
    assert DEFAULT_CODEX_JUDGE_MODEL == "gpt-5.6-sol"
    assert DEFAULT_OPENROUTER_JUDGE_MODEL == "anthropic/claude-opus-4-8"
    assert CODEX_JUDGE_REASONING_EFFORT == "high"


def test_codex_tool_scope_uses_absolute_root_and_positive_default(tmp_path: Path) -> None:
    root = tmp_path.resolve()

    scope = CodexToolScope(root=root)

    assert scope.root == root
    assert scope.max_calls == 24


def test_codex_tool_scope_rejects_relative_root() -> None:
    with pytest.raises(ValueError, match="absolute"):
        CodexToolScope(root=Path("relative/repository"))


@pytest.mark.parametrize("max_calls", [0, -1])
def test_codex_tool_scope_rejects_nonpositive_call_budget(tmp_path: Path, max_calls: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        CodexToolScope(root=tmp_path.resolve(), max_calls=max_calls)
