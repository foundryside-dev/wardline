from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

DEFAULT_OPENROUTER_JUDGE_MODEL = "anthropic/claude-opus-4-8"
DEFAULT_CODEX_JUDGE_MODEL = "gpt-5.6-sol"
CODEX_JUDGE_REASONING_EFFORT = "high"


class JudgeTransport(StrEnum):
    AUTO = "auto"
    CODEX_CLI = "codex-cli"
    OPENROUTER = "openrouter"


CONCRETE_JUDGE_TRANSPORTS = frozenset({JudgeTransport.CODEX_CLI, JudgeTransport.OPENROUTER})


@dataclass(frozen=True, slots=True)
class CodexToolScope:
    root: Path
    max_calls: int = 24

    def __post_init__(self) -> None:
        if not self.root.is_absolute():
            raise ValueError("CodexToolScope.root must be absolute")
        if self.max_calls <= 0:
            raise ValueError("CodexToolScope.max_calls must be positive")
