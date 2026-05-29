# src/wardline/core/emit.py
"""Finding sinks. JsonlSink is the SP0 default output."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from wardline.core.finding import Finding


class Sink(Protocol):
    def write(self, findings: Sequence[Finding]) -> None: ...


class JsonlSink:
    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, findings: Sequence[Finding]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("w", encoding="utf-8") as handle:
            for finding in findings:
                handle.write(finding.to_jsonl())
                handle.write("\n")
