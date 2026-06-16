# src/wardline/core/emit.py
"""Finding sinks. JsonlSink is the SP0 default output."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from wardline.core.finding import Finding
from wardline.core.safe_paths import safe_write_text, write_text_no_follow


class Sink(Protocol):
    def write(self, findings: Sequence[Finding]) -> None: ...


class JsonlSink:
    def __init__(self, path: Path, *, root: Path | None = None) -> None:
        self._path = path
        self._root = root

    def write(self, findings: Sequence[Finding]) -> None:
        content = "".join(f"{finding.to_jsonl()}\n" for finding in findings)
        if self._root is not None:
            safe_write_text(self._root, self._path, content, label=self._path.name)
        else:
            write_text_no_follow(self._path, content, label=self._path.name)
