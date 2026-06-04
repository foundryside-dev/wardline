# src/wardline/core/protocols.py
"""Plug-point Protocols for SP1 (Analyzer) and SP2 (Rule)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext


class Analyzer(Protocol):
    @property
    def last_context(self) -> AnalysisContext | None: ...

    def analyze(self, files: Sequence[Path], config: WardlineConfig, *, root: Path) -> Sequence[Finding]: ...


class Rule(Protocol):
    rule_id: str

    def check(self, context: AnalysisContext) -> Sequence[Finding]: ...
