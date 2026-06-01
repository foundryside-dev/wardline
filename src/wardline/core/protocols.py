# src/wardline/core/protocols.py
"""Plug-point Protocols for SP1 (Analyzer) and SP2 (Rule)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding


class Analyzer(Protocol):
    def analyze(self, files: Sequence[Path], config: WardlineConfig, *, root: Path) -> Sequence[Finding]: ...


class Rule(Protocol):
    rule_id: str

    def check(self, *args: object, **kwargs: object) -> Sequence[Finding]: ...
