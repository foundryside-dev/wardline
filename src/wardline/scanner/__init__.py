"""Wardline analysis engine. SP0 ships a no-op; SP1 replaces it."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding


class NoOpAnalyzer:
    """Placeholder analyzer that performs no analysis (SP0)."""

    def analyze(
        self, files: Sequence[Path], config: WardlineConfig, *, root: Path
    ) -> Sequence[Finding]:
        return []


__all__ = ["NoOpAnalyzer"]
