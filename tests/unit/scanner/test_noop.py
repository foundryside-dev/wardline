from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.scanner import NoOpAnalyzer


def test_noop_analyzer_returns_no_findings() -> None:
    result = NoOpAnalyzer().analyze([Path("a.py")], WardlineConfig(), root=Path("."))
    assert list(result) == []
