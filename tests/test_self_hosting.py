from __future__ import annotations

from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer


def test_wardline_scans_itself_clean() -> None:
    # SP2c: run Wardline's default rule set over its own src/wardline and assert
    # zero DEFECT findings. Clean BY CONSTRUCTION — src/wardline applies none of
    # its own trust decorators, so every function resolves to UNKNOWN_RAW:
    # PY-WL-101/102 are not-anchored-gated, PY-WL-103/104 tier-modulate to NONE.
    repo_root = Path(__file__).resolve().parent.parent
    src = repo_root / "src" / "wardline"
    files = sorted(src.rglob("*.py"))
    assert files, "expected to find Wardline source files"
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze(files, WardlineConfig(), root=repo_root)
    defects = [f for f in findings if f.kind == Kind.DEFECT]
    assert defects == [], (
        f"self-hosting found {len(defects)} DEFECT(s): "
        f"{[(d.rule_id, d.location.path, d.location.line_start) for d in defects]}"
    )
