from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.errors import DiscoveryError
from wardline.core.source_excerpt import extract_excerpt


def _write(root: Path, rel: str, lines: int) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(f"line{n}" for n in range(1, lines + 1)) + "\n", encoding="utf-8")


def test_excerpt_centres_on_line_with_gutters(tmp_path: Path) -> None:
    _write(tmp_path, "src/m.py", 100)
    text = extract_excerpt(tmp_path, "src/m.py", line=50, context_lines=2)
    assert "48: line48" in text and "50: line50" in text and "52: line52" in text
    assert "47: line47" not in text and "53: line53" not in text


def test_excerpt_clamps_at_file_edges(tmp_path: Path) -> None:
    _write(tmp_path, "src/m.py", 5)
    text = extract_excerpt(tmp_path, "src/m.py", line=1, context_lines=10)
    assert "1: line1" in text and "5: line5" in text


def test_excerpt_rejects_path_escape(tmp_path: Path) -> None:
    _write(tmp_path, "src/m.py", 5)
    with pytest.raises(DiscoveryError):
        extract_excerpt(tmp_path, "../../etc/passwd", line=1, context_lines=2)


def test_excerpt_truncates_to_char_limit(tmp_path: Path) -> None:
    _write(tmp_path, "src/m.py", 5)
    text = extract_excerpt(tmp_path, "src/m.py", line=3, context_lines=2, char_limit=10)
    assert len(text) <= 10
