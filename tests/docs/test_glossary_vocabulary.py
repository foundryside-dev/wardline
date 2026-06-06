"""Doc-discipline tests for the finding-lifecycle vocabulary glossary.

The glossary at ``docs/reference/finding-lifecycle-vocabulary.md`` is the single
source of truth for the finding-state / gate-population vocabulary. These tests
keep it complete (every ``SuppressionState`` value documented) and wired into the
mkdocs nav (so ``mkdocs build --strict`` does not orphan it).
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.finding import SuppressionState

_REPO = Path(__file__).parents[2]
_GLOSSARY = _REPO / "docs" / "reference" / "finding-lifecycle-vocabulary.md"
_MKDOCS = _REPO / "mkdocs.yml"
_NAV_PATH = "reference/finding-lifecycle-vocabulary.md"


def test_glossary_defines_every_suppression_state() -> None:
    text = _GLOSSARY.read_text(encoding="utf-8")
    for state in SuppressionState:
        assert state.value in text, f"glossary is missing SuppressionState '{state.value}'"


def test_glossary_in_nav() -> None:
    nav = _MKDOCS.read_text(encoding="utf-8")
    assert _NAV_PATH in nav, f"{_NAV_PATH} is not wired into the mkdocs nav"
