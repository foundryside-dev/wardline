"""Doc-discipline tests for the finding-lifecycle vocabulary glossary.

The glossary at ``docs/reference/finding-lifecycle-vocabulary.md`` is the single
source of truth for the finding-state / gate-population vocabulary. These tests
keep it complete (every ``SuppressionState`` value documented) and wired into the
mkdocs nav (so ``mkdocs build --strict`` does not orphan it).
"""

from __future__ import annotations

import re
from pathlib import Path

from wardline.core.finding import SuppressionState

_REPO = Path(__file__).parents[2]
_GLOSSARY = _REPO / "docs" / "reference" / "finding-lifecycle-vocabulary.md"
_MKDOCS = _REPO / "mkdocs.yml"
_NAV_PATH = "reference/finding-lifecycle-vocabulary.md"

# The glossary promises "every claim cites a real `file:line`". Line anchors rot silently
# when the cited code moves (an in-range / non-blank check would NOT catch it — the line
# still holds *some* code). So bind the load-bearing navigation anchors to a token that
# must appear on that exact source line. If code moves, this test fails and the source
# line here AND the glossary citation must be updated together. Each tuple is
# ``(repo-relative path, 1-based line, substring required on that line)``.
_ANCHORS: tuple[tuple[str, int, str], ...] = (
    # src/wardline/core/run.py — ScanSummary fields, gate population, delta-scope, gate_decision
    ("src/wardline/core/run.py", 50, "total: int"),
    ("src/wardline/core/run.py", 51, "active: int"),
    ("src/wardline/core/run.py", 53, "baselined: int"),
    ("src/wardline/core/run.py", 54, "waived: int"),
    ("src/wardline/core/run.py", 55, "judged: int"),
    ("src/wardline/core/run.py", 61, "informational: int"),
    ("src/wardline/core/run.py", 69, "unanalyzed: int"),
    ("src/wardline/core/run.py", 88, "gate_findings:"),
    ("src/wardline/core/run.py", 98, "class GateDecision"),
    ("src/wardline/core/run.py", 107, "verdict: str"),
    ("src/wardline/core/run.py", 327, "Baseline(frozenset())"),
    ("src/wardline/core/run.py", 337, "def apply_delta_scope"),
    ("src/wardline/core/run.py", 361, "active=sum"),
    ("src/wardline/core/run.py", 412, "honors_suppressions"),
    # src/wardline/cli/scan.py — CLI summary line + gate stderr
    ("src/wardline/cli/scan.py", 415, "suppressed"),
    ("src/wardline/cli/scan.py", 416, "{s.active} active"),
    ("src/wardline/cli/scan.py", 456, "gate: FAILED"),
    # src/wardline/mcp/server.py — MCP scan summary + gate block
    ("src/wardline/mcp/server.py", 330, '"total": result.summary.total'),
    ("src/wardline/mcp/server.py", 331, '"active": result.summary.active'),
    ("src/wardline/mcp/server.py", 332, '"baselined": result.summary.baselined'),
    ("src/wardline/mcp/server.py", 333, '"waived": result.summary.waived'),
    ("src/wardline/mcp/server.py", 334, '"judged": result.summary.judged'),
    ("src/wardline/mcp/server.py", 339, '"informational": result.summary.informational'),
    ("src/wardline/mcp/server.py", 343, '"unanalyzed": result.summary.unanalyzed'),
    ("src/wardline/mcp/server.py", 345, '"gate": {'),
    ("src/wardline/mcp/server.py", 346, '"tripped": decision.tripped'),
    ("src/wardline/mcp/server.py", 349, '"verdict": decision.verdict'),
    # src/wardline/core/agent_summary.py — agent-summary JSON keys
    ("src/wardline/core/agent_summary.py", 134, '"total_findings"'),
    ("src/wardline/core/agent_summary.py", 135, '"active_defects"'),
    ("src/wardline/core/agent_summary.py", 136, '"suppressed_findings"'),
    ("src/wardline/core/agent_summary.py", 138, '"baselined"'),
    ("src/wardline/core/agent_summary.py", 139, '"waived"'),
    ("src/wardline/core/agent_summary.py", 140, '"judged"'),
    ("src/wardline/core/agent_summary.py", 146, '"informational"'),
    ("src/wardline/core/agent_summary.py", 147, '"unanalyzed"'),
    ("src/wardline/core/agent_summary.py", 150, '"tripped": self.gate.tripped'),
    ("src/wardline/core/agent_summary.py", 153, '"verdict": self.gate.verdict'),
    # informational display array (new, W3 residual fix)
    ("src/wardline/core/agent_summary.py", 171, '"informational": informational'),
    # per-finding suppression_state output key (renamed from `suppressed`, weft-f506e5f845)
    ("src/wardline/core/finding.py", 140, '"suppression_state"'),
    ("src/wardline/core/finding.py", 285, 'wardline["suppression_state"]'),
    # stable-file anchors (lower churn, but locked for free)
    ("src/wardline/core/finding.py", 72, 'ACTIVE = "active"'),
    ("src/wardline/core/suppression.py", 24, "SuppressionState.BASELINED"),
)


def test_glossary_defines_every_suppression_state() -> None:
    text = _GLOSSARY.read_text(encoding="utf-8")
    for state in SuppressionState:
        assert state.value in text, f"glossary is missing SuppressionState '{state.value}'"


def test_glossary_in_nav() -> None:
    nav = _MKDOCS.read_text(encoding="utf-8")
    assert _NAV_PATH in nav, f"{_NAV_PATH} is not wired into the mkdocs nav"


def test_glossary_anchors_bind_to_code() -> None:
    """Each load-bearing ``file:line`` the glossary cites must point at the right code.

    Two-way lock: (1) the cited source line still contains its anchor token (catches code
    that moved out from under the citation), and (2) the glossary actually cites that line
    (catches the doc drifting away from the code). Both must hold, so doc + code can never
    silently diverge — the exact rot this PR's review found.
    """
    text = _GLOSSARY.read_text(encoding="utf-8")
    for relpath, line, token in _ANCHORS:
        code = (_REPO / relpath).read_text(encoding="utf-8").splitlines()
        assert 1 <= line <= len(code), f"{relpath}:{line} is out of range ({len(code)} lines)"
        assert token in code[line - 1], (
            f"{relpath}:{line} no longer contains {token!r} (got {code[line - 1]!r}); "
            f"update both the source line in _ANCHORS and the glossary citation"
        )
        base = relpath.rsplit("/", 1)[-1]
        # The glossary cites the basename (`run.py:280`) or a full path, possibly inside a
        # comma/dash list (`run.py:49,280` / `run.py:82-92`). Require the line to appear.
        cite = re.compile(rf"`(?:[\w./-]+/)?{re.escape(base)}:[\d,\-]*\b{line}\b")
        assert cite.search(text), f"glossary no longer cites {base}:{line} (anchor {token!r})"
