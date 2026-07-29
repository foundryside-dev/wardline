"""Doc-discipline tests for the finding-lifecycle vocabulary glossary.

The glossary at ``docs/reference/finding-lifecycle-vocabulary.md`` is the single
source of truth for the finding-state / gate-population vocabulary. These tests
keep it complete (every ``SuppressionState`` value documented) and bound to the
code it cites (every ``file:line`` anchor still points at the right source line).
"""

from __future__ import annotations

import re
from pathlib import Path

from wardline.core.finding import SuppressionState

_REPO = Path(__file__).parents[2]
_GLOSSARY = _REPO / "docs" / "reference" / "finding-lifecycle-vocabulary.md"

# The glossary promises "every claim cites a real `file:line`". Line anchors rot silently
# when the cited code moves (an in-range / non-blank check would NOT catch it — the line
# still holds *some* code). So bind the load-bearing navigation anchors to a token that
# must appear on that exact source line. If code moves, this test fails and the source
# line here AND the glossary citation must be updated together. Each tuple is
# ``(repo-relative path, 1-based line, substring required on that line)``.
_ANCHORS: tuple[tuple[str, int, str], ...] = (
    # src/wardline/core/run.py — ScanSummary fields, gate population, delta-scope, gate_decision
    ("src/wardline/core/run.py", 103, "total: int"),
    ("src/wardline/core/run.py", 104, "active: int"),
    ("src/wardline/core/run.py", 106, "baselined: int"),
    ("src/wardline/core/run.py", 107, "waived: int"),
    ("src/wardline/core/run.py", 108, "judged: int"),
    ("src/wardline/core/run.py", 114, "informational: int"),
    ("src/wardline/core/run.py", 122, "unanalyzed: int"),
    ("src/wardline/core/run.py", 169, "gate_population: GatePopulation"),
    ("src/wardline/core/run.py", 201, "class GateDecision"),
    ("src/wardline/core/run.py", 211, "verdict: str"),
    ("src/wardline/core/run.py", 594, "Baseline(frozenset())"),
    ("src/wardline/core/run.py", 625, "def apply_delta_scope"),
    ("src/wardline/core/run.py", 685, "active=sum"),
    ("src/wardline/core/run.py", 775, "honors_suppressions"),
    # src/wardline/cli/scan.py — CLI summary line + gate stderr
    ("src/wardline/cli/scan.py", 665, "suppressed"),
    ("src/wardline/cli/scan.py", 666, "{s.active} active"),
    ("src/wardline/cli/scan.py", 725, "gate: FAILED"),
    # src/wardline/mcp/server.py — MCP scan summary + gate block
    ("src/wardline/mcp/server.py", 945, '"total": result.summary.total'),
    ("src/wardline/mcp/server.py", 946, '"active": result.summary.active'),
    ("src/wardline/mcp/server.py", 947, '"baselined": result.summary.baselined'),
    ("src/wardline/mcp/server.py", 948, '"waived": result.summary.waived'),
    ("src/wardline/mcp/server.py", 949, '"judged": result.summary.judged'),
    ("src/wardline/mcp/server.py", 954, '"informational": result.summary.informational'),
    ("src/wardline/mcp/server.py", 958, '"unanalyzed": result.summary.unanalyzed'),
    ("src/wardline/mcp/server.py", 961, '"gate": {'),
    ("src/wardline/mcp/server.py", 962, '"tripped": decision.tripped'),
    ("src/wardline/mcp/server.py", 966, '"verdict": decision.verdict'),
    # src/wardline/core/agent_summary.py — agent-summary JSON keys
    ("src/wardline/core/agent_summary.py", 129, '"total_findings"'),
    ("src/wardline/core/agent_summary.py", 130, '"active_defects"'),
    ("src/wardline/core/agent_summary.py", 131, '"suppressed_findings"'),
    ("src/wardline/core/agent_summary.py", 133, '"baselined"'),
    ("src/wardline/core/agent_summary.py", 134, '"waived"'),
    ("src/wardline/core/agent_summary.py", 135, '"judged"'),
    ("src/wardline/core/agent_summary.py", 141, '"informational"'),
    ("src/wardline/core/agent_summary.py", 142, '"unanalyzed"'),
    ("src/wardline/core/agent_summary.py", 145, '"tripped": self.gate.tripped'),
    ("src/wardline/core/agent_summary.py", 148, '"verdict": self.gate.verdict'),
    # informational display array (new, W3 residual fix)
    ("src/wardline/core/agent_summary.py", 172, '"informational": informational'),
    # per-finding suppression_state output key (renamed from `suppressed`, weft-f506e5f845)
    ("src/wardline/core/finding.py", 145, '"suppression_state"'),
    ("src/wardline/core/finding.py", 305, 'wardline["suppression_state"]'),
    # stable-file anchors (lower churn, but locked for free)
    ("src/wardline/core/finding.py", 77, 'ACTIVE = "active"'),
    ("src/wardline/core/suppression.py", 24, "SuppressionState.BASELINED"),
)

# Every concrete source citation in the cross-surface mapping table. Keep this
# separate from _ANCHORS: a correct citation elsewhere in the glossary must not
# mask a stale pointer inside the table itself.
_MAPPING_TABLE_ANCHORS: tuple[tuple[str, str, int, str], ...] = (
    ("every finding", "src/wardline/core/run.py", 103, "total: int"),
    ("every finding", "src/wardline/mcp/server.py", 945, '"total": result.summary.total'),
    ("every finding", "src/wardline/core/agent_summary.py", 129, '"total_findings"'),
    ("live defect", "src/wardline/cli/scan.py", 666, "{s.active} active"),
    ("live defect", "src/wardline/core/run.py", 104, "active: int"),
    ("live defect", "src/wardline/core/run.py", 685, "active=sum"),
    ("live defect", "src/wardline/mcp/server.py", 946, '"active": result.summary.active'),
    ("live defect", "src/wardline/core/agent_summary.py", 130, '"active_defects"'),
    ("live defect", "src/wardline/core/finding.py", 304, "if finding.suppressed is not SuppressionState.ACTIVE"),
    ("suppressed (sum)", "src/wardline/cli/scan.py", 665, "suppressed"),
    ("suppressed (sum)", "src/wardline/core/agent_summary.py", 131, '"suppressed_findings"'),
    ("suppressed (sum)", "src/wardline/core/finding.py", 305, 'wardline["suppression_state"]'),
    ("baselined", "src/wardline/core/run.py", 106, "baselined: int"),
    ("baselined", "src/wardline/mcp/server.py", 947, '"baselined": result.summary.baselined'),
    ("baselined", "src/wardline/core/agent_summary.py", 133, '"baselined"'),
    ("waived", "src/wardline/core/run.py", 107, "waived: int"),
    ("waived", "src/wardline/mcp/server.py", 948, '"waived": result.summary.waived'),
    ("waived", "src/wardline/core/agent_summary.py", 134, '"waived"'),
    ("judged", "src/wardline/core/run.py", 108, "judged: int"),
    ("judged", "src/wardline/mcp/server.py", 949, '"judged": result.summary.judged'),
    ("judged", "src/wardline/core/agent_summary.py", 135, '"judged"'),
    ("informational (summary)", "src/wardline/core/run.py", 114, "informational: int"),
    (
        "informational (summary)",
        "src/wardline/mcp/server.py",
        954,
        '"informational": result.summary.informational',
    ),
    ("informational (summary)", "src/wardline/core/agent_summary.py", 141, '"informational"'),
    ("informational (display)", "src/wardline/core/agent_summary.py", 172, '"informational": informational'),
    ("under-scan", "src/wardline/core/run.py", 122, "unanalyzed: int"),
    ("under-scan", "src/wardline/mcp/server.py", 958, '"unanalyzed": result.summary.unanalyzed'),
    ("under-scan", "src/wardline/core/agent_summary.py", 142, '"unanalyzed"'),
    ("gate verdict", "src/wardline/core/run.py", 169, "gate_population: GatePopulation"),
    ("gate verdict", "src/wardline/core/run.py", 201, "class GateDecision"),
    ("gate verdict", "src/wardline/core/run.py", 211, "verdict: str"),
    ("gate verdict", "src/wardline/mcp/server.py", 961, '"gate": {'),
    ("gate verdict", "src/wardline/mcp/server.py", 962, '"tripped": decision.tripped'),
    ("gate verdict", "src/wardline/mcp/server.py", 966, '"verdict": decision.verdict'),
    ("gate verdict", "src/wardline/core/agent_summary.py", 145, '"tripped": self.gate.tripped'),
    ("gate verdict", "src/wardline/core/agent_summary.py", 148, '"verdict": self.gate.verdict'),
)


def test_glossary_defines_every_suppression_state() -> None:
    text = _GLOSSARY.read_text(encoding="utf-8")
    for state in SuppressionState:
        assert state.value in text, f"glossary is missing SuppressionState '{state.value}'"


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


def test_mapping_table_anchors_bind_to_code() -> None:
    text = _GLOSSARY.read_text(encoding="utf-8")
    table = text.split("## Cross-surface mapping table", 1)[1].split("\n\nThe unsuppressed", 1)[0]
    rows = {}
    for row in table.splitlines():
        if row.startswith("|"):
            rows[row.split("|")[1].strip()] = row
    for concept, relpath, line, token in _MAPPING_TABLE_ANCHORS:
        code = (_REPO / relpath).read_text(encoding="utf-8").splitlines()
        assert token in code[line - 1], f"{relpath}:{line} no longer contains {token!r}"
        base = relpath.rsplit("/", 1)[-1]
        cite = re.compile(rf"`(?:[\w./-]+/)?{re.escape(base)}:[\d,\-]*\b{line}\b")
        assert cite.search(rows[concept]), f"mapping table row {concept!r} no longer cites {base}:{line}"
