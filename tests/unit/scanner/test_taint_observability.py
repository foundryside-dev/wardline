"""Tests for taint suppression observability (debug logging + counters).

Covers:
- Debug log on taint map miss in _get_function_taint()
- Debug log on PY-WL-003 boundary suppression
- Warning on 0% taint map hit rate in engine
- GOVERNANCE_TAINT_CONFLICT finding for conflicting taint decorators
"""

from __future__ import annotations

import ast
import logging
from typing import TYPE_CHECKING

from wardline.core.severity import RuleId
from wardline.core.taints import TaintState
from wardline.manifest.models import BoundaryEntry, ModuleTierEntry, WardlineManifest
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.base import RuleBase
from wardline.scanner.rules.py_wl_003 import RulePyWl003

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

# ---------------------------------------------------------------------------
# Stub rule for testing base class taint miss logging
# ---------------------------------------------------------------------------

class _StubRule(RuleBase):
    RULE_ID = RuleId.PY_WL_001

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        self._get_function_taint(self._current_qualname)


# ---------------------------------------------------------------------------
# _get_function_taint() miss logging
# ---------------------------------------------------------------------------

class TestTaintMapMissLogging:
    """_get_function_taint() emits debug log when qualname is not in map."""

    def test_miss_logs_debug(self, caplog: pytest.LogCaptureFixture) -> None:
        rule = _StubRule()
        ctx = ScanContext(file_path="example.py", function_level_taint_map={})
        rule.set_context(ctx)

        with caplog.at_level(logging.DEBUG, logger="wardline.scanner.rules.base"):
            result = rule._get_function_taint("missing_func")

        assert result == TaintState.UNKNOWN_RAW
        assert any(
            "Taint map miss" in r.message and "missing_func" in r.message
            for r in caplog.records
        )

    def test_hit_does_not_log(self, caplog: pytest.LogCaptureFixture) -> None:
        rule = _StubRule()
        ctx = ScanContext(
            file_path="example.py",
            function_level_taint_map={"known_func": TaintState.ASSURED},
        )
        rule.set_context(ctx)

        with caplog.at_level(logging.DEBUG, logger="wardline.scanner.rules.base"):
            result = rule._get_function_taint("known_func")

        assert result == TaintState.ASSURED
        assert not any("Taint map miss" in r.message for r in caplog.records)

    def test_no_context_returns_unknown_raw_no_log(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No context means no taint map to miss — no debug log."""
        rule = _StubRule()
        with caplog.at_level(logging.DEBUG, logger="wardline.scanner.rules.base"):
            result = rule._get_function_taint("anything")

        assert result == TaintState.UNKNOWN_RAW
        assert not any("Taint map miss" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# PY-WL-003 boundary suppression logging
# ---------------------------------------------------------------------------

class TestPyWl003SuppressionLogging:
    """PY-WL-003 emits debug log when suppressed by structural validation boundary."""

    def test_boundary_suppression_logs_debug(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        rule = RulePyWl003()

        boundary = BoundaryEntry(
            function="validate_input",
            transition="shape_validation",
            overlay_scope="/",
        )

        ctx = ScanContext(
            file_path="/mod.py",
            function_level_taint_map={"validate_input": TaintState.GUARDED},
            boundaries=(boundary,),
        )
        rule.set_context(ctx)

        source = "def validate_input(data):\n    if 'key' in data:\n        pass\n"
        tree = ast.parse(source)

        with caplog.at_level(logging.DEBUG, logger="wardline.scanner.rules.py_wl_003"):
            rule.visit(tree)

        assert len(rule.findings) == 0
        assert any(
            "PY-WL-003 suppressed" in r.message and "validate_input" in r.message
            for r in caplog.records
        )

    def test_no_boundary_does_not_log_suppression(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        rule = RulePyWl003()
        ctx = ScanContext(
            file_path="mod.py",
            function_level_taint_map={"check_key": TaintState.EXTERNAL_RAW},
        )
        rule.set_context(ctx)

        source = "def check_key(d):\n    if 'k' in d:\n        pass\n"
        tree = ast.parse(source)

        with caplog.at_level(logging.DEBUG, logger="wardline.scanner.rules.py_wl_003"):
            rule.visit(tree)

        assert len(rule.findings) > 0
        assert not any(
            "PY-WL-003 suppressed" in r.message for r in caplog.records
        )


# ---------------------------------------------------------------------------
# Per-file taint map hit rate warning
# ---------------------------------------------------------------------------

class TestTaintHitRateWarning:
    """Engine warns when a file with functions has 0% taint map coverage."""

    def test_zero_hit_rate_warns(
        self, caplog: pytest.LogCaptureFixture, tmp_path: Path
    ) -> None:
        from wardline.scanner.engine import ScanEngine

        # File with functions but no decorators and no manifest module_tiers
        # → all functions fall back to UNKNOWN_RAW → 0% hit rate warning
        py_file = tmp_path / "no_taint.py"
        py_file.write_text("def foo():\n    pass\ndef bar():\n    pass\n")

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(),
            manifest=None,
        )

        with caplog.at_level(logging.WARNING, logger="wardline.scanner.engine"):
            engine.scan()

        assert any(
            "Taint map hit rate 0%" in r.message
            and "all fallback" in r.message
            for r in caplog.records
        )

    def test_nonzero_hit_rate_no_warning(
        self, caplog: pytest.LogCaptureFixture, tmp_path: Path
    ) -> None:
        from wardline.scanner.engine import ScanEngine

        # File with functions under a module_tiers entry → taint source is
        # "module_default", not "fallback" → no 0% warning
        py_file = tmp_path / "has_tier.py"
        py_file.write_text("def tracked():\n    pass\n")

        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path=str(tmp_path), default_taint="ASSURED"),
            ),
        )

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(),
            manifest=manifest,
        )

        with caplog.at_level(logging.WARNING, logger="wardline.scanner.engine"):
            engine.scan()

        assert not any(
            "Taint map hit rate 0%" in r.message
            and "has_tier.py" in r.message
            for r in caplog.records
        )

    def test_no_functions_no_warning(
        self, caplog: pytest.LogCaptureFixture, tmp_path: Path
    ) -> None:
        """A module with only constants/imports should not trigger."""
        py_file = tmp_path / "constants.py"
        py_file.write_text("X = 1\nY = 2\n")

        from wardline.scanner.engine import ScanEngine

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(),
        )

        with caplog.at_level(logging.WARNING, logger="wardline.scanner.engine"):
            engine.scan()

        assert not any(
            "Taint map hit rate 0%" in r.message for r in caplog.records
        )


# ---------------------------------------------------------------------------
# Taint conflict SARIF finding
# ---------------------------------------------------------------------------

class TestTaintConflictFinding:
    """Conflicting taint decorators emit a GOVERNANCE_TAINT_CONFLICT finding."""

    def test_conflicting_decorators_emit_finding(self, tmp_path: Path) -> None:
        from wardline.core.severity import RuleId as _RuleId
        from wardline.scanner.engine import ScanEngine

        py_file = tmp_path / "conflict.py"
        py_file.write_text(
            "from wardline.decorators import external_boundary, integral_read\n"
            "@external_boundary\n"
            "@integral_read\n"
            "def mixed():\n"
            "    pass\n"
        )

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(),
        )
        result = engine.scan()

        conflict_findings = [
            f for f in result.findings
            if f.rule_id == _RuleId.GOVERNANCE_TAINT_CONFLICT
        ]
        assert len(conflict_findings) >= 1
        f = conflict_findings[0]
        assert "mixed" in f.message
        assert f.qualname == "mixed"

    def test_no_conflict_no_finding(self, tmp_path: Path) -> None:
        from wardline.core.severity import RuleId as _RuleId
        from wardline.scanner.engine import ScanEngine

        py_file = tmp_path / "clean.py"
        py_file.write_text(
            "from wardline.decorators import external_boundary\n"
            "@external_boundary\n"
            "def single():\n"
            "    pass\n"
        )

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(),
        )
        result = engine.scan()

        assert not any(
            f.rule_id == _RuleId.GOVERNANCE_TAINT_CONFLICT
            for f in result.findings
        )
