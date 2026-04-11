"""Tests for dependency taint wiring through the engine into L2 variable taint.

Verifies that ScanEngine resolves DependencyTaintEntry declarations via
import alias mapping and threads them through to compute_variable_taints(),
producing correct per-variable taint assignments for:
- Dotted calls (import requests; requests.get(url))
- Bare imports (from requests import get; get(url))
- Aliased imports (import requests as req; req.get(url))
- Undeclared functions in declared packages (UNKNOWN_RAW fallback)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from wardline.core.severity import RuleId
from wardline.core.taints import TaintState
from wardline.manifest.models import DependencyTaintEntry, WardlineManifest
from wardline.scanner.engine import ScanEngine
from wardline.scanner.rules.base import RuleBase

if TYPE_CHECKING:
    import ast
    from pathlib import Path

    from wardline.scanner.context import ScanContext


# ── Helper rule that captures context ────────────────────────────


class _ContextCapturingRule(RuleBase):
    """Captures the ScanContext set by the engine for later inspection."""

    RULE_ID: ClassVar[RuleId] = RuleId.TEST_STUB

    def __init__(self) -> None:
        super().__init__()
        self.captured_contexts: list[ScanContext | None] = []

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        self.captured_contexts.append(self._context)


# ── Helpers ──────────────────────────────────────────────────────


def _write_py(path: Path, content: str) -> None:
    """Write a Python file, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _make_manifest(*entries: DependencyTaintEntry) -> WardlineManifest:
    """Build a minimal manifest with dependency_taint entries."""
    return WardlineManifest(dependency_taint=entries)


def _get_var_taint(
    rule: _ContextCapturingRule,
    func_name: str,
    var_name: str,
) -> TaintState | None:
    """Extract a variable taint from captured contexts."""
    for ctx in rule.captured_contexts:
        if ctx is not None and ctx.variable_taint_map is not None:
            func_vars = ctx.variable_taint_map.get(func_name)
            if func_vars is not None and var_name in func_vars:
                return func_vars[var_name]
    return None


# ── TestDependencyTaintWiring ────────────────────────────────────


class TestDependencyTaintWiring:
    """Engine resolves dependency taint entries and threads them into L2."""

    def test_dotted_call_gets_declared_taint(self, tmp_path: Path) -> None:
        """import requests; x = requests.get(url) -> x is EXTERNAL_RAW."""
        src = tmp_path / "src"
        _write_py(
            src / "app.py",
            "import requests\n\ndef fetch():\n    x = requests.get('http://example.com')\n",
        )
        manifest = _make_manifest(
            DependencyTaintEntry(
                package="requests",
                function="get",
                returns_taint="EXTERNAL_RAW",
                rationale="HTTP response is untrusted",
            ),
        )
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            rules=(rule,),
            analysis_level=2,
        )
        engine.scan()
        taint = _get_var_taint(rule, "fetch", "x")
        assert taint == TaintState.EXTERNAL_RAW

    def test_bare_import_gets_declared_taint(self, tmp_path: Path) -> None:
        """from requests import get; x = get(url) -> x is EXTERNAL_RAW."""
        src = tmp_path / "src"
        _write_py(
            src / "app.py",
            "from requests import get\n\ndef fetch():\n    x = get('http://example.com')\n",
        )
        manifest = _make_manifest(
            DependencyTaintEntry(
                package="requests",
                function="get",
                returns_taint="EXTERNAL_RAW",
                rationale="HTTP response is untrusted",
            ),
        )
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            rules=(rule,),
            analysis_level=2,
        )
        engine.scan()
        taint = _get_var_taint(rule, "fetch", "x")
        assert taint == TaintState.EXTERNAL_RAW

    def test_aliased_import_gets_declared_taint(self, tmp_path: Path) -> None:
        """import requests as req; x = req.get(url) -> x is EXTERNAL_RAW."""
        src = tmp_path / "src"
        _write_py(
            src / "app.py",
            "import requests as req\n\ndef fetch():\n    x = req.get('http://example.com')\n",
        )
        manifest = _make_manifest(
            DependencyTaintEntry(
                package="requests",
                function="get",
                returns_taint="EXTERNAL_RAW",
                rationale="HTTP response is untrusted",
            ),
        )
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            rules=(rule,),
            analysis_level=2,
        )
        engine.scan()
        taint = _get_var_taint(rule, "fetch", "x")
        assert taint == TaintState.EXTERNAL_RAW

    def test_undeclared_function_in_declared_package_gets_unknown_raw(
        self, tmp_path: Path
    ) -> None:
        """import requests; x = requests.head(url) when only .get declared -> UNKNOWN_RAW."""
        src = tmp_path / "src"
        _write_py(
            src / "app.py",
            "import requests\n\ndef fetch():\n    x = requests.head('http://example.com')\n",
        )
        manifest = _make_manifest(
            DependencyTaintEntry(
                package="requests",
                function="get",
                returns_taint="EXTERNAL_RAW",
                rationale="HTTP response is untrusted",
            ),
        )
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            rules=(rule,),
            analysis_level=2,
        )
        engine.scan()
        taint = _get_var_taint(rule, "fetch", "x")
        assert taint == TaintState.UNKNOWN_RAW
