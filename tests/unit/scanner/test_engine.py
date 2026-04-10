"""Tests for ScanEngine — file discovery, parse errors, rule crashes."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

import pytest

from wardline.core.severity import RuleId, Severity
from wardline.manifest.models import BoundaryEntry, ModuleTierEntry, WardlineManifest
from wardline.scanner.context import ScanContext
from wardline.scanner.engine import ScanEngine
from wardline.scanner.rules.base import RuleBase

if TYPE_CHECKING:
    import ast
    from pathlib import Path


# ── Test rule implementations ────────────────────────────────────


class _CountingRule(RuleBase):
    """Counts function visits — used to verify the engine runs rules."""

    RULE_ID: ClassVar[RuleId] = RuleId.TEST_STUB

    def __init__(self) -> None:
        super().__init__()
        self.visited: list[tuple[str, str]] = []

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        self.visited.append((node.name, "async" if is_async else "sync"))


class _CrashingRule(RuleBase):
    """Always raises RuntimeError — used to test TOOL-ERROR handling."""

    RULE_ID: ClassVar[RuleId] = RuleId.TEST_STUB

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        raise RuntimeError("deliberate crash for testing")


# ── Helpers ──────────────────────────────────────────────────────


def _write_py(path: Path, content: str) -> None:
    """Write a Python file, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ── Normal multi-file scan ───────────────────────────────────────


class TestNormalScan:
    """Engine discovers and scans multiple .py files."""

    def test_scans_multiple_files(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")
        _write_py(tmp_path / "sub" / "b.py", "async def bar(): pass\n")

        rule = _CountingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
        )
        result = engine.scan()

        assert result.files_scanned == 2
        assert result.files_skipped == 0
        assert len(result.errors) == 0
        # Both functions should be visited
        visited_names = {name for name, _ in rule.visited}
        assert visited_names == {"foo", "bar"}

    def test_skips_non_python_files(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "code.py", "def x(): pass\n")
        (tmp_path / "readme.txt").write_text("not python", encoding="utf-8")
        (tmp_path / "data.json").write_text("{}", encoding="utf-8")

        rule = _CountingRule()
        engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
        result = engine.scan()

        assert result.files_scanned == 1

    def test_empty_target_returns_empty_result(self, tmp_path: Path) -> None:
        engine = ScanEngine(target_paths=(tmp_path,))
        result = engine.scan()

        assert result.files_scanned == 0
        assert result.findings == []

    def test_no_rules_still_counts_files(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "x = 1\n")

        engine = ScanEngine(target_paths=(tmp_path,), rules=())
        result = engine.scan()

        assert result.files_scanned == 1
        assert result.findings == []

    def test_builds_project_indexes_before_rule_execution(self, tmp_path: Path) -> None:
        _write_py(
            tmp_path / "helpers.py",
            """\
from wardline.decorators.lifecycle import test_only

@test_only
def helper():
    return "beta"
""",
        )
        _write_py(
            tmp_path / "service.py",
            """\
def use_helper():
    return "beta"
""",
        )

        class _ContextAssertingRule(RuleBase):
            RULE_ID: ClassVar[RuleId] = RuleId.TEST_STUB

            def visit_function(
                self,
                node: ast.FunctionDef | ast.AsyncFunctionDef,
                *,
                is_async: bool,
            ) -> None:
                assert self._context is not None
                assert self._context.project_annotations_map is not None
                assert self._context.module_file_map is not None
                assert self._context.string_literal_counts is not None
                assert ("beta" in self._context.string_literal_counts)
                assert any(
                    ann.canonical_name == "test_only"
                    for annotations in self._context.project_annotations_map.values()
                    for ann in annotations
                )

        engine = ScanEngine(target_paths=(tmp_path,), rules=(_ContextAssertingRule(),))

        result = engine.scan()

        assert result.files_scanned == 2
        assert result.findings == []


# ── Exclude paths ────────────────────────────────────────────────


class TestExcludePaths:
    """Engine respects exclude_paths for both directories and files."""

    def test_excludes_directory(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "keep" / "a.py", "def keep(): pass\n")
        _write_py(tmp_path / "skip" / "b.py", "def skip(): pass\n")

        rule = _CountingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            exclude_paths=(tmp_path / "skip",),
            rules=(rule,),
        )
        result = engine.scan()

        assert result.files_scanned == 1
        visited_names = {name for name, _ in rule.visited}
        assert visited_names == {"keep"}

    def test_excludes_nested_directory(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a" / "b" / "deep.py", "def deep(): pass\n")

        engine = ScanEngine(
            target_paths=(tmp_path,),
            exclude_paths=(tmp_path / "a" / "b",),
            rules=(_CountingRule(),),
        )
        result = engine.scan()

        assert result.files_scanned == 0


# ── Parse error handling ─────────────────────────────────────────


class TestParseErrors:
    """Engine skips files with syntax errors and continues scanning."""

    def test_syntax_error_skips_file_continues_scan(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "good.py", "def ok(): pass\n")
        _write_py(tmp_path / "bad.py", "def broken(\n")  # unterminated

        rule = _CountingRule()
        engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
        result = engine.scan()

        assert result.files_scanned == 1
        assert result.files_skipped == 1
        assert any("Syntax error" in e for e in result.errors)
        # The good file's function should still be visited
        assert len(rule.visited) == 1

    def test_all_files_bad_produces_zero_scanned(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "bad1.py", "def (\n")
        _write_py(tmp_path / "bad2.py", "class\n")

        engine = ScanEngine(target_paths=(tmp_path,), rules=(_CountingRule(),))
        result = engine.scan()

        assert result.files_scanned == 0
        assert result.files_skipped == 2

    def test_utf8_bom_file_is_read(self, tmp_path: Path) -> None:
        bom_file = tmp_path / "bom.py"
        bom_file.write_bytes(b"\xef\xbb\xbfdef bom():\n    return 1\n")

        rule = _CountingRule()
        engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
        result = engine.scan()

        assert result.files_scanned == 1
        assert result.files_skipped == 0
        assert len(result.errors) == 0
        assert {name for name, _ in rule.visited} == {"bom"}

    def test_pep263_encoded_file_is_read(self, tmp_path: Path) -> None:
        encoded = tmp_path / "latin1.py"
        encoded.write_bytes(
            "# -*- coding: latin-1 -*-\n".encode("ascii")
            + "def cafe():\n    return 'caf\xe9'\n".encode("latin-1")
        )

        rule = _CountingRule()
        engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
        result = engine.scan()

        assert result.files_scanned == 1
        assert result.files_skipped == 0
        assert len(result.errors) == 0
        assert {name for name, _ in rule.visited} == {"cafe"}

    def test_invalid_encoding_reports_encoding_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad_encoding.py"
        bad.write_bytes(
            b"# -*- coding: ascii -*-\n"
            b"def broken():\n    return '\xff'\n"
        )

        engine = ScanEngine(target_paths=(tmp_path,), rules=(_CountingRule(),))
        result = engine.scan()

        assert result.files_scanned == 0
        assert result.files_skipped == 1
        assert any("Encoding error" in e for e in result.errors)


# ── Permission errors ────────────────────────────────────────────


class TestPermissionErrors:
    """Engine handles unreadable files and directories gracefully."""

    def test_unreadable_file_skipped_with_warning(self, tmp_path: Path) -> None:
        good = tmp_path / "good.py"
        bad = tmp_path / "noperm.py"
        _write_py(good, "def ok(): pass\n")
        _write_py(bad, "def secret(): pass\n")

        # Remove read permission
        bad.chmod(0o000)
        try:
            rule = _CountingRule()
            engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
            result = engine.scan()

            assert result.files_scanned == 1
            assert result.files_skipped == 1
            assert any(
                "Permission denied" in e or "Cannot read" in e
                for e in result.errors
            )
        finally:
            # Restore permissions for cleanup
            bad.chmod(0o644)

    def test_unreadable_directory_skipped(self, tmp_path: Path) -> None:
        good_dir = tmp_path / "good"
        bad_dir = tmp_path / "noaccess"
        _write_py(good_dir / "a.py", "def ok(): pass\n")
        bad_dir.mkdir()
        _write_py(bad_dir / "b.py", "def hidden(): pass\n")

        bad_dir.chmod(0o000)
        try:
            rule = _CountingRule()
            engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
            result = engine.scan()

            # Good file should still be scanned
            assert result.files_scanned >= 1
            visited_names = {name for name, _ in rule.visited}
            assert "ok" in visited_names
        finally:
            bad_dir.chmod(0o755)


# ── Rule crash → TOOL-ERROR finding ─────────────────────────────


class TestRuleCrashHandling:
    """A crashing rule produces a TOOL-ERROR finding without aborting."""

    def test_crashing_rule_emits_tool_error(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "code.py", "def trigger(): pass\n")

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(_CrashingRule(),),
        )
        result = engine.scan()

        assert result.files_scanned == 1
        assert len(result.findings) == 1

        finding = result.findings[0]
        assert finding.rule_id == RuleId.TOOL_ERROR
        assert finding.severity == Severity.WARNING
        assert "_CrashingRule" in finding.message
        assert "deliberate crash" in finding.message

    def test_crash_does_not_abort_other_rules(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "code.py", "def hello(): pass\n")

        counting = _CountingRule()
        crashing = _CrashingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(crashing, counting),
        )
        result = engine.scan()

        # Counting rule should still have run after the crash
        assert len(counting.visited) == 1
        assert counting.visited[0][0] == "hello"
        # Should have one TOOL-ERROR from the crashing rule
        tool_errors = [f for f in result.findings if f.rule_id == RuleId.TOOL_ERROR]
        assert len(tool_errors) == 1

    def test_crash_on_multiple_files(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def one(): pass\n")
        _write_py(tmp_path / "b.py", "def two(): pass\n")

        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(_CrashingRule(),),
        )
        result = engine.scan()

        assert result.files_scanned == 2
        tool_errors = [f for f in result.findings if f.rule_id == RuleId.TOOL_ERROR]
        assert len(tool_errors) == 2


# ── Symlink safety ───────────────────────────────────────────────


class TestSymlinkSafety:
    """Engine does not follow symlinks during directory walk."""

    def test_does_not_follow_directory_symlinks(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real"
        _write_py(real_dir / "a.py", "def real_fn(): pass\n")

        # Create a symlink loop
        link = tmp_path / "scan_root" / "link_to_real"
        (tmp_path / "scan_root").mkdir()
        _write_py(tmp_path / "scan_root" / "b.py", "def scan_fn(): pass\n")
        link.symlink_to(real_dir)

        rule = _CountingRule()
        engine = ScanEngine(
            target_paths=(tmp_path / "scan_root",),
            rules=(rule,),
        )
        result = engine.scan()

        # Should only scan b.py, not follow the symlink to real/a.py
        assert result.files_scanned == 1
        visited_names = {name for name, _ in rule.visited}
        assert visited_names == {"scan_fn"}


# ── Target path validation ───────────────────────────────────────


class TestTargetValidation:
    """Engine handles invalid target paths gracefully."""

    def test_nonexistent_target_reported(self, tmp_path: Path) -> None:
        engine = ScanEngine(
            target_paths=(tmp_path / "does_not_exist",),
        )
        result = engine.scan()

        assert result.files_scanned == 0
        assert any("not a directory" in e for e in result.errors)

    def test_file_as_target_reported(self, tmp_path: Path) -> None:
        f = tmp_path / "file.py"
        f.write_text("x = 1\n", encoding="utf-8")

        engine = ScanEngine(target_paths=(f,))
        result = engine.scan()

        assert result.files_scanned == 0
        assert any("not a directory" in e for e in result.errors)


# ── Multiple targets ─────────────────────────────────────────────


class TestMultipleTargets:
    """Engine scans across multiple target directories."""

    def test_scans_all_targets(self, tmp_path: Path) -> None:
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        _write_py(dir_a / "mod_a.py", "def fn_a(): pass\n")
        _write_py(dir_b / "mod_b.py", "def fn_b(): pass\n")

        rule = _CountingRule()
        engine = ScanEngine(
            target_paths=(dir_a, dir_b),
            rules=(rule,),
        )
        result = engine.scan()

        assert result.files_scanned == 2
        visited_names = {name for name, _ in rule.visited}
        assert visited_names == {"fn_a", "fn_b"}


# ── Context-capturing rule for boundary tests ────────────────────


class _ContextCapturingRule(RuleBase):
    """Captures self._context on visit_function for test inspection."""

    RULE_ID: ClassVar[RuleId] = RuleId.TEST_STUB

    def __init__(self) -> None:
        super().__init__()
        self.captured_context: ScanContext | None = None

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        self.captured_context = self._context


# ── ScanContext.boundaries tests ─────────────────────────────────


class TestScanContextBoundaries:
    """ScanContext carries overlay boundaries as a frozen tuple."""

    def test_boundaries_default_empty(self) -> None:
        ctx = ScanContext(file_path="test.py", function_level_taint_map={})
        assert ctx.boundaries == ()

    def test_boundaries_set_at_construction(self) -> None:
        b = BoundaryEntry(function="fn", transition="construction")
        ctx = ScanContext(
            file_path="test.py",
            function_level_taint_map={},
            boundaries=(b,),
        )
        assert len(ctx.boundaries) == 1
        assert ctx.boundaries[0].function == "fn"

    def test_boundaries_frozen(self) -> None:
        ctx = ScanContext(file_path="test.py", function_level_taint_map={})
        with pytest.raises(AttributeError):
            ctx.boundaries = ()  # type: ignore[misc]


# ── Engine boundary injection tests ──────────────────────────────


class TestEngineBoundaryInjection:
    """ScanEngine passes boundaries through to ScanContext."""

    def test_engine_passes_boundaries_to_context(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")
        b = BoundaryEntry(function="foo", transition="construction")
        rule = _ContextCapturingRule()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=(rule,),
            boundaries=(b,),
        )
        engine.scan()
        assert rule.captured_context is not None
        assert len(rule.captured_context.boundaries) == 1

    def test_engine_no_boundaries_backward_compat(self, tmp_path: Path) -> None:
        _write_py(tmp_path / "a.py", "def foo(): pass\n")
        rule = _ContextCapturingRule()
        engine = ScanEngine(target_paths=(tmp_path,), rules=(rule,))
        engine.scan()
        assert rule.captured_context is not None
        assert rule.captured_context.boundaries == ()


class TestScanResultFileTracking:
    def test_scanned_file_paths_populated(self, tmp_path: Path) -> None:
        """Engine records the paths of files it successfully scanned."""
        py_file = tmp_path / "example.py"
        py_file.write_text("x = 1\n", encoding="utf-8")

        from wardline.scanner.engine import ScanEngine, ScanResult
        from wardline.manifest.models import WardlineManifest

        engine = ScanEngine(
            target_paths=(tmp_path,),
            exclude_paths=(),
            rules=(),
            manifest=WardlineManifest(),
            boundaries=(),
            optional_fields=(),
            analysis_level=1,
        )
        result = engine.scan()
        assert len(result.scanned_file_paths) == 1
        assert result.scanned_file_paths[0] == py_file.resolve()

    def test_scanned_file_paths_excludes_skipped(self, tmp_path: Path) -> None:
        """Files that fail to parse are not in scanned_file_paths."""
        bad_file = tmp_path / "bad.py"
        bad_file.write_text("def broken(\n", encoding="utf-8")

        from wardline.scanner.engine import ScanEngine, ScanResult
        from wardline.manifest.models import WardlineManifest

        engine = ScanEngine(
            target_paths=(tmp_path,),
            exclude_paths=(),
            rules=(),
            manifest=WardlineManifest(),
            boundaries=(),
            optional_fields=(),
            analysis_level=1,
        )
        result = engine.scan()
        assert result.scanned_file_paths == []
        assert result.files_skipped == 1


# ── Tier-aware syntax error escalation (PY-011) ────────────────


class TestSyntaxErrorEscalation:
    """Syntax errors in Tier 1 modules escalate to ERROR severity."""

    def test_syntax_error_in_tier1_module_is_error(self, tmp_path: Path) -> None:
        """Syntax error in a Tier 1 (INTEGRAL) module -> ERROR severity."""
        src = tmp_path / "src" / "core"
        src.mkdir(parents=True)
        (src / "bad.py").write_text("def f(\n", encoding="utf-8")

        manifest = WardlineManifest(
            module_tiers=(ModuleTierEntry(path="src/core", default_taint="INTEGRAL"),),
        )
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            project_root=tmp_path,
        )
        result = engine.scan()

        syntax_findings = [f for f in result.findings if "syntax" in f.message.lower()]
        assert len(syntax_findings) == 1
        assert syntax_findings[0].severity == Severity.ERROR

    def test_syntax_error_in_tier2_module_is_warning(self, tmp_path: Path) -> None:
        """Syntax error in a Tier 2 (ASSURED) module -> WARNING severity."""
        src = tmp_path / "src" / "scanner"
        src.mkdir(parents=True)
        (src / "bad.py").write_text("def f(\n", encoding="utf-8")

        manifest = WardlineManifest(
            module_tiers=(ModuleTierEntry(path="src/scanner", default_taint="ASSURED"),),
        )
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            project_root=tmp_path,
        )
        result = engine.scan()

        syntax_findings = [f for f in result.findings if "syntax" in f.message.lower()]
        assert len(syntax_findings) == 1
        assert syntax_findings[0].severity == Severity.WARNING

    def test_syntax_error_in_tier4_module_is_warning(self, tmp_path: Path) -> None:
        """Syntax error in a Tier 4 (EXTERNAL_RAW) module -> WARNING severity."""
        src = tmp_path / "src" / "cli"
        src.mkdir(parents=True)
        (src / "bad.py").write_text("def f(\n", encoding="utf-8")

        manifest = WardlineManifest(
            module_tiers=(ModuleTierEntry(path="src/cli", default_taint="EXTERNAL_RAW"),),
        )
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            project_root=tmp_path,
        )
        result = engine.scan()

        syntax_findings = [f for f in result.findings if "syntax" in f.message.lower()]
        assert len(syntax_findings) == 1
        assert syntax_findings[0].severity == Severity.WARNING

    def test_syntax_error_in_unassigned_module_is_warning(self, tmp_path: Path) -> None:
        """Syntax error in a module with no tier assignment -> WARNING."""
        src = tmp_path / "unknown"
        src.mkdir()
        (src / "bad.py").write_text("def f(\n", encoding="utf-8")

        manifest = WardlineManifest()
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            project_root=tmp_path,
        )
        result = engine.scan()

        syntax_findings = [f for f in result.findings if "syntax" in f.message.lower()]
        assert len(syntax_findings) == 1
        assert syntax_findings[0].severity == Severity.WARNING

    def test_syntax_error_no_manifest_is_warning(self, tmp_path: Path) -> None:
        """Syntax error with no manifest at all -> WARNING."""
        src = tmp_path / "pkg"
        src.mkdir()
        (src / "bad.py").write_text("def f(\n", encoding="utf-8")

        engine = ScanEngine(target_paths=(src,))
        result = engine.scan()

        syntax_findings = [f for f in result.findings if "syntax" in f.message.lower()]
        assert len(syntax_findings) == 1
        assert syntax_findings[0].severity == Severity.WARNING


# ── TestPopulateSnippets ──────────────────────────────────────────


class TestPopulateSnippets:
    """Tests for the shared snippet-population helper."""

    def test_populates_none_snippet_from_source(self) -> None:
        from wardline.core.severity import Exceptionability
        from wardline.scanner.context import Finding, populate_snippets

        source = "line_zero\ndef process(data):\n    x = data.get('key', 'default')\n"
        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="test.py", line=3, col=4,
            end_line=3, end_col=30, message="test", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet=None, qualname="process",
        )
        result = populate_snippets([f], source)
        assert len(result) == 1
        assert result[0].source_snippet == "x = data.get('key', 'default')"

    def test_preserves_existing_snippet(self) -> None:
        from wardline.core.severity import Exceptionability
        from wardline.scanner.context import Finding, populate_snippets

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="test.py", line=1, col=0,
            end_line=1, end_col=10, message="test", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet="already set", qualname=None,
        )
        result = populate_snippets([f], "some source")
        assert result[0].source_snippet == "already set"

    def test_none_source_returns_findings_unchanged(self) -> None:
        from wardline.core.severity import Exceptionability
        from wardline.scanner.context import Finding, populate_snippets

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="test.py", line=1, col=0,
            end_line=None, end_col=None, message="test", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet=None, qualname=None,
        )
        result = populate_snippets([f], None)
        assert result[0].source_snippet is None

    def test_out_of_range_line_keeps_none(self) -> None:
        from wardline.core.severity import Exceptionability
        from wardline.scanner.context import Finding, populate_snippets

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="test.py", line=0, col=0,
            end_line=None, end_col=None, message="test", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet=None, qualname=None,
        )
        result = populate_snippets([f], "one line")
        assert result[0].source_snippet is None

    def test_snippet_is_stripped(self) -> None:
        from wardline.core.severity import Exceptionability
        from wardline.scanner.context import Finding, populate_snippets

        f = Finding(
            rule_id=RuleId.PY_WL_001, file_path="test.py", line=1, col=0,
            end_line=None, end_col=None, message="test", severity=Severity.ERROR,
            exceptionability=Exceptionability.STANDARD, taint_state=None,
            analysis_level=1, source_snippet=None, qualname=None,
        )
        result = populate_snippets([f], "    indented_code    ")
        assert result[0].source_snippet == "indented_code"


class TestEngineSnippetPopulation:
    """Verify _run_rule populates source_snippet on findings."""

    def test_source_snippet_populated_after_rule_visit(self, tmp_path: Path) -> None:
        """Scan a Python file containing a PY-WL-001 pattern, verify snippets."""
        code = 'def process(data):\n    x = data.get("key", "default")\n'
        py_file = tmp_path / "test_snippet.py"
        py_file.write_text(code)

        from wardline.scanner.rules import make_rules
        rules = make_rules()
        engine = ScanEngine(
            target_paths=(tmp_path,),
            rules=rules,
        )
        result = engine.scan()

        pywl001 = [f for f in result.findings if str(f.rule_id) == "PY-WL-001"]
        assert len(pywl001) >= 1, f"Expected PY-WL-001 finding, got: {[str(f.rule_id) for f in result.findings]}"
        for f in pywl001:
            assert f.source_snippet is not None, (
                f"source_snippet should be populated, got None for finding at line {f.line}"
            )


class TestEngineCoverageCounts:
    """Coverage counting: annotated vs total functions from project index."""

    def test_engine_coverage_counts(self, tmp_path: Path) -> None:
        """Scan counts annotated and total functions correctly."""
        _write_py(
            tmp_path / "annotated.py",
            """\
from wardline.decorators.lifecycle import test_only

@test_only
def decorated_func():
    pass

def plain_func():
    pass
""",
        )
        _write_py(
            tmp_path / "plain.py",
            """\
def another_func():
    pass

def yet_another():
    pass
""",
        )

        engine = ScanEngine(target_paths=(tmp_path,), rules=())
        result = engine.scan()

        assert result.total_function_count == 4
        assert result.annotated_function_count == 1

    def test_coverage_counts_zero_when_no_files(self, tmp_path: Path) -> None:
        """Empty directory yields zero counts."""
        engine = ScanEngine(target_paths=(tmp_path,), rules=())
        result = engine.scan()

        assert result.total_function_count == 0
        assert result.annotated_function_count == 0

    def test_coverage_counts_zero_annotations_when_no_decorators(self, tmp_path: Path) -> None:
        """Files with functions but no wardline decorators → annotated=0."""
        _write_py(tmp_path / "mod.py", "def foo(): pass\ndef bar(): pass\n")

        engine = ScanEngine(target_paths=(tmp_path,), rules=())
        result = engine.scan()

        assert result.total_function_count == 2
        assert result.annotated_function_count == 0

    def test_denominator_includes_inner_functions(self, tmp_path: Path) -> None:
        """Inner/nested functions are counted in the denominator."""
        _write_py(
            tmp_path / "nested.py",
            """\
def outer():
    def inner():
        pass
    return inner
""",
        )
        engine = ScanEngine(target_paths=(tmp_path,), rules=())
        result = engine.scan()
        # Both outer and outer.inner are in the qualname map
        assert result.total_function_count == 2

    def test_denominator_includes_property_methods(self, tmp_path: Path) -> None:
        """@property methods are FunctionDef nodes and counted in denominator."""
        _write_py(
            tmp_path / "props.py",
            """\
class Foo:
    @property
    def value(self):
        return 42

    def regular(self):
        pass
""",
        )
        engine = ScanEngine(target_paths=(tmp_path,), rules=())
        result = engine.scan()
        # value (property getter) + regular = 2
        assert result.total_function_count == 2

    def test_denominator_excludes_lambdas(self, tmp_path: Path) -> None:
        """ast.Lambda nodes are NOT counted in the function denominator."""
        _write_py(
            tmp_path / "lambdas.py",
            """\
def real_func():
    pass

fn = lambda x: x + 1
also_fn = lambda: None
""",
        )
        engine = ScanEngine(target_paths=(tmp_path,), rules=())
        result = engine.scan()
        # Only real_func in denominator, lambdas excluded
        assert result.total_function_count == 1
        # But lambdas are counted separately
        assert result.lambda_count == 2


class TestDataPathsTracedRatio:
    """call_edge_resolution_ratio and low_resolution_function_count from L3 taint."""

    def test_data_paths_traced_ratio_from_l3_scan(self, tmp_path: Path) -> None:
        """L3 scan with cross-function calls produces a non-null ratio."""
        _write_py(
            tmp_path / "calls.py",
            """\
def callee():
    return 42

def caller():
    return callee()
""",
        )
        engine = ScanEngine(target_paths=(tmp_path,), rules=(), analysis_level=3)
        result = engine.scan()

        # L3 ran, so ratio should be set (non-null)
        assert result.call_edge_resolution_ratio is not None
        assert isinstance(result.call_edge_resolution_ratio, float)
        assert 0.0 <= result.call_edge_resolution_ratio <= 1.0

    def test_data_paths_traced_ratio_null_at_l1(self, tmp_path: Path) -> None:
        """L1 scan (no call-graph) leaves ratio as None."""
        _write_py(tmp_path / "mod.py", "def foo(): pass\n")
        engine = ScanEngine(target_paths=(tmp_path,), rules=(), analysis_level=1)
        result = engine.scan()

        assert result.call_edge_resolution_ratio is None

    def test_data_paths_traced_ratio_null_at_l2(self, tmp_path: Path) -> None:
        """L2 scan (no call-graph) leaves ratio as None."""
        _write_py(tmp_path / "mod.py", "def foo(): pass\n")
        engine = ScanEngine(target_paths=(tmp_path,), rules=(), analysis_level=2)
        result = engine.scan()

        assert result.call_edge_resolution_ratio is None

    def test_data_paths_traced_ratio_zero_edges(self, tmp_path: Path) -> None:
        """L3 scan with zero call edges produces None ratio."""
        # A file with no cross-function calls → zero edges
        _write_py(tmp_path / "isolated.py", "x = 1\n")
        engine = ScanEngine(target_paths=(tmp_path,), rules=(), analysis_level=3)
        result = engine.scan()

        # No functions → no taint map → L3 doesn't run → None
        assert result.call_edge_resolution_ratio is None


class TestLambdaCount:
    """Lambda expression counting for denominator_excluded_count."""

    def test_lambda_count_populated(self, tmp_path: Path) -> None:
        """Lambda expressions are counted during project indexing."""
        _write_py(
            tmp_path / "mod.py",
            """\
f = lambda x: x + 1
g = lambda: None
def foo():
    h = lambda y: y * 2
    return h(3)
""",
        )
        engine = ScanEngine(target_paths=(tmp_path,), rules=())
        result = engine.scan()

        assert result.lambda_count == 3

    def test_lambda_count_zero_when_none(self, tmp_path: Path) -> None:
        """No lambdas → lambda_count is 0."""
        _write_py(tmp_path / "mod.py", "def foo(): pass\n")
        engine = ScanEngine(target_paths=(tmp_path,), rules=())
        result = engine.scan()

        assert result.lambda_count == 0
