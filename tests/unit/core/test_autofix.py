from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from wardline.core.autofix import run_autofix
from wardline.core.config import WardlineConfig
from wardline.core.errors import WardlineError
from wardline.core.finding import Finding, Kind, Location, Severity


def test_autofix_basic_assert(tmp_path: Path) -> None:
    content = """def my_func(x):
    assert x > 0
    return x
"""
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})

    result = run_autofix(findings, config, tmp_path)
    assert "test_file.py" in result
    assert "L2: replaced assert with `raise ValueError`" in result["test_file.py"]

    new_content = file_path.read_text(encoding="utf-8")
    expected = """def my_func(x):
    if not x > 0:
        raise ValueError('Validation failed')
    return x
"""
    assert new_content == expected


def test_autofix_relative_root_dry_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Dogfood-4 A1: the MCP server launches with the literal `--root .`; the
    # resolved file path relativized against the unresolved root raised
    # ValueError ("is not in the subpath of '.'") on ANY invocation, dry-run
    # included. The relative root must work end to end.
    content = """def my_func(x):
    assert x > 0
    return x
"""
    (tmp_path / "test_file.py").write_text(content, encoding="utf-8")
    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})
    monkeypatch.chdir(tmp_path)

    result = run_autofix(findings, config, Path("."), dry_run=True)

    assert "test_file.py" in result
    # dry-run: reported but not written
    assert (tmp_path / "test_file.py").read_text(encoding="utf-8") == content


def test_autofix_assert_with_msg(tmp_path: Path) -> None:
    content = """def my_func(x):
    assert x > 0, "x must be positive"
    return x
"""
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "TypeError"})

    result = run_autofix(findings, config, tmp_path)
    assert "test_file.py" in result

    new_content = file_path.read_text(encoding="utf-8")
    expected = """def my_func(x):
    if not x > 0:
        raise TypeError('x must be positive')
    return x
"""
    assert new_content == expected


def test_autofix_comment_guard(tmp_path: Path) -> None:
    content = """def my_func(x):
    assert (
        x > 0  # some comment
    )
    return x
"""
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})

    result = run_autofix(findings, config, tmp_path)
    # The comment is within the assert line's span, so comment guard fires and skips it.
    assert "test_file.py" not in result or len(result["test_file.py"]) == 0
    assert file_path.read_text(encoding="utf-8") == content


def test_autofix_dry_run(tmp_path: Path) -> None:
    content = """def my_func(x):
    assert x > 0
"""
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})

    result = run_autofix(findings, config, tmp_path, dry_run=True)
    assert "test_file.py" in result
    assert file_path.read_text(encoding="utf-8") == content


def test_autofix_confirm_callback(tmp_path: Path) -> None:
    content = """def my_func(x):
    assert x > 0
"""
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})

    called = []

    def confirm_cb(rel_path: str, orig: str, replacement: str, f: Finding) -> bool:
        called.append((rel_path, orig, replacement, f))
        return False  # Reject the fix

    result = run_autofix(findings, config, tmp_path, confirm_cb=confirm_cb)
    assert len(called) == 1
    assert "test_file.py" not in result
    assert file_path.read_text(encoding="utf-8") == content

    # Try again but accept
    called.clear()

    def confirm_cb_accept(rel_path: str, orig: str, replacement: str, f: Finding) -> bool:
        called.append((rel_path, orig, replacement, f))
        return True

    result2 = run_autofix(findings, config, tmp_path, confirm_cb=confirm_cb_accept)
    assert len(called) == 1
    assert "test_file.py" in result2
    assert "ValueError" in file_path.read_text(encoding="utf-8")


def test_has_comment_in_span_tokenizer_exception() -> None:
    from wardline.core.autofix import has_comment_in_span

    # Passing incomplete token sequence (unbalanced triple quotes) triggers TokenError.
    # The function should fail-closed and return True.
    res = has_comment_in_span(['assert """unclosed string'], 1, 1, 0, 26)
    assert res is True


def test_has_comment_in_span_no_sub_lines() -> None:
    from wardline.core.autofix import has_comment_in_span

    res = has_comment_in_span([], 1, 1, 0, 10)
    assert res is False


def test_own_statements_skips_defs() -> None:
    import ast

    from wardline.core.autofix import get_assert_nodes_for_function

    source = """def parent():
    def child():
        assert 1
    class MyClass:
        assert 2
    assert 3
"""
    tree = ast.parse(source)
    parent_func = tree.body[0]
    assert isinstance(parent_func, ast.FunctionDef)

    asserts = get_assert_nodes_for_function(parent_func)
    # The nested child() and MyClass should be skipped, returning only assert 3.
    assert len(asserts) == 1
    asserts_values = [a.test.value if isinstance(a.test, ast.Constant) else None for a in asserts]
    assert asserts_values == [3]


def test_autofix_path_outside_root(tmp_path: Path) -> None:
    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="../outside.py", line_start=1),
            fingerprint="test_fp",
        ),
        # rule_id is not PY-WL-111
        Finding(
            rule_id="PY-WL-101",
            message="unrelated finding",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp2",
        ),
        # path is None
        Finding(
            rule_id="PY-WL-111",
            message="no path",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path=None, line_start=1),
            fingerprint="test_fp3",
        ),
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})
    result = run_autofix(findings, config, tmp_path)
    assert not result


def test_autofix_file_read_failure(tmp_path: Path) -> None:
    # A directory at the finding path causes read_text() to raise OSError/IsADirectoryError
    dir_path = tmp_path / "test_dir.py"
    dir_path.mkdir()

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_dir.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})
    result = run_autofix(findings, config, tmp_path)
    assert not result


def test_autofix_write_failure_raises_and_reports_no_success(tmp_path: Path, monkeypatch) -> None:
    content = """def my_func(x):
    assert x > 0
    return x
"""
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})

    original_write_text = Path.write_text

    def _fail_write(path: Path, data: str, *args: Any, **kwargs: Any) -> int:
        if path == file_path:
            raise OSError("disk full")
        return original_write_text(path, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _fail_write)

    with pytest.raises(WardlineError, match="Failed to write autofix"):
        run_autofix(findings, config, tmp_path)

    assert file_path.read_text(encoding="utf-8") == content


def test_autofix_syntax_error(tmp_path: Path) -> None:
    content = "def my_func(x):\n   assert x > 0\n  return x\n"  # IndentationError
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})
    result = run_autofix(findings, config, tmp_path)
    assert not result


def test_autofix_line_start_not_in_func_nodes(tmp_path: Path) -> None:
    content = "x = 1\nassert x > 0\n"  # outside any function definition
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=2),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})
    result = run_autofix(findings, config, tmp_path)
    assert not result


def test_autofix_non_whitespace_prefix(tmp_path: Path) -> None:
    content = """def my_func(x):
    x = 1; assert x
    return x
"""
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})
    result = run_autofix(findings, config, tmp_path)
    assert "test_file.py" in result

    # The prefix was "    x = 1; ", which is not entirely whitespace.
    # It should fall back to 11 spaces (since assert starts at column 11).
    new_content = file_path.read_text(encoding="utf-8")
    expected = """def my_func(x):
    x = 1; if not x:
               raise ValueError('Validation failed')
    return x
"""
    assert new_content == expected


def test_autofix_empty_line_in_replacement(tmp_path: Path) -> None:
    from unittest.mock import patch

    content = "def my_func(x):\n    assert x > 0\n"
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})

    # We patch ast.unparse to return a string with an empty middle line.
    with patch("ast.unparse", return_value="if not x > 0:\n\n    raise ValueError"):
        run_autofix(findings, config, tmp_path)

    new_content = file_path.read_text(encoding="utf-8")
    # Empty line in replacement text should remain empty, without prepended prefix space.
    expected = "def my_func(x):\n    if not x > 0:\n\n        raise ValueError\n"
    assert new_content == expected


def test_autofix_node_missing_coords(tmp_path: Path) -> None:
    import ast
    from unittest.mock import patch

    content = "def my_func(x):\n    assert x > 0\n"
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})

    bad_node = ast.Assert(test=ast.Constant(value=True), msg=None)
    bad_node.lineno = None
    bad_node.col_offset = None
    # lineno and other offsets will be None by default in this constructor.

    with patch("wardline.core.autofix.get_assert_nodes_for_function", return_value=[bad_node]):
        result = run_autofix(findings, config, tmp_path)

    assert not result


def test_autofix_original_lines_empty(tmp_path: Path) -> None:
    import ast
    from unittest.mock import patch

    content = "def my_func(x):\n    assert x > 0\n"
    file_path = tmp_path / "test_file.py"
    file_path.write_text(content, encoding="utf-8")

    findings = [
        Finding(
            rule_id="PY-WL-111",
            message="assert-only boundary check",
            severity=Severity.ERROR,
            kind=Kind.DEFECT,
            location=Location(path="test_file.py", line_start=1),
            fingerprint="test_fp",
        )
    ]
    config = WardlineConfig(autofix={"boundary_exception": "ValueError"})

    bad_node = ast.Assert(test=ast.Constant(value=True), msg=None)
    bad_node.lineno = 2
    bad_node.end_lineno = 0  # end_lineno < lineno - 1 makes original_lines empty slice
    bad_node.col_offset = 0
    bad_node.end_col_offset = 0

    with patch("wardline.core.autofix.get_assert_nodes_for_function", return_value=[bad_node]):
        result = run_autofix(findings, config, tmp_path)

    # It should skip gracefully because original_lines is empty
    assert not result
