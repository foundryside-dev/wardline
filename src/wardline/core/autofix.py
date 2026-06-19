# src/wardline/core/autofix.py
"""Autofix/codemod engine for mechanical fixes (stdlib-only)."""

from __future__ import annotations

import ast
import io
import logging
import tokenize
from collections import defaultdict
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.errors import WardlineError
from wardline.core.finding import Finding

logger = logging.getLogger(__name__)


def has_comment_in_span(
    source_lines: list[str],
    lineno: int,
    end_lineno: int,
    col_offset: int,
    end_col_offset: int,
) -> bool:
    """Check if any comments exist within the exact character-level text span."""
    # Slice the lines in this range
    sub_lines = list(source_lines[lineno - 1 : end_lineno])
    if not sub_lines:
        return False
    # Adjust boundaries
    if len(sub_lines) == 1:
        sub_lines[0] = sub_lines[0][col_offset:end_col_offset]
    else:
        sub_lines[0] = sub_lines[0][col_offset:]
        sub_lines[-1] = sub_lines[-1][:end_col_offset]

    sub_source = "\n".join(sub_lines)
    try:
        tokens = tokenize.generate_tokens(io.StringIO(sub_source).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                return True
    except Exception:
        # Fail-closed: if tokenization fails, assume a comment could be lost
        return True
    return False


def _own_statements(node: ast.AST) -> Iterator[ast.stmt]:
    result: list[ast.stmt] = []
    stack: list[ast.AST] = list(reversed(list(ast.iter_child_nodes(node))))
    while stack:
        current = stack.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(current, ast.stmt):
            result.append(current)
        stack.extend(reversed(list(ast.iter_child_nodes(current))))
    return iter(result)


def get_assert_nodes_for_function(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Assert]:
    asserts = []
    for stmt in _own_statements(func_node):
        if isinstance(stmt, ast.Assert):
            asserts.append(stmt)
    return asserts


def get_assertion_replacement(assert_node: ast.Assert, exception_name: str) -> ast.If:
    """Build the replacement ast.If node from the original ast.Assert node."""
    # test: not (condition)
    not_test = ast.UnaryOp(op=ast.Not(), operand=assert_node.test)
    # raise ExceptionType(msg) or raise ExceptionType("Validation failed")
    raise_args: list[ast.expr] = (
        [assert_node.msg] if assert_node.msg is not None else [ast.Constant(value="Validation failed")]
    )

    raise_node = ast.Raise(
        exc=ast.Call(
            func=ast.Name(id=exception_name, ctx=ast.Load()),
            args=raise_args,
            keywords=[],
        )
    )
    return ast.If(test=not_test, body=[raise_node], orelse=[])


def run_autofix(
    findings: Sequence[Finding],
    config: WardlineConfig,
    root: Path,
    *,
    dry_run: bool = False,
    confirm_cb: Callable[[str, str, str, Finding], bool] | None = None,
) -> dict[str, list[str]]:
    """Apply autofixes to Python files in-place based on rule findings.

    Returns a mapping of relative_path -> list of description strings of applied fixes.
    """
    applied: dict[str, list[str]] = defaultdict(list)
    # Resolve once up front: the MCP server passes the literal `--root .`, and
    # relativizing a resolved file path against the UNRESOLVED root raises
    # ValueError ("is not in the subpath of '.'") — dogfood-4 A1, the crash that
    # made the only autofix verb unusable. Every comparison below works on the
    # resolved root.
    root = root.resolve()
    # Group findings by file path (resolved relative to root)
    by_file: dict[Path, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.rule_id == "PY-WL-111" and f.location.path:
            full_path = (root / f.location.path).resolve()
            if full_path.is_relative_to(root):
                by_file[full_path].append(f)

    exception_name = config.boundary_exception

    for file_path, file_findings in by_file.items():
        rel_path = file_path.relative_to(root).as_posix()
        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to read %s for autofix: %s", file_path, exc)
            continue

        source_lines = source.splitlines(keepends=True)
        # Parse AST to locate specific statement nodes
        try:
            tree = ast.parse(source)
        except Exception as exc:
            logger.warning("Failed to parse AST of %s for autofix: %s", file_path, exc)
            continue

        # Map function line_start to function nodes
        func_nodes: dict[int, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_nodes[node.lineno] = node

        # Collect all assert nodes to replace
        to_replace: list[tuple[ast.Assert, Finding]] = []
        for f in file_findings:
            line_start = f.location.line_start
            if line_start is None or line_start not in func_nodes:
                continue
            func_node = func_nodes[line_start]
            for assert_node in get_assert_nodes_for_function(func_node):
                to_replace.append((assert_node, f))

        # Sort by assert_node's line number and column offset in reverse (bottom to top)
        to_replace.sort(
            key=lambda x: (x[0].lineno or 0, x[0].col_offset or 0),
            reverse=True,
        )

        modified = False
        new_lines = list(source_lines)
        pending_fixes: list[str] = []

        for node, f in to_replace:
            # Ensure line bounds are valid
            lineno = node.lineno
            end_lineno = getattr(node, "end_lineno", lineno)
            col_offset = node.col_offset
            end_col_offset = getattr(node, "end_col_offset", col_offset)

            if lineno is None or end_lineno is None or col_offset is None or end_col_offset is None:
                continue

            # Copy literal prefix from the start line
            prefix = source_lines[lineno - 1][:col_offset]
            # Ensure prefix is entirely whitespace (tabs/spaces)
            if not prefix.isspace() and prefix != "":
                # Fall back to using standard spaces matching col_offset
                prefix = " " * col_offset

            # Check for comments inside the target span to avoid comment deletion
            if has_comment_in_span(source_lines, lineno, end_lineno, col_offset, end_col_offset):
                continue

            # Build replacement AST node and unparse
            replacement_node = get_assertion_replacement(node, exception_name)
            replacement_text = ast.unparse(replacement_node)

            # Indent each line of the unparsed replacement text
            indented_lines = []
            for i, line in enumerate(replacement_text.splitlines()):
                if i == 0:
                    indented_lines.append(line)
                elif line.strip():
                    indented_lines.append(prefix + line)
                else:
                    indented_lines.append(line)
            replacement_str = "\n".join(indented_lines)

            # Extract original statement snippet for confirmation
            original_lines = source_lines[lineno - 1 : end_lineno]
            if not original_lines:
                continue
            original_lines[0] = original_lines[0][col_offset:]
            original_lines[-1] = original_lines[-1][:end_col_offset]
            original_str = "".join(original_lines).strip()

            if confirm_cb is not None and not confirm_cb(rel_path, original_str, replacement_str.strip(), f):
                continue

            # Perform inline character-level replacement
            # Reconstruct the file lines
            # First, slice the unchanged lines before and after the range
            before_lines = new_lines[: lineno - 1]
            after_lines = new_lines[end_lineno:]

            # For target lines, replace the character span
            target_lines = new_lines[lineno - 1 : end_lineno]
            # Keep prefix from first line, and suffix from last line
            first_line_prefix = target_lines[0][:col_offset]
            last_line_suffix = target_lines[-1][end_col_offset:]

            # Form replacement lines
            middle_text = first_line_prefix + replacement_str + last_line_suffix
            # Replace the lines array
            new_lines = before_lines + [middle_text] + after_lines
            modified = True
            pending_fixes.append(f"L{lineno}: replaced assert with `raise {exception_name}`")

        if modified:
            if not dry_run:
                try:
                    file_path.write_text("".join(new_lines), encoding="utf-8")
                except OSError as exc:
                    raise WardlineError(f"Failed to write autofix changes to {rel_path}: {exc}") from exc
            applied[rel_path].extend(pending_fixes)

    return dict(applied)
