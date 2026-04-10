#!/usr/bin/env python3
"""Migrate specimen expected_match from boolean to structured form.

Derives expected_match values from fragment source using AST analysis
ONLY — completely independent of scanner rule logic (oracle independence).

Usage:
    uv run python scripts/migrate_expected_match.py [--dry-run] [--verbose]
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import logging
import sys
from pathlib import Path

import yaml

# Oracle independence: ONLY import from core (RuleId for validation)
# and manifest.loader (safe YAML loading). NEVER import scanner rules/engine/taint.
from wardline.core.severity import RuleId

logger = logging.getLogger(__name__)

# Rules with mechanical AST patterns — auto-migratable
AUTO_RULES: frozenset[str] = frozenset({
    "PY-WL-001", "PY-WL-002", "PY-WL-003", "PY-WL-004", "PY-WL-005", "PY-WL-007",
})

# Rules with complex triggering conditions — manual only
MANUAL_RULES: frozenset[str] = frozenset({
    "PY-WL-006", "PY-WL-008", "PY-WL-009", "SCN-021", "SUP-001",
})

# Broad exception types that PY-WL-004 fires on
_BROAD_EXCEPTIONS: frozenset[str] = frozenset({
    "Exception", "BaseException",
})


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _find_enclosing_function(node: ast.AST, parent_map: dict[int, ast.AST]) -> str | None:
    """Walk up the parent map to find the enclosing function name."""
    current: ast.AST | None = parent_map.get(id(node))
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
        current = parent_map.get(id(current))
    return None


def _build_parent_map(tree: ast.Module) -> dict[int, ast.AST]:
    """Build a child-id -> parent mapping for the AST."""
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _is_get_call_with_one_arg(node: ast.expr) -> bool:
    """Check if node is a .get() call with exactly 1 positional arg and no kwargs."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and len(node.args) == 1
        and len(node.keywords) == 0
    )


def _find_triggering_node(rule: str, tree: ast.Module) -> ast.AST | None:
    """Find the AST node that would trigger the given rule.

    Uses rule-specific AST patterns derived from the spec, NOT from
    importing scanner rule implementations.
    """
    for node in ast.walk(tree):
        if rule == "PY-WL-001":
            # ast.Call where func is Attribute(attr="get") on dict with default
            # Also matches .setdefault() and defaultdict()
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "setdefault"):
                    if len(node.args) >= 2:  # has default argument
                        return node
                if isinstance(node.func, ast.Name) and node.func.id == "defaultdict":
                    return node

        elif rule == "PY-WL-002":
            # ast.Call where func is Name(id="getattr") with 3 args
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "getattr" and len(node.args) == 3:
                    return node

        elif rule == "PY-WL-003":
            # Pattern 1: Compare with In/NotIn
            if isinstance(node, ast.Compare):
                for op in node.ops:
                    if isinstance(op, (ast.In, ast.NotIn)):
                        return node
            # Pattern 2-3: Compare with Is/IsNot/Eq/NotEq where one side is .get(1 arg) and other is None
            if isinstance(node, ast.Compare):
                for i, op in enumerate(node.ops):
                    if isinstance(op, (ast.Is, ast.IsNot, ast.Eq, ast.NotEq)):
                        left = node.left if i == 0 else node.comparators[i - 1]
                        right = node.comparators[i]
                        # Check both directions
                        if (_is_get_call_with_one_arg(left) and isinstance(right, ast.Constant) and right.value is None):
                            return node
                        if (_is_get_call_with_one_arg(right) and isinstance(left, ast.Constant) and left.value is None):
                            return node
            # Pattern 4: hasattr call
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "hasattr":
                    return node
            # Pattern 5: MatchMapping/MatchClass
            if isinstance(node, (ast.MatchMapping,)) if hasattr(ast, "MatchMapping") else False:
                return node

        elif rule == "PY-WL-004":
            # Pattern 1: bare except (handler.type is None)
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                return node
            # Pattern 2: except with broad exception type
            if isinstance(node, ast.ExceptHandler) and node.type is not None:
                if isinstance(node.type, ast.Name) and node.type.id in _BROAD_EXCEPTIONS:
                    return node
                # Tuple of exception types — check if any is broad
                if isinstance(node.type, ast.Tuple):
                    for elt in node.type.elts:
                        if isinstance(elt, ast.Name) and elt.id in _BROAD_EXCEPTIONS:
                            return node
            # Pattern 3: contextlib.suppress(BroadException)
            if isinstance(node, ast.Call):
                func = node.func
                is_suppress = (
                    (isinstance(func, ast.Attribute) and func.attr == "suppress")
                    or (isinstance(func, ast.Name) and func.id == "suppress")
                )
                if is_suppress:
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in _BROAD_EXCEPTIONS:
                            return node

        elif rule == "PY-WL-005":
            # ExceptHandler where body is single Pass/Continue/Break/Ellipsis
            if isinstance(node, ast.ExceptHandler) and len(node.body) == 1:
                stmt = node.body[0]
                if isinstance(stmt, (ast.Pass, ast.Continue, ast.Break)):
                    return node
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                    if stmt.value.value is ...:
                        return node

        elif rule == "PY-WL-007":
            # ast.Call where func is Name(id="isinstance")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "isinstance":
                    return node

    return None


def compute_expected_location(fragment: str, rule: str) -> dict[str, object] | None:
    """Compute structured expected_match from fragment AST analysis.

    Returns dict with line, text, function or None if no match found.
    This function is the shared core used by both migration and generation.
    """
    try:
        tree = ast.parse(fragment)
    except SyntaxError:
        return None

    triggering_node = _find_triggering_node(rule, tree)
    if triggering_node is None:
        return None

    parent_map = _build_parent_map(tree)
    source_lines = fragment.splitlines()

    line = triggering_node.lineno
    if line < 1 or line > len(source_lines):
        return None

    text = source_lines[line - 1].strip()
    function = _find_enclosing_function(triggering_node, parent_map)

    result: dict[str, object] = {
        "line": line,
        "text": text,
    }
    if function is not None:
        result["function"] = function

    return result


def migrate_specimen(yaml_path: Path, *, dry_run: bool, verbose: bool) -> str:
    """Migrate a single specimen file. Returns status string."""
    from wardline.manifest.loader import make_wardline_loader

    WardlineSafeLoader = make_wardline_loader()
    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.load(f, Loader=WardlineSafeLoader)  # noqa: S506

    if not isinstance(data, dict):
        return "error"

    verdict = data.get("verdict", "")
    expected_match = data.get("expected_match")

    # Skip TN/KFN — keep expected_match: false
    if verdict in ("true_negative", "known_false_negative"):
        return "skip_tn_kfn"

    # Skip already-structured specimens (idempotency)
    if isinstance(expected_match, dict):
        return "skip_structured"

    # Only migrate TP specimens with boolean true
    if verdict != "true_positive" or expected_match is not True:
        return "skip_other"

    rule = str(data.get("rule", ""))

    # Manual-only rules: keep boolean
    if rule in MANUAL_RULES or rule not in AUTO_RULES:
        return "skip_manual"

    fragment = data.get("fragment", "")
    if not fragment:
        return "error_no_fragment"

    location = compute_expected_location(str(fragment), rule)
    if location is None:
        logger.warning("No AST match for %s in %s", rule, yaml_path.name)
        return "no_match"

    if verbose:
        logger.info(
            "%s: expected_match: true → %s",
            yaml_path.name, location,
        )

    if dry_run:
        return "would_migrate"

    # Apply migration
    data["expected_match"] = location
    data["expected_match_source"] = "ast-reimplemented"

    # Recompute sha256 after YAML round-trip
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False, explicit_start=True)

    # Re-read to verify and fix sha256 if needed
    with open(yaml_path, encoding="utf-8") as f:
        written_data = yaml.load(f, Loader=WardlineSafeLoader)  # noqa: S506

    actual_fragment = str(written_data.get("fragment", ""))
    actual_hash = _sha256(actual_fragment)
    stored_hash = written_data.get("sha256", "")

    if actual_hash != stored_hash:
        written_data["sha256"] = actual_hash
        with open(yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(written_data, f, Dumper=yaml.SafeDumper, default_flow_style=False, sort_keys=False, explicit_start=True)

    # Validation: re-read and check structural integrity
    with open(yaml_path, encoding="utf-8") as f:
        final = yaml.load(f, Loader=WardlineSafeLoader)  # noqa: S506

    em = final.get("expected_match")
    if not isinstance(em, dict):
        raise ValueError(f"{yaml_path.name}: expected_match not a dict after migration")
    if not isinstance(em.get("line"), int) or em["line"] < 1:
        raise ValueError(f"{yaml_path.name}: invalid line={em.get('line')}")
    if not isinstance(em.get("text"), str) or not em["text"].strip():
        raise ValueError(f"{yaml_path.name}: invalid text={em.get('text')!r}")
    valid_keys = {"line", "text", "function"}
    unknown = set(em) - valid_keys
    if unknown:
        raise ValueError(f"{yaml_path.name}: unknown keys in expected_match: {unknown}")

    return "migrated"


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate specimen expected_match to structured form")
    parser.add_argument("--dry-run", action="store_true", help="Print changes without writing files")
    parser.add_argument("--verbose", action="store_true", help="Log each specimen's migration")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    corpus_dir = Path("corpus/specimens")
    if not corpus_dir.is_dir():
        logger.error("corpus/specimens not found — run from repo root")
        sys.exit(1)

    counters: dict[str, int] = {
        "migrated": 0,
        "would_migrate": 0,
        "skip_tn_kfn": 0,
        "skip_structured": 0,
        "skip_manual": 0,
        "skip_other": 0,
        "no_match": 0,
        "error": 0,
        "error_no_fragment": 0,
    }

    for yaml_path in sorted(corpus_dir.rglob("*.yaml")):
        status = migrate_specimen(yaml_path, dry_run=args.dry_run, verbose=args.verbose)
        counters[status] = counters.get(status, 0) + 1

    action = "would migrate" if args.dry_run else "Migrated"
    migrate_count = counters.get("would_migrate", 0) if args.dry_run else counters["migrated"]
    print(f"\nMigration {'(dry run) ' if args.dry_run else ''}complete:")
    print(f"  {action}:  {migrate_count}")
    print(f"  Skipped (already structured):  {counters['skip_structured']}")
    print(f"  Skipped (TN/KFN):  {counters['skip_tn_kfn']}")
    print(f"  Skipped (manual-only rules):  {counters['skip_manual']}")
    print(f"  Failed (no AST match):  {counters['no_match']}")
    print(f"  Failed (parse error):  {counters['error'] + counters['error_no_fragment']}")


if __name__ == "__main__":
    main()
