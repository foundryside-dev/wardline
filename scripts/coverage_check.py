#!/usr/bin/env python3
"""Decorator coverage check for Tier 1/4 modules.

Measures the percentage of functions in Tier 1 and Tier 4 modules that
have wardline decorator annotations. The self-hosting gate requires
80% decorator coverage on these boundary-critical modules.

Usage:
    python scripts/coverage_check.py [--manifest wardline.yaml] [--threshold 80]
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def _find_functions(tree: ast.Module) -> list[str]:
    """Collect all function qualnames in a module AST."""
    functions: list[str] = []

    def _walk(node: ast.AST, scope: str = "") -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = f"{scope}.{child.name}" if scope else child.name
                functions.append(qualname)
                _walk(child, qualname)
            elif isinstance(child, ast.ClassDef):
                class_scope = f"{scope}.{child.name}" if scope else child.name
                _walk(child, class_scope)
            else:
                _walk(child, scope)

    _walk(tree)
    return functions


def _has_wardline_decorator(
    file_path: str,
    qualname: str,
    annotations: dict[tuple[str, str], list[object]],
) -> bool:
    """Check if a function has any wardline decorator annotations."""
    return (file_path, qualname) in annotations


def check_coverage(
    manifest_path: Path,
    *,
    threshold: float = 80.0,
    root: Path | None = None,
) -> tuple[float, int, int, list[str]]:
    """Check decorator coverage on Tier 1/4 modules.

    Returns:
        (coverage_pct, decorated_count, total_count, details)
    """
    from wardline.manifest.loader import load_manifest
    from wardline.scanner.discovery import discover_annotations

    manifest = load_manifest(manifest_path)
    if root is None:
        root = manifest_path.parent

    # Identify Tier 1 and Tier 4 modules
    tier_map: dict[str, int] = {t.id: t.tier for t in manifest.tiers}
    target_modules: list[tuple[str, int]] = []
    unrecognised_taints: list[tuple[str, str]] = []
    for mt in manifest.module_tiers:
        tier_num = tier_map.get(mt.default_taint)
        if tier_num is None:
            unrecognised_taints.append((mt.path, mt.default_taint))
            continue
        if tier_num in (1, 4):
            target_modules.append((mt.path, tier_num))

    total_functions = 0
    decorated_functions = 0
    details: list[str] = []

    for module_path, tier_num in target_modules:
        full_path = root / module_path
        if full_path.is_file():
            py_files = [full_path]
        elif full_path.is_dir():
            py_files = sorted(full_path.rglob("*.py"))
        else:
            continue

        for py_file in py_files:
            # Skip __pycache__
            if "__pycache__" in py_file.parts:
                continue

            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue

            file_path_str = str(py_file)
            functions = _find_functions(tree)
            annotations = discover_annotations(tree, file_path_str)

            for qualname in functions:
                # Skip private/dunder methods — they're implementation
                # details not typically decorated
                basename = qualname.rsplit(".", 1)[-1]
                if basename.startswith("_"):
                    continue

                total_functions += 1
                if _has_wardline_decorator(
                    file_path_str, qualname, annotations
                ):
                    decorated_functions += 1
                else:
                    details.append(
                        f"  T{tier_num} {py_file.relative_to(root)}:"
                        f"{qualname}"
                    )

    # Warn about modules with unrecognised tier IDs (not silently skipped)
    for mod_path, taint_id in unrecognised_taints:
        details.append(
            f"  WARNING: {mod_path} has unrecognised tier ID "
            f"'{taint_id}' — skipped from coverage check"
        )

    if total_functions == 0:
        return 100.0, 0, 0, details

    pct = (decorated_functions / total_functions) * 100.0
    return pct, decorated_functions, total_functions, details


def main() -> None:
    """CLI entry point for coverage check."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Check decorator coverage on Tier 1/4 modules."
    )
    parser.add_argument(
        "--manifest", default="wardline.yaml",
        help="Path to wardline.yaml manifest.",
    )
    parser.add_argument(
        "--threshold", type=float, default=80.0,
        help="Minimum coverage percentage (default: 80).",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show undecorated function details.",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"error: manifest not found: {args.manifest}", file=sys.stderr)
        sys.exit(2)

    pct, decorated, total, details = check_coverage(
        manifest_path, threshold=args.threshold
    )

    print(
        f"Decorator coverage (Tier 1/4): "
        f"{decorated}/{total} = {pct:.1f}%"
    )

    # Always print warnings (unrecognised tier IDs) regardless of verbosity
    warnings = [d for d in details if d.strip().startswith("WARNING:")]
    non_warnings = [d for d in details if not d.strip().startswith("WARNING:")]

    if warnings:
        print(file=sys.stderr)
        for w in warnings:
            print(w, file=sys.stderr)

    if args.verbose and non_warnings:
        print(f"\nUndecorated public functions ({len(non_warnings)}):")
        for d in sorted(non_warnings):
            print(d)

    if pct >= args.threshold:
        print(f"PASS (threshold: {args.threshold}%)")
        sys.exit(0)
    else:
        print(f"FAIL (threshold: {args.threshold}%, got {pct:.1f}%)")
        sys.exit(1)


if __name__ == "__main__":
    main()
