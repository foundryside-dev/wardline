"""AST and annotation fingerprint computation.

AST fingerprints (``compute_ast_fingerprint``) capture function body structure
for exception staleness detection.

Annotation fingerprints (``compute_annotation_fingerprint`` and friends)
capture wardline decorator state for governance drift detection.
"""

from __future__ import annotations

import ast
import hashlib
import logging
import os
import sys
import tokenize
from datetime import date
from typing import TYPE_CHECKING

from wardline.scanner._scope import find_function_node
from wardline.scanner.discovery import discover_annotations

if TYPE_CHECKING:
    from pathlib import Path

    from wardline.manifest.models import (
        CoverageReport,
        FingerprintEntry,
        WardlineManifest,
    )
    from wardline.scanner.context import WardlineAnnotation

logger = logging.getLogger(__name__)

# Policy groups: groups 1-4 are tier/boundary/provenance decorators.
# All other groups are enforcement (supplementary).
_POLICY_GROUPS = frozenset({1, 2, 3, 4})


def compute_ast_fingerprint(
    file_path: Path,
    qualname: str,
    *,
    project_root: Path | None = None,
    tree: ast.Module | None = None,
) -> str | None:
    """Compute 16-char hex fingerprint for a function's AST structure.

    Includes Python version because ``ast.dump()`` can change between
    minor versions. Python upgrades require ``wardline exception refresh --all``.

    When *project_root* is provided the path hashed into the fingerprint is
    relativized so that CLI ``add`` (which receives a relative path) and
    engine ``apply_exceptions`` (which works with absolute paths) produce
    identical fingerprints for the same function.

    When *tree* is provided, the pre-parsed AST is used directly instead
    of re-reading and re-parsing the file.  Callers that need fingerprints
    for multiple qualnames in the same file should parse once and pass the
    tree to avoid O(n) re-parses.

    Returns None if the file can't be parsed or *qualname* is not found.
    """
    if tree is None:
        try:
            with tokenize.open(file_path) as fh:
                source = fh.read()
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            return None

    func_node = find_function_node(tree, qualname)
    if func_node is None:
        return None

    dump = ast.dump(func_node, include_attributes=False, annotate_fields=True)
    version = f"{sys.version_info.major}.{sys.version_info.minor}"

    if project_root is not None:
        try:
            display_path = str(file_path.relative_to(project_root.resolve()))
        except ValueError:
            display_path = str(file_path)
    else:
        display_path = str(file_path)

    payload = f"{version}|{display_path}|{qualname}|{dump}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# ── Annotation fingerprint computation ────────────────────────────


def compute_annotation_fingerprint(
    qualname: str,
    decorator_names: list[str] | tuple[str, ...],
    decorator_attrs: dict[str, object] | None = None,
) -> str:
    """Compute 16-char hex annotation fingerprint for a function.

    **Does NOT include file_path** — this is a deliberate divergence from
    ``compute_ast_fingerprint``. A function moved between files with
    unchanged annotations produces the same hash.

    Args:
        qualname: Fully qualified function name.
        decorator_names: Canonical wardline decorator names.
        decorator_attrs: Decorator attributes (key=value pairs).
            Currently always empty from static analysis; included
            for forward compatibility with runtime introspection.

    Returns:
        16-character hex SHA-256 hash.
    """
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    sorted_decorators = ",".join(sorted(decorator_names))
    attrs = decorator_attrs or {}
    sorted_attrs = ",".join(f"{k}={v}" for k, v in sorted(attrs.items()))
    payload = f"{version}|{qualname}|{sorted_decorators}|{sorted_attrs}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _classify_artefact(
    annotations: list[WardlineAnnotation],
) -> str:
    """Classify annotations as 'policy' or 'enforcement'.

    Groups 1-4 (tier flow, audit, plugin, internal data provenance)
    are 'policy'. All others are 'enforcement'.

    If any annotation is policy-group, the function is 'policy'.
    """
    for ann in annotations:
        if ann.group in _POLICY_GROUPS:
            return "policy"
    return "enforcement"


def _resolve_tier_for_file(
    file_path: str,
    manifest: WardlineManifest,
) -> int:
    """Resolve the authority tier for a file from the manifest.

    Uses longest-prefix matching on module_tiers, same as the taint
    assignment pass. Falls back to tier 4 (untrusted) if no match.
    """
    from pathlib import PurePath

    tier_map: dict[str, int] = {t.id: t.tier for t in manifest.tiers}
    file_p = PurePath(file_path)
    best_tier = 4  # default: untrusted
    best_length = -1

    for mt in manifest.module_tiers:
        entry_p = PurePath(mt.path)
        try:
            file_p.relative_to(entry_p)
        except ValueError:
            continue
        if len(mt.path) > best_length:
            tier_num = tier_map.get(mt.default_taint)
            if tier_num is not None:
                best_tier = tier_num
                best_length = len(mt.path)

    return best_tier


def _resolve_boundary_transition(
    qualname: str,
    annotations: list[WardlineAnnotation],
) -> str | None:
    """Resolve boundary transition from annotations.

    Looks for decorators that set boundary transitions (validates_shape,
    validates_semantic, validates_external, integral_construction,
    external_boundary).
    """
    _TRANSITION_MAP: dict[str, str] = {
        "validates_shape": "shape_validation",
        "validates_semantic": "semantic_validation",
        "validates_external": "external_validation",
        "integral_construction": "construction",
        "external_boundary": "ingress",
    }
    for ann in annotations:
        transition = _TRANSITION_MAP.get(ann.canonical_name)
        if transition is not None:
            return transition
    return None


def compute_single_annotation_fingerprint(
    file_path: Path,
    qualname: str,
    manifest: WardlineManifest,
) -> FingerprintEntry | None:
    """Compute annotation fingerprint for a single function.

    Discovers annotations for the file, finds the specified function,
    and computes its fingerprint entry.

    Returns None if the file can't be parsed or the function has no
    wardline annotations.
    """
    from wardline.manifest.models import FingerprintEntry

    try:
        with tokenize.open(file_path) as fh:
            source = fh.read()
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return None

    file_str = str(file_path)
    annotations = discover_annotations(tree, file_str)
    key = (file_str, qualname)

    if key not in annotations:
        return None

    anns = annotations[key]
    decorator_names = [a.canonical_name for a in anns]
    # Merge all attrs from annotations (currently always empty)
    merged_attrs: dict[str, object] = {}
    for a in anns:
        merged_attrs.update(a.attrs)

    annotation_hash = compute_annotation_fingerprint(
        qualname, decorator_names, merged_attrs
    )

    tier_context = _resolve_tier_for_file(file_str, manifest)
    boundary_transition = _resolve_boundary_transition(qualname, anns)
    artefact_class = _classify_artefact(anns)

    return FingerprintEntry(
        qualified_name=qualname,
        module=file_str,
        decorators=tuple(sorted(decorator_names)),
        annotation_hash=annotation_hash,
        tier_context=tier_context,
        boundary_transition=boundary_transition,
        last_changed=date.today().isoformat(),
        artefact_class=artefact_class,
    )


def _is_excluded_dir(part: str) -> bool:
    """Check if a directory component should be excluded from scanning."""
    return part.startswith(".") or part == "__pycache__" or part == ".venv"


def _count_functions_in_tree(tree: ast.Module) -> list[str]:
    """Count all function/method definitions in an AST, returning qualnames."""
    qualnames: list[str] = []
    _collect_qualnames(tree, qualnames, scope="")
    return qualnames


def _collect_qualnames(
    node: ast.AST,
    qualnames: list[str],
    scope: str,
) -> None:
    """Recursively collect function qualnames from an AST."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qn = f"{scope}.{child.name}" if scope else child.name
            qualnames.append(qn)
            _collect_qualnames(child, qualnames, scope=qn)
        elif isinstance(child, ast.ClassDef):
            class_scope = f"{scope}.{child.name}" if scope else child.name
            _collect_qualnames(child, qualnames, scope=class_scope)
        else:
            _collect_qualnames(child, qualnames, scope=scope)


def batch_compute_fingerprints(
    root: Path,
    manifest: WardlineManifest,
) -> tuple[list[FingerprintEntry], CoverageReport]:
    """Walk .py files under *root*, compute annotation fingerprints.

    Returns a tuple of (entries, coverage_report).

    Walks the directory tree, discovers annotations per file, and builds
    ``FingerprintEntry`` objects for every annotated function. Also
    counts total functions for coverage reporting.
    """
    from wardline.manifest.models import CoverageReport, FingerprintEntry

    entries: list[FingerprintEntry] = []
    total_functions = 0
    annotated_functions = 0
    tier1_total = 0
    tier1_annotated = 0
    tier1_unannotated: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Filter excluded dirs in-place to prevent descending
        dirnames[:] = [d for d in dirnames if not _is_excluded_dir(d)]

        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue

            file_path = os.path.join(dirpath, filename)
            try:
                with tokenize.open(file_path) as fh:
                    source = fh.read()
                tree = ast.parse(source, filename=file_path)
            except (OSError, SyntaxError, UnicodeDecodeError):
                logger.debug("Skipping unparseable file: %s", file_path)
                continue

            # Count all functions
            all_qualnames = _count_functions_in_tree(tree)
            total_functions += len(all_qualnames)

            # Discover wardline annotations
            annotations = discover_annotations(tree, file_path)

            # Resolve tier for this file
            tier_context = _resolve_tier_for_file(file_path, manifest)

            # Track tier 1 coverage
            if tier_context == 1:
                tier1_total += len(all_qualnames)

            # Track annotated qualnames for this file
            annotated_in_file: set[str] = set()

            for (fp, qualname), anns in annotations.items():
                if fp != file_path:
                    continue
                annotated_functions += 1
                annotated_in_file.add(qualname)

                decorator_names = [a.canonical_name for a in anns]
                merged_attrs: dict[str, object] = {}
                for a in anns:
                    merged_attrs.update(a.attrs)

                annotation_hash = compute_annotation_fingerprint(
                    qualname, decorator_names, merged_attrs
                )
                boundary_transition = _resolve_boundary_transition(qualname, anns)
                artefact_class = _classify_artefact(anns)

                entries.append(
                    FingerprintEntry(
                        qualified_name=qualname,
                        module=file_path,
                        decorators=tuple(sorted(decorator_names)),
                        annotation_hash=annotation_hash,
                        tier_context=tier_context,
                        boundary_transition=boundary_transition,
                        last_changed=date.today().isoformat(),
                        artefact_class=artefact_class,
                    )
                )

            # Count tier 1 annotated and unannotated
            if tier_context == 1:
                tier1_annotated += len(annotated_in_file)
                for qn in all_qualnames:
                    if qn not in annotated_in_file:
                        tier1_unannotated.append(f"{file_path}:{qn}")

    ratio = annotated_functions / total_functions if total_functions > 0 else 0.0

    coverage = CoverageReport(
        annotated=annotated_functions,
        total=total_functions,
        ratio=ratio,
        tier1_annotated=tier1_annotated,
        tier1_total=tier1_total,
        tier1_unannotated=tuple(sorted(tier1_unannotated)),
    )

    return entries, coverage
