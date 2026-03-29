"""Level 1 taint assignment — per-function taint from decorators and manifest.

Assigns a ``TaintState`` to every function in the scanned codebase using
three sources in strict precedence order:

1. **Decorator taint** (highest) — if the function has a wardline decorator
   that maps to a taint state, use it.
2. **Module tiers** — if the function's file path matches a declared
   ``module_tiers`` entry in the manifest, use that module's default taint.
3. **UNKNOWN_RAW** (fallback) — if neither applies.

This precedence is a security invariant: a function explicitly decorated
``@external_boundary`` in a module with a "safe" default taint must still
get ``EXTERNAL_RAW``.
"""

from __future__ import annotations

import ast
import logging
from typing import TYPE_CHECKING, Literal, NamedTuple

from wardline.core.taints import TaintState

if TYPE_CHECKING:
    from pathlib import Path

    from wardline.manifest.models import WardlineManifest
    from wardline.scanner.context import WardlineAnnotation

type TaintSource = Literal["decorator", "module_default", "fallback"]


class TaintConflict(NamedTuple):
    """Diagnostic emitted when a function has conflicting taint decorators."""

    qualname: str
    file_path: str
    used_decorator: str
    used_taint: TaintState
    ignored_decorator: str
    ignored_taint: TaintState


class RestorationOverclaim(NamedTuple):
    """Diagnostic: decorator claims a restored_tier exceeding its evidence ceiling."""

    qualname: str
    file_path: str
    claimed_tier: int
    evidence_ceiling: int
    evidence_taint: TaintState

logger = logging.getLogger(__name__)


# ── Decorator → TaintState mappings ──────────────────────────────
#
# Body evaluation taint: the taint state rules evaluate at INSIDE
# the function body. Per spec §A.4.3, validators evaluate at the
# INPUT tier (the data they receive), not the OUTPUT tier.
BODY_EVAL_TAINT: dict[str, TaintState] = {
    "external_boundary": TaintState.EXTERNAL_RAW,
    "validates_shape": TaintState.EXTERNAL_RAW,      # input: T4
    "validates_semantic": TaintState.GUARDED,  # input: T3
    "validates_external": TaintState.EXTERNAL_RAW,     # input: T4
    "integral_read": TaintState.INTEGRAL,
    "integral_writer": TaintState.INTEGRAL,
    "integral_construction": TaintState.INTEGRAL,
}

# Return value taint: the taint state assigned to the function's
# return value for propagation to callers. This is the OUTPUT tier.
RETURN_TAINT: dict[str, TaintState] = {
    "external_boundary": TaintState.EXTERNAL_RAW,
    "validates_shape": TaintState.GUARDED,     # output: T3
    "validates_semantic": TaintState.ASSURED,          # output: T2
    "validates_external": TaintState.ASSURED,          # output: T2
    "integral_read": TaintState.INTEGRAL,
    "integral_writer": TaintState.INTEGRAL,
    "integral_construction": TaintState.INTEGRAL,
}

# Structural invariant: both maps must cover exactly the same decorators.
# If a decorator is added to one but not the other, taint assignment will
# silently produce wrong values (the fallback masks the error).
if set(BODY_EVAL_TAINT) != set(RETURN_TAINT):
    _only_body = set(BODY_EVAL_TAINT) - set(RETURN_TAINT)
    _only_ret = set(RETURN_TAINT) - set(BODY_EVAL_TAINT)
    raise ValueError(
        f"BODY_EVAL_TAINT and RETURN_TAINT key sets diverge: "
        f"only in BODY={_only_body}, only in RETURN={_only_ret}"
    )

# Backward-compatible alias for explain_cmd.py and other importers.
DECORATOR_TAINT_MAP = BODY_EVAL_TAINT


# ── Public API ───────────────────────────────────────────────────


def assign_function_taints(
    tree: ast.Module,
    file_path: Path | str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    manifest: WardlineManifest | None = None,
    *,
    project_root: Path | None = None,
) -> tuple[dict[str, TaintState], dict[str, TaintState], dict[str, TaintSource], list[TaintConflict], list[RestorationOverclaim]]:
    """Assign taint states to every function in a parsed module.

    Args:
        tree: Parsed AST module.
        file_path: Path to the source file.
        annotations: Decorator annotations from ``discover_annotations()``.
        manifest: Loaded manifest (for ``module_tiers`` lookup).
            ``None`` means no manifest — all undecorated functions get
            ``UNKNOWN_RAW``.
        project_root: Project root directory for resolving relative
            manifest ``module_tiers`` paths against absolute file paths.

    Returns:
        Tuple of (body_taint_map, return_taint_map, taint_sources,
        taint_conflicts, restoration_overclaims):
        - body_taint_map: dict mapping qualname → ``TaintState`` for rule
          evaluation inside function bodies (INPUT tier).
        - return_taint_map: dict mapping qualname → ``TaintState`` for
          return value taint propagation (OUTPUT tier).
        - taint_sources: dict mapping qualname → ``TaintSource``
          indicating which branch assigned the taint ("decorator",
          "module_default", or "fallback").
        - taint_conflicts: list of ``TaintConflict`` diagnostics for
          functions with conflicting taint decorators.
        - restoration_overclaims: list of ``RestorationOverclaim``
          diagnostics for decorators claiming a tier exceeding evidence.
    """
    path_str = str(file_path)
    module_default = resolve_module_default(path_str, manifest, project_root=project_root)
    body_taint_map: dict[str, TaintState] = {}
    return_taint_map: dict[str, TaintState] = {}
    taint_sources: dict[str, TaintSource] = {}
    taint_conflicts: list[TaintConflict] = []
    restoration_overclaims: list[RestorationOverclaim] = []

    _walk_and_assign(
        tree, path_str, annotations, module_default,
        body_taint_map, return_taint_map, taint_sources,
        taint_conflicts, restoration_overclaims,
        scope="",
    )

    return body_taint_map, return_taint_map, taint_sources, taint_conflicts, restoration_overclaims


# ── Internal helpers ─────────────────────────────────────────────


def resolve_module_default(
    file_path: str,
    manifest: WardlineManifest | None,
    *,
    project_root: Path | None = None,
) -> TaintState | None:
    """Find the module_tiers default taint for a file path.

    Uses proper path-prefix matching: ``entry.path`` must be a prefix
    of ``file_path`` at a directory boundary. When multiple entries
    match, the most-specific (longest path) wins.

    ``project_root`` resolves relative manifest entry paths against the
    project directory so they match absolute scan file paths.

    Returns ``None`` if no manifest or no matching module_tiers entry.
    """
    if manifest is None:
        return None

    from pathlib import Path as _Path
    from pathlib import PurePath

    file_p = PurePath(file_path)
    root = _Path(project_root).resolve() if project_root is not None else None

    # Collect all matching entries
    matches: list[tuple[int, str]] = []
    for entry in manifest.module_tiers:
        entry_p = PurePath(root / entry.path) if root is not None else PurePath(entry.path)
        try:
            file_p.relative_to(entry_p)
        except ValueError:
            continue
        matches.append((len(entry.path), entry.default_taint))

    if not matches:
        return None

    # Most-specific match wins (longest path)
    matches.sort(key=lambda x: x[0], reverse=True)
    best_taint = matches[0][1]

    try:
        return TaintState(best_taint)
    except ValueError:
        logger.warning(
            "Invalid taint state '%s' in module_tiers for file '%s'",
            best_taint,
            file_path,
        )
        return None


def taint_from_annotations(
    file_path: str,
    qualname: str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    decorator_map: dict[str, TaintState] | None = None,
    conflicts: list[TaintConflict] | None = None,
) -> TaintState | None:
    """Resolve taint from decorator annotations.

    If multiple taint-assigning decorators are present, returns the
    first one found.  When the decorators disagree on taint state, logs
    a warning and appends a ``TaintConflict`` to *conflicts* (if
    provided) so the engine can emit a SARIF finding.  Duplicate
    decorators that agree on taint state are silently accepted.

    Args:
        decorator_map: Which decorator-name→taint mapping to use.
            Defaults to ``BODY_EVAL_TAINT`` (input tier).
        conflicts: Mutable list to collect conflict diagnostics.
            Pass ``None`` to skip collection (e.g. from ``explain``).
    """
    if decorator_map is None:
        decorator_map = BODY_EVAL_TAINT
    key = (file_path, qualname)
    anns = annotations.get(key)
    if not anns:
        return None

    first_taint: TaintState | None = None
    first_name: str | None = None
    for ann in anns:
        taint = decorator_map.get(ann.canonical_name)
        if taint is not None:
            if first_taint is None:
                first_taint = taint
                first_name = ann.canonical_name
            elif taint != first_taint:
                logger.warning(
                    "Multiple taint decorators on %s in %s: "
                    "using %s (%s), ignoring %s (%s)",
                    qualname, file_path,
                    first_name, first_taint,
                    ann.canonical_name, taint,
                )
                if conflicts is not None:
                    conflicts.append(TaintConflict(
                        qualname=qualname,
                        file_path=file_path,
                        used_decorator=first_name,  # type: ignore[arg-type]  # always set when first_taint is set
                        used_taint=first_taint,
                        ignored_decorator=ann.canonical_name,
                        ignored_taint=taint,
                    ))

    return first_taint


def _restoration_taint_from_annotations(
    file_path: str,
    qualname: str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    overclaims: list[RestorationOverclaim] | None = None,
) -> TaintState | None:
    """Resolve taint for restoration_boundary via §5.3 evidence matrix.

    Returns the evidence-derived taint state if the function has a
    restoration_boundary annotation, or None if it does not.

    When *overclaims* is provided, appends a ``RestorationOverclaim``
    diagnostic if the decorator's ``restored_tier`` exceeds the evidence
    ceiling per §5.3.
    """
    from wardline.core.evidence import max_restorable_tier
    from wardline.core.tiers import TAINT_TO_TIER

    key = (file_path, qualname)
    anns = annotations.get(key)
    if not anns:
        return None

    for ann in anns:
        if ann.canonical_name == "restoration_boundary":
            structural = bool(ann.attrs.get("structural_evidence", False))
            semantic = bool(ann.attrs.get("semantic_evidence", False))
            integrity = bool(ann.attrs.get("integrity_evidence"))
            institutional = bool(ann.attrs.get("institutional_provenance"))
            taint = max_restorable_tier(
                structural, semantic, integrity, institutional,
            )

            # Check if decorator's claimed tier exceeds evidence ceiling
            claimed_tier = ann.attrs.get("restored_tier")
            if claimed_tier is not None and overclaims is not None:
                ceiling_tier = TAINT_TO_TIER[taint].value
                if isinstance(claimed_tier, int) and claimed_tier < ceiling_tier:
                    overclaims.append(RestorationOverclaim(
                        qualname=qualname,
                        file_path=file_path,
                        claimed_tier=claimed_tier,
                        evidence_ceiling=ceiling_tier,
                        evidence_taint=taint,
                    ))

            return taint
    return None


def _walk_and_assign(
    node: ast.AST,
    file_path: str,
    annotations: dict[tuple[str, str], list[WardlineAnnotation]],
    module_default: TaintState | None,
    body_taint_map: dict[str, TaintState],
    return_taint_map: dict[str, TaintState],
    taint_sources: dict[str, TaintSource],
    taint_conflicts: list[TaintConflict],
    restoration_overclaims: list[RestorationOverclaim],
    scope: str,
) -> None:
    """Recursively walk AST nodes, assigning taint to each function."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{scope}.{child.name}" if scope else child.name

            # Precedence: decorator > module_tiers > UNKNOWN_RAW
            body_taint = taint_from_annotations(
                file_path, qualname, annotations,
                decorator_map=BODY_EVAL_TAINT,
                conflicts=taint_conflicts,
            )
            # Restoration boundaries use evidence-based taint, not static maps.
            # Short-circuit: set both body and return taint, skip RETURN_TAINT lookup.
            restoration_taint = None
            if body_taint is None:
                restoration_taint = _restoration_taint_from_annotations(
                    file_path, qualname, annotations,
                    overclaims=restoration_overclaims,
                )
                body_taint = restoration_taint

            if body_taint is not None:
                source: TaintSource = "decorator"
                if restoration_taint is not None:
                    # Evidence-derived: body and return taint are the same.
                    ret_taint = restoration_taint
                else:
                    ret_taint_or_none = taint_from_annotations(
                        file_path, qualname, annotations,
                        decorator_map=RETURN_TAINT,
                        conflicts=taint_conflicts,
                    )
                    ret_taint = ret_taint_or_none if ret_taint_or_none is not None else body_taint
            elif module_default is not None:
                body_taint = module_default
                ret_taint = module_default
                source = "module_default"
            else:
                body_taint = TaintState.UNKNOWN_RAW
                ret_taint = TaintState.UNKNOWN_RAW
                source = "fallback"

            body_taint_map[qualname] = body_taint
            return_taint_map[qualname] = ret_taint
            taint_sources[qualname] = source

            # Recurse into nested functions/methods
            _walk_and_assign(
                child, file_path, annotations, module_default,
                body_taint_map, return_taint_map, taint_sources,
                taint_conflicts, restoration_overclaims,
                scope=qualname,
            )
        elif isinstance(child, ast.ClassDef):
            class_scope = (
                f"{scope}.{child.name}" if scope else child.name
            )
            _walk_and_assign(
                child, file_path, annotations, module_default,
                body_taint_map, return_taint_map, taint_sources,
                taint_conflicts, restoration_overclaims,
                scope=class_scope,
            )
        else:
            _walk_and_assign(
                child, file_path, annotations, module_default,
                body_taint_map, return_taint_map, taint_sources,
                taint_conflicts, restoration_overclaims,
                scope=scope,
            )
