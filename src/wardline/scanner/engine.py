"""ScanEngine — orchestrates file discovery, AST parsing, and rule execution.

The engine walks the project tree (``os.walk(followlinks=False)``),
filters files against the manifest perimeter, parses each ``.py`` file
into an AST, and runs every enabled rule against every file.

Error handling philosophy:
- **Parse errors**: skip the file, log a warning, continue the scan.
- **Permission errors**: skip the directory/file, log a warning, continue.
- **Rule crashes**: catch the exception, emit a ``TOOL-ERROR`` finding,
  continue with remaining rules and files.
"""

from __future__ import annotations

import ast
import logging
import os
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState
from wardline.scanner._qualnames import build_qualname_map
from wardline.scanner.context import Finding, ScanContext, WardlineAnnotation, populate_snippets
from wardline.scanner.discovery import _detect_dynamic_imports, discover_annotations
from wardline.scanner.import_resolver import build_import_alias_map, resolve_call_fqn
from wardline.scanner.rejection_path import (
    BUILTIN_KNOWN_VALIDATORS,
    has_rejection_path,
    iter_reachable_calls,
)
from wardline.scanner.taint.callgraph import extract_call_edges
from wardline.scanner.taint.callgraph_propagation import (
    TaintProvenance,
    propagate_callgraph_taints,
)
from wardline.scanner.taint.function_level import assign_function_taints
from wardline.scanner.taint.variable_level import compute_variable_taints

if TYPE_CHECKING:
    from collections.abc import Callable

    from wardline.manifest.models import BoundaryEntry, OptionalFieldEntry, WardlineManifest
    from wardline.scanner.rules.base import RuleBase
    from wardline.scanner.taint.function_level import TaintSource

logger = logging.getLogger(__name__)


def _read_python_source(file_path: Path) -> str:
    """Read Python source with BOM and PEP 263 encoding detection."""
    try:
        with tokenize.open(file_path) as handle:
            return handle.read()
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise UnicodeError(str(exc)) from exc


@dataclass
class ScanResult:
    """Aggregated result of a scan run."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    files_with_degraded_taint: int = 0
    errors: list[str] = field(default_factory=list)
    scanned_file_paths: list[Path] = field(default_factory=list)
    annotated_function_count: int = 0
    total_function_count: int = 0


@dataclass(frozen=True)
class ProjectIndex:
    """Pre-computed project-wide indexes built before per-file scanning."""

    annotations: MappingProxyType[tuple[str, str], tuple[WardlineAnnotation, ...]]
    module_file_map: MappingProxyType[str, str]
    string_literal_counts: MappingProxyType[str, int]
    rejection_path_index: frozenset[str] = frozenset()
    annotated_function_count: int = 0
    total_function_count: int = 0


def expand_rejection_index(
    file_data: list[tuple[ast.Module, dict[str, str], dict[int, str], str]],
    seed: frozenset[str],
    *,
    max_rounds: int = 1,
) -> tuple[frozenset[str], bool]:
    """Expand a rejection path seed to transitive callers.

    Each round adds functions that call any function already in the index.
    Iteration stops when no new entries are added or ``max_rounds`` is
    reached.  Default ``max_rounds=1`` preserves spec-compliant two-hop
    behavior.

    Returns:
        Tuple of (expanded_index, converged). ``converged`` is True if
        expansion reached fixed point; False if ``max_rounds`` was hit.
    """
    index = set(seed)
    for _round in range(max_rounds):
        new_entries: set[str] = set()
        for tree, alias_map, qualname_map, module_name in file_data:
            local_fqns = frozenset(
                f"{module_name}.{qn}" for qn in qualname_map.values()
            )
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                qualname = qualname_map.get(id(node))
                if qualname is None:
                    continue
                fqn = f"{module_name}.{qualname}"
                if fqn in index:
                    continue
                for child in iter_reachable_calls(node):
                    callee_fqn = resolve_call_fqn(
                        child, alias_map, local_fqns, module_name
                    )
                    if callee_fqn is not None and callee_fqn in index:
                        new_entries.add(fqn)
                        break
        if not new_entries:
            return frozenset(index), True
        index.update(new_entries)
    return frozenset(index), False


class ScanEngine:
    """Orchestrates file discovery → AST parsing → rule execution.

    Args:
        target_paths: Root directories to scan.
        exclude_paths: Paths to exclude from scanning (resolved against
            each target for prefix matching).
        rules: Rule instances to execute against each file's AST.
    """

    def __init__(
        self,
        *,
        target_paths: tuple[Path, ...],
        exclude_paths: tuple[Path, ...] = (),
        rules: tuple[RuleBase, ...] = (),
        manifest: WardlineManifest | None = None,
        boundaries: tuple[BoundaryEntry, ...] = (),
        optional_fields: tuple[OptionalFieldEntry, ...] = (),
        analysis_level: int = 1,
        known_validators: frozenset[str] | None = None,
        max_expansion_rounds: int = 1,
        project_root: Path | None = None,
        changed_files: frozenset[Path] | None = None,
    ) -> None:
        self._target_paths = target_paths
        self._exclude_paths = tuple(p.resolve() for p in exclude_paths)
        self._rules = rules
        self._manifest = manifest
        self._boundaries = boundaries
        self._optional_fields = optional_fields
        self._analysis_level = analysis_level
        self._known_validators = known_validators if known_validators is not None else BUILTIN_KNOWN_VALIDATORS
        self._max_expansion_rounds = max_expansion_rounds
        self._project_root = project_root
        self._changed_files = changed_files
        self._project_index: ProjectIndex | None = None

    def scan(self) -> ScanResult:
        """Run a full scan across all target paths.

        Returns a ``ScanResult`` with all findings, counts, and errors.
        """
        result = ScanResult()
        self._project_index = self._build_project_indexes()
        result.annotated_function_count = self._project_index.annotated_function_count
        result.total_function_count = self._project_index.total_function_count

        for target in self._target_paths:
            resolved_target = target.resolve()
            if not resolved_target.is_dir():
                logger.warning("Target path is not a directory: %s", target)
                result.errors.append(f"Target path is not a directory: {target}")
                continue
            self._scan_tree(resolved_target, result)

        return result

    def _scan_tree(self, root: Path, result: ScanResult) -> None:
        """Walk a directory tree and scan all .py files."""
        try:
            onerror = self._walk_error_handler(result)
            walker = os.walk(root, followlinks=False, onerror=onerror)
        except OSError as exc:
            logger.warning("Cannot access target directory %s: %s", root, exc)
            result.errors.append(f"Cannot access target directory {root}: {exc}")
            return

        for dirpath, dirnames, filenames in walker:
            dir_resolved = Path(dirpath).resolve()

            # Prune excluded directories in-place (prevents os.walk descent)
            dirnames[:] = [
                d
                for d in dirnames
                if not self._is_excluded(dir_resolved / d)
            ]

            for filename in filenames:
                if not filename.endswith(".py"):
                    continue

                file_path = dir_resolved / filename
                if self._is_excluded(file_path):
                    continue
                if self._changed_files is not None and file_path not in self._changed_files:
                    continue

                self._scan_file(file_path, result)

    def _is_excluded(self, path: Path) -> bool:
        """Check if a resolved path falls under any exclude path."""
        for excluded in self._exclude_paths:
            try:
                path.relative_to(excluded)
                return True
            except ValueError:
                continue
        return False

    def _file_module_tier(self, file_path: Path) -> int:
        """Return the authority tier for *file_path*'s module, or 4 if unresolved.

        Uses the same longest-prefix matching strategy as the taint
        assignment pass in ``function_level._resolve_module_default``.
        """
        if self._manifest is None:
            return 4

        from pathlib import PurePath

        from wardline.core.tiers import TAINT_TO_TIER

        file_p = PurePath(file_path)
        root = Path(self._project_root).resolve() if self._project_root is not None else None

        best_tier = 4
        best_length = -1

        for entry in self._manifest.module_tiers:
            entry_p = PurePath(root / entry.path) if root is not None else PurePath(entry.path)
            try:
                file_p.relative_to(entry_p)
            except ValueError:
                continue
            if len(entry.path) > best_length:
                try:
                    taint = TaintState(entry.default_taint)
                    best_tier = TAINT_TO_TIER[taint].value
                except (ValueError, KeyError):
                    pass
                best_length = len(entry.path)

        return best_tier

    def _scan_file(self, file_path: Path, result: ScanResult) -> None:
        """Parse a single file and run all rules against its AST."""
        try:
            source = _read_python_source(file_path)
        except PermissionError as exc:
            logger.warning("Permission denied reading %s: %s", file_path, exc)
            result.files_skipped += 1
            result.errors.append(f"Permission denied: {file_path}")
            return
        except UnicodeError as exc:
            logger.warning("Encoding error in %s: %s", file_path, exc)
            result.files_skipped += 1
            result.errors.append(f"Encoding error in {file_path}: {exc}")
            return
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            result.files_skipped += 1
            result.errors.append(f"Cannot read {file_path}: {exc}")
            return

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as exc:
            logger.warning("Syntax error in %s: %s", file_path, exc)
            result.files_skipped += 1
            result.errors.append(f"Syntax error in {file_path}: {exc}")
            file_tier = self._file_module_tier(file_path)
            syntax_severity = Severity.ERROR if file_tier <= 1 else Severity.WARNING
            result.findings.append(
                Finding(
                    rule_id=RuleId.GOVERNANCE_FILE_SKIPPED,
                    file_path=str(file_path),
                    line=getattr(exc, "lineno", 1) or 1,
                    col=getattr(exc, "offset", 0) or 0,
                    end_line=None,
                    end_col=None,
                    message=f"File skipped due to syntax error: {exc}",
                    severity=syntax_severity,
                    exceptionability=Exceptionability.UNCONDITIONAL,
                    taint_state=None,
                    analysis_level=1,
                    source_snippet=None,
                ),
            )
            return

        result.files_scanned += 1
        result.scanned_file_paths.append(file_path)

        for diagnostic in _detect_dynamic_imports(tree):
            result.findings.append(
                Finding(
                    rule_id=RuleId.WARDLINE_DYNAMIC_IMPORT,
                    file_path=str(file_path),
                    line=diagnostic.line,
                    col=diagnostic.col,
                    end_line=None,
                    end_col=None,
                    message=diagnostic.message,
                    severity=Severity.WARNING,
                    exceptionability=Exceptionability.UNCONDITIONAL,
                    taint_state=None,
                    analysis_level=self._analysis_level,
                    source_snippet=None,
                    qualname=None,
                )
            )

        # Pass 1: Discovery + taint assignment (fault-tolerant)
        try:
            annotations = discover_annotations(tree, file_path)
            body_taint_map, return_taint_map, taint_sources, taint_conflicts, restoration_overclaims = assign_function_taints(
                tree, file_path, annotations, self._manifest,
                project_root=self._project_root,
            )
        except Exception as exc:
            logger.error("Discovery/taint failed for %s: %s", file_path, exc)
            result.errors.append(
                f"Discovery/taint failed for {file_path}: {exc}"
            )
            result.files_with_degraded_taint += 1
            result.findings.append(
                Finding(
                    rule_id=RuleId.GOVERNANCE_TAINT_DEGRADED,
                    file_path=str(file_path),
                    line=1,
                    col=0,
                    end_line=None,
                    end_col=None,
                    message=(
                        "Taint assignment degraded: using empty fallback taint map "
                        f"after {type(exc).__name__}: {exc}"
                    ),
                    severity=Severity.WARNING,
                    exceptionability=Exceptionability.UNCONDITIONAL,
                    taint_state=None,
                    analysis_level=self._analysis_level,
                    source_snippet=None,
                    qualname=None,
                )
            )
            annotations = {}
            body_taint_map, return_taint_map, taint_sources = {}, {}, {}
            taint_conflicts = []
            restoration_overclaims = []

        # Emit GOVERNANCE findings for conflicting taint decorators
        for conflict in taint_conflicts:
            result.findings.append(
                Finding(
                    rule_id=RuleId.GOVERNANCE_TAINT_CONFLICT,
                    file_path=conflict.file_path,
                    line=1,
                    col=0,
                    end_line=None,
                    end_col=None,
                    message=(
                        f"Conflicting taint decorators on {conflict.qualname}: "
                        f"using @{conflict.used_decorator} ({conflict.used_taint}), "
                        f"ignoring @{conflict.ignored_decorator} ({conflict.ignored_taint})"
                    ),
                    severity=Severity.WARNING,
                    exceptionability=Exceptionability.UNCONDITIONAL,
                    taint_state=conflict.used_taint,
                    analysis_level=self._analysis_level,
                    source_snippet=None,
                    qualname=conflict.qualname,
                )
            )

        # Emit GOVERNANCE findings for restoration overclaims
        for overclaim in restoration_overclaims:
            result.findings.append(
                Finding(
                    rule_id=RuleId.GOVERNANCE_RESTORATION_OVERCLAIM,
                    file_path=overclaim.file_path,
                    line=1,
                    col=0,
                    end_line=None,
                    end_col=None,
                    message=(
                        f"@restoration_boundary on {overclaim.qualname} claims "
                        f"restored_tier={overclaim.claimed_tier} but evidence "
                        f"supports at most tier {overclaim.evidence_ceiling} "
                        f"({overclaim.evidence_taint.value}). §5.3 evidence matrix."
                    ),
                    severity=Severity.WARNING,
                    exceptionability=Exceptionability.STANDARD,
                    taint_state=overclaim.evidence_taint,
                    analysis_level=self._analysis_level,
                    source_snippet=None,
                    qualname=overclaim.qualname,
                )
            )

        # Taint map hit rate: warn if every function in the file fell back
        # to UNKNOWN_RAW (no decorator, no module_tiers match).  This catches
        # misconfigured manifests that silently degrade rule accuracy.
        if taint_sources and all(
            src == "fallback" for src in taint_sources.values()
        ):
            logger.warning(
                "Taint map hit rate 0%% for %s "
                "(%d functions, all fallback to UNKNOWN_RAW)",
                file_path, len(taint_sources),
            )

        # Module-tiers auditability: detect blanket suppression and
        # high-trust taint without decorator evidence.
        _HIGH_TRUST_TAINTS = frozenset({
            TaintState.INTEGRAL, TaintState.ASSURED,
        })
        _MIN_FUNCTIONS_FOR_BLANKET = 5
        _BLANKET_THRESHOLD = 0.80

        if taint_sources:
            total = len(taint_sources)
            module_default_count = sum(
                1 for src in taint_sources.values() if src == "module_default"
            )
            decorator_count = sum(
                1 for src in taint_sources.values() if src == "decorator"
            )

            # Check 1: >80% of functions governed by module_tiers alone
            if (
                total >= _MIN_FUNCTIONS_FOR_BLANKET
                and module_default_count / total > _BLANKET_THRESHOLD
            ):
                pct = int(module_default_count / total * 100)
                result.findings.append(
                    Finding(
                        rule_id=RuleId.GOVERNANCE_MODULE_TIERS_BLANKET,
                        file_path=str(file_path),
                        line=1,
                        col=0,
                        end_line=None,
                        end_col=None,
                        message=(
                            f"Module-level taint default covers {pct}% of "
                            f"functions ({module_default_count}/{total}) with "
                            f"no per-function decorator evidence"
                        ),
                        severity=Severity.WARNING,
                        exceptionability=Exceptionability.UNCONDITIONAL,
                        taint_state=None,
                        analysis_level=self._analysis_level,
                        source_snippet=None,
                        qualname=None,
                    )
                )

            # Check 2: high-trust module_tiers with zero decorator usage
            if decorator_count == 0 and body_taint_map:
                sample_taint = next(iter(body_taint_map.values()), None)
                if (
                    sample_taint in _HIGH_TRUST_TAINTS
                    and module_default_count > 0
                ):
                    result.findings.append(
                        Finding(
                            rule_id=RuleId.GOVERNANCE_MODULE_TIERS_UNDECORATED,
                            file_path=str(file_path),
                            line=1,
                            col=0,
                            end_line=None,
                            end_col=None,
                            message=(
                                f"module_tiers assigns {sample_taint} to "
                                f"{total} functions but file has zero wardline "
                                f"decorator annotations"
                            ),
                            severity=Severity.WARNING,
                            exceptionability=Exceptionability.UNCONDITIONAL,
                            taint_state=sample_taint,
                            analysis_level=self._analysis_level,
                            source_snippet=None,
                            qualname=None,
                        )
                    )

        # Pass 1.5: Level 3 call-graph taint (when analysis_level >= 3)
        # L3 refines body_taint_map using callgraph analysis. The refined map
        # is still a body-evaluation map (what rules see inside function bodies),
        # but non-anchored functions may be demoted based on their callees'
        # return taints.
        taint_provenance: dict[str, TaintProvenance] | None = None
        if self._analysis_level >= 3 and body_taint_map:
            body_taint_map, taint_provenance = self._run_callgraph_taint(
                tree, body_taint_map, taint_sources, file_path, result,
                return_taint_map=return_taint_map,
            )

        # Pass 1.75: Level 2 variable-level taint (when analysis_level >= 2)
        variable_taint_map: dict[str, dict[str, TaintState]] | None = None
        if self._analysis_level >= 2 and body_taint_map:
            variable_taint_map = self._run_variable_taint(
                tree, body_taint_map, return_taint_map, taint_sources,
                file_path, result,
            )

        # Build per-file import alias map for two-hop rejection path resolution
        import_alias_map = build_import_alias_map(tree)

        if self._project_index is None:
            raise RuntimeError("_project_index is None — scan() must be called before _scan_file")
        ctx = ScanContext(
            file_path=str(file_path),
            function_level_taint_map=body_taint_map,  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
            annotations_map={  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
                qualname: tuple(found)
                for (ann_path, qualname), found in annotations.items()
                if ann_path == str(file_path)
            },
            project_annotations_map=self._project_index.annotations,
            module_file_map=self._project_index.module_file_map,
            string_literal_counts=self._project_index.string_literal_counts,
            boundaries=self._boundaries,
            optional_fields=self._optional_fields,
            variable_taint_map=variable_taint_map,  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
            analysis_level=self._analysis_level,
            taint_provenance=taint_provenance,  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
            rejection_path_index=self._project_index.rejection_path_index,
            import_alias_map=import_alias_map,  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
        )

        # Pass 2: Run rules with context
        for rule in self._rules:
            rule.set_context(ctx)
            self._run_rule(rule, tree, file_path, result, source=source)

    def _build_project_indexes(self) -> ProjectIndex:
        """Build project-wide discovery indexes before rule execution.

        This keeps cross-file rules deterministic regardless of scan order.
        Files that cannot be read or parsed are skipped here; the main scan pass
        still reports those errors authoritatively.

        Also computes the rejection path index:
        1. Seed: project functions with direct rejection paths + known_validators
        2. Expand: iterate up to max_expansion_rounds (default 1 = two-hop per spec)
        """
        all_annotations: dict[tuple[str, str], tuple[WardlineAnnotation, ...]] = {}
        module_file_map: dict[str, str] = {}
        string_literal_counts: dict[str, int] = {}

        # Per-file data retained for the expansion step
        _FileData = tuple[ast.Module, dict[str, str], dict[int, str], str]
        file_data: list[_FileData] = []  # (tree, alias_map, qualname_map, module_name)

        rejection_seed: set[str] = set()
        total_function_count = 0
        annotated_function_count = 0

        for root in self._target_paths:
            resolved_root = root.resolve()
            if not resolved_root.is_dir():
                continue
            for file_path in self._iter_python_files(resolved_root):
                module_name = self._module_name_for(resolved_root, file_path)
                if module_name is not None:
                    module_file_map[module_name] = str(file_path)
                try:
                    source = _read_python_source(file_path)
                    tree = ast.parse(source, filename=str(file_path))
                except (OSError, SyntaxError, UnicodeError):
                    continue

                for node in ast.walk(tree):
                    if (
                        isinstance(node, ast.Constant)
                        and isinstance(node.value, str)
                        and node.value
                    ):
                        string_literal_counts[node.value] = (
                            string_literal_counts.get(node.value, 0) + 1
                        )

                discovered = discover_annotations(tree, file_path)
                for key, value in discovered.items():
                    all_annotations[key] = tuple(value)

                # Coverage counting: count functions via qualname map
                qualname_map = build_qualname_map(tree)
                file_path_str = str(file_path)
                total_function_count += len(qualname_map)
                for _qn in qualname_map.values():
                    if (file_path_str, _qn) in all_annotations:
                        annotated_function_count += 1

                # Rejection path seeding: check each function for direct rejection
                if module_name is not None:
                    alias_map = build_import_alias_map(tree, module_path=module_name or "")
                    file_data.append((tree, alias_map, qualname_map, module_name))
                    for node in ast.walk(tree):
                        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            continue
                        qualname = qualname_map.get(id(node))
                        if qualname is None:
                            continue
                        fqn = f"{module_name}.{qualname}"
                        try:
                            if has_rejection_path(node):
                                rejection_seed.add(fqn)
                        except Exception as exc:
                            logger.warning(
                                "Rejection path check failed for %s in %s: %s",
                                fqn, file_path, exc,
                            )

        # Add known validators to the seed
        rejection_seed.update(self._known_validators)

        # Expansion: configurable depth (default 1 = two-hop per spec)
        try:
            rejection_path_index, converged = expand_rejection_index(
                file_data, frozenset(rejection_seed),
                max_rounds=self._max_expansion_rounds,
            )
        except Exception as exc:
            logger.warning(
                "Rejection path expansion failed: %s — falling back to seed",
                exc,
            )
            rejection_path_index = frozenset(rejection_seed)
            converged = True

        if not converged:
            logger.warning(
                "Rejection path expansion hit max_rounds=%d "
                "(%d entries in index)",
                self._max_expansion_rounds, len(rejection_path_index),
            )

        return ProjectIndex(
            annotations=MappingProxyType(all_annotations),
            module_file_map=MappingProxyType(module_file_map),
            string_literal_counts=MappingProxyType(string_literal_counts),
            rejection_path_index=rejection_path_index,
            annotated_function_count=annotated_function_count,
            total_function_count=total_function_count,
        )

    def _iter_python_files(self, root: Path) -> list[Path]:
        """Collect scan-eligible Python files beneath *root*."""
        files: list[Path] = []
        try:
            walker = os.walk(root, followlinks=False)
        except OSError:
            return files

        for dirpath, dirnames, filenames in walker:
            dir_resolved = Path(dirpath).resolve()
            dirnames[:] = [
                d
                for d in dirnames
                if not self._is_excluded(dir_resolved / d)
            ]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                file_path = dir_resolved / filename
                if not self._is_excluded(file_path):
                    files.append(file_path)
        return files

    def _module_name_for(self, root: Path, file_path: Path) -> str | None:
        """Derive a best-effort importable module name for a source file."""
        try:
            rel = file_path.relative_to(root)
        except ValueError:
            return None
        parts = list(rel.with_suffix("").parts)
        if not parts:
            return None
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            return None
        return ".".join(parts)

    def _run_variable_taint(
        self,
        tree: ast.Module,
        taint_map: dict[str, TaintState],
        return_taint_map: dict[str, TaintState],
        taint_sources: dict[str, TaintSource],
        file_path: Path,
        result: ScanResult,
    ) -> dict[str, dict[str, TaintState]] | None:
        """Run Level 2 variable-level taint on all functions in the AST.

        Returns a dict mapping qualname -> {variable: TaintState}, or None
        on failure.
        """
        # Build callee resolution map: for decorator-anchored callees, use
        # the return (OUTPUT) tier taint so that `x = validates_shape(data)`
        # assigns GUARDED to x. For non-anchored callees, keep the
        # L3-refined body taint (which equals return taint at L1, but may
        # have been demoted by L3 callgraph analysis).
        callee_taint_map: dict[str, TaintState] = dict(taint_map)
        for qn, src in taint_sources.items():
            if src == "decorator" and qn in return_taint_map:
                callee_taint_map[qn] = return_taint_map[qn]

        # ── Dependency taint resolution ─────────────────────────────
        # Build FQN → TaintState from manifest dependency_taint entries,
        # then resolve via import aliases to local/dotted names.
        resolved_dep_dotted: dict[str, TaintState] = {}
        dep_local_prefixes: frozenset[str] = frozenset()

        if self._manifest and self._manifest.dependency_taint:
            dep_fqn_map: dict[str, TaintState] = {}
            dep_packages: set[str] = set()
            for entry in self._manifest.dependency_taint:
                fqn = f"{entry.package}.{entry.function}"
                dep_fqn_map[fqn] = TaintState(entry.returns_taint)
                dep_packages.add(entry.package)

            import_aliases = build_import_alias_map(tree)
            _dep_local_prefixes: set[str] = set()

            for local_name, resolved_fqn in import_aliases.items():
                # Bare imports: from requests import get → get → requests.get
                if resolved_fqn in dep_fqn_map:
                    callee_taint_map.setdefault(
                        local_name, dep_fqn_map[resolved_fqn]
                    )

                # Module imports: import requests → requests → requests
                # Check if any dep FQN starts with resolved_fqn + "."
                for dep_fqn, dep_taint in dep_fqn_map.items():
                    if dep_fqn.startswith(resolved_fqn + "."):
                        suffix = dep_fqn[len(resolved_fqn) + 1 :]
                        dotted_local = f"{local_name}.{suffix}"
                        resolved_dep_dotted[dotted_local] = dep_taint

                # Track local names that map to declared packages
                if resolved_fqn in dep_packages:
                    _dep_local_prefixes.add(local_name)

            dep_local_prefixes = frozenset(_dep_local_prefixes)

        var_map: dict[str, dict[str, TaintState]] = {}
        qualname_map = self._build_qualname_map(tree)
        try:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qualname = qualname_map.get(id(node))
                    if qualname is not None and qualname in taint_map:
                        func_taint = taint_map[qualname]
                        var_taints = compute_variable_taints(
                            node,
                            func_taint,
                            callee_taint_map,
                            dependency_dotted_map=resolved_dep_dotted,
                            dependency_local_prefixes=dep_local_prefixes,
                        )
                        var_map[qualname] = var_taints
        except Exception as exc:
            logger.warning(
                "Variable-level taint failed for %s: %s", file_path, exc
            )
            result.errors.append(
                f"Variable-level taint failed for {file_path}: {exc}"
            )
            return None

        return var_map if var_map else None

    def _run_callgraph_taint(
        self,
        tree: ast.Module,
        taint_map: dict[str, TaintState],
        taint_sources: dict[str, TaintSource],
        file_path: Path,
        result: ScanResult,
        *,
        return_taint_map: dict[str, TaintState],
    ) -> tuple[dict[str, TaintState], dict[str, TaintProvenance] | None]:
        """Run Level 3 call-graph taint propagation.

        On success, returns the refined taint map and provenance records.
        On failure, emits a TOOL-ERROR finding and returns the original
        taint map with no provenance.
        """
        try:
            qualname_map = self._build_qualname_map(tree)
            edges, resolved_counts, unresolved_counts = extract_call_edges(
                tree, qualname_map
            )
            refined_map, provenance, l3_diagnostics = propagate_callgraph_taints(
                edges, taint_map, taint_sources, resolved_counts, unresolved_counts,
                return_taint_map=return_taint_map,
            )
            # Convert L3 diagnostics to Finding objects
            _diag_rule_map = {
                "L3_CONVERGENCE_BOUND": RuleId.L3_CONVERGENCE_BOUND,
                "L3_LOW_RESOLUTION": RuleId.L3_LOW_RESOLUTION,
            }
            for diag_code, diag_msg in l3_diagnostics:
                diag_rule = _diag_rule_map.get(diag_code)
                if diag_rule is not None:
                    result.findings.append(
                        Finding(
                            rule_id=diag_rule,
                            file_path=str(file_path),
                            line=1,
                            col=0,
                            end_line=None,
                            end_col=None,
                            message=diag_msg,
                            severity=Severity.WARNING,
                            exceptionability=Exceptionability.UNCONDITIONAL,
                            taint_state=None,
                            analysis_level=3,
                            source_snippet=None,
                            qualname=None,
                        )
                    )
            return refined_map, provenance
        except Exception as exc:
            logger.warning(
                "L3 call-graph taint failed for %s: %s", file_path, exc
            )
            result.errors.append(
                f"L3 call-graph taint failed for {file_path}: {exc}"
            )
            result.findings.append(
                Finding(
                    rule_id=RuleId.TOOL_ERROR,
                    file_path=str(file_path),
                    line=1,
                    col=0,
                    end_line=None,
                    end_col=None,
                    message=(
                        f"L3 call-graph taint failed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                    severity=Severity.ERROR,
                    exceptionability=Exceptionability.UNCONDITIONAL,
                    taint_state=None,
                    analysis_level=0,
                    source_snippet=None,
                    qualname=None,
                )
            )
            return taint_map, None

    @staticmethod
    def _build_qualname_map(tree: ast.Module) -> dict[int, str]:
        """Build {id(node): qualname} for all functions in the module.

        Delegates to the shared iterative implementation in ``scanner._qualnames``.
        """
        return build_qualname_map(tree)

    def _run_rule(
        self,
        rule: RuleBase,
        tree: ast.Module,
        file_path: Path,
        result: ScanResult,
        source: str | None = None,
    ) -> None:
        """Execute a single rule, catching crashes as TOOL-ERROR findings."""
        try:
            # Reset findings for this file (context already set via set_context)
            rule.findings.clear()

            rule.visit(tree)

            # Collect findings from the rule into the result
            result.findings.extend(populate_snippets(rule.findings, source))
        except Exception as exc:
            logger.error(
                "Rule %s crashed on %s: %s",
                type(rule).__name__,
                file_path,
                exc,
            )
            result.findings.append(
                Finding(
                    rule_id=RuleId.TOOL_ERROR,
                    file_path=str(file_path),
                    line=1,
                    col=0,
                    end_line=None,
                    end_col=None,
                    message=(
                        f"Rule {type(rule).__name__} crashed: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                    severity=Severity.WARNING,
                    exceptionability=Exceptionability.UNCONDITIONAL,
                    taint_state=None,
                    analysis_level=0,
                    source_snippet=None,
                    qualname=None,
                )
            )

    @staticmethod
    def _walk_error_handler(result: ScanResult) -> Callable[[OSError], None]:
        """Return an onerror callback for os.walk."""

        def handler(error: OSError) -> None:
            logger.warning("Directory walk error: %s", error)
            result.errors.append(f"Directory walk error: {error}")

        return handler
