# src/wardline/scanner/diagnostics.py
"""Engine-diagnostic Finding builders (SP1f).

Turns the L3 resolver's run metadata, kernel (code, message) diagnostics, and
unresolved-import facts into SP0 Findings. These are ENGINE diagnostics
(WLN-ENGINE-* / WLN-L3-*), distinct from SP2's policy rules (PY-WL-*). No taint
path is involved, so fingerprints are stable from identifying fields (not the
drifting metric values / percentages).
"""

from __future__ import annotations

import ast
import hashlib
import sys
from typing import TYPE_CHECKING

from wardline.core.finding import ENGINE_PATH as _ENGINE_PATH
from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.scanner.taint.stdlib_taint import stdlib_taint_keys

if TYPE_CHECKING:
    from wardline.scanner.taint.resolver_metadata import ResolverRunMetadata

_BUILTIN_MARKER_IMPORTS: dict[str, frozenset[str]] = {
    "wardline.decorators": frozenset({"external_boundary", "trust_boundary", "trusted"}),
    "wardline.decorators.trust": frozenset({"external_boundary", "trust_boundary", "trusted"}),
    "loom_markers": frozenset({"external_boundary", "trust_boundary", "trusted"}),
}

# code -> (rule_id, severity, kind)
_DIAG_MAP: dict[str, tuple[str, Severity, Kind]] = {
    "L3_CONVERGENCE_BOUND": ("WLN-L3-CONVERGENCE-BOUND", Severity.WARN, Kind.METRIC),
    "L3_MONOTONICITY_VIOLATION": ("WLN-L3-MONOTONICITY-VIOLATION", Severity.ERROR, Kind.DEFECT),
    "L3_LOW_RESOLUTION": ("WLN-L3-LOW-RESOLUTION", Severity.INFO, Kind.METRIC),
}


def _fingerprint(*parts: str) -> str:
    digest = hashlib.sha256()
    digest.update("\x00".join(parts).encode("utf-8"))
    return digest.hexdigest()


def build_metric_finding(metadata: ResolverRunMetadata, *, cache_hit_rate: float) -> Finding:
    """One METRIC finding carrying the L3 run metrics. Fingerprint is keyed on
    metric IDENTITY (fixed), since the values drift run to run."""
    return Finding(
        rule_id="WLN-ENGINE-METRICS",
        message="L3 resolver run metrics",
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path=_ENGINE_PATH),
        fingerprint=_fingerprint("WLN-ENGINE-METRICS", _ENGINE_PATH),
        properties={
            "scc_size_distribution": [list(p) for p in metadata.scc_size_distribution],
            "convergence_iterations_max": metadata.convergence_iterations_max,
            "convergence_iterations_histogram": [list(p) for p in metadata.convergence_iterations_histogram],
            "taint_source_counts": dict(metadata.taint_source_counts),
            "cache_hit_rate": cache_hit_rate,
        },
    )


def build_diagnostic_findings(diagnostics: list[tuple[str, str]]) -> list[Finding]:
    """Map kernel (code, message) diagnostics to Findings. Unknown codes become
    WLN-ENGINE-DIAGNOSTIC at ERROR so a new kernel code can never go silent."""
    findings: list[Finding] = []
    for code, message in diagnostics:
        mapped = _DIAG_MAP.get(code)
        if mapped is not None:
            rule_id, severity, kind = mapped
        else:
            rule_id, severity, kind = ("WLN-ENGINE-DIAGNOSTIC", Severity.ERROR, Kind.DEFECT)
            message = f"unknown L3 diagnostic {code!r}: {message}"
        findings.append(
            Finding(
                rule_id=rule_id,
                message=message,
                severity=severity,
                kind=kind,
                location=Location(path=_ENGINE_PATH),
                fingerprint=_fingerprint(rule_id, message),
            )
        )
    return findings


def build_unknown_import_findings(
    file_trees: list[tuple[str, str, ast.Module]],
    *,
    project_modules: frozenset[str],
    resolvable_star_modules: frozenset[str] = frozenset(),
) -> list[Finding]:
    """FACT findings for unresolved external imports across all files.

    ``file_trees`` is ``[(relpath, module_path, tree), ...]``. Fingerprint is
    stable from ``(module_path, package)``. ``resolvable_star_modules`` names the
    star-import modules the engine materialises statically (T1.2), so they are NOT
    reported as unresolved.
    """
    findings: list[Finding] = []
    stdlib_keys = stdlib_taint_keys()  # suppress curated stdlib entries (forward-correct)
    for relpath, module_path, tree in file_trees:
        for _mp, detail, reason in diagnose_unknown_imports(
            tree=tree,
            module_path=module_path,
            project_modules=project_modules,
            stdlib_keys=stdlib_keys,
            resolvable_star_modules=resolvable_star_modules,
        ):
            package = detail.split()[1] if detail.startswith("from ") else detail
            findings.append(
                Finding(
                    rule_id="WLN-ENGINE-UNKNOWN-IMPORT",
                    message=f"{module_path}: {reason}",
                    severity=Severity.NONE,
                    kind=Kind.FACT,
                    location=Location(path=relpath),
                    fingerprint=_fingerprint("WLN-ENGINE-UNKNOWN-IMPORT", module_path, package),
                    properties={"module": module_path, "package": package, "detail": detail},
                )
            )
    return findings


# --- diagnose_unknown_imports (ported from .old, Finding-free) ----------------


def _is_type_checking_guarded(node: ast.AST, tree: ast.Module) -> bool:
    """Return True if ``node`` is a descendant of an ``if TYPE_CHECKING:``
    block at module top level.

    Handles both forms:
    - ``from typing import TYPE_CHECKING; if TYPE_CHECKING: ...``
    - ``import typing; if typing.TYPE_CHECKING: ...``

    TYPE_CHECKING-guarded imports are annotation-only (not runtime-
    resolvable); they must NOT produce UNKNOWN_IMPORT diagnostics.
    """
    for top in tree.body:
        if not isinstance(top, ast.If):
            continue
        test = top.test
        is_tc = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute)
            and isinstance(test.value, ast.Name)
            and test.value.id == "typing"
            and test.attr == "TYPE_CHECKING"
        )
        if not is_tc:
            continue
        for child in ast.walk(top):
            if child is node:
                return True
    return False


def _top_level_module(dotted: str) -> str:
    """Return the top-level component of a dotted module name.

    ``urllib.request`` → ``urllib``; ``json`` → ``json``.
    """
    return dotted.partition(".")[0]


def _is_stdlib_module(dotted: str) -> bool:
    """Return True if the top-level of ``dotted`` is a Python standard
    library module.

    The standard library is part of Python itself — imports from it are
    not an "unknown external package" precision gap, they are
    runtime-resolvable by any Python interpreter. ``stdlib_taint.yaml``
    covers only the *curated* subset (modules whose call-return taints
    the scanner has explicit entries for); everything else in
    ``sys.stdlib_module_names`` (``typing``, ``dataclasses``, etc.)
    is still a known, safe import and must not produce UNKNOWN_IMPORT.
    """
    return _top_level_module(dotted) in sys.stdlib_module_names


def _is_builtin_marker_import(mod: str, alias: str) -> bool:
    """Return True for Wardline-owned marker imports the scanner resolves statically."""
    names = _BUILTIN_MARKER_IMPORTS.get(mod)
    return names is not None and alias in names


def diagnose_unknown_imports(
    *,
    tree: ast.Module,
    module_path: str,
    project_modules: frozenset[str],
    stdlib_keys: frozenset[tuple[str, str]],
    resolvable_star_modules: frozenset[str] = frozenset(),
) -> list[tuple[str, str, str]]:
    """Return ``(module_path, detail, reason)`` tuples for each unresolvable
    import, de-duplicated by ``(source_module, target_package)``.

    Triggers:
      * ``from X import *`` where ``X`` is not a project module, not a
        Python stdlib module, and no stdlib_taint entry has X as its
        package.
      * ``from X import name`` where ``X`` is not a project module, not
        a Python stdlib module, and ``(X, name)`` is not in
        ``stdlib_keys`` for ANY of the named aliases.

    Excludes:
      * Relative imports (``node.level > 0``).
      * TYPE_CHECKING-guarded imports.
      * Python stdlib modules (``sys.stdlib_module_names``) — these are
        part of the runtime even when absent from ``stdlib_taint.yaml``'s
        curated call-return table; skipping them prevents UNKNOWN_IMPORT
        from degrading into "every ``from typing import …``" noise.
    """
    findings: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        # Skip relative imports entirely — they resolve inside the
        # project via the scanner's relative-import machinery.
        if node.level > 0:
            continue
        # Skip TYPE_CHECKING-guarded imports.
        if _is_type_checking_guarded(node, tree):
            continue
        # ``node.module`` is ``None`` for bare ``from . import x`` (already
        # excluded above via ``node.level > 0``); any remaining ``None`` is
        # a malformed/empty ImportFrom that we skip without fabricating a
        # fallback value.
        if node.module is None:
            continue
        mod = node.module
        if not mod:
            continue
        if mod in project_modules:
            continue
        # Skip Python stdlib modules — any import whose top-level name
        # appears in ``sys.stdlib_module_names`` is resolvable at runtime
        # by definition and is not a precision gap.
        if _is_stdlib_module(mod):
            continue

        # Star-import branch.
        if any(alias.name == "*" for alias in node.names):
            # A statically-materialised star module (the trust vocabulary, T1.2) is
            # resolved, not a coverage gap — no FACT.
            if mod in resolvable_star_modules:
                continue
            if not any(key[0] == mod for key in stdlib_keys):
                key = (module_path, mod)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        (
                            module_path,
                            f"from {mod} import *",
                            f"star import from external package {mod!r} cannot be materialised",
                        )
                    )
            continue

        # Named-import branch — dedupe by (module_path, mod).
        unresolved_aliases: list[str] = []
        for alias in node.names:
            if _is_builtin_marker_import(mod, alias.name):
                continue
            if (mod, alias.name) in stdlib_keys:
                continue
            unresolved_aliases.append(alias.name)
        if unresolved_aliases:
            key = (module_path, mod)
            if key not in seen:
                seen.add(key)
                alias_preview = ", ".join(unresolved_aliases[:3])
                if len(unresolved_aliases) > 3:
                    alias_preview += f", ... ({len(unresolved_aliases)} total)"
                findings.append(
                    (
                        module_path,
                        f"from {mod} import {alias_preview}",
                        f"external import from {mod!r} cannot be resolved (aliases: {alias_preview})",
                    )
                )
    return findings
