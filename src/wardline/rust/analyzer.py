"""WP5/WP6: the Rust analyzer — index + provider + dataflow + rules, one tree/nmap.

``analyze_source`` parses ONCE, mints ONE ``NodeIdMap``, and threads it through entity
indexing, per-function trust seeding (the ``@trusted`` provider), builder-dataflow, and the
verdict rules — so callgraph/dataflow/rule passes share the single keying authority (spec
§5; a re-parse would mint divergent NodeIds and fail quietly).

WP6 adds ``analyze(files, config, *, root)`` — the engine ``Analyzer`` protocol method
``run_scan`` drives under ``--lang rust``. It discovers the tree's Cargo crate roots ONCE
(SP2, ``wardline.rust.crate_roots`` — the loomweave-oracle-mirroring whole-tree pass),
routes each ``.rs`` file to its real crate-prefixed module (``_module_for``), runs the
per-file pipeline, and surfaces a ``WLN-ENGINE-PARSE-ERROR`` FACT for any file
tree-sitter cannot fully parse (then contributes no findings for it — never half-analyze).

``last_context`` is the engine-shaped ``AnalysisContext | None`` (None in slice-1: the
Rust-native context is incompatible with the delta/SARIF consumers). The Rust-native
context is exposed separately as ``last_rust_context``.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from wardline.core.finding import ENGINE_PATH, Finding, Kind, Location, Severity
from wardline.core.taints import TaintState
from wardline.rust import qualname as q
from wardline.rust.context import RustAnalysisContext, RustTriggerContext
from wardline.rust.crate_roots import CrateRoots, discover_crate_roots
from wardline.rust.dataflow import analyze_command_dataflow
from wardline.rust.index import index_entities
from wardline.rust.mounts import MountOverlay, build_mount_overlay
from wardline.rust.nodeid import mint_node_ids
from wardline.rust.parse import has_errors, parse_rust
from wardline.rust.provider import RustTrustProvider
from wardline.rust.rules import RustProgramInjectionRule, RustShellInjectionRule

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from tree_sitter import Tree

    from wardline.core.config import WardlineConfig
    from wardline.scanner.context import AnalysisContext

__all__ = ["RustAnalyzer"]

_FAIL_CLOSED = TaintState.UNKNOWN_RAW  # an unmarked fn declares no trust -> findings suppressed


def _fp(*parts: str) -> str:
    digest = hashlib.sha256()
    digest.update("\x00".join(parts).encode("utf-8"))
    return digest.hexdigest()


class RustAnalyzer:
    """Slice-1 Rust analyzer. Holds the rule set and the last computed contexts."""

    def __init__(self) -> None:
        self._provider = RustTrustProvider()
        self._rules = (RustProgramInjectionRule(), RustShellInjectionRule())
        self._last_rust_context: RustAnalysisContext | None = None

    @property
    def last_context(self) -> AnalysisContext | None:
        """The engine-shaped context for ``run_scan``/SARIF. Always None in slice-1.

        The Rust-native ``RustAnalysisContext`` is NOT an ``AnalysisContext`` (no
        ``project_edges``, different field shape), so returning it would crash the
        delta-scope and SARIF code-flow consumers and fail the protocol's mypy floor.
        The delta path degrades correctly to file-level scoping when this is None.
        """
        return None

    @property
    def last_rust_context(self) -> RustAnalysisContext | None:
        """The Rust-native whole-source view of the most recent ``analyze_source`` /
        per-file ``analyze`` pass — for introspection, not consumed by ``run_scan``."""
        return self._last_rust_context

    def analyze(self, files: Sequence[Path], config: WardlineConfig, *, root: Path) -> Sequence[Finding]:
        """Engine ``Analyzer`` protocol: scan each ``.rs`` file under ``root``.

        ``config`` is accepted for protocol parity but unused in slice-1 (the Rust rules
        carry hardcoded base severities; ``weft.toml`` severity overrides are a preview
        gap, surfaced in the docs). A file that does not fully parse yields a
        ``WLN-ENGINE-PARSE-ERROR`` FACT and no ``RS-WL-*`` findings.
        """
        resolved_root = root.resolve()
        # SP2 whole-tree pass: discover Cargo crate roots ONCE per scan; every file's
        # module route resolves against this map (longest-prefix, symlink-safe walk).
        crate_roots = discover_crate_roots(resolved_root)
        # ADR-049 Amendment 8 pre-pass: read every file ONCE, then build each crate's
        # #[path] mount overlay from its scanned in-src sources — class-1 module routes
        # resolve mount-first (logical_module_path), filesystem-fallback otherwise.
        sources: dict[Path, str] = {}
        read_errors: dict[Path, str] = {}
        for file in files:
            try:
                sources[file] = file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                read_errors[file] = str(exc)
        overlays = _build_overlays(sources, resolved_root, crate_roots)
        findings: list[Finding] = []
        functions_total = 0
        functions_declared = 0
        files_analyzed = 0
        for file in files:
            relpath = _relpath(file, resolved_root)
            if file in read_errors:
                findings.append(_parse_error_finding(relpath, read_errors[file]))
                continue
            source = sources[file]
            tree = parse_rust(source)
            if has_errors(tree):
                findings.append(_parse_error_finding(relpath, "tree-sitter recovered from a syntax error"))
                continue
            module = _module_for(file, resolved_root, crate_roots, overlays)
            try:
                file_findings, context, file_callables = self._analyze_tree(tree, module=module, path=relpath)
            except Exception as exc:  # noqa: BLE001 — per-file isolation, see below
                # One pathological file (e.g. a RecursionError on a deeply-nested expression)
                # must not abort the whole scan and lose every other file's findings. Mirror
                # the Python engine's per-function isolation: degrade to a counted diagnostic
                # FACT (WLN-ENGINE-FILE-FAILED ∈ UNANALYZED_RULE_IDS) and keep scanning.
                findings.append(_file_failed_finding(relpath, f"{type(exc).__name__}: {exc}"))
                continue
            self._last_rust_context = context
            files_analyzed += 1
            # The coverage METRIC counts CALLABLES only — the emission carries the full
            # ten-kind surface (Phase 1b), but the trust-surface denominator is still
            # "functions that could have declared @trusted". `_analyze_tree` counts them
            # over the entity LIST (never the context mapping, which dict-ification
            # could collapse).
            functions_total += file_callables
            # Declared = seeded from a `/// @trusted` marker (tier is a real trust level, not
            # the fail-closed default). This is the trust SURFACE — the denominator that stops
            # a default-clean scan over an un-annotated repo from reading as a clean PASS.
            functions_declared += sum(1 for tier in context.project_taints.values() if tier is not _FAIL_CLOSED)
            findings.extend(file_findings)
        findings.append(_coverage_finding(functions_total, functions_declared, files_analyzed))
        return findings

    def analyze_source(self, source: str, *, module: str, path: str = "") -> list[Finding]:
        """Analyze a single in-memory source string (the WP5 rule-test entry)."""
        tree = parse_rust(source)
        findings, context, _ = self._analyze_tree(tree, module=module, path=path)
        self._last_rust_context = context
        return findings

    def _analyze_tree(self, tree: Tree, *, module: str, path: str) -> tuple[list[Finding], RustAnalysisContext, int]:
        """Run the per-file pipeline; returns ``(findings, context, callables_total)``.

        ``callables_total`` (the coverage-metric denominator) is counted over the
        entity LIST, before dict-ification — the context mapping is keyed and a
        pathological duplicate could collapse there.
        """
        nmap = mint_node_ids(tree)
        entities = index_entities(tree, nmap, module=module, path=path)
        callables = [e for e in entities if e.kind in ("function", "method")]

        project_taints: dict[str, TaintState] = {}
        triggers: list[RustTriggerContext] = []
        for entity in callables:
            # Phase 1b: the index emits the full ten-kind surface; the taint path
            # judges CALLABLES only (a module/struct/const has no body to seed or
            # walk — feeding one to taint_for/dataflow would be a category error).
            try:
                seed = self._provider.taint_for(entity.node)
            except ValueError:
                # A typo'd @trusted marker must not abort the scan: fail closed for this fn
                # (its findings suppressed). NOTE: a typo is currently swallowed silently —
                # surfacing it as an operator-visible diagnostic FACT is tracked backlog
                # (rust-bug-hunt-2026-06-09), not yet built.
                seed = None
            tier = seed.body_taint if seed is not None else _FAIL_CLOSED
            project_taints[entity.qualname] = tier
            body = entity.node.child_by_field_name("body")
            if body is None:
                continue
            for trig in analyze_command_dataflow(body, nmap):
                triggers.append(
                    RustTriggerContext(
                        trigger=trig,
                        qualname=entity.qualname,
                        tier=tier,
                        path=path,
                        # The entity's OWN anchors — the rules fold trigger positions into
                        # the fingerprint entity-relative (wlfp2 move-stability), so the
                        # containing fn's line/NodeId travel with each trigger.
                        entity_line_start=entity.location.line_start or 0,
                        entity_node_id=entity.node_id,
                    )
                )

        context = RustAnalysisContext(
            triggers=tuple(triggers),
            project_taints=project_taints,
            # Keyed by the kind-disambiguated FEDERATION id (`rust:{kind}:{qualname}`,
            # semantic `method` mapped to id-kind `function` by entity_id itself) — a
            # qualname-only key would silently drop one of `fn S` / `struct S`, whose
            # qualnames legitimately collide (the per-kind twin counter never suffixes
            # ACROSS kinds; the id's kind segment is what separates them).
            entities={q.entity_id(e.kind, e.qualname): e for e in entities},
        )
        findings: list[Finding] = []
        for rule in self._rules:
            findings.extend(rule.check(context))
        return findings, context, len(callables)


def _relpath(file: Path, resolved_root: Path) -> str:
    resolved = file.resolve()
    if resolved.is_relative_to(resolved_root):
        return resolved.relative_to(resolved_root).as_posix()
    return resolved.as_posix()


def _build_overlays(sources: dict[Path, str], resolved_root: Path, roots: CrateRoots) -> dict[Path, MountOverlay]:
    """One ``#[path]`` mount overlay per crate (ADR-049 Amendment 8), discovered over
    the scanned IN-SRC sources of that crate (class-2/3 files keep their ``#out``
    non-conformance routes — a mount declared outside ``src/`` is outside loomweave's
    emittable scope and never overlays a class-1 route). Paths are project-root-relative
    posix, matching the R5 sort rule ("declaring-file path relative to the project
    root"). A mount declared in a file outside the scan list is invisible — the overlay
    is the view of the scanned tree."""
    per_crate: dict[Path, tuple[str, dict[str, str]]] = {}
    for file, source in sources.items():
        resolved = file.resolve()
        crate_dir = roots.crate_dir_for(resolved)
        crate_name = roots.crate_name_for(resolved)
        if crate_dir is None or crate_name is None or not resolved.is_relative_to(crate_dir / "src"):
            continue
        if not resolved.is_relative_to(resolved_root):
            continue  # defensive: discover confines to root
        per_crate.setdefault(crate_dir, (crate_name, {}))[1][resolved.relative_to(resolved_root).as_posix()] = source
    return {
        crate_dir: build_mount_overlay(
            crate_sources,
            crate=crate_name,
            src_root=(crate_dir / "src").relative_to(resolved_root).as_posix(),
        )
        for crate_dir, (crate_name, crate_sources) in per_crate.items()
    }


def _module_for(file: Path, resolved_root: Path, roots: CrateRoots, overlays: dict[Path, MountOverlay]) -> str:
    """The SP2 module route. Three file classes:

    1. **In-src** (under a crate root's ``src/``): the ADR-049 oracle route — the
       crate's ``#[path]`` mount overlay first (Amendment 8,
       ``MountOverlay.logical_module_path``), whose default for an un-mounted file is
       the unchanged pure-filesystem
       ``rust_module_route(crate=<real Cargo.toml name>, src_root=<root>/src, file)``.
       Conformance-bearing: byte-identical to loomweave's emission for the same file.
    2. **Under a crate root but OUTSIDE its src/** (``tests/``, ``benches/``,
       ``build.rs``, ...): ``{crate}.#out.{<relpath segments from the crate dir,
       '.rs' stripped, ALL stems literal — no main/lib/mod collapsing>}``. Loomweave's
       ``emittable_scope`` emits NOTHING for these files, so this qualname carries no
       cross-tool conformance claim; the reserved ``#out`` segment is structurally
       impossible in loomweave's locator grammar (``#`` appears only inside
       ``impl#<...>`` discriminators), so a class-2 route can never collide with a
       class-1/loomweave locator (e.g. ``<crate>/tests/integration.rs`` vs
       ``<crate>/src/tests/integration.rs`` -> ``rust_app.#out.tests.integration``
       vs ``rust_app.tests.integration``). Wardline scans these files anyway —
       coverage is never narrowed to the entity surface.
    3. **Under no crate root** (a bare no-Cargo tree): the crate segment is the
       CONSTANT ``"crate"`` (cargo forbids the keyword ``crate`` as a package name,
       so it cannot collide with a class-1 crate) — route =
       ``crate.#out.{<relpath segments from the scan root, stems literal>}``.
       Relpath-pure and scan-root-name-INDEPENDENT: renaming the scan-root
       directory does not rekey fingerprints (e.g. ``bin/app.rs`` ->
       ``crate.#out.bin.app`` whatever the root is called). Same
       no-conformance-claim disclaimer as class 2.
    """
    resolved = file.resolve()
    crate_dir = roots.crate_dir_for(resolved)
    crate_name = roots.crate_name_for(resolved)
    if crate_dir is not None and crate_name is not None:
        src_root = crate_dir / "src"
        if resolved.is_relative_to(src_root):
            overlay = overlays.get(crate_dir)
            if overlay is not None and resolved.is_relative_to(resolved_root):
                return overlay.logical_module_path(resolved.relative_to(resolved_root).as_posix())
            # No overlay built for this crate (defensive): the filesystem default.
            return q.rust_module_route(crate=crate_name, src_root=str(src_root), file=str(resolved))
        return _out_route(crate_name, crate_dir, resolved)  # class 2
    try:
        return _out_route("crate", resolved_root, resolved)  # class 3
    except ValueError:
        # file outside root (should not happen — discover confines to root); degrade to crate.
        return "crate"


def _out_route(crate: str, base: Path, file: Path) -> str:
    """The class-2/3 non-conformance route: ``{crate}.#out.{relpath stems}``.

    Mechanical and relpath-pure: every path segment from ``base`` contributes its
    LITERAL stem (only the final ``.rs`` is stripped — ``main``/``lib``/``mod`` are
    NOT collapsed, unlike the ADR-049 in-src route, because there is no module tree
    to mirror out here and literal stems keep distinct files distinct). The ``#out``
    segment brands the route as outside loomweave's emittable scope.
    """
    rel = file.relative_to(base)
    segments = [*rel.parts[:-1], file.stem]
    return ".".join([crate, "#out", *segments])


def _parse_error_finding(relpath: str, detail: str) -> Finding:
    # Reuse the engine's parse-error rule id so it counts toward ScanSummary.unanalyzed
    # and the CLI "see WLN-ENGINE-* facts" line works for free (UNANALYZED_RULE_IDS).
    return _engine_fact("WLN-ENGINE-PARSE-ERROR", f"{relpath}: could not parse Rust source ({detail})", relpath)


def _file_failed_finding(relpath: str, detail: str) -> Finding:
    # Analysis raised AFTER a clean parse — a per-file under-scan, counted toward unanalyzed.
    return _engine_fact("WLN-ENGINE-FILE-FAILED", f"{relpath}: Rust analysis failed ({detail})", relpath)


def _coverage_finding(functions_total: int, functions_declared: int, files_analyzed: int) -> Finding:
    """A whole-scan METRIC reporting the Rust trust-surface coverage.

    Rust analysis is default-clean: an un-``@trusted`` function modulates its findings to
    NONE. So a scan over a repo with zero markers is *vacuously* green — ``0 active`` with
    nothing actually in the trust surface. This FACT exposes ``functions_declared`` over
    ``functions_total`` so that clean-because-analyzed-and-safe is distinguishable from
    clean-because-nothing-was-analyzable (the anti-false-green posture the CLI surfaces).
    The fingerprint is keyed on metric IDENTITY (fixed); the values drift per run.
    """
    message = (
        f"Rust trust-surface coverage: {functions_declared} of {functions_total} function(s) "
        f"declared @trusted across {files_analyzed} analyzed file(s)"
    )
    return Finding(
        rule_id="WLN-RUST-COVERAGE",
        message=message,
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path=ENGINE_PATH),
        fingerprint=_fp("WLN-RUST-COVERAGE", ENGINE_PATH),
        properties={
            "functions_total": functions_total,
            "functions_declared": functions_declared,
            "files_analyzed": files_analyzed,
            "lang": "rust",
        },
    )


def _engine_fact(rule_id: str, message: str, relpath: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=message,
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=Location(path=relpath),
        fingerprint=_fp(rule_id, relpath),
        properties={"lang": "rust"},
    )
