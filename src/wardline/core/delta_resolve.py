"""Affected-entity → file resolution + the delta finding filter (stdlib-only).

This module is the **resolution** seam (spec §5.2/§5.3) for the ``--affected`` delta
scan. It turns the parsed :class:`~wardline.core.delta_scope.AffectedScope` (a set of
producer-supplied entities, each carrying a SEI and/or a warpline locator) into a
:class:`ResolvedScope`: the concrete set of repo-relative files the engine should
analyze, plus the canonical affected qualname set the displayed-finding filter
(:func:`filter_to_affected`) keys on.

Two resolution paths, in order of authority (spec §5.2):

1. **SEI present and loomweave supports SEI** → resolve the opaque SEI to a current
   locator (mirrors :func:`wardline.core.sei_resolution.resolve_query_filters`:
   ``client.resolve_sei(sei)["current_locator"]`` → :func:`locator_to_qualname`),
   canonicalize, and match it in a freshly-built qualname index. Authoritative.
   A **SEI-drift guard** treats an SEI that resolves to a qualname *absent* from the
   current index (loomweave stale vs the working tree, e.g. a rename) as effectively
   stale and falls through to path 2, recording it as ``stale_sei``.
2. **SEI absent / loomweave unavailable / SEI did not resolve / SEI drifted** → fall
   back to the locator: :func:`locator_to_qualname` → canonicalize → match the index.

An entity neither path resolves lands in ``unresolved`` (it contributes no file and
trips the fail-closed full-fallback rule only when the *whole* set is unresolved —
that decision lives in ``run_scan``, spec §5.4).

The qualname **index is taint-free**: a cheap structural ``ast.parse`` pass over the
already-discovered files (:func:`build_qualname_index`), so the loomweave path is
optional and the index is always complete. All qualname comparisons use a single
canonical key (suffix-stripped of property-accessor ``:setter``/``:deleter`` markers,
matching :func:`wardline.core.finding._to_wire_qualname`) so a ``:setter`` finding
matches its base-name locator and a class-level locator matches every method under it.

**Caller-closure expansion (load-bearing — spec §5.3a).** Warpline's worklist is a
"changed + downstream (callee)" set, but taint findings anchor caller-side. After
resolving the affected entities to a base file set, :func:`resolve_affected_scope`
expands the *analyzed file set* once over the reverse call graph (reusing
:func:`wardline.core.delta.get_affected_entities`) to pull in the callers of the
affected entities. The filter set (``affected_qualnames``) stays the **base** set:
only the analyzed files expand, so the displayed findings still cover only the
requested entities while being computed correctly.

Nothing here re-mints a fingerprint (INV-2): :func:`filter_to_affected` is a pure
drop-filter over a findings list, and it touches only the displayed ``findings`` set —
never ``gate_findings`` (INV-4 / THREAT-001), which ``run_scan`` keeps as the unfiltered
analyzed population. A clean true delta remains advisory because skipped files were not
analyzed.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from wardline.core.delta import get_affected_entities
from wardline.core.delta_scope import AffectedEntity, AffectedScope
from wardline.core.finding import (
    _PROPERTY_ACCESSOR_QUALNAME_SUFFIXES,
    Finding,
)
from wardline.core.qualname import module_dotted_name
from wardline.core.sei_resolution import locator_to_qualname
from wardline.loomweave.identity import SeiResolver
from wardline.scanner.ast_primitives import (
    build_import_alias_map,
    iter_calls_in_function_body,
    resolve_call_fqn,
    resolve_self_method_fqn,
)
from wardline.scanner.index import (
    Entity,
    discover_class_qualnames,
    discover_file_entities,
)


def canonical_qualname(qualname: str) -> str:
    """Strip a property-accessor ``:setter``/``:deleter`` suffix for membership tests.

    ``Finding.qualname`` carries these suffixes (normalized away only at the Filigree
    wire, never on the raw :class:`~wardline.core.finding.Finding`), so a locator
    ``python:function:pkg.mod.Cls.prop`` would not string-equal a finding qualname
    ``pkg.mod.Cls.prop:setter`` without this. Index keys, ``affected_qualnames``, and
    :func:`filter_to_affected` all compare through this single helper. Reuses the suffix
    set defined alongside :func:`wardline.core.finding._to_wire_qualname` so the two
    canonicalizations never drift."""
    for suffix in _PROPERTY_ACCESSOR_QUALNAME_SUFFIXES:
        if qualname.endswith(suffix):
            return qualname.removesuffix(suffix)
    return qualname


@dataclass(frozen=True, slots=True)
class QualnameIndex:
    """A taint-free qualname→file map plus the structural call graph.

    ``by_qualname`` maps a **canonical** (suffix-stripped) qualname to a repo-relative
    POSIX path. ``project_edges`` (caller → resolved project callees) and ``entities``
    (canonical qualname → path) feed the reverse-edge caller closure in
    :func:`resolve_affected_scope` via :func:`wardline.core.delta.get_affected_entities`,
    so the closure runs off this cheap structural pass with no taint analysis."""

    by_qualname: dict[str, str]
    project_edges: dict[str, frozenset[str]]
    entities: dict[str, str]


@dataclass(frozen=True, slots=True)
class ResolvedScope:
    """The outcome of resolving an :class:`AffectedScope` against a :class:`QualnameIndex`.

    ``files`` is the caller-expanded set of repo-relative POSIX paths to analyze.
    ``affected_qualnames`` is the **base** (NOT caller-expanded) canonical affected set
    the displayed-finding filter keys on. The four entity buckets record provenance for
    the scope honesty block (spec §5.4): ``resolved`` via authoritative SEI, ``fell_back``
    via the spoofable qualname-locator path, ``stale_sei`` an SEI that resolved to a
    now-absent qualname, ``unresolved`` neither path matched. ``loomweave_used`` is True
    iff the SEI path actually resolved at least one entity."""

    files: frozenset[str]
    affected_qualnames: frozenset[str]
    resolved: tuple[AffectedEntity, ...]
    fell_back: tuple[AffectedEntity, ...]
    stale_sei: tuple[AffectedEntity, ...]
    unresolved: tuple[AffectedEntity, ...]
    loomweave_used: bool


def build_qualname_index(files: Sequence[Path], root: Path) -> QualnameIndex:
    """Build a taint-free qualname→file index + structural call graph over ``files``.

    A cheap structural pass: for each file, ``ast.parse`` the source (skipping the file
    on :class:`SyntaxError`/:class:`OSError` — a parse-error file contributes no entries
    and never raises out of ``run_scan``), discover its entities via
    :func:`wardline.scanner.index.discover_file_entities`, and resolve each body's call
    sites structurally (bare-name + imported-alias + ``self``/``cls`` method calls). No
    taint analysis. Index keys are CANONICAL (suffix-stripped) qualnames; values are the
    repo-relative POSIX path matching ``Entity.location.path``.

    Args:
        files: the already-discovered files (absolute or root-relative paths).
        root: the scan root, used to compute each file's repo-relative POSIX path.
    """
    by_qualname: dict[str, str] = {}
    entities_by_path: dict[str, str] = {}
    # First pass: discover entities + classes per file, keyed by relpath, so the call-edge
    # pass can resolve project FQNs against the WHOLE project (not just one module).
    per_file: list[tuple[str, str, ast.Module, list[Entity], set[str]]] = []
    for file in files:
        rel = _relpath(file, root)
        module = module_dotted_name(rel)
        if module is None:
            continue
        try:
            source = Path(file).read_bytes()
            tree = ast.parse(source)
        except (SyntaxError, OSError):
            # A parse-error / unreadable file contributes no entries and must not raise
            # out of run_scan (spec §5.3, Phase 2 parse-error handling).
            continue
        file_entities = discover_file_entities(tree, module=module, path=rel)
        class_qualnames = discover_class_qualnames(tree, module=module)
        per_file.append((rel, module, tree, file_entities, class_qualnames))
        for entity in file_entities:
            key = canonical_qualname(entity.qualname)
            by_qualname[key] = entity.location.path
            entities_by_path[key] = entity.location.path

    # The complete project function/class FQN universe, so structural call resolution can
    # see cross-module callees. Built from the RAW (non-canonical) qualnames because
    # resolve_call_fqn / resolve_self_method_fqn match the as-defined entity FQNs.
    project_fqns: frozenset[str] = frozenset(entity.qualname for _, _, _, ents, _ in per_file for entity in ents)
    all_class_qualnames: frozenset[str] = frozenset(cls for _, _, _, _, classes in per_file for cls in classes)

    project_edges: dict[str, frozenset[str]] = {}
    for _, module, tree, file_entities, _ in per_file:
        alias_map = build_import_alias_map(tree, module)
        for entity in file_entities:
            caller_class_fqn: str | None = entity.qualname.rsplit(".", 1)[0]
            if caller_class_fqn not in all_class_qualnames:
                caller_class_fqn = None
            callees: set[str] = set()
            for call in iter_calls_in_function_body(entity.node):
                target = resolve_call_fqn(call, alias_map, project_fqns, module)
                if target is None or target not in project_fqns:
                    target = resolve_self_method_fqn(
                        call,
                        caller_class_fqn=caller_class_fqn,
                        project_fqns=project_fqns,
                    )
                if target is not None and target in project_fqns:
                    callees.add(canonical_qualname(target))
            project_edges[canonical_qualname(entity.qualname)] = frozenset(callees)

    return QualnameIndex(
        by_qualname=by_qualname,
        project_edges=project_edges,
        entities=entities_by_path,
    )


def resolve_affected_scope(
    scope: AffectedScope,
    *,
    index: QualnameIndex,
    sei_resolver: SeiResolver | None,
) -> ResolvedScope:
    """Resolve each entity in ``scope`` to a file, then caller-expand the file set.

    Resolution order per entity (spec §5.2): authoritative SEI (when ``sei_resolver``
    supports SEI), then the qualname-locator fallback. An SEI that resolves to a qualname
    absent from ``index`` is treated as stale and falls through to the locator path
    (recorded in ``stale_sei``). The filter set (``affected_qualnames``) is the BASE set;
    only ``files`` is caller-expanded via the reverse call graph so caller-side sinks of a
    changed callee are analyzed (spec §5.3a)."""
    sei_supported = sei_resolver is not None and sei_resolver.capability.supported

    base_qualnames: set[str] = set()
    base_files: set[str] = set()
    resolved: list[AffectedEntity] = []
    fell_back: list[AffectedEntity] = []
    stale_sei: list[AffectedEntity] = []
    unresolved: list[AffectedEntity] = []
    loomweave_used = False

    for entity in scope.entities:
        drifted = False  # this entity's SEI resolved but its qualname is index-absent

        # 1. Authoritative SEI path.
        if entity.sei is not None and sei_supported:
            assert sei_resolver is not None  # narrowed by sei_supported
            sei_qualname = _resolve_sei_qualname(sei_resolver, entity.sei)
            if sei_qualname is not None:
                matched = _match_qualname(sei_qualname, index)
                if matched is not None:
                    qual, path = matched
                    base_qualnames.add(qual)
                    base_files.add(path)
                    resolved.append(entity)
                    loomweave_used = True
                    continue
                # SEI resolved but the qualname is absent from the current index
                # (loomweave stale vs the working tree) → treat as stale, fall through
                # to the locator path (SEI-drift guard, spec §5.2).
                drifted = True

        # 2. Qualname-locator fallback (also the SEI-drift recovery path).
        if entity.locator is not None:
            locator_qualname = canonical_qualname(locator_to_qualname(entity.locator))
            matched = _match_qualname(locator_qualname, index)
            if matched is not None:
                qual, path = matched
                base_qualnames.add(qual)
                base_files.add(path)
                # A drifted SEI recovered via its locator is recorded as stale (so the
                # scope block surfaces how much of the scope rests on a stale SEI),
                # never double-counted as a clean qualname fall-back.
                (stale_sei if drifted else fell_back).append(entity)
                continue

        # 3. Neither path yielded a file → unresolved (a drifted SEI whose locator also
        # missed is unresolved, recorded in exactly one bucket).
        unresolved.append(entity)

    files = _expand_callers(base_files, index)

    return ResolvedScope(
        files=files,
        affected_qualnames=frozenset(base_qualnames),
        resolved=tuple(resolved),
        fell_back=tuple(fell_back),
        stale_sei=tuple(stale_sei),
        unresolved=tuple(unresolved),
        loomweave_used=loomweave_used,
    )


def filter_to_affected(
    findings: list[Finding],
    affected_qualnames: frozenset[str],
    affected_files: frozenset[str],
) -> list[Finding]:
    """Narrow the DISPLAYED findings to the affected entities (spec §5.3, Phase 4).

    Keeps a finding iff its canonical qualname is in ``affected_qualnames`` (so a
    ``:setter``/``:deleter`` finding matches its base-name locator and a method finding
    matches a class-level locator via its class prefix), OR it is a file-level engine
    FACT (``qualname is None``) on an analyzed affected file (kept as context). Findings
    on *other* entities in the same analyzed file are dropped from the displayed output.

    PURE drop-filter: it never re-mints a fingerprint (INV-2). It is applied ONLY to the
    emitted ``findings`` list, NEVER to ``gate_findings`` (INV-4 / THREAT-001); the caller
    (``run_scan``) keeps the gate population as the unfiltered analyzed set so an
    attacker-influenceable scope cannot hide co-located findings from the gate. Never
    called with a ``None`` findings list (the ``gate_findings is None`` secure-default
    sentinel is left untouched)."""
    kept: list[Finding] = []
    for finding in findings:
        if finding.qualname is None:
            if finding.location.path in affected_files:
                kept.append(finding)
            continue
        if _qualname_in_affected(canonical_qualname(finding.qualname), affected_qualnames):
            kept.append(finding)
    return kept


def _qualname_in_affected(qualname: str, affected_qualnames: frozenset[str]) -> bool:
    """True if ``qualname`` is in the affected set or is a method under an affected class.

    A class-level locator (``python:class:pkg.mod.Cls`` → ``pkg.mod.Cls``) scopes in every
    method qualname under that class prefix (``pkg.mod.Cls.method``), so a worklist naming
    a class matches findings on all its methods (spec §5.2 canonicalization)."""
    if qualname in affected_qualnames:
        return True
    return any(qualname.startswith(f"{affected}.") for affected in affected_qualnames)


def _match_qualname(qualname: str, index: QualnameIndex) -> tuple[str, str] | None:
    """Match a canonical ``qualname`` against the index, returning ``(qualname, path)``.

    Matches an exact entity qualname, or a class-level qualname (which has no entity of
    its own) against any method under it — returning that class qualname as the affected
    key so the filter's class-prefix rule scopes in all its methods, and the method's
    file as a file to analyze."""
    path = index.by_qualname.get(qualname)
    if path is not None:
        return (qualname, path)
    # Class-level locator: no entity carries the bare class qualname, but its methods do.
    prefix = f"{qualname}."
    for member_qualname, member_path in index.by_qualname.items():
        if member_qualname.startswith(prefix):
            return (qualname, member_path)
    return None


def _resolve_sei_qualname(sei_resolver: SeiResolver, sei: str) -> str | None:
    """Resolve an opaque SEI to a canonical qualname via the resolver's client.

    Mirrors :func:`wardline.core.sei_resolution.resolve_query_filters`:
    ``client.resolve_sei(sei)["current_locator"]`` → :func:`locator_to_qualname` →
    :func:`canonical_qualname`. Returns ``None`` on any soft failure (no body, no
    ``current_locator``) — never raises, so a flaky loomweave degrades to the locator
    fallback rather than failing the scan. Reaches the SEI→current-locator wire through
    the resolver's bound :class:`~wardline.loomweave.identity.SeiClient` (the resolver's
    public surface returns an :class:`~wardline.core.identity.EntityBinding`, not the raw
    ``current_locator`` this path needs, matching ``resolve_query_filters``' use of the
    client directly)."""
    data = sei_resolver._client.resolve_sei(sei)
    if not isinstance(data, dict):
        return None
    locator = data.get("current_locator")
    if not isinstance(locator, str) or not locator:
        return None
    return canonical_qualname(locator_to_qualname(locator))


def _expand_callers(base_files: frozenset[str] | set[str], index: QualnameIndex) -> frozenset[str]:
    """Expand a base file set with the files of every caller of an affected entity.

    Reuses :func:`wardline.core.delta.get_affected_entities` (the reverse callee→caller
    BFS) over the index's structural call graph so a worklist naming a changed callee
    pulls in the caller-side files that carry the taint finding (spec §5.3a). The base
    files are always retained; only callers are added."""
    if not base_files:
        return frozenset(base_files)
    entity_map = {qualname: _IndexEntity(_IndexLocation(path)) for qualname, path in index.entities.items()}
    # get_affected_entities reads only ``entity.location.path``; _IndexEntity provides
    # exactly that, so the cast bridges the concrete-Entity annotation without building
    # real AST-backed Entity objects in this taint-free pass.
    affected_qualnames = get_affected_entities(
        set(base_files), cast("Mapping[str, Entity]", entity_map), index.project_edges
    )
    files = set(base_files)
    for qualname in affected_qualnames:
        path = index.entities.get(qualname)
        if path is not None:
            files.add(path)
    return frozenset(files)


@dataclass(frozen=True, slots=True)
class _IndexLocation:
    """The minimal ``.path`` surface :func:`get_affected_entities` reads off an entity."""

    path: str


@dataclass(frozen=True, slots=True)
class _IndexEntity:
    """A lightweight stand-in exposing only ``.location.path`` for the caller closure.

    :func:`wardline.core.delta.get_affected_entities` reads only ``entity.location.path``,
    so the caller closure runs off the cheap structural index without constructing real
    :class:`~wardline.scanner.index.Entity` objects (which would need an AST node)."""

    location: _IndexLocation


def _relpath(file: Path, root: Path) -> str:
    """Repo-relative POSIX path for ``file``, matching ``Entity.location.path``.

    Mirrors discovery's relpath convention so index keys line up with finding locations.
    A path already relative to (or outside) ``root`` is returned POSIX-normalized."""
    try:
        return file.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return file.as_posix()
