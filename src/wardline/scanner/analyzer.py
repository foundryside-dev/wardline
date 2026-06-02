# src/wardline/scanner/analyzer.py
"""WardlineAnalyzer — the end-to-end SP1 engine (replaces NoOpAnalyzer).

Parses each file, indexes entities, seeds L1 via the pluggable provider, runs the
L3 transitive fixed point ONCE over the whole project (minimum_scope is NOT on
the pipeline — full L3 subsumes its one-hop refinement), computes per-file L2
variable taints inside a per-function RecursionError boundary, exposes the result
as an AnalysisContext for SP2, and emits engine-diagnostic Findings. No policy
rules ship (empty RuleRegistry seam).
"""

from __future__ import annotations

import ast
import hashlib
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.qualname import module_dotted_name
from wardline.core.taints import TaintState, least_trusted
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.context import AnalysisContext, RuleRegistry
from wardline.scanner.diagnostics import (
    build_diagnostic_findings,
    build_metric_finding,
    build_unknown_import_findings,
)
from wardline.scanner.grammar import TrustGrammar, default_grammar
from wardline.scanner.index import discover_class_qualnames, discover_file_entities
from wardline.scanner.rules import build_default_registry
from wardline.scanner.taint.call_taint_map import build_call_taint_map
from wardline.scanner.taint.decorator_provider import (
    DecoratorTaintSourceProvider,
    vocabulary_star_exports,
)
from wardline.scanner.taint.function_level import seed_function_taints
from wardline.scanner.taint.project_resolver import ModuleInput, resolve_project_taints
from wardline.scanner.taint.provider import SeedContext, TaintSourceProvider
from wardline.scanner.taint.variable_level import (
    collect_self_attr_writes,
    compute_return_callee,
    compute_return_taint,
    compute_variable_taints,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from wardline.core.config import WardlineConfig
    from wardline.scanner.index import Entity
    from wardline.scanner.taint.summary_cache import SummaryCache


def _fp(*parts: str) -> str:
    digest = hashlib.sha256()
    digest.update("\x00".join(parts).encode("utf-8"))
    return digest.hexdigest()


class WardlineAnalyzer:
    """SP1 analyzer implementing core.protocols.Analyzer."""

    def __init__(
        self,
        *,
        provider: TaintSourceProvider | None = None,
        registry: RuleRegistry | None = None,
        summary_cache: SummaryCache | None = None,
        grammar: TrustGrammar | None = None,
    ) -> None:
        # A grammar (Track 2) supplies boundary types -> provider and rules -> the
        # per-config registry. An explicit provider/registry still wins (test seams).
        # grammar=None keeps the no-arg path behavior-identical to pre-Track-2.
        self._grammar = grammar
        if provider is None and grammar is not None:
            provider = DecoratorTaintSourceProvider(boundary_types=grammar.boundary_types)
        self._provider: TaintSourceProvider = provider or DecoratorTaintSourceProvider()
        self._registry = registry  # None -> build the default set per-config in analyze()
        self._cache = summary_cache
        self.last_context: AnalysisContext | None = None

    def analyze(self, files: Sequence[Path], config: WardlineConfig, *, root: Path) -> Sequence[Finding]:
        modules: list[ModuleInput] = []
        # (relpath, module_path, tree, entities, alias_map, class_qualnames)
        file_meta: list[tuple[str, str, ast.Module, tuple[Entity, ...], dict[str, str], frozenset[str]]] = []
        parse_findings: list[Finding] = []
        # Statically-known star-import exports (the trust vocabulary, T1.2). A REGISTRY-
        # derived constant for the whole scan — compute once and reuse at both seam points.
        star_exports = vocabulary_star_exports()

        # ``discover`` resolves the root to an absolute path, so the files it yields are
        # absolute. Resolve ``root`` to the same base here, or ``is_relative_to`` fails and
        # every finding carries an absolute, machine-specific path — which corrupts the
        # qualname (module_dotted_name expects a repo-relative path) and is rejected by
        # Filigree's project-relative-path validation.
        root = root.resolve()

        for path in files:
            relpath = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
            module = module_dotted_name(relpath)
            if module is None:
                # The file was discovered but maps to no module (e.g. a top-level
                # __init__.py). Emit a FACT making the skip OBSERVABLE — a silent
                # ``continue`` here was a false-green (the file counted as scanned yet
                # produced zero findings). This is its OWN rule_id, distinct from
                # WLN-ENGINE-FILE-SKIPPED: a benign layout artifact (nothing to
                # analyze), NOT a "tried and failed" signal — so it is deliberately
                # NOT in UNANALYZED_RULE_IDS and must not dilute the unanalyzed count.
                parse_findings.append(
                    Finding(
                        rule_id="WLN-ENGINE-NO-MODULE",
                        message=f"{relpath}: maps to no module (nothing to analyze)",
                        severity=Severity.NONE,
                        kind=Kind.FACT,
                        location=Location(path=relpath),
                        fingerprint=_fp("WLN-ENGINE-NO-MODULE", relpath),
                        properties={"reason": "no_module_mapping"},
                    )
                )
                continue
            # File-level fail-closed boundary. A read/decode error, a SyntaxError
            # (unparseable), or a RecursionError (pathological depth — a generated
            # mega-expression recurses not only in L2 but in entity discovery's
            # tree walk, which happens first) skips the file with a FACT rather
            # than aborting the whole scan. The per-function L2 boundary below is
            # finer-grained defense for the case where parse + discovery succeed.
            try:
                source = path.read_text(encoding="utf-8")  # universal-newline -> LF
                tree = ast.parse(source)
                entities = tuple(discover_file_entities(tree, module=module, path=relpath))
                classes = frozenset(discover_class_qualnames(tree, module=module))
                alias_map = build_import_alias_map(tree, module_path=module, star_exports=star_exports)
                seeds = seed_function_taints(
                    entities,
                    ctx=SeedContext(module=module, alias_map=alias_map),
                    provider=self._provider,
                )
            except (SyntaxError, UnicodeDecodeError, OSError) as exc:
                msg = getattr(exc, "msg", None) or str(exc)
                lineno = exc.lineno if isinstance(exc, SyntaxError) else None
                parse_findings.append(
                    Finding(
                        rule_id="WLN-ENGINE-PARSE-ERROR",
                        message=f"{relpath}: could not read/parse ({msg})",
                        severity=Severity.NONE,
                        kind=Kind.FACT,
                        location=Location(path=relpath, line_start=lineno),
                        fingerprint=_fp("WLN-ENGINE-PARSE-ERROR", relpath),
                        properties={"module": module},
                    )
                )
                continue
            except RecursionError:
                parse_findings.append(
                    Finding(
                        rule_id="WLN-ENGINE-FILE-SKIPPED",
                        message=f"{relpath}: skipped — expression too deep to analyze safely",
                        severity=Severity.NONE,
                        kind=Kind.FACT,
                        location=Location(path=relpath),
                        fingerprint=_fp("WLN-ENGINE-FILE-SKIPPED", relpath),
                        properties={"module": module, "reason": "recursion_limit"},
                    )
                )
                continue
            modules.append(
                ModuleInput(
                    module_path=module,
                    entities=entities,
                    class_qualnames=classes,
                    alias_map=alias_map,
                    seeds=seeds,
                    source_bytes=source.encode("utf-8"),
                )
            )
            file_meta.append((relpath, module, tree, entities, alias_map, classes))
            # T2.4 soundness inheritance: a CUSTOM boundary type that matched but
            # could not be proven (a required level unreadable) seeded the fail-closed
            # UNKNOWN_RAW. Surface it as an observable FACT so the extension plane
            # cannot silently false-green. Builtins never set this (the provider keeps
            # them silent), so the byte-identity oracle holds. NOT in
            # UNANALYZED_RULE_IDS: the function WAS scanned — only its annotation was
            # unreadable (an honest under-seed, not a file/function under-scan).
            for ent in entities:
                fn_seed = seeds.get(ent.qualname)
                if fn_seed is None:
                    continue
                for boundary in fn_seed.unprovable_boundaries:
                    parse_findings.append(
                        Finding(
                            rule_id="WLN-ENGINE-UNPROVABLE-BOUNDARY",
                            message=(
                                f"{ent.qualname}: custom boundary @{boundary} could not be "
                                f"proven (argument unreadable) — seeded UNKNOWN_RAW"
                            ),
                            severity=Severity.NONE,
                            kind=Kind.FACT,
                            location=ent.location,
                            # Keyed on (qualname, boundary) so two unprovable customs on
                            # one function produce two distinct FACTs (no collision).
                            fingerprint=_fp("WLN-ENGINE-UNPROVABLE-BOUNDARY", ent.qualname, boundary),
                            qualname=ent.qualname,
                            properties={"boundary": boundary, "reason": "arg_unreadable"},
                        )
                    )

        if self._cache is not None:
            result = resolve_project_taints(
                modules=modules,
                provider_fingerprint=self._provider.fingerprint(),
                summary_cache=self._cache,
                dirty_modules=frozenset(),
            )
        else:
            result = resolve_project_taints(modules=modules, provider_fingerprint=self._provider.fingerprint())

        # Measured AFTER resolve so it reflects THIS run's cache effectiveness
        # (0.0 cold, →1.0 warm). It is a genuinely run-varying METRIC; the
        # warm≡cold invariant applies to the taint findings, not to this metric.
        cache_hit_rate = self._cache.hit_rate() if self._cache is not None else 0.0

        project_taints = dict(result.taint_map)

        # Pre-bucket EFFECTIVE RETURN taints by module → {top_level_func_name:
        # return_taint}, once, for O(aliases) call resolution. A caller observes a
        # callee's RETURN taint, not its body — for anchored callees (e.g. a
        # @trust_boundary validator) body != return, and using body here would
        # mis-read validated output as raw (over-taint -> PY-WL-101 false positive).
        project_return_taints = dict(result.return_taint_map)
        project_by_module: dict[str, dict[str, TaintState]] = {}
        for _relpath, module, _tree, entities, _alias_map, _classes in file_meta:
            prefix = module + "."
            bucket = project_by_module.setdefault(module, {})
            for ent in entities:
                rest = ent.qualname[len(prefix) :] if ent.qualname.startswith(prefix) else ent.qualname
                if "." not in rest:  # top-level function (methods aren't bare-callable)
                    bucket[rest] = project_return_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)

        function_var_taints: dict[str, dict[str, TaintState]] = {}
        function_call_site_taints: dict[str, dict[int, dict[str, TaintState]]] = {}
        function_return_taints: dict[str, TaintState] = {}
        function_return_callee: dict[str, str | None] = {}
        entity_index: dict[str, Entity] = {}
        func_skip_findings: list[Finding] = []
        # Records carried from L2 pass 1 to pass 2 (closure A): one per entity.
        l2_records: list[tuple[Entity, TaintState, dict[str, TaintState], str]] = []
        # Per-class attribute summary: ``{class_qualname: {attr: least_trusted write taint}}``.
        class_attr_taints: dict[str, dict[str, TaintState]] = {}
        l2_failed: set[str] = set()

        def _run_l2(
            node: ast.FunctionDef | ast.AsyncFunctionDef, seed: TaintState, tm: dict[str, TaintState]
        ) -> tuple[dict[int, dict[str, TaintState]], dict[str, TaintState], TaintState | None, str | None]:
            call_sites: dict[int, dict[str, TaintState]] = {}
            var_taints = compute_variable_taints(node, seed, dict(tm), call_sites)
            ret_taint = compute_return_taint(node, seed, dict(tm), var_taints)
            # Pass a COPY of var_taints: _resolve_expr's walrus (NamedExpr) branch mutates
            # the dict it walks, and var_taints is stored into function_var_taints. A
            # forward-referencing walrus inside a return would otherwise get a second,
            # non-idempotent resolve pass that perturbs the stored map. Same start ⇒ same callee.
            ret_callee = compute_return_callee(node, seed, dict(tm), dict(var_taints))
            return call_sites, var_taints, ret_taint, ret_callee

        def _store(
            qn: str,
            call_sites: dict[int, dict[str, TaintState]],
            var_taints: dict[str, TaintState],
            ret_taint: TaintState | None,
            ret_callee: str | None,
        ) -> None:
            function_var_taints[qn] = var_taints
            function_call_site_taints[qn] = call_sites
            if ret_taint is not None:
                function_return_taints[qn] = ret_taint
            else:
                function_return_taints.pop(qn, None)
            function_return_callee[qn] = ret_callee

        # ── L2 pass 1 — per-method var/return taints + per-class attribute summary ──
        for _relpath, module, _tree, entities, alias_map, classes in file_meta:
            call_tm = build_call_taint_map(module_path=module, alias_map=alias_map, project_by_module=project_by_module)
            for ent in entities:
                entity_index[ent.qualname] = ent
                seed = project_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)
                # PART C — self/cls method-call parity with L3. The module-scoped
                # call_tm keys top-level functions only; a method's ``self.<sib>``
                # / ``cls.<sib>`` call sites are absent, so they used to fall back
                # to the function seed (fail-open launder for a @trusted method).
                # For a method entity whose enclosing class is known, inject the
                # sibling methods' RETURN taints under ``self.<name>``/``cls.<name>``
                # — mirroring resolve_self_method_fqn's class-membership gate.
                # Per-entity (not in call_tm) because ``self`` is class-relative:
                # baking it into the shared module map would collide across classes.
                method_tm = dict(call_tm)
                enclosing_class = ent.qualname.rsplit(".", 1)[0]
                is_method = enclosing_class in classes
                if is_method:
                    sib_prefix = enclosing_class + "."
                    for sib in entities:
                        if sib.qualname.startswith(sib_prefix) and "." not in sib.qualname[len(sib_prefix) :]:
                            sib_name = sib.qualname[len(sib_prefix) :]
                            sib_taint = project_return_taints.get(sib.qualname, TaintState.UNKNOWN_RAW)
                            method_tm[f"self.{sib_name}"] = sib_taint
                            method_tm[f"cls.{sib_name}"] = sib_taint
                try:
                    call_sites, var_taints, ret_taint, ret_callee = _run_l2(ent.node, seed, method_tm)
                except RecursionError:
                    # Fail-closed: absent vars read as the function taint, and the
                    # return taint is unknown. Emit a FACT so the gap is observable
                    # — a silently-absent function_return_taints entry would make
                    # PY-WL-101 quietly skip this function (an invisible under-taint).
                    l2_failed.add(ent.qualname)
                    call_sites, var_taints, ret_taint, ret_callee = {}, {}, None, None
                    func_skip_findings.append(
                        Finding(
                            rule_id="WLN-ENGINE-FUNCTION-SKIPPED",
                            message=f"{ent.qualname}: skipped L2 — expression too deep to analyze safely",
                            severity=Severity.NONE,
                            kind=Kind.FACT,
                            location=ent.location,
                            fingerprint=_fp("WLN-ENGINE-FUNCTION-SKIPPED", ent.qualname),
                            qualname=ent.qualname,
                            properties={"reason": "recursion_limit"},
                        )
                    )
                _store(ent.qualname, call_sites, var_taints, ret_taint, ret_callee)
                l2_records.append((ent, seed, method_tm, enclosing_class))
                # Closure A: fold this method's ``self.<attr>`` writes into the class
                # summary (least_trusted = weakest-link, so any raw write makes the
                # attribute raw for cross-method reads). RHS resolves against this
                # method's pass-1 var_taints so local indirection (``v = raw; self.x = v``)
                # is captured. Single round: a ``self.y = self.x`` attribute-to-attribute
                # chain resolves self.x at its pre-summary value here, so a deep attr chain
                # may under-resolve — a bounded residual FN (never an over-fire), consistent
                # with the engine's other documented function-level limits.
                if is_method and ent.qualname not in l2_failed:
                    writes = collect_self_attr_writes(ent.node, seed, dict(method_tm), dict(var_taints))
                    if writes:
                        summary = class_attr_taints.setdefault(enclosing_class, {})
                        for attr_name, attr_taint in writes.items():
                            summary[attr_name] = (
                                least_trusted(summary[attr_name], attr_taint) if attr_name in summary else attr_taint
                            )

        # ── L2 pass 2 — re-run methods of classes with an attribute summary, with
        # ``self.<attr>``/``cls.<attr>`` injected so cross-method reads see the summary.
        # Methods that read no summarised attribute recompute to identical values, so
        # overwriting is safe; pass-1-skipped methods (RecursionError) stay skipped.
        for ent, seed, method_tm, enclosing_class in l2_records:
            attr_summary = class_attr_taints.get(enclosing_class)
            if not attr_summary or ent.qualname in l2_failed:
                continue
            tm2 = dict(method_tm)
            for attr_name, attr_taint in attr_summary.items():
                tm2[f"self.{attr_name}"] = attr_taint
                tm2[f"cls.{attr_name}"] = attr_taint
            try:
                call_sites, var_taints, ret_taint, ret_callee = _run_l2(ent.node, seed, tm2)
            except RecursionError:  # pragma: no cover - pass 1 succeeded; defensive
                continue
            _store(ent.qualname, call_sites, var_taints, ret_taint, ret_callee)

        context = AnalysisContext(
            project_taints=project_taints,
            project_return_taints=project_return_taints,
            function_var_taints=function_var_taints,
            function_call_site_taints=function_call_site_taints,
            class_attr_taints=class_attr_taints,
            function_return_taints=function_return_taints,
            function_return_callee=function_return_callee,
            entities=entity_index,
            taint_provenance=dict(result.taint_provenance),
            declared_qualnames=frozenset(q for m in modules for q, s in m.seeds.items() if s.source == "provider"),
        )
        self.last_context = context

        findings: list[Finding] = list(parse_findings)
        findings.extend(func_skip_findings)
        findings.append(build_metric_finding(result.metadata, cache_hit_rate=cache_hit_rate))
        findings.extend(build_diagnostic_findings(list(result.diagnostics)))
        findings.extend(
            build_unknown_import_findings(
                [(rp, mp, tr) for rp, mp, tr, _e, _a, _c in file_meta],
                project_modules=frozenset(mp for _rp, mp, _tr, _e, _a, _c in file_meta),
                resolvable_star_modules=frozenset(star_exports.keys()),
            )
        )
        registry = (
            self._registry
            if self._registry is not None
            else build_default_registry(config, rules=(self._grammar.rules if self._grammar is not None else None))
        )
        findings.extend(registry.run(context))
        return findings


def build_analyzer(
    *, grammar: TrustGrammar | None = None, summary_cache: SummaryCache | None = None
) -> WardlineAnalyzer:
    """Construct an analyzer from a :class:`TrustGrammar` (default = the builtins).

    The grammar's boundary types feed the L1 provider; its rules feed the per-config
    rule registry. ``build_analyzer()`` with no grammar is behavior-identical to a
    bare ``WardlineAnalyzer()`` — this is the agent-facing entry point for running a
    scan under an extended grammar (``default_grammar().extend(...)``)."""
    return WardlineAnalyzer(
        grammar=grammar if grammar is not None else default_grammar(),
        summary_cache=summary_cache,
    )
