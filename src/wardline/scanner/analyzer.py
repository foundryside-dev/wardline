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
from collections.abc import Iterator
from typing import TYPE_CHECKING

from wardline.core.finding import ENGINE_PATH, Finding, Kind, Location, Severity
from wardline.core.taints import TaintState, combine
from wardline.scanner.context import AnalysisContext, RuleRegistry
from wardline.scanner.diagnostics import (
    build_diagnostic_findings,
    build_metric_finding,
    build_unknown_import_findings,
)
from wardline.scanner.grammar import TrustGrammar, default_grammar
from wardline.scanner.index import Entity
from wardline.scanner.pipeline import L2FunctionInput, ParseProjectInput, run_l2_function_stage, run_parse_project_stage
from wardline.scanner.rules import build_default_registry
from wardline.scanner.taint.call_taint_map import build_call_taint_map
from wardline.scanner.taint.decorator_provider import (
    DecoratorTaintSourceProvider,
    vocabulary_star_exports,
)
from wardline.scanner.taint.project_resolver import resolve_project_taints
from wardline.scanner.taint.provider import TaintSourceProvider

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from wardline.core.config import WardlineConfig
    from wardline.scanner.taint.summary_cache import SummaryCache


def _fp(*parts: str) -> str:
    digest = hashlib.sha256()
    digest.update("\x00".join(parts).encode("utf-8"))
    return digest.hexdigest()


_L2Record = tuple[Entity, TaintState, dict[str, TaintState], str, dict[str, str], str, bool]
type _L2InputKey = tuple[
    TaintState,
    tuple[tuple[str, TaintState], ...],
    tuple[tuple[str, TaintState], ...] | None,
]
type _L2Result = tuple[
    dict[int, dict[str, TaintState]],
    dict[int, dict[int | str | None, TaintState]],
    dict[str, TaintState],
    TaintState | None,
    str | None,
    dict[str, dict[str, TaintState]],
]


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
        from wardline.core.taints import _PROVENANCE_CLASH

        token_clash = _PROVENANCE_CLASH.set(config.provenance_clash)
        try:
            return self._analyze_inner(files, config, root=root)
        finally:
            _PROVENANCE_CLASH.reset(token_clash)

    def _analyze_inner(self, files: Sequence[Path], config: WardlineConfig, *, root: Path) -> Sequence[Finding]:
        # Statically-known star-import exports (the trust vocabulary, T1.2). A REGISTRY-
        # derived constant for the whole scan — compute once and reuse at both seam points.
        star_exports = vocabulary_star_exports()

        # Track config-defined sources and sanitisers matched across the project
        matched_sources: set[str] = set()
        matched_sanitisers: set[str] = set()

        # ``discover`` resolves the root to an absolute path, so the files it yields are
        # absolute. Resolve ``root`` to the same base here, or ``is_relative_to`` fails and
        # every finding carries an absolute, machine-specific path — which corrupts the
        # qualname (module_dotted_name expects a repo-relative path) and is rejected by
        # Filigree's project-relative-path validation.
        root = root.resolve()

        parse_stage = run_parse_project_stage(
            ParseProjectInput(
                files=files,
                root=root,
                provider=self._provider,
                config=config,
                star_exports=star_exports,
                summary_cache=self._cache,
            )
        )
        modules = parse_stage.modules
        file_meta = parse_stage.files
        parse_findings = list(parse_stage.parse_findings)
        dirty_modules = set(parse_stage.dirty_modules)

        if self._cache is not None:
            result = resolve_project_taints(
                modules=modules,
                provider_fingerprint=self._provider.fingerprint(),
                summary_cache=self._cache,
                dirty_modules=frozenset(dirty_modules),
                config=config,
            )
        else:
            result = resolve_project_taints(
                modules=modules,
                provider_fingerprint=self._provider.fingerprint(),
                config=config,
            )

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
        for parsed in file_meta:
            module = parsed.module
            prefix = module + "."
            bucket = project_by_module.setdefault(module, {})
            for ent in parsed.entities:
                rest = ent.qualname[len(prefix) :] if ent.qualname.startswith(prefix) else ent.qualname
                if "." not in rest:  # top-level function (methods aren't bare-callable)
                    bucket[rest] = project_return_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)

        function_var_taints: dict[str, dict[str, TaintState]] = {}
        function_call_site_taints: dict[str, dict[int, dict[str, TaintState]]] = {}
        function_call_site_arg_taints: dict[str, dict[int, dict[int | str | None, TaintState]]] = {}
        project_call_site_arg_taints: dict[int, dict[int | str | None, TaintState]] = {}
        function_return_taints: dict[str, TaintState] = {}
        function_return_callee: dict[str, str | None] = {}
        entity_index: dict[str, Entity] = {}
        func_skip_findings: list[Finding] = []
        # Records carried from L2 pass 1 to pass 2 (closure A): one per entity.
        l2_records: list[_L2Record] = []
        # Per-class attribute summary: ``{class_qualname: {attr: least_trusted write taint}}``.
        class_attr_taints: dict[str, dict[str, TaintState]] = {}
        l2_failed: set[str] = set()

        def _bind_call_site_arguments_to_parameters(
            args_node: ast.arguments,
            arg_taints: dict[int | str | None, TaintState],
            *,
            skip_implicit_receiver: bool = False,
        ) -> dict[str, TaintState]:
            bound: dict[str, list[TaintState]] = {}
            posonly_params = list(args_node.posonlyargs)
            positional_params = list(args_node.args)
            if skip_implicit_receiver:
                if posonly_params:
                    posonly_params = posonly_params[1:]
                elif positional_params:
                    positional_params = positional_params[1:]

            explicit_keyword_names = {
                key for key in arg_taints if isinstance(key, str) and not key.startswith("*")
            }
            filled_args: set[str] = set()
            positional_slots = [*posonly_params, *positional_params]
            pos_idx = 0
            for pos_key in sorted(k for k in arg_taints if isinstance(k, int)):
                if f"*{pos_key}" in arg_taints:
                    continue
                taint = arg_taints[pos_key]
                if pos_idx < len(positional_slots):
                    param = positional_slots[pos_idx]
                    bound.setdefault(param.arg, []).append(taint)
                    filled_args.add(param.arg)
                elif args_node.vararg:
                    bound.setdefault(args_node.vararg.arg, []).append(taint)
                pos_idx += 1

            # Handle *args unpacking. Starred arguments can only bind still-open
            # positional slots or *varargs; they cannot rebind explicit keywords.
            starred_taints = [
                taint for key, taint in arg_taints.items() if isinstance(key, str) and key.startswith("*")
            ]
            if starred_taints:
                star_meet = starred_taints[0]
                for st in starred_taints[1:]:
                    star_meet = combine(star_meet, st)
                for param in positional_slots[pos_idx:]:
                    if param.arg in explicit_keyword_names:
                        continue
                    bound.setdefault(param.arg, []).append(star_meet)
                if args_node.vararg:
                    bound.setdefault(args_node.vararg.arg, []).append(star_meet)

            for key, taint in arg_taints.items():
                if isinstance(key, int) or key is None or (isinstance(key, str) and key.startswith("*")):
                    continue
                if any(p.arg == key for p in positional_params):
                    if key not in filled_args:
                        bound.setdefault(key, []).append(taint)
                        filled_args.add(key)
                elif any(p.arg == key for p in args_node.kwonlyargs):
                    bound.setdefault(key, []).append(taint)
                    filled_args.add(key)
                elif args_node.kwarg:
                    bound.setdefault(args_node.kwarg.arg, []).append(taint)

            # Handle **kwargs unpacking. It cannot bind positional-only params,
            # already-filled params, or *varargs; it can bind unfilled
            # positional-or-keyword, keyword-only, and **kwargs slots.
            if None in arg_taints:
                unpack_taint = arg_taints[None]
                for arg in (*positional_params, *args_node.kwonlyargs):
                    if arg.arg not in filled_args:
                        bound.setdefault(arg.arg, []).append(unpack_taint)
                if args_node.kwarg:
                    bound.setdefault(args_node.kwarg.arg, []).append(unpack_taint)

            result: dict[str, TaintState] = {}
            for param_name, taints in bound.items():
                if taints:
                    meet = taints[0]
                    for t in taints[1:]:
                        meet = combine(meet, t)
                    result[param_name] = meet
            return result

        def _iter_l2_body_nodes(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
            def walk(current: ast.AST) -> Iterator[ast.AST]:
                for child in ast.iter_child_nodes(current):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                        continue
                    yield child
                    yield from walk(child)

            for stmt in node.body:
                yield stmt
                yield from walk(stmt)

        def _assignment_targets(node: ast.AST) -> list[ast.expr]:
            if isinstance(node, ast.Assign):
                return list(node.targets)
            if isinstance(node, ast.AnnAssign | ast.AugAssign):
                return [node.target]
            return []

        def _count_parameter_cells(records: list[_L2Record]) -> int:
            total = 0
            for ent, _seed, _tm, _enclosing_class, _alias_map, _module, _is_method in records:
                args = ent.node.args
                total += len(args.posonlyargs) + len(args.args) + len(args.kwonlyargs)
                total += 1 if args.vararg else 0
                total += 1 if args.kwarg else 0
            return total

        def _count_attribute_cells(records: list[_L2Record]) -> int:
            cells: set[tuple[str, str]] = set()
            for ent, _seed, _tm, enclosing_class, _alias_map, _module, is_method in records:
                for node in _iter_l2_body_nodes(ent.node):
                    for target in _assignment_targets(node):
                        if isinstance(target, ast.Attribute):
                            if isinstance(target.value, ast.Name) and target.value.id in {"self", "cls"} and is_method:
                                cells.add((enclosing_class, target.attr))
                            else:
                                cells.add((ent.qualname, target.attr))
            return len(cells)

        def _l2_iteration_bound(records: list[_L2Record]) -> int:
            lattice_demotions = max(1, len(TaintState) - 1)
            cells = max(1, _count_parameter_cells(records) + _count_attribute_cells(records))
            return lattice_demotions * cells + 1

        def _run_l2(
            node: ast.FunctionDef | ast.AsyncFunctionDef,
            seed: TaintState,
            tm: dict[str, TaintState],
            alias_map: dict[str, str],
            param_meets: dict[str, TaintState] | None = None,
            module_prefix: str | None = None,
        ) -> tuple[
            dict[int, dict[str, TaintState]],
            dict[int, dict[int | str | None, TaintState]],
            dict[str, TaintState],
            TaintState | None,
            str | None,
        ]:
            result = run_l2_function_stage(
                L2FunctionInput(
                    node=node,
                    function_taint=seed,
                    taint_map=dict(tm),
                    alias_map=alias_map,
                    param_meets=param_meets,
                    module_prefix=module_prefix,
                )
            )
            return (
                result.call_site_taints,
                result.call_site_arg_taints,
                result.variable_taints,
                result.return_taint,
                result.return_callee,
            )

        def _store(
            qn: str,
            call_sites: dict[int, dict[str, TaintState]],
            call_args: dict[int, dict[int | str | None, TaintState]],
            var_taints: dict[str, TaintState],
            ret_taint: TaintState | None,
            ret_callee: str | None,
        ) -> None:
            function_var_taints[qn] = var_taints
            function_call_site_taints[qn] = call_sites
            function_call_site_arg_taints[qn] = call_args
            if ret_taint is not None:
                function_return_taints[qn] = ret_taint
            else:
                function_return_taints.pop(qn, None)
            function_return_callee[qn] = ret_callee

        # ── L2 pass 1 — per-method var/return taints + per-class attribute summary ──
        all_classes = frozenset(c for parsed in file_meta for c in parsed.class_qualnames)
        for parsed in file_meta:
            module = parsed.module
            entities = parsed.entities
            alias_map = parsed.alias_map
            classes = parsed.class_qualnames
            # SummaryCache stores interprocedural summaries only. L2 rebuilds
            # flow-sensitive local/call-site maps consumed by sink rules and
            # PY-WL-105, so warm scans must not bypass this pass.
            call_tm = build_call_taint_map(
                module_path=module,
                alias_map=alias_map,
                project_by_module=project_by_module,
                config=config,
                matched_sources=matched_sources,
                matched_sanitisers=matched_sanitisers,
            )
            for ent in entities:
                entity_index[ent.qualname] = ent
                seed = project_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)
                method_tm = dict(call_tm)
                method_tm.update(project_return_taints)
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
                    call_sites, call_args, var_taints, ret_taint, ret_callee = _run_l2(
                        ent.node, seed, method_tm, alias_map, module_prefix=module
                    )
                except RecursionError:
                    l2_failed.add(ent.qualname)
                    call_sites, call_args, var_taints, ret_taint, ret_callee = {}, {}, {}, None, None
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
                _store(ent.qualname, call_sites, call_args, var_taints, ret_taint, ret_callee)
                project_call_site_arg_taints.update(call_args)
                l2_records.append((ent, seed, method_tm, enclosing_class, alias_map, module, is_method))
                if ent.qualname not in l2_failed:
                    from wardline.scanner.taint.variable_level import collect_attribute_writes

                    writes = collect_attribute_writes(
                        ent.node,
                        seed,
                        dict(method_tm),
                        dict(var_taints),
                        all_classes,
                        alias_map,
                        module,
                        enclosing_class=enclosing_class if is_method else None,
                    )
                    for target_class, cls_writes in writes.items():
                        summary = class_attr_taints.setdefault(target_class, {})
                        for attr_name, attr_taint in cls_writes.items():
                            summary[attr_name] = (
                                combine(summary[attr_name], attr_taint) if attr_name in summary else attr_taint
                            )

        # Compute initial project-wide parameter meets from pass-1 call sites
        project_param_meets: dict[str, dict[str, TaintState]] = {}
        for call_id, callee_qn in result.call_site_callees.items():
            callee_ent = entity_index.get(callee_qn)
            if callee_ent is not None:
                arg_taints = project_call_site_arg_taints.get(call_id)
                if arg_taints:
                    call_meets = _bind_call_site_arguments_to_parameters(
                        callee_ent.node.args,
                        arg_taints,
                        skip_implicit_receiver=call_id in result.call_site_implicit_receivers,
                    )
                    callee_meets = project_param_meets.setdefault(callee_qn, {})
                    for param, taint in call_meets.items():
                        if param in callee_meets:
                            callee_meets[param] = combine(callee_meets[param], taint)
                        else:
                            callee_meets[param] = taint

        # ── Iterative Fixed-point L2 Loop to converge parameters and attributes ──
        l2_iteration_bound = _l2_iteration_bound(l2_records)
        l2_converged = False
        last_l2_inputs: dict[str, _L2InputKey] = {}
        last_l2_results: dict[str, _L2Result] = {}
        for _iteration in range(l2_iteration_bound):
            old_class_attr_taints = {k: dict(v) for k, v in class_attr_taints.items()}
            old_project_param_meets = {k: dict(v) for k, v in project_param_meets.items()}

            # Run L2 pass on all functions with current class_attr_taints and project_param_meets
            class_attr_taints = {}
            project_call_site_arg_taints = {}
            for ent, seed, method_tm, enclosing_class, alias_map, module, is_method in l2_records:
                if ent.qualname in l2_failed:
                    continue
                tm_iter = dict(method_tm)
                attr_summary = old_class_attr_taints.get(enclosing_class)
                if attr_summary:
                    for attr_name, attr_taint in attr_summary.items():
                        tm_iter[f"self.{attr_name}"] = attr_taint
                        tm_iter[f"cls.{attr_name}"] = attr_taint
                param_meets = old_project_param_meets.get(ent.qualname)

                inputs_key = (
                    seed,
                    tuple(sorted(tm_iter.items())),
                    tuple(sorted(param_meets.items())) if param_meets else None,
                )
                if last_l2_inputs.get(ent.qualname) == inputs_key:
                    call_sites, call_args, var_taints, ret_taint, ret_callee, writes = last_l2_results[ent.qualname]
                else:
                    try:
                        call_sites, call_args, var_taints, ret_taint, ret_callee = _run_l2(
                            ent.node, seed, tm_iter, alias_map, param_meets=param_meets, module_prefix=module
                        )
                        from wardline.scanner.taint.variable_level import collect_attribute_writes

                        writes = collect_attribute_writes(
                            ent.node,
                            seed,
                            dict(tm_iter),
                            dict(var_taints),
                            all_classes,
                            alias_map,
                            module,
                            enclosing_class=enclosing_class if is_method else None,
                        )
                    except RecursionError:
                        continue
                    last_l2_inputs[ent.qualname] = inputs_key
                    last_l2_results[ent.qualname] = (call_sites, call_args, var_taints, ret_taint, ret_callee, writes)

                _store(ent.qualname, call_sites, call_args, var_taints, ret_taint, ret_callee)
                project_call_site_arg_taints.update(call_args)

                for target_class, cls_writes in writes.items():
                    summary = class_attr_taints.setdefault(target_class, {})
                    for attr_name, attr_taint in cls_writes.items():
                        summary[attr_name] = (
                            combine(summary[attr_name], attr_taint) if attr_name in summary else attr_taint
                        )

            # Re-compute project-wide parameter meets
            project_param_meets = {}
            for call_id, callee_qn in result.call_site_callees.items():
                callee_ent = entity_index.get(callee_qn)
                if callee_ent is not None:
                    arg_taints = project_call_site_arg_taints.get(call_id)
                    if arg_taints:
                        call_meets = _bind_call_site_arguments_to_parameters(
                            callee_ent.node.args,
                            arg_taints,
                            skip_implicit_receiver=call_id in result.call_site_implicit_receivers,
                        )
                        callee_meets = project_param_meets.setdefault(callee_qn, {})
                        for param, taint in call_meets.items():
                            if param in callee_meets:
                                callee_meets[param] = combine(callee_meets[param], taint)
                            else:
                                callee_meets[param] = taint

            # Break if class_attr_taints and project_param_meets did not change
            if class_attr_taints == old_class_attr_taints and project_param_meets == old_project_param_meets:
                l2_converged = True
                break

        if not l2_converged:
            affected = sorted(ent.qualname for ent, *_rest in l2_records if ent.qualname not in l2_failed)
            for qualname in affected:
                if qualname in function_return_taints:
                    function_return_taints[qualname] = combine(
                        function_return_taints[qualname],
                        TaintState.UNKNOWN_RAW,
                    )
                    function_return_callee[qualname] = None
            func_skip_findings.append(
                Finding(
                    rule_id="WLN-ENGINE-L2-CONVERGENCE-BOUND",
                    message=(
                        "L2 parameter/attribute fixed point did not converge within "
                        f"{l2_iteration_bound} lattice-bounded iterations"
                    ),
                    severity=Severity.NONE,
                    kind=Kind.FACT,
                    location=Location(path=ENGINE_PATH),
                    fingerprint=_fp("WLN-ENGINE-L2-CONVERGENCE-BOUND", str(l2_iteration_bound)),
                    properties={
                        "iteration_bound": l2_iteration_bound,
                        "affected_functions": affected,
                    },
                )
            )

        context = AnalysisContext(
            project_taints=project_taints,
            project_return_taints=project_return_taints,
            function_var_taints=function_var_taints,
            function_call_site_taints=function_call_site_taints,
            function_call_site_arg_taints=function_call_site_arg_taints,
            call_site_callees=result.call_site_callees,
            class_attr_taints=class_attr_taints,
            function_return_taints=function_return_taints,
            function_return_callee=function_return_callee,
            entities=entity_index,
            taint_provenance=dict(result.taint_provenance),
            declared_qualnames=frozenset(q for m in modules for q, s in m.seeds.items() if s.source == "provider"),
            project_edges=result.project_edges,
            call_site_implicit_receivers=result.call_site_implicit_receivers,
            alias_maps={m.module_path: m.alias_map for m in modules},
        )
        self.last_context = context

        findings: list[Finding] = list(parse_findings)
        findings.extend(func_skip_findings)
        findings.append(build_metric_finding(result.metadata, cache_hit_rate=cache_hit_rate))
        findings.extend(build_diagnostic_findings(list(result.diagnostics)))
        findings.extend(
            build_unknown_import_findings(
                [(parsed.relpath, parsed.module, parsed.tree) for parsed in file_meta],
                project_modules=frozenset(parsed.module for parsed in file_meta),
                resolvable_star_modules=frozenset(star_exports.keys()),
            )
        )
        # Check for unused config sources
        unused_sources = set(config.untrusted_sources) - matched_sources
        for src in sorted(unused_sources):
            findings.append(
                Finding(
                    rule_id="WLN-CONFIG-UNUSED-SOURCE",
                    message=(
                        f"Configuration error: untrusted source '{src}' "
                        "did not match any imports or calls in the scanned tree"
                    ),
                    severity=Severity.NONE,
                    kind=Kind.FACT,
                    location=Location(path="wardline.yaml"),
                    fingerprint=_fp("WLN-CONFIG-UNUSED-SOURCE", src),
                    properties={"source": src},
                )
            )

        # Check for unused config sanitisers
        unused_sanitisers = set(config.sanitisers) - matched_sanitisers
        for san in sorted(unused_sanitisers):
            findings.append(
                Finding(
                    rule_id="WLN-CONFIG-UNUSED-SANITISER",
                    message=(
                        f"Configuration error: sanitiser '{san}' did not match any imports or calls in the scanned tree"
                    ),
                    severity=Severity.NONE,
                    kind=Kind.FACT,
                    location=Location(path="wardline.yaml"),
                    fingerprint=_fp("WLN-CONFIG-UNUSED-SANITISER", san),
                    properties={"sanitiser": san},
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
