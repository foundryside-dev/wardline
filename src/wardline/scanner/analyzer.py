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
from wardline.core.taints import RAW_ZONE, TaintState, combine
from wardline.scanner.context import AnalysisContext, RuleRegistry
from wardline.scanner.diagnostics import (
    build_collision_findings,
    build_diagnostic_findings,
    build_metric_finding,
    build_unknown_import_findings,
)
from wardline.scanner.grammar import TrustGrammar, build_sanitiser_collision_findings, default_grammar
from wardline.scanner.index import Entity
from wardline.scanner.pipeline import L2FunctionInput, ParseProjectInput, run_l2_function_stage, run_parse_project_stage
from wardline.scanner.rules import build_default_registry
from wardline.scanner.rules._sink_helpers import SinkBindings, collect_sink_bindings
from wardline.scanner.taint.call_taint_map import build_call_taint_map
from wardline.scanner.taint.decorator_provider import (
    DecoratorTaintSourceProvider,
    vocabulary_star_exports,
)
from wardline.scanner.taint.module_summariser import collect_module_global_raw_seeds, own_scope_global_names
from wardline.scanner.taint.project_resolver import resolve_project_taints
from wardline.scanner.taint.provider import TaintSourceProvider
from wardline.scanner.taint.variable_level import L2BudgetExceeded, attribute_write_recording, project_attribute_writes

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
# The L2 fixed-point memo key. ``seed`` and ``method_tm`` are FIXED per entity across
# iterations (computed once in pass 1), so the key carries only the iteration-VARYING
# inputs: the class-attribute overlay and the parameter meets — both O(per-function).
# Keying on the full sorted taint map was O(project) per function per iteration,
# the whole-scan O(n^2) hotspot (resource-exhaustion on large/adversarial trees).
type _L2InputKey = tuple[
    tuple[tuple[str, TaintState], ...] | None,
    tuple[tuple[str, TaintState], ...] | None,
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

# Above this many candidate-key probes, stop the function-level L2 run and emit a
# loud function-skip finding. Falling back to the full project taint map would
# re-open the super-linear path this budget is meant to bound.
_CANDIDATE_KEY_BUDGET = 250_000


def _pruned_method_taint_map(
    node: ast.AST,
    alias_map: dict[str, str],
    module_prefix: str,
    call_tm: dict[str, TaintState],
    project_return_taints: dict[str, TaintState],
) -> dict[str, TaintState]:
    """Restrict the per-function taint map to keys the function can actually look up.

    Folding the whole project's return-taint map into EVERY function's taint map made
    each per-function L2 run O(project): the map copy in ``analyze_function_variables``,
    the per-call ``frozenset(taint_map.keys())``, and the fixed-point memo key all scale
    with the map — an O(n^2) whole-scan blowup. The L2 resolver only ever looks a key up
    by a form DERIVED FROM SOURCE TOKENS in the function body (variable_level.py):

      * a bare name / literal dotted chain as written (``foo`` / ``mod.fn`` / ``self.x``),
      * an alias-resolved chain (``resolve_call_fqn`` / ``_resolve_expr_fqn``:
        ``alias_map[root] + rest``),
      * a module-local candidate (``{module_prefix}.{name}``), and
      * a tracked-receiver-type method key (``{class_fqn}.{attr}`` where the class FQN
        is itself one of the resolved forms above and ``attr`` is an attribute token).

    So the restriction of the merged map to those candidate forms is lookup-equivalent
    to the full map: every key the body can derive is present with the same value
    (project return taints win over ``call_tm`` on conflict, matching the previous
    ``dict(call_tm); update(project_return_taints)`` precedence), and never-derivable
    keys cannot be consulted. Extra candidates that happen to exist in the merged map
    are included harmlessly (the full map contained them too).
    """
    chains: set[str] = set()
    attrs: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            chains.add(n.id)
        elif isinstance(n, ast.Attribute):
            attrs.add(n.attr)
            parts: list[str] = []
            cur: ast.expr = n
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
                chains.add(".".join(reversed(parts)))
    forms: set[str] = set(chains)
    for chain in chains:
        root, _, rest = chain.partition(".")
        target = alias_map.get(root)
        if target is not None:
            forms.add(f"{target}.{rest}" if rest else target)
        if module_prefix:
            forms.add(f"{module_prefix}.{chain}")
    if len(forms) * (len(attrs) + 1) > _CANDIDATE_KEY_BUDGET:
        raise L2BudgetExceeded(
            budget=_CANDIDATE_KEY_BUDGET,
            attempted=len(forms) * (len(attrs) + 1),
            operation="candidate_key_probe",
        )

    tm: dict[str, TaintState] = {}

    def _take(key: str) -> None:
        value = project_return_taints.get(key)
        if value is None:
            value = call_tm.get(key)
        if value is not None:
            tm[key] = value

    for form in forms:
        _take(form)
        for attr in attrs:
            _take(f"{form}.{attr}")
    return tm


def _with_module_global_params(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    param_meets: dict[str, TaintState] | None,
    global_seeds: dict[str, TaintState] | None,
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, TaintState] | None]:
    """Present raw MODULE GLOBALS to one function's L2 walk as implicit parameters.

    The L2 walk resolves a bare name as ``var_taints.get(name, function_taint)`` —
    so an unassigned module-global read would otherwise inherit the trusted caller
    seed (laundering the module-level taint, wardline-66b2c91470). Rather than
    threading a new seed channel through the engine, the raw globals the body
    references are appended as SYNTHETIC keyword-only parameters on a shallow
    wrapper node — sharing the ORIGINAL body/decorator statement objects, so the
    ``id()``-keyed call-site maps stay valid for every downstream consumer — and
    their taints are delivered through the existing ``param_meets`` channel.
    Semantically, module globals enter the function exactly like implicit
    parameters carrying the module-level taint: a function-local assignment then
    shadows the seed flow-sensitively, like any reassigned parameter. Names
    already bound as real parameters are skipped (a parameter shadows the global
    for the whole scope), as are globals the body never mentions (no dead
    ``var_taints`` entries).
    """
    if not global_seeds:
        return node, param_meets
    args = node.args
    existing = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg is not None:
        existing.add(args.vararg.arg)
    if args.kwarg is not None:
        existing.add(args.kwarg.arg)
    referenced = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    names = sorted(name for name in global_seeds if name in referenced and name not in existing)
    if not names:
        return node, param_meets
    synthetic = [ast.copy_location(ast.arg(arg=name), node) for name in names]
    new_args = ast.arguments(
        posonlyargs=list(args.posonlyargs),
        args=list(args.args),
        vararg=args.vararg,
        kwonlyargs=[*args.kwonlyargs, *synthetic],
        kw_defaults=[*args.kw_defaults, *([None] * len(synthetic))],
        kwarg=args.kwarg,
        defaults=list(args.defaults),
    )
    wrapper = type(node)(
        name=node.name,
        args=new_args,
        body=node.body,
        decorator_list=node.decorator_list,
        returns=node.returns,
        type_comment=node.type_comment,
        type_params=list(getattr(node, "type_params", [])),
    )
    ast.copy_location(wrapper, node)
    merged = dict(param_meets or {})
    for name in names:
        merged[name] = combine(merged[name], global_seeds[name]) if name in merged else global_seeds[name]
    return wrapper, merged


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
        # Entity-qualname seeds applied in the parse stage ARE the directive taking
        # effect — count them as matched, or a working untrusted_sources entry that
        # names a project function is misreported as WLN-CONFIG-UNUSED-SOURCE (only
        # the import/alias path in build_call_taint_map recorded matches before).
        matched_sources.update(parse_stage.matched_config_sources)

        # Use the SHADOW-AWARE provider fingerprint computed during the parse stage
        # for BOTH the dirty-detection key (above, inside the parse stage) AND the
        # resolver's summary cache here. They MUST agree, or a summary computed under
        # a non-shadowed root could be served when re-scanning a shadowed one
        # (cross-root cache poisoning → a spoofed-trust false GREEN survives).
        if self._cache is not None:
            result = resolve_project_taints(
                modules=modules,
                provider_fingerprint=parse_stage.provider_fingerprint,
                summary_cache=self._cache,
                dirty_modules=frozenset(dirty_modules),
                config=config,
            )
        else:
            result = resolve_project_taints(
                modules=modules,
                provider_fingerprint=parse_stage.provider_fingerprint,
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

        # Nested-def RETURN taints, bucketed by their enclosing entity — injected
        # into the enclosing function's per-entity taint map under the helper's
        # BARE name. The L2 bare-name resolution otherwise treats an already-
        # analyzed local helper (``m.f.<locals>.clean``) as an unknown callee and
        # applies the worst-arg conservatism, turning every local validate/parse
        # helper into a PY-WL-101 ERROR FP (2026-06-10 review; the launder-closing
        # conservatism of wardline-93d608c997 is preserved for genuinely-unknown
        # bare names). This pass-1 seed uses the L1 return tiers; the fixed-point
        # loop below overlays the PRECISE L2 actual-return taints once they exist
        # (an undecorated ``def clean(x): return 1`` is UNKNOWN_RAW at L1 but
        # INTEGRAL at L2). Built once per scan — a per-entity scan of the project
        # map would reintroduce the O(n^2) hotspot the pruned taint map removed.
        # Lexically sound: a nested def shadows any module-level/imported callable
        # of the same name for the whole enclosing scope.
        nested_def_returns: dict[str, dict[str, TaintState]] = {}
        for nested_qn, nested_taint in project_return_taints.items():
            enclosing_qn, sep, bare = nested_qn.rpartition(".<locals>.")
            if sep and "." not in bare:
                nested_def_returns.setdefault(enclosing_qn, {})[bare] = nested_taint

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

            explicit_keyword_names = {key for key in arg_taints if isinstance(key, str) and not key.startswith("*")}
            filled_args: set[str] = set()
            positional_slots = [*posonly_params, *positional_params]
            pos_idx = 0
            post_star_positional_taints: list[TaintState] = []
            seen_starred_unpack = False
            for pos_key in sorted(k for k in arg_taints if isinstance(k, int)):
                if f"*{pos_key}" in arg_taints:
                    seen_starred_unpack = True
                    continue
                taint = arg_taints[pos_key]
                if seen_starred_unpack:
                    post_star_positional_taints.append(taint)
                    continue
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

            for taint in post_star_positional_taints:
                for param in positional_slots[pos_idx:]:
                    if param.arg in explicit_keyword_names:
                        continue
                    bound.setdefault(param.arg, []).append(taint)
                if args_node.vararg:
                    bound.setdefault(args_node.vararg.arg, []).append(taint)

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
            global_seeds: dict[str, TaintState] | None = None,
        ) -> tuple[
            dict[int, dict[str, TaintState]],
            dict[int, dict[int | str | None, TaintState]],
            dict[str, TaintState],
            TaintState | None,
            str | None,
        ]:
            # Module-global taint channel: raw module globals enter as implicit params.
            node, param_meets = _with_module_global_params(node, param_meets, global_seeds)
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

        # ── Module-scope channels (wardline-66b2c91470 / wardline-13cfdd7b31) ──
        # (a) module-level name bindings (callable aliases / constructed instances) for
        # the sink rules' binding-aware resolution, exposed on the context;
        # (b) module-global RAW seeds — module-level names assigned from a raw source at
        # import time, presented to each function's L2 walk as implicit raw parameters.
        module_sink_bindings: dict[str, SinkBindings] = {}
        module_global_taints: dict[str, dict[str, TaintState]] = {}
        for parsed in file_meta:
            module_sink_bindings[parsed.module] = collect_sink_bindings(parsed.tree, parsed.alias_map, parsed.module)
            global_raw_seeds = collect_module_global_raw_seeds(
                parsed.tree,
                module=parsed.module,
                alias_map=parsed.alias_map,
                return_taints=project_return_taints,
                local_fqns=frozenset(ent.qualname for ent in parsed.entities),
                untrusted_sources=frozenset(config.untrusted_sources),
            )
            if global_raw_seeds:
                module_global_taints[parsed.module] = global_raw_seeds

        # ── L2 pass 1 — per-method var/return taints + per-class attribute summary ──
        all_classes = frozenset(c for parsed in file_meta for c in parsed.class_qualnames)
        failed_paths: set[str] = set()
        function_skip_recorded: set[str] = set()

        def _record_file_failure(relpath: str, ent: Entity, exc: Exception) -> None:
            # Per-file isolation, mirroring the Rust frontend's WLN-ENGINE-FILE-FAILED:
            # an unexpected engine exception on ONE file's analysis must not abort the
            # whole scan (losing every other file's findings) — and must not silently
            # skip either. Fail closed: a gate-eligible ERROR DEFECT names the file
            # (rule id already in UNANALYZED_RULE_IDS, so it counts toward
            # ScanSummary.unanalyzed). One finding per file — the fingerprint is keyed
            # on the relpath (the Rust contract), so a second failing entity in the
            # same file must not mint a colliding distinct finding. ``line_start``
            # falls back to the entity line so the lineless-DEFECT downgrade
            # (suppression.py) never demotes it back out of the gate.
            l2_failed.add(ent.qualname)
            if relpath in failed_paths:
                return
            failed_paths.add(relpath)
            func_skip_findings.append(
                Finding(
                    rule_id="WLN-ENGINE-FILE-FAILED",
                    message=f"{relpath}: analysis failed at {ent.qualname} ({type(exc).__name__}: {exc})",
                    severity=Severity.ERROR,
                    kind=Kind.DEFECT,
                    location=Location(path=relpath, line_start=ent.location.line_start or 1),
                    fingerprint=_fp("WLN-ENGINE-FILE-FAILED", relpath),
                    qualname=ent.qualname,
                    properties={"reason": "analysis_exception", "exception": type(exc).__name__},
                )
            )

        def _record_l2_skip(
            ent: Entity,
            *,
            reason: str,
            message_detail: str,
            budget_error: L2BudgetExceeded | None = None,
        ) -> None:
            l2_failed.add(ent.qualname)
            if ent.qualname in function_skip_recorded:
                return
            function_skip_recorded.add(ent.qualname)
            properties: dict[str, object] = {"reason": reason}
            if budget_error is not None:
                properties.update(
                    {
                        "budget": budget_error.budget,
                        "attempted": budget_error.attempted,
                        "operation": budget_error.operation,
                    }
                )
            func_skip_findings.append(
                Finding(
                    rule_id="WLN-ENGINE-FUNCTION-SKIPPED",
                    message=f"{ent.qualname}: skipped L2 — {message_detail}",
                    severity=Severity.ERROR,
                    kind=Kind.DEFECT,
                    location=ent.location,
                    fingerprint=_fp("WLN-ENGINE-FUNCTION-SKIPPED", ent.qualname),
                    qualname=ent.qualname,
                    properties=properties,
                )
            )

        def _record_l2_recursion(ent: Entity, *, reason: str = "recursion_limit") -> None:
            _record_l2_skip(ent, reason=reason, message_detail="expression too deep to analyze safely")

        def _record_l2_budget(ent: Entity, exc: L2BudgetExceeded) -> None:
            _record_l2_skip(
                ent,
                reason="taint_budget_exceeded",
                message_detail="function too large to analyze soundly",
                budget_error=exc,
            )

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
            # Per-class sibling RETURN-taint entries, built ONCE per module (the
            # previous per-method rescan of all module entities was O(entities) per
            # method). A caller observes a sibling's RETURN taint via self./cls.
            sibling_tm: dict[str, dict[str, TaintState]] = {}
            for ent in entities:
                enclosing = ent.qualname.rsplit(".", 1)[0]
                if enclosing in classes:
                    sib_name = ent.qualname[len(enclosing) + 1 :]
                    sib_taint = project_return_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)
                    bucket = sibling_tm.setdefault(enclosing, {})
                    bucket[f"self.{sib_name}"] = sib_taint
                    bucket[f"cls.{sib_name}"] = sib_taint
            for ent in entities:
                entity_index[ent.qualname] = ent
                seed = project_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)
                enclosing_class = ent.qualname.rsplit(".", 1)[0]
                is_method = enclosing_class in classes
                # Attribute writes are recorded DURING the L2 walk (per-statement
                # var_taints, branch-aware receiver types) — a post-hoc second walk
                # against the FINAL var_taints laundered reassigned-after-write RHS
                # variables and branch-rebound receivers (wardline-b369c7d06c).
                recorded_writes: dict[str, dict[str, TaintState]] = {}
                writes: dict[str, dict[str, TaintState]] = {}
                method_tm: dict[str, TaintState] = {}
                try:
                    method_tm = _pruned_method_taint_map(ent.node, alias_map, module, call_tm, project_return_taints)
                    if is_method:
                        method_tm.update(sibling_tm.get(enclosing_class, {}))
                    # Own nested defs shadow same-named module/imported callables
                    # for the whole scope, so they layer LAST (see nested_def_returns).
                    method_tm.update(nested_def_returns.get(ent.qualname, {}))
                    with attribute_write_recording(recorded_writes):
                        call_sites, call_args, var_taints, ret_taint, ret_callee = _run_l2(
                            ent.node,
                            seed,
                            method_tm,
                            alias_map,
                            module_prefix=module,
                            global_seeds=module_global_taints.get(module),
                        )
                    writes = project_attribute_writes(
                        recorded_writes, all_classes, enclosing_class if is_method else None
                    )
                except L2BudgetExceeded as exc:
                    _record_l2_budget(ent, exc)
                    call_sites, call_args, var_taints, ret_taint, ret_callee = (
                        {},
                        {},
                        {},
                        TaintState.UNKNOWN_RAW,
                        None,
                    )
                    writes = {}
                except RecursionError:
                    _record_l2_recursion(ent)
                    call_sites, call_args, var_taints, ret_taint, ret_callee = (
                        {},
                        {},
                        {},
                        TaintState.UNKNOWN_RAW,
                        None,
                    )
                    writes = {}
                except MemoryError:
                    raise  # exhaustion is not a per-file condition — isolating it would thrash
                except Exception as exc:  # noqa: BLE001 — per-file isolation, see _record_file_failure
                    call_sites, call_args, var_taints, ret_taint, ret_callee = {}, {}, {}, None, None
                    writes = {}
                    _record_file_failure(parsed.relpath, ent, exc)
                _store(ent.qualname, call_sites, call_args, var_taints, ret_taint, ret_callee)
                project_call_site_arg_taints.update(call_args)
                l2_records.append((ent, seed, method_tm, enclosing_class, alias_map, module, is_method))
                for target_class, cls_writes in writes.items():
                    summary = class_attr_taints.setdefault(target_class, {})
                    for attr_name, attr_taint in cls_writes.items():
                        summary[attr_name] = (
                            combine(summary[attr_name], attr_taint) if attr_name in summary else attr_taint
                        )

        # Module-global taint channel, WRITE direction: a function assigning raw to a
        # declared ``global g`` marks the module global; the fixed-point loop below
        # re-runs every function with the merged seeds, so OTHER functions reading
        # ``g`` inherit. ONE merge hop only (documented approximation): the write
        # taints are read from pass 1 and stay FIXED through the loop — a raw value
        # routed global→function→second global needs a second hop and is a bounded
        # FN. The write taint is the function's FINAL (exit-state) L2 taint for the
        # name; only RAW_ZONE writes are recorded (the channel propagates raw, it
        # never upgrades a module-level raw seed to clean), and seeds combine
        # least-trusted-wins with the import-time seeds.
        for ent, _seed, _tm, _enclosing_class, _alias_map, module, _is_method in l2_records:
            if ent.qualname in l2_failed:
                continue
            global_names = own_scope_global_names(ent.node)
            if not global_names:
                continue
            final_vars = function_var_taints.get(ent.qualname, {})
            for name in global_names:
                write_taint = final_vars.get(name)
                if write_taint is not None and write_taint in RAW_ZONE:
                    bucket = module_global_taints.setdefault(module, {})
                    bucket[name] = combine(bucket[name], write_taint) if name in bucket else write_taint

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

        def _l2_nested_def_overlay() -> dict[str, dict[str, TaintState]]:
            """Per-enclosing-entity nested-def bare-name map from the PRECISE L2
            actual-return taints (``function_return_taints``); see the pass-1
            ``nested_def_returns`` seed for the rationale. Recomputed per fixed-
            point iteration so a helper chain converges; participates in the memo
            key and the convergence check below."""
            overlay: dict[str, dict[str, TaintState]] = {}
            for nested_qn, nested_taint in function_return_taints.items():
                enclosing_qn, sep, bare = nested_qn.rpartition(".<locals>.")
                if sep and "." not in bare:
                    overlay.setdefault(enclosing_qn, {})[bare] = nested_taint
            return overlay

        # ── Iterative Fixed-point L2 Loop to converge parameters and attributes ──
        l2_iteration_bound = _l2_iteration_bound(l2_records)
        l2_converged = False
        last_l2_inputs: dict[str, _L2InputKey] = {}
        last_l2_results: dict[str, _L2Result] = {}
        for _iteration in range(l2_iteration_bound):
            old_class_attr_taints = {k: dict(v) for k, v in class_attr_taints.items()}
            old_project_param_meets = {k: dict(v) for k, v in project_param_meets.items()}
            nested_def_overlay = _l2_nested_def_overlay()

            # Run L2 pass on all functions with current class_attr_taints and project_param_meets
            class_attr_taints = {}
            project_call_site_arg_taints = {}
            for ent, seed, method_tm, enclosing_class, alias_map, module, is_method in l2_records:
                if ent.qualname in l2_failed:
                    continue
                attr_summary = old_class_attr_taints.get(enclosing_class)
                param_meets = old_project_param_meets.get(ent.qualname)
                nested_map = nested_def_overlay.get(ent.qualname)

                # ``seed``/``method_tm`` are fixed per entity, so the memo key carries
                # only the iteration-varying inputs (see ``_L2InputKey``) — and on a
                # hit the O(per-function) ``tm_iter`` copy is skipped entirely.
                inputs_key = (
                    tuple(sorted(attr_summary.items())) if attr_summary else None,
                    tuple(sorted(param_meets.items())) if param_meets else None,
                    tuple(sorted(nested_map.items())) if nested_map else None,
                )
                if last_l2_inputs.get(ent.qualname) == inputs_key:
                    call_sites, call_args, var_taints, ret_taint, ret_callee, writes = last_l2_results[ent.qualname]
                else:
                    tm_iter = dict(method_tm)
                    if attr_summary:
                        for attr_name, attr_taint in attr_summary.items():
                            tm_iter[f"self.{attr_name}"] = attr_taint
                            tm_iter[f"cls.{attr_name}"] = attr_taint
                    if nested_map:
                        # Own nested defs shadow same-named module/imported callables
                        # (and the pass-1 L1 seed) for the whole scope — layered last.
                        tm_iter.update(nested_map)
                    recorded_writes = {}
                    try:
                        with attribute_write_recording(recorded_writes):
                            # ``module_global_taints`` is FIXED during this loop (merged
                            # once after pass 1), so the ``inputs_key`` memo stays valid.
                            call_sites, call_args, var_taints, ret_taint, ret_callee = _run_l2(
                                ent.node,
                                seed,
                                tm_iter,
                                alias_map,
                                param_meets=param_meets,
                                module_prefix=module,
                                global_seeds=module_global_taints.get(module),
                            )
                        writes = project_attribute_writes(
                            recorded_writes, all_classes, enclosing_class if is_method else None
                        )
                    except L2BudgetExceeded as exc:
                        _record_l2_budget(ent, exc)
                        call_sites, call_args, var_taints, ret_taint, ret_callee, writes = (
                            {},
                            {},
                            {},
                            TaintState.UNKNOWN_RAW,
                            None,
                            {},
                        )
                    except RecursionError:
                        _record_l2_recursion(ent, reason="fixpoint_recursion")
                        call_sites, call_args, var_taints, ret_taint, ret_callee, writes = (
                            {},
                            {},
                            {},
                            TaintState.UNKNOWN_RAW,
                            None,
                            {},
                        )
                    except MemoryError:
                        raise  # exhaustion is not a per-file condition — isolating it would thrash
                    except Exception as exc:  # noqa: BLE001 — per-file isolation, see _record_file_failure
                        _record_file_failure(ent.location.path, ent, exc)
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

            # Break if class_attr_taints, project_param_meets, and the nested-def
            # return overlay did not change (the overlay feeds tm_iter, so a still-
            # moving helper chain must keep iterating).
            if (
                class_attr_taints == old_class_attr_taints
                and project_param_meets == old_project_param_meets
                and _l2_nested_def_overlay() == nested_def_overlay
            ):
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

        # The registry is built BEFORE the context so the selected rule-id set can
        # ride on it (PY-WL-120's suppress-and-delegate consults enablement; a
        # duck-typed registry seam without a ``rules`` property yields None —
        # "unknown", the historical assume-enabled posture).
        registry = (
            self._registry
            if self._registry is not None
            else build_default_registry(config, rules=(self._grammar.rules if self._grammar is not None else None))
        )
        registry_rules = getattr(registry, "rules", None)
        enabled_rule_ids = (
            frozenset(str(getattr(rule, "rule_id", type(rule).__name__)) for rule in registry_rules)
            if registry_rules is not None
            else None
        )

        context = AnalysisContext(
            project_taints=project_taints,
            project_return_taints=project_return_taints,
            function_var_taints=function_var_taints,
            function_call_site_taints=function_call_site_taints,
            function_call_site_arg_taints=function_call_site_arg_taints,
            call_site_callees=result.call_site_callees,
            call_site_candidate_callees=result.call_site_candidate_callees,
            class_attr_taints=class_attr_taints,
            function_return_taints=function_return_taints,
            function_return_callee=function_return_callee,
            entities=entity_index,
            taint_provenance=dict(result.taint_provenance),
            declared_qualnames=frozenset(q for m in modules for q, s in m.seeds.items() if s.source == "provider"),
            declared_body_taints={
                q: s.body_taint for m in modules for q, s in m.seeds.items() if s.source == "provider"
            },
            project_edges=result.project_edges,
            call_site_implicit_receivers=result.call_site_implicit_receivers,
            alias_maps={m.module_path: m.alias_map for m in modules},
            analyzed_source_sha256={parsed.relpath: parsed.source_sha256 for parsed in file_meta},
            module_bindings=module_sink_bindings,
            enabled_rule_ids=enabled_rule_ids,
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
                    location=Location(path="weft.toml"),
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
                    location=Location(path="weft.toml"),
                    fingerprint=_fp("WLN-CONFIG-UNUSED-SANITISER", san),
                    properties={"sanitiser": san},
                )
            )
        # A sanitiser colliding with a modelled serialisation sink would otherwise be
        # dropped silently; the collision FACT speaks instead of UNUSED-SANITISER.
        findings.extend(build_sanitiser_collision_findings(config.sanitisers))

        # Per-rule isolation: one crashing rule must not abort the whole scan and
        # silently lose every other rule's findings. Each rule runs in its own
        # single-rule registry (reusing RuleRegistry.run's maturity stamping); a
        # raise becomes a gate-eligible ERROR DEFECT at ENGINE_PATH (the lineless
        # downgrade exempts ENGINE_PATH, so it trips --fail-on ERROR — fail-closed,
        # same posture as WLN-ENGINE-FINGERPRINT-COLLISION). Duck-typed registry
        # seams without a ``rules`` property keep the undelegated single call.
        if registry_rules is None:
            findings.extend(registry.run(context))
        else:
            for rule in registry_rules:
                solo = RuleRegistry()
                solo.register(rule)
                try:
                    findings.extend(solo.run(context))
                except Exception as exc:  # noqa: BLE001 — per-rule isolation, see above
                    rid = str(getattr(rule, "rule_id", type(rule).__name__))
                    findings.append(
                        Finding(
                            rule_id="WLN-ENGINE-RULE-FAILED",
                            message=(
                                f"rule {rid} aborted ({type(exc).__name__}: {exc}) — "
                                "its findings are missing from this scan"
                            ),
                            severity=Severity.ERROR,
                            kind=Kind.DEFECT,
                            location=Location(path=ENGINE_PATH),
                            fingerprint=_fp("WLN-ENGINE-RULE-FAILED", rid),
                            properties={"rule": rid, "exception": type(exc).__name__},
                        )
                    )
        # Sink-argument resolution degraded to the pessimistic flow-INSENSITIVE
        # fallback somewhere (an L2-skipped function): surface the recorded set as
        # ONE NONE/FACT finding per scan, mirroring WLN-ENGINE-FUNCTION-SKIPPED. A
        # finding, not a UserWarning — MCP/library consumers see the degradation,
        # and a warnings-as-error embedder cannot turn the diagnostic into a
        # rule-aborting raise (review 2026-06-10).
        if context.flow_insensitive_fallbacks:
            findings.append(
                Finding(
                    rule_id="WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK",
                    message=(
                        "sink-argument taint resolution fell back to the pessimistic "
                        f"flow-insensitive map for {len(context.flow_insensitive_fallbacks)} "
                        "function(s) — their sink findings assume UNKNOWN_RAW arguments"
                    ),
                    severity=Severity.NONE,
                    kind=Kind.FACT,
                    location=Location(path=ENGINE_PATH),
                    # Keyed on the engine path only (never the affected qualnames) so the
                    # one-per-scan FACT keeps a stable identity as the set churns.
                    fingerprint=_fp("WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK", ENGINE_PATH),
                    properties={"qualnames": sorted(context.flow_insensitive_fallbacks)},
                )
            )
        # Proactive no-collision guard (wardline-8fb773a7af): every fingerprint
        # consumer joins on Finding.fingerprint as a unique key, so two DISTINCT
        # findings sharing one is a silent false-negative. Run last, over the full
        # emitted set, and append a loud ENGINE DEFECT per collision. Its own input
        # is the pre-append list, so the guard never sees (or collides with) itself.
        findings.extend(build_collision_findings(findings))
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
