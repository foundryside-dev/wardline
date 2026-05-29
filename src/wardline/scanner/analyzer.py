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
from wardline.core.taints import TaintState
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.context import AnalysisContext, RuleRegistry
from wardline.scanner.diagnostics import (
    build_diagnostic_findings,
    build_metric_finding,
    build_unknown_import_findings,
)
from wardline.scanner.index import discover_class_qualnames, discover_file_entities
from wardline.scanner.taint.call_taint_map import build_call_taint_map
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
from wardline.scanner.taint.function_level import seed_function_taints
from wardline.scanner.taint.project_resolver import ModuleInput, resolve_project_taints
from wardline.scanner.taint.provider import SeedContext, TaintSourceProvider
from wardline.scanner.taint.variable_level import compute_variable_taints

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
    ) -> None:
        self._provider: TaintSourceProvider = provider or DecoratorTaintSourceProvider()
        self._registry = registry or RuleRegistry()
        self._cache = summary_cache
        self.last_context: AnalysisContext | None = None

    def analyze(
        self, files: Sequence[Path], config: WardlineConfig, *, root: Path
    ) -> Sequence[Finding]:
        modules: list[ModuleInput] = []
        # (relpath, module_path, tree, entities, alias_map)
        file_meta: list[tuple[str, str, ast.Module, tuple[Entity, ...], dict[str, str]]] = []
        parse_findings: list[Finding] = []

        for path in files:
            relpath = (
                path.relative_to(root).as_posix()
                if path.is_relative_to(root)
                else path.as_posix()
            )
            module = module_dotted_name(relpath)
            if module is None:
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
                alias_map = build_import_alias_map(tree, module_path=module)
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
            file_meta.append((relpath, module, tree, entities, alias_map))

        if self._cache is not None:
            result = resolve_project_taints(
                modules=modules,
                provider_fingerprint=self._provider.fingerprint(),
                summary_cache=self._cache,
                dirty_modules=frozenset(),
            )
        else:
            result = resolve_project_taints(
                modules=modules, provider_fingerprint=self._provider.fingerprint()
            )

        # Measured AFTER resolve so it reflects THIS run's cache effectiveness
        # (0.0 cold, →1.0 warm). It is a genuinely run-varying METRIC; the
        # warm≡cold invariant applies to the taint findings, not to this metric.
        cache_hit_rate = self._cache.hit_rate() if self._cache is not None else 0.0

        project_taints = dict(result.taint_map)

        # Per-file L2 with a per-function RecursionError boundary.
        # NOTE: project_taints is the refined *body* taint; equals return taint
        # for all non-anchored functions (SP1 universe). # SP2: expose the
        # return map for anchored callees with distinct return tiers.
        # Pre-bucket project taints by module → {top_level_func_name: taint},
        # once, so the per-file L2 builder is O(aliases) not O(project_funcs).
        project_by_module: dict[str, dict[str, TaintState]] = {}
        for _relpath, module, _tree, entities, _alias_map in file_meta:
            prefix = module + "."
            bucket = project_by_module.setdefault(module, {})
            for ent in entities:
                rest = ent.qualname[len(prefix):] if ent.qualname.startswith(prefix) else ent.qualname
                if "." not in rest:  # top-level function (methods aren't bare-callable)
                    bucket[rest] = project_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)

        function_var_taints: dict[str, dict[str, TaintState]] = {}
        entity_index: dict[str, Entity] = {}
        for _relpath, module, _tree, entities, alias_map in file_meta:
            call_tm = build_call_taint_map(
                module_path=module, alias_map=alias_map, project_by_module=project_by_module
            )
            for ent in entities:
                entity_index[ent.qualname] = ent
                seed = project_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)
                try:
                    var_taints = compute_variable_taints(ent.node, seed, dict(call_tm))
                except RecursionError:
                    var_taints = {}  # fail-closed; absent vars read as the function taint
                function_var_taints[ent.qualname] = var_taints

        context = AnalysisContext(
            project_taints=project_taints,
            function_var_taints=function_var_taints,
            entities=entity_index,
            taint_provenance=dict(result.taint_provenance),
        )
        self.last_context = context

        findings: list[Finding] = list(parse_findings)
        findings.append(build_metric_finding(result.metadata, cache_hit_rate=cache_hit_rate))
        findings.extend(build_diagnostic_findings(list(result.diagnostics)))
        findings.extend(
            build_unknown_import_findings(
                [(rp, mp, tr) for rp, mp, tr, _e, _a in file_meta],
                project_modules=frozenset(mp for _rp, mp, _tr, _e, _a in file_meta),
            )
        )
        findings.extend(self._registry.run(context))  # empty in SP1
        return findings
