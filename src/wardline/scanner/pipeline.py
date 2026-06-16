"""Typed scanner pipeline stages shared by analyzer orchestration and tests."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.qualname import module_dotted_name
from wardline.core.taints import TaintState
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.index import Entity, discover_class_qualnames, discover_file_entities
from wardline.scanner.taint.function_level import seed_function_taints
from wardline.scanner.taint.project_resolver import ModuleInput
from wardline.scanner.taint.provider import SeedContext, TaintSourceProvider
from wardline.scanner.taint.variable_level import (
    VariableTaintContext,
    analyze_function_variables,
)

if TYPE_CHECKING:
    from wardline.core.config import WardlineConfig
    from wardline.scanner.taint.summary_cache import SummaryCache


def _fp(*parts: str) -> str:
    digest = hashlib.sha256()
    digest.update("\x00".join(parts).encode("utf-8"))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class ParsedFile:
    relpath: str
    module: str
    tree: ast.Module
    entities: tuple[Entity, ...]
    alias_map: dict[str, str]
    class_qualnames: frozenset[str]
    source_sha256: str


@dataclass(frozen=True, slots=True)
class ParseProjectInput:
    files: Sequence[Path]
    root: Path
    provider: TaintSourceProvider
    config: WardlineConfig
    star_exports: dict[str, dict[str, str]]
    summary_cache: SummaryCache | None = None


@dataclass(frozen=True, slots=True)
class ParseProjectOutput:
    modules: list[ModuleInput]
    files: list[ParsedFile]
    parse_findings: list[Finding]
    dirty_modules: frozenset[str]
    provider_fingerprint: str
    # config.untrusted_sources entries that matched a PROJECT ENTITY QUALNAME and
    # were applied as seeds here. The analyzer unions these into its matched-source
    # bookkeeping — without this channel a WORKING directive was misreported as
    # WLN-CONFIG-UNUSED-SOURCE (only the import/alias path recorded matches).
    matched_config_sources: frozenset[str] = frozenset()


def _provider_fingerprint_for_project(provider: TaintSourceProvider, project_modules: frozenset[str]) -> str:
    """Project-aware provider fingerprint, falling back to the bare one.

    A provider may expose ``fingerprint_for_project(project_modules)`` to fold
    project-shadow state (which builtin marker roots the scan shadows) into the
    summary-cache key — preventing a warm cache from serving a TRUSTED summary
    computed under a non-shadowed root when re-scanning a shadowed one. Providers
    that do not (the trivial default) fall back to the plain ``fingerprint()``.
    """
    project_fingerprint = getattr(provider, "fingerprint_for_project", None)
    if callable(project_fingerprint):
        typed_project_fingerprint = cast(Any, project_fingerprint)
        return str(typed_project_fingerprint(project_modules))
    return provider.fingerprint()


def run_parse_project_stage(stage_input: ParseProjectInput) -> ParseProjectOutput:
    """Read, parse, index, seed, and cache-classify project files."""
    modules: list[ModuleInput] = []
    parsed_files: list[ParsedFile] = []
    parse_findings: list[Finding] = []
    dirty_modules: set[str] = set()
    matched_config_sources: set[str] = set()
    root = stage_input.root.resolve()

    # The set of dotted module names in the scan. Used to fail closed for builtin
    # markers when the project shadows a builtin marker root, AND to compute the
    # shadow-aware provider fingerprint threaded into BOTH the dirty-detection key
    # below and the resolver's summary cache (see analyzer.py).
    project_modules = frozenset(
        module
        for path in stage_input.files
        if (
            module := module_dotted_name(
                path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
            )
        )
        is not None
    )
    provider_fingerprint = _provider_fingerprint_for_project(stage_input.provider, project_modules)

    for path in stage_input.files:
        relpath = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
        module = module_dotted_name(relpath)
        if module is None:
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

        try:
            source = path.read_text(encoding="utf-8")
            source_bytes = source.encode("utf-8")
            source_sha256 = hashlib.sha256(source_bytes).hexdigest()

            from wardline.core.ruleset import ruleset_hash
            from wardline.scanner.taint.project_resolver import _RESOLVER_VERSION
            from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION, compute_cache_key

            cache_key = compute_cache_key(
                module_path=module,
                source_bytes=source_bytes,
                schema_version=SUMMARY_SCHEMA_VERSION,
                resolver_version=_RESOLVER_VERSION,
                provider_fingerprint=provider_fingerprint,
                scan_policy_hash=ruleset_hash(stage_input.config),
            )
            if stage_input.summary_cache is None or not stage_input.summary_cache.has_current(cache_key):
                dirty_modules.add(module)

            tree = ast.parse(source)
            entities = tuple(discover_file_entities(tree, module=module, path=relpath))
            classes = frozenset(discover_class_qualnames(tree, module=module))
            is_pkg_file = path.name == "__init__.py"
            alias_map = build_import_alias_map(
                tree,
                module_path=module,
                is_package=is_pkg_file,
                star_exports=stage_input.star_exports,
            )
            seeds = seed_function_taints(
                entities,
                ctx=SeedContext(module=module, alias_map=alias_map, project_modules=project_modules),
                provider=stage_input.provider,
            )
            for ent in entities:
                if ent.qualname in stage_input.config.untrusted_sources:
                    from wardline.scanner.taint.function_level import FunctionSeed

                    # The seed below IS the directive taking effect — record the match
                    # so the analyzer's unused-source diagnostic does not contradict it.
                    matched_config_sources.add(ent.qualname)
                    seeds[ent.qualname] = FunctionSeed(
                        qualname=ent.qualname,
                        body_taint=TaintState.EXTERNAL_RAW,
                        return_taint=TaintState.EXTERNAL_RAW,
                        source="provider",
                        unprovable_boundaries=(),
                    )
        except (SyntaxError, UnicodeDecodeError, OSError) as exc:
            # A discovered-but-unparseable file is a GATE-ELIGIBLE ERROR DEFECT, not a
            # NONE FACT: its sinks were never analyzed, so a default `--fail-on ERROR`
            # reading GREEN over it is a fail-open (e.g. a latin-1 coding cookie that
            # CPython runs but this UTF-8 reader rejects hides live code from the scan).
            # Severity ERROR so the documented agent loop (`scan . --fail-on ERROR`)
            # trips — the secure-by-default posture (same as the suppression gate and
            # WLN-ENGINE-FINGERPRINT-COLLISION). Repository baseline/waiver still
            # ANNOTATE it but cannot clear the secure gate; `--trust-suppressions` can
            # (an explicit operator trust decision). ``line_start`` falls back to 1 so
            # the lineless-DEFECT downgrade (suppression.py) never demotes it back out
            # of the gate for read/encoding errors that carry no line.
            msg = getattr(exc, "msg", None) or str(exc)
            lineno = exc.lineno if isinstance(exc, SyntaxError) else None
            parse_findings.append(
                Finding(
                    rule_id="WLN-ENGINE-PARSE-ERROR",
                    message=f"{relpath}: could not read/parse ({msg})",
                    severity=Severity.ERROR,
                    kind=Kind.DEFECT,
                    location=Location(path=relpath, line_start=lineno or 1),
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
                    severity=Severity.ERROR,
                    kind=Kind.DEFECT,
                    location=Location(path=relpath, line_start=1),
                    fingerprint=_fp("WLN-ENGINE-FILE-SKIPPED", relpath),
                    properties={"module": module, "reason": "recursion_limit"},
                )
            )
            continue
        except Exception as exc:  # noqa: BLE001 — per-file isolation, mirrors the Rust frontend
            # An UNEXPECTED exception while indexing/seeding one file must not abort
            # the whole scan (losing every other file's findings) — and must not be a
            # silent skip either. Fail closed: a WLN-ENGINE-FILE-FAILED ERROR DEFECT
            # (gate-eligible, counted toward ScanSummary.unanalyzed) names the file,
            # and the scan continues — the Rust frontend's per-file contract.
            parse_findings.append(
                Finding(
                    rule_id="WLN-ENGINE-FILE-FAILED",
                    message=f"{relpath}: analysis failed ({type(exc).__name__}: {exc})",
                    severity=Severity.ERROR,
                    kind=Kind.DEFECT,
                    location=Location(path=relpath, line_start=1),
                    fingerprint=_fp("WLN-ENGINE-FILE-FAILED", relpath),
                    properties={"module": module, "reason": "analysis_exception", "exception": type(exc).__name__},
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
                source_bytes=source_bytes,
            )
        )
        parsed_files.append(
            ParsedFile(
                relpath=relpath,
                module=module,
                tree=tree,
                entities=entities,
                alias_map=alias_map,
                class_qualnames=classes,
                source_sha256=source_sha256,
            )
        )
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
                        fingerprint=_fp("WLN-ENGINE-UNPROVABLE-BOUNDARY", ent.qualname, boundary),
                        qualname=ent.qualname,
                        properties={"boundary": boundary, "reason": "arg_unreadable"},
                    )
                )

    return ParseProjectOutput(
        modules=modules,
        files=parsed_files,
        parse_findings=parse_findings,
        dirty_modules=frozenset(dirty_modules),
        provider_fingerprint=provider_fingerprint,
        matched_config_sources=frozenset(matched_config_sources),
    )


@dataclass(frozen=True, slots=True)
class L2FunctionInput:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    function_taint: TaintState
    taint_map: dict[str, TaintState]
    alias_map: dict[str, str]
    param_meets: dict[str, TaintState] | None = None
    module_prefix: str | None = None


@dataclass(frozen=True, slots=True)
class L2FunctionOutput:
    call_site_taints: dict[int, dict[str, TaintState]]
    call_site_arg_taints: dict[int, dict[int | str | None, TaintState]]
    variable_taints: dict[str, TaintState]
    return_taint: TaintState | None
    return_callee: str | None


def run_l2_function_stage(stage_input: L2FunctionInput) -> L2FunctionOutput:
    """Run the variable-level scanner stage for one function."""
    result = analyze_function_variables(
        stage_input.node,
        stage_input.function_taint,
        stage_input.taint_map,
        VariableTaintContext(
            alias_map=stage_input.alias_map,
            module_prefix=stage_input.module_prefix,
            param_meets=stage_input.param_meets,
        ),
    )
    return L2FunctionOutput(
        call_site_taints=result.call_site_taints,
        call_site_arg_taints=result.call_site_arg_taints,
        variable_taints=result.variable_taints,
        return_taint=result.return_taint,
        return_callee=result.return_callee,
    )
