# src/wardline/core/run.py
"""SP8: the scan orchestration shared by the CLI and the MCP server.

This is the behaviour-preserving extraction of what used to live inline in
``cli/scan.py``. Both the CLI and the MCP server call ``run_scan`` so they are
identical by construction — same findings, same ``active`` count, same gate.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

from wardline.core import config as config_mod
from wardline.core.baseline import Baseline, load_baseline
from wardline.core.delta import get_affected_entities, get_changed_files_since
from wardline.core.discovery import discover, missing_source_roots
from wardline.core.errors import ConfigError
from wardline.core.finding import (
    UNANALYZED_RULE_IDS,
    Finding,
    Kind,
    Location,
    Maturity,
    Severity,
    SuppressionState,
)
from wardline.core.judged import load_judged
from wardline.core.paths import baseline_path, judged_path, weft_config_path
from wardline.core.protocols import Analyzer
from wardline.core.suppression import apply_suppressions, gate_trips, severity_gates
from wardline.core.waivers import WaiverSet, load_project_waivers

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext


def _fp(*parts: str) -> str:
    digest = hashlib.sha256()
    digest.update("\x00".join(parts).encode("utf-8"))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class ScanSummary:
    total: int  # every finding (defects + facts/metrics)
    active: int  # non-suppressed DEFECTs in the emitted findings (NOT the gate population —
    # the gate evaluates ScanResult.gate_findings unless --trust-suppressions)
    baselined: int
    waived: int
    judged: int
    # Files DISCOVERED but NEVER analysed despite being analysable — a genuine
    # under-scan (parse errors, too-deep skips, missing source roots). Benign
    # no-module skips (WLN-ENGINE-NO-MODULE) are EXCLUDED — see UNANALYZED_RULE_IDS.
    # These are Severity.NONE FACTs that never trip the severity gate, so they are
    # counted separately to surface a silent under-scan / false-green.
    unanalyzed: int = 0


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: list[Finding]
    summary: ScanSummary
    files_scanned: int
    # The analysis context is retained in-process so explain_finding can reuse
    # this exact run instead of re-deriving. Never serialised over MCP.
    context: AnalysisContext | None
    scanned_paths: tuple[str, ...] = ()
    # The UNSUPPRESSED gate population (None SENTINEL — never a falsy-empty fallback).
    # Repository-controlled baseline/waiver/judged still ANNOTATE ``findings`` (visible
    # as ``suppressed=…``), but a malicious PR must not be able to clear the ``--fail-on``
    # gate by committing a suppression keyed to its own new defect. ``gate_decision``
    # evaluates this when it is not None, else falls back to ``findings`` (the trusted,
    # local ``--trust-suppressions`` / directly-constructed-ScanResult behaviour). It is
    # scoped by ``--new-since`` identically to ``findings``.
    gate_findings: list[Finding] | None = None


@dataclass(frozen=True, slots=True)
class GateDecision:
    tripped: bool
    fail_on: str | None
    exit_class: int  # 0 clean, 1 gate tripped, 2 reserved for tool errors (CLI layer)
    # A human-readable verdict so "summary.active:0 + gate.tripped:true" never reads as
    # a bug: ``reason`` names the count and class of defects that decided it (and the
    # escape hatches when the trip is solely from suppressed-but-gated findings);
    # ``evaluated`` names the population it judged (unsuppressed by default vs honored
    # under --trust-suppressions). Both None when no threshold is set (no gate).
    reason: str | None = None
    evaluated: str | None = None

    def __post_init__(self) -> None:
        # Enforce the invariants the ``gate_decision`` factory upholds so a *second*
        # constructor cannot reintroduce dogfood #2 (a tripped gate that reads as passed).
        # exit_class mirrors tripped (0/1); the reserved 2 is a CLI SystemExit, never a
        # GateDecision value.
        if self.exit_class != (1 if self.tripped else 0):
            raise ValueError(f"exit_class {self.exit_class} contradicts tripped={self.tripped}")
        # A tripped gate must always carry its verdict — never silently None.
        if self.tripped and self.reason is None:
            raise ValueError("a tripped gate must carry a reason")
        # No threshold (fail_on None) ⟺ no verdict; a threshold always produces both.
        if (self.fail_on is None) != (self.reason is None):
            raise ValueError("reason must be present iff fail_on is set")
        if (self.fail_on is None) != (self.evaluated is None):
            raise ValueError("evaluated must be present iff fail_on is set")


def run_scan(
    root: Path,
    *,
    config_path: Path | None = None,
    cache_dir: Path | None = None,
    confine_to_root: bool = True,
    new_since: str | None = None,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    strict_defaults: bool = False,
    trust_suppressions: bool = False,
) -> ScanResult:
    """Discover → analyze → apply suppressions. Pure function of (disk + config).

    Raises ``WardlineError`` subclasses on bad config / unreadable paths; the
    caller (CLI or MCP server) maps those to its own error channel.

    ``confine_to_root`` (default True) makes ``discover`` reject any
    ``source_root`` that resolves outside ``root``. Callers that intentionally
    scan outside the project root must opt out explicitly.

    ``trust_suppressions`` (default False) is the SECURITY default. When False the
    ``--fail-on`` gate evaluates a separately-built UNSUPPRESSED population
    (``ScanResult.gate_findings``): repository-controlled baseline/waiver/judged
    files still annotate the emitted ``findings`` but cannot clear the gate, so a
    malicious PR cannot self-suppress its own new defect. When True the gate falls
    back to the suppressed ``findings`` (``gate_findings`` is set to None) — the
    trusted local / judge-DX behaviour, an explicit operator trust decision suitable
    only for a trusted checkout, never for enforcement on untrusted PR content. The
    secure CI ratchet is the operator-supplied, unforgeable ``--new-since`` instead.
    """
    from wardline.scanner.analyzer import build_analyzer
    from wardline.scanner.grammar import TrustGrammar, default_grammar
    from wardline.scanner.taint.summary_cache import SummaryCache

    # An EXPLICIT --config path that doesn't exist must NOT silently fall back to
    # default policy (dropping the operator's severity overrides/excludes) — that
    # is a false-green. The IMPLICIT default (root/weft.toml) may legitimately
    # be absent; config_mod.load tolerates that.
    if config_path is not None and not config_path.exists():
        raise ConfigError(f"config file does not exist: {config_path}")
    cfg_path = config_path or weft_config_path(root)
    cfg = config_mod.load(
        cfg_path,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    cache = None
    if cache_dir is not None:
        cache = SummaryCache(cache_dir=cache_dir)
        from wardline.core.taints import _PROVENANCE_CLASH

        token_clash = _PROVENANCE_CLASH.set(cfg.provenance_clash)
        try:
            cache.load()
        finally:
            _PROVENANCE_CLASH.reset(token_clash)
    import warnings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        files = discover(root, cfg, confine_to_root=confine_to_root)
        captured_warnings = list(w)
    for warn in captured_warnings:
        msg = str(warn.message)
        if not msg.startswith("WLN-ENGINE-FILE-SKIPPED: "):
            warnings.warn_explicit(
                warn.message,
                warn.category,
                warn.filename,
                warn.lineno,
            )
    grammar = default_grammar()
    for pack_name, pkg in cfg.pack_modules.items():
        pack_grammar = getattr(pkg, "grammar", None)
        if pack_grammar is not None:
            if not isinstance(pack_grammar, TrustGrammar):
                raise ConfigError(f"pack {pack_name!r} attribute 'grammar' must be a TrustGrammar instance")
            grammar = grammar.extend(
                boundary_types=pack_grammar.boundary_types,
                rules=pack_grammar.rules,
            )

    analyzer: Analyzer = build_analyzer(grammar=grammar, summary_cache=cache)
    raw = list(analyzer.analyze(files, cfg, root=root))
    for warn in captured_warnings:
        msg = str(warn.message)
        if msg.startswith("WLN-ENGINE-FILE-SKIPPED: "):
            skipped_rel = msg[len("WLN-ENGINE-FILE-SKIPPED: ") :].strip()
            raw.append(
                Finding(
                    rule_id="WLN-ENGINE-FILE-SKIPPED",
                    message=f"{skipped_rel}: skipped — symlink resolves outside the project root",
                    severity=Severity.NONE,
                    kind=Kind.FACT,
                    location=Location(path=skipped_rel),
                    fingerprint=_fp("WLN-ENGINE-FILE-SKIPPED", skipped_rel),
                    properties={"reason": "out_of_root_symlink"},
                )
            )
    # A non-existent (non-escaping) source_root is otherwise only a stderr warning
    # from discover — invisible to the MCP agent. Surface it as a finding that
    # reaches both the CLI summary and the MCP result, and counts toward unanalyzed.
    for src in missing_source_roots(root, cfg, confine_to_root=confine_to_root):
        raw.append(
            Finding(
                rule_id="WLN-ENGINE-SOURCE-ROOT-MISSING",
                message=f"source root does not exist: {src}",
                severity=Severity.NONE,
                kind=Kind.FACT,
                location=Location(path=src),
                fingerprint=_fp("WLN-ENGINE-SOURCE-ROOT-MISSING", src),
                properties={"source_root": src},
            )
        )
    if cache is not None:
        cache.save()
    baseline = load_baseline(baseline_path(root))
    waivers = WaiverSet(load_project_waivers(root))
    judged = load_judged(judged_path(root))
    today = date.today()
    # The emitted findings ALWAYS carry the full suppression annotations (baseline,
    # waiver, judged) so ``suppressed=…`` is visible in output regardless of trust.
    findings = apply_suppressions(raw, baseline, waivers, today=today, judged=judged)
    # The gate population applies ZERO suppression but runs the SAME structural
    # transforms apply_suppressions does (esp. the lineless-DEFECT→non-gating-FACT
    # downgrade), so the only difference vs ``findings`` is the suppression sources —
    # NOT ``list(raw)``, which would let a lineless DEFECT trip the gate. When the
    # operator trusts repo suppressions, gate_findings is None and the gate falls back
    # to the suppressed ``findings`` (None SENTINEL, never an accidental falsy-empty).
    gate_findings: list[Finding] | None
    if trust_suppressions:
        gate_findings = None
    else:
        gate_findings = apply_suppressions(raw, Baseline(frozenset()), WaiverSet([]), today=today, judged=None)

    if new_since is not None:
        changed_files = get_changed_files_since(new_since, root)
        context = analyzer.last_context
        if context is not None:
            affected = get_affected_entities(changed_files, context.entities, context.project_edges)
        else:
            affected = set()

        def apply_delta_scope(candidates: list[Finding]) -> list[Finding]:
            # Suppress any ACTIVE defect outside the delta so the gate only fires on
            # findings new since ``new_since``. Applied to BOTH emitted and gate
            # populations so the operator-supplied (unforgeable) ratchet scopes the gate.
            scoped: list[Finding] = []
            for f in candidates:
                if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE:
                    is_new = (f.location.path in changed_files) or (f.qualname is not None and f.qualname in affected)
                    if not is_new:
                        f = replace(
                            f,
                            suppressed=SuppressionState.BASELINED,
                            suppression_reason=f"delta: unchanged since {new_since}",
                        )
                scoped.append(f)
            return scoped

        findings = apply_delta_scope(findings)
        if gate_findings is not None:
            gate_findings = apply_delta_scope(gate_findings)

    defects = [f for f in findings if f.kind is Kind.DEFECT]
    summary = ScanSummary(
        total=len(findings),
        active=sum(1 for f in defects if f.suppressed is SuppressionState.ACTIVE),
        baselined=sum(1 for f in defects if f.suppressed is SuppressionState.BASELINED),
        waived=sum(1 for f in defects if f.suppressed is SuppressionState.WAIVED),
        judged=sum(1 for f in defects if f.suppressed is SuppressionState.JUDGED),
        unanalyzed=sum(1 for f in findings if f.rule_id in UNANALYZED_RULE_IDS),
    )
    resolved_root = root.resolve()
    return ScanResult(
        findings=findings,
        summary=summary,
        files_scanned=len(files),
        context=analyzer.last_context,
        scanned_paths=tuple(
            path.relative_to(resolved_root).as_posix() if path.is_relative_to(resolved_root) else path.as_posix()
            for path in files
        ),
        gate_findings=gate_findings,
    )


def gate_decision(result: ScanResult, fail_on: Severity | None) -> GateDecision:
    """Translate a scan into a pass/fail verdict. A trip is data, not an error."""
    if fail_on is None:
        return GateDecision(tripped=False, fail_on=None, exit_class=0)
    # None SENTINEL: evaluate the unsuppressed gate population when present (secure
    # default), else the suppressed ``findings`` (trusted ``--trust-suppressions`` /
    # a directly-constructed ScanResult with no gate_findings).
    honors_suppressions = result.gate_findings is None
    gate_population = result.findings if honors_suppressions else result.gate_findings
    assert gate_population is not None  # narrow for mypy; the sentinel branch set findings
    tripped = gate_trips(gate_population, fail_on)
    sev = fail_on.value
    evaluated = (
        "post-suppression (repository baseline/waiver/judged honored — trusted-local)"
        if honors_suppressions
        else "unsuppressed (repository baseline/waiver/judged ignored)"
    )
    reason = _gate_reason(result, fail_on, tripped=tripped, honors_suppressions=honors_suppressions)
    return GateDecision(
        tripped=tripped,
        fail_on=sev,
        exit_class=1 if tripped else 0,
        reason=reason,
        evaluated=evaluated,
    )


def baseline_migration_hint(
    result: ScanResult,
    decision: GateDecision,
    *,
    root: Path,
    new_since: str | None,
) -> str | None:
    """A LOUD one-line migration signal for the secure gate-default rollout, or None.

    Returns the hint ONLY in the exact 'my repo went red with no code change' case:
    a committed ``.weft/wardline/baseline.yaml`` exists, the gate tripped, the trip is
    driven SOLELY by baselined defects re-entering the unsuppressed population (no
    genuinely-active defect), and the operator passed neither ``--trust-suppressions``
    nor ``--new-since``. Otherwise None — a genuine active trip, a waiver/judged-only
    trip, a trusted/PR-scoped run, or no baseline file are all NOT the rollout surprise.
    """
    if not decision.tripped or decision.fail_on is None or new_since is not None:
        return None
    # --trust-suppressions honors the baseline, so there is no surprise to migrate from.
    if result.gate_findings is None:
        return None
    if not baseline_path(root).is_file():
        return None
    from wardline.core.suppression import gate_breakdown

    fail_on = Severity(decision.fail_on)
    active, _suppressed = gate_breakdown(result.findings, fail_on)
    if active:
        return None  # a real active defect tripped it — not a migration artifact
    baselined = sum(
        1
        for f in result.findings
        if f.kind is Kind.DEFECT
        and f.suppressed is SuppressionState.BASELINED
        and f.maturity is not Maturity.PREVIEW
        and severity_gates(f.severity, fail_on)
    )
    if not baselined:
        return None  # tripped by waived/judged only — different escape, not this hint
    sev = decision.fail_on
    return (
        f"migration: baseline present but not honored by default since v1.0 (secure gate default) — "
        f"{baselined} baselined {sev}+ defect(s) re-enter the gate. Pass --trust-suppressions for a "
        f"trusted local checkout or --new-since <merge-base> in CI. See UPGRADING.md."
    )


def _gate_reason(result: ScanResult, fail_on: Severity, *, tripped: bool, honors_suppressions: bool) -> str:
    """The human verdict string, counted over the ACTUAL gate population so the numbers
    are exactly what tripped it."""
    from wardline.core.suppression import gate_breakdown

    sev = fail_on.value
    if not tripped:
        return f"no {sev}+ defects in the evaluated population"
    # Under --trust-suppressions the gate IS the annotated findings (suppressions
    # honored), so only genuinely-active defects can have tripped it; never misdirect to
    # the suppression flags.
    if honors_suppressions:
        active, _ = gate_breakdown(result.findings, fail_on)
        return f"{active} active {sev}+ defect(s) at or above {sev}"
    # Secure default: classify the defects that ACTUALLY gate (the unsuppressed gate
    # population) by their state in the emitted findings. A ``--new-since`` delta scopes
    # out-of-delta defects to BASELINED in the gate population too, so they are not ACTIVE
    # here and are correctly NOT counted — the reason never inflates with scoped-out
    # findings nor points at a flag that was already supplied.
    gate_pop = result.gate_findings or []
    emitted_state = {f.fingerprint: f.suppressed for f in result.findings}
    active = 0
    suppressed = 0
    for f in gate_pop:
        if f.kind is not Kind.DEFECT or f.maturity is Maturity.PREVIEW:
            continue
        if f.suppressed is not SuppressionState.ACTIVE or not severity_gates(f.severity, fail_on):
            continue
        if emitted_state.get(f.fingerprint, SuppressionState.ACTIVE) is SuppressionState.ACTIVE:
            active += 1
        else:
            suppressed += 1
    escape = "pass --trust-suppressions (trusted checkout) or --new-since <ref> (PR)"
    if active and suppressed:
        return f"{active} active + {suppressed} suppressed {sev}+ defect(s) gate by default; {escape}"
    if suppressed:
        return f"{suppressed} suppressed {sev}+ defect(s) (baseline/waiver/judged) not cleared; {escape}"
    return f"{active} active {sev}+ defect(s) at or above {sev}"
