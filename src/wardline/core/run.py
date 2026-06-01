# src/wardline/core/run.py
"""SP8: the scan orchestration shared by the CLI and the MCP server.

This is the behaviour-preserving extraction of what used to live inline in
``cli/scan.py``. Both the CLI and the MCP server call ``run_scan`` so they are
identical by construction — same findings, same ``active`` count, same gate.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from wardline.core import config as config_mod
from wardline.core.baseline import load_baseline
from wardline.core.discovery import discover, missing_source_roots
from wardline.core.errors import ConfigError
from wardline.core.finding import (
    UNANALYZED_RULE_IDS,
    Finding,
    Kind,
    Location,
    Severity,
    SuppressionState,
)
from wardline.core.judged import load_judged
from wardline.core.suppression import apply_suppressions, gate_trips
from wardline.core.waivers import WaiverSet, parse_waivers
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.context import AnalysisContext
from wardline.scanner.taint.summary_cache import SummaryCache


def _fp(*parts: str) -> str:
    digest = hashlib.sha256()
    digest.update("\x00".join(parts).encode("utf-8"))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class ScanSummary:
    total: int  # every finding (defects + facts/metrics)
    active: int  # non-suppressed DEFECTs — the gate population
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


@dataclass(frozen=True, slots=True)
class GateDecision:
    tripped: bool
    fail_on: str | None
    exit_class: int  # 0 clean, 1 gate tripped, 2 reserved for tool errors (CLI layer)


def run_scan(
    root: Path,
    *,
    config_path: Path | None = None,
    cache_dir: Path | None = None,
    confine_to_root: bool = False,
) -> ScanResult:
    """Discover → analyze → apply suppressions. Pure function of (disk + config).

    Raises ``WardlineError`` subclasses on bad config / unreadable paths; the
    caller (CLI or MCP server) maps those to its own error channel.

    ``confine_to_root`` (default False, preserving CLI behaviour) makes
    ``discover`` reject any ``source_root`` that resolves outside ``root`` — the
    MCP server passes True so a poisoned config cannot read out-of-root source.
    """
    # An EXPLICIT --config path that doesn't exist must NOT silently fall back to
    # default policy (dropping the operator's severity overrides/excludes) — that
    # is a false-green. The IMPLICIT default (root/wardline.yaml) may legitimately
    # be absent; config_mod.load tolerates that.
    if config_path is not None and not config_path.exists():
        raise ConfigError(f"config file does not exist: {config_path}")
    cfg_path = config_path or (root / "wardline.yaml")
    cfg = config_mod.load(cfg_path)
    cache = None
    if cache_dir is not None:
        cache = SummaryCache(cache_dir=cache_dir)
        cache.load()
    files = discover(root, cfg, confine_to_root=confine_to_root)
    analyzer = WardlineAnalyzer(summary_cache=cache)
    raw = list(analyzer.analyze(files, cfg, root=root))
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
    baseline = load_baseline(root / ".wardline" / "baseline.yaml")
    waivers = WaiverSet(parse_waivers(cfg.waivers))
    judged = load_judged(root / ".wardline" / "judged.yaml")
    findings = apply_suppressions(raw, baseline, waivers, today=date.today(), judged=judged)

    defects = [f for f in findings if f.kind is Kind.DEFECT]
    summary = ScanSummary(
        total=len(findings),
        active=sum(1 for f in defects if f.suppressed is SuppressionState.ACTIVE),
        baselined=sum(1 for f in defects if f.suppressed is SuppressionState.BASELINED),
        waived=sum(1 for f in defects if f.suppressed is SuppressionState.WAIVED),
        judged=sum(1 for f in defects if f.suppressed is SuppressionState.JUDGED),
        unanalyzed=sum(1 for f in findings if f.rule_id in UNANALYZED_RULE_IDS),
    )
    return ScanResult(
        findings=findings,
        summary=summary,
        files_scanned=len(files),
        context=analyzer.last_context,
    )


def gate_decision(result: ScanResult, fail_on: Severity | None) -> GateDecision:
    """Translate a scan into a pass/fail verdict. A trip is data, not an error."""
    if fail_on is None:
        return GateDecision(tripped=False, fail_on=None, exit_class=0)
    tripped = gate_trips(result.findings, fail_on)
    return GateDecision(tripped=tripped, fail_on=fail_on.value, exit_class=1 if tripped else 0)
