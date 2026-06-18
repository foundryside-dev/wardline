# src/wardline/core/run.py
"""SP8: the scan orchestration shared by the CLI and the MCP server.

This is the behaviour-preserving extraction of what used to live inline in
``cli/scan.py``. Both the CLI and the MCP server call ``run_scan`` so they are
identical by construction — same findings, same ``active`` count, same gate.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wardline.core import config as config_mod
from wardline.core.baseline import Baseline, load_baseline
from wardline.core.delta import get_affected_entities, get_changed_files_since
from wardline.core.delta_resolve import (
    build_qualname_index,
    filter_to_affected,
    resolve_affected_scope,
)
from wardline.core.delta_scope import AffectedScope, DeltaScopeReport, ScopeParseError
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
from wardline.core.frontends import FRONTENDS
from wardline.core.judged import load_judged
from wardline.core.paths import baseline_path, enclosing_project_root, judged_path, weft_config_path
from wardline.core.protocols import Analyzer
from wardline.core.suppression import SEVERITY_ORDER, apply_suppressions, gate_trips, severity_gates
from wardline.core.waivers import WaiverSet, load_project_waivers

if TYPE_CHECKING:
    from wardline.loomweave.identity import SeiResolver
    from wardline.scanner.context import AnalysisContext


def _fp(*parts: str) -> str:
    digest = hashlib.sha256()
    digest.update("\x00".join(parts).encode("utf-8"))
    return digest.hexdigest()


def _relpath(file: Path, root: Path) -> str:
    """Repo-relative POSIX path for ``file`` — the discovery/finding-location convention.

    Matches ``ScanResult.scanned_paths`` and ``delta_resolve._relpath`` so the delta scope's
    ``resolved.files`` (which are these relpaths) line up with the discovered ``files``."""
    resolved_root = root.resolve()
    resolved_file = file.resolve()
    if resolved_file.is_relative_to(resolved_root):
        return resolved_file.relative_to(resolved_root).as_posix()
    return file.as_posix()


@dataclass(frozen=True, slots=True)
class ScanSummary:
    total: int  # every finding (defects + facts/metrics)
    active: int  # non-suppressed DEFECTs in the emitted findings (NOT the gate population —
    # the gate evaluates ScanResult.gate_findings unless --trust-suppressions)
    baselined: int
    waived: int
    judged: int
    # Every NON-DEFECT finding (facts, metrics, classifications). The defect buckets
    # above (active/baselined/waived/judged) partition the DEFECTs; this is the rest,
    # so the five together sum to ``total`` exactly (the buckets-sum-to-total invariant —
    # weft-f506e5f845). Before this bucket existed, non-defect facts/metrics were silently
    # uncounted and total != sum(buckets).
    informational: int = 0
    # Files DISCOVERED but NEVER analysed despite being analysable — a genuine
    # under-scan (parse errors, too-deep skips, missing source roots). Benign
    # no-module skips (WLN-ENGINE-NO-MODULE) are EXCLUDED — see UNANALYZED_RULE_IDS.
    # PARSE-ERROR/FILE-FAILED are gate-eligible ERROR DEFECTs (fail-closed: unscanned
    # code must not read GREEN); FILE-SKIPPED/SOURCE-ROOT-MISSING stay non-gating FACTs.
    # This is an OVERLAY counted by rule_id across both buckets, NOT a partition
    # member — it is not added into the sum-to-total identity.
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
    # Whether the gate population HONORS the repository suppressions (the
    # ``--trust-suppressions`` posture). Historically this was inferred from the
    # ``gate_findings is None`` sentinel, but a delta scan under ``--trust-suppressions``
    # must MATERIALISE a concrete gate population (the post-suppression, pre-delta-filter
    # findings) so the gate is never the delta-FILTERED display set — an attacker-
    # influenceable ``--affected`` scope must not forge a green (INV-4 / THREAT-001). That
    # materialisation breaks the ``is None`` proxy, so the posture is carried EXPLICITLY
    # here. ``None`` ⇒ derive from the legacy sentinel (``gate_findings is None``), so a
    # directly-constructed ScanResult keeps its prior meaning. Read via ``honors_suppressions``.
    gate_honors_suppressions: bool | None = None
    # The delta-scan honesty/provenance block (``--affected``), or None for a full scan
    # (so a full scan serialises no scope block — INV-1). Constructed by ``run_scan`` from
    # the resolved scope + post-filter counts when ``affected`` is supplied. Carries
    # ``files_discovered``/``files_analyzed`` and the boundary caveat — see
    # ``wardline.core.delta_scope.DeltaScopeReport``.
    scope: DeltaScopeReport | None = None

    @property
    def honors_suppressions(self) -> bool:
        """Whether the gate honors the repository suppressions (``--trust-suppressions``).

        Explicit when ``gate_honors_suppressions`` is set; otherwise derived from the legacy
        ``gate_findings is None`` sentinel so a directly-constructed ScanResult is unchanged.
        Decoupling the posture from the sentinel is what lets a delta scan materialise a
        concrete (post-suppression, pre-delta-filter) gate population without flipping the
        gate into "ignore suppressions" mode (INV-4: the gate is never the delta display set).
        """
        if self.gate_honors_suppressions is not None:
            return self.gate_honors_suppressions
        return self.gate_findings is None


_SEVERITY_VALUES: frozenset[str] = frozenset(s.value for s in Severity)


_VERDICT_VALUES: frozenset[str] = frozenset({"NOT_EVALUATED", "PASSED", "FAILED"})


@dataclass(frozen=True, slots=True)
class GateDecision:
    tripped: bool
    fail_on: str | None
    exit_class: int  # 0 clean, 1 gate tripped, 2 reserved for tool errors (CLI layer)
    # An explicit verdict so a bare scan (no --fail-on) never reads as a clean PASS: a
    # vacuous green is the worst false signal for a governance suite (weft-b937e53854).
    #   NOT_EVALUATED — no threshold ran (fail_on is None); the gate did not judge.
    #   PASSED        — a threshold ran and nothing tripped.
    #   FAILED        — a threshold ran and tripped.
    verdict: str
    # A human-readable verdict so "summary.active:0 + gate.tripped:true" never reads as
    # a bug: ``reason`` names the count and class of defects that decided it (and, for
    # NOT_EVALUATED, what WOULD trip); ``evaluated`` names the population it judged
    # (unsuppressed by default vs honored under --trust-suppressions). ``would_trip_at`` is
    # the highest severity at which the gate WOULD trip on that population (None if nothing
    # would), computed in every branch so a bare scan still tells the agent the worst it found.
    reason: str | None = None
    evaluated: str | None = None
    would_trip_at: str | None = None
    # The unanalyzed sub-gate (A4, wardline-7fd0f3a82c). ``fail_on_unanalyzed`` is the knob
    # state; the two ``*_tripped`` flags decompose ``tripped`` so consumers (CLI echo, MCP
    # next_actions) can attribute a trip to its sub-gate without parsing ``reason``. The
    # decomposition lives IN the decision — not as a surface-level exit-code OR — so the
    # MCP gate block (which has no exit code) can express the unanalyzed gate at all.
    fail_on_unanalyzed: bool = False
    severity_tripped: bool = False
    unanalyzed_tripped: bool = False

    def __post_init__(self) -> None:
        # Enforce the invariants the ``gate_decision`` factory upholds so a *second*
        # constructor cannot reintroduce dogfood #2 (a tripped gate that reads as passed).
        # exit_class mirrors tripped (0/1); the reserved 2 is a CLI SystemExit, never a
        # GateDecision value.
        if self.exit_class != (1 if self.tripped else 0):
            raise ValueError(f"exit_class {self.exit_class} contradicts tripped={self.tripped}")
        if self.verdict not in _VERDICT_VALUES:
            raise ValueError(f"verdict {self.verdict!r} is not one of {sorted(_VERDICT_VALUES)}")
        # The verdict is keyed to the gate state — these guards are what stop a tripped gate
        # from ever serialising as a pass (the dogfood #2 regression). The gate is evaluated
        # when EITHER sub-gate is configured (a severity threshold or the unanalyzed knob).
        if (self.verdict == "NOT_EVALUATED") != (self.fail_on is None and not self.fail_on_unanalyzed):
            raise ValueError("verdict NOT_EVALUATED iff neither --fail-on nor --fail-on-unanalyzed is set")
        if (self.verdict == "FAILED") != self.tripped:
            raise ValueError("verdict FAILED iff the gate tripped")
        # Every decision carries its reason now — including NOT_EVALUATED (what would trip).
        if self.reason is None:
            raise ValueError("a gate decision must always carry a reason")
        # fail_on is always a Severity value (the factory passes Severity.value); an
        # arbitrary string satisfies the guards above but is still an illegal state.
        if self.fail_on is not None and self.fail_on not in _SEVERITY_VALUES:
            raise ValueError(f"fail_on {self.fail_on!r} is not a valid Severity value")
        if self.would_trip_at is not None and self.would_trip_at not in _SEVERITY_VALUES:
            raise ValueError(f"would_trip_at {self.would_trip_at!r} is not a valid Severity value")
        # The sub-trip decomposition must EXPLAIN the overall trip — an overall trip no
        # sub-gate accounts for (or a sub-trip without its knob) is an illegal state.
        if self.tripped != (self.severity_tripped or self.unanalyzed_tripped):
            raise ValueError("tripped must equal (severity_tripped or unanalyzed_tripped)")
        if self.severity_tripped and self.fail_on is None:
            raise ValueError("severity_tripped requires a fail_on threshold")
        if self.unanalyzed_tripped and not self.fail_on_unanalyzed:
            raise ValueError("unanalyzed_tripped requires fail_on_unanalyzed")


def run_scan(
    root: Path,
    *,
    config_path: Path | None = None,
    cache_dir: Path | None = None,
    confine_to_root: bool = True,
    new_since: str | None = None,
    affected: AffectedScope | None = None,
    sei_resolver: SeiResolver | None = None,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    strict_defaults: bool = False,
    trust_suppressions: bool = False,
    skip_suppression: bool = False,
    lang: str = "python",
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
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

    ``affected`` (default None) is the ``--affected`` delta scope: a parsed, producer-
    supplied :class:`~wardline.core.delta_scope.AffectedScope`. When None the path is the
    byte-identical full scan (INV-1 — no qualname index is built, no resolver is probed).
    When supplied, discovery still walks the whole tree but only the files containing an
    affected entity (caller-closure-expanded) reach the analyzer, and the EMITTED findings
    are narrowed to those entities. The severity gate still evaluates the FULL unsuppressed
    population (``gate_findings`` is NEVER narrowed — INV-4 / THREAT-001), so an attacker-
    influenceable scope cannot forge a green. An empty/all-unresolvable scope falls back to
    a full scan (fail-closed honesty, INV-3). Mutually exclusive with ``new_since``
    (composing them is a ``ScopeParseError``). The ``scope`` block on the result records the
    mode/counts/caveat.

    ``sei_resolver`` (default None) is the loomweave SEI resolver, INJECTED by the caller
    (CLI/MCP) — ``run_scan`` never constructs one, so it stays network-free. Used only to
    resolve an affected entity's SEI to a current locator; absent/unavailable resolvers
    degrade to the qualname-locator fallback.

    ``lang`` (default ``"python"``) selects the language frontend: ``"python"`` is the
    released path (byte-identical to before this parameter existed); ``"rust"`` routes
    ``.rs`` discovery to the preview ``RustAnalyzer``. Any other value is a ``ConfigError``.
    """
    if affected is not None and new_since is not None:
        # --affected and --new-since scope different things via different mechanisms
        # (discovery/analysis pre-filter vs. operator-supplied gate ratchet); composing
        # them is rejected loudly, never silently double-scoped.
        raise ScopeParseError("--affected and --new-since are mutually exclusive")
    if lang not in FRONTENDS:
        known = ", ".join(f"'{k}'" for k in sorted(FRONTENDS))
        raise ConfigError(f"unknown language {lang!r}; expected one of {known}")
    frontend = FRONTENDS[lang]
    suffixes = frontend.suffixes
    from wardline.scanner.taint.summary_cache import SummaryCache, summary_cache_auth_secret_from_env

    # An EXPLICIT --config path must NOT silently fall back to default policy
    # (dropping the operator's severity overrides/excludes) whether it is missing
    # OR present-but-malformed — either way that is a false-green. The IMPLICIT
    # default (root/weft.toml) may legitimately be absent and tolerates a broken
    # shared file with a warning; config_mod.load enforces both via ``explicit``.
    cfg_path = config_path or weft_config_path(root)
    cfg = config_mod.load(
        cfg_path,
        explicit=config_path is not None,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    cache = None
    if cache_dir is not None:
        cache = SummaryCache(cache_dir=cache_dir, cache_auth_secret=summary_cache_auth_secret_from_env())
        from wardline.core.taints import _PROVENANCE_CLASH

        token_clash = _PROVENANCE_CLASH.set(cfg.provenance_clash)
        try:
            cache.load()
        finally:
            _PROVENANCE_CLASH.reset(token_clash)
    import warnings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        files = discover(root, cfg, confine_to_root=confine_to_root, suffixes=suffixes)
        captured_warnings = list(w)
    if progress_callback is not None:
        progress_callback({"phase": "discovered", "files_discovered": len(files)})
    for warn in captured_warnings:
        msg = str(warn.message)
        if not msg.startswith("WLN-ENGINE-FILE-SKIPPED: "):
            warnings.warn_explicit(
                warn.message,
                warn.category,
                warn.filename,
                warn.lineno,
            )
    analyzer: Analyzer = frontend.build_analyzer(config=cfg, summary_cache=cache)
    # Delta scoping (--affected) lives BETWEEN discovery and analysis. When ``affected``
    # is None this whole block is short-circuited (INV-1): no qualname index is built and
    # no SEI resolver is probed, so the full-scan path pays zero delta cost. When supplied,
    # the engine analyzes only the files containing an affected entity (caller-closure-
    # expanded). Each scoped file is still analyzed in FULL (whole-module context), so the
    # only soundness gap is the declared inter-file one (spec §5.3a). Fail-closed: an empty
    # resolution → analyze EVERYTHING (full-fallback, INV-3).
    scope_mode: str | None = None
    affected_qualnames: frozenset[str] = frozenset()
    affected_files: frozenset[str] = frozenset()
    entities_requested = 0
    fell_back_count = 0
    stale_sei_count = 0
    unresolved_entities: tuple[dict[str, str | None], ...] = ()
    loomweave_used = False
    analyze_files = files
    if affected is not None:
        entities_requested = affected.item_count
        index = build_qualname_index(files, root)
        resolved = resolve_affected_scope(affected, index=index, sei_resolver=sei_resolver)
        fell_back_count = len(resolved.fell_back)
        stale_sei_count = len(resolved.stale_sei)
        loomweave_used = resolved.loomweave_used
        unresolved_entities = tuple({"locator": e.locator, "sei": e.sei} for e in resolved.unresolved)
        if resolved.files:
            scope_mode = "delta"
            affected_qualnames = resolved.affected_qualnames
            affected_files = resolved.files
            analyze_files = [f for f in files if _relpath(f, root) in resolved.files]
        else:
            # Fail-closed: zero files resolved (empty / all-unresolvable / loomweave-absent
            # + qualname-miss) → run the FULL analysis, declared as full-fallback (INV-3).
            scope_mode = "full-fallback"
    if progress_callback is not None:
        if scope_mode == "delta":
            progress_callback(
                {
                    "phase": "analyzing",
                    "files_discovered": len(files),
                    "files_analyzed": len(analyze_files),
                }
            )
        else:
            progress_callback({"phase": "analyzing", "files_discovered": len(files)})
    raw = list(analyzer.analyze(analyze_files, cfg, root=root))
    if progress_callback is not None:
        progress_callback(
            {
                "phase": "analyzed",
                "files_discovered": len(files),
                "files_analyzed": len(analyze_files),
                "findings": len(raw),
            }
        )
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
    # N-3 (wardline-8669de3576): the scan root GOVERNS finding identity — qualnames
    # are minted relative to it, suppression state is read beneath it, and output
    # defaults under it. A scan rooted in a SUBDIRECTORY of a weft project silently
    # mints qualnames no federated tool (Loomweave/Filigree/dossier) matches and
    # skips the project baseline. Surface it as a FACT so it reaches the CLI
    # warning, the MCP result, and findings.jsonl alike. Not an under-scan (every
    # discovered file WAS analysed), so it never counts toward unanalyzed.
    enclosing = enclosing_project_root(root)
    if enclosing is not None:
        rel = root.resolve().relative_to(enclosing)
        prefix_parts = rel.parts[1:] if rel.parts and rel.parts[0] == "src" else rel.parts
        # module_dotted_name strips one leading src/ component, so scanning P/src
        # mints the SAME qualnames as scanning P — the prefix is empty there and
        # the message must not claim a phantom 'src.' prefix.
        qualname_prefix = ".".join(prefix_parts)
        qualname_clause = (
            f"qualnames are minted relative to the scan root (missing the '{qualname_prefix}.' "
            "package prefix other Weft tools expect), "
            if qualname_prefix
            else "qualnames are minted relative to the scan root, "
        )
        raw.append(
            Finding(
                rule_id="WLN-ENGINE-NESTED-SCAN-ROOT",
                message=(
                    f"scan root '{rel.as_posix()}' is a subdirectory of the weft project at "
                    f"{enclosing}: {qualname_clause}the project's baseline/waivers/judged state "
                    "is not loaded, and output defaults under the subdirectory. Scan the project "
                    "root for federation-stable results."
                ),
                severity=Severity.NONE,
                kind=Kind.FACT,
                location=Location(path=rel.as_posix()),
                fingerprint=_fp("WLN-ENGINE-NESTED-SCAN-ROOT", rel.as_posix()),
                properties={
                    "scan_root": str(root.resolve()),
                    "project_root": str(enclosing),
                    "qualname_prefix": qualname_prefix,
                },
            )
        )
    if cache is not None:
        cache.save()
    today = date.today()
    gate_findings: list[Finding] | None
    if skip_suppression:
        # `wardline rekey` (P4) scans a project whose stores are still OLD-scheme;
        # loading them would (correctly) SCHEME_MISMATCH. Skip the store files entirely
        # and apply EMPTY suppression — the structural transforms (esp. the lineless-
        # DEFECT→FACT downgrade) STILL run, so the result is exactly the join population
        # the stores hold, derived without reading the stores it is about to migrate.
        findings = apply_suppressions(raw, Baseline(frozenset()), WaiverSet([]), today=today, judged=None)
        gate_findings = None
    else:
        baseline = load_baseline(baseline_path(root))
        waivers = WaiverSet(load_project_waivers(root))
        judged = load_judged(judged_path(root))
        # The emitted findings ALWAYS carry the full suppression annotations (baseline,
        # waiver, judged) so ``suppressed=…`` is visible in output regardless of trust.
        findings = apply_suppressions(raw, baseline, waivers, today=today, judged=judged)
        # The gate population applies ZERO suppression but runs the SAME structural
        # transforms apply_suppressions does (esp. the lineless-DEFECT→non-gating-FACT
        # downgrade), so the only difference vs ``findings`` is the suppression sources —
        # NOT ``list(raw)``, which would let a lineless DEFECT trip the gate. When the
        # operator trusts repo suppressions, gate_findings is None and the gate falls back
        # to the suppressed ``findings`` (None SENTINEL, never an accidental falsy-empty).
        if trust_suppressions:
            gate_findings = None
        else:
            gate_findings = apply_suppressions(raw, Baseline(frozenset()), WaiverSet([]), today=today, judged=None)

    if new_since is not None:
        changed_files = get_changed_files_since(new_since, root)
        context = analyzer.last_context
        if context is not None:
            new_since_affected = get_affected_entities(changed_files, context.entities, context.project_edges)
        else:
            new_since_affected = set()

        def apply_delta_scope(candidates: list[Finding]) -> list[Finding]:
            # Suppress any ACTIVE defect outside the delta so the gate only fires on
            # findings new since ``new_since``. Applied to BOTH emitted and gate
            # populations so the operator-supplied (unforgeable) ratchet scopes the gate.
            scoped: list[Finding] = []
            for f in candidates:
                if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE:
                    is_new = (f.location.path in changed_files) or (
                        f.qualname is not None and f.qualname in new_since_affected
                    )
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

    # The gate posture is carried EXPLICITLY (not inferred from ``gate_findings is None``)
    # so delta mode can materialise a concrete gate population without flipping the gate
    # into "ignore suppressions" mode. ``None`` here ⇒ ScanResult derives the legacy
    # sentinel meaning, preserving the full-scan path byte-for-byte (INV-1).
    gate_honors_suppressions: bool | None = None

    # --affected finding filter: narrow the EMITTED findings to the affected entities only
    # in delta mode (NOT full-fallback). The gate population is NEVER the delta-FILTERED
    # display set — an attacker-influenceable ``--affected`` scope must not forge a green
    # (INV-4 / THREAT-001).
    #
    # Secure default (trust_suppressions off): ``gate_findings`` already holds the full
    # UNSUPPRESSED analyzed population, unfiltered — leave it untouched.
    #
    # ``--trust-suppressions`` on (``gate_findings is None`` by design): the gate would
    # otherwise FALL BACK to ``result.findings`` — which is about to be delta-filtered, so
    # a surgical-exclusion worklist could hide an in-analyzed-file ERROR from the gate.
    # MATERIALISE the gate population HERE as the post-suppression / pre-delta-filter
    # snapshot, and record that the posture still honors suppressions. Only the DISPLAYED
    # ``findings`` then get the delta filter.
    if scope_mode == "delta":
        if trust_suppressions and gate_findings is None:
            gate_findings = list(findings)
            gate_honors_suppressions = True
        findings = filter_to_affected(findings, affected_qualnames, affected_files)

    defects = [f for f in findings if f.kind is Kind.DEFECT]
    summary = ScanSummary(
        total=len(findings),
        active=sum(1 for f in defects if f.suppressed is SuppressionState.ACTIVE),
        baselined=sum(1 for f in defects if f.suppressed is SuppressionState.BASELINED),
        waived=sum(1 for f in defects if f.suppressed is SuppressionState.WAIVED),
        judged=sum(1 for f in defects if f.suppressed is SuppressionState.JUDGED),
        informational=len(findings) - len(defects),
        unanalyzed=sum(1 for f in findings if f.rule_id in UNANALYZED_RULE_IDS),
    )
    # The delta scope honesty block (spec §5.4), attached only when --affected was supplied.
    # ``gate_authority`` is the machine-readable companion: a delta scan is ADVISORY (the
    # gate still runs over the full population, but a delta pass is type-distinguishable from
    # a full pass), a full-fallback is the gate-of-record.
    scope: DeltaScopeReport | None = None
    if scope_mode is not None:
        scope = DeltaScopeReport(
            mode=scope_mode,
            gate_authority="advisory" if scope_mode == "delta" else "gate-of-record",
            entities_requested=entities_requested,
            files_discovered=len(files),
            files_analyzed=len(analyze_files),
            in_scope_findings=len(findings),
            fell_back_count=fell_back_count,
            stale_sei_count=stale_sei_count,
            unresolved_entities=unresolved_entities,
            loomweave_used=loomweave_used,
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
        gate_honors_suppressions=gate_honors_suppressions,
        scope=scope,
    )


def _would_trip_at(gate_population: list[Finding]) -> str | None:
    """The HIGHEST severity at which the gate would trip on this population, or None.

    ``gate_trips`` is monotonic in the threshold (a lower threshold catches a superset), so
    the highest tripping threshold equals the max severity of any active gating defect — the
    single most useful "set --fail-on X to catch the worst thing here" signal.
    """
    for sev in reversed(SEVERITY_ORDER):  # CRITICAL → ERROR → WARN → INFO
        if gate_trips(gate_population, sev):
            return sev.value
    return None


def _not_evaluated_reason(would_trip_at: str | None, evaluated: str, *, gate: str = "gate") -> str:
    base = f"no --fail-on threshold set; {gate} did not evaluate"
    if would_trip_at is None:
        return f"{base}. No active defect would trip at any threshold; evaluated {evaluated}"
    return (
        f"{base}. would_trip_at {would_trip_at} — pass --fail-on {would_trip_at} (or lower) to "
        f"enforce; evaluated {evaluated}"
    )


def gate_decision(result: ScanResult, fail_on: Severity | None, *, fail_on_unanalyzed: bool = False) -> GateDecision:
    """Translate a scan into a pass/fail verdict. A trip is data, not an error.

    Two independent sub-gates compose into one decision: the severity gate (``fail_on``)
    and the unanalyzed gate (``fail_on_unanalyzed`` — trips when any file was discovered
    but never analysed; benign no-module skips excluded, see ``ScanSummary.unanalyzed``).
    Folding the unanalyzed gate in HERE (A4, wardline-7fd0f3a82c) is what lets both
    surfaces share it: the CLI exits on ``tripped`` and the MCP gate block serialises the
    same decision, so neither can drift.
    """
    # Population selection is DECOUPLED from the suppression posture: the gate ALWAYS
    # evaluates ``gate_findings`` when present, falling back to ``findings`` only when it is
    # the legacy ``None`` sentinel (a full ``--trust-suppressions`` scan or a directly-
    # constructed ScanResult). A delta ``--trust-suppressions`` scan MATERIALISES a concrete
    # ``gate_findings`` (post-suppression, pre-delta-filter) so the gate is never the delta-
    # FILTERED display set — an attacker-influenceable scope cannot forge a green (INV-4).
    # ``honors_suppressions`` (the explicit posture, NOT the sentinel) only labels the
    # ``evaluated`` string. Selection is LIFTED above the no-threshold branch so even a bare
    # scan computes would_trip_at over the SAME population an actual --fail-on would judge.
    honors_suppressions = result.honors_suppressions
    gate_population = result.findings if result.gate_findings is None else result.gate_findings
    assert gate_population is not None  # narrow for mypy; the sentinel branch set findings
    would_trip_at = _would_trip_at(gate_population)
    evaluated = (
        "post-suppression (repository baseline/waiver/judged honored — trusted-local)"
        if honors_suppressions
        else "unsuppressed (repository baseline/waiver/judged ignored)"
    )
    if fail_on is None and not fail_on_unanalyzed:
        # NOT a clean pass — the gate never ran. The verdict says so; would_trip_at names the
        # worst severity present so the agent's first bare scan is not a false green.
        return GateDecision(
            tripped=False,
            fail_on=None,
            exit_class=0,
            verdict="NOT_EVALUATED",
            reason=_not_evaluated_reason(would_trip_at, evaluated),
            evaluated=evaluated,
            would_trip_at=would_trip_at,
        )
    severity_tripped = fail_on is not None and gate_trips(gate_population, fail_on)
    unanalyzed_tripped = bool(fail_on_unanalyzed and result.summary.unanalyzed)
    tripped = severity_tripped or unanalyzed_tripped
    if fail_on is not None:
        reason = _gate_reason(result, fail_on, tripped=severity_tripped, honors_suppressions=honors_suppressions)
    else:
        # Unanalyzed-only gate: the unanalyzed sub-gate evaluated but the severity gate
        # never ran — the reason must say so, or a PASSED here is a vacuous severity green.
        reason = _not_evaluated_reason(would_trip_at, evaluated, gate="the severity gate")
    if fail_on_unanalyzed:
        n = result.summary.unanalyzed
        prefix = (
            f"{n} file(s) discovered but not analyzed (fail_on_unanalyzed tripped)"
            if unanalyzed_tripped
            else "0 files unanalyzed (fail_on_unanalyzed passed)"
        )
        reason = f"{prefix}; {reason}"
    return GateDecision(
        tripped=tripped,
        fail_on=fail_on.value if fail_on is not None else None,
        exit_class=1 if tripped else 0,
        verdict="FAILED" if tripped else "PASSED",
        reason=reason,
        evaluated=evaluated,
        would_trip_at=would_trip_at,
        fail_on_unanalyzed=fail_on_unanalyzed,
        severity_tripped=severity_tripped,
        unanalyzed_tripped=unanalyzed_tripped,
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
    # Use the explicit posture, NOT the ``gate_findings is None`` sentinel: a delta
    # --trust-suppressions scan materialises a concrete gate population but still honors
    # suppressions, so it must be treated identically to a full trusted run here.
    if result.honors_suppressions:
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
    # the suppression flags. Count over the GATE population, not the emitted ``findings``:
    # a delta scan materialises a concrete (post-suppression, pre-delta-filter) gate
    # population while ``findings`` is the narrowed display set — counting the display set
    # would understate the trip. For a full scan ``gate_findings`` is the ``None`` sentinel,
    # so this falls back to ``findings`` and is byte-identical to before.
    if honors_suppressions:
        honored_pop = result.gate_findings if result.gate_findings is not None else result.findings
        active, _ = gate_breakdown(honored_pop, fail_on)
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
