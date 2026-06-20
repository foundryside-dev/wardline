# src/wardline/cli/scan.py
"""`wardline scan` — SP1 wires discovery → WardlineAnalyzer → JSONL sink."""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import IO, TYPE_CHECKING

import click

from wardline.core.artifacts import write_scan_artifact
from wardline.core.config import load as load_config
from wardline.core.config import resolve_filigree_url, resolve_loomweave_url
from wardline.core.delta_scope import (
    _MAX_PAYLOAD_BYTES,
    AffectedScope,
    parse_affected_scope_text,
)
from wardline.core.emit import JsonlSink
from wardline.core.errors import WardlineError
from wardline.core.filigree_emit import (
    EmitResult,
    FiligreeEmitter,
    filigree_destination,
    filigree_disabled_reason,
    filigree_url_project,
)
from wardline.core.finding import Severity
from wardline.core.paths import weft_config_path
from wardline.core.run import baseline_migration_hint, gate_decision, run_scan
from wardline.core.safe_paths import write_text_no_follow
from wardline.core.sarif import SarifSink, build_sarif

if TYPE_CHECKING:
    from wardline.loomweave.identity import SeiResolver


@click.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--format", "fmt", type=click.Choice(["jsonl", "sarif", "agent-summary", "legis"]), default="jsonl")
@click.option(
    "--lang",
    type=click.Choice(["python", "rust"]),
    default="python",
    help=(
        "Language frontend. 'rust' scans .rs files for RS-WL-* command-injection findings "
        "(frozen identity, baseline-eligible; config severity overrides not yet applied)."
    ),
)
@click.option("--output", type=click.Path(path_type=Path), default=None)
# exit 1 if any non-suppressed DEFECT has severity >= this threshold (SP3b)
@click.option("--fail-on", type=click.Choice(["CRITICAL", "ERROR", "WARN", "INFO"], case_sensitive=False), default=None)
# Opt-in CI enforcement: exit 1 when any file was discovered but not analysed
# (parse error / too-deep / missing source root — NOT benign no-module skips).
# Default FALSE preserves the released exit-code behaviour; the count is ALWAYS
# surfaced.
@click.option(
    "--fail-on-unanalyzed/--no-fail-on-unanalyzed",
    default=False,
    help="Exit 1 if any file was discovered but could not be analyzed.",
)
@click.option(
    "--cache-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Persist L3 summary cache here for faster incremental scans.",
)
@click.option(
    "--filigree-url",
    "filigree_url",
    default=None,
    help="POST findings to this Filigree Weft scan-results URL (opt-in).",
)
@click.option(
    "--local-only",
    "--no-emit",
    "local_only",
    is_flag=True,
    default=False,
    help=(
        "Disable sibling emission even when Filigree or Loomweave URLs resolve from flags, env, or local install state."
    ),
)
@click.option(
    "--filigree-max-findings-per-request",
    type=click.IntRange(min=1),
    default=None,
    help=(
        "Maximum Wardline findings per Filigree scan-results POST "
        "(default 1000; also configurable with WARDLINE_FILIGREE_MAX_FINDINGS_PER_REQUEST)."
    ),
)
@click.option(
    "--loomweave-url",
    "loomweave_url",
    default=None,
    help="Persist per-entity taint facts to this Loomweave taint-store URL (opt-in, fail-soft).",
)
@click.option(
    "--new-since",
    type=str,
    default=None,
    help="PR-scoped 'new findings only' gate: only gate on findings in files/entities changed since this git ref.",
)
@click.option(
    "--affected",
    "affected_file",
    type=click.File("r"),
    default=None,
    help=(
        "Scan only entities in this warpline reverify-worklist / entity-list "
        "(file path, or '-' for stdin). Advisory delta, not a gate: out-of-scope "
        "cross-file flows are not analyzed (see the scope block), so it cannot drive "
        "--fail-on (use --new-since to gate changed code, or a full scan for the gate "
        "of record). Empty/unresolvable -> full scan. Mutually exclusive with "
        "--new-since and --fail-on."
    ),
)
@click.option(
    "--trust-pack",
    "trusted_packs",
    multiple=True,
    help="Allow importing this trust-grammar pack from weft.toml [wardline]. May be repeated.",
)
@click.option(
    "--allow-custom-packs",
    "trust_local_packs",
    is_flag=True,
    default=False,
    help="Allow loading custom trust-grammar packs from the local project directory.",
)
@click.option(
    "--fix",
    is_flag=True,
    help="Apply mechanical autofixes during the scan.",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Automatically confirm all fixes when --fix is specified.",
)
@click.option(
    "--strict-defaults",
    is_flag=True,
    default=False,
    help="Ignore repository-supplied custom configuration overrides (weft.toml).",
)
@click.option(
    "--allow-source-root-escape",
    is_flag=True,
    default=False,
    help="Allow weft.toml [wardline] source_roots to resolve outside PATH.",
)
@click.option(
    "--trust-suppressions",
    is_flag=True,
    default=False,
    help=(
        "Let repository-controlled baseline/waiver/judged files clear the --fail-on gate "
        "(they always annotate findings regardless). Use ONLY for trusted local checkouts; "
        "in CI prefer the unforgeable --new-since <merge-base> ratchet. Default off: by "
        "default the gate evaluates the unsuppressed population so a PR cannot self-suppress."
    ),
)
@click.option(
    "--allow-dirty",
    is_flag=True,
    default=False,
    help=(
        "For --format legis only: on a dirty working tree, emit an UNSIGNED, clearly-marked "
        "(dirty: true) dev artifact instead of refusing. Signing stays clean-tree-only; this "
        "lets the dev/tour loop exercise the Wardline->legis handshake without a commit."
    ),
)
def scan(
    path: Path,
    config_path: Path | None,
    fmt: str,
    lang: str,
    output: Path | None,
    fail_on: str | None,
    fail_on_unanalyzed: bool,
    cache_dir: Path | None,
    filigree_url: str | None,
    local_only: bool,
    filigree_max_findings_per_request: int | None,
    loomweave_url: str | None,
    new_since: str | None,
    affected_file: IO[str] | None,
    trusted_packs: tuple[str, ...],
    trust_local_packs: bool,
    fix: bool,
    yes: bool,
    strict_defaults: bool,
    allow_source_root_escape: bool,
    trust_suppressions: bool,
    allow_dirty: bool,
) -> None:
    """Scan PATH for findings.

    PATH is the scan root and GOVERNS finding identity: qualnames and
    fingerprints are minted relative to it, and baseline/waiver/judged
    suppression state is read from PATH's .weft/wardline/. Scan the project
    root — a subdirectory scan mints qualnames other Weft tools
    (Loomweave/Filigree/dossier) will not match, misses the project's
    suppression state, and writes output into the subdirectory (wardline
    warns when it detects this).
    """
    if lang == "rust":
        # Posture banner: RS-WL-* identity is graduated (frozen, baseline-eligible) but
        # rule coverage is the command-injection slice and weft.toml severity overrides
        # do not yet apply to Rust findings (analyzer accepts config for protocol parity
        # only). Surface the remaining gaps so a green gate is read at the right scope.
        click.echo(
            "note: --lang rust covers the command-injection slice (RS-WL-108/112); "
            "config severity overrides do not yet apply to Rust findings.",
            err=True,
        )
    output_is_default = output is None
    emit_result: EmitResult | None = None
    loomweave_result = None
    try:
        if config_path is None and not strict_defaults and not weft_config_path(path).is_file():
            click.echo(
                "warning: no weft.toml found; using built-in source_roots=['.'], which can make "
                "project-root scans broad and slow. Run `wardline doctor --repair --root "
                f"{path}` to create a bounded default policy, or `wardline scan-job start {path}` "
                "for a pollable long-running scan.",
                err=True,
            )
        cfg = load_config(
            config_path or weft_config_path(path),
            explicit=config_path is not None,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
        )
        filigree_url = resolve_filigree_url(filigree_url, path, config_path, strict_defaults=strict_defaults)
        loomweave_url = resolve_loomweave_url(loomweave_url, path, config_path, strict_defaults=strict_defaults)
        if local_only:
            filigree_url = None
            loomweave_url = None
        # --affected delta scope (Phase 7): read the producer-supplied worklist / entity
        # list (a real path, or '-' for stdin — click.File resolved the stream) and parse
        # it INSIDE this try so ScopeParseError (invalid JSON / over-cap) lands on the shared
        # SystemExit(2) path (malformed scope -> exit 2, spec §7). The hand-supplied JSON is
        # untrusted; INV-4 keeps it off the gate population, so trust is moot for the verdict.
        affected: AffectedScope | None = None
        if affected_file is not None:
            # --affected is mutually exclusive with --new-since (they scope different things
            # via different mechanisms; run_scan also rejects the pair as ScopeParseError).
            # When a git-driven --since lands (Phase 12) it MUST reject against --affected here
            # too — there is no --since flag yet, so nothing to check beyond --new-since.
            if new_since is not None:
                raise WardlineError("--affected and --new-since are mutually exclusive")
            # --affected is an ADVISORY delta: it analyzes only the scoped subset, so it can
            # never authoritatively PASS a severity gate (an ERROR in an unanalyzed file
            # would go unseen — exit 0 would be an unearned green). Refuse to gate it. Use
            # --new-since for an authoritative change-scoped gate (full analysis, gates the
            # changed subset), or a full scan for the gate of record.
            if fail_on is not None:
                raise WardlineError(
                    "--affected (advisory delta) cannot drive --fail-on: a delta scan analyzes "
                    "only part of the tree, so it cannot certify a green gate. Use --new-since "
                    "<ref> to gate only changed code (full analysis), or run a full scan for the "
                    "gate of record."
                )
            # Bound the read at the byte cap BEFORE json.loads: read at most cap+1 chars
            # from the (possibly stdin) handle and reject an over-cap blob pre-parse. A
            # huge VALID JSON payload must not force a full unbounded read + parse before
            # the DoS cap fires. parse_affected_scope_text enforces the byte-accurate cap
            # and maps invalid JSON / over-cap to ScopeParseError (a WardlineError), so it
            # lands on the shared SystemExit(2) malformed-scope path (§7).
            raw = affected_file.read(_MAX_PAYLOAD_BYTES + 1)
            affected = parse_affected_scope_text(raw)
        # Inject the SEI resolver (run_scan stays network-free). Built only when a delta
        # scope is requested and a loomweave URL resolves; any loomweave error -> None
        # (fail-soft, recorded as "loomweave unavailable" in the scope block).
        sei_resolver = _build_sei_resolver(loomweave_url, path) if affected is not None else None
        result = run_scan(
            path,
            config_path=config_path,
            cache_dir=cache_dir,
            new_since=new_since,
            affected=affected,
            sei_resolver=sei_resolver,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
            confine_to_root=not allow_source_root_escape,
            trust_suppressions=trust_suppressions,
            lang=lang,
        )
        findings = result.findings
        if fix:
            from wardline.core.autofix import run_autofix
            from wardline.core.finding import Finding

            fixable = [f for f in findings if f.rule_id == "PY-WL-111"]
            if fixable:

                def confirm_cb(rel_path: str, orig: str, replacement: str, f: Finding) -> bool:
                    if yes:
                        return True
                    click.echo(f"\n[PY-WL-111] Suggesting boundary fix in {rel_path} (line {f.location.line_start}):")
                    click.echo(f"  - {click.style(orig, fg='red')}")
                    click.echo(f"  + {click.style(replacement, fg='green')}")
                    return click.confirm("Apply this fix?", default=True)

                applied = run_autofix(fixable, cfg, path, dry_run=False, confirm_cb=confirm_cb)
                if applied:
                    result = run_scan(
                        path,
                        config_path=config_path,
                        cache_dir=cache_dir,
                        new_since=new_since,
                        affected=affected,
                        sei_resolver=sei_resolver,
                        trust_local_packs=trust_local_packs,
                        trusted_packs=trusted_packs,
                        strict_defaults=strict_defaults,
                        confine_to_root=not allow_source_root_escape,
                        trust_suppressions=trust_suppressions,
                        lang=lang,
                    )
                    findings = result.findings
        # Delta-scope honesty block (--affected): threaded into every --format channel as a
        # run-level property (SARIF), a top-level key (agent-summary), and a stderr line.
        # jsonl carries findings only (unchanged), but the stderr summary still prints.
        scope_props: dict[str, object] | None = (
            {"wardline_delta_scope": result.scope.to_dict()} if result.scope is not None else None
        )
        if fmt == "sarif":
            if output_is_default:
                output = write_scan_artifact(
                    path,
                    fmt,
                    cfg,
                    json.dumps(
                        build_sarif(findings, result.context, run_properties=scope_props),
                        indent=2,
                        ensure_ascii=False,
                    ),
                )
            else:
                assert output is not None
                SarifSink(output).write(findings, result.context, run_properties=scope_props)
        elif fmt == "jsonl":
            if output_is_default:
                output = write_scan_artifact(path, fmt, cfg, "".join(f"{finding.to_jsonl()}\n" for finding in findings))
            else:
                assert output is not None
                JsonlSink(output).write(findings)
        elif fmt == "legis":
            # The signed, verbatim-postable scan for legis's POST /wardline/scan-results.
            # Signs when WARDLINE_LEGIS_ARTIFACT_KEY is provisioned (env/.env); else emits
            # unsigned provenance (legis records it unverified). A dirty/non-repo tree under
            # signing raises LegisArtifactError -> exit 2 (CLI is loud by design).
            from wardline.core.legis import (
                build_legis_artifact,
                legis_artifact_outcome,
                load_legis_artifact_key,
            )

            legis_key = load_legis_artifact_key(path)
            artifact = build_legis_artifact(
                result,
                root=path,
                config=cfg,
                key=legis_key.encode("utf-8") if legis_key else None,
                allow_dirty=allow_dirty,
            )
            artifact_json = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
            if output_is_default:
                output = write_scan_artifact(path, fmt, cfg, artifact_json)
            else:
                assert output is not None
                write_text_no_follow(output, artifact_json, label=output.name)
            # Loud signal: an artifact marked dirty is UNSIGNED (dev/tour only). legis
            # records it `unverified`; never gate CI on it. The dirty/signed status comes
            # from the shared authority; the human stderr wording stays CLI-specific.
            if legis_artifact_outcome(artifact).dirty:
                click.echo(
                    "warning: dirty working tree — emitted an UNSIGNED legis dev artifact "
                    "(dirty: true, legis records it unverified). Commit for a signed artifact.",
                    err=True,
                )
        # Weft emission is additive: scan uses the emitter's fail-soft protocol mode so
        # a Filigree reject is reported as upload failure, not as a pre-gate exit 2.
        if filigree_url is not None:
            from wardline.filigree.config import load_filigree_token

            # INV-5: a delta scan emits the FULL discovery list as scanned_paths but a
            # FILTERED findings list, so Filigree's auto mark_unseen would read every
            # out-of-scope finding as fixed and close its issue (irreversible signal loss).
            # Force mark_unseen=False in delta mode; full / full-fallback scans reconcile
            # normally (mark_unseen=None -> auto).
            delta_mode = result.scope is not None and result.scope.mode == "delta"
            emit_result = FiligreeEmitter(
                filigree_url,
                token=load_filigree_token(path),
                max_findings_per_request=filigree_max_findings_per_request,
                protocol_errors_loud=False,
            ).emit(
                findings,
                scanned_paths=result.scanned_paths,
                mark_unseen=False if delta_mode else None,
            )
        # Loomweave taint-store write is fail-soft: an outage/403 returns a not-reachable
        # WriteResult (reported below); a LoomweaveError (missing extra, 4xx, bad scheme)
        # is a WardlineError → caught here → exit 2, exactly as Filigree errors do.
        if loomweave_url is not None:
            from wardline.loomweave.client import LoomweaveClient
            from wardline.loomweave.config import load_loomweave_token, resolve_project_name
            from wardline.loomweave.write import write_facts_to_loomweave

            client = LoomweaveClient(
                loomweave_url,
                secret=load_loomweave_token(path),
                project=resolve_project_name(path),
            )
            loomweave_result = write_facts_to_loomweave(result, path, client)
        if fmt == "agent-summary":
            from wardline.core.agent_summary import build_agent_summary

            decision = gate_decision(result, Severity(fail_on)) if fail_on is not None else gate_decision(result, None)
            agent_summary_dict = build_agent_summary(
                result,
                decision,
                filigree_emit=_filigree_status(emit_result),
                loomweave_write=_loomweave_status(loomweave_result),
                migration_hint=baseline_migration_hint(result, decision, root=path, new_since=new_since),
            ).to_dict()
            # Surface the --affected delta-scope honesty block alongside the summary (the
            # same block SARIF carries in run_properties; absent for a full scan, INV-1).
            if result.scope is not None:
                agent_summary_dict["scope"] = result.scope.to_dict()
            agent_summary_json = json.dumps(agent_summary_dict, sort_keys=True) + "\n"
            if output_is_default:
                output = write_scan_artifact(path, fmt, cfg, agent_summary_json)
            else:
                # Explicit -o path: no-follow, matching the JSONL/SARIF sinks. A raw
                # write_text would follow a repo-controlled symlink at the chosen filename
                # and truncate an arbitrary user-writable target in an untrusted checkout.
                assert output is not None
                write_text_no_follow(output, agent_summary_json, label=output.name)
        assert output is not None
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    if emit_result is not None:
        if not emit_result.reachable:
            if emit_result.auth_rejected:
                # Reachable but refused — actionable, NOT "could not reach" (dogfood #5).
                # Split 401 (no/bad token → set one) from 403 (token present but lacks
                # access / blocked → setting a token won't help) so the remedy fits.
                if emit_result.status == 403:
                    click.echo(
                        f"warning: Filigree returned 403 (forbidden) at {filigree_url}; the token is "
                        "present but lacks access (scope/permission) or the request is blocked. "
                        "Findings written locally only.",
                        err=True,
                    )
                elif emit_result.token_sent:
                    # A token WAS sent and rejected — the value is wrong, not absent. Saying
                    # "set the token" here is the C-7 misdiagnosis (weft-23574069a1).
                    click.echo(
                        f"warning: Filigree rejected the token (401) at {filigree_url}; a token WAS sent but "
                        "its value is wrong — align WEFT_FEDERATION_TOKEN (env or .env) to the canonical "
                        "federation token. Findings written locally only.",
                        err=True,
                    )
                else:
                    click.echo(
                        f"warning: Filigree returned 401 (auth rejected) at {filigree_url}; no token was sent — "
                        "set WEFT_FEDERATION_TOKEN (env or .env) to the project token. Findings written locally only.",
                        err=True,
                    )
            elif emit_result.status is not None:
                click.echo(
                    f"warning: Filigree returned {emit_result.status} (server error) at {filigree_url}; "
                    "findings written locally only.",
                    err=True,
                )
            else:
                click.echo(
                    f"warning: could not reach Filigree at {filigree_url}; findings written locally only.",
                    err=True,
                )
        else:
            # N1 / C-10(a): name the destination project so a wrong-project write is visible
            # rather than reading as silent success. An unpinned URL means Filigree resolves
            # the project server-side — surface that ambiguity explicitly.
            dest_project = filigree_url_project(filigree_url)
            where = (
                f"project {dest_project!r}"
                if dest_project
                else "unscoped endpoint (URL pins no project; add ?project= to make routing explicit)"
            )
            line = (
                f"emitted {len(findings)} finding(s) to {filigree_url} [{where}] — "
                f"{emit_result.created} created / {emit_result.updated} updated"
            )
            if emit_result.failed:
                line += f" / {emit_result.failed} failed"
            if emit_result.warnings:
                line += f"; {len(emit_result.warnings)} warning(s): " + "; ".join(emit_result.warnings)
            click.echo(line)
    if loomweave_result is not None:
        logged_loomweave_url = _redact_url_for_log(loomweave_url)
        if not loomweave_result.reachable:
            reason = loomweave_result.disabled_reason or "unreachable"
            click.echo(
                f"warning: Loomweave taint store not written at {logged_loomweave_url} ({reason}); scan unaffected.",
                err=True,
            )
        else:
            line = f"wrote {loomweave_result.written} taint fact(s) to {logged_loomweave_url}"
            if loomweave_result.unresolved_qualnames:
                line += (
                    f"; {len(loomweave_result.unresolved_qualnames)} qualname(s) unresolved (not indexed by Loomweave)"
                )
            click.echo(line)
    # --affected delta-scope one-liner (stderr). Prints for EVERY --format when a scope
    # block exists; a full scan (no --affected) prints nothing new (INV-1).
    if result.scope is not None:
        sc = result.scope
        click.echo(
            f"scope: {sc.mode} ({sc.gate_authority}) — analyzed {sc.files_analyzed} of "
            f"{sc.files_discovered} discovered file(s); {sc.in_scope_findings} in-scope "
            f"finding(s); {len(sc.unresolved_entities)} entity(ies) unresolved",
            err=True,
        )
    s = result.summary
    unanalyzed_segment = f"; {s.unanalyzed} file(s) could not be analyzed" if s.unanalyzed else ""
    # "active" = non-suppressed DEFECTs in the EMITTED findings — the canonical term
    # used by SuppressionState.ACTIVE, ScanSummary.active, the MCP summary key, the
    # agent-summary active_defects, and the wardline:loop prompt. It is NOT Filigree's
    # first-seen "new" (unseen fingerprint) nor the --fail-on gate population
    # (ScanResult.gate_findings). See docs/reference/finding-lifecycle-vocabulary.md.
    click.echo(
        f"scanned {result.files_scanned} file(s); {s.total} finding(s) — "
        f"{s.baselined + s.waived + s.judged} suppressed "
        f"({s.baselined} baseline / {s.waived} waiver / {s.judged} judged), {s.active} active"
        f"{unanalyzed_segment} -> {output}"
    )
    # N-3: a scan rooted in a subdirectory of a weft project mints qualnames no
    # federated tool matches and skips the project's suppression state. The FACT
    # carries the full explanation — reuse it verbatim so CLI and MCP say the same.
    nested = next((f for f in result.findings if f.rule_id == "WLN-ENGINE-NESTED-SCAN-ROOT"), None)
    if nested is not None:
        click.echo(f"warning: {nested.message}", err=True)
    # A discovered-but-not-analysed file is a silent under-scan; never hide it.
    if s.unanalyzed:
        click.echo(
            f"warning: {s.unanalyzed} file(s) were discovered but could not be analyzed "
            f"(see WLN-ENGINE-* diagnostics in {output}).",
            err=True,
        )
    if lang == "rust":
        # Coverage posture: Rust analysis is default-clean, so a scan over a repo with no
        # @trusted markers is vacuously green. Surface the trust surface explicitly so
        # "0 active" is never mistaken for "analyzed and safe" (the anti-false-green line).
        coverage = next((f for f in result.findings if f.rule_id == "WLN-RUST-COVERAGE"), None)
        if coverage is not None:
            declared = coverage.properties["functions_declared"]
            total = coverage.properties["functions_total"]
            click.echo(f"trust surface: {declared} of {total} function(s) declared @trusted", err=True)
            if total > 0 and declared == 0:
                click.echo(
                    "warning: no function declares @trusted — the scan analyzed 0 of "
                    f"{total} function(s) for trust; a clean result here proves nothing. "
                    "Add /// @trusted(level=ASSURED) markers to your boundary functions.",
                    err=True,
                )
    # Both sub-gates (severity + opt-in unanalyzed) live in the ONE shared decision —
    # the same one the MCP scan tool serialises — so the surfaces cannot drift (A4).
    gate_dec = gate_decision(
        result,
        Severity(fail_on) if fail_on is not None else None,
        fail_on_unanalyzed=fail_on_unanalyzed,
    )
    if gate_dec.verdict == "NOT_EVALUATED":
        # A bare scan never ran the gate — say so explicitly so a clean-looking exit is not
        # mistaken for a PASS (weft-b937e53854). Carries would_trip_at via the reason.
        click.echo(f"gate: NOT_EVALUATED — {gate_dec.reason}", err=True)
    elif gate_dec.tripped:
        # Never let "0 active + gate FAILED" read as a bug: say why and which population.
        # Name only the knob(s) that actually tripped — an unanalyzed-only trip must not
        # print "--fail-on None".
        knobs = []
        if gate_dec.severity_tripped:
            knobs.append(f"--fail-on {gate_dec.fail_on}")
        if gate_dec.unanalyzed_tripped:
            knobs.append("--fail-on-unanalyzed")
        click.echo(f"gate: FAILED ({', '.join(knobs)}) — {gate_dec.reason}", err=True)
        click.echo(f"gate: evaluated {gate_dec.evaluated}", err=True)
        # The secure-gate-default rollout signal: a committed baseline that used to clear
        # the gate now re-enters it. Loud + separable from the generic reason above.
        hint = baseline_migration_hint(result, gate_dec, root=path, new_since=new_since)
        if hint is not None:
            click.echo(hint, err=True)
    elif gate_dec.fail_on is None:
        # Only the unanalyzed gate ran and it passed — keep the no-vacuous-severity-green
        # signal a NOT_EVALUATED verdict used to carry here.
        click.echo(f"gate: PASSED (--fail-on-unanalyzed only) — {gate_dec.reason}", err=True)
    if gate_dec.tripped:
        raise SystemExit(1)


def _build_sei_resolver(loomweave_url: str | None, root: Path) -> SeiResolver | None:
    """Construct a loomweave :class:`SeiResolver` for the ``--affected`` SEI path, or None.

    Built only when a loomweave URL resolved. Fail-soft (Phase 3 injection contract): any
    loomweave error — missing extra, bad scheme, unreachable, capabilities probe failure —
    yields ``None`` so a delta scan degrades to the spoofable qualname-locator path rather
    than exiting 2. ``run_scan`` records ``loomweave_used=False`` in the scope block. The
    resolver is injected so ``run_scan`` stays network-free.
    """
    if loomweave_url is None:
        return None
    try:
        from wardline.core.errors import LoomweaveError
        from wardline.loomweave.client import LoomweaveClient
        from wardline.loomweave.config import load_loomweave_token, resolve_project_name
        from wardline.loomweave.identity import SeiCapability, SeiResolver

        client = LoomweaveClient(
            loomweave_url,
            secret=load_loomweave_token(root),
            project=resolve_project_name(root),
        )
        return SeiResolver(client, SeiCapability.from_capabilities(client.capabilities()))
    except (LoomweaveError, OSError):
        return None


def _filigree_status(result: EmitResult | None) -> dict[str, object]:
    if result is None:
        return {
            "configured": False,
            "reachable": None,
            "created": 0,
            "updated": 0,
            "failed": 0,
            "failures": [],
            "warnings": [],
            "disabled_reason": "not configured",
            "destination": filigree_destination(None),
        }
    return {
        "configured": True,
        "reachable": result.reachable,
        "created": result.created,
        "updated": result.updated,
        "failed": result.failed,
        # PDR-0023: per-finding reject reasons so a partial ingest is not flattened to a count.
        "failures": [f.to_wire() for f in result.failures],
        "warnings": list(result.warnings),
        "disabled_reason": filigree_disabled_reason(
            reachable=result.reachable,
            status=result.status,
            token_sent=result.token_sent,
            url=result.url,
        ),
        # N1 / C-10(a): name where findings went so a wrong-project write is visible.
        "destination": filigree_destination(result.url),
    }


def _loomweave_status(result: object | None) -> dict[str, object]:
    if result is None:
        return {
            "configured": False,
            "reachable": None,
            "written": 0,
            "unresolved_qualnames": [],
            "disabled_reason": "not configured",
        }
    return {
        "configured": True,
        "reachable": getattr(result, "reachable", False),
        "written": getattr(result, "written", 0),
        "unresolved_qualnames": list(getattr(result, "unresolved_qualnames", ())),
        "disabled_reason": getattr(result, "disabled_reason", None),
    }


def _redact_url_for_log(url: str | None) -> str:
    if url is None:
        return "<not configured>"
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return url.split("?", 1)[0].split("#", 1)[0]
    try:
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return f"{parts.scheme}://<redacted>"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port is not None:
        host = f"{host}:{port}"
    if parts.username is not None or parts.password is not None:
        host = f"<redacted>@{host}"
    return urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", ""))
