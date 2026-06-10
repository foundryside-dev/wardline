# src/wardline/cli/scan.py
"""`wardline scan` — SP1 wires discovery → WardlineAnalyzer → JSONL sink."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.config import resolve_filigree_url, resolve_loomweave_url
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
from wardline.core.sarif import SarifSink


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
    help="Language frontend. 'rust' (PREVIEW) scans .rs files for RS-WL-* command-injection findings.",
)
@click.option("--output", type=click.Path(path_type=Path), default=None)
# exit 1 if any non-suppressed DEFECT has severity >= this threshold (SP3b)
@click.option("--fail-on", type=click.Choice(["CRITICAL", "ERROR", "WARN", "INFO"]), default=None)
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
    loomweave_url: str | None,
    new_since: str | None,
    trusted_packs: tuple[str, ...],
    trust_local_packs: bool,
    fix: bool,
    yes: bool,
    strict_defaults: bool,
    allow_source_root_escape: bool,
    trust_suppressions: bool,
    allow_dirty: bool,
) -> None:
    """Scan PATH for findings."""
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
    if fmt == "sarif":
        default_name = "findings.sarif"
    elif fmt == "agent-summary":
        default_name = "findings.agent-summary.json"
    elif fmt == "legis":
        default_name = "scan.legis.json"
    else:
        default_name = "findings.jsonl"
    output = output if output is not None else (path / default_name)
    emit_result: EmitResult | None = None
    loomweave_result = None
    try:
        filigree_url = resolve_filigree_url(filigree_url, path, config_path, strict_defaults=strict_defaults)
        loomweave_url = resolve_loomweave_url(loomweave_url, path, config_path, strict_defaults=strict_defaults)
        result = run_scan(
            path,
            config_path=config_path,
            cache_dir=cache_dir,
            new_since=new_since,
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
            from wardline.core.config import load
            from wardline.core.finding import Finding

            cfg = load(
                config_path or weft_config_path(path),
                explicit=config_path is not None,
                trust_local_packs=trust_local_packs,
                trusted_packs=trusted_packs,
                strict_defaults=strict_defaults,
            )
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
                        trust_local_packs=trust_local_packs,
                        trusted_packs=trusted_packs,
                        strict_defaults=strict_defaults,
                        confine_to_root=not allow_source_root_escape,
                        trust_suppressions=trust_suppressions,
                        lang=lang,
                    )
                    findings = result.findings
        if fmt == "sarif":
            sarif_sink = SarifSink(output)
            sarif_sink.write(findings, result.context)
        elif fmt == "jsonl":
            jsonl_sink = JsonlSink(output)
            jsonl_sink.write(findings)
        elif fmt == "legis":
            # The signed, verbatim-postable scan for legis's POST /wardline/scan-results.
            # Signs when WARDLINE_LEGIS_ARTIFACT_KEY is provisioned (env/.env); else emits
            # unsigned provenance (legis records it unverified). A dirty/non-repo tree under
            # signing raises LegisArtifactError -> exit 2 (CLI is loud by design).
            from wardline.core.config import load as load_cfg
            from wardline.core.legis import (
                build_legis_artifact,
                legis_artifact_outcome,
                load_legis_artifact_key,
            )

            legis_cfg = load_cfg(
                config_path or weft_config_path(path),
                explicit=config_path is not None,
                trust_local_packs=trust_local_packs,
                trusted_packs=trusted_packs,
                strict_defaults=strict_defaults,
            )
            legis_key = load_legis_artifact_key(path)
            artifact = build_legis_artifact(
                result,
                root=path,
                config=legis_cfg,
                key=legis_key.encode("utf-8") if legis_key else None,
                allow_dirty=allow_dirty,
            )
            output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            # Loud signal: an artifact marked dirty is UNSIGNED (dev/tour only). legis
            # records it `unverified`; never gate CI on it. The dirty/signed status comes
            # from the shared authority; the human stderr wording stays CLI-specific.
            if legis_artifact_outcome(artifact).dirty:
                click.echo(
                    "warning: dirty working tree — emitted an UNSIGNED legis dev artifact "
                    "(dirty: true, legis records it unverified). Commit for a signed artifact.",
                    err=True,
                )
        # Weft emission is additive: a FiligreeEmitError (HTTP >= 400) is a Wardline
        # payload bug -> caught below -> exit 2; an unreachable sibling warns + continues.
        if filigree_url is not None:
            from wardline.filigree.config import load_filigree_token

            emit_result = FiligreeEmitter(filigree_url, token=load_filigree_token(path)).emit(
                findings, scanned_paths=result.scanned_paths
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
            output.write_text(
                json.dumps(
                    build_agent_summary(
                        result,
                        decision,
                        filigree_emit=_filigree_status(emit_result),
                        loomweave_write=_loomweave_status(loomweave_result),
                        migration_hint=baseline_migration_hint(result, decision, root=path, new_since=new_since),
                    ).to_dict(),
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
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
                else "server-default project (URL pins none — add ?project= to make it explicit)"
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
        if not loomweave_result.reachable:
            reason = loomweave_result.disabled_reason or "unreachable"
            click.echo(
                f"warning: Loomweave taint store not written at {loomweave_url} ({reason}); scan unaffected.",
                err=True,
            )
        else:
            line = f"wrote {loomweave_result.written} taint fact(s) to {loomweave_url}"
            if loomweave_result.unresolved_qualnames:
                line += (
                    f"; {len(loomweave_result.unresolved_qualnames)} qualname(s) unresolved (not indexed by Loomweave)"
                )
            click.echo(line)
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
    # A discovered-but-not-analysed file is a silent under-scan; never hide it.
    if s.unanalyzed:
        click.echo(
            f"warning: {s.unanalyzed} file(s) were discovered but could not be analyzed "
            f"(see WLN-ENGINE-* facts in {output}).",
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
    gate_dec = gate_decision(result, Severity(fail_on)) if fail_on is not None else gate_decision(result, None)
    gate_tripped = gate_dec.tripped
    if gate_dec.verdict == "NOT_EVALUATED":
        # A bare scan never ran the gate — say so explicitly so a clean-looking exit is not
        # mistaken for a PASS (weft-b937e53854). Carries would_trip_at via the reason.
        click.echo(f"gate: NOT_EVALUATED — {gate_dec.reason}", err=True)
    elif gate_dec.tripped:
        # Never let "0 active + gate FAILED" read as a bug: say why and which population.
        click.echo(f"gate: FAILED (--fail-on {gate_dec.fail_on}) — {gate_dec.reason}", err=True)
        click.echo(f"gate: evaluated {gate_dec.evaluated}", err=True)
        # The secure-gate-default rollout signal: a committed baseline that used to clear
        # the gate now re-enters it. Loud + separable from the generic reason above.
        hint = baseline_migration_hint(result, gate_dec, root=path, new_since=new_since)
        if hint is not None:
            click.echo(hint, err=True)
    # Independent of the severity gate: opt-in enforcement of "everything analysed".
    if gate_tripped or (fail_on_unanalyzed and s.unanalyzed):
        raise SystemExit(1)


def _filigree_status(result: EmitResult | None) -> dict[str, object]:
    if result is None:
        return {
            "configured": False,
            "reachable": None,
            "created": 0,
            "updated": 0,
            "failed": 0,
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
