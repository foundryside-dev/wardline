# src/wardline/cli/scan.py
"""`wardline scan` — SP1 wires discovery → WardlineAnalyzer → JSONL sink."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.config import resolve_clarion_url, resolve_filigree_url
from wardline.core.emit import JsonlSink
from wardline.core.errors import WardlineError
from wardline.core.filigree_emit import EmitResult, FiligreeEmitter
from wardline.core.finding import Severity
from wardline.core.run import gate_decision, run_scan
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
    help="POST findings to this Filigree Loom scan-results URL (opt-in).",
)
@click.option(
    "--clarion-url",
    "clarion_url",
    default=None,
    help="Persist per-entity taint facts to this Clarion taint-store URL (opt-in, fail-soft).",
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
    help="Allow importing this trust-grammar pack from wardline.yaml. May be repeated.",
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
    help="Ignore repository-supplied custom configuration overrides (wardline.yaml).",
)
@click.option(
    "--allow-source-root-escape",
    is_flag=True,
    default=False,
    help="Allow wardline.yaml source_roots to resolve outside PATH.",
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
def scan(
    path: Path,
    config_path: Path | None,
    fmt: str,
    output: Path | None,
    fail_on: str | None,
    fail_on_unanalyzed: bool,
    cache_dir: Path | None,
    filigree_url: str | None,
    clarion_url: str | None,
    new_since: str | None,
    trusted_packs: tuple[str, ...],
    trust_local_packs: bool,
    fix: bool,
    yes: bool,
    strict_defaults: bool,
    allow_source_root_escape: bool,
    trust_suppressions: bool,
) -> None:
    """Scan PATH for findings."""
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
    clarion_result = None
    try:
        filigree_url = resolve_filigree_url(
            filigree_url,
            path,
            config_path,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
        )
        clarion_url = resolve_clarion_url(
            clarion_url,
            path,
            config_path,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
        )
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
        )
        findings = result.findings
        if fix:
            from wardline.core.autofix import run_autofix
            from wardline.core.config import load
            from wardline.core.finding import Finding

            cfg = load(
                config_path or (path / "wardline.yaml"),
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
            from wardline.core.legis import build_legis_artifact, load_legis_artifact_key

            legis_cfg = load_cfg(
                config_path or (path / "wardline.yaml"),
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
            )
            output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        # Loom emission is additive: a FiligreeEmitError (HTTP >= 400) is a Wardline
        # payload bug -> caught below -> exit 2; an unreachable sibling warns + continues.
        if filigree_url is not None:
            emit_result = FiligreeEmitter(filigree_url).emit(findings, scanned_paths=result.scanned_paths)
        # Clarion taint-store write is fail-soft: an outage/403 returns a not-reachable
        # WriteResult (reported below); a ClarionError (missing extra, 4xx, bad scheme)
        # is a WardlineError → caught here → exit 2, exactly as Filigree errors do.
        if clarion_url is not None:
            from wardline.clarion.client import ClarionClient
            from wardline.clarion.config import load_clarion_token, resolve_project_name
            from wardline.clarion.write import write_facts_to_clarion

            client = ClarionClient(
                clarion_url,
                secret=load_clarion_token(path),
                project=resolve_project_name(path),
            )
            clarion_result = write_facts_to_clarion(result, path, client)
        if fmt == "agent-summary":
            from wardline.core.agent_summary import build_agent_summary

            decision = gate_decision(result, Severity(fail_on)) if fail_on is not None else gate_decision(result, None)
            output.write_text(
                json.dumps(
                    build_agent_summary(
                        result,
                        decision,
                        filigree_emit=_filigree_status(emit_result),
                        clarion_write=_clarion_status(clarion_result),
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
            click.echo(
                f"warning: could not reach Filigree at {filigree_url}; findings written locally only.",
                err=True,
            )
        else:
            line = (
                f"emitted {len(findings)} finding(s) to {filigree_url} — "
                f"{emit_result.created} created / {emit_result.updated} updated"
            )
            if emit_result.failed:
                line += f" / {emit_result.failed} failed"
            if emit_result.warnings:
                line += f"; {len(emit_result.warnings)} warning(s): " + "; ".join(emit_result.warnings)
            click.echo(line)
    if clarion_result is not None:
        if not clarion_result.reachable:
            reason = clarion_result.disabled_reason or "unreachable"
            click.echo(
                f"warning: Clarion taint store not written at {clarion_url} ({reason}); scan unaffected.",
                err=True,
            )
        else:
            line = f"wrote {clarion_result.written} taint fact(s) to {clarion_url}"
            if clarion_result.unresolved_qualnames:
                line += f"; {len(clarion_result.unresolved_qualnames)} qualname(s) unresolved (not indexed by Clarion)"
            click.echo(line)
    s = result.summary
    unanalyzed_segment = f"; {s.unanalyzed} file(s) could not be analyzed" if s.unanalyzed else ""
    click.echo(
        f"scanned {result.files_scanned} file(s); {s.total} finding(s) — "
        f"{s.baselined + s.waived + s.judged} suppressed "
        f"({s.baselined} baseline / {s.waived} waiver / {s.judged} judged), {s.active} new"
        f"{unanalyzed_segment} -> {output}"
    )
    # A discovered-but-not-analysed file is a silent under-scan; never hide it.
    if s.unanalyzed:
        click.echo(
            f"warning: {s.unanalyzed} file(s) were discovered but could not be analyzed "
            f"(see WLN-ENGINE-* facts in {output}).",
            err=True,
        )
    gate_tripped = fail_on is not None and gate_decision(result, Severity(fail_on)).tripped
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
        }
    return {
        "configured": True,
        "reachable": result.reachable,
        "created": result.created,
        "updated": result.updated,
        "failed": result.failed,
        "warnings": list(result.warnings),
        "disabled_reason": None if result.reachable else "filigree unreachable",
    }


def _clarion_status(result: object | None) -> dict[str, object]:
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
