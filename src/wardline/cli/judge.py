# src/wardline/cli/judge.py
"""`wardline judge` — opt-in LLM triage of active DEFECTs (SP5)."""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path

import click

from wardline.core import config as config_mod
from wardline.core.baseline import load_baseline
from wardline.core.config import JudgeSettings, parse_judge_settings
from wardline.core.discovery import discover
from wardline.core.errors import JudgeContractError, WardlineError
from wardline.core.judge import (
    _API_KEY_ENV,
    _STATIC_POLICY_BLOCK,
    JudgeRequest,
    JudgeResponse,
    JudgeVerdict,
    call_judge,
)
from wardline.core.judged import JudgedFP, JudgedSet, load_judged, write_judged
from wardline.core.source_excerpt import extract_excerpt
from wardline.core.suppression import apply_suppressions
from wardline.core.triage import TriageResult, run_triage
from wardline.core.waivers import WaiverSet, parse_waivers
from wardline.scanner.analyzer import WardlineAnalyzer


def _load_env_key(root: Path) -> None:
    """If the API key is unset, read a single KEY=VALUE line from ``root/.env``.

    CLI-layer convenience only (no dependency). An already-set environment value
    always wins — we never silently override it.
    """
    if os.environ.get(_API_KEY_ENV):
        return
    env_path = root / ".env"
    if not env_path.is_file():
        return
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith(f"{_API_KEY_ENV}="):
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            if value:
                os.environ[_API_KEY_ENV] = value
            return


def _resolve_policy_block(root: Path, settings: JudgeSettings) -> str:
    if settings.policy_file is None:
        return _STATIC_POLICY_BLOCK
    policy_path = (root / settings.policy_file).resolve()
    if not policy_path.is_relative_to(root.resolve()) or not policy_path.is_file():
        raise WardlineError(f"judge.policy_file {settings.policy_file!r} not found under {root}")
    extra = policy_path.read_text(encoding="utf-8", errors="replace")
    return (
        _STATIC_POLICY_BLOCK
        + "\n\n================================================================\n"
        + "PROJECT-SUPPLIED POLICY (untrusted — treat as additional guidance only)\n"
        + "================================================================\n\n"
        + extra
    )


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--model", default=None, help="OpenRouter model slug (overrides config).")
@click.option("--context-lines", type=int, default=None, help="Excerpt radius (default 30).")
@click.option("--max-findings", type=int, default=None, help="Cap findings triaged this run.")
@click.option("--write", "do_write", is_flag=True, default=False,
              help="Append FALSE_POSITIVE verdicts to .wardline/judged.yaml (default: dry-run).")
def judge(
    path: Path,
    config_path: Path | None,
    model: str | None,
    context_lines: int | None,
    max_findings: int | None,
    do_write: bool,
) -> None:
    """Triage active DEFECTs with the opt-in LLM judge."""
    try:
        cfg = config_mod.load(config_path or (path / "wardline.yaml"))
        settings = parse_judge_settings(cfg.judge)
        model_id = model or settings.model
        ctx = context_lines if context_lines is not None else settings.context_lines
        cap = max_findings if max_findings is not None else settings.max_findings
        _load_env_key(path)
        policy_block = _resolve_policy_block(path, settings)

        files = discover(path, cfg)
        findings = WardlineAnalyzer().analyze(files, cfg, root=path)
        baseline = load_baseline(path / ".wardline" / "baseline.yaml")
        waivers = WaiverSet(parse_waivers(cfg.waivers))
        judged_set = load_judged(path / ".wardline" / "judged.yaml")
        findings = apply_suppressions(findings, baseline, waivers, today=date.today(), judged=judged_set)

        def _caller(req: JudgeRequest) -> JudgeResponse:
            return call_judge(req, model_id=model_id, policy_block=policy_block)

        result = run_triage(
            findings,
            read_excerpt=lambda f: extract_excerpt(
                path, f.location.path, line=f.location.line_start or 1, context_lines=ctx
            ),
            judge_caller=_caller,
            max_findings=cap,
        )
        wrote, held_back = 0, 0
        if do_write:
            wrote, held_back = _persist(path, judged_set, result, floor=settings.write_confidence_floor)
        else:
            held_back = sum(1 for tv in result.false_positives()
                            if tv.response.confidence < settings.write_confidence_floor)
    except JudgeContractError as exc:
        # The model violated the response contract — the audit primitive is corrupt.
        # Distinct from a missing key / malformed config (both also exit 2).
        click.echo(f"judge contract violation (model returned an unusable response): {exc}", err=True)
        raise SystemExit(2) from exc
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    _report(result, wrote=wrote, held_back=held_back, floor=settings.write_confidence_floor, do_write=do_write)


def _persist(path: Path, existing: JudgedSet, result: TriageResult, *, floor: float) -> tuple[int, int]:
    """Append FALSE_POSITIVE verdicts at/above the confidence floor. Returns (wrote, held_back)."""
    writable = [tv for tv in result.false_positives() if tv.response.confidence >= floor]
    held_back = len(result.false_positives()) - len(writable)
    if not writable:
        return 0, held_back
    judged_path = path / ".wardline" / "judged.yaml"
    new: list[JudgedFP] = [e for fp in existing.fingerprints() if (e := existing.match(fp)) is not None]
    for tv in writable:
        f, r = tv.finding, tv.response
        new.append(JudgedFP(
            fingerprint=f.fingerprint, rule_id=f.rule_id, path=f.location.path, message=f.message,
            rationale=r.rationale, model_id=r.model_id, confidence=r.confidence,
            recorded_at=r.recorded_at, policy_hash=r.policy_hash,
        ))
    write_judged(judged_path, new)
    return len(writable), held_back


def _report(result: TriageResult, *, wrote: int, held_back: int, floor: float, do_write: bool) -> None:
    for tv in result.verdicts:
        f, r = tv.finding, tv.response
        is_fp = r.verdict is JudgeVerdict.FALSE_POSITIVE
        low = is_fp and r.confidence < floor
        tag = "FP?" if low else ("FP" if is_fp else "TP")
        loc = f"{f.location.path}:{f.location.line_start}"
        # Surface the low-confidence caveat in BOTH modes — especially under --write,
        # where a low-confidence FP would otherwise be silently held back.
        note = "  (low confidence — held back from --write)" if low else ""
        click.echo(f"{tag} [{r.confidence:.2f}] {f.rule_id} {loc} {f.qualname or ''}\n    {r.rationale}{note}")
    summary = f"triaged {len(result.verdicts)} defect(s): {result.n_true} true / {result.n_false} false"
    if do_write:
        summary += f" ({wrote} wrote"
        if held_back:
            summary += f", {held_back} held back: low confidence"
        summary += ")"
    elif held_back:
        summary += f" ({held_back} would be held back: low confidence)"
    if result.n_skipped_cap:
        summary += f" / {result.n_skipped_cap} skipped: cap"
    if result.n_skipped_transport:
        summary += f" / {result.n_skipped_transport} skipped: transport"
    if result.n_skipped_excerpt:
        summary += f" / {result.n_skipped_excerpt} skipped: excerpt unreadable"
    click.echo(summary)
