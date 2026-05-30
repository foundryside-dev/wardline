# src/wardline/cli/judge.py
"""`wardline judge` — opt-in LLM triage of active DEFECTs (SP5).

The analyze -> suppress -> triage -> persist pipeline lives in
``core.judge_run.run_judge`` (shared with the SP8 MCP judge tool). This command
builds the real urllib-backed caller, delegates the pipeline ONCE, and formats the
human-readable report from the returned ``JudgeOutcome``.
"""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core import config as config_mod
from wardline.core.config import parse_judge_settings
from wardline.core.errors import JudgeContractError, WardlineError
from wardline.core.judge import JudgeRequest, JudgeResponse, JudgeVerdict, call_judge
from wardline.core.judge_run import (
    JudgeOutcome,
    resolve_policy_block,
    run_judge,
)
from wardline.core.judge_run import (
    load_env_key as _load_env_key,  # re-exported: tests import _load_env_key from here
)
from wardline.core.triage import TriageResult


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
        # Build the real network caller here so test monkeypatching of this module's
        # `call_judge` still intercepts, and so run_judge never takes its own default
        # (network) caller branch from the CLI.
        _load_env_key(path)
        policy_block = resolve_policy_block(path, settings)

        def _caller(req: JudgeRequest) -> JudgeResponse:
            return call_judge(req, model_id=model_id, policy_block=policy_block)

        outcome = run_judge(
            path,
            config_path=config_path,
            model=model,
            context_lines=context_lines,
            max_findings=max_findings,
            write=do_write,
            judge_caller=_caller,
        )
    except JudgeContractError as exc:
        # The model violated the response contract — the audit primitive is corrupt.
        # Distinct from a missing key / malformed config (both also exit 2).
        click.echo(f"judge contract violation (model returned an unusable response): {exc}", err=True)
        raise SystemExit(2) from exc
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    _report(outcome, floor=settings.write_confidence_floor, do_write=do_write)


def _report(outcome: JudgeOutcome, *, floor: float, do_write: bool) -> None:
    result: TriageResult = outcome.result
    wrote, held_back = outcome.wrote, outcome.held_back
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
