# src/wardline/cli/judge.py
"""`wardline judge` — opt-in LLM triage of active DEFECTs (SP5).

The analyze -> suppress -> triage -> persist pipeline lives in
``core.judge_run.run_judge`` (shared with the SP8 MCP judge tool). This command is
a thin option-and-report adapter around that single provider-selection boundary.
"""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core.confinement import SourceRootConfinement
from wardline.core.errors import JudgeContractError, WardlineError
from wardline.core.judge import JudgeVerdict
from wardline.core.judge_run import JudgeOutcome, run_judge
from wardline.core.judge_types import JudgeTransport
from wardline.core.triage import TriageResult


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--transport",
    type=click.Choice([item.value for item in JudgeTransport], case_sensitive=True),
    default=None,
    help="Judge transport: auto, codex-cli, or openrouter (default auto).",
)
@click.option("--model", default=None, help="OpenRouter model slug (overrides config).")
@click.option("--codex-model", default=None, help="Codex CLI model id (overrides config).")
@click.option("--context-lines", type=int, default=None, help="Excerpt radius (default 30).")
@click.option("--max-findings", type=int, default=None, help="Cap findings triaged this run.")
@click.option(
    "--write",
    "do_write",
    is_flag=True,
    default=False,
    help="Append FALSE_POSITIVE verdicts to .weft/wardline/judged.yaml (default: dry-run).",
)
@click.option(
    "--trust-judge-policy",
    is_flag=True,
    default=False,
    help="Allow loading judge.policy_file from the scanned project as untrusted judge context.",
)
@click.option(
    "--trust-judge-config",
    is_flag=True,
    default=False,
    help="Allow project judge config to select transport, both models, context, cap, and write confidence floor.",
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
    "--strict-defaults",
    is_flag=True,
    default=False,
    help="Ignore repository-supplied custom configuration overrides (weft.toml).",
)
def judge(
    path: Path,
    config_path: Path | None,
    transport: str | None,
    model: str | None,
    codex_model: str | None,
    context_lines: int | None,
    max_findings: int | None,
    do_write: bool,
    trust_judge_policy: bool,
    trust_judge_config: bool,
    trusted_packs: tuple[str, ...],
    trust_local_packs: bool,
    strict_defaults: bool,
) -> None:
    """Triage active DEFECTs with the opt-in LLM judge."""
    try:
        outcome = run_judge(
            path,
            config_path=config_path,
            transport=transport,
            model=model,
            codex_model=codex_model,
            context_lines=context_lines,
            max_findings=max_findings,
            write=do_write,
            source_root_confinement=SourceRootConfinement.PROJECT_ROOT,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            trust_judge_config=trust_judge_config,
            trust_judge_policy=trust_judge_policy,
            strict_defaults=strict_defaults,
        )
    except JudgeContractError as exc:
        # The model violated the response contract — the audit primitive is corrupt.
        # Distinct from a missing key / malformed config (both also exit 2).
        click.echo(f"judge contract violation (model returned an unusable response): {exc}", err=True)
        raise SystemExit(2) from exc
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc

    _report(outcome, do_write=do_write)


def _report(outcome: JudgeOutcome, *, do_write: bool) -> None:
    result: TriageResult = outcome.result
    wrote, held_back = outcome.wrote, outcome.held_back
    for tv in result.verdicts:
        f, r = tv.finding, tv.response
        is_fp = r.verdict is JudgeVerdict.FALSE_POSITIVE
        low = is_fp and r.confidence < outcome.write_confidence_floor
        tag = "FP?" if low else ("FP" if is_fp else "TP")
        loc = f"{f.location.path}:{f.location.line_start}"
        # Surface the low-confidence caveat in BOTH modes — especially under --write,
        # where a low-confidence FP would otherwise be silently held back.
        note = "  (low confidence — held back from --write)" if low else ""
        click.echo(
            f"{tag} [{r.confidence:.2f}] {f.rule_id} {loc} "
            f"via {r.judge_transport.value}/{r.model_id} {f.qualname or ''}\n    {r.rationale}{note}"
        )
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
