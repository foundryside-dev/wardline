# src/wardline/core/judge_run.py
"""SP8: judge orchestration shared by the CLI and the MCP judge tool.

The ONLY core path that touches the network (urllib -> OpenRouter), and only when
actually invoked. ``judge_caller`` is injectable for tests, so the pipeline is
hermetic; the default builds the real urllib caller. The CLI delegates here and
formats the human-readable report from the returned ``JudgeOutcome``.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from wardline.core import config as config_mod
from wardline.core.config import JudgeSettings, parse_judge_settings
from wardline.core.errors import WardlineError
from wardline.core.judge import (
    _API_KEY_ENV,
    _STATIC_POLICY_BLOCK,
    JudgeRequest,
    JudgeResponse,
    call_judge,
)
from wardline.core.judged import JudgedFP, JudgedSet, load_judged, write_judged
from wardline.core.paths import judged_path as judged_file
from wardline.core.paths import weft_config_path
from wardline.core.run import run_scan
from wardline.core.safe_paths import safe_project_file
from wardline.core.source_excerpt import extract_excerpt
from wardline.core.triage import TriageResult, run_triage


@dataclass(frozen=True, slots=True)
class Verdict:
    """A flattened per-finding verdict — the structured surface for MCP/JSON consumers."""

    fingerprint: str
    rule_id: str
    path: str
    line: int | None
    label: str  # JudgeVerdict value: "TRUE_POSITIVE" | "FALSE_POSITIVE"
    confidence: float
    rationale: str


@dataclass(frozen=True, slots=True)
class JudgeOutcome:
    verdicts: list[Verdict]
    wrote: int
    held_back: int
    # The raw triage result — carried so the CLI can render its byte-identical
    # human report (qualname, low-confidence caveats, skip counts) without re-running
    # the pipeline. MCP consumers use ``verdicts`` and ignore this.
    result: TriageResult


def load_env_key(root: Path) -> None:
    """If the API key is unset, read a single KEY=VALUE line from ``root/.env``.

    Convenience only (no dependency). An already-set environment value always wins —
    we never silently override it. The key comes from env / ``.env`` ONLY, never config.
    """
    if os.environ.get(_API_KEY_ENV):
        return
    env_path = safe_project_file(root, root / ".env", label=".env")
    if not env_path.is_file():
        return
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith(f"{_API_KEY_ENV}="):
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            if value:
                os.environ[_API_KEY_ENV] = value
            return


def resolve_policy_block(root: Path, settings: JudgeSettings) -> str:
    return _STATIC_POLICY_BLOCK


def effective_judge_settings(settings: JudgeSettings, *, trust_judge_config: bool) -> JudgeSettings:
    if trust_judge_config:
        return settings
    return JudgeSettings(policy_file=settings.policy_file)


def resolve_project_policy(root: Path, settings: JudgeSettings, *, trust_judge_policy: bool) -> str | None:
    if settings.policy_file is None:
        return None
    if not trust_judge_policy:
        raise WardlineError(
            "judge.policy_file requires explicit trust_judge_policy because project-supplied policy "
            "is untrusted input to the judge"
        )
    policy_path = (root / settings.policy_file).resolve()
    if not policy_path.is_relative_to(root.resolve()) or not policy_path.is_file():
        raise WardlineError(f"judge.policy_file {settings.policy_file!r} not found under {root}")
    return policy_path.read_text(encoding="utf-8", errors="replace")


def _persist(root: Path, existing: JudgedSet, result: TriageResult, *, floor: float) -> tuple[int, int]:
    """Append FALSE_POSITIVE verdicts at/above the confidence floor. Returns (wrote, held_back)."""
    writable = [tv for tv in result.false_positives() if tv.response.confidence >= floor]
    held_back = len(result.false_positives()) - len(writable)
    if not writable:
        return 0, held_back
    judged_path = judged_file(root)
    new: list[JudgedFP] = [e for fp in existing.fingerprints() if (e := existing.match(fp)) is not None]
    for tv in writable:
        f, r = tv.finding, tv.response
        new.append(
            JudgedFP(
                fingerprint=f.fingerprint,
                rule_id=f.rule_id,
                path=f.location.path,
                message=f.message,
                rationale=r.rationale,
                model_id=r.model_id,
                confidence=r.confidence,
                recorded_at=r.recorded_at,
                policy_hash=r.policy_hash,
            )
        )
    write_judged(judged_path, new, root=root)
    return len(writable), held_back


def run_judge(
    root: Path,
    *,
    config_path: Path | None = None,
    model: str | None = None,
    context_lines: int | None = None,
    max_findings: int | None = None,
    write: bool = False,
    confine_to_root: bool = True,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    trust_judge_config: bool = False,
    trust_judge_policy: bool = False,
    strict_defaults: bool = False,
    judge_caller: Callable[[JudgeRequest], JudgeResponse] | None = None,
) -> JudgeOutcome:
    """Analyze -> suppress -> triage -> (optional) persist. Returns structured verdicts.

    ``judge_caller`` is injected by tests and the CLI; when ``None`` the default
    urllib-backed caller is built here (reading the key from env / ``.env``). The
    network is touched only when the default caller is actually invoked on a finding.
    """
    cfg = config_mod.load(
        config_path or weft_config_path(root),
        explicit=config_path is not None,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    settings = effective_judge_settings(parse_judge_settings(cfg.judge), trust_judge_config=trust_judge_config)
    model_id = model or settings.model
    ctx_lines = context_lines if context_lines is not None else settings.context_lines
    cap = max_findings if max_findings is not None else settings.max_findings

    project_policy = resolve_project_policy(root, settings, trust_judge_policy=trust_judge_policy)

    caller: Callable[[JudgeRequest], JudgeResponse]
    if judge_caller is None:
        load_env_key(root)
        policy_block = resolve_policy_block(root, settings)

        def _default_caller(req: JudgeRequest) -> JudgeResponse:
            return call_judge(req, model_id=model_id, policy_block=policy_block, project_policy=project_policy)

        caller = _default_caller
    else:
        caller = judge_caller

    scan = run_scan(
        root,
        config_path=config_path,
        confine_to_root=confine_to_root,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
        # The judge flow is the trusted local path: it consults judged records. The
        # emitted ``findings`` are always judged-annotated regardless of this flag;
        # passing True keeps the gate (if any consumer reads it) on the trusted set too.
        trust_suppressions=True,
    )
    judged_set = load_judged(judged_file(root))

    result = run_triage(
        scan.findings,
        read_excerpt=lambda f: extract_excerpt(
            root, f.location.path, line=f.location.line_start or 1, context_lines=ctx_lines
        ),
        judge_caller=caller,
        max_findings=cap,
    )

    verdicts = [
        Verdict(
            fingerprint=tv.finding.fingerprint,
            rule_id=tv.finding.rule_id,
            path=tv.finding.location.path,
            line=tv.finding.location.line_start,
            label=tv.response.verdict.value,
            confidence=tv.response.confidence,
            rationale=tv.response.rationale,
        )
        for tv in result.verdicts
    ]

    floor = settings.write_confidence_floor
    if write:
        wrote, held_back = _persist(root, judged_set, result, floor=floor)
    else:
        wrote = 0
        held_back = sum(1 for tv in result.false_positives() if tv.response.confidence < floor)

    return JudgeOutcome(verdicts=verdicts, wrote=wrote, held_back=held_back, result=result)
