# src/wardline/core/judge_run.py
"""SP8: judge orchestration shared by the CLI and the MCP judge tool.

``judge_caller`` is injectable for hermetic tests. Otherwise this module resolves one
provider per run and builds either the OpenRouter caller or the sealed Codex CLI caller.
The CLI delegates here and formats the human-readable report from ``JudgeOutcome``.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from wardline.core import config as config_mod
from wardline.core.config import JudgeSettings, parse_judge_settings
from wardline.core.confinement import SourceRootConfinement
from wardline.core.errors import JudgeConfigurationError, JudgeTransportError, WardlineError
from wardline.core.judge import (
    _API_KEY_ENV,
    _STATIC_POLICY_BLOCK,
    JudgeRequest,
    JudgeResponse,
    call_judge,
)
from wardline.core.judge_transport import Probe, probe_codex_cli, resolve_judge_transport
from wardline.core.judge_types import CodexToolScope, JudgeTransport
from wardline.core.judged import JudgedFP, JudgedSet, load_judged, write_judged
from wardline.core.paths import judged_path as judged_file
from wardline.core.paths import weft_config_path
from wardline.core.run import run_scan
from wardline.core.safe_paths import safe_project_file
from wardline.core.source_excerpt import extract_excerpt
from wardline.core.triage import TriageResult, active_defects, run_triage

_CODEX_RUN_TRANSPORT_ERROR = "Codex CLI transport failed for this judge run"


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
    write_confidence_floor: float


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


def _normalize_transport(value: JudgeTransport | str) -> JudgeTransport:
    if isinstance(value, JudgeTransport):
        return value
    if isinstance(value, str):
        try:
            return JudgeTransport(value)
        except ValueError:
            pass
    allowed = ", ".join(item.value for item in JudgeTransport)
    raise JudgeConfigurationError(f"judge transport must be one of {allowed}") from None


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
    transport: JudgeTransport | str | None = None,
    model: str | None = None,
    codex_model: str | None = None,
    context_lines: int | None = None,
    max_findings: int | None = None,
    write: bool = False,
    source_root_confinement: SourceRootConfinement = SourceRootConfinement.PROJECT_ROOT,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    trust_judge_config: bool = False,
    trust_judge_policy: bool = False,
    strict_defaults: bool = False,
    judge_caller: Callable[[JudgeRequest], JudgeResponse] | None = None,
    codex_probe: Probe = probe_codex_cli,
) -> JudgeOutcome:
    """Analyze -> suppress -> triage -> (optional) persist. Returns structured verdicts.

    An injected ``judge_caller`` bypasses provider resolution. Otherwise the requested
    transport is resolved once, after the scan proves there is work to adjudicate.
    """
    cfg = config_mod.load(
        config_path or weft_config_path(root),
        explicit=config_path is not None,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    settings = effective_judge_settings(parse_judge_settings(cfg.judge), trust_judge_config=trust_judge_config)
    ctx_lines = context_lines if context_lines is not None else settings.context_lines
    cap = max_findings if max_findings is not None else settings.max_findings
    if cap is not None and cap <= 0:
        raise ValueError(f"max_findings must be positive, got {cap}")
    requested_transport = _normalize_transport(transport) if transport is not None else settings.transport
    floor = settings.write_confidence_floor

    scan = run_scan(
        root,
        config_path=config_path,
        source_root_confinement=source_root_confinement,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
        # The judge flow is the trusted local path: it consults judged records. The
        # emitted ``findings`` are always judged-annotated regardless of this flag;
        # passing True keeps the gate (if any consumer reads it) on the trusted set too.
        trust_suppressions=True,
    )
    judged_set = load_judged(judged_file(root))

    if not active_defects(scan.findings):
        result = TriageResult()
    else:
        project_policy = resolve_project_policy(root, settings, trust_judge_policy=trust_judge_policy)
        caller: Callable[[JudgeRequest], JudgeResponse]
        if judge_caller is not None:
            caller = judge_caller
        else:
            selected = resolve_judge_transport(requested_transport, probe=codex_probe)
            if selected is JudgeTransport.OPENROUTER:
                load_env_key(root)
                model_id = model if model is not None else settings.model
                policy_block = resolve_policy_block(root, settings)

                def _openrouter_caller(req: JudgeRequest) -> JudgeResponse:
                    return call_judge(
                        req,
                        model_id=model_id,
                        policy_block=policy_block,
                        project_policy=project_policy,
                        judge_transport=JudgeTransport.OPENROUTER,
                    )

                caller = _openrouter_caller
            else:
                model_id = codex_model if codex_model is not None else settings.codex_model
                codex_tool_scope = CodexToolScope(root=root.resolve())
                codex_transport_failed = False

                def _codex_caller(req: JudgeRequest) -> JudgeResponse:
                    nonlocal codex_transport_failed
                    if codex_transport_failed:
                        raise JudgeTransportError(_CODEX_RUN_TRANSPORT_ERROR) from None
                    try:
                        return call_judge(
                            req,
                            model_id=model_id,
                            policy_block=None,
                            project_policy=project_policy,
                            judge_transport=JudgeTransport.CODEX_CLI,
                            codex_tool_scope=codex_tool_scope,
                        )
                    except JudgeTransportError:
                        codex_transport_failed = True
                    raise JudgeTransportError(_CODEX_RUN_TRANSPORT_ERROR) from None

                caller = _codex_caller

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

    if write:
        wrote, held_back = _persist(root, judged_set, result, floor=floor)
    else:
        wrote = 0
        held_back = sum(1 for tv in result.false_positives() if tv.response.confidence < floor)

    return JudgeOutcome(
        verdicts=verdicts,
        wrote=wrote,
        held_back=held_back,
        result=result,
        write_confidence_floor=floor,
    )
