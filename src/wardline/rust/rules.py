"""WP5: the two slice-1 command-injection rules (the verdict layer).

RS-WL-108 (program injection) — tainted data reaches the *program* of ``Command::new`` —
is a NEW threat class (attacker-chosen executable), base **ERROR**. RS-WL-112 (shell
injection) — tainted data reaches a ``sh -c`` style shell command line — base **WARN**.
Both modulate by the containing fn's declared trust tier (``modulate``: an unmarked /
fail-closed fn yields ``NONE`` and is suppressed) and key on RAW_ZONE membership of the
*selected* taint. De-confliction: when the program itself is tainted (108's territory),
112 stays silent so one boundary yields one finding. CWE-78 rides the message prose.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity, compute_finding_fingerprint
from wardline.core.taints import RAW_ZONE, TaintState, least_trusted
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from collections.abc import Sequence

    from wardline.rust.context import RustAnalysisContext, RustTriggerContext

__all__ = ["RustProgramInjectionRule", "RustShellInjectionRule"]

# Programs that interpret their argument as a command line — the RS-WL-112 gate. A
# non-shell program with a tainted arg is the argv-list flood (a hard FP), so it never fires.
_SHELL_PROGRAMS = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
)


class RustProgramInjectionRule:
    """RS-WL-108 — untrusted data chooses the executable spawned by ``Command::new``."""

    rule_id = "RS-WL-108"
    base_severity = Severity.ERROR

    def check(self, context: RustAnalysisContext) -> Sequence[Finding]:
        findings: list[Finding] = []
        for tc in context.triggers:
            if tc.trigger.program_taint not in RAW_ZONE:
                continue
            severity = modulate(self.base_severity, tc.tier)
            if severity is Severity.NONE:
                continue
            findings.append(_program_finding(tc, severity))
        return findings


class RustShellInjectionRule:
    """RS-WL-112 — untrusted data reaches a ``sh -c`` style shell command line."""

    rule_id = "RS-WL-112"
    base_severity = Severity.WARN

    def check(self, context: RustAnalysisContext) -> Sequence[Finding]:
        findings: list[Finding] = []
        for tc in context.triggers:
            trig = tc.trigger
            # De-confliction: a tainted PROGRAM is RS-WL-108's finding; do not double-report.
            if trig.program_taint in RAW_ZONE:
                continue
            if not (trig.shell_flag_seen and _is_shell(trig.program_literal)):
                continue
            worst = _worst_arg_taint(tc)
            if worst not in RAW_ZONE:
                continue
            severity = modulate(self.base_severity, tc.tier)
            if severity is Severity.NONE:
                continue
            findings.append(_shell_finding(tc, severity, worst))
        return findings


def _is_shell(program_literal: str | None) -> bool:
    # Basename + case-fold: `/bin/sh`, `C:\Windows\System32\cmd.exe`, and `BASH` are all shells.
    if program_literal is None:
        return False
    basename = program_literal.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return basename in _SHELL_PROGRAMS


def _worst_arg_taint(tc: RustTriggerContext) -> TaintState:
    worst = TaintState.ASSURED
    for _node_id, taint in tc.trigger.arg_taints:
        worst = least_trusted(worst, taint)
    return worst


def _program_finding(tc: RustTriggerContext, severity: Severity) -> Finding:
    trig = tc.trigger
    taint_path = (
        f"{trig.program_taint.value}->Command::new(program)@L{trig.constructor_line}->exec@L{trig.trigger_line}"
    )
    message = (
        f"Untrusted data selects the program executed by Command::new "
        f"(constructed at line {trig.constructor_line}, run at line {trig.trigger_line}): "
        f"an attacker controls which executable runs (CWE-78)."
    )
    # Fingerprint discriminator (NOT the display path): source-derived + entity-relative
    # only (wlfp2 — see _fp_discriminant). The constructor's relative line is folded so
    # two stepwise builders terminating on one line stay distinct by construction site.
    fp_disc = f"Command::new(program)@L+{trig.constructor_line - tc.entity_line_start}"
    return _finding(RustProgramInjectionRule.rule_id, tc, severity, taint_path, fp_disc, message)


def _shell_finding(tc: RustTriggerContext, severity: Severity, worst: TaintState) -> Finding:
    trig = tc.trigger
    taint_path = f"{worst.value}->arg->'{trig.program_literal} -c'->exec@L{trig.trigger_line}"
    message = (
        f"Untrusted data reaches a shell command line "
        f"('{trig.program_literal} -c ...', run at line {trig.trigger_line}): "
        f"an attacker can inject shell syntax (CWE-78)."
    )
    # The program literal is a source token (the spelling as written), so it is a legal
    # wlfp2 discriminator component; the resolved `worst` tier is NOT (display-only).
    fp_disc = f"arg->'{trig.program_literal} -c'"
    return _finding(RustShellInjectionRule.rule_id, tc, severity, taint_path, fp_disc, message)


def _fp_discriminant(tc: RustTriggerContext, fp_disc: str) -> str:
    """The wlfp2 ``taint_path`` fingerprint component for one trigger.

    Every folded position is ENTITY-RELATIVE (wlfp2 move-stability, the
    rust-sp2-2026-06-10 keystone rekey — see core/finding.py:170): the trigger line
    folds as ``line - entity_line_start`` and the trigger NodeId as
    ``trigger_node_id - entity_node_id``. Both anchors are the containing fn's own
    (its first line, its pre-order index), so an edit ABOVE the entity — a comment
    at the top of the file, a sibling fn inserted above — shifts absolute lines and
    pre-order indices in lockstep and leaves both deltas invariant. An edit INSIDE
    the fn above the trigger moves the deltas and rekeys (accepted: that is the
    same entity-relative limitation the Python sink rules carry).

    The relative-NodeId fold is the SOLE same-line discriminant: two DISTINCT
    triggers on one physical line (identical rule/path/qualname/relative-line) get
    distinct fingerprints — the no-collision invariant. Resolved taint tiers never
    appear here (they drift across builds: weft-4a9d0f863c); the human-readable
    ``properties["taint_path"]`` keeps the absolute-line display form.
    """
    trig = tc.trigger
    rel_line = trig.trigger_line - tc.entity_line_start
    rel_node = int(trig.trigger_node_id) - int(tc.entity_node_id)
    return f"{fp_disc}->exec@L+{rel_line}@node+{rel_node}"


def _finding(
    rule_id: str, tc: RustTriggerContext, severity: Severity, taint_path: str, fp_disc: str, message: str
) -> Finding:
    trig = tc.trigger
    return Finding(
        rule_id=rule_id,
        message=message,
        severity=severity,
        kind=Kind.DEFECT,
        location=Location(path=tc.path, line_start=trig.trigger_line, line_end=trig.trigger_line),
        fingerprint=compute_finding_fingerprint(
            rule_id=rule_id,
            path=tc.path,
            qualname=tc.qualname,
            taint_path=_fp_discriminant(tc, fp_disc),
        ),
        qualname=tc.qualname,
        properties={
            "taint_path": taint_path,
            "constructor_line": trig.constructor_line,
            "trigger_node_id": int(trig.trigger_node_id),
        },
    )
