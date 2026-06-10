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
    return _finding(RustProgramInjectionRule.rule_id, tc, severity, taint_path, message)


def _shell_finding(tc: RustTriggerContext, severity: Severity, worst: TaintState) -> Finding:
    trig = tc.trigger
    taint_path = f"{worst.value}->arg->'{trig.program_literal} -c'->exec@L{trig.trigger_line}"
    message = (
        f"Untrusted data reaches a shell command line "
        f"('{trig.program_literal} -c ...', run at line {trig.trigger_line}): "
        f"an attacker can inject shell syntax (CWE-78)."
    )
    return _finding(RustShellInjectionRule.rule_id, tc, severity, taint_path, message)


def _finding(rule_id: str, tc: RustTriggerContext, severity: Severity, taint_path: str, message: str) -> Finding:
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
            # Fold the trigger's NodeId so two DISTINCT commands on the SAME line (identical
            # taint_path) get distinct fingerprints — the no-collision invariant. line_start
            # was dropped from the fingerprint by the move-stability rekey (wlfp2), so the
            # NodeId fold is now the SOLE same-line discriminant. The NodeId is the
            # reproducible pre-order index, so this stays deterministic across runs. The
            # stored properties["taint_path"] keeps the clean, human-readable form.
            taint_path=f"{taint_path}@node{trig.trigger_node_id}",
        ),
        qualname=tc.qualname,
        properties={
            "taint_path": taint_path,
            "constructor_line": trig.constructor_line,
            "trigger_node_id": int(trig.trigger_node_id),
        },
    )
