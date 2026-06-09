"""PY-WL-112 — untrusted data reaches a ``shell=True`` subprocess call.

The completion of PY-WL-108's deferred follow-up. 108 covers the *always-shell*
APIs (``os.system`` / ``os.popen`` / ``subprocess.getoutput`` /
``getstatusoutput``) and DELIBERATELY excludes the ``subprocess.run`` / ``call`` /
``check_call`` / ``check_output`` / ``Popen`` family, because with the default
``shell=False`` those take an argv-LIST (no shell, no injection) and firing on
them floods false positives. This rule closes that gap on the *one* condition
that makes the family injectable: a literal ``shell=True`` keyword (CWE-78).

**Scope (FP-safe, same discipline as 108):**
  - fires ONLY when ``shell=True`` is a statically-visible literal keyword. A
    ``**kwargs`` spread, a non-constant ``shell=flag``, a positional ``shell``, or
    ``shell=1`` (truthy-but-not-True) is NOT matched — a bounded false negative,
    chosen over the argv-list false positive 108 was avoiding;
  - the argument-taint test is inherited from ``TaintedSinkRule`` (worst resolvable
    arg in RAW_ZONE), so a fully-literal ``subprocess.run('ls -la', shell=True)``
    does NOT fire — the rule keys on untrusted DATA reaching the sink, not on
    ``shell=True`` alone (a separate, lower-confidence hygiene smell, out of scope).

Tier-modulated and trusted-tier-gated exactly like 106/107/108 (silent in the
undecorated developer-freedom zone, speaking only where trust is declared).
"""

from __future__ import annotations

import ast

from wardline.core.finding import Kind, Severity
from wardline.scanner.rules._sink_helpers import TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

# The conditionally-shell subprocess family. ``getoutput``/``getstatusoutput`` are
# intentionally absent — they are always-shell and already covered by PY-WL-108, so
# listing them here would double-fire.
_SINKS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    }
)


def _has_literal_shell_true(call: ast.Call) -> bool:
    """True iff *call* passes ``shell=True`` as a literal keyword. ``**kwargs``
    (``arg is None``), a non-constant value, or any constant other than ``True`` is
    not matched — only the unambiguous, statically-visible case fires."""
    return any(
        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in call.keywords
    )


METADATA = RuleMetadata(
    rule_id="PY-WL-112",
    base_severity=Severity.WARN,  # matches the 108 OS-command family; ERROR is defensible
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data reaches a subprocess call with a literal shell=True "
        "(conditionally-shell OS-command injection, CWE-78)."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    subprocess.run(read_raw(p), shell=True)",
    ),
    # Clean by ARGV-LIST (default shell=False, no shell) AND clean by LITERAL command
    # (no untrusted taint even with shell=True) — the rule needs both shell=True and taint.
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f(p):\n    subprocess.run(['ls', '-la'])",
        "@trusted(level='ASSURED')\ndef f():\n    subprocess.run('ls -la', shell=True)",
    ),
)


class UntrustedToShellSubprocess(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "shell=True subprocess"

    def _accept_call(self, call: ast.Call) -> bool:  # noqa: PLR6301
        """Extra per-call gate beyond the SINK-name match: require literal shell=True
        so the safe argv-list default (shell=False) never trips this family."""
        return _has_literal_shell_true(call)
