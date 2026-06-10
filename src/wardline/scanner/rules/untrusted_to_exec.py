# src/wardline/scanner/rules/untrusted_to_exec.py
"""PY-WL-107 — untrusted data reaches a dynamic-code-execution sink.

``eval`` / ``exec`` / ``compile`` on untrusted input is arbitrary code execution
(CWE-95). Tier-modulated; fires only where trust is declared. Matches the bare
builtins (``eval(x)``), the ``builtins.eval`` forms, and the ``__builtins__.eval``
spelling. The ``__builtins__`` form is real but narrow: in ``__main__``
``__builtins__`` is the builtins MODULE (so ``.eval`` executes), while in an
imported module it is a plain dict (attribute access fails) — it is matched
because where it does run, it is full arbitrary-code-execution
(wardline-c83b40c73a).

**Severity: WARN — a deliberate FP-economics call, not an oversight (severity
lattice review 2026-06-10).** Blast-radius alone would argue ERROR alongside
108/112/118/124, but those rules buy their ERROR with strong per-finding
evidence: a slot-precise ArgSpec, a literal ``shell=True``, or an SQL-string
position gate. This rule's sinks take ONE polymorphic payload argument tested
worst-of-all-args, ``compile`` is pervasive in legitimate metaprogramming, and
``eval``/``exec`` payloads are routinely pre-validated in ways the engine cannot
prove — so its evidence per finding is one class weaker, and its base sits one
class lower. Promote via ``rules.severity`` per project, or revisit alongside
the frozen identity corpus when the rule gains slot/shape evidence.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Severity
from wardline.scanner.rules._sink_helpers import TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

_SINKS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "builtins.eval",
        "builtins.exec",
        "builtins.compile",
        "__builtins__.eval",
        "__builtins__.exec",
        "__builtins__.compile",
    }
)

METADATA = RuleMetadata(
    rule_id="PY-WL-107",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    multi_emit=True,
    description="Untrusted data reaches a dynamic-code-execution sink (eval/exec/compile) in a trusted-tier function.",
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    eval(read_raw(p))",
    ),
    examples_clean=("@trusted(level='ASSURED')\ndef f():\n    return eval('1 + 1')",),
)


class UntrustedToExec(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "dynamic-code-execution"
