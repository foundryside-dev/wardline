# src/wardline/scanner/rules/untrusted_to_reflection.py
"""PY-WL-123 — tainted attribute NAME reaches setattr/getattr (CWE-915).

Charter: dynamic attribute injection — an untrusted NAME argument (position 1)
to the builtin ``setattr``/``getattr`` inside a trusted-tier function lets an
attacker pick which attribute is written/read (mass assignment, e.g. reaching
``__class__``-adjacent state). Tier-modulated; fires only where trust is
declared.

Only the NAME slot is dangerous: an untrusted VALUE assigned to a fixed
attribute (``setattr(obj, 'name', raw)``), a tainted ``getattr`` default, or a
tainted receiver are ordinary data flow, not attribute injection — the
arg-position-aware :class:`ArgSpec` keeps them silent.

Severity: WARN. Exploitation depends on the target object's shape (a
mass-assignment VECTOR, not direct code execution), so it sits below the
unconditional-RCE ERROR class (108/112/118/124). Note the WARN co-residents
106/107 are there for a DIFFERENT reason — they ARE direct-RCE sinks held at
WARN on FP economics (weaker worst-of-all-args evidence; see their module
docstrings) — so this rule does not cite them as a "non-RCE WARN convention".
"""

from __future__ import annotations

from wardline.core.finding import Kind, Maturity, Severity
from wardline.scanner.rules._sink_helpers import ArgSpec, TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

# setattr/getattr are positional-only builtins — the NAME is position 1, always.
_NAME_SPEC = ArgSpec(positions=(1,))

_SINK_SPECS: dict[str, ArgSpec | None] = {
    "setattr": _NAME_SPEC,
    "getattr": _NAME_SPEC,
    "builtins.setattr": _NAME_SPEC,
    "builtins.getattr": _NAME_SPEC,
}

METADATA = RuleMetadata(
    rule_id="PY-WL-123",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data is used as the attribute NAME in setattr/getattr in a trusted-tier function "
        "(dynamic attribute injection / mass assignment)."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p, obj):\n    setattr(obj, read_raw(p), 1)\n    return 1",
    ),
    examples_clean=(
        # Fixed attribute name: the untrusted VALUE slot is not the injection vector.
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p, obj):\n    setattr(obj, 'name', read_raw(p))\n    return 1",
    ),
    maturity=Maturity.PREVIEW,
)


class UntrustedToReflection(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = frozenset(_SINK_SPECS)
    SINK_SPECS = _SINK_SPECS
    sink_label = "attribute-reflection"
