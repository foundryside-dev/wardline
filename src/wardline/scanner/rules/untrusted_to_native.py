# src/wardline/scanner/rules/untrusted_to_native.py
"""PY-WL-124 — untrusted path reaches a native-library load sink (CWE-114).

Charter: a tainted library path/name reaching ``ctypes.CDLL`` /
``ctypes.WinDLL`` / ``ctypes.OleDLL`` / ``ctypes.PyDLL`` or
``ctypes.cdll.LoadLibrary`` inside a trusted-tier function. Loading an
attacker-controlled shared object is arbitrary NATIVE code execution
(CWE-114 process control / CWE-829 untrusted functionality). Tier-modulated;
fires only where trust is declared.

Severity: ERROR. Same blast radius as the command/program-execution family
(PY-WL-108) and SQLi (PY-WL-118) — full process compromise with no further
preconditions — so the same ERROR base.

Only the library NAME/PATH slot is dangerous (``ArgSpec`` slot precision, review
2026-06-10): a tainted ``mode=`` / ``use_errno=`` flag with a constant library
name is not a native-load injection and must not fire.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Maturity, Severity
from wardline.scanner.rules._sink_helpers import ArgSpec, TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

# The library path/name is the first positional / the ``name`` keyword.
_NAME_SPEC = ArgSpec(positions=(0,), keywords=("name",))

_SINK_SPECS: dict[str, ArgSpec | None] = {
    "ctypes.CDLL": _NAME_SPEC,
    "ctypes.WinDLL": _NAME_SPEC,
    "ctypes.OleDLL": _NAME_SPEC,
    "ctypes.PyDLL": _NAME_SPEC,
    "ctypes.cdll.LoadLibrary": ArgSpec(positions=(0,)),
}

_SINKS = frozenset(_SINK_SPECS)

METADATA = RuleMetadata(
    rule_id="PY-WL-124",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data reaches a native-library load sink (ctypes.CDLL/WinDLL/OleDLL/PyDLL, "
        "ctypes.cdll.LoadLibrary) in a trusted-tier function."
    ),
    examples_violation=(
        "import ctypes\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    return ctypes.CDLL(read_raw(p))",
    ),
    examples_clean=("import ctypes\n@trusted(level='ASSURED')\ndef f():\n    ctypes.CDLL('libm.so.6')",),
    maturity=Maturity.PREVIEW,
)


class UntrustedToNative(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    SINK_SPECS = _SINK_SPECS
    sink_label = "native-library-load"
