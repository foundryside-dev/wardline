# src/wardline/scanner/rules/untrusted_to_deserialization.py
"""PY-WL-106 — untrusted data reaches a deserialization sink in a trusted-tier function.

Deserializing untrusted bytes (``pickle.loads``, ``yaml.load``, ``marshal.loads``, …)
is a classic remote-code-execution vector (CWE-502). Tier-modulated: silent in the
developer-freedom zone, fires where trust is declared. The ``safe_*`` loaders and the
*dump* direction are intentionally NOT sinks here. ``json.loads`` is excluded (it does
not execute) to avoid noise.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Severity
from wardline.scanner.rules._sink_helpers import TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

_SINKS = frozenset(
    {
        "pickle.loads",
        "pickle.load",
        "marshal.loads",
        "marshal.load",
        "yaml.load",
        "yaml.load_all",
        "yaml.unsafe_load",
        "yaml.full_load",
    }
)

METADATA = RuleMetadata(
    rule_id="PY-WL-106",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description="Untrusted data reaches a deserialization sink (pickle/marshal/yaml.load) in a trusted-tier function.",
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    pickle.loads(read_raw(p))",
    ),
    examples_clean=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trust_boundary(to_level='ASSURED')\ndef validate(x):\n    if not x:\n        raise ValueError\n    return x\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    blob = validate(read_raw(p))\n"
        "    obj = pickle.loads(blob)\n    return blob",
    ),
)


class UntrustedToDeserialization(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "deserialization"
