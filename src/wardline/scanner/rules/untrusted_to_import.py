# src/wardline/scanner/rules/untrusted_to_import.py
"""PY-WL-115 — untrusted data reaches a dynamic import sink in a trusted-tier function.

Fires when raw-zone data reaches a dynamic module load sink (importlib.import_module
or __import__) inside a trusted-tier function.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Severity
from wardline.scanner.rules._sink_helpers import TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

_SINKS = frozenset({"importlib.import_module", "__import__"})

METADATA = RuleMetadata(
    rule_id="PY-WL-115",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description=(
        "Untrusted data reaches a dynamic import sink (importlib.import_module / "
        "__import__) in a trusted-tier function."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    importlib.import_module(read_raw(p))",
    ),
    examples_clean=("@trusted(level='ASSURED')\ndef f(p):\n    importlib.import_module('sys')",),
)


class UntrustedToImport(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "dynamic import"
