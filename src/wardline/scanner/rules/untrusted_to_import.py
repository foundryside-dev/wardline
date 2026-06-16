# src/wardline/scanner/rules/untrusted_to_import.py
"""PY-WL-115 — untrusted data reaches a dynamic code/module-load sink in a trusted-tier function.

Fires when raw-zone data reaches a dynamic module-load or file-execution sink inside a
trusted-tier function. The sink family covers the import-and-execute class (CWE-829 /
CWE-94): ``importlib.import_module`` and ``__import__`` (attacker-chosen module name),
``runpy.run_path`` / ``runpy.run_module`` (import-and-EXECUTE an attacker-controlled
file path / module — blast radius equivalent to ``exec``), and
``importlib.util.spec_from_file_location`` (a tainted file-path arg builds a loader for
attacker-chosen code). Expanded from the original two-sink charter
(importlib.import_module / __import__) per wardline-c83b40c73a.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Severity
from wardline.scanner.rules._sink_helpers import TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

_SINKS = frozenset(
    {
        "importlib.import_module",
        "__import__",
        "runpy.run_path",
        "runpy.run_module",
        "importlib.util.spec_from_file_location",
    }
)

METADATA = RuleMetadata(
    rule_id="PY-WL-115",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "Untrusted data reaches a dynamic code/module-load sink (importlib.import_module / "
        "__import__ / runpy.run_path / runpy.run_module / "
        "importlib.util.spec_from_file_location) in a trusted-tier function."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    importlib.import_module(read_raw(p))",
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    runpy.run_path(read_raw(p))",
    ),
    examples_clean=("@trusted(level='ASSURED')\ndef f(p):\n    importlib.import_module('sys')",),
)


class UntrustedToImport(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "dynamic import"
