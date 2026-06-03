# src/wardline/scanner/rules/path_traversal.py
"""PY-WL-116 — untrusted data reaches a path/filesystem-traversal sink.

Passing untrusted data to filesystem APIs (``open``, ``os.open``, ``pathlib.Path``,
or helper functions like ``os.path.join``) can lead to path traversal (CWE-22).
Tier-modulated; fires only where trust is declared.
"""

from __future__ import annotations

from wardline.core.finding import Kind, Maturity, Severity
from wardline.scanner.rules._sink_helpers import TaintedSinkRule
from wardline.scanner.rules.metadata import RuleMetadata

_SINKS = frozenset(
    {
        "open",
        "builtins.open",
        "os.open",
        "os.path.join",
        "pathlib.Path",
    }
)

METADATA = RuleMetadata(
    rule_id="PY-WL-116",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description=(
        "Untrusted data reaches a path/filesystem-traversal sink (open/os.path.join/pathlib.Path) "
        "in a trusted-tier function."
    ),
    examples_violation=(
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p):\n    open(read_raw(p))",
    ),
    examples_clean=("@trusted(level='ASSURED')\ndef f():\n    open('safe_file.txt')",),
    maturity=Maturity.PREVIEW,
)


class PathTraversal(TaintedSinkRule):
    rule_id = METADATA.rule_id
    metadata = METADATA
    SINKS = _SINKS
    sink_label = "path-traversal"
