"""WP5: the minimal analysis context the Rust rules judge.

``RustAnalysisContext`` carries what a ``RustRule`` needs — the reconstructed command
triggers (each tagged with its containing fn's qualname and resolved trust tier) plus the
``project_taints`` map (qualname -> body taint) the analyzer also exposes as ``last_context``
for ``run_scan``'s delta/ScanResult path. The rules are deliberately a SEPARATE protocol
from the Python ``Rule``/``AnalysisContext`` (they never plug into the Python ``RuleRegistry``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from wardline.core.finding import Finding
    from wardline.core.taints import TaintState
    from wardline.rust.dataflow import CommandTrigger
    from wardline.rust.index import RustEntity

__all__ = ["RustAnalysisContext", "RustRule", "RustTriggerContext"]


@dataclass(frozen=True, slots=True)
class RustTriggerContext:
    """One command trigger bound to its containing function's identity and trust tier."""

    trigger: CommandTrigger
    qualname: str  # the containing fn (finding qualname + fingerprint key)
    tier: TaintState  # the containing fn's body taint — modulates rule severity
    path: str  # the source file path (Location + fingerprint key)


@dataclass(frozen=True, slots=True)
class RustAnalysisContext:
    """The whole-source view a rule pass consumes."""

    triggers: Sequence[RustTriggerContext]
    project_taints: Mapping[str, TaintState]  # qualname -> body taint
    entities: Mapping[str, RustEntity]


@runtime_checkable
class RustRule(Protocol):
    """A Rust verdict rule. NOT the Python ``Rule`` protocol and NOT registered in the
    Python ``RuleRegistry`` — it consumes a ``RustAnalysisContext``, not an ``AnalysisContext``."""

    rule_id: str

    def check(self, context: RustAnalysisContext) -> Sequence[Finding]: ...
