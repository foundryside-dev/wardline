# src/wardline/scanner/rules/__init__.py
"""SP2 policy rules: the trust-vocabulary-driven defect rule set, the compact
tier-modulation severity model, and the default ``RuleRegistry`` factory."""

from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

from wardline.core.finding import Severity
from wardline.scanner.context import RuleRegistry
from wardline.scanner.rules.boundary_without_rejection import BoundaryWithoutRejection
from wardline.scanner.rules.broad_exception import BroadException
from wardline.scanner.rules.silent_exception import SilentException
from wardline.scanner.rules.untrusted_reaches_trusted import UntrustedReachesTrusted

if TYPE_CHECKING:
    from wardline.core.config import WardlineConfig

# Registration order = emission order (deterministic findings stream).
_ALL_RULE_CLASSES = (
    UntrustedReachesTrusted,
    BoundaryWithoutRejection,
    BroadException,
    SilentException,
)


def _enabled(rule_id: str, patterns: tuple[str, ...]) -> bool:
    """A rule is enabled if any pattern is ``*`` or fnmatch-matches its id."""
    return any(p == "*" or fnmatch.fnmatch(rule_id, p) for p in patterns)


def build_default_registry(config: WardlineConfig) -> RuleRegistry:
    """Build the SP2 rule set, honoring ``config.rules_enable`` (fnmatch include
    list; ``*`` = all) and ``config.rules_severity`` (per-rule base-severity
    override, applied BEFORE tier modulation). An unknown severity string raises
    ``ValueError`` (a config error surfaced eagerly)."""
    registry = RuleRegistry()
    for cls in _ALL_RULE_CLASSES:
        rule_id = cls.rule_id
        if not _enabled(rule_id, config.rules_enable):
            continue
        override = config.rules_severity.get(rule_id)
        base = Severity(override) if override is not None else None
        registry.register(cls(base_severity=base))
    return registry
