# src/wardline/scanner/rules/__init__.py
"""SP2 policy rules: the trust-vocabulary-driven defect rule set, the compact
tier-modulation severity model, and the default ``RuleRegistry`` factory."""

from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

from wardline.core.finding import (
    ENGINE_PATH,
    Finding,
    Kind,
    Location,
    Severity,
    compute_finding_fingerprint,
)
from wardline.scanner.context import RuleRegistry
from wardline.scanner.rules.assert_only_boundary import AssertOnlyBoundary
from wardline.scanner.rules.boundary_without_rejection import BoundaryWithoutRejection
from wardline.scanner.rules.broad_exception import BroadException
from wardline.scanner.rules.contradictory_trust import ContradictoryTrust
from wardline.scanner.rules.degenerate_boundary import DegenerateBoundary
from wardline.scanner.rules.failopen_boundary import FailOpenBoundary
from wardline.scanner.rules.invalid_decorator_level import InvalidDecoratorLevel
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.none_leak import NoneLeak
from wardline.scanner.rules.path_traversal import PathTraversal
from wardline.scanner.rules.silent_exception import SilentException
from wardline.scanner.rules.sql_injection import SQLInjection
from wardline.scanner.rules.ssrf import SSRF
from wardline.scanner.rules.stored_taint import StoredTaint
from wardline.scanner.rules.untrusted_reaches_trusted import UntrustedReachesTrusted
from wardline.scanner.rules.untrusted_to_command import UntrustedToCommand
from wardline.scanner.rules.untrusted_to_deserialization import UntrustedToDeserialization
from wardline.scanner.rules.untrusted_to_exec import UntrustedToExec
from wardline.scanner.rules.untrusted_to_import import UntrustedToImport
from wardline.scanner.rules.untrusted_to_shell_subprocess import UntrustedToShellSubprocess
from wardline.scanner.rules.untrusted_to_trusted_callee import UntrustedReachesTrustedCallee

if TYPE_CHECKING:
    from wardline.core.config import WardlineConfig
    from wardline.scanner.context import AnalysisContext, _RuleClass

# Registration order = emission order (deterministic findings stream).
_ALL_RULE_CLASSES = (
    UntrustedReachesTrusted,
    BoundaryWithoutRejection,
    BroadException,
    SilentException,
    ContradictoryTrust,
    NoneLeak,
    UntrustedReachesTrustedCallee,
    UntrustedToDeserialization,
    UntrustedToExec,
    UntrustedToCommand,
    UntrustedToShellSubprocess,
    AssertOnlyBoundary,
    FailOpenBoundary,
    InvalidDecoratorLevel,
    UntrustedToImport,
    PathTraversal,
    SSRF,
    SQLInjection,
    DegenerateBoundary,
    StoredTaint,
)


# Public alias: the builtin rule set the default grammar (Track 2) preloads.
# Kept as the single source of truth — `default_grammar()` references this so the
# grammar's builtin rules cannot drift from the legacy registry construction.
BUILTIN_RULE_CLASSES = _ALL_RULE_CLASSES

_POLICY_CONFIG_RULE_ID = "WLN-ENGINE-POLICY-CONFIG"
_POLICY_CONFIG_METADATA = RuleMetadata(
    rule_id=_POLICY_CONFIG_RULE_ID,
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description="Project policy configuration weakens or disables Wardline policy rules.",
)


def _enabled(rule_id: str, patterns: tuple[str, ...]) -> bool:
    """A rule is enabled if any pattern is ``*`` or fnmatch-matches its id."""
    return any(p == "*" or fnmatch.fnmatch(rule_id, p) for p in patterns)


def _pattern_matches(pattern: str, rule_ids: tuple[str, ...]) -> frozenset[str]:
    """Return the known rule IDs selected by one ``rules.enable`` pattern."""
    return frozenset(rule_id for rule_id in rule_ids if _enabled(rule_id, (pattern,)))


def _policy_config_finding(message: str, *, reason: str, taint_path: str, **properties: object) -> Finding:
    return Finding(
        rule_id=_POLICY_CONFIG_RULE_ID,
        message=message,
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path=ENGINE_PATH),
        fingerprint=compute_finding_fingerprint(
            rule_id=_POLICY_CONFIG_RULE_ID,
            path=ENGINE_PATH,
            taint_path=taint_path,
        ),
        # OLD (wlfp1) taint_path == NEW (unchanged by P3), but ephemeral — recompute for rekey (P4).
        taint_path_v0=taint_path,
        properties={"reason": reason, **properties},
    )


class _PolicyConfigRule:
    rule_id = _POLICY_CONFIG_RULE_ID
    metadata = _POLICY_CONFIG_METADATA

    def __init__(self, findings: tuple[Finding, ...]) -> None:
        self.base_severity = Severity.ERROR
        self._findings = findings

    def check(self, context: AnalysisContext) -> list[Finding]:
        return list(self._findings)


def _resolve_enabled_rules(
    patterns: tuple[str, ...], rule_ids: tuple[str, ...]
) -> tuple[frozenset[str], tuple[Finding, ...]]:
    findings: list[Finding] = []
    if not patterns:
        findings.append(
            _policy_config_finding(
                "rules.enable selects no policy rules",
                reason="empty_enable_patterns",
                taint_path="rules.enable:empty",
                patterns=[],
            )
        )
        return frozenset(), tuple(findings)

    selected: set[str] = set()
    for pattern in patterns:
        matches = _pattern_matches(pattern, rule_ids)
        if not matches:
            findings.append(
                _policy_config_finding(
                    f"rules.enable pattern {pattern!r} matches no known policy rules",
                    reason="unknown_rule_pattern",
                    taint_path=f"rules.enable:{pattern}",
                    pattern=pattern,
                )
            )
            continue
        selected.update(matches)

    if not selected:
        findings.append(
            _policy_config_finding(
                "rules.enable selects no known policy rules",
                reason="empty_effective_ruleset",
                taint_path=f"rules.enable:empty-effective:{','.join(patterns)}",
                patterns=list(patterns),
            )
        )
    return frozenset(selected), tuple(findings)


def _is_defect_rule(cls: _RuleClass) -> bool:
    metadata = getattr(cls, "metadata", None)
    if metadata is None:
        return True
    return getattr(metadata, "kind", Kind.DEFECT) is Kind.DEFECT


def _resolve_severity_overrides(
    overrides: dict[str, str], rule_classes: tuple[_RuleClass, ...]
) -> tuple[dict[str, Severity], tuple[Finding, ...]]:
    classes_by_id = {cls.rule_id: cls for cls in rule_classes}
    resolved: dict[str, Severity] = {}
    findings: list[Finding] = []
    for rule_id, override in overrides.items():
        cls = classes_by_id.get(rule_id)
        if cls is None:
            findings.append(
                _policy_config_finding(
                    f"rules.severity override {rule_id!r} is not a known policy rule",
                    reason="unknown_severity_rule",
                    taint_path=f"rules.severity:{rule_id}:unknown",
                    rule_id=rule_id,
                    override=override,
                )
            )
            continue
        try:
            severity = Severity(override)
        except (TypeError, ValueError) as exc:
            findings.append(
                _policy_config_finding(
                    f"rules.severity override for {rule_id!r} is not a valid severity",
                    reason="invalid_severity",
                    taint_path=f"rules.severity:{rule_id}:invalid:{override}",
                    rule_id=rule_id,
                    override=override,
                    error=str(exc),
                )
            )
            continue
        if severity is Severity.NONE and _is_defect_rule(cls):
            findings.append(
                _policy_config_finding(
                    f"rules.severity override for {rule_id!r} cannot be NONE",
                    reason="none_severity_override",
                    taint_path=f"rules.severity:{rule_id}:NONE",
                    rule_id=rule_id,
                    override=override,
                )
            )
            continue
        resolved[rule_id] = severity
    return resolved, tuple(findings)


def build_default_registry(config: WardlineConfig, *, rules: tuple[_RuleClass, ...] | None = None) -> RuleRegistry:
    """Build the rule set, honoring ``config.rules_enable`` (fnmatch include list;
    ``*`` = all) and ``config.rules_severity`` (per-rule base-severity override,
    applied BEFORE tier modulation). Unknown rule selectors, empty effective rule
    sets, unknown severity targets, invalid severity strings, and ``NONE`` severity
    overrides for defect rules are rejected as active engine defects and are not
    honored.

    ``rules`` are the rule CLASSES to register, in order; ``None`` uses the builtin
    set (Track 2: a grammar passes ``grammar.rules`` so agent-defined rules register
    on the same config-gated path as the builtins)."""
    rule_classes = rules if rules is not None else BUILTIN_RULE_CLASSES
    rule_ids = tuple(cls.rule_id for cls in rule_classes)
    enabled_ids, enable_findings = _resolve_enabled_rules(config.rules_enable, rule_ids)
    severity_overrides, severity_findings = _resolve_severity_overrides(dict(config.rules_severity), rule_classes)

    registry = RuleRegistry()
    policy_config_findings = enable_findings + severity_findings
    if policy_config_findings:
        registry.register(_PolicyConfigRule(policy_config_findings))
    for cls in rule_classes:
        rule_id = cls.rule_id
        if rule_id not in enabled_ids:
            continue
        base = severity_overrides.get(rule_id)
        registry.register(cls(base_severity=base))
    return registry
