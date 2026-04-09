"""Tests for Severity, Exceptionability, and RuleId enums."""

import json

from wardline.core.severity import Exceptionability, RuleId, Severity


class TestSeverity:
    def test_values(self) -> None:
        assert str(Severity.ERROR) == "ERROR"
        assert str(Severity.WARNING) == "WARNING"
        assert str(Severity.SUPPRESS) == "SUPPRESS"

    def test_count(self) -> None:
        assert len(Severity) == 3


class TestExceptionability:
    def test_values(self) -> None:
        assert str(Exceptionability.UNCONDITIONAL) == "UNCONDITIONAL"
        assert str(Exceptionability.STANDARD) == "STANDARD"
        assert str(Exceptionability.RELAXED) == "RELAXED"
        assert str(Exceptionability.TRANSPARENT) == "TRANSPARENT"

    def test_count(self) -> None:
        assert len(Exceptionability) == 4


class TestRuleId:
    def test_canonical_rule_round_trip(self) -> None:
        """Canonical rule IDs use hyphens in values, underscores in names."""
        assert str(RuleId.PY_WL_001) == "PY-WL-001"
        assert str(RuleId.PY_WL_005) == "PY-WL-005"
        assert str(RuleId.PY_WL_009) == "PY-WL-009"

    def test_pseudo_rule_round_trip(self) -> None:
        """Pseudo-rule-IDs are full members of RuleId."""
        assert str(RuleId.TOOL_ERROR) == "TOOL-ERROR"
        assert str(RuleId.PY_WL_001_GOVERNED_DEFAULT) == "PY-WL-001-GOVERNED-DEFAULT"
        assert str(RuleId.WARDLINE_UNRESOLVED_DECORATOR) == "WARDLINE-UNRESOLVED-DECORATOR"
        assert str(RuleId.GOVERNANCE_REGISTRY_MISMATCH_ALLOWED) == "GOVERNANCE-REGISTRY-MISMATCH-ALLOWED"

    def test_canonical_count(self) -> None:
        """Total RuleId member count (canonical + supplementary + pseudo)."""
        assert len(RuleId) == 39

    def test_json_serialisation(self) -> None:
        """StrEnum members serialise as plain strings."""
        assert json.dumps(RuleId.PY_WL_001) == '"PY-WL-001"'
        assert json.dumps(RuleId.TOOL_ERROR) == '"TOOL-ERROR"'

    def test_all_pseudo_rules_are_members(self) -> None:
        """Every pseudo-rule-ID that Finding.rule_id can hold must be a member."""
        pseudo_ids = [
            "PY-WL-001-GOVERNED-DEFAULT",
            "PY-WL-001-UNGOVERNED-DEFAULT",
            "WARDLINE-UNRESOLVED-DECORATOR",
            "TOOL-ERROR",
            "GOVERNANCE-REGISTRY-MISMATCH-ALLOWED",
            "GOVERNANCE-RULE-DISABLED",
            "GOVERNANCE-PERMISSIVE-DISTRIBUTION",
            "GOVERNANCE-STALE-EXCEPTION",
            "GOVERNANCE-UNKNOWN-PROVENANCE",
            "GOVERNANCE-RECURRING-EXCEPTION",
            "GOVERNANCE-BATCH-REFRESH",
            "GOVERNANCE-NO-EXPIRY-EXCEPTION",
        ]
        rule_values = {r.value for r in RuleId}
        for pid in pseudo_ids:
            assert pid in rule_values, f"Pseudo-rule-ID {pid} is not a RuleId member"
