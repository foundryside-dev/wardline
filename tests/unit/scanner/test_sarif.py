"""Tests for SARIF v2.1.0 output module."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState

if TYPE_CHECKING:
    from pathlib import Path
from wardline.scanner.context import Finding
from wardline.scanner.sarif import GovernanceEvent, SarifReport, _make_result, compute_control_law


def _make_finding(
    *,
    rule_id: RuleId = RuleId.PY_WL_001,
    file_path: str = "src/example.py",
    line: int = 10,
    col: int = 4,
    end_line: int | None = 10,
    end_col: int | None = 30,
    message: str = "Use .get() with a default",
    severity: Severity = Severity.ERROR,
    exceptionability: Exceptionability = Exceptionability.STANDARD,
    taint_state: object = None,
    analysis_level: int = 1,
    source_snippet: str | None = None,
    qualname: str | None = None,
    retroactive_scan: bool = False,
    exception_id: str | None = None,
    annotation_groups: tuple[int, ...] = (),
    data_source: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        col=col,
        end_line=end_line,
        end_col=end_col,
        message=message,
        severity=severity,
        exceptionability=exceptionability,
        taint_state=taint_state,
        analysis_level=analysis_level,
        source_snippet=source_snippet,
        qualname=qualname,
        retroactive_scan=retroactive_scan,
        exception_id=exception_id,
        annotation_groups=annotation_groups,
        data_source=data_source,
    )


# ---------------------------------------------------------------------------
# TestSarifStructure
# ---------------------------------------------------------------------------


class TestSarifStructure:
    def test_empty_report_valid_structure(self) -> None:
        report = SarifReport(findings=[], verification_mode=True)
        d = report.to_dict()
        assert d["version"] == "2.1.0"
        assert len(d["runs"]) == 1
        assert d["runs"][0]["results"] == []

    def test_schema_version(self) -> None:
        report = SarifReport(findings=[], verification_mode=True)
        d = report.to_dict()
        assert d["$schema"].endswith("sarif-schema-2.1.0.json")
        assert d["version"] == "2.1.0"

    def test_tool_info(self) -> None:
        report = SarifReport(findings=[], tool_version="1.2.3")
        d = report.to_dict()
        driver = d["runs"][0]["tool"]["driver"]
        assert driver["name"] == "wardline"
        assert driver["version"] == "1.2.3"
        assert driver["informationUri"] == "https://wardline.dev"


# ---------------------------------------------------------------------------
# TestSarifResults
# ---------------------------------------------------------------------------


class TestSarifResults:
    def test_single_finding_produces_result(self) -> None:
        report = SarifReport(findings=[_make_finding()])
        d = report.to_dict()
        assert len(d["runs"][0]["results"]) == 1

    def test_result_has_required_fields(self) -> None:
        report = SarifReport(findings=[_make_finding()])
        result = report.to_dict()["runs"][0]["results"][0]
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result

    def test_result_property_bag(self) -> None:
        report = SarifReport(findings=[_make_finding()])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        assert "wardline.rule" in props
        assert "wardline.taintState" in props
        assert "wardline.severity" in props
        assert "wardline.exceptionability" in props
        assert "wardline.analysisLevel" in props

    def test_result_property_bag_contains_explicit_taint_state(self) -> None:
        report = SarifReport(findings=[_make_finding(taint_state="ASSURED")])
        result = report.to_dict()["runs"][0]["results"][0]
        assert result["properties"]["wardline.taintState"] == "ASSURED"

    def test_result_property_bag_defaults_taint_state_when_missing(self) -> None:
        report = SarifReport(findings=[_make_finding(taint_state=None)])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        assert props["wardline.taintState"] is None

    def test_mandatory_properties_never_omitted(self) -> None:
        """All mandatory properties (§A.3) present even when taint_state is None."""
        report = SarifReport(findings=[_make_finding(taint_state=None)])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        mandatory = [
            "wardline.rule",
            "wardline.taintState",
            "wardline.severity",
            "wardline.exceptionability",
            "wardline.analysisLevel",
        ]
        nullable = {"wardline.taintState", "wardline.enclosingTier", "wardline.dataSource"}
        for key in mandatory:
            assert key in props, f"mandatory key {key!r} missing from properties"
            if key not in nullable:
                assert props[key] is not None, f"mandatory key {key!r} is None"

    def test_no_unknown_string_in_taint_state(self) -> None:
        """No non-canonical 'UNKNOWN' token in taintState — must be null or canonical."""
        report = SarifReport(findings=[_make_finding(taint_state=None)])
        sarif = json.loads(report.to_json_string())
        for result in sarif["runs"][0]["results"]:
            ts = result["properties"]["wardline.taintState"]
            assert ts is None or ts in {
                "INTEGRAL", "ASSURED", "GUARDED", "EXTERNAL_RAW",
                "UNKNOWN_RAW", "UNKNOWN_GUARDED", "UNKNOWN_ASSURED", "MIXED_RAW",
            }, f"Non-canonical taintState: {ts!r}"

    def test_result_property_bag_qualname_and_snippet(self) -> None:
        """wardline.qualname and wardline.sourceSnippet appear when set."""
        finding = _make_finding(qualname="MyClass.handle", source_snippet="x = 1")
        report = SarifReport(findings=[finding])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        assert props["wardline.qualname"] == "MyClass.handle"
        assert props["wardline.sourceSnippet"] == "x = 1"

    def test_result_property_bag_omits_none_qualname(self) -> None:
        """None-valued qualname and sourceSnippet are omitted (not serialized as null)."""
        report = SarifReport(findings=[_make_finding()])
        result = report.to_dict()["runs"][0]["results"][0]
        props = result["properties"]
        assert "wardline.qualname" not in props
        assert "wardline.sourceSnippet" not in props

    def test_sarif_level_mapping(self) -> None:
        err = _make_finding(severity=Severity.ERROR)
        warn = _make_finding(severity=Severity.WARNING, line=20)
        report = SarifReport(findings=[err, warn])
        results = report.to_dict()["runs"][0]["results"]
        # Both have same ruleId; check by line instead.
        level_by_line = {
            r["locations"][0]["physicalLocation"]["region"]["startLine"]: r["level"]
            for r in results
        }
        assert level_by_line[10] == "error"
        assert level_by_line[20] == "warning"

    def test_suppress_severity_maps_to_note_level(self) -> None:
        """SUPPRESS findings must emit SARIF level 'note', not 'error' or 'warning'.

        SUPPRESS means the pattern is *expected* at this taint level — it is
        not a violation.  SARIF 'note' is the correct level for informational
        findings that should not trigger review queues.
        """
        finding = _make_finding(
            severity=Severity.SUPPRESS,
            exceptionability=Exceptionability.TRANSPARENT,
        )
        report = SarifReport(findings=[finding])
        result = report.to_dict()["runs"][0]["results"][0]
        assert result["level"] == "note", (
            f"SUPPRESS finding must have SARIF level 'note', got {result['level']!r}"
        )

    def test_suppress_sarif_level_all_three_variants(self) -> None:
        """All three severity levels map to distinct SARIF levels."""
        suppress = _make_finding(severity=Severity.SUPPRESS, line=1)
        warning = _make_finding(severity=Severity.WARNING, line=2)
        error = _make_finding(severity=Severity.ERROR, line=3)
        report = SarifReport(findings=[suppress, warning, error])
        results = report.to_dict()["runs"][0]["results"]
        level_by_line = {
            r["locations"][0]["physicalLocation"]["region"]["startLine"]: r["level"]
            for r in results
        }
        assert level_by_line[1] == "note"
        assert level_by_line[2] == "warning"
        assert level_by_line[3] == "error"

    def test_column_is_1_based(self) -> None:
        finding = _make_finding(col=0, end_col=5)
        report = SarifReport(findings=[finding])
        region = (
            report.to_dict()["runs"][0]["results"][0]["locations"][0][
                "physicalLocation"
            ]["region"]
        )
        assert region["startColumn"] == 1
        assert region["endColumn"] == 6

    def test_absolute_file_path_is_made_relative_to_base_path(self) -> None:
        report = SarifReport(
            findings=[
                _make_finding(file_path="/repo/src/example.py"),
            ],
            base_path="/repo",
        )
        result = report.to_dict()["runs"][0]["results"][0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/example.py"


# ---------------------------------------------------------------------------
# TestR1ResultProperties
# ---------------------------------------------------------------------------


class TestR1ResultProperties:
    """R1: enclosingTier, annotationGroups, excepted, dataSource (§10.1)."""

    @pytest.mark.parametrize("taint,expected_tier", [
        (TaintState.INTEGRAL, 1),
        (TaintState.ASSURED, 2),
        (TaintState.GUARDED, 3),
        (TaintState.UNKNOWN_ASSURED, 3),
        (TaintState.UNKNOWN_GUARDED, 3),
        (TaintState.EXTERNAL_RAW, 4),
        (TaintState.UNKNOWN_RAW, 4),
        (TaintState.MIXED_RAW, 4),
        (None, None),
    ])
    def test_enclosing_tier_from_taint_state(self, taint, expected_tier) -> None:
        """enclosingTier derived from TAINT_TO_TIER for all 8 states + None."""
        finding = _make_finding(taint_state=taint)
        result = _make_result(finding, base_path=None)
        assert result["properties"]["wardline.enclosingTier"] == expected_tier

    def test_annotation_groups_sorted(self) -> None:
        """Annotation groups appear sorted in result properties."""
        finding = _make_finding(annotation_groups=(5, 1, 12))
        result = _make_result(finding, base_path=None)
        assert result["properties"]["wardline.annotationGroups"] == [1, 5, 12]

    def test_annotation_groups_empty(self) -> None:
        """No annotations -> empty list."""
        finding = _make_finding(annotation_groups=())
        result = _make_result(finding, base_path=None)
        assert result["properties"]["wardline.annotationGroups"] == []

    def test_annotation_groups_deduplicated(self) -> None:
        """Duplicate group numbers are deduplicated at emission time."""
        finding = _make_finding(annotation_groups=(3, 1, 3, 1))
        result = _make_result(finding, base_path=None)
        assert result["properties"]["wardline.annotationGroups"] == [1, 3]

    def test_excepted_true_when_exception_id_set(self) -> None:
        """Finding with exception_id -> excepted True."""
        finding = _make_finding(exception_id="EXC-001")
        result = _make_result(finding, base_path=None)
        assert result["properties"]["wardline.excepted"] is True

    def test_excepted_false_when_no_exception(self) -> None:
        """Finding without exception_id -> excepted False."""
        finding = _make_finding(exception_id=None)
        result = _make_result(finding, base_path=None)
        assert result["properties"]["wardline.excepted"] is False

    def test_data_source_null_by_default(self) -> None:
        """Data source is null when not set."""
        finding = _make_finding()
        result = _make_result(finding, base_path=None)
        assert result["properties"]["wardline.dataSource"] is None

    def test_data_source_string_when_set(self) -> None:
        """Data source appears as string when set."""
        finding = _make_finding(data_source="partner-api")
        result = _make_result(finding, base_path=None)
        assert result["properties"]["wardline.dataSource"] == "partner-api"

    def test_nullable_mandatory_properties_present_as_keys(self) -> None:
        """Nullable mandatory properties present as KEYS even when null."""
        finding = _make_finding(taint_state=None, data_source=None)
        result = _make_result(finding, base_path=None)
        props = result["properties"]
        assert "wardline.enclosingTier" in props
        assert "wardline.dataSource" in props
        assert "wardline.taintState" in props
        assert props["wardline.enclosingTier"] is None
        assert props["wardline.dataSource"] is None
        assert props["wardline.taintState"] is None

    def test_all_mandatory_result_properties_present(self) -> None:
        """All 9 mandatory result-level properties present (§10.1)."""
        finding = _make_finding(taint_state=TaintState.INTEGRAL)
        result = _make_result(finding, base_path=None)
        props = set(result["properties"].keys())
        required = {
            "wardline.rule", "wardline.taintState", "wardline.severity",
            "wardline.exceptionability", "wardline.analysisLevel",
            "wardline.enclosingTier", "wardline.annotationGroups",
            "wardline.excepted", "wardline.dataSource",
        }
        missing = required - props
        assert not missing, f"Missing mandatory properties: {missing}"


# ---------------------------------------------------------------------------
# TestSarifDeterminism
# ---------------------------------------------------------------------------


class TestSarifDeterminism:
    def test_results_sorted_by_file_and_line(self) -> None:
        f1 = _make_finding(file_path="z.py", line=1)
        f2 = _make_finding(file_path="a.py", line=5)
        f3 = _make_finding(file_path="a.py", line=2)
        report = SarifReport(findings=[f1, f2, f3])
        results = report.to_dict()["runs"][0]["results"]
        locations = [
            (
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                r["locations"][0]["physicalLocation"]["region"]["startLine"],
            )
            for r in results
        ]
        assert locations == [("a.py", 2), ("a.py", 5), ("z.py", 1)]

    def test_same_input_same_output(self) -> None:
        findings = [_make_finding(), _make_finding(line=20)]
        r1 = SarifReport(findings=findings, verification_mode=True)
        r2 = SarifReport(findings=findings, verification_mode=True)
        assert r1.to_json_string() == r2.to_json_string()

    def test_verification_mode_omits_timestamps(self) -> None:
        report = SarifReport(
            findings=[_make_finding()], verification_mode=True
        )
        text = report.to_json_string()
        assert "timestamp" not in text.lower()
        assert "invocationStartTimeUtc" not in text
        assert "invocationEndTimeUtc" not in text


# ---------------------------------------------------------------------------
# TestSarifRuleDescriptors
# ---------------------------------------------------------------------------


class TestSarifRuleDescriptors:
    def test_rule_descriptors_generated(self) -> None:
        report = SarifReport(findings=[_make_finding()])
        rules = report.to_dict()["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "PY-WL-001"

    def test_governed_default_not_in_implemented_rules(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        implemented = props["wardline.implementedRules"]
        assert "PY-WL-001-GOVERNED-DEFAULT" not in implemented
        # But canonical rules are present.
        assert "PY-WL-001" in implemented

    def test_conformance_gaps_empty(self) -> None:
        """Conformance gaps must remain empty after WP 1.3."""
        report = SarifReport(findings=[])
        output = report.to_dict()
        gaps = output["runs"][0]["properties"]["wardline.conformanceGaps"]
        assert gaps == []

    def test_canonical_rule_short_descriptions_are_authoritative(self) -> None:
        findings = [
            _make_finding(rule_id=RuleId.PY_WL_001),
            _make_finding(rule_id=RuleId.PY_WL_002, line=20),
            _make_finding(rule_id=RuleId.PY_WL_003, line=30),
            _make_finding(rule_id=RuleId.PY_WL_004, line=40),
            _make_finding(rule_id=RuleId.PY_WL_005, line=50),
            _make_finding(rule_id=RuleId.PY_WL_006, line=60),
            _make_finding(rule_id=RuleId.PY_WL_007, line=70),
            _make_finding(rule_id=RuleId.PY_WL_008, line=80),
            _make_finding(rule_id=RuleId.PY_WL_009, line=90),
        ]
        report = SarifReport(findings=findings)
        rules = report.to_dict()["runs"][0]["tool"]["driver"]["rules"]
        descriptions = {rule["id"]: rule["shortDescription"]["text"] for rule in rules}

        assert descriptions["PY-WL-001"] == "Dict key access with fallback default"
        assert descriptions["PY-WL-002"] == "Attribute access with fallback default"
        assert descriptions["PY-WL-003"] == "Existence-checking as structural gate"
        assert descriptions["PY-WL-004"] == "Broad exception handler"
        assert descriptions["PY-WL-005"] == "Silent exception handler"
        assert descriptions["PY-WL-006"] == "Audit-critical write in broad exception handler"
        assert descriptions["PY-WL-007"] == "Runtime type-checking on internal data"
        assert descriptions["PY-WL-008"] == "Validation boundary with no rejection path"
        assert descriptions["PY-WL-009"] == "Semantic validation without prior shape validation"


# ---------------------------------------------------------------------------
# TestSarifPropertyBags
# ---------------------------------------------------------------------------


class TestSarifPropertyBags:
    def test_run_level_property_bag(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.propertyBagVersion" in props
        assert "wardline.governanceProfile" in props
        assert "wardline.implementedRules" in props
        assert "wardline.conformanceGaps" in props
        assert "wardline.unknownRawFunctionCount" in props
        assert "wardline.unresolvedDecoratorCount" in props

    def test_governance_profile_defaults_to_lite(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.governanceProfile"] == "lite"

    def test_governance_profile_wired(self) -> None:
        report = SarifReport(findings=[], governance_profile="assurance")
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.governanceProfile"] == "assurance"

    def test_unknown_raw_count_defaults_to_zero(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.unknownRawFunctionCount"] == 0
        assert props["wardline.unresolvedDecoratorCount"] == 0

    def test_unknown_raw_count_wired(self) -> None:
        report = SarifReport(
            findings=[], unknown_raw_count=5, unresolved_decorator_count=3
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.unknownRawFunctionCount"] == 5
        assert props["wardline.unresolvedDecoratorCount"] == 3

    def test_files_with_degraded_taint_defaults_to_zero(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.filesWithDegradedTaint"] == 0

    def test_files_with_degraded_taint_wired(self) -> None:
        report = SarifReport(findings=[], files_with_degraded_taint=2)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.filesWithDegradedTaint"] == 2

    def test_property_bag_version(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.propertyBagVersion"] == "0.5"

    def test_input_hash_always_emitted(self) -> None:
        """wardline.inputHash is always present in run properties."""
        report = SarifReport(findings=[], input_hash="sha256:abc123")
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.inputHash"] == "sha256:abc123"

    def test_input_hash_empty_string_default(self) -> None:
        """Default empty input_hash emits empty string (not absent)."""
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.inputHash" in props
        assert props["wardline.inputHash"] == ""

    def test_input_files_always_emitted(self) -> None:
        """wardline.inputFiles is always present, defaults to 0."""
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.inputFiles"] == 0

    def test_input_files_wired(self) -> None:
        report = SarifReport(findings=[], input_files=42)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.inputFiles"] == 42

    def test_overlay_hashes_always_emitted(self) -> None:
        """wardline.overlayHashes is always present (empty list when no overlays)."""
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.overlayHashes"] == []

    def test_overlay_hashes_with_entries(self) -> None:
        report = SarifReport(
            findings=[],
            overlay_hashes=("sha256:aaa", "sha256:bbb"),
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.overlayHashes"] == ["sha256:aaa", "sha256:bbb"]

    def test_coverage_ratio_omitted_when_none(self) -> None:
        """wardline.coverageRatio is absent when coverage_ratio is None."""
        report = SarifReport(findings=[], coverage_ratio=None)
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.coverageRatio" not in props

    def test_coverage_ratio_present_when_set(self) -> None:
        report = SarifReport(findings=[], coverage_ratio=0.73456789)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.coverageRatio"] == 0.7346

    def test_coverage_ratio_zero_is_emitted(self) -> None:
        """coverageRatio 0.0 is emitted (distinct from None/absent)."""
        report = SarifReport(findings=[], coverage_ratio=0.0)
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.coverageRatio" in props
        assert props["wardline.coverageRatio"] == 0.0

    def test_input_hash_not_suppressed_in_verification_mode(self) -> None:
        """inputHash is deterministic — present even in verification mode."""
        report = SarifReport(
            findings=[],
            verification_mode=True,
            input_hash="sha256:abc",
            input_files=5,
            overlay_hashes=("sha256:def",),
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.inputHash"] == "sha256:abc"
        assert props["wardline.inputFiles"] == 5
        assert props["wardline.overlayHashes"] == ["sha256:def"]

    def test_conformance_gaps_from_field(self) -> None:
        """conformanceGaps populated from field, not hardcoded."""
        report = SarifReport(
            findings=[],
            conformance_gaps=("gap A", "gap B"),
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.conformanceGaps"] == ["gap A", "gap B"]

    def test_conformance_gaps_default_empty(self) -> None:
        """No gaps declared = empty list (still present)."""
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.conformanceGaps"] == []

    def test_suppressed_cell_finding_count_increments_for_suppress_findings(
        self,
    ) -> None:
        """wardline.suppressedCellFindingCount counts SUPPRESS-severity findings.

        SUPPRESS findings are emitted into SARIF (not dropped) so they appear
        in the diagnostic counters.  The gateBlockingCount must remain zero for
        these findings.
        """
        suppress1 = _make_finding(
            severity=Severity.SUPPRESS,
            exceptionability=Exceptionability.TRANSPARENT,
            line=1,
        )
        suppress2 = _make_finding(
            severity=Severity.SUPPRESS,
            exceptionability=Exceptionability.TRANSPARENT,
            line=2,
        )
        error = _make_finding(severity=Severity.ERROR, line=3)
        report = SarifReport(findings=[suppress1, suppress2, error])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.suppressedCellFindingCount"] == 2
        assert props["wardline.errorFindingCount"] == 1
        assert props["wardline.gateBlockingCount"] == 1

    def test_suppress_findings_do_not_increment_gate_blocking_count(self) -> None:
        """SUPPRESS findings must not contribute to wardline.gateBlockingCount."""
        findings = [
            _make_finding(
                severity=Severity.SUPPRESS,
                exceptionability=Exceptionability.TRANSPARENT,
                line=i,
            )
            for i in range(1, 6)
        ]
        report = SarifReport(findings=findings)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.gateBlockingCount"] == 0
        assert props["wardline.suppressedCellFindingCount"] == 5


# ---------------------------------------------------------------------------
# TestSarifOutput
# ---------------------------------------------------------------------------


class TestSarifOutput:
    def test_to_json_writes_file(self, tmp_path: Path) -> None:
        report = SarifReport(findings=[_make_finding()])
        out = tmp_path / "report.sarif"
        report.to_json(out)
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"

    def test_to_json_string(self) -> None:
        report = SarifReport(findings=[_make_finding()])
        text = report.to_json_string()
        data = json.loads(text)
        assert data["version"] == "2.1.0"

    def test_json_breaking_characters(self) -> None:
        finding = _make_finding(
            message='He said "hello"\nand then\ttabbed'
        )
        report = SarifReport(findings=[finding])
        text = report.to_json_string()
        # Must parse cleanly — no broken JSON from special chars.
        data = json.loads(text)
        result = data["runs"][0]["results"][0]
        assert '"hello"' in result["message"]["text"]
        assert "\n" in result["message"]["text"]


# ---------------------------------------------------------------------------
# TestSarifGovernanceMetadata
# ---------------------------------------------------------------------------


class TestSarifGovernanceMetadata:
    """Tests for WP 2.4 governance metadata fields in run-level properties."""

    def test_analysis_level_in_run_properties(self) -> None:
        report = SarifReport(findings=[], analysis_level=3)
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.analysisLevel"] == 3

    def test_analysis_level_defaults_to_1(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.analysisLevel"] == 1

    def test_manifest_hash_present_when_set(self) -> None:
        report = SarifReport(findings=[], manifest_hash="abc123def")
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.manifestHash"] == "abc123def"

    def test_manifest_hash_none_when_not_set(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.manifestHash" in props
        assert props["wardline.manifestHash"] is None

    def test_scan_timestamp_present_when_not_verification_mode(self) -> None:
        report = SarifReport(
            findings=[],
            verification_mode=False,
            scan_timestamp="2026-03-24T12:00:00Z",
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.scanTimestamp"] == "2026-03-24T12:00:00Z"

    def test_scan_timestamp_absent_in_verification_mode(self) -> None:
        report = SarifReport(
            findings=[],
            verification_mode=True,
            scan_timestamp="2026-03-24T12:00:00Z",
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.scanTimestamp" not in props

    def test_commit_ref_present_when_not_verification_mode(self) -> None:
        report = SarifReport(
            findings=[],
            verification_mode=False,
            commit_ref="a1b2c3d4",
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.commitRef"] == "a1b2c3d4"

    def test_commit_ref_absent_in_verification_mode(self) -> None:
        report = SarifReport(
            findings=[],
            verification_mode=True,
            commit_ref="a1b2c3d4",
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.commitRef" not in props

    def test_control_law_defaults_to_normal(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.controlLaw"] == "normal"

    def test_control_law_propagated_to_run_properties(self) -> None:
        report = SarifReport(findings=[], control_law="alternate")
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.controlLaw"] == "alternate"

    def test_defaults_all_none_except_analysis_level(self) -> None:
        report = SarifReport(findings=[])
        assert report.analysis_level == 1
        assert report.control_law == "normal"
        assert report.manifest_hash is None
        assert report.scan_timestamp is None
        assert report.commit_ref is None


# ---------------------------------------------------------------------------
# TestComputeControlLaw
# ---------------------------------------------------------------------------


class TestComputeControlLaw:
    """Tests for §9.5 control law computation."""

    def test_normal_when_no_degradation(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=False,
            conformance_gaps=(),
            rules_disabled=(),
            stale_exception_count=0,
        )
        assert law == "normal"
        assert degradations == ()

    def test_alternate_when_ratification_overdue(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=True,
            conformance_gaps=(),
            rules_disabled=(),
            stale_exception_count=0,
        )
        assert law == "alternate"
        assert "ratification_overdue" in degradations

    def test_alternate_when_conformance_gaps(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=False,
            conformance_gaps=("SARIF-run-level-incomplete",),
            rules_disabled=(),
            stale_exception_count=0,
        )
        assert law == "alternate"
        assert "conformance_gaps_present" in degradations

    def test_alternate_when_rules_disabled(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=False,
            conformance_gaps=(),
            rules_disabled=("PY-WL-006", "PY-WL-007"),
            stale_exception_count=0,
        )
        assert law == "alternate"
        assert "rules_disabled" in degradations

    def test_alternate_when_stale_exceptions(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=False,
            conformance_gaps=(),
            rules_disabled=(),
            stale_exception_count=3,
        )
        assert law == "alternate"
        assert "stale_exceptions_present" in degradations

    def test_multiple_degradations_all_reported(self) -> None:
        law, degradations = compute_control_law(
            ratification_overdue=True,
            conformance_gaps=("gap-1",),
            rules_disabled=("PY-WL-006",),
            stale_exception_count=1,
        )
        assert law == "alternate"
        assert len(degradations) == 4

    def test_degradations_are_sorted(self) -> None:
        """Deterministic output for verification mode."""
        law, degradations = compute_control_law(
            ratification_overdue=True,
            conformance_gaps=("gap-1",),
            rules_disabled=(),
            stale_exception_count=0,
        )
        assert degradations == tuple(sorted(degradations))

    def test_compute_and_report_integration(self) -> None:
        """Verify compute_control_law output feeds SarifReport correctly."""
        law, degradations = compute_control_law(
            ratification_overdue=True,
            stale_exception_count=2,
        )
        report = SarifReport(
            findings=[],
            control_law=law,
            control_law_degradations=degradations,
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.controlLaw"] == "alternate"
        assert "ratification_overdue" in props["wardline.controlLawDegradations"]
        assert "stale_exceptions_present" in props["wardline.controlLawDegradations"]

    def test_direct_when_manifest_unavailable(self) -> None:
        """manifest_unavailable=True -> direct law."""
        law, degradations = compute_control_law(manifest_unavailable=True)
        assert law == "direct"
        assert degradations == ("manifest_unavailable",)

    def test_direct_overrides_other_degradations(self) -> None:
        """Direct law takes precedence over alternate-law conditions."""
        law, _degradations = compute_control_law(
            manifest_unavailable=True,
            ratification_overdue=True,
            rules_disabled=("PY-WL-001",),
        )
        assert law == "direct"

    def test_direct_law_emitted_in_sarif(self) -> None:
        """SARIF run properties include 'direct' when control law is direct."""
        report = SarifReport(
            findings=[],
            control_law="direct",
            control_law_degradations=("manifest_unavailable",),
        )
        sarif = report.to_dict()
        run_props = sarif["runs"][0]["properties"]
        assert run_props["wardline.controlLaw"] == "direct"
        assert run_props["wardline.controlLawDegradations"] == ["manifest_unavailable"]


# ---------------------------------------------------------------------------
# TestControlLawDegradationsEmission
# ---------------------------------------------------------------------------


class TestControlLawDegradationsEmission:
    """SARIF emission of wardline.controlLawDegradations."""

    def test_degradations_omitted_when_normal(self) -> None:
        report = SarifReport(findings=[], control_law="normal")
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.controlLawDegradations" not in props

    def test_degradations_emitted_when_alternate(self) -> None:
        report = SarifReport(
            findings=[],
            control_law="alternate",
            control_law_degradations=("ratification_overdue", "stale_exceptions_present"),
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.controlLawDegradations"] == [
            "ratification_overdue", "stale_exceptions_present"
        ]


# ---------------------------------------------------------------------------
# TestRetrospectiveScan
# ---------------------------------------------------------------------------


class TestRetrospectiveScan:
    """§9.5 retrospective scan SARIF properties."""

    def test_run_level_retroactive_scan_emitted(self) -> None:
        report = SarifReport(
            findings=[],
            retroactive_scan=True,
            retroactive_scan_range="abc123..def456",
        )
        props = report.to_dict()["runs"][0]["properties"]
        assert props["wardline.retroactiveScan"] is True
        assert props["wardline.retroactiveScanRange"] == "abc123..def456"

    def test_run_level_retroactive_omitted_when_false(self) -> None:
        report = SarifReport(findings=[])
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.retroactiveScan" not in props
        assert "wardline.retroactiveScanRange" not in props

    def test_result_level_retroactive_scan_emitted(self) -> None:
        finding = _make_finding(retroactive_scan=True)
        report = SarifReport(findings=[finding])
        result = report.to_dict()["runs"][0]["results"][0]
        assert result["properties"]["wardline.retroactiveScan"] is True

    def test_result_level_retroactive_omitted_when_false(self) -> None:
        finding = _make_finding()
        report = SarifReport(findings=[finding])
        result = report.to_dict()["runs"][0]["results"][0]
        assert "wardline.retroactiveScan" not in result["properties"]


# ---------------------------------------------------------------------------
# TestGovernanceEvents
# ---------------------------------------------------------------------------


class TestGovernanceEvents:
    """Tests for §9 governance audit event logging in SARIF (GOV-005)."""

    def test_no_events_omitted_from_sarif(self) -> None:
        """Empty governance_events -> no wardline.governanceEvents in SARIF."""
        report = SarifReport(findings=[], governance_events=())
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.governanceEvents" not in props

    def test_events_emitted_in_sarif(self) -> None:
        """GovernanceEvent objects appear as structured array in run properties."""
        events = (
            GovernanceEvent(
                event_type="exception_expired",
                message="Exception 'EX-001' has stale AST fingerprint",
                timestamp="2026-03-29T10:00:00Z",
            ),
            GovernanceEvent(
                event_type="control_law_transition",
                message="Control law is 'alternate' due to: stale_exceptions_present",
            ),
        )
        report = SarifReport(findings=[], governance_events=events)
        props = report.to_dict()["runs"][0]["properties"]
        assert "wardline.governanceEvents" in props
        gov_events = props["wardline.governanceEvents"]
        assert len(gov_events) == 2
        assert gov_events[0]["eventType"] == "exception_expired"
        assert gov_events[0]["message"] == "Exception 'EX-001' has stale AST fingerprint"
        assert gov_events[0]["timestamp"] == "2026-03-29T10:00:00Z"
        assert gov_events[1]["eventType"] == "control_law_transition"
        assert gov_events[1]["message"] == "Control law is 'alternate' due to: stale_exceptions_present"

    def test_event_timestamp_omitted_when_none(self) -> None:
        """Events without timestamp don't include the timestamp key."""
        events = (
            GovernanceEvent(
                event_type="ratification_renewed",
                message="Manifest ratification is overdue",
            ),
        )
        report = SarifReport(findings=[], governance_events=events)
        props = report.to_dict()["runs"][0]["properties"]
        gov_events = props["wardline.governanceEvents"]
        assert len(gov_events) == 1
        assert "timestamp" not in gov_events[0]
        assert gov_events[0]["eventType"] == "ratification_renewed"

    def test_all_seven_event_types_accepted(self) -> None:
        """All 7 governance event types can be represented."""
        event_types = [
            "exception_created",
            "exception_expired",
            "exception_escalated",
            "tier_change",
            "ratification_renewed",
            "fingerprint_changed",
            "control_law_transition",
        ]
        events = tuple(
            GovernanceEvent(event_type=et, message=f"Test {et}")
            for et in event_types
        )
        report = SarifReport(findings=[], governance_events=events)
        props = report.to_dict()["runs"][0]["properties"]
        gov_events = props["wardline.governanceEvents"]
        assert len(gov_events) == 7
        emitted_types = [e["eventType"] for e in gov_events]
        assert emitted_types == event_types

    def test_governance_event_frozen(self) -> None:
        """GovernanceEvent is frozen — attributes cannot be mutated."""
        event = GovernanceEvent(event_type="tier_change", message="test")
        import pytest
        with pytest.raises(AttributeError):
            event.event_type = "other"  # type: ignore[misc]
