"""Tests for manifest data models — construction, immutability, from_toml."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from types import MappingProxyType
from typing import TYPE_CHECKING

import pytest

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState
from wardline.manifest.models import (
    BoundaryEntry,
    ContractBinding,
    DelegationConfig,
    DelegationGrant,
    DependencyTaintEntry,
    ExceptionEntry,
    FingerprintEntry,
    ManifestMetadata,
    ModuleTierEntry,
    RulesConfig,
    ScannerConfig,
    ScannerConfigError,
    TemporalSeparation,
    TierEntry,
    WardlineManifest,
    WardlineOverlay,
)

if TYPE_CHECKING:
    from pathlib import Path

# ── ExceptionEntry ────────────────────────────────────────────────


class TestExceptionEntry:
    def test_construction(self) -> None:
        e = ExceptionEntry(
            id="EXC-001",
            rule="PY-WL-004",
            taint_state="EXTERNAL_RAW",
            location="src/adapters.py:42",
            exceptionability="STANDARD",
            severity_at_grant="WARNING",
            rationale="Intentional broad catch for logging",
            reviewer="jsmith",
        )
        assert e.id == "EXC-001"
        assert e.rule == "PY-WL-004"

    def test_frozen(self) -> None:
        e = ExceptionEntry(
            id="EXC-001",
            rule="PY-WL-004",
            taint_state="EXTERNAL_RAW",
            location="src/a.py:1",
            exceptionability="STANDARD",
            severity_at_grant="WARNING",
            rationale="reason",
            reviewer="r",
        )
        with pytest.raises(FrozenInstanceError):
            e.id = "EXC-002"  # type: ignore[misc]

    def test_optional_fields(self) -> None:
        e = ExceptionEntry(
            id="E1",
            rule="PY-WL-001",
            taint_state="EXTERNAL_RAW",
            location="L",
            exceptionability="STANDARD",
            severity_at_grant="WARNING",
            rationale="reason",
            reviewer="reviewer",
            expires="2026-12-31",
            provenance="manual",
        )
        assert e.expires == "2026-12-31"
        assert e.provenance == "manual"


class TestExceptionEntryNewFields:
    """Verify new governance and fingerprint fields on ExceptionEntry."""

    def _make_entry(self, **overrides: object) -> ExceptionEntry:
        defaults = dict(
            id="EXC-NEW",
            rule="PY-WL-004",
            taint_state="EXTERNAL_RAW",
            location="src/a.py:1",
            exceptionability="STANDARD",
            severity_at_grant="WARNING",
            rationale="reason",
            reviewer="r",
        )
        defaults.update(overrides)
        return ExceptionEntry(**defaults)  # type: ignore[arg-type]

    def test_ast_fingerprint_defaults_empty(self) -> None:
        assert self._make_entry().ast_fingerprint == ""

    def test_recurrence_count_defaults_zero(self) -> None:
        assert self._make_entry().recurrence_count == 0

    def test_governance_path_defaults_standard(self) -> None:
        assert self._make_entry().governance_path == "standard"

    def test_last_refreshed_by_defaults_none(self) -> None:
        assert self._make_entry().last_refreshed_by is None

    def test_last_refresh_rationale_defaults_none(self) -> None:
        assert self._make_entry().last_refresh_rationale is None

    def test_last_refreshed_at_defaults_none(self) -> None:
        assert self._make_entry().last_refreshed_at is None

    def test_new_fields_are_frozen(self) -> None:
        e = self._make_entry()
        with pytest.raises(FrozenInstanceError):
            e.ast_fingerprint = "CHANGED"  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            e.recurrence_count = 99  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            e.governance_path = "CHANGED"  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            e.last_refreshed_by = "CHANGED"  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            e.last_refresh_rationale = "CHANGED"  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            e.last_refreshed_at = "CHANGED"  # type: ignore[misc]


# ── FingerprintEntry ──────────────────────────────────────────────


class TestFingerprintEntry:
    def test_construction(self) -> None:
        f = FingerprintEntry(
            qualified_name="mymod.handler",
            module="mymod",
            decorators=("external_boundary",),
            annotation_hash="abc123",
            tier_context=4,
        )
        assert f.qualified_name == "mymod.handler"
        assert f.decorators == ("external_boundary",)

    def test_frozen(self) -> None:
        f = FingerprintEntry(
            qualified_name="x",
            module="m",
            decorators=(),
            annotation_hash="h",
            tier_context=1,
        )
        with pytest.raises(FrozenInstanceError):
            f.tier_context = 2  # type: ignore[misc]


# ── WardlineManifest ──────────────────────────────────────────────


class TestWardlineManifest:
    def test_construction_with_defaults(self) -> None:
        m = WardlineManifest()
        assert m.governance_profile == "lite"
        assert m.tiers == ()
        assert m.module_tiers == ()

    def test_construction_with_data(self) -> None:
        m = WardlineManifest(
            governance_profile="assurance",
            tiers=(
                TierEntry(id="db", tier=1, description="Database"),
                TierEntry(id="api", tier=4, description="External API"),
            ),
            module_tiers=(
                ModuleTierEntry(path="audit/", default_taint="INTEGRAL"),
            ),
            metadata=ManifestMetadata(
                organisation="TestOrg",
                ratification_date="2026-01-15",
                review_interval_days=180,
            ),
        )
        assert m.governance_profile == "assurance"
        assert len(m.tiers) == 2
        assert m.tiers[0].tier == 1
        assert m.metadata.organisation == "TestOrg"

    def test_frozen(self) -> None:
        m = WardlineManifest()
        with pytest.raises(FrozenInstanceError):
            m.tiers = ()  # type: ignore[misc]


# ── WardlineOverlay ───────────────────────────────────────────────


class TestWardlineOverlay:
    def test_construction(self) -> None:
        o = WardlineOverlay(
            overlay_for="adapters/",
            boundaries=(
                BoundaryEntry(
                    function="mymod.check_shape",
                    transition="shape_validation",
                    from_tier=4,
                    to_tier=3,
                ),
            ),
            contract_bindings=(
                ContractBinding(
                    contract="landscape_recording",
                    functions=("mymod.record",),
                ),
            ),
        )
        assert o.overlay_for == "adapters/"
        assert len(o.boundaries) == 1
        assert o.boundaries[0].transition == "shape_validation"
        assert len(o.contract_bindings) == 1

    def test_frozen(self) -> None:
        o = WardlineOverlay(overlay_for="x/")
        with pytest.raises(FrozenInstanceError):
            o.overlay_for = "y/"  # type: ignore[misc]

    def test_boundary_restoration(self) -> None:
        b = BoundaryEntry(
            function="mymod.load_audit",
            transition="restoration",
            restored_tier=1,
            provenance={
                "structural": True,
                "semantic": True,
                "integrity": "checksum",
                "institutional": "internal_db",
            },
        )
        assert b.restored_tier == 1
        assert b.from_tier is None
        assert b.provenance is not None


# ── BoundaryEntry overlay_scope ───────────────────────────────────


class TestBoundaryEntryOverlayScope:
    def test_overlay_scope_defaults_to_empty(self) -> None:
        b = BoundaryEntry(function="fn", transition="construction")
        assert b.overlay_scope == ""

    def test_overlay_scope_set_at_construction(self) -> None:
        b = BoundaryEntry(
            function="fn", transition="construction", overlay_scope="adapters/"
        )
        assert b.overlay_scope == "adapters/"


# ── DelegationConfig ──────────────────────────────────────────────


class TestDelegationConfig:
    def test_defaults(self) -> None:
        d = DelegationConfig()
        assert d.default_authority == "RELAXED"
        assert d.grants == ()

    def test_with_grants(self) -> None:
        d = DelegationConfig(
            default_authority="STANDARD",
            grants=(
                DelegationGrant(path="audit/", authority="NONE"),
            ),
        )
        assert d.grants[0].authority == "NONE"

    def test_frozen(self) -> None:
        d = DelegationConfig()
        with pytest.raises(FrozenInstanceError):
            d.default_authority = "NONE"  # type: ignore[misc]


# ── ScannerConfig ─────────────────────────────────────────────────


class TestScannerConfig:
    def test_defaults(self) -> None:
        c = ScannerConfig()
        assert c.target_paths == ()
        assert c.exclude_paths == ()
        assert c.enabled_rules == ()
        assert c.default_taint is None
        assert c.analysis_level == 1

    def test_frozen(self) -> None:
        c = ScannerConfig()
        with pytest.raises(FrozenInstanceError):
            c.analysis_level = 2  # type: ignore[misc]

    def test_from_toml(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "wardline.toml"
        toml_file.write_text("""\
[wardline]
target_paths = ["src/", "lib/"]
exclude_paths = ["src/vendor/"]
enabled_rules = ["PY-WL-001", "PY-WL-004"]
default_taint = "EXTERNAL_RAW"
analysis_level = 2
""")
        config = ScannerConfig.from_toml(toml_file)
        assert config.target_paths == (tmp_path / "src", tmp_path / "lib")
        assert config.exclude_paths == (tmp_path / "src" / "vendor",)
        assert config.enabled_rules == (
            RuleId.PY_WL_001,
            RuleId.PY_WL_004,
        )
        assert config.default_taint is TaintState.EXTERNAL_RAW
        assert config.analysis_level == 2

    def test_from_toml_minimal(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "wardline.toml"
        toml_file.write_text("[wardline]\n")
        config = ScannerConfig.from_toml(toml_file)
        assert config.target_paths == ()
        assert config.enabled_rules == ()
        assert config.default_taint is None
        assert config.analysis_level == 1

    def test_from_toml_uses_binary_mode(self, tmp_path: Path) -> None:
        """Verify from_toml works with UTF-8 content (binary mode)."""
        toml_file = tmp_path / "wardline.toml"
        toml_file.write_bytes(
            b'[wardline]\ntarget_paths = ["src/m\xc3\xb6dule/"]\n'
        )
        config = ScannerConfig.from_toml(toml_file)
        assert config.target_paths == (tmp_path / "src/mödule",)

    def test_from_toml_result_is_frozen(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "wardline.toml"
        toml_file.write_text("[wardline]\n")
        config = ScannerConfig.from_toml(toml_file)
        with pytest.raises(FrozenInstanceError):
            config.analysis_level = 3  # type: ignore[misc]

    @pytest.mark.parametrize("bad_value,toml_repr", [
        (True, "true"),
        (False, "false"),
        (0, "0"),
        (4, "4"),
        (-1, "-1"),
    ])
    def test_analysis_level_rejects_invalid(
        self, tmp_path: Path, bad_value: object, toml_repr: str
    ) -> None:
        toml_file = tmp_path / "wardline.toml"
        toml_file.write_text(
            f"[wardline]\nanalysis_level = {toml_repr}\n"
        )
        with pytest.raises(ScannerConfigError, match="analysis_level"):
            ScannerConfig.from_toml(toml_file)

    @pytest.mark.parametrize("level", [1, 2, 3])
    def test_analysis_level_accepts_valid(
        self, tmp_path: Path, level: int
    ) -> None:
        toml_file = tmp_path / "wardline.toml"
        toml_file.write_text(
            f"[wardline]\nanalysis_level = {level}\n"
        )
        config = ScannerConfig.from_toml(toml_file)
        assert config.analysis_level == level


# ── RulesConfig deep-freeze ──────────────────────────────────────


class TestRulesConfigDeepFreeze:
    """RulesConfig.overrides dicts are deep-frozen via MappingProxyType."""

    def test_overrides_are_mapping_proxy(self) -> None:
        rc = RulesConfig(overrides=({"id": "PY-WL-001", "severity": "ERROR"},))
        assert isinstance(rc.overrides[0], MappingProxyType)

    def test_overrides_immutable(self) -> None:
        rc = RulesConfig(overrides=({"id": "PY-WL-001", "severity": "ERROR"},))
        with pytest.raises(TypeError):
            rc.overrides[0]["severity"] = "WARNING"  # type: ignore[index]

    def test_empty_overrides(self) -> None:
        rc = RulesConfig()
        assert rc.overrides == ()

    def test_already_frozen_proxy_preserved(self) -> None:
        proxy = MappingProxyType({"id": "R1"})
        rc = RulesConfig(overrides=(proxy,))
        assert rc.overrides[0] is proxy


# ── TemporalSeparation ────────────────────────────────────────────


class TestTemporalSeparation:
    def test_defaults(self) -> None:
        ts = TemporalSeparation()
        assert ts.alternative == "same-actor-with-retrospective"
        assert ts.retrospective_window_days == 10
        assert ts.rationale == ""

    def test_enforced(self) -> None:
        ts = TemporalSeparation(alternative="enforced")
        assert ts.alternative == "enforced"

    def test_frozen(self) -> None:
        ts = TemporalSeparation()
        with pytest.raises(FrozenInstanceError):
            ts.alternative = "enforced"  # type: ignore[misc]

    def test_manifest_metadata_temporal_separation_none_means_undeclared(self) -> None:
        meta = ManifestMetadata(organisation="test")
        assert meta.temporal_separation is None

    def test_manifest_metadata_temporal_separation_round_trip(self) -> None:
        ts = TemporalSeparation(
            alternative="same-actor-with-retrospective",
            retrospective_window_days=15,
            rationale="small team",
        )
        meta = ManifestMetadata(organisation="test", temporal_separation=ts)
        assert meta.temporal_separation is not None
        assert meta.temporal_separation.alternative == "same-actor-with-retrospective"
        assert meta.temporal_separation.retrospective_window_days == 15
        assert meta.temporal_separation.rationale == "small team"


# ── ExceptionEntry enum field coercion ────────────────────────────


class TestExceptionEntryEnumFields:
    """ExceptionEntry stores enum values, not raw strings."""

    def test_construction_from_strings_coerces_to_enums(self) -> None:
        entry = ExceptionEntry(
            id="EXC-TEST",
            rule="PY-WL-004",
            taint_state="EXTERNAL_RAW",
            location="src/foo.py::bar",
            exceptionability="STANDARD",
            severity_at_grant="ERROR",
            rationale="test",
            reviewer="test",
        )
        assert isinstance(entry.rule, RuleId)
        assert isinstance(entry.taint_state, TaintState)
        assert isinstance(entry.exceptionability, Exceptionability)
        assert isinstance(entry.severity_at_grant, Severity)
        assert entry.rule == "PY-WL-004"
        assert entry.taint_state == "EXTERNAL_RAW"

    def test_construction_from_enums_works(self) -> None:
        entry = ExceptionEntry(
            id="EXC-TEST",
            rule=RuleId.PY_WL_004,
            taint_state=TaintState.EXTERNAL_RAW,
            location="src/foo.py::bar",
            exceptionability=Exceptionability.STANDARD,
            severity_at_grant=Severity.ERROR,
            rationale="test",
            reviewer="test",
        )
        assert entry.rule is RuleId.PY_WL_004
        assert entry.taint_state is TaintState.EXTERNAL_RAW

    def test_invalid_rule_raises(self) -> None:
        with pytest.raises(ValueError, match="INVALID"):
            ExceptionEntry(
                id="EXC-TEST",
                rule="INVALID",
                taint_state="EXTERNAL_RAW",
                location="src/foo.py::bar",
                exceptionability="STANDARD",
                severity_at_grant="ERROR",
                rationale="test",
                reviewer="test",
            )


# ── DependencyTaintEntry enum field coercion ──────────────────────


class TestDependencyTaintEntryEnumFields:
    def test_returns_taint_coerced_to_enum(self) -> None:
        entry = DependencyTaintEntry(
            package="requests",
            function="requests.get",
            returns_taint="EXTERNAL_RAW",
            rationale="HTTP response is external",
        )
        assert isinstance(entry.returns_taint, TaintState)
        assert entry.returns_taint == "EXTERNAL_RAW"

    def test_invalid_returns_taint_raises(self) -> None:
        with pytest.raises(ValueError, match="BOGUS"):
            DependencyTaintEntry(
                package="requests",
                function="requests.get",
                returns_taint="BOGUS",
                rationale="test",
            )
