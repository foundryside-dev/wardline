"""Tests for module_tiers auditability governance findings.

Covers:
- GOVERNANCE_MODULE_TIERS_BLANKET: >80% module_default with >=5 functions
- GOVERNANCE_MODULE_TIERS_UNDECORATED: high-trust taint, zero decorators
- --strict-governance exit code behavior
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.severity import RuleId
from wardline.manifest.models import ModuleTierEntry, WardlineManifest

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# GOVERNANCE_MODULE_TIERS_BLANKET
# ---------------------------------------------------------------------------

class TestBlanketSuppression:
    """Blanket module_tiers coverage fires when >80% of functions are module_default."""

    def test_blanket_fires_for_many_undecorated_functions(self, tmp_path: Path) -> None:
        from wardline.scanner.engine import ScanEngine

        # 6 functions, all governed by module_tiers, none decorated
        py_file = tmp_path / "big_module.py"
        py_file.write_text(
            "def a(): pass\n"
            "def b(): pass\n"
            "def c(): pass\n"
            "def d(): pass\n"
            "def e(): pass\n"
            "def f(): pass\n"
        )

        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path=str(tmp_path), default_taint="ASSURED"),
            ),
        )

        engine = ScanEngine(target_paths=(tmp_path,), rules=(), manifest=manifest)
        result = engine.scan()

        blanket = [
            f for f in result.findings
            if f.rule_id == RuleId.GOVERNANCE_MODULE_TIERS_BLANKET
        ]
        assert len(blanket) == 1
        assert "100%" in blanket[0].message
        assert "6/6" in blanket[0].message

    def test_blanket_does_not_fire_below_threshold(self, tmp_path: Path) -> None:
        from wardline.scanner.engine import ScanEngine

        # 6 functions, 4 decorated (67% module_default = below 80%)
        py_file = tmp_path / "mostly_decorated.py"
        py_file.write_text(
            "from wardline.decorators import external_boundary\n"
            "@external_boundary\ndef a(): pass\n"
            "@external_boundary\ndef b(): pass\n"
            "@external_boundary\ndef c(): pass\n"
            "@external_boundary\ndef d(): pass\n"
            "def e(): pass\n"
            "def f(): pass\n"
        )

        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path=str(tmp_path), default_taint="ASSURED"),
            ),
        )

        engine = ScanEngine(target_paths=(tmp_path,), rules=(), manifest=manifest)
        result = engine.scan()

        blanket = [
            f for f in result.findings
            if f.rule_id == RuleId.GOVERNANCE_MODULE_TIERS_BLANKET
        ]
        assert len(blanket) == 0

    def test_blanket_does_not_fire_for_small_files(self, tmp_path: Path) -> None:
        from wardline.scanner.engine import ScanEngine

        # 3 functions — below the >=5 minimum
        py_file = tmp_path / "small.py"
        py_file.write_text("def a(): pass\ndef b(): pass\ndef c(): pass\n")

        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path=str(tmp_path), default_taint="ASSURED"),
            ),
        )

        engine = ScanEngine(target_paths=(tmp_path,), rules=(), manifest=manifest)
        result = engine.scan()

        blanket = [
            f for f in result.findings
            if f.rule_id == RuleId.GOVERNANCE_MODULE_TIERS_BLANKET
        ]
        assert len(blanket) == 0


# ---------------------------------------------------------------------------
# GOVERNANCE_MODULE_TIERS_UNDECORATED
# ---------------------------------------------------------------------------

class TestUndecoratedHighTrust:
    """High-trust module_tiers with zero decorators fires governance finding."""

    def test_undecorated_fires_for_audit_trail(self, tmp_path: Path) -> None:
        from wardline.scanner.engine import ScanEngine

        py_file = tmp_path / "claimed_trusted.py"
        py_file.write_text("def handler(): pass\n")

        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path=str(tmp_path), default_taint="INTEGRAL"),
            ),
        )

        engine = ScanEngine(target_paths=(tmp_path,), rules=(), manifest=manifest)
        result = engine.scan()

        undecorated = [
            f for f in result.findings
            if f.rule_id == RuleId.GOVERNANCE_MODULE_TIERS_UNDECORATED
        ]
        assert len(undecorated) == 1
        assert "INTEGRAL" in undecorated[0].message
        assert "zero" in undecorated[0].message

    def test_undecorated_fires_for_pipeline(self, tmp_path: Path) -> None:
        from wardline.scanner.engine import ScanEngine

        py_file = tmp_path / "claimed_pipeline.py"
        py_file.write_text("def process(): pass\n")

        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path=str(tmp_path), default_taint="ASSURED"),
            ),
        )

        engine = ScanEngine(target_paths=(tmp_path,), rules=(), manifest=manifest)
        result = engine.scan()

        undecorated = [
            f for f in result.findings
            if f.rule_id == RuleId.GOVERNANCE_MODULE_TIERS_UNDECORATED
        ]
        assert len(undecorated) == 1

    def test_undecorated_does_not_fire_for_low_trust(self, tmp_path: Path) -> None:
        from wardline.scanner.engine import ScanEngine

        # EXTERNAL_RAW is low-trust — blanket application is expected
        py_file = tmp_path / "external.py"
        py_file.write_text("def ingest(): pass\n")

        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path=str(tmp_path), default_taint="EXTERNAL_RAW"),
            ),
        )

        engine = ScanEngine(target_paths=(tmp_path,), rules=(), manifest=manifest)
        result = engine.scan()

        undecorated = [
            f for f in result.findings
            if f.rule_id == RuleId.GOVERNANCE_MODULE_TIERS_UNDECORATED
        ]
        assert len(undecorated) == 0

    def test_undecorated_does_not_fire_with_decorators(self, tmp_path: Path) -> None:
        from wardline.scanner.engine import ScanEngine

        py_file = tmp_path / "decorated.py"
        py_file.write_text(
            "from wardline.decorators import integral_read\n"
            "@integral_read\ndef handler(): pass\n"
        )

        manifest = WardlineManifest(
            module_tiers=(
                ModuleTierEntry(path=str(tmp_path), default_taint="INTEGRAL"),
            ),
        )

        engine = ScanEngine(target_paths=(tmp_path,), rules=(), manifest=manifest)
        result = engine.scan()

        undecorated = [
            f for f in result.findings
            if f.rule_id == RuleId.GOVERNANCE_MODULE_TIERS_UNDECORATED
        ]
        assert len(undecorated) == 0


# ---------------------------------------------------------------------------
# --strict-governance flag
# ---------------------------------------------------------------------------

class TestStrictGovernance:
    """--strict-governance makes GOVERNANCE findings affect exit code."""

    def test_strict_governance_config_default_false(self, tmp_path: Path) -> None:
        from wardline.manifest.models import ScannerConfig

        toml_file = tmp_path / "wardline.toml"
        toml_file.write_text("[wardline]\n")
        cfg = ScannerConfig.from_toml(toml_file)
        assert cfg.strict_governance is False

    def test_strict_governance_config_true(self, tmp_path: Path) -> None:
        from wardline.manifest.models import ScannerConfig

        toml_file = tmp_path / "wardline.toml"
        toml_file.write_text("[wardline]\nstrict_governance = true\n")
        cfg = ScannerConfig.from_toml(toml_file)
        assert cfg.strict_governance is True
