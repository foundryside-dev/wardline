"""Tests for wardline.manifest.regime — governance metric collection."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from wardline.manifest import regime
from wardline.manifest.regime import (
    collect_exception_metrics,
    collect_fingerprint_metrics,
    collect_manifest_metrics,
    collect_rule_metrics,
)

# Path to the frozen governance fixture
_FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "governance"
_FIXTURE_MANIFEST = _FIXTURE_DIR / "wardline.yaml"


@pytest.fixture(autouse=True)
def _pin_today(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin today to 2026-03-24 for deterministic age calculations."""
    monkeypatch.setattr(regime, "_TODAY", date(2026, 3, 24))


# ---------------------------------------------------------------------------
# Exception metrics
# ---------------------------------------------------------------------------


class TestCollectExceptionMetrics:
    def test_collect_exception_metrics(self) -> None:
        """Fixture has 3 exceptions: 2 active (standard + agent), 1 expired (expedited)."""
        m = collect_exception_metrics(_FIXTURE_DIR)
        assert m.total == 3
        # EXC-001 expires 2027-01-01 → active
        # EXC-002 expires 2025-01-01 → expired
        # EXC-003 expires 2027-06-01 → active
        assert m.active == 2
        assert m.expired == 1
        # EXC-002 is expedited
        assert m.expedited == 1
        assert m.expedited_ratio == pytest.approx(1 / 3)
        assert set(m.governance_paths) == {"standard", "expedited"}

    def test_collect_exception_metrics_no_file(self, tmp_path: Path) -> None:
        """Missing exception file returns all zeros."""
        m = collect_exception_metrics(tmp_path)
        assert m.total == 0
        assert m.active == 0
        assert m.expired == 0
        assert m.agent_originated == 0
        assert m.expedited == 0
        assert m.expedited_ratio == 0.0
        assert m.governance_paths == ()

    def test_collect_exception_metrics_agent_originated(self) -> None:
        """Fixture has 1 agent-originated exception (EXC-003)."""
        m = collect_exception_metrics(_FIXTURE_DIR)
        assert m.agent_originated == 1


# ---------------------------------------------------------------------------
# Fingerprint metrics
# ---------------------------------------------------------------------------


class TestCollectFingerprintMetrics:
    def test_collect_fingerprint_metrics(self) -> None:
        """Fixture baseline has 3 entries, generated 2026-03-22."""
        m = collect_fingerprint_metrics(_FIXTURE_DIR)
        assert m.present is True
        assert m.generated_at == "2026-03-22T00:00:00Z"
        # 2026-03-24 - 2026-03-22 = 2 days
        assert m.age_days == 2
        assert m.annotated == 3
        assert m.total == 3
        assert m.coverage_ratio == pytest.approx(1.0)

    def test_collect_fingerprint_metrics_no_baseline(self, tmp_path: Path) -> None:
        """Missing baseline returns 'not present' defaults."""
        m = collect_fingerprint_metrics(tmp_path)
        assert m.present is False
        assert m.generated_at == ""
        assert m.age_days is None
        assert m.annotated == 0
        assert m.total == 0
        assert m.coverage_ratio == 0.0


# ---------------------------------------------------------------------------
# Manifest metrics
# ---------------------------------------------------------------------------


class TestCollectManifestMetrics:
    def test_collect_manifest_metrics(self) -> None:
        """Fixture manifest: ratified 2026-03-01, interval 180 days."""
        m = collect_manifest_metrics(_FIXTURE_MANIFEST)
        assert m.governance_profile == "lite"
        assert m.schema_version == "1.0"
        assert m.ratification_date == "2026-03-01"
        # 2026-03-24 - 2026-03-01 = 23 days
        assert m.ratification_age_days == 23
        assert m.review_interval_days == 180
        assert m.ratification_overdue is False

    def test_collect_ratification_overdue(self, tmp_path: Path) -> None:
        """Ratification overdue when age >= interval."""
        # Create a manifest with old ratification date and short interval
        manifest_content = """\
$id: "https://wardline.dev/schemas/1.0/wardline"
metadata:
  organisation: "test"
  ratified_by:
    name: "reviewer"
    role: "lead"
  ratification_date: "2025-01-01"
  review_interval_days: 90
governance_profile: "assurance"
tiers:
  - id: "tier1"
    tier: 1
    description: "test tier"
module_tiers:
  - path: "src/"
    default_taint: "ASSURED"
delegation:
  default_authority: "RELAXED"
rules:
  overrides: []
"""
        manifest_path = tmp_path / "wardline.yaml"
        manifest_path.write_text(manifest_content, encoding="utf-8")
        m = collect_manifest_metrics(manifest_path)
        assert m.governance_profile == "assurance"
        # 2026-03-24 - 2025-01-01 = 448 days, interval 90 → overdue
        assert m.ratification_overdue is True
        assert m.ratification_age_days is not None
        assert m.ratification_age_days >= 90


# ---------------------------------------------------------------------------
# Rule metrics
# ---------------------------------------------------------------------------


class TestCollectRuleMetrics:
    def test_collect_rule_metrics(self, tmp_path: Path) -> None:
        """Config with no disabled rules → all 9 canonical rules active."""
        toml_path = tmp_path / "wardline.toml"
        toml_path.write_text("[wardline]\ndisabled_rules = []\n", encoding="utf-8")
        m = collect_rule_metrics(_FIXTURE_MANIFEST, toml_path)
        assert m.total_rules == 9
        assert m.active_rules == 9
        assert m.disabled_rules == ()
        assert m.disabled_unconditional == ()

    def test_collect_rule_metrics_unconditional_disabled(self, tmp_path: Path) -> None:
        """Disabling PY-WL-008 (all UNCONDITIONAL) is detected."""
        toml_path = tmp_path / "wardline.toml"
        toml_path.write_text('[wardline]\ndisabled_rules = ["PY-WL-008"]\n', encoding="utf-8")
        m = collect_rule_metrics(_FIXTURE_MANIFEST, toml_path)
        assert m.total_rules == 9
        assert m.active_rules == 8
        assert "PY-WL-008" in m.disabled_rules
        assert "PY-WL-008" in m.disabled_unconditional
