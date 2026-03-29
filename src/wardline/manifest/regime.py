"""Regime metric collection — pure functions for governance health data.

Each ``collect_*`` function reads manifest/baseline data once and returns
a frozen dataclass. No CLI concerns; no side effects beyond file I/O.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from typing import TYPE_CHECKING

from wardline.core.matrix import SEVERITY_MATRIX
from wardline.core.severity import Exceptionability, GovernancePath, RuleId
from wardline.manifest.exceptions import load_exceptions
from wardline.manifest.loader import ManifestLoadError, load_manifest
from wardline.manifest.models import ScannerConfig

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Return types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExceptionMetrics:
    """Counts and ratios derived from the exception register."""

    total: int = 0
    active: int = 0
    expired: int = 0
    agent_originated: int = 0
    expedited: int = 0
    expedited_ratio: float = 0.0
    governance_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class FingerprintMetrics:
    """Baseline fingerprint health."""

    present: bool = False
    generated_at: str = ""
    age_days: int | None = None
    annotated: int = 0
    total: int = 0
    coverage_ratio: float = 0.0


@dataclass(frozen=True)
class ManifestMetrics:
    """Manifest-level governance metadata."""

    governance_profile: str = "lite"
    schema_version: str = ""
    analysis_level: int = 1
    ratification_date: str | None = None
    ratification_age_days: int | None = None
    review_interval_days: int | None = None
    ratification_overdue: bool = False
    ratified_by_present: bool = False
    temporal_separation_posture: str | None = None


@dataclass(frozen=True)
class RuleMetrics:
    """Rule enablement health."""

    total_rules: int = 0
    active_rules: int = 0
    disabled_rules: tuple[str, ...] = ()
    disabled_unconditional: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Collection functions
# ---------------------------------------------------------------------------

_TODAY = None  # Test hook: set to a date to override today


def _today() -> date:
    """Return today's date (overridable for tests)."""
    if _TODAY is not None:
        return _TODAY
    return date.today()


def collect_exception_metrics(manifest_dir: Path) -> ExceptionMetrics:
    """Collect exception register metrics from *manifest_dir*.

    Returns zero-valued metrics if the exception file is missing.
    """
    try:
        entries = load_exceptions(manifest_dir)
    except (ManifestLoadError, OSError):
        return ExceptionMetrics()

    if not entries:
        return ExceptionMetrics()

    today = _today()
    active = 0
    expired = 0
    agent_originated = 0
    expedited = 0
    governance_paths_set: set[str] = set()

    for entry in entries:
        governance_paths_set.add(str(entry.governance_path))

        # Expired?
        if entry.expires:
            try:
                expiry = date.fromisoformat(entry.expires)
            except ValueError:
                active += 1
                continue
            if expiry < today:
                expired += 1
            else:
                active += 1
        else:
            active += 1

        if entry.agent_originated:
            agent_originated += 1

        if entry.governance_path == GovernancePath.EXPEDITED:
            expedited += 1

    total = len(entries)
    expedited_ratio = expedited / total if total else 0.0

    return ExceptionMetrics(
        total=total,
        active=active,
        expired=expired,
        agent_originated=agent_originated,
        expedited=expedited,
        expedited_ratio=expedited_ratio,
        governance_paths=tuple(sorted(governance_paths_set)),
    )


def collect_fingerprint_metrics(manifest_dir: Path) -> FingerprintMetrics:
    """Collect fingerprint baseline metrics from *manifest_dir*.

    Reads the baseline JSON once. Returns "not present" defaults if missing.
    """
    baseline_path = manifest_dir / "wardline.fingerprint.json"
    if not baseline_path.exists():
        return FingerprintMetrics()

    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return FingerprintMetrics()

    generated_at = data.get("generated_at", "")
    age_days: int | None = None
    if generated_at:
        try:
            gen_dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            age_days = (_today() - gen_dt.date()).days
        except (ValueError, TypeError):
            pass

    coverage = data.get("coverage", {})

    return FingerprintMetrics(
        present=True,
        generated_at=generated_at,
        age_days=age_days,
        annotated=coverage.get("annotated", 0),
        total=coverage.get("total", 0),
        coverage_ratio=coverage.get("ratio", 0.0),
    )


def collect_manifest_metrics(manifest_path: Path) -> ManifestMetrics:
    """Collect manifest-level governance metrics.

    Returns sensible defaults if the manifest cannot be loaded.
    """
    try:
        manifest = load_manifest(manifest_path)
    except (ManifestLoadError, OSError):
        return ManifestMetrics()

    meta = manifest.metadata
    ratification_date = meta.ratification_date
    ratification_age_days: int | None = None
    ratification_overdue = False

    if ratification_date:
        try:
            rat_date = date.fromisoformat(ratification_date)
            ratification_age_days = (_today() - rat_date).days
            if meta.review_interval_days is not None:
                ratification_overdue = ratification_age_days >= meta.review_interval_days
        except (ValueError, TypeError):
            pass

    ratified_by_present = meta.ratified_by is not None

    temporal_separation_posture: str | None = None
    if meta.temporal_separation is not None:
        alt = meta.temporal_separation.alternative
        temporal_separation_posture = "enforced" if alt == "enforced" else f"alternative:{alt}"

    return ManifestMetrics(
        governance_profile=manifest.governance_profile,
        schema_version="1.0",
        analysis_level=1,
        ratification_date=ratification_date,
        ratification_age_days=ratification_age_days,
        review_interval_days=meta.review_interval_days,
        ratification_overdue=ratification_overdue,
        ratified_by_present=ratified_by_present,
        temporal_separation_posture=temporal_separation_posture,
    )


def collect_rule_metrics(manifest_path: Path, config_path: Path) -> RuleMetrics:
    """Collect rule enablement metrics.

    Cross-references disabled rules from ``wardline.toml`` against the
    severity matrix to detect disabled UNCONDITIONAL rules.

    Returns zero-valued metrics if config cannot be loaded.
    """
    try:
        config = ScannerConfig.from_toml(config_path)
    except (OSError, Exception):
        return RuleMetrics()

    # Canonical analysis rules (PY-WL-001 .. PY-WL-009)
    canonical_rules = {r for r in RuleId if r.value.startswith("PY-WL-") and len(r.value) == 9}

    disabled = set(config.disabled_rules) & canonical_rules
    active = canonical_rules - disabled

    # Detect disabled rules that have any UNCONDITIONAL cell in the matrix
    disabled_unconditional: list[str] = []
    for rule_id in sorted(disabled, key=lambda r: r.value):
        for (r, _t), cell in SEVERITY_MATRIX.items():
            if r == rule_id and cell.exceptionability == Exceptionability.UNCONDITIONAL:
                disabled_unconditional.append(rule_id.value)
                break

    return RuleMetrics(
        total_rules=len(canonical_rules),
        active_rules=len(active),
        disabled_rules=tuple(r.value for r in sorted(disabled, key=lambda r: r.value)),
        disabled_unconditional=tuple(disabled_unconditional),
    )
