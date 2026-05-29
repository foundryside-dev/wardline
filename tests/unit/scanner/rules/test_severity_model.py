from __future__ import annotations

from wardline.core.finding import Severity
from wardline.core.taints import TaintState as T
from wardline.scanner.rules.severity_model import modulate


def test_trusted_tiers_pass_base_through() -> None:
    for tier in (T.INTEGRAL, T.ASSURED):
        assert modulate(Severity.ERROR, tier) == Severity.ERROR
        assert modulate(Severity.CRITICAL, tier) == Severity.CRITICAL


def test_partial_tiers_downgrade_one_step() -> None:
    for tier in (T.GUARDED, T.UNKNOWN_ASSURED, T.UNKNOWN_GUARDED):
        assert modulate(Severity.CRITICAL, tier) == Severity.ERROR
        assert modulate(Severity.ERROR, tier) == Severity.WARN
        assert modulate(Severity.WARN, tier) == Severity.INFO
        assert modulate(Severity.INFO, tier) == Severity.INFO  # floor


def test_freedom_tiers_suppress_to_none() -> None:
    for tier in (T.EXTERNAL_RAW, T.UNKNOWN_RAW, T.MIXED_RAW):
        assert modulate(Severity.CRITICAL, tier) == Severity.NONE
        assert modulate(Severity.INFO, tier) == Severity.NONE


def test_every_taint_state_is_classified() -> None:
    # No TaintState may fall through unmapped (would silently mis-modulate).
    for tier in T:
        assert isinstance(modulate(Severity.ERROR, tier), Severity)
