"""T1.4 waiver discipline: every waiver carries a reason, and the waiver count stays
within a fixed, reviewed budget. This guards the repo's own (dogfood) scan config — not
the corpus FP gate (which scans tests/corpus/fixtures with no config) — so suppression
cannot quietly accumulate beyond its reviewed budget (an FP-economics smell)."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.errors import ConfigError
from wardline.core.waivers import load_project_waivers, parse_waivers

REPO_ROOT = Path(__file__).resolve().parents[2]
_VALID_FP = "a" * 64  # 64-char lowercase hex


def test_reasonless_waiver_rejected():
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": _VALID_FP}])  # no reason


def test_waiver_with_reason_accepted():
    waivers = parse_waivers([{"fingerprint": _VALID_FP, "reason": "triaged: framework false positive"}])
    assert waivers[0].reason.strip()


def _repo_waivers() -> tuple:
    # Waivers live in <root>/.weft/wardline/waivers.yaml; absent → empty tuple.
    # load_project_waivers re-validates: a reasonless or malformed waiver raises here.
    return load_project_waivers(REPO_ROOT)


def test_repo_waivers_all_have_reasons():
    for waiver in _repo_waivers():
        assert waiver.reason and waiver.reason.strip(), f"waiver {waiver.fingerprint} has no reason"


# P13: decoupled from rule count. The old `<= len(_ALL_RULE_CLASSES)` ceiling
# silently grew from 4 to 27 as rules shipped — a suppression budget must not
# scale with the detection surface it suppresses. The repo carries ZERO waivers
# today. Five is the reviewed risk ceiling (not current usage): enough room for
# explicitly triaged false positives without coupling growth to the number of
# rules. Raising this constant requires a dedicated review with a named owner
# and rationale; adding a rule never creates suppression headroom as a side effect.
_WAIVER_CEILING = 5


def test_waiver_count_within_fixed_ceiling():
    waiver_count = len(_repo_waivers())
    assert waiver_count <= _WAIVER_CEILING, (
        f"waiver count {waiver_count} exceeds the fixed ceiling {_WAIVER_CEILING} — "
        "suppression is outgrowing its reviewed budget (FP-economics breach)"
    )
