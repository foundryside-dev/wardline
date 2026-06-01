"""T1.4 waiver discipline: every waiver carries a reason; waiver count does not
outgrow rule count. Without this, the FP-rate gate is gameable by waiving findings."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core import config as config_mod
from wardline.core.errors import ConfigError
from wardline.core.waivers import parse_waivers
from wardline.scanner.rules import _ALL_RULE_CLASSES

REPO_ROOT = Path(__file__).resolve().parents[2]
_VALID_FP = "a" * 64  # 64-char lowercase hex


def test_reasonless_waiver_rejected():
    with pytest.raises(ConfigError):
        parse_waivers([{"fingerprint": _VALID_FP}])  # no reason


def test_waiver_with_reason_accepted():
    waivers = parse_waivers([{"fingerprint": _VALID_FP, "reason": "triaged: framework false positive"}])
    assert waivers[0].reason.strip()


def _repo_waivers() -> tuple:
    cfg_path = REPO_ROOT / "wardline.yaml"
    cfg = config_mod.load(cfg_path if cfg_path.exists() else None)
    # parse_waivers re-validates: a reasonless or malformed waiver raises here.
    return parse_waivers(cfg.waivers)


def test_repo_waivers_all_have_reasons():
    for waiver in _repo_waivers():
        assert waiver.reason and waiver.reason.strip(), f"waiver {waiver.fingerprint} has no reason"


def test_waiver_count_not_outgrowing_rule_count():
    waiver_count = len(_repo_waivers())
    rule_count = len(_ALL_RULE_CLASSES)  # the curated builtin rule set (4 today)
    assert waiver_count <= rule_count, (
        f"waiver count {waiver_count} exceeds rule count {rule_count} — "
        "suppression is outgrowing the rule set (FP-economics breach)"
    )
