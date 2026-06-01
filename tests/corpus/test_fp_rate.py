"""T1.4 FP-rate gate over the labeled corpus.

FP rate = active DEFECTs labeled FALSE_POSITIVE / total active DEFECTs, gated <= 5%.
The corpus is sized so a single mislabel cannot trivially breach the budget.
"""

from __future__ import annotations

from corpus.harness import reconcile


def test_fp_rate_within_budget():
    rec = reconcile()
    assert rec.active_defects >= 20, (
        f"corpus too small to be a meaningful gate: {rec.active_defects} active DEFECTs "
        "(need >= 20 so one mislabel cannot trivially breach 5%)"
    )
    assert not rec.unaccounted, (
        f"engine fired DEFECTs with no manifest entry (clean-shape regression?): {rec.unaccounted}"
    )
    assert not rec.stale, (
        f"stale manifest entries (no finding matched): {[(e.path, e.rule_id, e.qualname) for e in rec.stale]}"
    )
    assert rec.fp_rate <= 0.05, f"FP rate {rec.fp_rate:.1%} exceeds the 5% budget"
