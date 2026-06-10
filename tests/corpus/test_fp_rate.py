"""T1.4 FP-rate gate over the labeled corpus.

FP rate = active DEFECTs labeled FALSE_POSITIVE / total active DEFECTs, gated <= 5%.
The corpus is sized so a single mislabel cannot trivially breach the budget.

FALSE_POSITIVE entries are clean-shape sentinels: the engine must NOT fire on them.
Silent sentinel = passing (not stale); fired sentinel = a live FP counted against the
budget. The corpus must carry sentinels so the gate exercises real reconciliation.
"""

from __future__ import annotations

from corpus.harness import FALSE_POSITIVE, load_manifest, reconcile  # type: ignore[import-not-found]


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


def test_corpus_carries_false_positive_sentinels():
    # The gate only exercises real reconciliation if the corpus mixes labels: clean-shape
    # sentinels (FALSE_POSITIVE) alongside the TRUE_POSITIVE defects. A silent sentinel is
    # the engine behaving correctly, so it must NOT be reported stale.
    expectations = load_manifest()
    sentinels = [e for e in expectations if e.label == FALSE_POSITIVE]
    assert len(sentinels) >= 3, (
        f"corpus has {len(sentinels)} FALSE_POSITIVE sentinels (need >= 3 so the FP-rate "
        "gate computes over a mixed corpus, not a vacuous all-TP one)"
    )
    rec = reconcile()
    silent_stale = [e for e in rec.stale if e.label == FALSE_POSITIVE]
    assert not silent_stale, (
        "silent FALSE_POSITIVE sentinels were reported stale — a sentinel the engine "
        "does not fire on is PASSING, not stale: "
        f"{[(e.path, e.rule_id, e.qualname) for e in silent_stale]}"
    )


def test_fired_sentinel_counts_against_budget(monkeypatch, tmp_path):
    # End-to-end fired-sentinel path: relabel a known-firing fixture entry as
    # FALSE_POSITIVE in a scratch manifest — the fired finding must be counted as a
    # live FP (against the budget), not reported stale or unaccounted.
    import corpus.harness as harness  # type: ignore[import-not-found]

    original = harness.MANIFEST_PATH.read_text()
    relabel_target = 'qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE'
    assert relabel_target in original, "relabel target drifted — pick another known-firing entry"
    scratch = tmp_path / "MANIFEST.yaml"
    scratch.write_text(original.replace(relabel_target, relabel_target.replace("TRUE_POSITIVE", "FALSE_POSITIVE")))
    monkeypatch.setattr(harness, "MANIFEST_PATH", scratch)

    rec = reconcile()
    assert rec.false_positives == 1
    assert rec.fp_rate == 1 / rec.active_defects
    assert not rec.unaccounted
    assert "deser_sink.loads_untrusted" not in {e.qualname for e in rec.stale}


def test_reconciliation_fp_rate_arithmetic():
    # Directly exercise the FP-rate computation on the FALSE_POSITIVE path, which the
    # live corpus (all TRUE_POSITIVE today) never hits. Guards the gate's own math.
    from corpus.harness import Reconciliation  # type: ignore[import-not-found]

    none_fp = Reconciliation(active_defects=20, false_positives=0, unaccounted=[], stale=[])
    assert none_fp.fp_rate == 0.0

    one_in_twenty = Reconciliation(active_defects=20, false_positives=1, unaccounted=[], stale=[])
    assert one_in_twenty.fp_rate == 0.05  # exactly at budget

    over_budget = Reconciliation(active_defects=20, false_positives=2, unaccounted=[], stale=[])
    assert over_budget.fp_rate > 0.05  # the >5% case the gate must reject

    empty = Reconciliation(active_defects=0, false_positives=0, unaccounted=[], stale=[])
    assert empty.fp_rate == 0.0  # no division by zero
