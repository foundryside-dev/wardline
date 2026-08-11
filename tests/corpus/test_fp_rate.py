"""T1.4 FP-rate gate over the labeled corpus.

FP rate = active DEFECTs labeled FALSE_POSITIVE / total active DEFECTs, gated <= 5%.
The corpus is sized so a single mislabel cannot trivially breach the budget.

FALSE_POSITIVE entries are clean-shape sentinels: the engine must NOT fire on them.
Silent sentinel = passing (not stale); fired sentinel = a live FP counted against the
budget. The corpus must carry sentinels so the gate exercises real reconciliation.
"""

from __future__ import annotations

import pytest

import corpus.harness as harness  # type: ignore[import-not-found]
from corpus.harness import FALSE_POSITIVE, load_manifest, reconcile  # type: ignore[import-not-found]
from wardline.core.finding import Kind
from wardline.core.run import run_scan


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


# --------------------------------------------------------------------------------------
# S0 P1/P2/P3: strict manifest loading, preview findings in the population, per-kind gate.
# --------------------------------------------------------------------------------------


def _scratch_manifest(tmp_path, text, *, complete=True):
    scratch = tmp_path / "MANIFEST.yaml"
    if complete:
        if "fixtures:" not in text:
            text += "fixtures: {}\n"
        if "sentinels:" not in text:
            text += "sentinels: {}\n"
    scratch.write_text(text, encoding="utf-8")
    return scratch


def _row(**overrides):
    """A syntactically valid flow-style manifest row with `overrides` applied verbatim."""
    fields = {
        "rule_id": "PY-WL-106",
        "qualname": '"deser_sink.loads_untrusted"',
        "label": "TRUE_POSITIVE",
    }
    fields.update(overrides)
    body = ", ".join(f"{k}: {v}" for k, v in fields.items() if v is not None)
    return "fixtures:\n  deser_sink.py:\n" + f"    - {{{body}}}\n"


def test_manifest_rejects_unknown_keys(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-106, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE, maturty: stable}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="unknown key"):
        harness.load_manifest()


def test_manifest_rejects_unknown_rule_ids(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-999, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="unknown rule_id"):
        harness.load_manifest()


def test_manifest_maturity_must_match_the_rule(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-118, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE, maturity: stable}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="maturity"):
        harness.load_manifest()


def test_manifest_rejects_missing_fixture_files(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        'fixtures:\n  no_such_file.py:\n    - {rule_id: PY-WL-106, qualname: "x.f", label: TRUE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="no such fixture"):
        harness.load_manifest()


def test_manifest_rejects_unknown_kind_and_interaction(tmp_path, monkeypatch):
    for field_yaml, match in (("kind: sorcery", "kind"), ("interaction: frenemies", "interaction")):
        bad = _scratch_manifest(
            tmp_path,
            "fixtures:\n  deser_sink.py:\n"
            '    - {rule_id: PY-WL-106, qualname: "deser_sink.loads_untrusted", '
            f"label: TRUE_POSITIVE, {field_yaml}}}\n",
        )
        monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
        with pytest.raises(ValueError, match=match):
            harness.load_manifest()


# --- structural rejections (malformed top level / section shapes) ---------------------


def test_manifest_rejects_non_mapping_root(tmp_path, monkeypatch):
    bad = _scratch_manifest(tmp_path, "- fixtures\n- sentinels\n", complete=False)
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="root must be a mapping"):
        harness.load_manifest()


def test_manifest_rejects_unknown_section(tmp_path, monkeypatch):
    bad = _scratch_manifest(tmp_path, "fixtures: {}\nsentinels: {}\nsorceries: {}\n", complete=False)
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="sections must be exactly"):
        harness.load_manifest()


def test_manifest_rejects_missing_section(tmp_path, monkeypatch):
    bad = _scratch_manifest(tmp_path, "fixtures: {}\n", complete=False)
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="sections must be exactly"):
        harness.load_manifest()


def test_manifest_rejects_non_mapping_section(tmp_path, monkeypatch):
    bad = _scratch_manifest(tmp_path, "fixtures: []\nsentinels: {}\n", complete=False)
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="section must be a mapping"):
        harness.load_manifest()


def test_manifest_rejects_non_list_rows(tmp_path, monkeypatch):
    bad = _scratch_manifest(tmp_path, "fixtures:\n  deser_sink.py: {}\n")
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="rows must be a list"):
        harness.load_manifest()


def test_manifest_rejects_non_mapping_entry(tmp_path, monkeypatch):
    bad = _scratch_manifest(tmp_path, "fixtures:\n  deser_sink.py:\n    - not_a_mapping\n")
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="entry must be a mapping"):
        harness.load_manifest()


def test_manifest_rejects_non_string_path(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path, "fixtures:\n  17:\n    - {rule_id: PY-WL-106, qualname: a, label: TRUE_POSITIVE}\n"
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="non-empty string"):
        harness.load_manifest()


# --- required / typed / enumerated field rejections -----------------------------------


@pytest.mark.parametrize("missing", ["rule_id", "qualname", "label"])
def test_manifest_rejects_missing_required_field(tmp_path, monkeypatch, missing):
    bad = _scratch_manifest(tmp_path, _row(**{missing: None}))
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match=f"missing required key.*{missing}"):
        harness.load_manifest()


@pytest.mark.parametrize("field_name", ["rule_id", "qualname", "label", "note", "maturity", "kind", "interaction"])
@pytest.mark.parametrize("value", ["[a, b]", "{a: 1}", "17"])
def test_manifest_rejects_non_string_field_values(tmp_path, monkeypatch, field_name, value):
    # Load-bearing: an unhashable YAML value reaching a `not in frozenset` membership
    # test raises TypeError, not the ValueError the loader promises.
    bad = _scratch_manifest(tmp_path, _row(**{field_name: value}))
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="must be a string"):
        harness.load_manifest()


def test_manifest_rejects_unknown_label(tmp_path, monkeypatch):
    bad = _scratch_manifest(tmp_path, _row(label="MAYBE_POSITIVE"))
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="bad label"):
        harness.load_manifest()


def test_manifest_rejects_bad_maturity_value(tmp_path, monkeypatch):
    bad = _scratch_manifest(tmp_path, _row(maturity="experimental"))
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="bad maturity"):
        harness.load_manifest()


def test_manifest_rejects_duplicate_reconciliation_keys(tmp_path, monkeypatch):
    row = '    - {rule_id: PY-WL-106, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE}\n'
    bad = _scratch_manifest(tmp_path, "fixtures:\n  deser_sink.py:\n" + row + row)
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="duplicate manifest key"):
        harness.load_manifest()


@pytest.mark.parametrize(
    ("interaction", "label"),
    [("contradiction", "FALSE_POSITIVE"), ("match", "TRUE_POSITIVE")],
)
def test_manifest_rejects_interaction_label_mismatch(tmp_path, monkeypatch, interaction, label):
    bad = _scratch_manifest(tmp_path, _row(interaction=interaction, label=label))
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="interaction"):
        harness.load_manifest()


# --- section / path-containment rejections --------------------------------------------


def test_manifest_rejects_sentinel_file_listed_under_fixtures(tmp_path, monkeypatch):
    # clean_exec_const.py is a real file, but it lives under sentinels/ — listing it in
    # the fixtures section must not resolve.
    bad = _scratch_manifest(
        tmp_path,
        'fixtures:\n  clean_exec_const.py:\n    - {rule_id: PY-WL-107, qualname: "x.f", label: TRUE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="no such fixture"):
        harness.load_manifest()


def test_manifest_rejects_absolute_paths(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        'fixtures:\n  /etc/passwd:\n    - {rule_id: PY-WL-106, qualname: "x.f", label: TRUE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="must be relative"):
        harness.load_manifest()


def test_manifest_rejects_parent_traversal_out_of_its_section(tmp_path, monkeypatch):
    # ../fixtures/deser_sink.py IS a real file from SENTINEL_ROOT, so an is_file() check
    # alone would accept this section escape. The containment check is what rejects it.
    assert (harness.SENTINEL_ROOT / "../fixtures/deser_sink.py").is_file()
    bad = _scratch_manifest(
        tmp_path,
        "sentinels:\n  ../fixtures/deser_sink.py:\n"
        '    - {rule_id: PY-WL-106, qualname: "deser_sink.loads_untrusted", label: FALSE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match=r"\.\."):
        harness.load_manifest()


def test_manifest_rejects_symlink_escape(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "smuggled.py").write_text("X = 1\n", encoding="utf-8")
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (tmp_path / "sentinels").mkdir()
    (fixtures / "smuggled.py").symlink_to(outside / "smuggled.py")
    monkeypatch.setattr(harness, "CORPUS_ROOT", fixtures)
    monkeypatch.setattr(harness, "SENTINEL_ROOT", tmp_path / "sentinels")
    bad = _scratch_manifest(
        tmp_path,
        'fixtures:\n  smuggled.py:\n    - {rule_id: PY-WL-106, qualname: "x.f", label: TRUE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="escapes"):
        harness.load_manifest()


# --- P1: preview findings enter both numerator and denominator ------------------------


def test_preview_finding_moves_numerator_and_denominator(monkeypatch, tmp_path):
    # THE discriminating case for P1: a corpus whose only findings come from
    # snippets built on a PREVIEW rule's own examples_violation (guaranteed to
    # fire by the examples contract). Under the old maturity skip reconcile()
    # counted nothing here (active_defects == 0); with the skip gone the preview
    # findings land in the denominator AND, labeled FALSE_POSITIVE, the
    # numerator.
    from wardline.scanner.rules.sql_injection import METADATA as SQLI

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    sentinels = tmp_path / "sentinels"
    sentinels.mkdir()
    (sentinels / "clean_placeholder.py").write_text("X = 1\n", encoding="utf-8")
    src = (
        "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
        + SQLI.examples_violation[0]
        + "\n"
    )
    (fixtures / "preview_fp.py").write_text(src, encoding="utf-8")

    # Discover every DEFECT the engine fires here, then manifest ALL of them so
    # the reconciliation is closed: PY-WL-118 rows as FALSE_POSITIVE (the point),
    # any co-firing stable rule as TRUE_POSITIVE.
    maturities = harness._rule_maturities()
    fired = [f for f in run_scan(fixtures).findings if f.kind is Kind.DEFECT]
    assert any(f.rule_id == "PY-WL-118" for f in fired), "PY-WL-118's violation example must fire it"
    rows = "".join(
        f'    - {{rule_id: {f.rule_id}, qualname: "{f.qualname}", '
        f"label: {'FALSE_POSITIVE' if f.rule_id == 'PY-WL-118' else 'TRUE_POSITIVE'}, "
        f"maturity: {maturities[f.rule_id]}, "
        f'note: "synthetic P1 gate row"}}\n'
        for f in fired
    )
    manifest = _scratch_manifest(tmp_path, "fixtures:\n  preview_fp.py:\n" + rows)
    monkeypatch.setattr(harness, "CORPUS_ROOT", fixtures)
    monkeypatch.setattr(harness, "SENTINEL_ROOT", sentinels)
    monkeypatch.setattr(harness, "MANIFEST_PATH", manifest)

    rec = harness.reconcile()
    n_preview = sum(1 for f in fired if f.rule_id == "PY-WL-118")
    assert rec.active_defects == len(fired)  # denominator includes preview (was: excluded)
    assert rec.false_positives == n_preview  # numerator includes the preview FP rows
    assert not rec.unaccounted


# --- P3 / spec §12: the per-kind gate --------------------------------------------------


def test_per_kind_fp_rate_within_budget():
    # Spec §12 "Per-kind gates" (NOT P3 — P3 is the reconciliation-ordering
    # obligation that must be clean BEFORE any rate is evaluated, asserted in
    # test_fp_rate_within_budget): every declared kind has >=3 distinct clean
    # sentinel files and >=5 TP specimens. TP fixture-file diversity is retained
    # as an additional gate.
    # At >=10 active defects the kind meets the 5% FP budget; below 10 it is
    # sentinel-gated low-sample and its counts go into the implementation receipt.
    rec = harness.reconcile()
    from collections import Counter

    entries = harness.load_manifest()
    manifest_kinds = {e.kind for e in entries}
    true_fixture_paths = {
        kind: {
            e.path for e in entries if e.kind == kind and e.section == "fixtures" and e.label == harness.TRUE_POSITIVE
        }
        for kind in manifest_kinds
    }
    clean_sentinel_paths = {
        kind: {
            e.path for e in entries if e.kind == kind and e.section == "sentinels" and e.label == harness.FALSE_POSITIVE
        }
        for kind in manifest_kinds
    }
    true_specimens = Counter(e.kind for e in entries if e.label == harness.TRUE_POSITIVE)
    assert set(rec.active_by_kind) == manifest_kinds
    for kind in sorted(manifest_kinds):
        defects = rec.active_by_kind[kind]
        fps = rec.fp_by_kind.get(kind, 0)
        assert len(clean_sentinel_paths[kind]) >= 3, f"kind {kind}: fewer than 3 distinct clean sentinel files"
        assert len(true_fixture_paths[kind]) >= 3, f"kind {kind}: fewer than 3 true fixture files"
        assert true_specimens[kind] >= 5, f"kind {kind}: fewer than 5 true-positive specimens"
        if defects >= 10:
            assert fps / defects <= 0.05, f"kind {kind}: FP rate {fps}/{defects} exceeds 5%"
        else:
            assert defects >= 5, f"kind {kind}: fewer than 5 active defect specimens"


def test_per_kind_arithmetic_exposes_what_the_global_rate_hides():
    # Scope: this exercises the RATIO, not the gate's assertion — it shows the numbers
    # the per-kind gate reads can diverge from the aggregate rate at all. 1 FP in 30 is
    # 3.3% globally (passing) but 10% inside `contracts`. That the live gate in
    # test_per_kind_fp_rate_within_budget actually goes red on a degraded corpus was
    # proven separately by mutation (three sentinel files removed -> RED); see the
    # Task 10 report.
    from corpus.harness import Reconciliation  # type: ignore[import-not-found]

    rec = Reconciliation(
        active_defects=30,
        false_positives=1,
        unaccounted=[],
        stale=[],
        active_by_kind={"core": 20, "contracts": 10},
        fp_by_kind={"contracts": 1},
    )
    assert rec.fp_rate <= 0.05  # aggregate gate is blind to it
    assert rec.fp_by_kind["contracts"] / rec.active_by_kind["contracts"] > 0.05  # per-kind gate bites
    assert rec.fp_by_kind.get("core", 0) / rec.active_by_kind["core"] == 0.0


def test_per_kind_tallies_are_read_from_the_expectation_not_hardcoded(monkeypatch, tmp_path):
    # The live manifest declares one kind (`core`), so nothing there would catch a
    # reconcile() that attributed every finding to a hardcoded bucket. Label the
    # preview rows a different kind and assert the split follows the manifest.
    from wardline.scanner.rules.sql_injection import METADATA as SQLI

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    sentinels = tmp_path / "sentinels"
    sentinels.mkdir()
    (sentinels / "clean_placeholder.py").write_text("X = 1\n", encoding="utf-8")
    src = (
        "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
        + SQLI.examples_violation[0]
        + "\n"
    )
    (fixtures / "preview_fp.py").write_text(src, encoding="utf-8")
    # A second, stable-rule specimen so the two kinds are genuinely populated: the
    # SQLI violation example fires PY-WL-118 and nothing else.
    (fixtures / "core_tp.py").write_text(
        (harness.CORPUS_ROOT / "deser_sink.py").read_text(encoding="utf-8"), encoding="utf-8"
    )
    maturities = harness._rule_maturities()
    fired = [f for f in run_scan(fixtures).findings if f.kind is Kind.DEFECT]
    assert {f.rule_id for f in fired} >= {"PY-WL-118", "PY-WL-106"}
    by_path: dict[str, list] = {}
    for f in fired:
        by_path.setdefault(f.location.path, []).append(f)
    rows = "".join(
        f"  {path}:\n"
        + "".join(
            f'    - {{rule_id: {f.rule_id}, qualname: "{f.qualname}", '
            f"label: {'FALSE_POSITIVE' if f.rule_id == 'PY-WL-118' else 'TRUE_POSITIVE'}, "
            f"maturity: {maturities[f.rule_id]}, "
            f"kind: {'contracts' if f.rule_id == 'PY-WL-118' else 'core'}, "
            f'note: "synthetic per-kind row"}}\n'
            for f in group
        )
        for path, group in sorted(by_path.items())
    )
    manifest = _scratch_manifest(tmp_path, "fixtures:\n" + rows)
    monkeypatch.setattr(harness, "CORPUS_ROOT", fixtures)
    monkeypatch.setattr(harness, "SENTINEL_ROOT", sentinels)
    monkeypatch.setattr(harness, "MANIFEST_PATH", manifest)

    rec = harness.reconcile()
    n_preview = sum(1 for f in fired if f.rule_id == "PY-WL-118")
    assert set(rec.active_by_kind) == {"core", "contracts"}
    assert rec.active_by_kind["contracts"] == n_preview
    assert rec.active_by_kind["core"] == len(fired) - n_preview
    assert rec.fp_by_kind["contracts"] == n_preview
    assert rec.fp_by_kind["core"] == 0


def test_unaccounted_findings_are_not_attributed_to_a_kind(monkeypatch, tmp_path):
    # An unaccounted finding has no expectation and therefore no kind: it must raise the
    # global denominator without silently inflating `core`.
    from wardline.scanner.rules.sql_injection import METADATA as SQLI

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    sentinels = tmp_path / "sentinels"
    sentinels.mkdir()
    (sentinels / "clean_placeholder.py").write_text("X = 1\n", encoding="utf-8")
    src = (
        "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
        + SQLI.examples_violation[0]
        + "\n"
    )
    (fixtures / "preview_fp.py").write_text(src, encoding="utf-8")
    fired = [f for f in run_scan(fixtures).findings if f.kind is Kind.DEFECT]
    manifest = _scratch_manifest(tmp_path, "fixtures: {}\nsentinels: {}\n")
    monkeypatch.setattr(harness, "CORPUS_ROOT", fixtures)
    monkeypatch.setattr(harness, "SENTINEL_ROOT", sentinels)
    monkeypatch.setattr(harness, "MANIFEST_PATH", manifest)

    rec = harness.reconcile()
    assert rec.active_defects == len(fired)
    assert len(rec.unaccounted) == len(fired)
    assert rec.active_by_kind == {}
    assert rec.fp_by_kind == {}


def test_py_wl_110_carries_a_contradiction_and_a_match_specimen():
    # PY-WL-110 fires on two DISTINCT markers. The pair proves the rule discriminates
    # rather than counting decorators: a contradiction TP specimen and a matching-marker
    # clean sentinel that must stay silent.
    entries = [e for e in harness.load_manifest() if e.rule_id == "PY-WL-110"]
    contradictions = [e for e in entries if e.interaction == "contradiction"]
    matches = [e for e in entries if e.interaction == "match"]
    assert contradictions, "PY-WL-110 has no interaction: contradiction specimen"
    assert matches, "PY-WL-110 has no interaction: match clean sentinel"
    assert all(e.label == harness.TRUE_POSITIVE and e.section == "fixtures" for e in contradictions)
    assert all(e.label == harness.FALSE_POSITIVE and e.section == "sentinels" for e in matches)


# --- checks that previously had NO standing test (review finding, Task 10) -------------


def test_manifest_rejects_empty_path_key(tmp_path, monkeypatch):
    # The `not path` half of the non-empty-string guard. Without it an empty key resolves
    # to the section ROOT (a directory), which fails later with a misleading
    # "no such fixture" instead of naming the real defect.
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  '':\n    - {rule_id: PY-WL-106, qualname: \"x.f\", label: TRUE_POSITIVE}\n",
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="non-empty string"):
        harness.load_manifest()


def test_manifest_rejects_a_file_name_reused_across_scan_roots(tmp_path, monkeypatch):
    # The reconciliation key is ROOT-RELATIVE, so one file name in both roots would make
    # two distinct specimens collide onto one key and silently reconcile against the
    # wrong ground truth.
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-106, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE}\n'
        "sentinels:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-106, qualname: "other.thing", label: FALSE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="reused across scan roots"):
        harness.load_manifest()


def test_manifest_rejects_a_true_positive_row_in_the_sentinels_section(tmp_path, monkeypatch):
    # sentinels/ is the clean-shape root: a TRUE_POSITIVE row there would assert the
    # engine SHOULD fire on a file whose whole purpose is that it stays silent.
    bad = _scratch_manifest(
        tmp_path,
        "sentinels:\n  clean_exec_const.py:\n"
        '    - {rule_id: PY-WL-107, qualname: "clean_exec_const.const_eval", label: TRUE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="must be FALSE_POSITIVE"):
        harness.load_manifest()
