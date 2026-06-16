"""P4 S2 — the NON-CIRCULAR reconstruction gate (the make-or-break test).

``compute_old_new_fingerprints`` reconstructs each finding's OLD (wlfp1) fingerprint
from ``finding.location.line_start`` + ``finding.taint_path_v0``. If that reconstruction
is even subtly wrong (a different node/attribute than the dead engine used), EVERY
verdict silently orphans at migration time and resurfaces ACTIVE — the worst failure
mode for this phase, and one a self-consistent test would miss.

So the oracle is the REAL pre-P3 corpus: ``tests/unit/core/fixtures/wlfp1_sinks_
fingerprints.json`` is the genuine wlfp1 (line_start-IN) output of the dead engine,
frozen from ``git 966cd9f^`` (P3's parent, corpus_version 3). It was NOT produced by
running the current engine. The gate: run the CURRENT engine on the same sinks
fixture, reconstruct every ``old_fp``, and assert the multiset equals the frozen
wlfp1 fingerprints byte-for-byte. The sinks fixture exercises the entire call-site
family (101/105/106/112/114/115/116/118/120 — both PY-WL-120 sites), which is the
only non-trivial reconstruction, so this validates the risky path end-to-end against
the actual dead engine.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("blake3", reason="run_scan identity path needs wardline[loomweave]")

from wardline.core.rekey import compute_old_new_fingerprints, is_join_population  # noqa: E402
from wardline.core.run import run_scan  # noqa: E402

_SINKS_FIXTURE = Path(__file__).resolve().parents[2] / "golden" / "identity" / "fixtures" / "sinks"
_WLFP1_GOLDEN = Path(__file__).resolve().parent / "fixtures" / "wlfp1_sinks_fingerprints.json"


def _frozen_wlfp1() -> list[dict]:
    return json.loads(_WLFP1_GOLDEN.read_text(encoding="utf-8"))["fingerprints"]


def test_reconstructed_old_fp_multiset_matches_real_wlfp1_corpus() -> None:
    frozen = _frozen_wlfp1()
    expected_old = sorted(r["fingerprint"] for r in frozen)

    result = run_scan(_SINKS_FIXTURE)
    remaps = compute_old_new_fingerprints(result.findings)

    # Non-vacuity: the migration scope must actually be the 26-finding sinks set.
    assert len(remaps) == len(frozen) == 26, f"expected 26 join-population findings, got {len(remaps)}"

    got_old = sorted(r.old_fp for r in remaps)
    assert got_old == expected_old, (
        "RECONSTRUCTION DRIFT: a reconstructed old_fp does not match the real pre-P3 (wlfp1) "
        "engine output. taint_path_v0 / line_start does not byte-reproduce what the dead engine "
        "hashed — every baselined/waived/judged verdict would silently orphan on migration."
    )


def test_new_fp_is_the_live_fingerprint() -> None:
    result = run_scan(_SINKS_FIXTURE)
    by_id = {id(f): f for f in result.findings}
    remaps = compute_old_new_fingerprints(result.findings)
    live = {f.fingerprint for f in result.findings if is_join_population(f)}
    got_new = {r.new_fp for r in remaps}
    assert got_new == live, "new_fp must be the live wlfp2 finding.fingerprint, unchanged"
    assert by_id  # sanity: scan produced findings


def test_old_and_new_differ_for_the_whole_set() -> None:
    # line_start dropped for ALL rules, so every finding's identity moved — there must
    # be no accidental old==new (which would mean a finding wasn't actually rekeyed).
    result = run_scan(_SINKS_FIXTURE)
    remaps = compute_old_new_fingerprints(result.findings)
    assert remaps and all(r.old_fp != r.new_fp for r in remaps)
