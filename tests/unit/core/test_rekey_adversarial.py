"""P4 — adversarial rekey coverage (wardline-85b418585b).

Two scenarios beyond the single-store rollback that existing tests cover:

(a) MIXED-SCHEME PARTIAL migration with a pre-resume SOURCE change. One leg is
    already migrated (live store rewritten to wlfp2), another is still pending
    (live store still wlfp1) — a genuine two-scheme-at-once live tree — and the
    project source mutates before `--resume`. Because the resume path reads ONLY
    the immutable snapshot + the frozen journal remap (never re-scans, never reads
    the live store or source), the source change MUST be a no-op: the pending leg
    carries the snapshot verdict deterministically and the already-done leg is left
    byte-untouched. Proves no verdict loss / no silent corruption / deterministic.

(b) MULTI-STORE rollback restores all-or-nothing. A rollback spanning >1 store
    restores every one byte-identical (the stated single-store gap), and — under a
    mid-rollback write failure — the snapshot is left fully intact so a re-run
    converges (no unrecoverable half-rolled-back state, no data loss).
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from wardline.core import paths  # noqa: E402
from wardline.core.baseline import load_baseline  # noqa: E402
from wardline.core.errors import WardlineError  # noqa: E402
from wardline.core.judged import load_judged  # noqa: E402
from wardline.core.rekey import (  # noqa: E402
    Journal,
    Leg,
    carry_baseline_forward,
    resume_rekey,
    rollback,
    snapshot_dir,
    write_journal,
)

# Old (wlfp1) / new (wlfp2) fingerprints for two distinct verdicts.
A_OLD, A_NEW = "a" * 64, "1" * 64
B_OLD, B_NEW = "b" * 64, "2" * 64


def _seed_snapshot(root: Path) -> None:
    """Snapshot two old-scheme stores: a baseline (verdict A) + a judged (verdict B)."""
    sdir = snapshot_dir(root)
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / "baseline.yaml").write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp1",
                "version": 1,
                "entries": [{"fingerprint": A_OLD, "rule_id": "PY-WL-108", "path": "m.py", "message": "x"}],
            }
        ),
        encoding="utf-8",
    )
    (sdir / "judged.yaml").write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp1",
                "version": 1,
                "findings": [
                    {
                        "fingerprint": B_OLD,
                        "rule_id": "PY-WL-108",
                        "path": "m.py",
                        "verdict": "FALSE_POSITIVE",
                        "rationale": "sanitized at the boundary",
                        "model_id": "test-model",
                        "policy_hash": "deadbeef",
                        "confidence": 0.97,
                        "recorded_at": "2026-06-10T00:00:00Z",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


# --- (a) mixed-scheme partial migration + pre-resume source change ----------------


def test_mixed_scheme_partial_resume_ignores_source_change(tmp_path: Path) -> None:
    """Baseline already migrated (wlfp2 live), judged still pending (wlfp1 live), and
    the source changes before resume. Resume must carry the judged verdict from the
    SNAPSHOT (no re-scan), leave the already-done baseline byte-identical, and orphan
    nothing — the source mutation is a no-op by construction."""
    root = tmp_path
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    _seed_snapshot(root)

    remap = {A_OLD: A_NEW, B_OLD: B_NEW}

    # Hand-build the crash-mid-migration state: baseline leg DONE with a wlfp2 live store;
    # judged leg PENDING with the ORIGINAL wlfp1 live store still in place.
    res = carry_baseline_forward(snapshot_dir(root) / "baseline.yaml", remap)
    from wardline.core.rekey import _write_store_doc  # noqa: PLC0415

    _write_store_doc(root, paths.baseline_path(root), res.document)
    # judged live store is still the old wlfp1 doc (copy the snapshot back as "live"):
    (state / "judged.yaml").write_bytes((snapshot_dir(root) / "judged.yaml").read_bytes())

    journal = Journal(
        remap=remap,
        legs=[
            Leg("baseline", done=True, carried=[A_OLD]),
            Leg("judged", done=False),
            Leg("waivers", done=True),  # never existed -> treated done
            Leg("filigree", done=True),
        ],
    )
    write_journal(paths.migration_journal_path(root), journal, root=root)

    # The live tree genuinely holds BOTH schemes at once right now.
    assert load_baseline(paths.baseline_path(root)).fingerprints == frozenset({A_NEW})
    with pytest.raises(WardlineError):  # judged live store is still wlfp1 -> rejected by loader
        load_judged(paths.judged_path(root))

    # Mutate the project source AFTER the partial migration, BEFORE resume.
    (root / "m.py").write_text("# changed source — must not affect the resume\nprint('x')\n", encoding="utf-8")

    baseline_before = paths.baseline_path(root).read_bytes()

    resumed = resume_rekey(root, findings=None, filigree=None)

    # (i) judged pending leg carried the SNAPSHOT verdict, re-keyed to wlfp2.
    assert load_judged(paths.judged_path(root)).fingerprints() == frozenset({B_NEW})
    assert resumed.leg("judged").done is True
    assert resumed.leg("judged").orphaned == []  # source change did NOT orphan the verdict
    assert resumed.complete

    # (ii) the already-done baseline leg was left byte-identical (not re-derived/rewritten).
    assert paths.baseline_path(root).read_bytes() == baseline_before
    assert load_baseline(paths.baseline_path(root)).fingerprints == frozenset({A_NEW})

    # (iii) deterministic: a second resume reproduces byte-identical stores.
    judged_after = paths.judged_path(root).read_bytes()
    resume_rekey(root, findings=None, filigree=None)
    assert paths.judged_path(root).read_bytes() == judged_after
    assert paths.baseline_path(root).read_bytes() == baseline_before


def test_mixed_scheme_resume_is_source_independent_proof(tmp_path: Path) -> None:
    """Tightened proof that the carry is snapshot-bound: even if the post-crash LIVE
    judged store is corrupted to empty AND the source is deleted, resume still re-derives
    the verdict from the immutable snapshot."""
    root = tmp_path
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    _seed_snapshot(root)
    remap = {A_OLD: A_NEW, B_OLD: B_NEW}

    # Corrupt the live judged store to an EMPTY wlfp2 doc (simulates a torn write).
    (state / "judged.yaml").write_text(
        yaml.safe_dump({"fingerprint_scheme": "wlfp2", "version": 1, "findings": []}), encoding="utf-8"
    )
    journal = Journal(
        remap=remap,
        legs=[
            Leg("baseline", done=True),
            Leg("judged", done=False),
            Leg("waivers", done=True),
            Leg("filigree", done=True),
        ],
    )
    write_journal(paths.migration_journal_path(root), journal, root=root)

    # No source file at all (deleted) — must not matter.
    resume_rekey(root, findings=None, filigree=None)

    assert load_judged(paths.judged_path(root)).fingerprints() == frozenset({B_NEW}), (
        "resume must re-derive the verdict from the snapshot — an empty store here would mean "
        "the judged verdict was silently shredded by trusting the corrupted live store"
    )


# --- (b) multi-store rollback: all-or-nothing -------------------------------------


def _seed_for_rollback(root: Path) -> tuple[bytes, bytes]:
    """Snapshot baseline + judged (pre-migration), and write DIFFERENT wlfp2 live stores
    + a journal, as a completed multi-store migration. Returns the two snapshot blobs."""
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    _seed_snapshot(root)
    sdir = snapshot_dir(root)
    base_orig = (sdir / "baseline.yaml").read_bytes()
    judged_orig = (sdir / "judged.yaml").read_bytes()
    # Migrated (wlfp2) live stores — what rollback must overwrite.
    (state / "baseline.yaml").write_bytes(b"REKEYED-wlfp2-BASELINE")
    (state / "judged.yaml").write_bytes(b"REKEYED-wlfp2-JUDGED")
    paths.migration_journal_path(root).write_text("schema_version: 1\nremap: {}\n", encoding="utf-8")
    return base_orig, judged_orig


def test_multistore_rollback_restores_all_byte_identical(tmp_path: Path) -> None:
    """A rollback spanning TWO stores restores BOTH byte-identical and clears journal +
    snapshot — no store is left in its migrated (wlfp2) state."""
    root = tmp_path
    state = paths.weft_state_dir(root)
    base_orig, judged_orig = _seed_for_rollback(root)

    result = rollback(root)

    assert set(result.restored) == {"baseline.yaml", "judged.yaml"}
    assert (state / "baseline.yaml").read_bytes() == base_orig
    assert (state / "judged.yaml").read_bytes() == judged_orig
    assert not paths.migration_journal_path(root).exists()
    sdir = snapshot_dir(root)
    assert not (sdir / "baseline.yaml").exists()
    assert not (sdir / "judged.yaml").exists()


def test_multistore_rollback_failure_preserves_snapshot_and_converges(tmp_path: Path) -> None:
    """If the SECOND store's restore write fails mid-rollback, the snapshot must remain
    fully intact (deletion is after all writes) so a re-run converges — no unrecoverable
    half-rolled-back state, no verdict loss. all-or-nothing = recoverable, not torn."""
    root = tmp_path
    state = paths.weft_state_dir(root)
    base_orig, judged_orig = _seed_for_rollback(root)
    sdir = snapshot_dir(root)

    # Force the judged restore write to fail: pre-create the live path AS A DIRECTORY so
    # write_bytes raises (IsADirectoryError). The first store (baseline) restores fine.
    (state / "judged.yaml").unlink()
    (state / "judged.yaml").mkdir()

    with pytest.raises(OSError):
        rollback(root)

    # The snapshot is UNTOUCHED — both legs of provenance survive the partial failure.
    assert (sdir / "baseline.yaml").read_bytes() == base_orig
    assert (sdir / "judged.yaml").read_bytes() == judged_orig
    assert paths.migration_journal_path(root).exists()  # journal not removed -> resume/rollback still possible

    # Heal the obstruction and re-run: rollback now converges, restoring ALL stores.
    (state / "judged.yaml").rmdir()
    result = rollback(root)
    assert set(result.restored) == {"baseline.yaml", "judged.yaml"}
    assert (state / "baseline.yaml").read_bytes() == base_orig
    assert (state / "judged.yaml").read_bytes() == judged_orig
    assert not paths.migration_journal_path(root).exists()
