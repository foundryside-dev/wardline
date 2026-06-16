"""P4 S7 — per-leg idempotent application + the crash-after-write-before-flag proof.

The crash test is the one that matters: carry NEVER reads the live store, only the
snapshot, so a resume after a partial run (store written, done-flag not persisted, and
even the live store corrupted) re-derives the CORRECT content — never an empty store.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from wardline.core import paths  # noqa: E402
from wardline.core.baseline import load_baseline  # noqa: E402
from wardline.core.errors import ConfigError  # noqa: E402
from wardline.core.rekey import (  # noqa: E402
    Journal,
    _write_store_doc,  # noqa: E402
    apply_pending_legs,
    carry_baseline_forward,
    snapshot_dir,
)

A, NA = "a" * 64, "1" * 64


def _seed_snapshot_baseline(root: Path) -> None:
    sdir = snapshot_dir(root)
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / "baseline.yaml").write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp1",  # old scheme — the pre-migration state
                "version": 1,
                "entries": [{"fingerprint": A, "rule_id": "PY-WL-108", "path": "m.py", "message": "x"}],
            }
        ),
        encoding="utf-8",
    )


def test_legs_idempotent_and_gate_green_after_yaml(tmp_path: Path) -> None:
    root = tmp_path
    _seed_snapshot_baseline(root)
    journal = Journal(remap={A: NA})  # findings=[] (forward run) + filigree=None -> filigree leg is a no-op done

    apply_pending_legs(root, journal, findings=[])
    bp = paths.baseline_path(root)
    # Gate green under wlfp2: the rekeyed store loads clean (no SCHEME_MISMATCH)...
    assert load_baseline(bp).fingerprints == frozenset({NA})
    # ...while the pre-migration snapshot is still old-scheme (would fail to load).
    with pytest.raises(ConfigError):
        load_baseline(snapshot_dir(root) / "baseline.yaml")
    assert journal.complete

    # Idempotent: a second run rewrites nothing (every leg already done).
    mtime = bp.stat().st_mtime_ns
    apply_pending_legs(root, journal, findings=[])
    assert bp.stat().st_mtime_ns == mtime


def test_crash_after_write_before_flag_preserves_content(tmp_path: Path) -> None:
    root = tmp_path
    _seed_snapshot_baseline(root)
    journal = Journal(remap={A: NA})

    # Simulate a crash: the baseline leg WROTE the store but the done-flag was never
    # persisted (leg.done stays False). Then — to prove resume does NOT trust the live
    # store — corrupt the live store to an EMPTY one.
    res = carry_baseline_forward(snapshot_dir(root) / "baseline.yaml", journal.remap)
    _write_store_doc(root, paths.baseline_path(root), res.document)
    paths.baseline_path(root).write_text(
        yaml.safe_dump({"fingerprint_scheme": "wlfp2", "version": 1, "entries": []}), encoding="utf-8"
    )
    assert journal.leg("baseline").done is False  # crash left it pending

    # Resume: re-carries from the SNAPSHOT, not the corrupted live store.
    apply_pending_legs(root, journal)
    assert load_baseline(paths.baseline_path(root)).fingerprints == frozenset({NA}), (
        "resume must re-derive verdicts from the snapshot — an empty store here would mean "
        "every verdict was silently shredded"
    )
