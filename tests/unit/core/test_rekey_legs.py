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
from wardline.core.judge_types import JudgeTransport  # noqa: E402
from wardline.core.judged import load_judged  # noqa: E402
from wardline.core.rekey import (  # noqa: E402
    Journal,
    _write_store_doc,  # noqa: E402
    apply_pending_legs,
    carry_baseline_forward,
    carry_judged_forward,
    resume_rekey,
    snapshot_dir,
    write_journal,
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


def _seed_snapshot_judged_v1(root: Path) -> None:
    sdir = snapshot_dir(root)
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / "judged.yaml").write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp1",
                "version": 1,
                "findings": [
                    {
                        "fingerprint": A,
                        "rule_id": "PY-WL-108",
                        "path": "m.py",
                        "message": "shell",
                        "verdict": "FALSE_POSITIVE",
                        "rationale": "legacy verdict",
                        "confidence": 0.97,
                        "model_id": "anthropic/claude",
                        "recorded_at": "2026-06-01T00:00:00+00:00",
                        "policy_hash": "deadbeef",
                    }
                ],
            },
            sort_keys=False,
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


def test_apply_pending_judged_leg_migrates_v1_to_loadable_v2(tmp_path: Path) -> None:
    root = tmp_path
    _seed_snapshot_judged_v1(root)
    journal = Journal(remap={A: NA})

    apply_pending_legs(root, journal, findings=[])

    carried = load_judged(paths.judged_path(root)).match(NA)
    document = yaml.safe_load(paths.judged_path(root).read_text(encoding="utf-8"))
    assert document["version"] == 2
    assert carried is not None
    assert carried.judge_transport is JudgeTransport.OPENROUTER


def test_resume_rederives_v1_judged_snapshot_with_concrete_transport(tmp_path: Path) -> None:
    root = tmp_path
    _seed_snapshot_judged_v1(root)
    journal = Journal(remap={A: NA})
    journal.leg("baseline").done = True

    result = carry_judged_forward(snapshot_dir(root) / "judged.yaml", journal.remap)
    _write_store_doc(root, paths.judged_path(root), result.document)
    paths.judged_path(root).write_text("corrupted live store\n", encoding="utf-8")
    assert journal.leg("judged").done is False
    write_journal(paths.migration_journal_path(root), journal, root=root)

    resume_rekey(root)

    carried = load_judged(paths.judged_path(root)).match(NA)
    assert carried is not None
    assert carried.judge_transport is JudgeTransport.OPENROUTER


def test_preflight_rejects_invalid_v2_judged_before_baseline_mutation(tmp_path: Path) -> None:
    root = tmp_path
    _seed_snapshot_baseline(root)
    sdir = snapshot_dir(root)
    (sdir / "judged.yaml").write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp2",
                "version": 2,
                "findings": [{"fingerprint": A, "judge_transport": "auto"}],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    baseline_live = paths.baseline_path(root)
    baseline_live.write_bytes(b"baseline-live-before")
    before = baseline_live.read_bytes()

    with pytest.raises(ConfigError, match="judge_transport"):
        apply_pending_legs(root, Journal(remap={A: NA}))

    assert baseline_live.read_bytes() == before


def test_resume_preflights_every_pending_snapshot_scheme_before_any_write(tmp_path: Path) -> None:
    root = tmp_path
    _seed_snapshot_baseline(root)
    sdir = snapshot_dir(root)
    (sdir / "judged.yaml").write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp999",
                "version": 1,
                "findings": [{"fingerprint": A, "rule_id": "PY-WL-108", "path": "m.py"}],
            }
        ),
        encoding="utf-8",
    )

    baseline_live = paths.baseline_path(root)
    judged_live = paths.judged_path(root)
    baseline_live.write_bytes(b"baseline-live-before")
    judged_live.write_bytes(b"judged-live-before")
    journal_path = paths.migration_journal_path(root)
    write_journal(journal_path, Journal(remap={A: NA}), root=root)
    before = {
        baseline_live: baseline_live.read_bytes(),
        judged_live: judged_live.read_bytes(),
        journal_path: journal_path.read_bytes(),
    }

    with pytest.raises(ConfigError, match="judged.yaml: unsupported fingerprint scheme 'wlfp999'"):
        resume_rekey(root)

    assert {path: path.read_bytes() for path in before} == before
