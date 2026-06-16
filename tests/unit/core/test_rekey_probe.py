"""P4 S9 — `--probe`: read-only cross-check that writes NOTHING."""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from wardline.core import paths  # noqa: E402
from wardline.core.finding import Finding, Kind, Location, Severity  # noqa: E402
from wardline.core.fingerprint_v0 import compute_finding_fingerprint_v0  # noqa: E402
from wardline.core.rekey import probe, snapshot_dir  # noqa: E402

ORPHAN = "f" * 64


def _finding() -> Finding:
    return Finding(
        rule_id="PY-WL-108",
        message="m",
        severity=Severity.WARN,
        kind=Kind.DEFECT,
        location=Location(path="m.py", line_start=10),
        fingerprint="9" * 64,
        qualname="m.f",
        taint_path_v0="os.system@4:20",
    )


def test_probe_reports_unmatched_and_writes_nothing(tmp_path: Path) -> None:
    root = tmp_path
    f = _finding()
    old_fp = compute_finding_fingerprint_v0(
        rule_id="PY-WL-108", path="m.py", line_start=10, qualname="m.f", taint_path="os.system@4:20"
    )
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    # Live baseline (old-scheme): one matchable old_fp + one orphan (source gone).
    (state / "baseline.yaml").write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp1",
                "version": 1,
                "entries": [
                    {"fingerprint": old_fp, "rule_id": "PY-WL-108", "path": "m.py", "message": "x"},
                    {"fingerprint": ORPHAN, "rule_id": "PY-WL-101", "path": "gone.py", "message": "y"},
                ],
            }
        ),
        encoding="utf-8",
    )

    report = probe(root, [f])
    assert report.scanned_findings == 1
    assert report.matched == 1
    assert report.orphaned == (ORPHAN,)
    assert report.collisions == ()
    assert report.per_store == {"baseline.yaml": 1}
    assert not report.clean

    # Writes NOTHING: no journal, no snapshot, baseline untouched.
    assert not paths.migration_journal_path(root).exists()
    assert not snapshot_dir(root).exists()


def test_probe_clean_when_all_match(tmp_path: Path) -> None:
    root = tmp_path
    f = _finding()
    old_fp = compute_finding_fingerprint_v0(
        rule_id="PY-WL-108", path="m.py", line_start=10, qualname="m.f", taint_path="os.system@4:20"
    )
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    (state / "baseline.yaml").write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp1",
                "version": 1,
                "entries": [{"fingerprint": old_fp, "rule_id": "PY-WL-108", "path": "m.py", "message": "x"}],
            }
        ),
        encoding="utf-8",
    )
    report = probe(root, [f])
    assert report.matched == 1 and report.orphaned == () and report.clean
    assert report.prescheme is False  # a wlfp1-stamped store is not pre-scheme


def test_probe_does_not_flag_an_empty_project(tmp_path: Path) -> None:
    # No stores at all -> nothing to migrate, nothing to caution about.
    assert probe(tmp_path, [_finding()]).prescheme is False


def _write_store(state: Path, name: str, *, scheme: str | None, fingerprints: list[str]) -> None:
    doc: dict = {
        "version": 1,
        "entries": [{"fingerprint": fp, "rule_id": "PY-WL-108", "path": "m.py", "message": "x"} for fp in fingerprints],
    }
    if scheme is not None:
        doc["fingerprint_scheme"] = scheme
    (state / name).write_text(yaml.safe_dump(doc), encoding="utf-8")


def test_probe_reports_a_healthy_current_scheme_baseline_as_clean_noop(tmp_path: Path) -> None:
    # A7 (weft-dda1a6d8dd): a store ALREADY stamped with the live scheme whose entries
    # all match the current scan is a healthy baseline with NO migration pending. The
    # probe must report matched=N, orphaned=0, clean — never 100% orphaned (which it
    # did when it compared every store against the wlfp1-reconstructed keys only).
    root = tmp_path
    f = _finding()
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    _write_store(state, "baseline.yaml", scheme="wlfp2", fingerprints=[f.fingerprint])

    report = probe(root, [f])
    assert report.matched == 1
    assert report.orphaned == ()
    assert report.stale == ()
    assert report.clean
    assert report.no_op
    assert report.current_scheme_stores == ("baseline.yaml",)
    # Read-only, as ever.
    assert not paths.migration_journal_path(root).exists()
    assert not snapshot_dir(root).exists()


def test_probe_current_scheme_entry_without_a_finding_is_stale_not_orphaned(tmp_path: Path) -> None:
    # An entry already at the live scheme that matches no current finding is baseline
    # DRIFT (the source changed since baselining) — a rekey would not touch it, so it
    # must not be reported as a migration orphan with the source-moved cause.
    root = tmp_path
    f = _finding()
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    _write_store(state, "baseline.yaml", scheme="wlfp2", fingerprints=[f.fingerprint, "e" * 64])

    report = probe(root, [f])
    assert report.matched == 1
    assert report.orphaned == ()
    assert report.stale == ("e" * 64,)
    assert report.no_op
    assert report.clean  # no migration pending — stale entries are hygiene, not rekey risk


def test_probe_mixed_schemes_judges_each_store_against_its_own_scheme(tmp_path: Path) -> None:
    # One store still wlfp1 (migration pending for it), one already wlfp2: the wlfp1
    # store is judged against the reconstructed old keys, the wlfp2 store against the
    # live fingerprints — neither contaminates the other's verdict.
    root = tmp_path
    f = _finding()
    old_fp = compute_finding_fingerprint_v0(
        rule_id="PY-WL-108", path="m.py", line_start=10, qualname="m.f", taint_path="os.system@4:20"
    )
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    _write_store(state, "baseline.yaml", scheme="wlfp1", fingerprints=[old_fp, ORPHAN])
    doc = {
        "fingerprint_scheme": "wlfp2",
        "version": 1,
        "waivers": [{"fingerprint": f.fingerprint, "rule_id": "PY-WL-108", "path": "m.py", "message": "x"}],
    }
    (state / "waivers.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")

    report = probe(root, [f])
    assert report.matched == 2  # old_fp via the remap keys, f.fingerprint via the live set
    assert report.orphaned == (ORPHAN,)
    assert report.per_store == {"baseline.yaml": 1}
    assert report.current_scheme_stores == ("waivers.yaml",)
    assert not report.no_op  # a wlfp1 store still pends migration
    assert not report.clean


def test_run_rekey_refuses_when_no_migration_is_pending(tmp_path: Path) -> None:
    # Companion guard to the probe fix: applying a rekey over stores ALREADY at the
    # live scheme would re-key wlfp2 entries through the wlfp1 remap and orphan every
    # verdict (the destructive twin of the A7 probe misread). Refuse before writing.
    from wardline.core.errors import WardlineError
    from wardline.core.rekey import run_rekey

    root = tmp_path
    f = _finding()
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    _write_store(state, "baseline.yaml", scheme="wlfp2", fingerprints=[f.fingerprint])
    before = (state / "baseline.yaml").read_bytes()

    with pytest.raises(WardlineError, match="no fingerprint migration is pending"):
        run_rekey(root, [f])
    assert (state / "baseline.yaml").read_bytes() == before
    assert not paths.migration_journal_path(root).exists()
    assert not snapshot_dir(root).exists()


def test_probe_flags_a_scheme_less_prescheme_store(tmp_path: Path) -> None:
    # A POPULATED store with NO fingerprint_scheme header predates P1's stamp. Its
    # fingerprints may also predate 705acfe (resolved-taint) -> v0 can't reconstruct them
    # and verdicts orphan from a formula change, not source churn. Surface the possibility.
    root = tmp_path
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    (state / "baseline.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "entries": [{"fingerprint": "a" * 64, "rule_id": "PY-WL-101", "path": "x.py", "message": "y"}],
            }
        ),
        encoding="utf-8",
    )
    assert probe(root, [_finding()]).prescheme is True
