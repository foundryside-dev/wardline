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
