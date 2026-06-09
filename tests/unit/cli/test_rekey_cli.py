"""P4 S11 — `wardline rekey` end to end over a copied tree: migrate / probe / resume / rollback."""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
pytest.importorskip("blake3", reason="run_scan needs wardline[loomweave]")

from click.testing import CliRunner  # noqa: E402

from wardline.cli.main import cli  # noqa: E402
from wardline.core import paths  # noqa: E402
from wardline.core.baseline import load_baseline  # noqa: E402
from wardline.core.fingerprint_v0 import compute_finding_fingerprint_v0  # noqa: E402
from wardline.core.rekey import load_journal, snapshot_dir, write_journal  # noqa: E402
from wardline.core.run import run_scan  # noqa: E402

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return raw(p)\n"
)


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return project


def _seed_wlfp1_baseline(project: Path):
    """Seed an OLD-scheme baseline whose entry is the real wlfp1 fingerprint of the
    leaky PY-WL-101 finding (so the migration genuinely carries it to its new_fp)."""
    leak = next(f for f in run_scan(project).findings if f.rule_id == "PY-WL-101")
    old_fp = compute_finding_fingerprint_v0(
        rule_id=leak.rule_id,
        path=leak.location.path,
        line_start=leak.location.line_start,
        qualname=leak.qualname,
        taint_path=leak.taint_path_v0,
    )
    bp = paths.baseline_path(project)
    bp.parent.mkdir(parents=True, exist_ok=True)
    bp.write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp1",
                "version": 1,
                "entries": [
                    {
                        "fingerprint": old_fp,
                        "rule_id": leak.rule_id,
                        "path": leak.location.path,
                        "message": leak.message,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return leak, old_fp


def test_rekey_migrates_baseline_and_is_resumable_without_rescan(tmp_path: Path) -> None:
    project = _project(tmp_path)
    leak, old_fp = _seed_wlfp1_baseline(project)
    assert leak.fingerprint != old_fp

    res = CliRunner().invoke(cli, ["rekey", str(project)])
    assert res.exit_code == 0, res.output
    assert load_baseline(paths.baseline_path(project)).fingerprints == frozenset({leak.fingerprint})
    assert paths.migration_journal_path(project).is_file()
    assert (snapshot_dir(project) / "baseline.yaml").is_file()

    # RESUME WITHOUT RE-SCAN: revert the baseline leg to pending + corrupt the live store,
    # then DELETE the source so any re-scan would fail — resume must still re-derive the
    # verdict from the snapshot.
    jpath = paths.migration_journal_path(project)
    journal = load_journal(jpath)
    journal.leg("baseline").done = False
    write_journal(jpath, journal, root=project)
    paths.baseline_path(project).write_text(
        yaml.safe_dump({"fingerprint_scheme": "wlfp2", "version": 1, "entries": []}), encoding="utf-8"
    )
    (project / "svc.py").unlink()  # a re-scan would now find nothing / error

    res2 = CliRunner().invoke(cli, ["rekey", str(project), "--resume"])
    assert res2.exit_code == 0, res2.output
    assert load_baseline(paths.baseline_path(project)).fingerprints == frozenset({leak.fingerprint})
    assert "predates" not in res2.output  # a schemed wlfp1 store must NOT trip the prescheme caution


def test_rekey_probe_writes_nothing(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _seed_wlfp1_baseline(project)
    res = CliRunner().invoke(cli, ["rekey", str(project), "--probe"])
    assert res.exit_code == 0, res.output
    assert "will carry" in res.output
    assert "predates" not in res.output  # a schemed wlfp1 store must NOT trip the prescheme caution
    assert not paths.migration_journal_path(project).exists()
    assert not snapshot_dir(project).exists()


def test_rekey_rollback_restores(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _seed_wlfp1_baseline(project)
    original = paths.baseline_path(project).read_bytes()
    assert CliRunner().invoke(cli, ["rekey", str(project)]).exit_code == 0
    assert paths.baseline_path(project).read_bytes() != original  # migrated

    res = CliRunner().invoke(cli, ["rekey", str(project), "--rollback"])
    assert res.exit_code == 0, res.output
    assert paths.baseline_path(project).read_bytes() == original  # byte-identical restore
    assert not paths.migration_journal_path(project).exists()


def test_probe_cautions_on_a_scheme_less_store(tmp_path: Path) -> None:
    # A scheme-less (pre-P1) baseline -> the probe must caution that a high orphan rate may
    # be a fingerprint-formula change, not source churn, AND the orphan label must name the
    # custom-rule cause (not only "source moved/deleted").
    project = _project(tmp_path)
    bp = paths.baseline_path(project)
    bp.parent.mkdir(parents=True, exist_ok=True)
    # NO fingerprint_scheme header; one entry that no current finding matches -> an orphan.
    bp.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "entries": [{"fingerprint": "a" * 64, "rule_id": "PY-WL-101", "path": "svc.py", "message": "x"}],
            }
        ),
        encoding="utf-8",
    )
    res = CliRunner().invoke(cli, ["rekey", str(project), "--probe"])
    assert res.exit_code == 1, res.output  # an orphan present -> non-clean probe
    assert "predates" in res.output  # the pre-scheme caution fired
    assert "taint_path_v0" in res.output  # the orphan label names the custom-rule cause


def test_rekey_on_scheme_less_baseline_sets_flag_and_cautions_on_resume(tmp_path: Path) -> None:
    # End-to-end snapshot-detection path (distinct from --probe, which reads LIVE stores):
    # a scheme-less (pre-P1) baseline whose fingerprints DO reconstruct still carries, but the
    # forward run must FLAG it from the SNAPSHOT (journal.snapshot_prescheme) and caution, and
    # --resume must re-print that caution from the persisted journal.
    project = _project(tmp_path)
    leak, _ = _seed_wlfp1_baseline(project)
    bp = paths.baseline_path(project)
    doc = yaml.safe_load(bp.read_text(encoding="utf-8"))
    doc.pop("fingerprint_scheme", None)  # strip the header -> scheme-less / pre-P1
    bp.write_text(yaml.safe_dump(doc), encoding="utf-8")

    res = CliRunner().invoke(cli, ["rekey", str(project)])
    assert res.exit_code == 0, res.output
    assert "predates" in res.output  # forward run cautions (flag read from the snapshot)
    jpath = paths.migration_journal_path(project)
    assert load_journal(jpath).snapshot_prescheme is True  # persisted onto the journal
    assert load_baseline(bp).fingerprints == frozenset({leak.fingerprint})  # still carried

    journal = load_journal(jpath)
    journal.leg("baseline").done = False
    write_journal(jpath, journal, root=project)
    res2 = CliRunner().invoke(cli, ["rekey", str(project), "--resume"])
    assert res2.exit_code == 0, res2.output
    assert "predates" in res2.output  # --resume re-prints the caution from the loaded journal


def test_mutually_exclusive_flags(tmp_path: Path) -> None:
    res = CliRunner().invoke(cli, ["rekey", str(_project(tmp_path)), "--probe", "--rollback"])
    assert res.exit_code == 2
    assert "mutually exclusive" in res.output
