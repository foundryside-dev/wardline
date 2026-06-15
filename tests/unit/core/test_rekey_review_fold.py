"""P4 review fold — the secondary findings (all real, all folded):
Filigree 2xx-with-failures, populated-collision surfacing, expired-waiver carry,
and the already-complete forward-rerun guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from wardline.core import paths  # noqa: E402
from wardline.core.errors import WardlineError  # noqa: E402
from wardline.core.filigree_emit import EmitResult, FailedFinding  # noqa: E402
from wardline.core.finding import Finding, Kind, Location, Severity  # noqa: E402
from wardline.core.rekey import (  # noqa: E402
    Journal,
    apply_pending_legs,
    probe,
    run_rekey,
    snapshot_dir,
    write_journal,
)


class _FakeEmitter:
    def __init__(self, result: EmitResult) -> None:
        self._result = result

    def emit(self, findings, *, scanned_paths=()):  # type: ignore[no-untyped-def]
        return self._result


def _defect(fp: str, line: int, tpv0: str) -> Finding:
    return Finding(
        rule_id="PY-WL-108",
        message="m",
        severity=Severity.WARN,
        kind=Kind.DEFECT,
        location=Location(path="m.py", line_start=line),
        fingerprint=fp,
        qualname="m.f",
        taint_path_v0=tpv0,
    )


def test_filigree_2xx_with_failures_records_debt_not_done(tmp_path: Path) -> None:
    # A 2xx whose body reports rejected findings is NOT a clean reconciliation.
    j = Journal(remap={})
    for n in ("baseline", "judged", "waivers"):
        j.leg(n).done = True
    partial = _FakeEmitter(
        EmitResult(
            reachable=True,
            created=1,
            failures=(
                FailedFinding(reason="rejected", fingerprint="wlfp2:p1"),
                FailedFinding(reason="rejected", fingerprint="wlfp2:p2"),
            ),
            url="http://x",
        )
    )
    apply_pending_legs(tmp_path, j, findings=[_defect("1" * 64, 3, "a@1:2")], filigree=partial)
    assert j.leg("filigree").done is False
    assert j.leg("filigree").debt and "rejected" in j.leg("filigree").debt
    assert not j.complete


def test_probe_surfaces_a_real_collision(tmp_path: Path) -> None:
    # Two findings DISTINCT under wlfp1 (different line_start -> different old_fp) but
    # sharing one new_fp -> a collision the operator must SEE.
    f1 = _defect("c" * 64, 10, "os.system@1:2")
    f2 = _defect("c" * 64, 20, "os.system@1:2")
    report = probe(tmp_path, [f1, f2])
    assert len(report.collisions) == 1
    assert report.collisions[0].new_fp == "c" * 64
    assert len(report.collisions[0].old_fps) == 2
    assert not report.clean


def test_carry_preserves_an_expired_waiver(tmp_path: Path) -> None:
    # Preservation, not filtering: an operator's expired waiver carries with its past date.
    from wardline.core.rekey import carry_waivers_forward

    a, na = "a" * 64, "1" * 64
    sp = tmp_path / "waivers.yaml"
    sp.write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp1",
                "version": 1,
                "waivers": [{"fingerprint": a, "reason": "old", "expires": "2000-01-01"}],
            }
        ),
        encoding="utf-8",
    )
    carry = carry_waivers_forward(sp, {a: na})
    entry = carry.document["waivers"][0]
    assert entry["fingerprint"] == na and entry["expires"] == "2000-01-01"


def test_run_rekey_refuses_when_already_complete(tmp_path: Path) -> None:
    # A forward re-run over a COMPLETE migration would re-carry from the stale wlfp1
    # snapshot and drop verdicts added since — refuse loudly, point at --rollback.
    root = tmp_path
    snapshot_dir(root).mkdir(parents=True)
    (snapshot_dir(root) / "baseline.yaml").write_text(
        "fingerprint_scheme: wlfp1\nversion: 1\nentries: []\n", encoding="utf-8"
    )
    j = Journal(remap={})
    for leg in j.legs:
        leg.done = True
    write_journal(paths.migration_journal_path(root), j, root=root)
    assert j.complete

    with pytest.raises(WardlineError, match="already complete"):
        run_rekey(root, [], filigree=None)
