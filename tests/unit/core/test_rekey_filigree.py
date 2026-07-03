"""P4 S8 — the Filigree leg: LAST, soft-fail into recorded debt, never aborts the
already-complete YAML migration."""

from __future__ import annotations

from pathlib import Path

import yaml

from wardline.core import paths
from wardline.core.filigree_emit import EmitResult
from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.fingerprint_v0 import compute_finding_fingerprint_v0
from wardline.core.rekey import Journal, apply_pending_legs, load_journal, run_rekey


class _FakeEmitter:
    def __init__(self, result: EmitResult) -> None:
        self._result = result
        self.calls: list = []
        self.scanned_paths_calls: list = []

    def emit(self, findings, *, scanned_paths=()):  # type: ignore[no-untyped-def]
        self.calls.append(list(findings))
        self.scanned_paths_calls.append(list(scanned_paths))
        return self._result


def _join_finding() -> Finding:
    return Finding(
        rule_id="PY-WL-108",
        message="m",
        severity=Severity.WARN,
        kind=Kind.DEFECT,
        location=Location(path="m.py", line_start=3),
        fingerprint="1" * 64,
    )


def _journal_yaml_done() -> Journal:
    j = Journal(remap={})
    for name in ("baseline", "judged", "waivers"):
        j.leg(name).done = True
    return j


def _seed_old_baseline(root: Path, finding: Finding) -> str:
    old_fp = compute_finding_fingerprint_v0(
        rule_id=finding.rule_id,
        path=finding.location.path,
        line_start=finding.location.line_start,
        qualname=finding.qualname,
        taint_path=finding.taint_path_v0,
    )
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True, exist_ok=True)
    (state / "baseline.yaml").write_text(
        yaml.safe_dump(
            {
                "fingerprint_scheme": "wlfp1",
                "version": 1,
                "entries": [
                    {
                        "fingerprint": old_fp,
                        "rule_id": finding.rule_id,
                        "path": finding.location.path,
                        "message": finding.message,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return old_fp


def test_filigree_leg_soft_fails_and_then_succeeds(tmp_path: Path) -> None:
    finding = _join_finding()

    # Unreachable sibling -> leg not done, debt recorded, migration NOT aborted.
    j = _journal_yaml_done()
    bad = _FakeEmitter(EmitResult(reachable=False, status=None, url="http://x"))
    apply_pending_legs(tmp_path, j, findings=[finding], filigree=bad)
    assert j.leg("filigree").done is False
    filigree_debt = j.leg("filigree").debt
    assert filigree_debt and "unreachable" in filigree_debt.lower()
    assert bad.calls and bad.calls[0][0].fingerprint == "1" * 64  # re-emitted under new_fp

    # A later 2xx marks it done.
    ok = _FakeEmitter(EmitResult(reachable=True, url="http://x"))
    apply_pending_legs(tmp_path, j, findings=[finding], filigree=ok)
    assert j.leg("filigree").done is True
    assert j.leg("filigree").debt is None
    assert j.complete


def test_filigree_leg_emits_all_kinds_not_the_defect_only_join_population(tmp_path: Path) -> None:
    # The re-emit rides Filigree's kind-blind, per-(file, scan_source) mark_unseen
    # sweep. A DEFECT-only subset would (a) sweep still-live FACT fingerprints on the
    # named files as unseen (false "fixed"), and (b) drop the FACT-kind
    # incomplete-analysis markers (e.g. WLN-ENGINE-SOURCE-ROOT-MISSING) BEFORE the
    # emitter's has_incomplete_analysis guard runs, enabling a sweep the normal
    # all-kinds emit path would refuse. So the leg must emit the FULL finding set,
    # exactly like a normal scan emit — while ``carried`` still records only the
    # DEFECT join population the stores re-keyed on.
    defect = _join_finding()
    fact = Finding(
        rule_id="WLN-ENGINE-SOURCE-ROOT-MISSING",
        message="configured source root does not exist",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=Location(path="<engine>", line_start=1),
        fingerprint="f" * 64,
    )
    colocated_fact = Finding(
        rule_id="WLN-ENGINE-UNKNOWN-IMPORT",
        message="unknown import",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=Location(path="m.py", line_start=1),
        fingerprint="e" * 64,
    )

    j = _journal_yaml_done()
    ok = _FakeEmitter(EmitResult(reachable=True, url="http://x"))
    apply_pending_legs(tmp_path, j, findings=[defect, fact, colocated_fact], filigree=ok)

    assert j.leg("filigree").done is True
    emitted = ok.calls[0]
    # ALL kinds are on the wire (the FACTs are re-asserted, so the sweep cannot read
    # their absence as a fix, and the incomplete-analysis marker reaches the guard).
    assert {f.fingerprint for f in emitted} == {defect.fingerprint, fact.fingerprint, colocated_fact.fingerprint}
    assert any(f.kind is Kind.FACT for f in emitted)
    # scanned_paths covers every emitted finding's file (complete-per-path chunks).
    assert ok.scanned_paths_calls[0] == sorted({"m.py", "<engine>"})
    # ...but the store-join bookkeeping stays DEFECT-only.
    assert j.leg("filigree").carried == [defect.fingerprint]


def test_no_filigree_configured_is_a_noop_done(tmp_path: Path) -> None:
    j = _journal_yaml_done()
    apply_pending_legs(tmp_path, j, findings=[_join_finding()], filigree=None)
    assert j.leg("filigree").done is True
    assert j.complete


def test_forward_rerun_retries_deferred_filigree_leg_when_yaml_is_current(tmp_path: Path) -> None:
    finding = _join_finding()
    old_fp = _seed_old_baseline(tmp_path, finding)
    assert old_fp != finding.fingerprint

    bad = _FakeEmitter(EmitResult(reachable=False, status=503, url="http://x"))
    first = run_rekey(tmp_path, [finding], filigree=bad)
    assert first.complete is False
    assert first.leg("baseline").done is True
    assert first.leg("filigree").done is False

    stored = yaml.safe_load(paths.baseline_path(tmp_path).read_text(encoding="utf-8"))
    assert stored["fingerprint_scheme"] == "wlfp2"
    assert load_journal(paths.migration_journal_path(tmp_path)).complete is False

    ok = _FakeEmitter(EmitResult(reachable=True, url="http://x"))
    second = run_rekey(tmp_path, [finding], filigree=ok)

    assert ok.calls and ok.calls[0][0].fingerprint == finding.fingerprint
    assert second.complete is True
    assert second.leg("filigree").done is True
    assert load_journal(paths.migration_journal_path(tmp_path)).complete is True
