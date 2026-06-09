"""P4 S8 — the Filigree leg: LAST, soft-fail into recorded debt, never aborts the
already-complete YAML migration."""

from __future__ import annotations

from pathlib import Path

from wardline.core.filigree_emit import EmitResult
from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.rekey import Journal, apply_pending_legs


class _FakeEmitter:
    def __init__(self, result: EmitResult) -> None:
        self._result = result
        self.calls: list = []

    def emit(self, findings, *, scanned_paths=()):  # type: ignore[no-untyped-def]
        self.calls.append(list(findings))
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


def test_filigree_leg_soft_fails_and_then_succeeds(tmp_path: Path) -> None:
    finding = _join_finding()

    # Unreachable sibling -> leg not done, debt recorded, migration NOT aborted.
    j = _journal_yaml_done()
    bad = _FakeEmitter(EmitResult(reachable=False, status=None, url="http://x"))
    apply_pending_legs(tmp_path, j, findings=[finding], filigree=bad)
    assert j.leg("filigree").done is False
    assert j.leg("filigree").debt and "unreachable" in j.leg("filigree").debt.lower()
    assert bad.calls and bad.calls[0][0].fingerprint == "1" * 64  # re-emitted under new_fp

    # A later 2xx marks it done.
    ok = _FakeEmitter(EmitResult(reachable=True, url="http://x"))
    apply_pending_legs(tmp_path, j, findings=[finding], filigree=ok)
    assert j.leg("filigree").done is True
    assert j.leg("filigree").debt is None
    assert j.complete


def test_no_filigree_configured_is_a_noop_done(tmp_path: Path) -> None:
    j = _journal_yaml_done()
    apply_pending_legs(tmp_path, j, findings=[_join_finding()], filigree=None)
    assert j.leg("filigree").done is True
    assert j.complete
