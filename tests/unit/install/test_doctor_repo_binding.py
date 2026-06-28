"""doctor.repo_binding — the READ-ONLY repo-binding / store-read check.

The wardline analog of the 2026-06-26 loomweave stale-binary incident: a server can
start cleanly (initialize + tools/list succeed) yet be unable to READ its repo-scoped
baseline store, so its findings silently go dark. This check reports a fact READ FROM
INSIDE the store (its schema version) so the seam can say "I cannot read my store"
instead of looking healthy. Fork-1 status split: ABSENT is opt-in (status ok, never
flips doctor.ok); PRESENT-but-UNREADABLE is the incident (status error, flips ok).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from wardline.core.baseline import BASELINE_VERSION, write_baseline
from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.paths import baseline_path
from wardline.install.doctor import _check_repo_binding, machine_readable_doctor

_FP_A = "a" * 64
_FP_B = "b" * 64


def _finding(fp: str) -> Finding:
    return Finding(
        rule_id="PY-WL-101",
        message=f"msg {fp[:4]}",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/m.py", line_start=1),
        fingerprint=fp,
    )


def test_check_repo_binding_present_readable(tmp_path: Path) -> None:
    # Round-trip through the REAL writer at the REAL path, then read it back.
    write_baseline(baseline_path(tmp_path), [_finding(_FP_A), _finding(_FP_B)], root=tmp_path)
    check, block = _check_repo_binding(tmp_path)
    assert check.id == "doctor.repo_binding"
    assert check.status == "ok"
    assert check.to_dict()["fixed"] is False
    assert block["resolved_root"] == str(tmp_path)
    assert block["binding_ok"] is True
    assert block["store"] == {
        "present": True,
        "readable": True,
        "schema_version": BASELINE_VERSION,
        "baseline_finding_count": 2,
    }


def test_check_repo_binding_absent_is_ok_not_error(tmp_path: Path) -> None:
    # Opt-in feature not set up: absence is NOT the incident — status stays ok so it
    # never flips doctor.ok nor nags every baseline-less repo.
    check, block = _check_repo_binding(tmp_path)
    assert check.status == "ok"
    assert block["binding_ok"] is False
    assert block["store"]["present"] is False
    assert block["store"]["schema_version"] is None
    assert block["store"]["baseline_finding_count"] is None


def test_check_repo_binding_present_unreadable_is_error(tmp_path: Path) -> None:
    # The stale-binary incident: a store at a schema this build does not serve. status
    # error (flips doctor.ok); the on-disk version is named in the message even though
    # store.schema_version reports null.
    write_baseline(baseline_path(tmp_path), [_finding(_FP_A)], root=tmp_path)
    p = baseline_path(tmp_path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    raw["version"] = 999
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")
    check, block = _check_repo_binding(tmp_path)
    assert check.status == "error"
    assert check.ok is False
    assert "999" in (check.message or "")
    assert block["binding_ok"] is False
    assert block["store"]["readable"] is False
    assert block["store"]["schema_version"] is None


def test_check_repo_binding_symlinked_store_is_unreadable_not_followed(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside-baseline.yaml"
    write_baseline(outside, [_finding(_FP_A)], root=None)
    p = baseline_path(tmp_path)
    p.parent.mkdir(parents=True)
    p.symlink_to(outside)

    check, block = _check_repo_binding(tmp_path)

    assert check.status == "error"
    assert check.ok is False
    assert block["binding_ok"] is False
    assert block["store"] == {
        "present": True,
        "readable": False,
        "schema_version": None,
        "baseline_finding_count": None,
    }
    assert "baseline.yaml" in (check.message or "")
    assert str(outside) not in (check.message or "")


def _isolate(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: tmp_path / "home")
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)


def test_machine_readable_doctor_carries_repo_binding_block_and_check(tmp_path: Path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    payload = machine_readable_doctor(tmp_path, fix=False)
    assert "repo_binding" in payload
    rb = payload["repo_binding"]
    assert rb["resolved_root"] == str(tmp_path)
    assert set(rb["store"]) == {"present", "readable", "schema_version", "baseline_finding_count"}
    assert "binding_ok" in rb
    by_id = {c["id"]: c for c in payload["checks"]}
    assert "doctor.repo_binding" in by_id


def test_machine_readable_doctor_absent_store_does_not_flip_ok(tmp_path: Path, monkeypatch) -> None:
    # An absent baseline must NOT force doctor.ok false via the repo_binding check.
    _isolate(tmp_path, monkeypatch)
    payload = machine_readable_doctor(tmp_path, fix=False)
    by_id = {c["id"]: c for c in payload["checks"]}
    assert by_id["doctor.repo_binding"]["status"] == "ok"
    assert "doctor.repo_binding" not in " ".join(payload["next_actions"])


def test_machine_readable_doctor_unreadable_store_flips_ok(tmp_path: Path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    write_baseline(baseline_path(tmp_path), [_finding(_FP_A)], root=tmp_path)
    p = baseline_path(tmp_path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    raw["version"] = 999
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")
    payload = machine_readable_doctor(tmp_path, fix=False)
    assert payload["ok"] is False
    assert any("doctor.repo_binding" in a for a in payload["next_actions"])
