"""P4 S5 — carry verdicts from the SNAPSHOT (D-PROVENANCE), byte-preserving every
non-fingerprint field, flagging orphans, and producing a doc that loads clean under
wlfp2 (the S12 contract, proven early)."""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from wardline.core import paths  # noqa: E402
from wardline.core.baseline import load_baseline  # noqa: E402
from wardline.core.judged import load_judged  # noqa: E402
from wardline.core.rekey import (  # noqa: E402
    carry_baseline_forward,
    carry_judged_forward,
    carry_waivers_forward,
)
from wardline.core.waivers import load_project_waivers  # noqa: E402

A, B, C = "a" * 64, "b" * 64, "c" * 64
NA, NB = "1" * 64, "2" * 64
REMAP = {A: NA, B: NB}  # C is intentionally absent -> orphan


def _seed(path: Path, doc: dict) -> None:
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def test_carry_baseline_preserves_fields_and_flags_orphan(tmp_path: Path) -> None:
    sp = tmp_path / "baseline.yaml"
    _seed(
        sp,
        {
            "fingerprint_scheme": "wlfp1",  # OLD scheme — loaders would reject; carry reads raw
            "version": 1,
            "entries": [
                {"fingerprint": A, "rule_id": "PY-WL-108", "path": "m.py", "message": "shell"},
                {"fingerprint": B, "rule_id": "PY-WL-101", "path": "n.py", "message": "ret"},
                {"fingerprint": C, "rule_id": "PY-WL-102", "path": "o.py", "message": "gone"},
            ],
        },
    )
    res = carry_baseline_forward(sp, REMAP)

    assert set(res.carried) == {A, B}
    assert res.orphaned == (C,)
    assert res.document["fingerprint_scheme"] == "wlfp2"
    entry = next(e for e in res.document["entries"] if e["fingerprint"] == NA)
    assert entry["rule_id"] == "PY-WL-108" and entry["message"] == "shell"  # provenance preserved

    # The carried doc LOADS clean under wlfp2 (no SCHEME_MISMATCH) — the S12 contract.
    out = paths.baseline_path(tmp_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    _seed(out, res.document)
    assert load_baseline(out).fingerprints == frozenset({NA, NB})


def test_carry_judged_preserves_full_provenance(tmp_path: Path) -> None:
    sp = tmp_path / "judged.yaml"
    _seed(
        sp,
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
                    "rationale": "operator-controlled constant",
                    "confidence": 0.97,
                    "model_id": "anthropic/claude",
                    "recorded_at": "2026-06-01T00:00:00+00:00",
                    "policy_hash": "deadbeef",
                },
                {
                    "fingerprint": C,
                    "rule_id": "PY-WL-101",
                    "path": "o.py",
                    "message": "gone",
                    "verdict": "FALSE_POSITIVE",
                    "rationale": "stale",
                    "confidence": 0.5,
                    "model_id": "m",
                    "recorded_at": "2026-06-01T00:00:00+00:00",
                    "policy_hash": "f00d",
                },
            ],
        },
    )
    res = carry_judged_forward(sp, REMAP)
    assert set(res.carried) == {A} and res.orphaned == (C,)

    out = paths.judged_path(tmp_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    _seed(out, res.document)
    js = load_judged(out)
    carried = js.match(NA)
    assert carried is not None
    assert carried.rationale == "operator-controlled constant"  # full provenance survived
    assert carried.model_id == "anthropic/claude"
    assert abs(carried.confidence - 0.97) < 1e-9
    assert js.match(C) is None  # orphan not carried


def test_carry_waivers_preserves_reason_and_expiry(tmp_path: Path) -> None:
    sp = tmp_path / "waivers.yaml"
    _seed(
        sp,
        {
            "fingerprint_scheme": "wlfp1",
            "version": 1,
            "waivers": [
                {"fingerprint": A, "reason": "accepted risk", "expires": "2099-01-01"},
                {"fingerprint": C, "reason": "moved away"},
            ],
        },
    )
    res = carry_waivers_forward(sp, REMAP)
    assert set(res.carried) == {A} and res.orphaned == (C,)

    out = paths.waivers_path(tmp_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    _seed(out, res.document)
    waivers = load_project_waivers(tmp_path)
    assert len(waivers) == 1
    assert waivers[0].fingerprint == NA
    assert waivers[0].reason == "accepted risk"
    assert waivers[0].expires is not None and waivers[0].expires.isoformat() == "2099-01-01"
