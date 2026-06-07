"""T5.2 live oracle — Wardline findings/gate round-trip through a real legis.

Deselected by default (marker `legis_e2e`); run with:
    WARDLINE_LEGIS_URL=http://127.0.0.1:8000 .venv/bin/pytest -m legis_e2e -v

legis is a FastAPI app the suite owns; rather than hardcode its launch, this
oracle talks to an ALREADY-RUNNING legis pointed at by `WARDLINE_LEGIS_URL`
(start legis however you run it, then set the env var). It auto-skips cleanly
when the env var is unset or the server is unreachable, so default CI is never
affected — the always-on guard is the hermetic contract test
(`tests/conformance/test_legis_intake_contract.py`).

What it proves: Wardline emits a scan response; the agent hands it to legis's
`POST /wardline/scan-results`; legis governs (routes the active defects into the
named 2x2 cell) WITHOUT Wardline re-judging. The routed population matches
Wardline's own active-defect set — the one-judge property, live.

Cell choice: this oracle deliberately drives ONLY the `surface_override` cell, so a
bare `create_app()` factory server suffices to run it — that cell builds its engine
lazily and needs no wired sign-off gate. (`block_escalate` would require a server
stood up with a `signoff_gate`; exercising it is out of this seam's scope.) Verified
live against `uvicorn --factory legis.api.app:create_app`.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from wardline.core.config import load as load_config
from wardline.core.legis import build_legis_artifact
from wardline.core.run import run_scan

pytestmark = pytest.mark.legis_e2e

_LEGIS_URL = os.environ.get("WARDLINE_LEGIS_URL")
# Set to the SAME secret legis was launched with (LEGIS_WARDLINE_ARTIFACT_KEY) to
# exercise the signed-required hop; the signed test skips cleanly when it is unset.
_ARTIFACT_KEY = os.environ.get("WARDLINE_LEGIS_ARTIFACT_KEY")

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _post(url: str, payload: dict) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 — test-local URL
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # 4xx/5xx carry a JSON body we want to assert on
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"detail": raw}


def _require_reachable_legis() -> str:
    if not _LEGIS_URL:
        pytest.skip("WARDLINE_LEGIS_URL not set — start legis and point this oracle at it")
    base = _LEGIS_URL.rstrip("/")
    try:  # cheap liveness probe; skip (not fail) when legis is simply not up
        urllib.request.urlopen(base + "/health", timeout=5)  # noqa: S310
    except urllib.error.HTTPError:
        pass  # any HTTP answer means the server is up (route may 404 — fine)
    except (urllib.error.URLError, OSError) as exc:
        pytest.skip(f"legis at {base} not reachable: {exc}")
    return base


def _scan_artifact(root: Path, *, key: bytes | None = None) -> tuple[dict, set[str]]:
    """The signed (or unsigned) verbatim-postable scan via build_legis_artifact, plus
    the expected active-defect fingerprints for the one-judge cross-check."""
    result = run_scan(root)
    cfg = load_config(root / "weft.toml")
    scan = build_legis_artifact(result, root=root, config=cfg, key=key)
    # The one-judge cross-check must mirror the population the artifact carries, which
    # mirrors gate_decision: the gate (unsuppressed) view, not the suppressed findings.
    # Otherwise a committed baseline/waiver/judged would make this oracle assert the
    # wrong population (it is green today only because _LEAKY has no committed suppression).
    gate_population = result.gate_findings if result.gate_findings is not None else result.findings
    active_fps = {f.fingerprint for f in gate_population if f.kind.value == "defect" and f.suppressed.value == "active"}
    return scan, active_fps


def _proj(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def _commit(root: Path) -> None:
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "t@example.com"],
        ["git", "config", "user.name", "t"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "init"],
    ):
        subprocess.run(cmd, cwd=root, check=True, capture_output=True)


def test_legis_routes_wardline_active_defects(tmp_path: Path) -> None:
    base = _require_reachable_legis()
    scan, active_fps = _scan_artifact(_proj(tmp_path))
    assert active_fps  # svc.leaky is an active PY-WL-101 defect

    status, body = _post(
        base + "/wardline/scan-results",
        {"cell": "surface_override", "agent_id": "wardline-e2e", "scan": scan},
    )
    assert status == 200, body
    routed = body.get("routed")
    assert isinstance(routed, list)
    # legis governs: one routed entry per active defect — Wardline never re-judged.
    assert {r["fingerprint"] for r in routed} == active_fps


def test_legis_accepts_signed_artifact(tmp_path: Path) -> None:
    # The signed-required hop: with the shared key provisioned on BOTH sides, a
    # Wardline-signed scan verifies and routes. Skips cleanly unless the operator
    # launched legis with LEGIS_WARDLINE_ARTIFACT_KEY and set the same value here.
    base = _require_reachable_legis()
    if not _ARTIFACT_KEY:
        pytest.skip("WARDLINE_LEGIS_ARTIFACT_KEY not set — launch legis with the matching key to run this")
    proj = _proj(tmp_path)
    _commit(proj)  # signing requires a clean, committed tree
    scan, active_fps = _scan_artifact(proj, key=_ARTIFACT_KEY.encode("utf-8"))
    assert scan["artifact_signature"].startswith("hmac-sha256:v2:")
    assert active_fps

    status, body = _post(
        base + "/wardline/scan-results",
        {"cell": "surface_override", "agent_id": "wardline-e2e", "scan": scan},
    )
    assert status == 200, body  # signature verified server-side
    assert {r["fingerprint"] for r in body.get("routed", [])} == active_fps


def test_legis_routes_nothing_for_a_clean_scan(tmp_path: Path) -> None:
    base = _require_reachable_legis()
    # An all-clean scan (no findings) → legis routes nothing. Proves the gate
    # population is Wardline's, not a legis re-derivation.
    status, body = _post(
        base + "/wardline/scan-results",
        {"cell": "surface_override", "agent_id": "wardline-e2e", "scan": {"findings": []}},
    )
    assert status == 200, body
    assert body.get("routed") == []
