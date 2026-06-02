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
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from wardline.core.run import run_scan

pytestmark = pytest.mark.legis_e2e

_LEGIS_URL = os.environ.get("WARDLINE_LEGIS_URL")

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _post(url: str, payload: dict) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 — test-local URL
        return resp.status, json.loads(resp.read().decode("utf-8"))


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


def _scan_response(root: Path) -> dict:
    result = run_scan(root)
    return {"findings": [json.loads(f.to_jsonl()) for f in result.findings]}


def _proj(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def test_legis_routes_wardline_active_defects(tmp_path: Path) -> None:
    base = _require_reachable_legis()
    proj = _proj(tmp_path)
    result = run_scan(proj)
    scan = {"findings": [json.loads(f.to_jsonl()) for f in result.findings]}
    active_fps = {f.fingerprint for f in result.findings if f.kind.value == "defect" and f.suppressed.value == "active"}
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
