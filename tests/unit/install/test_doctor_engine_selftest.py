"""Part B of wardline-bd9d1e65cb: doctor engine self-test + configured-but-missing
Loomweave dep flag.

The engine self-test runs the analyzer on a tiny BUILT-IN source->sink fixture and
asserts the expected ERROR fires — proving the taint engine is wired and firing in THIS
install. It does NOT claim the user's scans enforce (wardline is annotation-driven; a
boundary-less scan is still inert — Part A's per-scan posture carries that).

The loomweave.dep check flags a real misconfiguration the user otherwise cannot see: a
Loomweave taint-store URL is configured but the [loomweave] extra (blake3) is missing, so
every taint-fact write silently no-ops (fail-soft — the gate is unaffected).
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.errors import LoomweaveError
from wardline.install import doctor as D


def test_engine_selftest_fires_on_known_flow() -> None:
    check = D._check_engine_selftest()
    assert check.id == "engine.selftest"
    assert check.status == "ok"
    assert check.message == "taint analysis fires correctly"


def test_engine_selftest_reports_error_when_engine_returns_no_defect(monkeypatch) -> None:
    # Simulate a broken/degraded engine: the known flow no longer fires.
    monkeypatch.setattr(D, "_run_engine_selftest", lambda: [])
    check = D._check_engine_selftest()
    assert check.status == "error"
    assert "did not fire PY-WL-108" in (check.message or "")


def test_engine_selftest_reports_error_when_engine_raises(monkeypatch) -> None:
    def boom() -> list:
        raise RuntimeError("analyzer exploded")

    monkeypatch.setattr(D, "_run_engine_selftest", boom)
    check = D._check_engine_selftest()
    assert check.status == "error"
    assert "could not run" in (check.message or "")


def test_loomweave_dep_ok_when_not_configured(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    check = D._check_loomweave_dep(tmp_path, effective_url=None)
    assert check.id == "loomweave.dep"
    assert check.status == "ok"
    assert "not configured" in (check.message or "")


def test_loomweave_dep_error_when_configured_via_env_but_blake3_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://127.0.0.1:9730")

    def no_blake3():
        raise LoomweaveError("blake3 missing")

    monkeypatch.setattr("wardline.loomweave.require_blake3", no_blake3)
    check = D._check_loomweave_dep(tmp_path, effective_url=None)
    assert check.status == "error"
    assert "[loomweave]" in (check.message or "")


def test_loomweave_dep_error_when_configured_via_launch_flag_but_blake3_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)

    def no_blake3():
        raise LoomweaveError("blake3 missing")

    monkeypatch.setattr("wardline.loomweave.require_blake3", no_blake3)
    check = D._check_loomweave_dep(tmp_path, effective_url="http://127.0.0.1:9730")
    assert check.status == "error"


def test_loomweave_dep_error_when_configured_via_mcp_json_arg_but_blake3_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"wardline": {"command": "wardline", '
        '"args": ["mcp", "--loomweave-url", "http://127.0.0.1:9730"]}}}',
        encoding="utf-8",
    )

    def no_blake3():
        raise LoomweaveError("blake3 missing")

    monkeypatch.setattr("wardline.loomweave.require_blake3", no_blake3)
    check = D._check_loomweave_dep(tmp_path, effective_url=None)
    assert check.status == "error"


def test_loomweave_dep_ok_when_configured_and_blake3_present(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://127.0.0.1:9730")
    monkeypatch.setattr("wardline.loomweave.require_blake3", lambda: object())
    check = D._check_loomweave_dep(tmp_path, effective_url=None)
    assert check.status == "ok"


def test_ambient_published_port_does_not_count_as_configured(tmp_path: Path, monkeypatch) -> None:
    # Ambient auto-discovery (a sibling's published port) is NOT operator intent — a base
    # install dialing a found sibling degrades fail-soft, so it must not be flagged.
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    port_dir = tmp_path / ".weft" / "loomweave"
    port_dir.mkdir(parents=True)
    (port_dir / "ephemeral.port").write_text("9730", encoding="utf-8")

    def no_blake3():
        raise LoomweaveError("blake3 missing")

    monkeypatch.setattr("wardline.loomweave.require_blake3", no_blake3)
    check = D._check_loomweave_dep(tmp_path, effective_url=None)
    assert check.status == "ok"


def test_machine_readable_doctor_includes_both_part_b_checks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    payload = D.machine_readable_doctor(tmp_path, fix=False)
    ids = [c["id"] for c in payload["checks"]]
    assert "engine.selftest" in ids
    assert "loomweave.dep" in ids
    by_id = {c["id"]: c for c in payload["checks"]}
    assert by_id["engine.selftest"]["status"] == "ok"
    assert by_id["loomweave.dep"]["status"] == "ok"
