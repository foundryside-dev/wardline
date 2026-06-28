"""`wardline doctor` stale ephemeral.port detection + clearing.

Root-cause regression suite for the ~90s `wardline scan` hang: a sibling's
``.weft/<sibling>/ephemeral.port`` advertises 'an instance is listening here NOW'.
When the owning ``serve`` process has exited (connection refused) or wedged (accepts
TCP, never answers), the file lingers and every scan dials a dead/hung origin,
stalling the agent gate up to the 30s federation ``urlopen`` timeout per round-trip.
Doctor detects the stale advertisement and clears it under --repair.
"""

from __future__ import annotations

import socket
import time
from pathlib import Path

from wardline.install.doctor import (
    _check_stale_sibling_ports,
    _port_origin_reachable,
    _read_port_file,
    machine_readable_doctor,
)


def _proj(tmp_path: Path) -> Path:
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    return tmp_path


def _publish_port(proj: Path, sibling: str, port: int, *, legacy: bool = False) -> Path:
    base = proj / (f".{sibling}" if legacy else Path(".weft") / sibling)
    base.mkdir(parents=True, exist_ok=True)
    f = base / "ephemeral.port"
    f.write_text(str(port), encoding="utf-8")
    return f


_DEAD = lambda url: False  # noqa: E731 — every advertised port is unreachable
_LIVE = lambda url: True  # noqa: E731 — every advertised port answers


# ---------------------------------------------------------------------------
# _read_port_file parse discipline (mirrors core/config._read_published_port)
# ---------------------------------------------------------------------------


def test_read_port_file_valid(tmp_path):
    f = _publish_port(_proj(tmp_path), "filigree", 9397)
    assert _read_port_file(tmp_path, f) == 9397


def test_read_port_file_rejects_non_digit(tmp_path):
    proj = _proj(tmp_path)
    f = proj / ".weft" / "filigree" / "ephemeral.port"
    f.parent.mkdir(parents=True)
    f.write_text("not-a-port", encoding="utf-8")
    assert _read_port_file(proj, f) is None


def test_read_port_file_rejects_out_of_range(tmp_path):
    f = _publish_port(_proj(tmp_path), "filigree", 70000)
    assert _read_port_file(tmp_path, f) is None


def test_read_port_file_absent(tmp_path):
    assert _read_port_file(tmp_path, tmp_path / ".weft" / "filigree" / "ephemeral.port") is None


# ---------------------------------------------------------------------------
# _check_stale_sibling_ports detection + clearing
# ---------------------------------------------------------------------------


def test_stale_port_reported_not_cleared_without_fix(tmp_path):
    proj = _proj(tmp_path)
    f = _publish_port(proj, "filigree", 9397)
    c = _check_stale_sibling_ports(proj, fix=False, probe=_DEAD)
    assert c.status == "ok" and c.fixed is False  # advisory — never flips aggregate
    assert f.exists()  # check-only: not deleted
    assert any("ephemeral.port" in r for r in c.removed)  # would-remove listed
    assert "filigree" in (c.message or "")


def test_stale_port_cleared_with_fix(tmp_path):
    proj = _proj(tmp_path)
    f = _publish_port(proj, "loomweave", 41271)
    c = _check_stale_sibling_ports(proj, fix=True, probe=_DEAD)
    assert c.status == "ok" and c.fixed is True
    assert not f.exists()  # cleared
    assert any("ephemeral.port" in r for r in c.removed)
    assert "cleared" in (c.message or "")


def test_live_port_is_kept(tmp_path):
    proj = _proj(tmp_path)
    f = _publish_port(proj, "filigree", 9397)
    c = _check_stale_sibling_ports(proj, fix=True, probe=_LIVE)
    assert f.exists()  # a live server answers — never touched
    assert c.removed == [] and c.fixed is False
    assert "no stale" in (c.message or "")


def test_only_unreachable_sibling_cleared(tmp_path):
    proj = _proj(tmp_path)
    fil = _publish_port(proj, "filigree", 9397)
    loom = _publish_port(proj, "loomweave", 41271)
    # filigree dead, loomweave live — only filigree's file is cleared
    probe = lambda url: "41271" in url  # noqa: E731
    c = _check_stale_sibling_ports(proj, fix=True, probe=probe)
    assert not fil.exists()
    assert loom.exists()
    assert "filigree" in (c.message or "") and "loomweave" not in (c.message or "")


def test_no_port_files_is_ok_and_silent(tmp_path):
    proj = _proj(tmp_path)
    c = _check_stale_sibling_ports(proj, fix=True, probe=_DEAD)
    assert c.status == "ok" and c.removed == [] and c.fixed is False


def test_legacy_dir_port_file_detected(tmp_path):
    proj = _proj(tmp_path)
    f = _publish_port(proj, "filigree", 9397, legacy=True)  # .filigree/ephemeral.port
    c = _check_stale_sibling_ports(proj, fix=True, probe=_DEAD)
    assert not f.exists()
    assert any(".filigree" in r for r in c.removed)


def test_symlinked_port_file_not_followed(tmp_path):
    proj = _proj(tmp_path)
    real = tmp_path.parent / "real_port"
    real.write_text("9397", encoding="utf-8")
    base = proj / ".weft" / "filigree"
    base.mkdir(parents=True)
    (base / "ephemeral.port").symlink_to(real)
    c = _check_stale_sibling_ports(proj, fix=True, probe=_DEAD)
    # regular-only read => a symlinked advertisement is never read, never followed, never deleted
    assert real.exists()
    assert c.removed == []


def test_advisory_status_never_flips_aggregate(tmp_path):
    proj = _proj(tmp_path)
    _publish_port(proj, "filigree", 9397)
    c = _check_stale_sibling_ports(proj, fix=False, probe=_DEAD)
    assert c.ok is True  # a stale port is hygiene, not a health failure


def test_probe_uses_dialed_host_per_sibling(tmp_path):
    # The probe MUST hit the same host the scan dials: filigree publishes a `localhost`
    # origin (self-heals over IPv4/IPv6 — a filigree bound to ::1 only is reachable
    # there), loomweave publishes `127.0.0.1`. Probing the wrong host would call a live
    # ::1-only filigree dead and clear its live port file (data loss under --repair).
    proj = _proj(tmp_path)
    _publish_port(proj, "filigree", 9397)
    _publish_port(proj, "loomweave", 41271)
    seen: list[str] = []

    def _record(url: str) -> bool:
        seen.append(url)
        return True  # all live — nothing cleared; we only assert the probed host

    _check_stale_sibling_ports(proj, fix=True, probe=_record)
    assert "http://localhost:9397/" in seen
    assert "http://127.0.0.1:41271/" in seen


# ---------------------------------------------------------------------------
# _port_origin_reachable — the SHORT-timeout property that fixes the hang
# ---------------------------------------------------------------------------


def test_probe_refused_port_is_unreachable_fast(tmp_path):
    # Bind then close to obtain a definitely-closed loopback port.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    start = time.monotonic()
    assert _port_origin_reachable(f"http://127.0.0.1:{port}/", 1.0) is False
    assert time.monotonic() - start < 5.0  # connection refused is instant


def test_probe_unresponsive_server_times_out_not_30s(tmp_path):
    # A server that accepts the TCP connection but never answers — the exact wedged
    # state that makes a scan hang 30s. The probe must give up at its short deadline.
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)  # listen, never accept/respond
    port = srv.getsockname()[1]
    try:
        start = time.monotonic()
        assert _port_origin_reachable(f"http://127.0.0.1:{port}/", 1.0) is False
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, f"probe blocked {elapsed:.1f}s — short timeout not applied"
    finally:
        srv.close()


def test_probe_live_server_is_reachable():
    import http.server
    import threading

    class _Quiet(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(404)
            self.end_headers()

        def log_message(self, *a):  # silence
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Quiet)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        # Any HTTP status (even 404) proves a live server — reachable, not stale.
        assert _port_origin_reachable(f"http://127.0.0.1:{port}/", 2.0) is True
    finally:
        httpd.shutdown()


# ---------------------------------------------------------------------------
# machine_readable_doctor wiring
# ---------------------------------------------------------------------------


def test_machine_readable_includes_stale_ports_check(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: tmp_path / "_home")
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    proj = _proj(tmp_path)
    _publish_port(proj, "filigree", 9397)
    payload = machine_readable_doctor(proj, fix=True, port_probe=_DEAD)
    by_id = {c["id"]: c for c in payload["checks"]}
    assert "stale_sibling_ports" in by_id
    assert by_id["stale_sibling_ports"]["status"] == "ok"  # advisory: success stays ok
    assert not (proj / ".weft" / "filigree" / "ephemeral.port").exists()  # cleared via fix


def test_machine_readable_keeps_live_port(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: tmp_path / "_home")
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    proj = _proj(tmp_path)
    _publish_port(proj, "loomweave", 41271)
    machine_readable_doctor(proj, fix=True, port_probe=_LIVE)
    assert (proj / ".weft" / "loomweave" / "ephemeral.port").exists()
