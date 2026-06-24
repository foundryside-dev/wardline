# tests/unit/install/test_doctor_filigree_auth.py
import json
import stat
from collections.abc import Mapping
from pathlib import Path

from wardline.core.filigree_emit import Response
from wardline.install.doctor import (
    _check_filigree_auth,
    _check_project_mcp,
    _is_loopback,
    _mcp_filigree_url,
    _resolve_probe_target,
    _resolve_probe_url,
    _rewrite_env_token,
    machine_readable_doctor,
)


def test_rewrite_env_sets_new_name_and_drops_legacy(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "WARDLINE_ATTEST_KEY=keep-me\nWARDLINE_FILIGREE_TOKEN=stale\nOTHER=x\n",
        encoding="utf-8",
    )
    _rewrite_env_token(env, "GOODTOKEN")
    text = env.read_text(encoding="utf-8")
    assert "WEFT_FEDERATION_TOKEN=GOODTOKEN" in text
    assert "WARDLINE_FILIGREE_TOKEN" not in text  # stale legacy line removed
    assert "WARDLINE_ATTEST_KEY=keep-me" in text  # unrelated line preserved
    assert "OTHER=x" in text
    assert stat.S_IMODE(env.stat().st_mode) == 0o600


def test_rewrite_env_updates_existing_new_name(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("WEFT_FEDERATION_TOKEN=old\nKEEP=1\n", encoding="utf-8")
    _rewrite_env_token(env, "NEW")
    text = env.read_text(encoding="utf-8")
    assert text.count("WEFT_FEDERATION_TOKEN=") == 1
    assert "WEFT_FEDERATION_TOKEN=NEW" in text
    assert "KEEP=1" in text


def test_rewrite_env_creates_file_when_absent(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    _rewrite_env_token(env, "NEW")
    assert env.read_text(encoding="utf-8").strip() == "WEFT_FEDERATION_TOKEN=NEW"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600


def test_rewrite_env_preserves_non_utf8_unrelated_line(tmp_path: Path) -> None:
    # An unrelated line carrying a raw non-UTF8 byte (0xE9, Latin-1 'é' in another
    # secret) must survive byte-for-byte. A decode round-trip with errors="replace"
    # would corrupt it to U+FFFD; the bytes-based rewrite preserves it.
    env = tmp_path / ".env"
    env.write_bytes(b"WARDLINE_ATTEST_KEY=caf\xe9-secret\nWARDLINE_FILIGREE_TOKEN=stale\n")
    _rewrite_env_token(env, "GOODTOKEN")
    data = env.read_bytes()
    assert b"WARDLINE_ATTEST_KEY=caf\xe9-secret" in data  # non-UTF8 byte intact
    assert b"\xef\xbf\xbd" not in data  # no U+FFFD replacement char introduced
    assert b"WEFT_FEDERATION_TOKEN=GOODTOKEN" in data
    assert b"WARDLINE_FILIGREE_TOKEN" not in data
    assert stat.S_IMODE(env.stat().st_mode) == 0o600


# --- Task 3: probe-URL resolution + loopback ---------------------------------


def _write_mcp_with_filigree_url(root: Path, url: str) -> None:
    root.joinpath(".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wardline": {
                        "type": "stdio",
                        "command": "wardline",
                        "args": ["mcp", "--root", ".", "--filigree-url", url],
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def test_mcp_filigree_url_extracts_arg(tmp_path: Path) -> None:
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/weft/scan-results")
    assert _mcp_filigree_url(tmp_path) == "http://127.0.0.1:8749/api/weft/scan-results"


def test_mcp_filigree_url_none_when_absent(tmp_path: Path) -> None:
    tmp_path.joinpath(".mcp.json").write_text(
        json.dumps({"mcpServers": {"wardline": {"args": ["mcp", "--root", "."]}}}), encoding="utf-8"
    )
    assert _mcp_filigree_url(tmp_path) is None
    assert _mcp_filigree_url(tmp_path / "nope") is None  # missing file


def test_mcp_filigree_url_none_when_args_not_list(tmp_path: Path) -> None:
    # A hand-corrupted config where args is a string: str.index("--filigree-url")
    # is a substring search that would otherwise return a char index, and
    # args[idx + 1] a single bogus character. The list-type guard returns None.
    tmp_path.joinpath(".mcp.json").write_text(
        json.dumps({"mcpServers": {"wardline": {"args": "mcp --filigree-url http://x"}}}),
        encoding="utf-8",
    )
    assert _mcp_filigree_url(tmp_path) is None


def test_check_project_mcp_accepts_pinned_sibling_args_in_operator_order(tmp_path: Path, monkeypatch) -> None:
    # Plain `wardline doctor` (no --repair): an entry pinning --loomweave-url AND
    # --filigree-url in the real lacuna order (loomweave-first) must read as configured,
    # not "missing wardline server". The order-preserving preserve fix guards this.
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    tmp_path.joinpath(".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wardline": {
                        "type": "stdio",
                        "command": "/bin/wardline",
                        "args": [
                            "mcp",
                            "--root",
                            ".",
                            "--loomweave-url",
                            "http://127.0.0.1:9730",
                            "--filigree-url",
                            "http://127.0.0.1:8749/api/p/lacuna/weft/scan-results",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    check = _check_project_mcp(tmp_path)
    assert check.ok, check.message


def test_resolve_probe_url_precedence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/weft/scan-results")
    # flag wins
    assert _resolve_probe_url(tmp_path, "http://flag/x") == "http://flag/x"
    # env beats .mcp.json
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://env/y")
    assert _resolve_probe_url(tmp_path, None) == "http://env/y"
    # .mcp.json arg is the fallback that makes the real setup work
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    assert _resolve_probe_url(tmp_path, None) == "http://127.0.0.1:8749/api/weft/scan-results"


def test_resolve_probe_url_none_when_unconfigured(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    # No flag, no env, no .mcp.json arg, and no live filigree daemon (no published
    # ephemeral.port, project not server-registered) -> nothing to verify.
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: tmp_path / "nohome")
    assert _resolve_probe_url(tmp_path, None) is None


def test_resolve_probe_url_excludes_project_published_port(tmp_path: Path, monkeypatch) -> None:
    # A project-owned published-port file can name an attacker-controlled local port.
    # The structured target keeps provenance for messaging, but the legacy string helper
    # must not hand that URL to future credential-bearing callers.
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: tmp_path / "nohome")
    port_file = tmp_path / ".weft" / "filigree" / "ephemeral.port"
    port_file.parent.mkdir(parents=True)
    port_file.write_text("9189", encoding="ascii")
    assert _resolve_probe_url(tmp_path, None) is None
    target = _resolve_probe_target(tmp_path, None)
    assert target is not None
    assert target.url == "http://localhost:9189/api/weft/scan-results"
    assert target.token_probe_allowed is False


def test_resolve_probe_url_mcp_arg_beats_published_port(tmp_path: Path, monkeypatch) -> None:
    # A pinned --filigree-url (e.g. a fixed-port/remote target the published-port rung
    # cannot reconstruct) still outranks the auto-discovered ephemeral port.
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: tmp_path / "nohome")
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/weft/scan-results")
    port_file = tmp_path / ".weft" / "filigree" / "ephemeral.port"
    port_file.parent.mkdir(parents=True)
    port_file.write_text("9189", encoding="ascii")
    assert _resolve_probe_url(tmp_path, None) == "http://127.0.0.1:8749/api/weft/scan-results"


def test_is_loopback() -> None:
    assert _is_loopback("http://127.0.0.1:8749/x") is True
    assert _is_loopback("http://127.255.255.255:8749/x") is True
    assert _is_loopback("http://localhost:8749/x") is True
    assert _is_loopback("http://[::1]:8749/x") is True
    assert _is_loopback("https://filigree.example.com/x") is False


def test_is_loopback_rejects_127_prefixed_registrable_hosts() -> None:
    # The host literally STARTS with "127." but is a registrable name that resolves
    # off-box via DNS. A startswith("127.") check would wrongly send the federation
    # bearer to the attacker; strict IP parsing rejects it (no probe, no leak).
    assert _is_loopback("http://127.attacker.com/x") is False
    assert _is_loopback("http://127.evil/x") is False
    assert _is_loopback("http://127.0.0.1.evil.com/x") is False


# --- Task 4: detection (no repair) -------------------------------------------


class _ScriptedTransport:
    """Returns a Response per token: maps Authorization bearer -> status."""

    def __init__(self, status_by_token: dict[str, int], *, unreachable: bool = False) -> None:
        self._status_by_token = status_by_token
        self._unreachable = unreachable
        self.calls: list[tuple[str, str]] = []

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response:
        if self._unreachable:
            raise OSError("connection refused")
        token = headers.get("Authorization", "").removeprefix("Bearer ")
        self.calls.append((url, headers.get("Authorization", "")))
        return Response(status=self._status_by_token.get(token, 401), body="")


def _setup_lacuna(root: Path, monkeypatch, env_token: str) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WEFT_FEDERATION_TOKEN", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_TOKEN", raising=False)
    _write_mcp_with_filigree_url(root, "http://127.0.0.1:8749/api/weft/scan-results")
    root.joinpath(".env").write_text(f"WARDLINE_FILIGREE_TOKEN={env_token}\n", encoding="utf-8")


def test_check_detects_rejected_token(tmp_path: Path, monkeypatch) -> None:
    _setup_lacuna(tmp_path, monkeypatch, env_token="STALE")
    t = _ScriptedTransport({"GOOD": 400})  # daemon accepts GOOD; STALE -> 401
    check = _check_filigree_auth(tmp_path, repair=False, transport=t)
    assert check.status == "error"
    assert "rejected" in (check.message or "")
    assert check.fixed is False


def test_check_ok_when_token_accepted(tmp_path: Path, monkeypatch) -> None:
    _setup_lacuna(tmp_path, monkeypatch, env_token="GOOD")
    t = _ScriptedTransport({"GOOD": 400})
    check = _check_filigree_auth(tmp_path, repair=False, transport=t)
    assert check.status == "ok"


def test_check_error_when_token_absent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WEFT_FEDERATION_TOKEN", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_TOKEN", raising=False)
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/weft/scan-results")
    check = _check_filigree_auth(tmp_path, repair=False, transport=_ScriptedTransport({}))
    assert check.status == "error"
    assert "no federation token" in (check.message or "")


def test_check_ok_when_auth_off_and_no_token(tmp_path: Path, monkeypatch) -> None:
    # Daemon has auth OFF: it accepts an unauthenticated emit ("" bearer -> 400). No token
    # configured is fine — not an error.
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WEFT_FEDERATION_TOKEN", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_TOKEN", raising=False)
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/weft/scan-results")
    t = _ScriptedTransport({"": 400})  # empty (no) bearer is accepted
    check = _check_filigree_auth(tmp_path, repair=False, transport=t)
    assert check.status == "ok"


def test_check_ok_when_unreachable(tmp_path: Path, monkeypatch) -> None:
    _setup_lacuna(tmp_path, monkeypatch, env_token="STALE")
    check = _check_filigree_auth(tmp_path, repair=False, transport=_ScriptedTransport({}, unreachable=True))
    assert check.status == "ok"
    assert "not reachable" in (check.message or "")


def test_check_ok_when_non_loopback(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setenv("WEFT_FEDERATION_TOKEN", "T")
    check = _check_filigree_auth(
        tmp_path,
        repair=False,
        filigree_url="https://remote.example.com/api/weft/scan-results",
        transport=_ScriptedTransport({}),
    )
    assert check.status == "ok"
    assert "non-loopback" in (check.message or "")


def test_check_ok_when_url_unresolved(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: tmp_path / "nohome")
    check = _check_filigree_auth(tmp_path, repair=False, transport=_ScriptedTransport({}))
    assert check.status == "ok"
    assert "not configured" in (check.message or "")


# --- Stale --filigree-url pin shadowing a LIVE published daemon (rotated port) -------


class _PortRoutedTransport:
    """Reachable only for *live_port*; any other host:port raises (unreachable)."""

    def __init__(self, live_port: int, status: int = 400) -> None:
        self._live_port = live_port
        self._status = status
        self.calls: list[tuple[str, str]] = []

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response:
        from urllib.parse import urlsplit

        self.calls.append((url, headers.get("Authorization", "")))
        if urlsplit(url).port != self._live_port:
            raise OSError("connection refused")
        return Response(status=self._status, body="")


def test_check_does_not_follow_published_port_after_pinned_url_fails(tmp_path: Path, monkeypatch) -> None:
    # .mcp.json pins an explicit loopback target. A repository-owned published-port
    # file may be stale or planted, so doctor must not follow it with the bearer after
    # the explicit pin is unreachable.
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setenv("WEFT_FEDERATION_TOKEN", "T")
    (tmp_path / ".weft" / "filigree").mkdir(parents=True)
    (tmp_path / ".weft" / "filigree" / "ephemeral.port").write_text("9397", encoding="utf-8")
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:9229/api/weft/scan-results")
    transport = _PortRoutedTransport(9397)
    check = _check_filigree_auth(tmp_path, repair=False, transport=transport)
    assert check.status == "ok"
    assert "not reachable" in (check.message or "")
    assert transport.calls == [("http://127.0.0.1:9229/api/weft/scan-results", "Bearer T")]


def test_check_stays_soft_when_pin_dead_and_no_live_published(tmp_path: Path, monkeypatch) -> None:
    # Pinned dead AND nothing live published: a genuinely-absent daemon stays soft "ok".
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setenv("WEFT_FEDERATION_TOKEN", "T")
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:9229/api/weft/scan-results")
    check = _check_filigree_auth(tmp_path, repair=False, transport=_ScriptedTransport({}, unreachable=True))
    assert check.status == "ok"
    assert "not reachable" in (check.message or "")


def test_check_does_not_send_token_to_project_published_port(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_TOKEN", raising=False)
    monkeypatch.setenv("WEFT_FEDERATION_TOKEN", "SECRET")
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: tmp_path / "nohome")
    port_file = tmp_path / ".weft" / "filigree" / "ephemeral.port"
    port_file.parent.mkdir(parents=True)
    port_file.write_text("9189", encoding="ascii")
    transport = _ScriptedTransport({})

    check = _check_filigree_auth(tmp_path, repair=False, transport=transport)

    assert check.status == "ok"
    assert "published port" in (check.message or "")
    assert "not probed" in (check.message or "")
    assert transport.calls == []


def test_repair_does_not_probe_mints_against_project_published_port(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WEFT_FEDERATION_TOKEN", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_TOKEN", raising=False)
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: tmp_path / "home")
    port_file = tmp_path / ".weft" / "filigree" / "ephemeral.port"
    port_file.parent.mkdir(parents=True)
    port_file.write_text("9189", encoding="ascii")
    tmp_path.joinpath(".env").write_text("WEFT_FEDERATION_TOKEN=STALE\n", encoding="utf-8")
    home_mint = tmp_path / "home" / ".config" / "filigree"
    home_mint.mkdir(parents=True)
    (home_mint / "federation_token").write_text("GOOD\n", encoding="utf-8")
    transport = _ScriptedTransport({"GOOD": 400})

    check = _check_filigree_auth(tmp_path, repair=True, transport=transport)

    assert check.status == "ok"
    assert "published port" in (check.message or "")
    assert "not probed" in (check.message or "")
    assert transport.calls == []
    assert tmp_path.joinpath(".env").read_text(encoding="utf-8") == "WEFT_FEDERATION_TOKEN=STALE\n"


# --- Task 5: repair -----------------------------------------------------------


def test_repair_writes_accepted_candidate(tmp_path: Path, monkeypatch) -> None:
    _setup_lacuna(tmp_path, monkeypatch, env_token="STALE")
    # server-mode store holds the accepted token
    cfg = tmp_path / "home" / ".config" / "filigree"
    cfg.mkdir(parents=True)
    (cfg / "federation_token").write_text("GOOD\n", encoding="utf-8")
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: tmp_path / "home")
    t = _ScriptedTransport({"GOOD": 400})  # GOOD accepted, STALE -> 401

    check = _check_filigree_auth(tmp_path, repair=True, transport=t)

    assert check.status == "ok"
    assert check.fixed is True
    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "WEFT_FEDERATION_TOKEN=GOOD" in env_text
    assert "WARDLINE_FILIGREE_TOKEN" not in env_text


def test_fix_probes_and_repairs_with_mcp_filigree_url(tmp_path: Path, monkeypatch) -> None:
    # Regression (primary lacuna path): a .mcp.json pinning --filigree-url + a stale .env
    # token. machine_readable_doctor(fix=True) runs repair_install (which rewrites the
    # wardline entry) and must still probe/repair the token. Two guarantees:
    #   1. repair_install PRESERVES the operator-pinned --filigree-url arg (it is the
    #      runtime emit target; the published-port rung cannot reconstruct a fixed-port
    #      server-mode URL, so stripping it would silently disable emit).
    #   2. filigree.auth detects the stale token and pins the accepted mint in .env.
    home = tmp_path / "home"
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    _setup_lacuna(tmp_path, monkeypatch, env_token="STALE")
    # local mint holds the accepted token
    cfg = home / ".config" / "filigree"
    cfg.mkdir(parents=True)
    (cfg / "federation_token").write_text("GOOD\n", encoding="utf-8")
    t = _ScriptedTransport({"GOOD": 400})  # GOOD accepted, STALE -> 401

    payload = machine_readable_doctor(tmp_path, fix=True, transport=t)

    checks = {c["id"]: c for c in payload["checks"]}
    auth = checks["filigree.auth"]
    assert auth["status"] == "ok"
    assert auth["fixed"] is True
    # repair preserved the pinned emit target rather than normalizing it away.
    args = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["wardline"]["args"]
    assert "--filigree-url" in args
    assert args[args.index("--filigree-url") + 1] == "http://127.0.0.1:8749/api/weft/scan-results"
    # the .mcp.json check accepts the pinned arg (not "missing wardline server").
    mcp_check = checks["mcp.registration"]
    assert mcp_check["status"] == "ok"
    assert "WEFT_FEDERATION_TOKEN=GOOD" in (tmp_path / ".env").read_text(encoding="utf-8")


def test_repair_writes_project_store_candidate_when_config_store_rejected(tmp_path: Path, monkeypatch) -> None:
    # Exercises the SECOND candidate rung and the "first rejected -> second accepted"
    # iteration: ~/.config/filigree holds a rejected mint, the project store
    # <root>/.weft/filigree/federation_token holds the accepted one. The project-store
    # value must be the one pinned in .env.
    #
    # Post-F1 (rung 3 reads <root>/.weft/filigree/federation_token directly) the
    # resolver would otherwise pick up the valid project mint with no repair needed.
    # To still drive the repair ITERATION we set a stale token via the CANONICAL name,
    # which outranks the mint (rung 1/2 > rung 3): the probe of that stale token fails,
    # and the doctor recovers by iterating the local mints.
    _setup_lacuna(tmp_path, monkeypatch, env_token="STALE")
    (tmp_path / ".env").write_text("WEFT_FEDERATION_TOKEN=STALE\n", encoding="utf-8")
    cfg = tmp_path / "home" / ".config" / "filigree"
    cfg.mkdir(parents=True)
    (cfg / "federation_token").write_text("WRONG\n", encoding="utf-8")  # first rung: rejected
    proj = tmp_path / ".weft" / "filigree"
    proj.mkdir(parents=True)
    (proj / "federation_token").write_text("GOOD\n", encoding="utf-8")  # project rung: accepted
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: tmp_path / "home")
    t = _ScriptedTransport({"GOOD": 400})  # only GOOD accepted; STALE/WRONG -> 401

    check = _check_filigree_auth(tmp_path, repair=True, transport=t)

    assert check.status == "ok"
    assert check.fixed is True
    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "WEFT_FEDERATION_TOKEN=GOOD" in env_text
    assert "WARDLINE_FILIGREE_TOKEN" not in env_text


def test_repair_no_candidate_matches_does_not_write(tmp_path: Path, monkeypatch) -> None:
    _setup_lacuna(tmp_path, monkeypatch, env_token="STALE")
    cfg = tmp_path / "home" / ".config" / "filigree"
    cfg.mkdir(parents=True)
    (cfg / "federation_token").write_text("ALSO-WRONG\n", encoding="utf-8")
    monkeypatch.setattr("wardline.install.doctor.Path.home", lambda: tmp_path / "home")
    t = _ScriptedTransport({"GOOD": 400})  # neither STALE nor ALSO-WRONG is accepted

    check = _check_filigree_auth(tmp_path, repair=True, transport=t)

    assert check.status == "error"
    assert "no local federation_token matched" in (check.message or "")
    assert "WARDLINE_FILIGREE_TOKEN=STALE" in (tmp_path / ".env").read_text(encoding="utf-8")  # untouched
