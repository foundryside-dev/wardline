"""SP9 live round-trip against a real `clarion serve`. Deselected by default
(marker `clarion_e2e`); run with: .venv/bin/pytest -m clarion_e2e -v

Requires a `clarion` binary on PATH with the HTTP read API + wardline write path,
plus `clarion-plugin-python` on PATH so `clarion analyze` extracts Python entities.

This is the ONLY oracle independent of the hermetic fakes used elsewhere in SP9:
it runs a real `clarion serve` over a tmp project with real HMAC + real blake3 and
asserts scan -> write -> direct read (the load-bearing cross-impl blake3 equality)
-> explain query. The direct `get_taint_fact` read is deliberate: `explain_finding`
falls back to a local re-analysis on any miss/stale/outage, so it cannot by itself
prove the stored fact is reachable and fresh."""

from __future__ import annotations

import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from shutil import which

import pytest

pytestmark = pytest.mark.clarion_e2e

_IDENTITY_ENV = "CLARION_LOOM_IDENTITY_SECRET"
_SECRET = "wardline-e2e-shared-loom-secret"  # noqa: S105 — test-local HMAC secret

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _has_wardline_routes(binary: str) -> bool:
    """True iff the binary advertises the SP9 `/api/wardline/*` routes. The 1.0.0
    release on PATH predates these routes (it 404s them before auth); the 1.0.1
    build does mount them. Discriminate by the route string baked into the binary."""
    try:
        out = subprocess.run(["strings", binary], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return "/api/wardline/taint-facts" in out


def _resolve_clarion() -> str | None:
    """Pick the first clarion binary that actually carries the SP9 wardline routes:
    explicit override, then PATH, then the repo's local release/debug build. PATH
    first would pick the stale 1.0.0 binary (no routes), so capability-filter."""
    candidates: list[str | None] = [
        os.environ.get("WARDLINE_CLARION_BIN"),
        which("clarion"),
        str(Path.home() / "clarion" / "target" / "release" / "clarion"),
        str(Path.home() / "clarion" / "target" / "debug" / "clarion"),
    ]
    for cand in candidates:
        if cand and Path(cand).is_file() and _has_wardline_routes(cand):
            return cand
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_capabilities(base_url: str, proc: subprocess.Popen[bytes], log: Path) -> None:
    """Poll the unauthenticated capabilities probe until it answers 200, or raise
    with the server log tail so the caller can skip with a specific reason."""
    deadline = time.monotonic() + 20.0
    url = f"{base_url}/api/v1/_capabilities"
    last_err = "no response"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"clarion serve exited early (rc={proc.returncode}). Log tail:\n"
                f"{log.read_text(encoding='utf-8', errors='replace')[-2000:]}"
            )
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:  # noqa: S310 — loopback probe
                if resp.status == 200:
                    return
        except urllib.error.HTTPError as exc:  # bound but rejecting — still "up"
            if exc.code < 500:
                return
            last_err = f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError) as exc:
            last_err = str(exc)
        time.sleep(0.1)
    raise RuntimeError(
        f"clarion serve HTTP API did not become ready at {url} (last: {last_err}). "
        f"Log tail:\n{log.read_text(encoding='utf-8', errors='replace')[-2000:]}"
    )


@pytest.fixture
def clarion_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    clarion_bin = _resolve_clarion()
    if clarion_bin is None:
        pytest.skip(
            "no clarion with /api/wardline routes found (PATH clarion is 1.0.0, "
            "predates SP9); set WARDLINE_CLARION_BIN to a 1.0.1+ build"
        )
    if which("clarion-plugin-python") is None:
        pytest.skip("clarion-plugin-python not on PATH; analyze would skip_no_plugins")

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")

    # 1) Clarion needs an initialised .clarion/ before analyze; then analyze persists
    #    entities to .clarion/clarion.db. Both take a positional/--path of the project.
    install = subprocess.run(
        [clarion_bin, "install", "--path", str(proj)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if install.returncode != 0:
        pytest.skip(f"clarion install failed: {install.stderr.strip() or install.stdout.strip()}")

    analyze = subprocess.run(
        [clarion_bin, "analyze", str(proj)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    out = f"{analyze.stdout}\n{analyze.stderr}"
    if analyze.returncode != 0:
        pytest.skip(f"clarion analyze failed (rc={analyze.returncode}): {out.strip()[-500:]}")
    if "skipped_no_plugins" in out:
        pytest.skip("clarion analyze reported skipped_no_plugins (python plugin did not run)")

    # 2) write a clarion.yaml enabling serve.http + the wardline write path + HMAC identity.
    #    Keys confirmed against clarion-mcp/src/config.rs (HttpReadConfig: enabled, bind,
    #    identity_token_env, wardline_taint_write) and docs/operator/clarion-http-read-api.md.
    port = _free_port()
    config = proj / "clarion.yaml"
    config.write_text(
        "version: 1\n"
        "serve:\n"
        "  http:\n"
        "    enabled: true\n"
        f"    bind: 127.0.0.1:{port}\n"
        f"    identity_token_env: {_IDENTITY_ENV}\n"
        "    wardline_taint_write: true\n",
        encoding="utf-8",
    )

    # 3) start `clarion serve`. It is primarily an MCP stdio server: keep stdin open
    #    (a PIPE we never close until teardown) so the stdio loop does not hit EOF and
    #    tear down the HTTP listener. Drain stdout/stderr to a log file (an undrained
    #    PIPE would deadlock a chatty server, and the log gives the skip/failure reason).
    log_path = proj / "serve.log"
    server_env = {**os.environ, _IDENTITY_ENV: _SECRET}
    base_url = f"http://127.0.0.1:{port}"
    with log_path.open("wb") as log_fh:
        proc = subprocess.Popen(  # noqa: S603
            [clarion_bin, "serve", "--path", str(proj), "--config", str(config)],
            stdin=subprocess.PIPE,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            env=server_env,
        )
        try:
            try:
                _wait_for_capabilities(base_url, proc, log_path)
            except RuntimeError as exc:
                pytest.skip(str(exc))
            # Client side: the secret VALUE must equal what Clarion read from the env
            # var named by identity_token_env.
            monkeypatch.setenv("WARDLINE_CLARION_TOKEN", _SECRET)
            yield proj, base_url
        finally:
            if proc.stdin is not None:
                proc.stdin.close()
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)


def test_scan_write_then_explain_query_round_trip(clarion_server: tuple[Path, str]) -> None:
    proj, url = clarion_server
    from wardline.clarion.client import ClarionClient
    from wardline.clarion.config import load_clarion_token, resolve_project_name
    from wardline.clarion.write import write_facts_to_clarion
    from wardline.core.explain import explain_finding
    from wardline.core.run import run_scan

    client = ClarionClient(
        url,
        secret=load_clarion_token(proj),
        project=resolve_project_name(proj),
    )

    # scan -> write (real HMAC POST through the writer-actor)
    result = run_scan(proj)
    wr = write_facts_to_clarion(result, proj, client)
    assert wr.reachable is True
    assert wr.written >= 2  # both entities (svc.read_raw, svc.leaky) resolve + persist
    assert wr.unresolved_qualnames == ()

    # Direct read THROUGH real HMAC — the load-bearing oracle leg. explain_finding
    # below cannot prove this on its own (it silently falls back to local re-analysis
    # on a miss/stale/outage), so assert the stored fact is reachable and FRESH here.
    view = client.get_taint_fact("svc.leaky")
    assert view is not None
    assert view.exists is True
    assert view.current_content_hash is not None
    assert isinstance(view.wardline_json, dict)
    # Cross-impl check: wardline's blake3 stamp must byte-equal Clarion's live file hash
    # (this equality is exactly what _is_fresh depends on; a blake3 divergence breaks it).
    assert view.wardline_json["content_hash_at_compute"] == view.current_content_hash
    assert view.wardline_json["taint"]["actual_return"] == "EXTERNAL_RAW"

    # Also exercise the POST :batch-get route directly — this is the route
    # explain_finding's fast path actually uses, and a fresh hit there is what makes
    # the cheap path fire. (The GET assertion above covers the single-read route; the
    # explain assertions below pass identically whether store-served or locally
    # re-analyzed, so prove the batch-get round-trip + freshness here explicitly.)
    batch = client.batch_get(["svc.leaky"])
    assert batch is not None
    assert len(batch) == 1
    assert batch[0].qualname == "svc.leaky"
    assert batch[0].exists is True
    assert batch[0].wardline_json["content_hash_at_compute"] == batch[0].current_content_hash

    # explain query (integration check — fast path serves from the fresh stored blob)
    exp = explain_finding(proj, path="svc.py", line=6, clarion=client, sink_qualname="svc.leaky")
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"
    assert exp.tier_in == "EXTERNAL_RAW"


def test_sei_client_against_live_clarion(clarion_server: tuple[Path, str]) -> None:
    """Exercise the SEI client against whatever a real `clarion serve` actually
    advertises — adaptive, so it is a true oracle either way (the SEI conformance
    oracle's two consumer-side scenarios):
      - capability ABSENT  -> honest degrade (UNAVAILABLE, no crash, works on locator)
      - capability PRESENT -> resolve a real locator; opacity holds on any SEI returned
    The consumer must NEVER crash and must NEVER parse the SEI."""
    proj, url = clarion_server
    from wardline.clarion.client import ClarionClient
    from wardline.clarion.config import load_clarion_token, resolve_project_name
    from wardline.clarion.identity import IdentityStatus, SeiResolver

    client = ClarionClient(url, secret=load_clarion_token(proj), project=resolve_project_name(proj))
    resolver = SeiResolver.detect(client)

    # Discover svc.leaky's real locator via the SP9 qualname->locator resolve; fall back
    # to the canonical locator form if that route is unavailable.
    rr = client.resolve(["svc.leaky"])
    locator = (rr.resolved.get("svc.leaky") if rr is not None else None) or "python:function:svc.leaky"

    binding = resolver.resolve_locator(locator)  # must never crash
    assert binding.binding_key  # coherent, non-empty, either branch

    if not resolver.capability.supported:
        # Degrade path: no `sei` capability -> honest unavailable, no guessing.
        assert binding.identity is IdentityStatus.UNAVAILABLE
        assert binding.sei is None
        assert binding.keyed_on_sei is False
        assert binding.binding_key == locator
        return

    # SEI-present path: resolution is coherent; any SEI returned is OPAQUE + verbatim.
    assert binding.identity in (IdentityStatus.ALIVE, IdentityStatus.UNAVAILABLE)
    if binding.identity is IdentityStatus.ALIVE:
        assert isinstance(binding.sei, str) and binding.sei
        assert binding.keyed_on_sei is True
        assert binding.binding_key == binding.sei
        # Opacity (oracle identity_round_trip_and_opacity): reserved prefix, not the locator.
        assert binding.sei.startswith("clarion:eid:")
        assert binding.sei != locator
        # The opaque token round-trips through resolve_sei without the client parsing it.
        assert resolver.resolve_identity_status(binding.sei) is IdentityStatus.ALIVE


def test_loom_dossier_against_live_clarion(clarion_server: tuple[Path, str]) -> None:
    """T4.3 oracle: assemble a one-call dossier against a real `clarion serve`.

    Adaptive (a true oracle either way): the self/trust posture is always real; the
    Clarion-sourced sections fill iff the live build advertises the SEI + HTTP-linkage
    capabilities, and degrade to honest `unavailable` otherwise. Never crashes, never
    parses the SEI, never exceeds the token budget."""
    proj, url = clarion_server
    from wardline.clarion.client import ClarionClient
    from wardline.clarion.config import load_clarion_token, resolve_project_name
    from wardline.clarion.identity import ContentStatus, IdentityStatus
    from wardline.loom_dossier import build_loom_dossier

    client = ClarionClient(url, secret=load_clarion_token(proj), project=resolve_project_name(proj))
    caps = client.capabilities() or {}
    sei_up = isinstance(caps.get("sei"), dict) and caps["sei"].get("supported") is True
    linkages_up = isinstance(caps.get("linkages"), dict) and caps["linkages"].get("http") is True

    d = build_loom_dossier("svc.leaky", root=proj, clarion_client=client)

    # self/trust is always real — svc.leaky leaks an external-boundary value
    assert d.identity.qualname == "svc.leaky"
    assert d.trust.gate_verdict == "defect"
    assert any(f.rule_id == "PY-WL-101" for f in d.trust.active_findings)
    # token budget holds on a real envelope
    assert d.estimated_tokens() <= 2000

    if sei_up:
        # SEI resolved live → opaque key, alive identity (never parsed)
        assert isinstance(d.identity.sei, str) and d.identity.sei.startswith("clarion:eid:")
        assert d.identity.keyed_on_sei is True
        assert d.identity.identity_status is IdentityStatus.ALIVE
    else:
        assert d.identity.sei is None
        assert d.identity.identity_status is IdentityStatus.UNAVAILABLE

    if linkages_up:
        # leaky -> read_raw, so callees must include read_raw's locator; content FRESH (live)
        assert d.linkages.available is True
        assert d.linkages.content_status is ContentStatus.FRESH
        assert any("read_raw" in n for n in d.linkages.callees)
    else:
        assert d.linkages.available is False
