"""SP9 live round-trip against a real `loomweave serve`. Deselected by default
(marker `loomweave_e2e`); run with: .venv/bin/pytest -m loomweave_e2e -v

Requires a `loomweave` binary on PATH with the HTTP read API + wardline write path,
plus `loomweave-plugin-python` on PATH so `loomweave analyze` extracts Python entities.

This is the ONLY oracle independent of the hermetic fakes used elsewhere in SP9:
it runs a real `loomweave serve` over a tmp project with real HMAC + real blake3 and
asserts scan -> write -> direct read (the load-bearing cross-impl blake3 equality)
-> explain query. The direct `get_taint_fact` read is deliberate: `explain_finding`
falls back to a local re-analysis on any miss/stale/outage, so it cannot by itself
prove the stored fact is reachable and fresh."""

from __future__ import annotations

import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from shutil import which

import pytest

pytestmark = pytest.mark.loomweave_e2e

_IDENTITY_ENV = "LOOMWEAVE_WEFT_IDENTITY_SECRET"
_SECRET = "wardline-e2e-shared-weft-secret"  # noqa: S105 — test-local HMAC secret

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _resolve_loomweave() -> str | None:
    """Pick an explicit binary first, then PATH, then local builds.

    Route support is proven by launching and probing the HTTP API, not by scraping
    implementation strings out of the binary. That keeps valid builds from being
    skipped because their route literals were optimized or renamed internally.
    """
    candidates: list[str | None] = [
        os.environ.get("WARDLINE_LOOMWEAVE_BIN"),
        which("loomweave"),
        str(Path.home() / "loomweave" / "target" / "release" / "loomweave"),
        str(Path.home() / "loomweave" / "target" / "debug" / "loomweave"),
    ]
    for cand in candidates:
        if cand and Path(cand).is_file():
            return cand
    return None


def _write_loomweave_config(config: Path) -> None:
    config.write_text(
        "version: 1\n"
        "serve:\n"
        "  http:\n"
        "    enabled: true\n"
        "    bind: 127.0.0.1:0\n"
        f"    identity_token_env: {_IDENTITY_ENV}\n"
        "    wardline_taint_write: true\n",
        encoding="utf-8",
    )


def _base_url_from_loomweave_log(text: str) -> str | None:
    match = re.search(r"\bbind=127\.0\.0\.1:(?P<port>[1-9][0-9]*)\b", text)
    return f"http://127.0.0.1:{match.group('port')}" if match else None


def _wardline_taint_route_live(base_url: str) -> bool:
    req = urllib.request.Request(
        base_url.rstrip("/") + "/api/wardline/taint-facts",
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)  # noqa: S310 — loopback route probe
        return True
    except urllib.error.HTTPError as exc:
        return exc.code != 404
    except OSError:
        return False


def _wait_for_capabilities(proc: subprocess.Popen[bytes], log: Path) -> str:
    """Poll the unauthenticated capabilities probe until it answers 200, or raise
    with the server log tail so the caller can skip with a specific reason."""
    deadline = time.monotonic() + 20.0
    base_url: str | None = None
    last_err = "waiting for Loomweave to report HTTP bind address"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"loomweave serve exited early (rc={proc.returncode}). Log tail:\n"
                f"{log.read_text(encoding='utf-8', errors='replace')[-2000:]}"
            )
        log_text = log.read_text(encoding="utf-8", errors="replace")
        base_url = base_url or _base_url_from_loomweave_log(log_text)
        if base_url is None:
            time.sleep(0.1)
            continue
        url = f"{base_url}/api/v1/_capabilities"
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:  # noqa: S310 — loopback probe
                if resp.status == 200:
                    return base_url
        except urllib.error.HTTPError as exc:  # bound but rejecting — still "up"
            if exc.code < 500:
                return base_url
            last_err = f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError) as exc:
            last_err = str(exc)
        time.sleep(0.1)
    raise RuntimeError(
        f"loomweave serve HTTP API did not become ready at {url} (last: {last_err}). "
        f"Log tail:\n{log.read_text(encoding='utf-8', errors='replace')[-2000:]}"
    )


@pytest.fixture
def loomweave_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    loomweave_bin = _resolve_loomweave()
    if loomweave_bin is None:
        pytest.skip(
            "no loomweave with /api/wardline routes found (PATH loomweave is 1.0.0, "
            "predates SP9); set WARDLINE_LOOMWEAVE_BIN to a 1.0.1+ build"
        )
    if which("loomweave-plugin-python") is None:
        pytest.skip("loomweave-plugin-python not on PATH; analyze would skip_no_plugins")

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")

    # 1) Loomweave needs an initialised .loomweave/ before analyze; then analyze persists
    #    entities to .loomweave/loomweave.db. Both take a positional/--path of the project.
    install = subprocess.run(
        [loomweave_bin, "install", "--path", str(proj)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if install.returncode != 0:
        pytest.skip(f"loomweave install failed: {install.stderr.strip() or install.stdout.strip()}")

    analyze = subprocess.run(
        [loomweave_bin, "analyze", str(proj)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    out = f"{analyze.stdout}\n{analyze.stderr}"
    if analyze.returncode != 0:
        pytest.skip(f"loomweave analyze failed (rc={analyze.returncode}): {out.strip()[-500:]}")
    if "skipped_no_plugins" in out:
        pytest.skip("loomweave analyze reported skipped_no_plugins (python plugin did not run)")

    # 2) write a loomweave.yaml enabling serve.http + the wardline write path + HMAC identity.
    #    Keys confirmed against loomweave-mcp/src/config.rs (HttpReadConfig: enabled, bind,
    #    identity_token_env, wardline_taint_write) and docs/operator/loomweave-http-read-api.md.
    config = proj / "loomweave.yaml"
    _write_loomweave_config(config)

    # 3) start `loomweave serve`. It is primarily an MCP stdio server: keep stdin open
    #    (a PIPE we never close until teardown) so the stdio loop does not hit EOF and
    #    tear down the HTTP listener. Drain stdout/stderr to a log file (an undrained
    #    PIPE would deadlock a chatty server, and the log gives the skip/failure reason).
    log_path = proj / "serve.log"
    server_env = {**os.environ, _IDENTITY_ENV: _SECRET}
    with log_path.open("wb") as log_fh:
        proc = subprocess.Popen(  # noqa: S603
            [loomweave_bin, "serve", "--path", str(proj), "--config", str(config)],
            stdin=subprocess.PIPE,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            env=server_env,
        )
        try:
            try:
                base_url = _wait_for_capabilities(proc, log_path)
            except RuntimeError as exc:
                pytest.skip(str(exc))
            if not _wardline_taint_route_live(base_url):
                pytest.skip("live loomweave does not serve /api/wardline/taint-facts")
            # Client side: the secret VALUE must equal what Loomweave read from the env
            # var named by identity_token_env.
            monkeypatch.setenv("WARDLINE_LOOMWEAVE_TOKEN", _SECRET)
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


def test_scan_write_then_explain_query_round_trip(loomweave_server: tuple[Path, str]) -> None:
    proj, url = loomweave_server
    from wardline.core.explain import explain_finding
    from wardline.core.run import run_scan
    from wardline.loomweave.client import LoomweaveClient
    from wardline.loomweave.config import load_loomweave_token, resolve_project_name
    from wardline.loomweave.write import write_facts_to_loomweave

    client = LoomweaveClient(
        url,
        secret=load_loomweave_token(proj),
        project=resolve_project_name(proj),
    )

    # scan -> write (real HMAC POST through the writer-actor)
    result = run_scan(proj)
    wr = write_facts_to_loomweave(result, proj, client)
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
    # Cross-impl check: wardline's blake3 stamp must byte-equal Loomweave's live file hash
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
    exp = explain_finding(proj, path="svc.py", line=6, loomweave=client, sink_qualname="svc.leaky")
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"
    assert exp.tier_in == "EXTERNAL_RAW"


def test_sei_client_against_live_loomweave(loomweave_server: tuple[Path, str]) -> None:
    """Exercise the SEI client against whatever a real `loomweave serve` actually
    advertises — adaptive, so it is a true oracle either way (the SEI conformance
    oracle's two consumer-side scenarios):
      - capability ABSENT  -> honest degrade (UNAVAILABLE, no crash, works on locator)
      - capability PRESENT -> resolve a real locator; opacity holds on any SEI returned
    The consumer must NEVER crash and must NEVER parse the SEI."""
    proj, url = loomweave_server
    from wardline.loomweave.client import LoomweaveClient
    from wardline.loomweave.config import load_loomweave_token, resolve_project_name
    from wardline.loomweave.identity import IdentityStatus, SeiResolver

    client = LoomweaveClient(url, secret=load_loomweave_token(proj), project=resolve_project_name(proj))
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
        assert binding.sei.startswith("loomweave:eid:")
        assert binding.sei != locator
        # The opaque token round-trips through resolve_sei without the client parsing it.
        assert resolver.resolve_identity_status(binding.sei) is IdentityStatus.ALIVE


def test_weft_dossier_against_live_loomweave(loomweave_server: tuple[Path, str]) -> None:
    """T4.3 oracle: assemble a one-call dossier against a real `loomweave serve`.

    Adaptive (a true oracle either way): the self/trust posture is always real; the
    Loomweave-sourced sections fill iff the live build advertises the SEI + HTTP-linkage
    capabilities, and degrade to honest `unavailable` otherwise. Never crashes, never
    parses the SEI, never exceeds the token budget."""
    proj, url = loomweave_server
    from wardline.loomweave.client import LoomweaveClient
    from wardline.loomweave.config import load_loomweave_token, resolve_project_name
    from wardline.loomweave.identity import ContentStatus, IdentityStatus
    from wardline.weft_dossier import build_weft_dossier

    client = LoomweaveClient(url, secret=load_loomweave_token(proj), project=resolve_project_name(proj))
    caps = client.capabilities() or {}
    sei_up = isinstance(caps.get("sei"), dict) and caps["sei"].get("supported") is True
    linkages_up = isinstance(caps.get("linkages"), dict) and caps["linkages"].get("http") is True

    d = build_weft_dossier("svc.leaky", root=proj, loomweave_client=client)

    # self/trust is always real — svc.leaky leaks an external-boundary value
    assert d.identity.qualname == "svc.leaky"
    assert d.trust.gate_verdict == "defect"
    assert any(f.rule_id == "PY-WL-101" for f in d.trust.active_findings)
    # token budget holds on a real envelope
    assert d.estimated_tokens() <= 2000

    if sei_up:
        # SEI resolved live → opaque key, alive identity (never parsed)
        assert isinstance(d.identity.sei, str) and d.identity.sei.startswith("loomweave:eid:")
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


def test_taint_read_by_sei_against_live_loomweave(loomweave_server: tuple[Path, str]) -> None:
    """T3.4 oracle (live wire half): the rename-stable read-by-SEI route round-trips.

    Adaptive — a true oracle either way:
      - ``taint_store.read_by_sei`` ABSENT -> the capability degrades honestly (an older
        SEI Loomweave); nothing to assert beyond detection.
      - PRESENT -> write facts (Loomweave stamps each fact's SEI server-side from its alive
        sei_binding), resolve svc.leaky's SEI, then read it back BY SEI: the fact exists
        and is fresh; a bogus opaque SEI returns exists:false. The SEI is never parsed.

    The flipped-binding rename leg lives in Loomweave's own oracle + the hermetic unit
    test (``test_client_by_sei.test_fact_survives_a_rename_via_sei``) — Wardline cannot
    flip Loomweave's sei_bindings from the client, so that split is honest, not a gap."""
    proj, url = loomweave_server
    from wardline.core.run import run_scan
    from wardline.loomweave.client import LoomweaveClient
    from wardline.loomweave.config import load_loomweave_token, resolve_project_name
    from wardline.loomweave.identity import SeiResolver, TaintStoreCapability
    from wardline.loomweave.write import write_facts_to_loomweave

    client = LoomweaveClient(url, secret=load_loomweave_token(proj), project=resolve_project_name(proj))
    caps = client.capabilities()
    if not TaintStoreCapability.from_capabilities(caps).read_by_sei:
        pytest.skip("live loomweave does not advertise taint_store.read_by_sei (pre-0006 build)")

    # scan -> write (Loomweave stamps the SEI server-side from the alive sei_binding)
    wr = write_facts_to_loomweave(run_scan(proj), proj, client)
    assert wr.reachable is True and wr.written >= 2

    # resolve svc.leaky -> locator -> stable SEI
    resolver = SeiResolver.detect(client)
    rr = client.resolve(["svc.leaky"])
    locator = (rr.resolved.get("svc.leaky") if rr is not None else None) or "python:function:svc.leaky"
    binding = resolver.resolve_locator(locator)
    assert binding.keyed_on_sei is True and isinstance(binding.sei, str)

    # read the fact back BY ITS STABLE SEI — the rename-stable retrieval surface
    views = client.batch_get_by_sei([binding.sei])
    assert views is not None and len(views) == 1
    v = views[0]
    assert v.sei == binding.sei  # opaque, echoed verbatim
    assert v.exists is True
    assert isinstance(v.wardline_json, dict)
    assert v.wardline_json["content_hash_at_compute"] == v.current_content_hash  # live fresh
    assert v.wardline_json["taint"]["actual_return"] == "EXTERNAL_RAW"

    # a bogus opaque SEI -> exists:false (honest miss, never a crash)
    bogus = client.batch_get_by_sei(["loomweave:eid:0000000000000000000000000000dead"])
    assert bogus is not None and len(bogus) == 1
    assert bogus[0].exists is False


def test_published_ephemeral_port_resolves_live_url(loomweave_server: tuple[Path, str]) -> None:
    """ADR-044 (consumer half, live wire): a running serve publishes
    ``.loomweave/ephemeral.port``, and ``resolve_loomweave_url`` self-heals to it.

    Tolerant of the in-flight publisher: if the live build does not yet write the
    file, skip (the contract proves once both halves land) rather than fail. When
    the file IS present, it must agree byte-for-byte with the bound port the serve
    log reported, and the resolver must return exactly that loopback URL. The
    published port is the sole project-derived rung (flag > env > published-port; no
    project-config URL key is read)."""
    proj, url = loomweave_server
    from wardline.core.config import resolve_loomweave_url

    port_file = proj / ".loomweave" / "ephemeral.port"
    if not port_file.exists():
        pytest.skip("live loomweave does not publish .loomweave/ephemeral.port yet (pre-ADR-044 build)")

    bound_port = url.rsplit(":", 1)[1]
    assert port_file.read_text(encoding="ascii").strip() == bound_port

    # No project-config URL rung exists, so resolution self-heals to the published port.
    assert resolve_loomweave_url(None, proj, None) == f"http://127.0.0.1:{bound_port}"
