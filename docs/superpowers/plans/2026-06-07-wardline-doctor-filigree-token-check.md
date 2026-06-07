# wardline doctor — filigree federation-token check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `filigree.auth` check to `wardline doctor` that probes the configured Filigree daemon with the token wardline would emit, detects a 401/403 token mismatch, and under `--repair` recovers the accepted token from local mints and pins it as `WEFT_FEDERATION_TOKEN` in `.env`.

**Architecture:** A new `FiligreeEmitter.verify_token()` probe (sentinel-body POST, reusing the existing injectable `Transport` seam) provides the live auth check. `install/doctor.py` gains `_check_filigree_auth` plus helpers for probe-URL resolution (flag → env → `.mcp.json` arg → published port), candidate-token gathering, and a surgical `.env` rewrite. The check is wired into `machine_readable_doctor` (JSON path) and surfaced in the human `doctor` / `--repair` output.

**Tech Stack:** Python 3.13, click, stdlib `urllib`/`json`/`tomllib`, pytest. Zero new deps.

**Spec:** `docs/superpowers/specs/2026-06-07-wardline-doctor-filigree-token-check-design.md`

---

## File Structure

- `src/wardline/core/filigree_emit.py` — add `ProbeResult` dataclass + `FiligreeEmitter.verify_token()`.
- `src/wardline/install/doctor.py` — add `_check_filigree_auth` + helpers (`_resolve_probe_url`, `_mcp_filigree_url`, `_is_loopback`, `_filigree_token_candidates`, `_rewrite_env_token`); wire into `machine_readable_doctor`.
- `src/wardline/cli/doctor.py` — add optional `--filigree-url`; surface `filigree.auth` in human output.
- `tests/unit/core/test_filigree_verify_token.py` — probe classification.
- `tests/unit/install/test_doctor_filigree_auth.py` — resolution, detection, repair, `.env` rewrite.
- `tests/unit/cli/test_doctor.py` — CLI flag + not-configured integration (append).

---

## Task 1: `FiligreeEmitter.verify_token()` probe

**Files:**
- Modify: `src/wardline/core/filigree_emit.py` (add `ProbeResult` near `EmitResult`; add `verify_token` method on `FiligreeEmitter`)
- Test: `tests/unit/core/test_filigree_verify_token.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_filigree_verify_token.py
from collections.abc import Mapping

import pytest

from wardline.core.filigree_emit import FiligreeEmitter, Response


class _FakeTransport:
    """Records the last POST and returns a canned Response or raises."""

    def __init__(self, *, status: int | None = None, exc: Exception | None = None) -> None:
        self._status = status
        self._exc = exc
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response:
        self.calls.append((url, body, dict(headers)))
        if self._exc is not None:
            raise self._exc
        assert self._status is not None
        return Response(status=self._status, body="")


def test_verify_token_401_is_rejected() -> None:
    t = _FakeTransport(status=401)
    result = FiligreeEmitter("http://127.0.0.1:8749/api/weft/scan-results", transport=t, token="bad").verify_token()
    assert result.reachable is True
    assert result.accepted is False
    assert result.status == 401


def test_verify_token_400_is_accepted() -> None:
    # Auth middleware runs before body validation: a good token + sentinel body => 400.
    t = _FakeTransport(status=400)
    result = FiligreeEmitter("http://127.0.0.1:8749/api/weft/scan-results", transport=t, token="good").verify_token()
    assert result.accepted is True
    assert result.status == 400
    # Sentinel body present; bearer attached.
    url, body, headers = t.calls[0]
    assert headers["Authorization"] == "Bearer good"
    assert body  # non-empty sentinel


def test_verify_token_403_is_rejected() -> None:
    result = FiligreeEmitter("http://x/y", transport=_FakeTransport(status=403), token="t").verify_token()
    assert result.accepted is False


def test_verify_token_transport_error_is_unreachable() -> None:
    t = _FakeTransport(exc=OSError("connection refused"))
    result = FiligreeEmitter("http://127.0.0.1:8749/api/weft/scan-results", transport=t, token="t").verify_token()
    assert result.reachable is False
    assert result.accepted is False
    assert result.status is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/core/test_filigree_verify_token.py -q`
Expected: FAIL — `AttributeError: 'FiligreeEmitter' object has no attribute 'verify_token'`.

- [ ] **Step 3: Write minimal implementation**

In `src/wardline/core/filigree_emit.py`, add the `ProbeResult` dataclass immediately after the `EmitResult` class (before `filigree_disabled_reason`):

```python
@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Outcome of an auth probe (verify_token). ``accepted`` is True when the daemon
    authenticated the bearer (any non-401/403 status, e.g. a 400 from the sentinel body).
    ``reachable`` is False only on a transport failure (connection refused / timeout)."""

    reachable: bool
    accepted: bool
    status: int | None = None
```

Add the method to `FiligreeEmitter` (after `emit`):

```python
    def verify_token(self) -> ProbeResult:
        """Probe whether the daemon accepts this emitter's bearer token, WITHOUT
        recording anything. Auth runs in middleware before body validation, so a
        deliberately-incomplete sentinel body yields 400 (auth passed) or 401/403
        (rejected). Never reuses emit() — that would POST a valid empty scan."""
        body = b"{}"  # parses as JSON, missing required scan-results fields => 400 when authed
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            resp = self._transport.post(self._url, body, headers)
        except (urllib.error.URLError, OSError):
            return ProbeResult(reachable=False, accepted=False)
        accepted = resp.status not in (401, 403)
        return ProbeResult(reachable=True, accepted=accepted, status=resp.status)
```

(`urllib` is already imported at the top of the module.)

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/core/test_filigree_verify_token.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/filigree_emit.py tests/unit/core/test_filigree_verify_token.py
git commit -m "feat(emit): add FiligreeEmitter.verify_token auth probe"
```

---

## Task 2: surgical `.env` token rewriter

**Files:**
- Modify: `src/wardline/install/doctor.py` (add `_rewrite_env_token`)
- Test: `tests/unit/install/test_doctor_filigree_auth.py` (new file; first tests)

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/install/test_doctor_filigree_auth.py
import stat
from pathlib import Path

from wardline.install.doctor import _rewrite_env_token


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_filigree_auth.py -q`
Expected: FAIL — `ImportError: cannot import name '_rewrite_env_token'`.

- [ ] **Step 3: Write minimal implementation**

In `src/wardline/install/doctor.py`, add near the other helpers:

```python
def _rewrite_env_token(env_path: Path, value: str) -> None:
    """Surgically pin ``WEFT_FEDERATION_TOKEN=<value>`` in *env_path*. Removes any
    existing ``WEFT_FEDERATION_TOKEN`` or legacy ``WARDLINE_FILIGREE_TOKEN`` line,
    preserves all other lines/order, creates the file if absent, and sets mode 0600
    (the file holds a secret)."""
    drop = ("WEFT_FEDERATION_TOKEN=", "WARDLINE_FILIGREE_TOKEN=")
    kept: list[str] = []
    if env_path.is_file():
        for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if raw.strip().startswith(drop):
                continue
            kept.append(raw)
    kept.append(f"WEFT_FEDERATION_TOKEN={value}")
    env_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    env_path.chmod(0o600)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_filigree_auth.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/doctor.py tests/unit/install/test_doctor_filigree_auth.py
git commit -m "feat(doctor): add surgical .env federation-token rewriter"
```

---

## Task 3: probe-URL resolution + loopback helper

**Files:**
- Modify: `src/wardline/install/doctor.py` (add `_mcp_filigree_url`, `_resolve_probe_url`, `_is_loopback`)
- Test: `tests/unit/install/test_doctor_filigree_auth.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# append to tests/unit/install/test_doctor_filigree_auth.py
import json

from wardline.install.doctor import _is_loopback, _mcp_filigree_url, _resolve_probe_url


def _write_mcp_with_filigree_url(root: Path, url: str) -> None:
    root.joinpath(".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"wardline": {"type": "stdio", "command": "wardline",
             "args": ["mcp", "--root", ".", "--filigree-url", url]}}}
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
    assert _resolve_probe_url(tmp_path, None) is None


def test_is_loopback() -> None:
    assert _is_loopback("http://127.0.0.1:8749/x") is True
    assert _is_loopback("http://localhost:8749/x") is True
    assert _is_loopback("http://[::1]:8749/x") is True
    assert _is_loopback("https://filigree.example.com/x") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_filigree_auth.py -q`
Expected: FAIL — `ImportError: cannot import name '_mcp_filigree_url'`.

- [ ] **Step 3: Write minimal implementation**

In `src/wardline/install/doctor.py` (the module already imports `json`, `os`, and `urlsplit` from `urllib.parse`), add the helpers. Note the probe URL is resolved ONLY from a deliberately-configured emit target (flag → env → `.mcp.json --filigree-url` arg); the published-port rung is intentionally NOT used, so doctor does no network unless filigree emit is explicitly wired (this also keeps the existing doctor tests network-free):

```python
_FILIGREE_URL_ENV = "WARDLINE_FILIGREE_URL"


def _mcp_filigree_url(root: Path) -> str | None:
    """The ``--filigree-url`` value from the wardline server entry in ``.mcp.json``,
    or None. This is the URL the agent's MCP server actually emits to, and the only
    place it is recorded in the common (MCP) setup."""
    path = root / ".mcp.json"
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    try:
        args = raw["mcpServers"]["wardline"]["args"]
        idx = args.index("--filigree-url")
        value = args[idx + 1]
    except (KeyError, TypeError, ValueError, IndexError):
        return None
    return value if isinstance(value, str) else None


def _resolve_probe_url(root: Path, flag: str | None) -> str | None:
    """Probe-URL precedence: flag > WARDLINE_FILIGREE_URL env > .mcp.json wardline
    --filigree-url arg. None when nothing resolves. The published-port rung is
    deliberately excluded: doctor probes only a configured emit target, so it does
    no network unless filigree emit is explicitly wired."""
    if flag:
        return flag
    env = os.environ.get(_FILIGREE_URL_ENV)
    if env:
        return env
    return _mcp_filigree_url(root)


def _is_loopback(url: str) -> bool:
    """True when *url*'s host is loopback — the only origins a bearer is probed against."""
    host = (urlsplit(url).hostname or "").lower()
    return host in {"localhost", "::1"} or host.startswith("127.")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_filigree_auth.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/doctor.py tests/unit/install/test_doctor_filigree_auth.py
git commit -m "feat(doctor): resolve filigree probe URL (incl. .mcp.json arg) + loopback guard"
```

---

## Task 4: `_check_filigree_auth` — detection (no repair)

**Files:**
- Modify: `src/wardline/install/doctor.py` (add `_filigree_token_candidates`, `_check_filigree_auth`)
- Test: `tests/unit/install/test_doctor_filigree_auth.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# append to tests/unit/install/test_doctor_filigree_auth.py
from collections.abc import Mapping

from wardline.core.filigree_emit import Response
from wardline.install.doctor import _check_filigree_auth


class _ScriptedTransport:
    """Returns a Response per token: maps Authorization bearer -> status."""

    def __init__(self, status_by_token: dict[str, int], *, unreachable: bool = False) -> None:
        self._status_by_token = status_by_token
        self._unreachable = unreachable

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response:
        if self._unreachable:
            raise OSError("connection refused")
        token = headers.get("Authorization", "").removeprefix("Bearer ")
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
    check = _check_filigree_auth(tmp_path, repair=False, filigree_url="https://remote.example.com/api/weft/scan-results",
                                 transport=_ScriptedTransport({}))
    assert check.status == "ok"
    assert "non-loopback" in (check.message or "")


def test_check_ok_when_url_unresolved(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    check = _check_filigree_auth(tmp_path, repair=False, transport=_ScriptedTransport({}))
    assert check.status == "ok"
    assert "not configured" in (check.message or "")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_filigree_auth.py -q`
Expected: FAIL — `ImportError: cannot import name '_check_filigree_auth'`.

- [ ] **Step 3: Write minimal implementation**

In `src/wardline/install/doctor.py`, add the import for the emitter and token loader at the top with the other imports:

```python
from wardline.core.filigree_emit import FiligreeEmitter, Transport, UrllibTransport
from wardline.filigree.config import load_filigree_token
```

Add the candidate helper and the check (detection only; the `repair` branch is filled in Task 5):

```python
def _filigree_token_candidates(root: Path) -> list[str]:
    """Locally-readable federation-token mints, in precedence order: the server-mode
    store (~/.config/filigree) then the project store (<root>/.weft/filigree). Returns
    distinct, non-empty values."""
    paths = [
        Path.home() / ".config" / "filigree" / "federation_token",
        root / ".weft" / "filigree" / "federation_token",
    ]
    out: list[str] = []
    for p in paths:
        try:
            value = p.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value and value not in out:
            out.append(value)
    return out


def _check_filigree_auth(
    root: Path,
    *,
    repair: bool,
    filigree_url: str | None = None,
    transport: Transport | None = None,
) -> DoctorCheck:
    """Verify the token wardline would emit is accepted by the configured Filigree
    daemon. Read-only probe; under *repair*, recover the accepted token from local
    mints and pin it in .env. The probe targets only loopback origins."""
    probe_transport = transport if transport is not None else UrllibTransport(timeout=2.0)
    url = _resolve_probe_url(root, filigree_url)
    if url is None:
        return DoctorCheck("filigree.auth", "ok", message="filigree not configured; nothing to verify")
    if not _is_loopback(url):
        return DoctorCheck("filigree.auth", "ok", message="non-loopback filigree; token not probed")
    token = load_filigree_token(root)  # may be None — probe anyway (the daemon may have auth off)
    probe = FiligreeEmitter(url, transport=probe_transport, token=token).verify_token()
    if not probe.reachable:
        return DoctorCheck("filigree.auth", "ok", message="filigree daemon not reachable; token not verified")
    if probe.accepted:
        return DoctorCheck("filigree.auth", "ok")
    # Rejected (401/403): filigree auth is on and our credential is not accepted.
    if repair:
        return _repair_filigree_auth(root, url, probe_transport)  # implemented in Task 5
    if token:
        return DoctorCheck(
            "filigree.auth", "error",
            message=f"emit token rejected by filigree ({probe.status}); "
            "the configured token is not what the daemon accepts",
        )
    return DoctorCheck(
        "filigree.auth", "error",
        message="filigree rejected an unauthenticated emit and no federation token is set; "
        "export WEFT_FEDERATION_TOKEN or add it to .env",
    )
```

For this task, add a temporary stub so the module imports while Task 5 is pending (it is replaced in Task 5):

```python
def _repair_filigree_auth(root: Path, url: str, transport: Transport) -> DoctorCheck:
    return DoctorCheck("filigree.auth", "error", message="repair not yet implemented")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_filigree_auth.py -q`
Expected: PASS (detection tests green; repair path not yet exercised).

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/doctor.py tests/unit/install/test_doctor_filigree_auth.py
git commit -m "feat(doctor): detect filigree emit-token mismatch via live probe"
```

---

## Task 5: `_repair_filigree_auth` — recover + pin the accepted token

**Files:**
- Modify: `src/wardline/install/doctor.py` (replace the `_repair_filigree_auth` stub)
- Test: `tests/unit/install/test_doctor_filigree_auth.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# append to tests/unit/install/test_doctor_filigree_auth.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_filigree_auth.py -q`
Expected: FAIL — repair returns the "not yet implemented" stub.

- [ ] **Step 3: Write minimal implementation**

Replace the `_repair_filigree_auth` stub in `src/wardline/install/doctor.py`:

```python
def _repair_filigree_auth(root: Path, url: str, transport: Transport) -> DoctorCheck:
    """A 401/403 was seen. Probe each locally-readable mint; if exactly one is
    accepted, pin it as WEFT_FEDERATION_TOKEN in .env and confirm. Otherwise write
    nothing and report (the daemon likely uses an env override we cannot read)."""
    for candidate in _filigree_token_candidates(root):
        probe = FiligreeEmitter(url, transport=transport, token=candidate).verify_token()
        if probe.reachable and probe.accepted:
            _rewrite_env_token(root / ".env", candidate)
            return DoctorCheck(
                "filigree.auth", "ok", fixed=True,
                message="wrote WEFT_FEDERATION_TOKEN to .env (was a stale/mismatched token)",
            )
    return DoctorCheck(
        "filigree.auth", "error",
        message="no local federation_token matched the daemon — it likely uses a "
        "WEFT_FEDERATION_TOKEN env override; set that same value in .env",
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_filigree_auth.py -q`
Expected: PASS (all detection + repair tests green).

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/doctor.py tests/unit/install/test_doctor_filigree_auth.py
git commit -m "feat(doctor): repair recovers accepted federation token into .env"
```

---

## Task 6: wire into machine_readable_doctor + CLI

**Files:**
- Modify: `src/wardline/install/doctor.py` (`machine_readable_doctor` signature + append check)
- Modify: `src/wardline/cli/doctor.py` (`--filigree-url` option; surface `filigree.auth` in human output; pass through to JSON path)
- Test: `tests/unit/cli/test_doctor.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# append to tests/unit/cli/test_doctor.py
def test_doctor_accepts_filigree_url_flag_and_reports_not_configured(tmp_path: Path, monkeypatch) -> None:
    # No filigree wiring (no .mcp.json arg, no env, no port) => filigree.auth is ok/not-configured,
    # so doctor does no network and the new flag is accepted.
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WEFT_FEDERATION_TOKEN", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_TOKEN", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    repair = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path), "--repair"])
    assert repair.exit_code == 0, repair.output

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "filigree.auth" in result.output


def test_doctor_fix_json_includes_filigree_auth_check(tmp_path: Path, monkeypatch) -> None:
    import json as _json

    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WEFT_FEDERATION_TOKEN", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_TOKEN", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path), "--fix"])
    payload = _json.loads(result.output)
    ids = [c["id"] for c in payload["checks"]]
    assert "filigree.auth" in ids
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/cli/test_doctor.py -q`
Expected: FAIL — `--filigree-url` is an unknown option / `filigree.auth` not in output.

- [ ] **Step 3: Write minimal implementation**

In `src/wardline/install/doctor.py`, update `machine_readable_doctor`:

```python
def machine_readable_doctor(
    root: Path,
    *,
    fix: bool = False,
    filigree_url: str | None = None,
    transport: Transport | None = None,
) -> dict[str, Any]:
```

and append the new check to the `checks` list (after `_check_auth_token`):

```python
    checks.append(_check_auth_token(root))
    checks.append(_check_filigree_auth(root, repair=fix, filigree_url=filigree_url, transport=transport))
```

In `src/wardline/cli/doctor.py`, add the import and option, and surface the check in the human paths:

```python
from wardline.install.doctor import (
    _check_filigree_auth,
    check_install,
    machine_readable_doctor,
    repair_install,
)
```

Add the option decorator (after `--fix`):

```python
@click.option("--filigree-url", default=None, help="Filigree Weft URL to probe (default: resolve from .mcp.json/env).")
```

Update the signature: `def doctor(root: Path, repair: bool, fix_json: bool, filigree_url: str | None) -> None:`

In the `--fix` branch, pass it through:

```python
            payload = machine_readable_doctor(root, fix=True, filigree_url=filigree_url)
```

In the `--repair` branch, after the install-check loop and before the exit decision, add:

```python
        fcheck = _check_filigree_auth(root, repair=True, filigree_url=filigree_url)
        status = ("fixed" if fcheck.fixed else fcheck.message) if fcheck.ok else f"failed ({fcheck.message})"
        click.echo(f"  filigree.auth: {status}")
        if not all(check.ok for check in after) or not fcheck.ok:
            raise SystemExit(1)
        return
```

(Replace the existing `if all(check.ok for check in after): return / raise SystemExit(1)` tail of the `--repair` branch with the block above.)

In the default branch, surface detection too. Replace the default tail:

```python
    checks = check_install(root)
    fcheck = _check_filigree_auth(root, repair=False, filigree_url=filigree_url)
    ok = all(check.ok for check in checks) and fcheck.ok
    click.echo("wardline doctor: ok" if ok else "wardline doctor:")
    for check in checks:
        if ok:
            continue
        click.echo(f"  {check.name}: {check.message}")
    if not ok:
        click.echo(f"  filigree.auth: {fcheck.message}" if not fcheck.ok else "")
        raise SystemExit(1)
```

To always show the `filigree.auth` line (the CLI test asserts its presence even when ok), simplify the default tail to:

```python
    checks = check_install(root)
    fcheck = _check_filigree_auth(root, repair=False, filigree_url=filigree_url)
    ok = all(check.ok for check in checks) and fcheck.ok
    click.echo("wardline doctor: ok" if ok else "wardline doctor:")
    for check in checks:
        if not check.ok:
            click.echo(f"  {check.name}: {check.message}")
    fmsg = fcheck.message or ("ok" if fcheck.ok else "error")
    click.echo(f"  filigree.auth: {fmsg}")
    if not ok:
        raise SystemExit(1)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/cli/test_doctor.py -q`
Expected: PASS. The existing `test_doctor_fix_emits_shared_machine_readable_shape` must stay green: with the published-port rung excluded from probe resolution and no `--filigree-url` arg in `_local_mcp_entry()`, `filigree.auth` resolves no URL → `ok`/"not configured" → no network, so `payload["ok"]` stays `True` and `next_actions` stays `[]`.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/doctor.py src/wardline/cli/doctor.py tests/unit/cli/test_doctor.py
git commit -m "feat(doctor): wire filigree.auth check into machine-readable + CLI surfaces"
```

---

## Task 7: full-suite gate + changelog

**Files:**
- Modify: `CHANGELOG.md` (under `[Unreleased] / Added`)
- Test: full suite + linters

- [ ] **Step 1: Run the whole suite + linters**

Run:
```bash
.venv/bin/pytest -q
.venv/bin/ruff check src tests
.venv/bin/mypy src
```
Expected: all green. Fix any failures before continuing (no "pre-existing" excuse — red is red).

- [ ] **Step 2: Add the changelog entry**

In `CHANGELOG.md`, under `## [Unreleased]` → `### Added`:

```markdown
- `wardline doctor` now verifies the Filigree federation token: it probes the
  configured daemon (URL resolved from `.mcp.json`/env) with the token wardline
  would emit and reports a `filigree.auth` check. `--repair` recovers the
  daemon-accepted token from local mints and pins it as `WEFT_FEDERATION_TOKEN`
  in `.env`, removing a stale `WARDLINE_FILIGREE_TOKEN` line.
```

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): note doctor filigree.auth check"
```

- [ ] **Step 4: Live acceptance against lacuna (manual, optional but recommended)**

Run a real probe against the running daemon to confirm end-to-end (the spec's oracle):
```bash
wardline doctor --root ~/lacuna --repair
```
Expected: `filigree.auth: fixed` (writes `WEFT_FEDERATION_TOKEN` into `~/lacuna/.env`), then `wardline scan` from lacuna emits successfully and a finding lands in Filigree. Do not claim done on unit tests alone — confirm the emit block flips to success.

---

## Self-Review Notes

- **Spec coverage:** probe-URL-from-`.mcp.json` (Task 3), sentinel-`{}` probe not `emit([])` (Task 1), detection table incl. absent/non-loopback/unreachable (Task 4), repair-from-local-mints + no-candidate guard (Task 5), `.env`-only write leaving the MCP bearer alone (Tasks 2/5; no `.mcp.json` write anywhere), loopback discipline (Tasks 3/4), CLI surface (Task 6). All covered.
- **Type consistency:** `ProbeResult(reachable, accepted, status)`, `DoctorCheck(id, status, fixed, message)`, `Response(status, body)`, `_check_filigree_auth(root, *, repair, filigree_url=None, transport=None)`, `_repair_filigree_auth(root, url, transport)` — names match across tasks.
- **Note for executor:** Task 4 introduces a temporary `_repair_filigree_auth` stub that Task 5 replaces — if executing out of order, do Task 5 before relying on repair.
