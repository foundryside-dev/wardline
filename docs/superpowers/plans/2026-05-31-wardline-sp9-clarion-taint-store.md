# Wardline SP9 — Clarion-backed taint store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Wardline's `explain_taint` into a query against a persistent taint store that Clarion owns (writing per-entity taint facts at scan time, reading them back at explain time with a freshness gate and an SP8 re-run fallback), and unlock the full N-hop taint chain on top of it — all behind an opt-in `wardline[clarion]` extra that leaves the base package zero-dependency.

**Architecture:** Four units, bottom-up: (a) `clarion/client.py` — a stdlib HTTP+JSON client for the four `/api/wardline/*` routes with an injectable transport, stdlib HMAC auth, status bands, and 2000-item chunking; (b) `clarion/facts.py` — a pure `build_taint_facts` projector from the engine's `AnalysisContext` into Wardline-owned `wardline-taint-1` blobs, stamping a blake3 whole-file hash; (c) a fail-soft scan-time write path in `core/run.py` + `cli/scan.py` + the MCP `scan` tool; (d) a Clarion-backed read path in `core/explain.py` + the MCP `explain_taint` tool with a freshness gate, plus the full N-hop chain walk. The standalone SP8 re-run remains the regression oracle and the freshness/outage fallback throughout.

**Tech Stack:** Python 3.11+, stdlib-only core (`urllib`, `hmac`, `hashlib`, `json`), `blake3` as the sole new dependency behind the `clarion` extra, `click` (CLI), `pytest` (TDD). Wire contract: Clarion `~/clarion/docs/federation/contracts.md` §"Wardline taint-fact store (SP9)" + §"Authentication".

---

## Context the engineer needs (read before starting)

**The spec is authoritative:** `docs/superpowers/specs/2026-05-31-wardline-sp9-clarion-taint-store-design.md`. Read it once. The Clarion wire contract it targets is `~/clarion/docs/federation/contracts.md` (the SP9 + Authentication sections).

**Engine surface you will project from** (already computed by every scan — you add no analysis):
- `wardline.core.run.run_scan(root, *, config_path=None, cache_dir=None, confine_to_root=False) -> ScanResult`. `ScanResult` has `.findings: list[Finding]`, `.summary`, `.files_scanned`, `.context: AnalysisContext | None`.
- `wardline.scanner.context.AnalysisContext` (frozen, MappingProxy-wrapped) carries:
  - `entities: Mapping[str, Entity]` keyed by the **composed dotted qualname**.
  - `project_return_taints: Mapping[str, TaintState]` — effective/declared return tier per function.
  - `function_return_taints: Mapping[str, TaintState]` — actual least-trusted computed return taint.
  - `function_return_callee: Mapping[str, str | None]` — the bare callee name that contributed the worst return, or `None`.
  - `taint_provenance: Mapping[str, TaintProvenance]` where `TaintProvenance` has `.source: Literal["anchored","module_default","minimum_scope","callgraph","fallback"]`, `.resolved_call_count: int`, `.unresolved_call_count: int`.
- `wardline.scanner.index.Entity` (frozen): `.qualname: str`, `.kind: str` (`"function"`/`"method"`), `.node`, `.location: Location`. `Location.path` is the **project-relative POSIX path**; `Location.line_start: int | None`.
- `wardline.core.taints.TaintState` is an enum; `.value` is the string (e.g. `"EXTERNAL_RAW"`).
- `wardline.core.qualname.module_dotted_name(rel_path) -> str | None` and `reconstruct_qualname(...)` already produce Clarion-byte-conformant qualnames. **Reuse; never reimplement.**

**The pattern to mirror for the client:** `wardline.core.filigree_emit` — `Transport` Protocol (`.post(url, body, headers) -> Response`), `UrllibTransport`, `Response(status, body)`, and the status-band classification (`urllib.error.URLError`/`OSError` → soft; `5xx` → soft; non-2xx → loud `*Error`; `2xx` parsed defensively). Read it before Task 1.

**Errors:** `wardline.core.errors` has `WardlineError` and subclasses (`ConfigError`, `FiligreeEmitError`, …). You will add `ClarionError(WardlineError)` in Task 1.

**`.env` key loading to mirror:** `wardline.core.judge_run.load_env_key` reads one `KEY=VALUE` line from `root/.env` only when the env var is unset (env always wins). You will write a sibling `load_clarion_token` in Task 1.

**Tests:** the oracle. `pyproject.toml` runs `-m 'not network'` by default and registers a `network` marker. You will add a `clarion_e2e` marker for the live round-trip (Task 9), deselected by default exactly like `network`. The clean-fixture footgun: `tests/fixtures/sample_project` is **clean** (no active defect). Use the `_LEAKY` tmp-project idiom for any test that needs a PY-WL-101 defect:

```python
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)
```

**Commands:** use `.venv/bin/` binaries (never bare `pytest`/`python`). `git` is the controller's job under subagent-driven execution — if you are an implementer subagent, do NOT run any git verb.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/wardline/clarion/__init__.py` | Package marker + the missing-extra guard helper (`require_blake3`). |
| `src/wardline/clarion/client.py` | `ClarionClient` + `Transport`/`UrllibTransport`/`Response`, HMAC signing, status bands, chunking. The four wire routes. |
| `src/wardline/clarion/facts.py` | `build_taint_facts` (pure projector) + `TaintFactWrite`/`TaintFactView` dataclasses + blake3 stamping + the `wardline-taint-1` blob shape. |
| `src/wardline/clarion/config.py` | `load_clarion_token(root)` (env/`.env`), `resolve_project_name(root)`, the `WARDLINE_CLARION_TOKEN` constant. |
| `src/wardline/clarion/write.py` | `write_facts_to_clarion(result, root, client)` — the fail-soft scan-time write orchestration (build facts → write). Keeps `run_scan` pure; the write is a caller-side side effect. |
| `src/wardline/clarion/_hmac.py` | `canonical_message` + `sign_request` — Clarion's HMAC-SHA256 request signature, stdlib-only. |
| `src/wardline/core/errors.py` | Add `ClarionError(WardlineError)`. |
| `src/wardline/core/explain.py` | `explain_finding` gains a Clarion-backed mode + freshness gate; new `explain_chain` for the N-hop walk; both fall back to the existing re-run. |
| `src/wardline/cli/scan.py` | `--clarion-url` flag → write path. |
| `src/wardline/cli/mcp.py` | `--clarion-url` flag → server config. |
| `src/wardline/mcp/server.py` | `WardlineMCPServer` gains optional `clarion_url`/loads token; `scan` writes facts; `explain_taint` reads + `chain`/`max_hops` args. |
| `pyproject.toml` | New `clarion = ["blake3>=1.0"]` extra; `clarion_e2e` pytest marker. |
| `tests/unit/clarion/test_client.py` | Client: HMAC fixed-vector, chunking, status bands, defensive parsing. |
| `tests/unit/clarion/test_facts.py` | Fact builder: blob shape, blake3 stamp, per-file memoization, qualname conformance. |
| `tests/conformance/test_qualname_clarion_parity.py` | Wardline composition vs Clarion's normative fixture. |
| `tests/unit/core/test_run_clarion.py` | Write path: fail-soft, unresolved reporting, write-disabled soft. |
| `tests/unit/core/test_explain_clarion.py` | Read path: fresh-served, stale/absent/missing-hash → re-run, chain walk + truncation. |
| `tests/e2e/test_clarion_live.py` | `clarion_e2e` round-trip against a real `clarion serve`. |

---

## Task 1: The `clarion` extra, the missing-extra guard, and `ClarionError`

**Files:**
- Create: `src/wardline/clarion/__init__.py`
- Modify: `src/wardline/core/errors.py`
- Modify: `pyproject.toml` (add the `clarion` extra and the `clarion_e2e` marker)
- Test: `tests/unit/clarion/test_extra_guard.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/clarion/test_extra_guard.py
import builtins
import pytest
from wardline.clarion import require_blake3
from wardline.core.errors import ClarionError, WardlineError


def test_clarion_error_is_a_wardline_error():
    assert issubclass(ClarionError, WardlineError)


def test_require_blake3_returns_the_module_when_installed():
    # blake3 is installed in the dev env (the `clarion` extra is in `dev`).
    mod = require_blake3()
    assert hasattr(mod, "blake3")


def test_require_blake3_raises_actionable_error_when_missing(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "blake3":
            raise ModuleNotFoundError("No module named 'blake3'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ClarionError, match=r"install .*wardline\[clarion\]"):
        require_blake3()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/unit/clarion/test_extra_guard.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.clarion'`.

- [ ] **Step 3: Add `ClarionError` to `core/errors.py`**

Append after the existing error classes:

```python
class ClarionError(WardlineError):
    """A Clarion-integration error the user must act on (missing extra, a 4xx
    bad request, a bad --clarion-url). Soft Clarion conditions — outage, 5xx,
    403 WRITE_DISABLED/PROJECT_MISMATCH — are NOT this; they warn and continue."""
```

- [ ] **Step 4: Create `src/wardline/clarion/__init__.py`**

```python
# src/wardline/clarion/__init__.py
"""SP9: the opt-in Clarion-backed taint store integration.

Everything here is behind the ``wardline[clarion]`` extra. The base package and
the ``scanner`` extra never import this package, so they stay zero-dependency;
``blake3`` (the only new dependency) is imported lazily through ``require_blake3``.
"""

from __future__ import annotations

from types import ModuleType

from wardline.core.errors import ClarionError


def require_blake3() -> ModuleType:
    """Import and return the ``blake3`` module, or raise an actionable error.

    Called lazily on the only path that hashes files. Keeping the import here
    (not at module top) is what lets the rest of ``wardline.clarion`` be imported
    for type-checking / wiring without the extra installed."""
    try:
        import blake3
    except ModuleNotFoundError as exc:
        raise ClarionError(
            "the Clarion integration needs blake3 — install it with: "
            "pip install 'wardline[clarion]'"
        ) from exc
    return blake3
```

- [ ] **Step 5: Add the extra and the marker to `pyproject.toml`**

Under `[project.optional-dependencies]`, add (and add `wardline[clarion]` to the `dev` extra's list so CI installs it):

```toml
clarion = ["blake3>=1.0"]
```

Under `[tool.pytest.ini_options]`, extend `markers` (keep `network`):

```toml
markers = [
    "network: tests that need network (live OpenRouter judge e2e — SP5)",
    "clarion_e2e: tests that need a real `clarion serve` binary (SP9 round-trip)",
]
```

And extend the default deselect so the live round-trip is off by default:

```toml
addopts = "-m 'not network and not clarion_e2e'"
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/unit/clarion/test_extra_guard.py -v`
Expected: PASS (3 passed). If `blake3` is not yet installed, run `.venv/bin/pip install 'blake3>=1.0'` first.

- [ ] **Step 7: Commit**

```bash
git add src/wardline/clarion/__init__.py src/wardline/core/errors.py pyproject.toml tests/unit/clarion/test_extra_guard.py
git commit -m "feat(sp9): clarion extra, blake3 missing-extra guard, ClarionError"
```

---

## Task 2: Qualname → Clarion parity conformance test

This locks the silent-failure trap shut **before** any client code depends on it: Clarion's `resolve` is exact-only, so a divergent qualname spelling would make every fact land in `unresolved` and silently no-op the store. Wardline's `core/qualname.py` is already documented as byte-conformant; this test proves it against Clarion's normative fixture and will catch any future drift.

**Files:**
- Create: `tests/conformance/qualnames_clarion.json` (a copy of Clarion's fixture)
- Test: `tests/conformance/test_qualname_clarion_parity.py`

- [ ] **Step 1: Vendor Clarion's normative fixture**

Copy `~/clarion/docs/federation/fixtures/wardline-qualname-normalization.json` to `tests/conformance/qualnames_clarion.json` verbatim (it is a standalone spec vector; vendoring pins the version Wardline was validated against).

```bash
cp ~/clarion/docs/federation/fixtures/wardline-qualname-normalization.json \
   tests/conformance/qualnames_clarion.json
```

- [ ] **Step 2: Write the failing test**

```python
# tests/conformance/test_qualname_clarion_parity.py
import json
from pathlib import Path

import pytest

from wardline.core.qualname import module_dotted_name

_FIXTURE = json.loads(
    (Path(__file__).parent / "qualnames_clarion.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize(
    "vec",
    _FIXTURE["module_normalization_vectors"],
    ids=lambda v: v["file_path"],
)
def test_module_dotted_name_matches_clarion(vec):
    expected = vec["expected_module"]
    got = module_dotted_name(vec["file_path"])
    if expected == "":
        # Clarion REJECTS an empty qualified name (Wardline emits no entity).
        # Wardline represents that as None.
        assert got is None
    else:
        assert got == expected


@pytest.mark.parametrize(
    "vec",
    [v for v in _FIXTURE["qualified_name_vectors"] if v["kind"] == "function"],
    ids=lambda v: v["expected_qualified_name"],
)
def test_composed_function_qualname_matches_clarion(vec):
    # Wardline composes the resolve key as f"{module}.{__qualname__}". The fixture
    # supplies __qualname__ in `qualname`; reconstruct_qualname is tested separately
    # against the AST — here we pin the COMPOSITION the fact builder will use.
    module = module_dotted_name(vec["file_path"])
    assert module is not None
    composed = f"{module}.{vec['qualname']}"
    assert composed == vec["expected_qualified_name"]
```

- [ ] **Step 3: Run the test to verify it passes immediately (the conformance already holds)**

Run: `.venv/bin/pytest tests/conformance/test_qualname_clarion_parity.py -v`
Expected: PASS — every module vector (incl. the `lib/`/`app/`/`a/src/b.py`/`__init__` traps) and every function-composition vector. **If any vector FAILS, stop and report it** — it means Wardline's composition has drifted from Clarion and the integration would silently miss; do not "fix" the test, fix `core/qualname.py`.

- [ ] **Step 4: Commit**

```bash
git add tests/conformance/qualnames_clarion.json tests/conformance/test_qualname_clarion_parity.py
git commit -m "test(sp9): pin qualname composition against Clarion's parity fixture"
```

---

## Task 3: HMAC signing helper

The single load-bearing auth detail, pinned byte-exactly from Clarion source (`canonical_hmac_message`/`component_hmac_hex` in `~/clarion/crates/clarion-cli/src/http_read.rs`). Isolating it as a pure function makes the fixed-vector test trivial.

**Files:**
- Create: `src/wardline/clarion/_hmac.py`
- Test: `tests/unit/clarion/test_hmac.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/clarion/test_hmac.py
import hashlib
import hmac as _hmac

from wardline.clarion._hmac import canonical_message, sign_request


def test_canonical_message_is_three_lines_no_trailing_newline():
    msg = canonical_message("POST", "/api/wardline/resolve", b'{"a":1}')
    body_hash = hashlib.sha256(b'{"a":1}').hexdigest()
    assert msg == f"POST\n/api/wardline/resolve\n{body_hash}"
    assert not msg.endswith("\n")


def test_empty_body_hashes_the_empty_string():
    # bodyless GET: sha256(b"") = e3b0c4…b855
    msg = canonical_message("GET", "/api/wardline/taint-facts?qualname=x", b"")
    assert msg.endswith(
        "\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_sign_request_matches_a_reference_hmac():
    secret, method, paq, body = "s3cr3t", "POST", "/api/wardline/resolve", b'{"qualnames":[]}'
    expected = _hmac.new(
        secret.encode("utf-8"),
        canonical_message(method, paq, body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert sign_request(secret, method, paq, body) == expected
    assert all(c in "0123456789abcdef" for c in sign_request(secret, method, paq, body))


def test_header_value_format():
    sig = sign_request("s", "GET", "/x", b"")
    # The client builds the header value as f"clarion:{sig}"; assert sig is bare hex.
    assert ":" not in sig
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/unit/clarion/test_hmac.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.clarion._hmac'`.

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/clarion/_hmac.py
"""Clarion's HMAC-SHA256 request signature, reproduced byte-exactly (stdlib only).

Pinned from Clarion's `canonical_hmac_message` / `component_hmac_hex`
(clarion-cli/src/http_read.rs) and `contracts.md` §Authentication:

    <METHOD>\\n<PATH_AND_QUERY>\\n<sha256_hex(body)>      # no trailing newline

then lowercase-hex HMAC-SHA256 over that message. The header is
`X-Loom-Component: clarion:<hmac>`. Note: the BODY hash here is SHA-256; the
freshness hash (clarion/facts.py) is blake3 — they are unrelated.
"""

from __future__ import annotations

import hashlib
import hmac


def canonical_message(method: str, path_and_query: str, body: bytes) -> str:
    """The exact string Clarion signs: three parts joined by '\\n', no trailing newline."""
    return f"{method}\n{path_and_query}\n{hashlib.sha256(body).hexdigest()}"


def sign_request(secret: str, method: str, path_and_query: str, body: bytes) -> str:
    """Return the lowercase-hex HMAC-SHA256 signature (bare hex, no 'clarion:' prefix)."""
    return hmac.new(
        secret.encode("utf-8"),
        canonical_message(method, path_and_query, body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/unit/clarion/test_hmac.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/wardline/clarion/_hmac.py tests/unit/clarion/test_hmac.py
git commit -m "feat(sp9): byte-exact Clarion HMAC-SHA256 request signing (stdlib)"
```

---

## Task 4: Config — token loading and project name

**Files:**
- Create: `src/wardline/clarion/config.py`
- Test: `tests/unit/clarion/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/clarion/test_config.py
from wardline.clarion.config import (
    WARDLINE_CLARION_TOKEN_ENV,
    load_clarion_token,
    resolve_project_name,
)


def test_env_var_wins_over_dotenv(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(f"{WARDLINE_CLARION_TOKEN_ENV}=from-dotenv\n", encoding="utf-8")
    monkeypatch.setenv(WARDLINE_CLARION_TOKEN_ENV, "from-env")
    assert load_clarion_token(tmp_path) == "from-env"


def test_dotenv_used_when_env_unset(tmp_path, monkeypatch):
    monkeypatch.delenv(WARDLINE_CLARION_TOKEN_ENV, raising=False)
    (tmp_path / ".env").write_text(
        f'{WARDLINE_CLARION_TOKEN_ENV}="quoted-secret"\n', encoding="utf-8"
    )
    assert load_clarion_token(tmp_path) == "quoted-secret"


def test_returns_none_when_unset_and_no_dotenv(tmp_path, monkeypatch):
    monkeypatch.delenv(WARDLINE_CLARION_TOKEN_ENV, raising=False)
    assert load_clarion_token(tmp_path) is None


def test_project_name_is_the_root_directory_name(tmp_path):
    proj = tmp_path / "my-project"
    proj.mkdir()
    assert resolve_project_name(proj) == "my-project"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/unit/clarion/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.clarion.config'`.

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/clarion/config.py
"""SP9 credentials + project guard. The HMAC secret comes from env / `.env` ONLY,
never from wardline.yaml — the same discipline as the OpenRouter judge key. The
env var name is independent of Clarion's server-side name; only the secret VALUE
must match the value the Clarion operator put in `serve.http.identity_token_env`.
"""

from __future__ import annotations

import os
from pathlib import Path

WARDLINE_CLARION_TOKEN_ENV = "WARDLINE_CLARION_TOKEN"


def load_clarion_token(root: Path) -> str | None:
    """Return the HMAC secret from the environment, or a single KEY=VALUE line in
    ``root/.env``, or None. An already-set environment value always wins."""
    value = os.environ.get(WARDLINE_CLARION_TOKEN_ENV)
    if value:
        return value
    env_path = root / ".env"
    if not env_path.is_file():
        return None
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith(f"{WARDLINE_CLARION_TOKEN_ENV}="):
            parsed = line.split("=", 1)[1].strip().strip('"').strip("'")
            return parsed or None
    return None


def resolve_project_name(root: Path) -> str:
    """Clarion's project guard handle: the project-root directory name."""
    return root.resolve().name
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/unit/clarion/test_config.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/wardline/clarion/config.py tests/unit/clarion/test_config.py
git commit -m "feat(sp9): Clarion token loading (env/.env) + project-guard name"
```

---

## Task 5: `ClarionClient` — transport, signing, status bands, the four routes, chunking

**Files:**
- Create: `src/wardline/clarion/client.py`
- Test: `tests/unit/clarion/test_client.py`

The dataclasses `TaintFactWrite`/`TaintFactView` are defined in Task 6 (`clarion/facts.py`); to keep this task self-contained the client uses `dict`-shaped payloads for write/read and Task 6 wires the typed builders in. The client's job is transport + auth + chunking + parsing, not blob shape.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/clarion/test_client.py
import json

import pytest

from wardline.clarion._hmac import sign_request
from wardline.clarion.client import ClarionClient, Response
from wardline.core.errors import ClarionError


class FakeTransport:
    """Records requests; returns queued responses (or a default 200)."""

    def __init__(self, responses=None):
        self.calls = []  # list of (method, url, body, headers)
        self._responses = list(responses or [])

    def request(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))
        if self._responses:
            return self._responses.pop(0)
        return Response(status=200, body="{}")


def _client(transport, **kw):
    return ClarionClient(
        "http://clarion.example", secret="s3cr3t", project="proj",
        transport=transport, **kw,
    )


def test_resolve_signs_and_parses():
    body = json.dumps({"resolved": {"a.b": "python:function:a.b"}, "unresolved": ["c.d"]})
    t = FakeTransport([Response(status=200, body=body)])
    result = _client(t).resolve(["a.b", "c.d"])
    assert result.resolved == {"a.b": "python:function:a.b"}
    assert result.unresolved == ["c.d"]
    method, url, sent_body, headers = t.calls[0]
    assert method == "POST"
    assert url == "http://clarion.example/api/wardline/resolve"
    # the project guard is sent
    assert json.loads(sent_body)["project"] == "proj"
    # the signature covers method + path_and_query + body
    expected = sign_request("s3cr3t", "POST", "/api/wardline/resolve", sent_body)
    assert headers["X-Loom-Component"] == f"clarion:{expected}"


def test_no_secret_sends_no_auth_header():
    t = FakeTransport([Response(status=200, body='{"resolved":{},"unresolved":[]}')])
    ClarionClient("http://c", secret=None, project="proj", transport=t).resolve(["a.b"])
    assert "X-Loom-Component" not in t.calls[0][3]


def test_write_chunks_against_batch_max():
    # 5 facts, batch_max=2 → 3 chunks (2+2+1), each a separate POST.
    t = FakeTransport([Response(status=200, body='{"written":2,"unresolved_qualnames":[]}')] * 3)
    facts = [{"qualname": f"m.f{i}", "wardline_json": {}} for i in range(5)]
    result = _client(t, batch_max=2).write_taint_facts(facts)
    assert len(t.calls) == 3
    assert result.written == 6  # 2+2+2 from the stubbed responses; sums across chunks


def test_batch_get_chunks_and_preserves_input_order():
    # 3 qualnames, batch_max=2 → 2 chunks; the bare-array responses are concatenated in order.
    r1 = json.dumps([{"qualname": "a", "exists": False}, {"qualname": "b", "exists": False}])
    r2 = json.dumps([{"qualname": "c", "exists": True, "wardline_json": {"x": 1},
                      "current_content_hash": "deadbeef"}])
    t = FakeTransport([Response(status=200, body=r1), Response(status=200, body=r2)])
    views = _client(t, batch_max=2).batch_get(["a", "b", "c"])
    assert [v.qualname for v in views] == ["a", "b", "c"]
    assert views[2].exists is True
    assert views[2].current_content_hash == "deadbeef"
    assert views[0].current_content_hash is None  # field-absent → None


def test_5xx_is_soft_returns_none_sentinel():
    t = FakeTransport([Response(status=503, body='{"code":"STORAGE_ERROR"}')])
    # soft failure surfaces as a ClarionUnavailable marker, NOT an exception
    result = _client(t).batch_get(["a"])
    assert result is None  # batch_get returns None on a soft failure


def test_403_write_disabled_is_soft_on_write():
    t = FakeTransport([Response(status=403, body='{"code":"WRITE_DISABLED"}')])
    result = _client(t).write_taint_facts([{"qualname": "m.f", "wardline_json": {}}])
    assert result.reachable is False
    assert result.disabled_reason == "WRITE_DISABLED"


def test_4xx_invalid_path_is_loud():
    t = FakeTransport([Response(status=400, body='{"code":"INVALID_PATH"}')])
    with pytest.raises(ClarionError, match="INVALID_PATH"):
        _client(t).resolve(["a.b"])


def test_connection_error_is_soft():
    class Boom:
        def request(self, *a, **k):
            raise OSError("connection refused")

    assert _client(Boom()).batch_get(["a"]) is None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/unit/clarion/test_client.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.clarion.client'`.

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/clarion/client.py
"""SP9: the dep-light HTTP+JSON client for Clarion's /api/wardline/* routes.

Mirrors core/filigree_emit's transport discipline: an injectable Transport (no
test touches the network), and status bands where a sibling-absent/5xx outage is
SOFT (the caller degrades to the SP8 re-run) while a 4xx is a LOUD ClarionError
(Wardline sent a bad request). The split adds: 403 WRITE_DISABLED/PROJECT_MISMATCH
are soft (the store is off / wrong project — not a Wardline bug). The client routes
on the envelope `code`, not the HTTP status (the same code can carry different
statuses by route).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from wardline.clarion._hmac import sign_request
from wardline.core.errors import ClarionError

_ALLOWED_SCHEMES = ("http", "https")
_SOFT_CODES = frozenset({"WRITE_DISABLED", "PROJECT_MISMATCH"})


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: str


class Transport(Protocol):
    def request(
        self, method: str, url: str, body: bytes, headers: Mapping[str, str]
    ) -> Response: ...


class UrllibTransport:
    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def request(
        self, method: str, url: str, body: bytes, headers: Mapping[str, str]
    ) -> Response:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise ClarionError(
                f"--clarion-url must use http or https; got scheme {scheme!r} in {url!r}"
            )
        data = body if body else None
        req = urllib.request.Request(url, data=data, headers=dict(headers), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                return Response(status=resp.status, body=resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            with exc:
                return Response(status=exc.code, body=exc.read().decode("utf-8", "replace"))


@dataclass(frozen=True, slots=True)
class ResolveResult:
    resolved: dict[str, str]
    unresolved: list[str]


@dataclass(frozen=True, slots=True)
class WriteResult:
    reachable: bool
    written: int = 0
    unresolved_qualnames: tuple[str, ...] = ()
    disabled_reason: str | None = None  # "WRITE_DISABLED" / "PROJECT_MISMATCH" when soft-off


@dataclass(frozen=True, slots=True)
class TaintFactView:
    qualname: str
    exists: bool
    wardline_json: dict[str, Any] | None = None
    current_content_hash: str | None = None

    @classmethod
    def from_wire(cls, obj: Mapping[str, Any]) -> TaintFactView:
        return cls(
            qualname=str(obj.get("qualname", "")),
            exists=bool(obj.get("exists", False)),
            wardline_json=obj.get("wardline_json"),       # field-absent → None
            current_content_hash=obj.get("current_content_hash"),  # field-absent → None
        )


def _chunks(seq: Sequence[Any], size: int):
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _error_code(body: str) -> str | None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    return parsed.get("code") if isinstance(parsed, dict) else None


class ClarionClient:
    def __init__(
        self,
        base_url: str,
        *,
        secret: str | None,
        project: str,
        transport: Transport | None = None,
        batch_max: int = 2000,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._secret = secret
        self._project = project
        self._transport: Transport = transport if transport is not None else UrllibTransport()
        self._batch_max = batch_max

    # -- transport + classification ------------------------------------------

    def _send(self, method: str, path_and_query: str, payload: dict[str, Any] | None) -> Response | None:
        """Sign + send. Returns the Response, or None on a SOFT failure (outage/5xx)."""
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        headers: dict[str, str] = {}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if self._secret:
            sig = sign_request(self._secret, method, path_and_query, body)
            headers["X-Loom-Component"] = f"clarion:{sig}"
        url = f"{self._base}{path_and_query}"
        try:
            resp = self._transport.request(method, url, body, headers)
        except (urllib.error.URLError, OSError):
            return None  # sibling absent — soft
        if resp.status >= 500:
            return None  # server outage — soft
        return resp

    def _require_ok(self, resp: Response, path: str) -> dict[str, Any]:
        """For routes with no soft 4xx: 2xx → parsed dict; anything else → loud."""
        if not 200 <= resp.status < 300:
            raise ClarionError(
                f"Clarion rejected {path} ({resp.status}; code={_error_code(resp.body)}): {resp.body}"
            )
        try:
            parsed = json.loads(resp.body) if resp.body else {}
        except json.JSONDecodeError:
            parsed = {}
        return parsed if isinstance(parsed, dict) else {}

    # -- routes ---------------------------------------------------------------

    def resolve(self, qualnames: list[str]) -> ResolveResult | None:
        resolved: dict[str, str] = {}
        unresolved: list[str] = []
        for chunk in _chunks(qualnames, self._batch_max):
            payload = {"project": self._project, "qualnames": list(chunk)}
            resp = self._send("POST", "/api/wardline/resolve", payload)
            if resp is None:
                return None
            data = self._require_ok(resp, "/api/wardline/resolve")
            r = data.get("resolved")
            if isinstance(r, dict):
                resolved.update(r)
            u = data.get("unresolved")
            if isinstance(u, list):
                unresolved.extend(str(x) for x in u)
        return ResolveResult(resolved=resolved, unresolved=unresolved)

    def write_taint_facts(self, facts: list[dict[str, Any]]) -> WriteResult:
        written = 0
        unresolved: list[str] = []
        for chunk in _chunks(facts, self._batch_max):
            payload = {"project": self._project, "facts": list(chunk)}
            resp = self._send("POST", "/api/wardline/taint-facts", payload)
            if resp is None:
                return WriteResult(reachable=False)  # soft outage
            if resp.status == 403:
                return WriteResult(reachable=False, disabled_reason=_error_code(resp.body) or "WRITE_DISABLED")
            data = self._require_ok(resp, "/api/wardline/taint-facts")
            written += int(data.get("written", 0) or 0)
            uq = data.get("unresolved_qualnames")
            if isinstance(uq, list):
                unresolved.extend(str(x) for x in uq)
        return WriteResult(reachable=True, written=written, unresolved_qualnames=tuple(unresolved))

    def get_taint_fact(self, qualname: str) -> TaintFactView | None:
        # query params must be byte-identical to the signed path_and_query
        query = urllib.parse.urlencode({"project": self._project, "qualname": qualname})
        paq = f"/api/wardline/taint-facts?{query}"
        resp = self._send("GET", paq, None)
        if resp is None:
            return None
        if resp.status == 403:
            return None  # PROJECT_MISMATCH — soft
        data = self._require_ok(resp, paq)
        return TaintFactView.from_wire(data)

    def batch_get(self, qualnames: list[str]) -> list[TaintFactView] | None:
        views: list[TaintFactView] = []
        for chunk in _chunks(qualnames, self._batch_max):
            payload = {"project": self._project, "qualnames": list(chunk)}
            resp = self._send("POST", "/api/wardline/taint-facts:batch-get", payload)
            if resp is None:
                return None
            if resp.status == 403:
                return None  # PROJECT_MISMATCH — soft
            try:
                parsed = json.loads(resp.body) if resp.body else []
            except json.JSONDecodeError:
                parsed = []
            if not 200 <= resp.status < 300 or not isinstance(parsed, list):
                raise ClarionError(
                    f"Clarion rejected batch-get ({resp.status}; code={_error_code(resp.body)})"
                )
            views.extend(TaintFactView.from_wire(o) for o in parsed if isinstance(o, dict))
        return views
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/unit/clarion/test_client.py -v`
Expected: PASS (8 passed). Note: `test_write_chunks_against_batch_max` asserts `written == 6` because the fake returns `written:2` for each of 3 chunks and the client sums across chunks.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/clarion/client.py tests/unit/clarion/test_client.py
git commit -m "feat(sp9): ClarionClient — HMAC transport, status bands, 2000-chunking, 4 routes"
```

---

## Task 6: `build_taint_facts` — project the engine context into `wardline-taint-1` blobs

**Files:**
- Create: `src/wardline/clarion/facts.py`
- Test: `tests/unit/clarion/test_facts.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/clarion/test_facts.py
from pathlib import Path

from wardline.clarion.facts import SCHEMA_VERSION, build_taint_facts
from wardline.core.run import run_scan

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _scan_leaky(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj, run_scan(proj)


def test_builds_one_fact_per_function_entity(tmp_path):
    proj, result = _scan_leaky(tmp_path)
    facts = build_taint_facts(result, proj)
    quals = {f["qualname"] for f in facts}
    # both functions are entities; qualnames are the composed dotted form
    assert "svc.read_raw" in quals
    assert "svc.leaky" in quals


def test_leaky_fact_carries_the_taint_projection(tmp_path):
    proj, result = _scan_leaky(tmp_path)
    facts = {f["qualname"]: f for f in build_taint_facts(result, proj)}
    leaky = facts["svc.leaky"]
    blob = leaky["wardline_json"]
    assert blob["schema_version"] == SCHEMA_VERSION
    assert blob["qualname"] == "svc.leaky"
    assert blob["taint"]["actual_return"] == "EXTERNAL_RAW"
    # leaky's worst return comes from calling read_raw → contributing callee resolves
    assert blob["taint"]["contributing_callee_qualname"] == "svc.read_raw"
    # read_raw is a boundary leaf → its own contributing callee is null
    read_raw = facts["svc.read_raw"]["wardline_json"]
    assert read_raw["taint"]["contributing_callee_qualname"] is None


def test_content_hash_is_blake3_whole_file_and_top_level_and_in_blob(tmp_path):
    proj, result = _scan_leaky(tmp_path)
    import blake3
    expected = blake3.blake3((proj / "svc.py").read_bytes()).hexdigest()
    fact = next(f for f in build_taint_facts(result, proj) if f["qualname"] == "svc.leaky")
    # top-level write column AND inside the opaque blob (the read returns only the blob)
    assert fact["content_hash_at_compute"] == expected
    assert fact["wardline_json"]["content_hash_at_compute"] == expected
    assert len(expected) == 64  # blake3-256 lowercase hex


def test_per_file_hash_is_memoized(tmp_path, monkeypatch):
    proj, result = _scan_leaky(tmp_path)
    import wardline.clarion.facts as facts_mod
    calls = {"n": 0}
    real = facts_mod._read_bytes

    def counting(path):
        calls["n"] += 1
        return real(path)

    monkeypatch.setattr(facts_mod, "_read_bytes", counting)
    build_taint_facts(result, proj)
    # two entities, one file → the file is read exactly once
    assert calls["n"] == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/unit/clarion/test_facts.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.clarion.facts'`.

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/clarion/facts.py
"""SP9: project the engine's AnalysisContext into Wardline-owned taint-fact blobs.

`build_taint_facts` is a pure function of (ScanResult + root). It produces one
fact per function entity. Each fact carries:
  - `qualname`: the composed dotted form (Entity.qualname — already Clarion-conformant),
  - `wardline_json`: the opaque `wardline-taint-1` blob (Clarion stores it verbatim),
  - top-level `content_hash_at_compute` (Clarion's queryable column) — REPEATED inside
    the blob because Clarion's read never returns the column, only the blob (the
    freshness gate reads the in-blob copy).

`content_hash_at_compute` = blake3 of the entity's containing file, WHOLE FILE, RAW
BYTES (binary read — no LF translation), lowercase hex. This matches Clarion's
`current_content_hash` (clarion_storage::current_file_hash); it is NOT sha256, NOT
LF-normalized, NOT span-scoped. blake3 is imported lazily via require_blake3, so the
base package stays zero-dependency.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wardline.clarion import require_blake3
from wardline.core.run import ScanResult

SCHEMA_VERSION = "wardline-taint-1"


def _read_bytes(path: Path) -> bytes:
    """Whole file, raw bytes. Indirected so tests can spy on read frequency."""
    return path.read_bytes()


def _resolve_callee_qualname(context: Any, qualname: str, callee: str | None) -> str | None:
    """Resolve the bare contributing-callee name to a same-module entity qualname for
    the chain walk, mirroring explain_finding's honest 1-hop rule: only when the callee
    is a simple (non-dotted) name AND `<module>.<callee>` is a known entity. Otherwise
    None — the chain can't follow this hop and will truncate explicitly."""
    if callee is None or "." in callee or "." not in qualname:
        return None
    module = qualname.rsplit(".", 1)[0]
    candidate = f"{module}.{callee}"
    return candidate if candidate in context.entities else None


def build_taint_facts(result: ScanResult, root: Path) -> list[dict[str, Any]]:
    """Build the write payloads (one per function entity). Empty list if the scan
    produced no context (no entities)."""
    context = result.context
    if context is None:
        return []
    blake3 = require_blake3()
    hash_cache: dict[str, str] = {}

    # Index findings by qualname so each fact can carry its anchoring findings[].
    findings_by_qualname: dict[str, list[dict[str, Any]]] = {}
    for f in result.findings:
        if f.qualname is None:
            continue
        findings_by_qualname.setdefault(f.qualname, []).append(
            {"rule_id": f.rule_id, "fingerprint": f.fingerprint,
             "line_start": f.location.line_start}
        )

    facts: list[dict[str, Any]] = []
    for qualname, entity in context.entities.items():
        rel_path = entity.location.path
        if rel_path not in hash_cache:
            hash_cache[rel_path] = blake3.blake3(_read_bytes(root / rel_path)).hexdigest()
        content_hash = hash_cache[rel_path]

        declared = context.project_return_taints.get(qualname)
        actual = context.function_return_taints.get(qualname)
        prov = context.taint_provenance.get(qualname)
        callee = context.function_return_callee.get(qualname)

        blob: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "qualname": qualname,
            "content_hash_at_compute": content_hash,
            "taint": {
                "declared_return": declared.value if declared is not None else None,
                "actual_return": actual.value if actual is not None else None,
                "source": prov.source if prov is not None else None,
                "contributing_callee_qualname": _resolve_callee_qualname(context, qualname, callee),
                "resolved_call_count": prov.resolved_call_count if prov is not None else 0,
                "unresolved_call_count": prov.unresolved_call_count if prov is not None else 0,
            },
            "findings": findings_by_qualname.get(qualname, []),
        }
        facts.append({
            "qualname": qualname,
            "wardline_json": blob,
            "content_hash_at_compute": content_hash,
        })
    return facts
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/unit/clarion/test_facts.py -v`
Expected: PASS (4 passed). If `test_leaky_fact_carries_the_taint_projection` shows a different `actual_return` value, print the blob and reconcile against `context.function_return_taints` — do not change the assertion to match a wrong projection; confirm the engine value first.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/clarion/facts.py tests/unit/clarion/test_facts.py
git commit -m "feat(sp9): build_taint_facts — per-entity wardline-taint-1 blobs + blake3 stamp"
```

---

## Task 7: Scan-time write path (core + CLI + MCP)

**Files:**
- Create: `src/wardline/clarion/write.py` (the fail-soft orchestration wrapper)
- Modify: `src/wardline/cli/scan.py` (add `--clarion-url`)
- Modify: `src/wardline/cli/mcp.py` (add `--clarion-url`)
- Modify: `src/wardline/mcp/server.py` (server holds clarion config; `scan` writes)
- Test: `tests/unit/clarion/test_write.py`

The write path is fail-soft and lives in its own wrapper so both the CLI and the MCP `scan` tool call exactly one function. `run_scan` itself stays pure — the write is a caller-side side effect on the returned `ScanResult`, not folded into the gate.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/clarion/test_write.py
from pathlib import Path

from wardline.clarion.client import WriteResult
from wardline.clarion.write import write_facts_to_clarion
from wardline.core.run import run_scan

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


class FakeClient:
    def __init__(self, result):
        self._result = result
        self.written_payloads = None

    def write_taint_facts(self, facts):
        self.written_payloads = facts
        return self._result


def _proj(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def test_write_reports_written_and_unresolved(tmp_path):
    proj = _proj(tmp_path)
    result = run_scan(proj)
    client = FakeClient(WriteResult(reachable=True, written=2, unresolved_qualnames=("x.y",)))
    outcome = write_facts_to_clarion(result, proj, client)
    assert outcome.reachable is True
    assert outcome.written == 2
    assert outcome.unresolved_qualnames == ("x.y",)
    assert client.written_payloads is not None  # facts were built and handed over


def test_write_disabled_is_soft(tmp_path):
    proj = _proj(tmp_path)
    result = run_scan(proj)
    client = FakeClient(WriteResult(reachable=False, disabled_reason="WRITE_DISABLED"))
    outcome = write_facts_to_clarion(result, proj, client)
    assert outcome.reachable is False
    assert outcome.disabled_reason == "WRITE_DISABLED"


def test_outage_is_soft(tmp_path):
    proj = _proj(tmp_path)
    result = run_scan(proj)
    client = FakeClient(WriteResult(reachable=False))
    outcome = write_facts_to_clarion(result, proj, client)
    assert outcome.reachable is False
    assert outcome.disabled_reason is None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/unit/clarion/test_write.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.clarion.write'`.

- [ ] **Step 3: Write `clarion/write.py`**

```python
# src/wardline/clarion/write.py
"""SP9: the fail-soft scan-time write orchestration.

Build facts → write them. The whole step is non-load-bearing: a Clarion outage,
403 WRITE_DISABLED, or PROJECT_MISMATCH returns a WriteResult the caller reports
but never fails on. There is no capability probe — the contract does not advertise
the store, so the write is attempt-then-handle-403 (the client already does this).
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from wardline.clarion.client import WriteResult
from wardline.clarion.facts import build_taint_facts
from wardline.core.run import ScanResult


class _WriteClient(Protocol):
    def write_taint_facts(self, facts: list[dict]) -> WriteResult: ...


def write_facts_to_clarion(result: ScanResult, root: Path, client: _WriteClient) -> WriteResult:
    """Project the scan into facts and write them. Fail-soft by construction —
    the client returns a WriteResult (reachable False on outage/disabled), never raises
    for soft conditions. A 4xx (bad request) still raises ClarionError from the client."""
    facts = build_taint_facts(result, root)
    if not facts:
        return WriteResult(reachable=True, written=0)
    return client.write_taint_facts(facts)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/unit/clarion/test_write.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Wire the CLI flag (`cli/scan.py`)**

Add the option and the post-scan write. Insert the option decorator after `--filigree-url`:

```python
@click.option("--clarion-url", "clarion_url", default=None,
              help="Persist per-entity taint facts to this Clarion taint-store URL (opt-in, fail-soft).")
```

Add `clarion_url: str | None` to the `scan(...)` signature (after `filigree_url`). After the Filigree emission block (inside the `try`), add:

```python
        if clarion_url is not None:
            from wardline.clarion.client import ClarionClient
            from wardline.clarion.config import load_clarion_token, resolve_project_name
            from wardline.clarion.write import write_facts_to_clarion

            client = ClarionClient(
                clarion_url,
                secret=load_clarion_token(path),
                project=resolve_project_name(path),
            )
            clarion_result = write_facts_to_clarion(result, path, client)
```

(Declare `clarion_result = None` next to `emit_result` at the top of the function.) After the Filigree reporting block, add reporting:

```python
    if clarion_result is not None:
        if not clarion_result.reachable:
            reason = clarion_result.disabled_reason or "unreachable"
            click.echo(
                f"warning: Clarion taint store not written ({reason}); scan unaffected.",
                err=True,
            )
        else:
            line = f"wrote {clarion_result.written} taint fact(s) to {clarion_url}"
            if clarion_result.unresolved_qualnames:
                line += f"; {len(clarion_result.unresolved_qualnames)} qualname(s) unresolved (not indexed by Clarion)"
            click.echo(line)
```

Note: a `ClarionError` (missing extra, 4xx, bad scheme) propagates to the existing `except WardlineError` block → `exit 2`, exactly as Filigree errors do.

- [ ] **Step 6: Wire the MCP server (`cli/mcp.py` + `mcp/server.py`)**

In `cli/mcp.py`, add the option and pass it through:

```python
@click.option("--clarion-url", "clarion_url", default=None,
              help="Clarion taint-store URL: `scan` writes facts; `explain_taint` queries it.")
```

Add `clarion_url: str | None` to the command function signature and change the construction to:

```python
    WardlineMCPServer(root=root, clarion_url=clarion_url).rpc.run_stdio()
```

In `mcp/server.py`, change `WardlineMCPServer.__init__`:

```python
    def __init__(self, *, root: Path, clarion_url: str | None = None) -> None:
        self.root = Path(root)
        self.clarion_url = clarion_url
        self.rpc = JsonRpcServer(server_name="wardline", server_version=__version__)
        self._tools: dict[str, Any] = {}
        self._register_tools()
        self._wire()

    def _clarion_client(self):
        """Build a ClarionClient for this server's root, or None when no URL is set."""
        if self.clarion_url is None:
            return None
        from wardline.clarion.client import ClarionClient
        from wardline.clarion.config import load_clarion_token, resolve_project_name
        return ClarionClient(
            self.clarion_url,
            secret=load_clarion_token(self.root),
            project=resolve_project_name(self.root),
        )
```

The tool handlers are module-level functions taking `(args, root)`; to give `_scan`/`_explain_taint` access to the client, make them bound methods OR pass the server. Minimal change: convert `_scan` and `_explain_taint` registration to wrap the server. Replace their `handler=_scan` / `handler=_explain_taint` with small closures in `_register_tools`:

```python
            handler=lambda args, root: _scan(args, root, self._clarion_client()),
```
```python
            handler=lambda args, root: _explain_taint(args, root, self._clarion_client(), self.root),
```

Update `_scan` to optionally write (after computing `result`, before building the return dict):

```python
def _scan(args: dict[str, Any], root: Path, clarion=None) -> dict[str, Any]:
    ...
    result = run_scan(path, config_path=_cfg(args, root), confine_to_root=True)
    if clarion is not None:
        from wardline.clarion.write import write_facts_to_clarion
        wr = write_facts_to_clarion(result, path, clarion)  # fail-soft; never raises on outage
        # surface as a non-fatal note in the payload (the agent sees it, the gate ignores it)
    decision = gate_decision(result, threshold)
    ...
```

Add a `"clarion"` key to the `_scan` return dict when `clarion is not None`:

```python
        "clarion": None if clarion is None else {
            "reachable": wr.reachable,
            "written": wr.written,
            "unresolved_qualnames": list(wr.unresolved_qualnames),
            "disabled_reason": wr.disabled_reason,
        },
```

(`_explain_taint`'s new signature is implemented in Task 8 — for this task, give it `clarion=None, server_root=None` defaults so the wiring compiles and the SP8 behavior is unchanged.)

- [ ] **Step 7: Add a write-path MCP test**

```python
# tests/unit/mcp/test_server_clarion_write.py
from pathlib import Path

from wardline.clarion.client import WriteResult
from wardline.mcp.server import _scan

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


class FakeClient:
    def write_taint_facts(self, facts):
        return WriteResult(reachable=True, written=len(facts))


def test_scan_tool_writes_facts_when_client_present(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, FakeClient())
    assert out["clarion"]["reachable"] is True
    assert out["clarion"]["written"] >= 2


def test_scan_tool_omits_clarion_block_when_no_client(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None)
    assert out["clarion"] is None
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/clarion/test_write.py tests/unit/mcp/test_server_clarion_write.py -v`
Expected: PASS (5 passed).

- [ ] **Step 9: Run the full suite to confirm no SP8 regression**

Run: `.venv/bin/pytest -q`
Expected: PASS (all green; the existing MCP/scan/explain tests must be unchanged).

- [ ] **Step 10: Commit**

```bash
git add src/wardline/clarion/write.py src/wardline/cli/scan.py src/wardline/cli/mcp.py src/wardline/mcp/server.py tests/unit/clarion/test_write.py tests/unit/mcp/test_server_clarion_write.py
git commit -m "feat(sp9): fail-soft scan-time taint-fact write (CLI --clarion-url + MCP scan)"
```

---

## Task 8: Clarion-backed read path + freshness gate (`explain_finding` + MCP `explain_taint`)

**Files:**
- Modify: `src/wardline/core/explain.py` (Clarion-backed mode + freshness gate)
- Modify: `src/wardline/mcp/server.py` (`_explain_taint` passes the client)
- Test: `tests/unit/core/test_explain_clarion.py`

The standalone behavior is the regression oracle: with no client, `explain_finding` is byte-identical to SP8. With a client AND a caller-supplied `sink_qualname` (the MCP loop just ran `scan`, so it has it), the store is consulted FIRST — a fresh fact is served from the blob with **no re-analysis**; every other outcome (miss, stale, `exists:false`, missing hash, soft outage) falls back to the SP8 re-run. When no `sink_qualname` is supplied (a `(path,line)`/fingerprint-only query), there is no pre-scan qualname to key the store on, so it takes the SP8 re-run and consults the store afterward for freshness — the fast no-scan win is the `sink_qualname` path.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_explain_clarion.py
from pathlib import Path

import blake3

from wardline.clarion.client import TaintFactView
from wardline.core.explain import explain_finding

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _proj(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


class SpyClient:
    """Returns queued batch_get views; records whether it was consulted."""

    def __init__(self, views):
        self._views = views
        self.batch_get_calls = 0

    def batch_get(self, qualnames):
        self.batch_get_calls += 1
        return self._views


def _fresh_blob(proj, qualname):
    h = blake3.blake3((proj / "svc.py").read_bytes()).hexdigest()
    return {
        "schema_version": "wardline-taint-1",
        "qualname": qualname,
        "content_hash_at_compute": h,
        "taint": {"declared_return": "INTEGRAL", "actual_return": "EXTERNAL_RAW",
                  "source": "anchored", "contributing_callee_qualname": "svc.read_raw",
                  "resolved_call_count": 1, "unresolved_call_count": 0},
        "findings": [],
    }, h


def test_fresh_fact_is_served_without_reanalysis(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    blob, h = _fresh_blob(proj, "svc.leaky")  # in-blob stamp == the file's live blake3
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob,
                         current_content_hash=h)  # Clarion's live hash == the stamp → FRESH
    client = SpyClient([view])

    # Spy on run_scan to PROVE a fresh hit (with a known sink_qualname) never re-analyzes.
    import wardline.core.explain as explain_mod
    calls = {"n": 0}
    real = explain_mod.run_scan

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(explain_mod, "run_scan", counting)

    # The MCP loop passes path/line/fingerprint AND sink_qualname; the fast path keys
    # on sink_qualname and short-circuits BEFORE any _explain_local scan.
    exp = explain_finding(proj, path="svc.py", line=7, clarion=client, sink_qualname="svc.leaky")
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"
    assert exp.tier_in == "EXTERNAL_RAW"
    assert exp.immediate_tainted_callee == "read_raw"  # bare leaf of the resolved callee qualname
    assert calls["n"] == 0          # served from the store: NO re-analysis
    assert client.batch_get_calls == 1


def test_stale_hash_falls_back_to_reanalysis(tmp_path):
    proj = _proj(tmp_path)
    blob, h = _fresh_blob(proj, "svc.leaky")
    blob["content_hash_at_compute"] = "0" * 64   # the stamp Wardline wrote is now wrong
    # Clarion returns the file's REAL live hash; stamp != live hash → STALE → re-run.
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob,
                         current_content_hash=h)
    # path/line let the fallback re-run locate the finding (the realistic MCP call).
    exp = explain_finding(proj, path="svc.py", line=7, clarion=SpyClient([view]),
                          sink_qualname="svc.leaky")
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"  # correct because it fell back to a real re-run


def test_missing_current_hash_is_stale(tmp_path):
    proj = _proj(tmp_path)
    blob, h = _fresh_blob(proj, "svc.leaky")
    # file deleted/unreadable at Clarion request time → current_content_hash absent (None)
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob,
                         current_content_hash=None)
    exp = explain_finding(proj, path="svc.py", line=7, clarion=SpyClient([view]),
                          sink_qualname="svc.leaky")
    assert exp is not None  # re-run fallback


def test_exists_false_falls_back(tmp_path):
    proj = _proj(tmp_path)
    view = TaintFactView(qualname="svc.leaky", exists=False)
    exp = explain_finding(proj, path="svc.py", line=7, clarion=SpyClient([view]),
                          sink_qualname="svc.leaky")
    assert exp is not None  # re-run fallback


def test_no_client_is_identical_to_sp8(tmp_path):
    proj = _proj(tmp_path)
    a = explain_finding(proj, path="svc.py", line=7)
    b = explain_finding(proj, path="svc.py", line=7, clarion=None)
    assert a == b
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/unit/core/test_explain_clarion.py -v`
Expected: FAIL — `explain_finding() got an unexpected keyword argument 'clarion'`.

- [ ] **Step 3: Implement the Clarion-backed mode in `core/explain.py`**

Three changes: (1) rename the current body of `explain_finding` (validation + `run_scan` + `_match` + projection) to a private `_explain_local(...)` with the same parameters minus `clarion`/`sink_qualname`; (2) add the freshness helper + blob projector below; (3) add a new `explain_finding` wrapper that consults the store FIRST when both `clarion` and `sink_qualname` are supplied (so a fresh hit never scans), and otherwise delegates to `_explain_local` and uses the store only for a freshness upgrade.

```python
# src/wardline/core/explain.py  (additions — keep the existing imports + dataclass)
from typing import Any


def _is_fresh(view: Any) -> bool:
    """Fresh iff: exists, a live current_content_hash is present, and the in-blob
    content_hash_at_compute equals that live hash. Wardline decides freshness by
    comparing the stamp IT wrote against the hash Clarion read live; Clarion never
    asserts a verdict. Missing hash (file deleted/unreadable) or exists:false ⇒ stale."""
    if not view.exists or view.current_content_hash is None:
        return False
    blob = view.wardline_json or {}
    stamped = blob.get("content_hash_at_compute")
    return stamped is not None and stamped == view.current_content_hash


def _callee_leaf(callee_qualname: str | None) -> str | None:
    """The blob stores the resolved callee QUALNAME; SP8's immediate_tainted_callee is
    the bare trailing name. Project back for surface parity with the SP8 shape."""
    return None if callee_qualname is None else callee_qualname.rsplit(".", 1)[-1]


def _explanation_from_blob(view: Any) -> TaintExplanation:
    """Project a fresh stored blob into the SP8 TaintExplanation shape (no analysis).
    The store is entity-scoped, so per-finding location comes from the blob's findings[]
    when present (else blank/None — the entity is known, the specific finding is not)."""
    blob = view.wardline_json or {}
    taint = blob.get("taint", {})
    findings = blob.get("findings", [])
    first = findings[0] if findings else {}
    callee_q = taint.get("contributing_callee_qualname")
    return TaintExplanation(
        fingerprint=str(first.get("fingerprint", "")),
        rule_id=str(first.get("rule_id", "")),
        sink_qualname=blob.get("qualname"),
        path="",
        line=first.get("line_start"),
        tier_in=taint.get("actual_return"),
        tier_out=taint.get("declared_return"),
        immediate_tainted_callee=_callee_leaf(callee_q),
        source_boundary_qualname=callee_q,
        resolved_call_count=int(taint.get("resolved_call_count", 0) or 0),
        unresolved_call_count=int(taint.get("unresolved_call_count", 0) or 0),
    )


def explain_finding(
    root: Path,
    *,
    fingerprint: str | None = None,
    path: str | None = None,
    line: int | None = None,
    config_path: Path | None = None,
    confine_to_root: bool = False,
    clarion: Any | None = None,
    sink_qualname: str | None = None,
) -> TaintExplanation | None:
    """Explain ONE finding's taint. Standalone (clarion=None) ⇒ identical to SP8.

    Fast path: when `clarion` and `sink_qualname` are both given (the MCP loop just
    scanned, so it knows the sink's qualname), consult the store FIRST — a FRESH fact
    is served from the blob with NO re-analysis. On a miss/stale/outage, or when no
    `sink_qualname` is available, fall back to the SP8 re-run (`_explain_local`)."""
    if clarion is not None and sink_qualname is not None:
        views = clarion.batch_get([sink_qualname])
        if views and _is_fresh(views[0]):
            return _explanation_from_blob(views[0])
        # miss/stale/outage → fall through to the re-run
    return _explain_local(
        root, fingerprint=fingerprint, path=path, line=line,
        config_path=config_path, confine_to_root=confine_to_root,
    )
```

`_explain_local` keeps the existing argument-validation (`requires either fingerprint or (path, line)`) so a re-run path without a fingerprint/location still raises as before. The standalone `test_no_client_is_identical_to_sp8` passes because `clarion=None` skips the fast path entirely and delegates straight to `_explain_local`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/unit/core/test_explain_clarion.py -v`
Expected: PASS. The fresh-hit test passes `sink_qualname="svc.leaky"` and asserts `run_scan` was not called; stale/absent/missing-hash and no-client tests exercise the fallback.

- [ ] **Step 5: Wire the MCP `explain_taint` tool**

In `mcp/server.py`, update `_explain_taint` to accept and use the client + server root, and pass the sink qualname when the caller provides it:

```python
def _explain_taint(args, root, clarion=None, server_root=None):
    match_path = args.get("path") if args.get("line") is not None else None
    if match_path is not None:
        _resolve_under_root(root, match_path)
    exp = explain_finding(
        root,
        fingerprint=args.get("fingerprint"),
        path=match_path,
        line=args.get("line"),
        config_path=_cfg(args, root),
        confine_to_root=True,
        clarion=clarion,
        sink_qualname=args.get("sink_qualname"),
    )
    if exp is None:
        raise ToolError(
            "fingerprint not in current scan; your code changed since the scan that "
            "produced it — re-scan.",
        )
    result_dict = {
        "fingerprint": exp.fingerprint,
        "rule_id": exp.rule_id,
        "sink_qualname": exp.sink_qualname,
        "location": {"path": exp.path, "line": exp.line},
        "tier_in": exp.tier_in,
        "tier_out": exp.tier_out,
        "immediate_tainted_callee": exp.immediate_tainted_callee,
        "source_boundary_qualname": exp.source_boundary_qualname,
        "resolved_call_count": exp.resolved_call_count,
        "unresolved_call_count": exp.unresolved_call_count,
    }
    return result_dict
```

Add `"sink_qualname": {"type": "string"}` to the `explain_taint` input schema properties (optional; lets a fresh store hit skip re-analysis). Task 9 inserts the `chain` block into `result_dict` immediately before `return result_dict`.

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (all green; SP8 explain tests unchanged because `clarion` defaults to None).

- [ ] **Step 7: Commit**

```bash
git add src/wardline/core/explain.py src/wardline/mcp/server.py tests/unit/core/test_explain_clarion.py
git commit -m "feat(sp9): Clarion-backed explain_taint read path + freshness gate (SP8 fallback)"
```

---

## Task 9: Full N-hop chain walk

**Files:**
- Modify: `src/wardline/core/explain.py` (add `explain_chain`)
- Modify: `src/wardline/mcp/server.py` (`explain_taint` gains `chain`/`max_hops`)
- Test: `tests/unit/core/test_explain_chain.py`

The chain walks `contributing_callee_qualname` from the sink to the originating boundary, `batch_get`ting each hop. It is entirely client-side; Clarion never parses the blob. A stale/absent/unresolvable hop truncates the chain with an explicit marker — never a silent stop.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_explain_chain.py
import blake3

from wardline.clarion.client import TaintFactView
from wardline.core.explain import explain_chain

# A 3-hop leaky chain: leaky -> mid -> read_raw (boundary leaf).
_CHAIN = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "def mid(p):\n    return read_raw(p)\n"
    "@trusted\ndef leaky(p):\n    return mid(p)\n"
)


def _proj(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_CHAIN, encoding="utf-8")
    return proj


def _fresh_view(proj, qualname, callee_qualname):
    h = blake3.blake3((proj / "svc.py").read_bytes()).hexdigest()
    blob = {
        "schema_version": "wardline-taint-1", "qualname": qualname,
        "content_hash_at_compute": h,
        "taint": {"declared_return": "INTEGRAL", "actual_return": "EXTERNAL_RAW",
                  "source": "anchored", "contributing_callee_qualname": callee_qualname,
                  "resolved_call_count": 1, "unresolved_call_count": 0},
        "findings": [],
    }
    return TaintFactView(qualname=qualname, exists=True, wardline_json=blob,
                         current_content_hash=h)


class MapClient:
    def __init__(self, by_qualname):
        self._by = by_qualname

    def batch_get(self, qualnames):
        return [self._by.get(q, TaintFactView(qualname=q, exists=False)) for q in qualnames]


def test_chain_walks_to_the_boundary(tmp_path):
    proj = _proj(tmp_path)
    client = MapClient({
        "svc.leaky": _fresh_view(proj, "svc.leaky", "svc.mid"),
        "svc.mid": _fresh_view(proj, "svc.mid", "svc.read_raw"),
        "svc.read_raw": _fresh_view(proj, "svc.read_raw", None),  # boundary leaf
    })
    chain = explain_chain(proj, sink_qualname="svc.leaky", clarion=client, max_hops=10)
    assert [hop.qualname for hop in chain.hops] == ["svc.leaky", "svc.mid", "svc.read_raw"]
    assert chain.truncated_at is None  # reached the leaf cleanly


def test_chain_truncates_explicitly_on_stale_hop(tmp_path):
    proj = _proj(tmp_path)
    stale = _fresh_view(proj, "svc.mid", "svc.read_raw")
    stale.wardline_json["content_hash_at_compute"] = "0" * 64  # stamp != live hash
    client = MapClient({
        "svc.leaky": _fresh_view(proj, "svc.leaky", "svc.mid"),
        "svc.mid": stale,
    })
    chain = explain_chain(proj, sink_qualname="svc.leaky", clarion=client, max_hops=10)
    assert [hop.qualname for hop in chain.hops] == ["svc.leaky"]
    assert chain.truncated_at == "svc.mid"  # explicit, never a silent stop


def test_chain_respects_max_hops(tmp_path):
    proj = _proj(tmp_path)
    client = MapClient({
        "svc.leaky": _fresh_view(proj, "svc.leaky", "svc.mid"),
        "svc.mid": _fresh_view(proj, "svc.mid", "svc.read_raw"),
        "svc.read_raw": _fresh_view(proj, "svc.read_raw", None),
    })
    chain = explain_chain(proj, sink_qualname="svc.leaky", clarion=client, max_hops=2)
    assert len(chain.hops) == 2
    assert chain.truncated_at == "svc.read_raw"  # the unwalked next hop
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/unit/core/test_explain_chain.py -v`
Expected: FAIL — `ImportError: cannot import name 'explain_chain'`.

- [ ] **Step 3: Implement `explain_chain` in `core/explain.py`**

```python
@dataclass(frozen=True, slots=True)
class ChainHop:
    qualname: str
    tier_in: str | None
    tier_out: str | None
    contributing_callee_qualname: str | None


@dataclass(frozen=True, slots=True)
class TaintChain:
    hops: list[ChainHop]
    truncated_at: str | None  # the next qualname we could NOT walk (stale/absent/max_hops), or None


def explain_chain(
    root: Path,
    *,
    sink_qualname: str,
    clarion: Any,
    max_hops: int = 20,
    config_path: Path | None = None,
) -> TaintChain:
    """Walk contributing_callee_qualname from the sink to the boundary, batch_getting
    each hop's fresh fact. Truncate EXPLICITLY (never silently) on a stale/absent hop,
    an unresolvable callee, or max_hops. Entirely client-side; Clarion never parses."""
    hops: list[ChainHop] = []
    current: str | None = sink_qualname
    seen: set[str] = set()
    while current is not None:
        if len(hops) >= max_hops:
            return TaintChain(hops=hops, truncated_at=current)
        if current in seen:  # cycle guard
            return TaintChain(hops=hops, truncated_at=current)
        seen.add(current)
        views = clarion.batch_get([current])
        if not views:
            return TaintChain(hops=hops, truncated_at=current)  # soft outage
        view = views[0]
        if not _is_fresh(view):
            return TaintChain(hops=hops, truncated_at=current)  # stale/absent → explicit stop
        blob = view.wardline_json or {}
        taint = blob.get("taint", {})
        next_q = taint.get("contributing_callee_qualname")
        hops.append(ChainHop(
            qualname=current,
            tier_in=taint.get("actual_return"),
            tier_out=taint.get("declared_return"),
            contributing_callee_qualname=next_q,
        ))
        current = next_q  # None at the boundary leaf → clean finish
    return TaintChain(hops=hops, truncated_at=None)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/pytest tests/unit/core/test_explain_chain.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Wire the MCP `explain_taint` chain option**

In `mcp/server.py`, extend `_explain_taint`: when `args.get("chain")` is true and a client + `sink_qualname` are available, call `explain_chain` and add a `"chain"` block to the response:

```python
    if args.get("chain") and clarion is not None and exp is not None and exp.sink_qualname:
        from wardline.core.explain import explain_chain
        ch = explain_chain(root, sink_qualname=exp.sink_qualname, clarion=clarion,
                           max_hops=int(args.get("max_hops", 20)))
        result_dict["chain"] = {
            "hops": [{"qualname": h.qualname, "tier_in": h.tier_in, "tier_out": h.tier_out,
                      "contributing_callee_qualname": h.contributing_callee_qualname}
                     for h in ch.hops],
            "truncated_at": ch.truncated_at,
        }
```

Add `"chain": {"type": "boolean"}` and `"max_hops": {"type": "integer"}` to the `explain_taint` input schema, and note in the tool description that `chain` needs a configured Clarion store (it degrades to a single hop without one).

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (all green).

- [ ] **Step 7: Commit**

```bash
git add src/wardline/core/explain.py src/wardline/mcp/server.py tests/unit/core/test_explain_chain.py
git commit -m "feat(sp9): full N-hop taint chain walk over the Clarion store (explicit truncation)"
```

---

## Task 10: Live `clarion_e2e` round-trip

**Files:**
- Create: `tests/e2e/test_clarion_live.py`
- Test: itself (marked `clarion_e2e`, deselected by default)

This is the SP4 lesson: a wire contract needs one real round-trip that hermetic fakes can't give. It runs a real `clarion serve` with the write path enabled over a tmp project, real HMAC, real blake3, and asserts scan→write→explain→query.

- [ ] **Step 1: Write the test**

```python
# tests/e2e/test_clarion_live.py
"""SP9 live round-trip against a real `clarion serve`. Deselected by default
(marker `clarion_e2e`); run with: .venv/bin/pytest -m clarion_e2e -v
Requires a `clarion` binary on PATH with the HTTP read API + wardline write path.
"""

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.clarion_e2e

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def clarion_server(tmp_path, monkeypatch):
    if shutil.which("clarion") is None:
        pytest.skip("clarion binary not on PATH")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    # 1) analyze the project so Clarion has entities to resolve against
    subprocess.run(["clarion", "analyze", str(proj)], check=True, cwd=proj)
    # 2) write a clarion.yaml enabling the HTTP API + the wardline write path + HMAC
    port = _free_port()
    secret = "e2e-shared-secret"
    (proj / "clarion.yaml").write_text(
        "serve:\n  http:\n    enabled: true\n"
        f"    bind: 127.0.0.1:{port}\n"
        "    identity_token_env: CLARION_LOOM_IDENTITY_SECRET\n"
        "    wardline_taint_write: true\n",
        encoding="utf-8",
    )
    env = {**os.environ, "CLARION_LOOM_IDENTITY_SECRET": secret}
    proc = subprocess.Popen(["clarion", "serve"], cwd=proj, env=env)
    # wait for the port
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        proc.terminate()
        pytest.fail("clarion serve did not come up")
    monkeypatch.setenv("WARDLINE_CLARION_TOKEN", secret)
    yield proj, f"http://127.0.0.1:{port}"
    proc.terminate()
    proc.wait(timeout=5)


def test_scan_write_then_explain_query_round_trip(clarion_server):
    proj, url = clarion_server
    from wardline.clarion.client import ClarionClient
    from wardline.clarion.config import load_clarion_token, resolve_project_name
    from wardline.clarion.write import write_facts_to_clarion
    from wardline.core.explain import explain_finding
    from wardline.core.run import run_scan

    client = ClarionClient(url, secret=load_clarion_token(proj),
                           project=resolve_project_name(proj))

    # write
    result = run_scan(proj)
    wr = write_facts_to_clarion(result, proj, client)
    assert wr.reachable is True
    assert wr.written >= 2  # both entities resolve + persist

    # query back: a FRESH fact is served from the store (real HMAC + real blake3 match)
    exp = explain_finding(proj, path="svc.py", line=7, clarion=client, sink_qualname="svc.leaky")
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"
    assert exp.tier_in == "EXTERNAL_RAW"
```

- [ ] **Step 2: Run the e2e test (only if a clarion binary is available)**

Run: `.venv/bin/pytest -m clarion_e2e tests/e2e/test_clarion_live.py -v`
Expected: PASS, or SKIP with "clarion binary not on PATH". If it FAILS with an HMAC 401, the canonicalization has drifted — re-read `~/clarion/crates/clarion-cli/src/http_read.rs` and reconcile `clarion/_hmac.py`. **This is the test that catches a real wire drift; do not weaken it.**

- [ ] **Step 3: Confirm it is deselected by default**

Run: `.venv/bin/pytest -q tests/e2e/test_clarion_live.py`
Expected: `no tests ran` / deselected (the default `addopts` excludes `clarion_e2e`).

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/test_clarion_live.py
git commit -m "test(sp9): live clarion_e2e scan->write->explain round-trip (deselected by default)"
```

---

## Task 11: Documentation

**Files:**
- Modify: `docs/agents.md` (note the Clarion-backed `explain_taint` mode + `chain`)
- Create: `docs/guides/clarion-taint-store.md` (a Loom-integration guide)
- Modify: `mkdocs.yml` (add the new guide to the nav)
- Modify: `CHANGELOG.md` (Unreleased)
- Test: docs build `--strict`

- [ ] **Step 1: Write the integration guide**

Create `docs/guides/clarion-taint-store.md` covering: what it does (persistent taint store, explain becomes a query, full chain), the opt-in (`pip install 'wardline[clarion]'`, `--clarion-url`, `WARDLINE_CLARION_TOKEN` from env/`.env`), the fail-soft guarantee (Clarion absent/disabled/stale → SP8 re-run; never load-bearing), the never-serve-stale freshness gate (blake3 whole-file compare), and the project guard. Keep it consistent with `docs/agents.md`'s MCP section. Do NOT document the HMAC internals (that is `clarion/_hmac.py`'s job); document the operator-facing config only.

- [ ] **Step 2: Add the `chain` note to `docs/agents.md`**

In the MCP `explain_taint` description, add a sentence: a configured Clarion store turns `explain_taint` into a query and enables `chain: true` to walk the full taint chain to the originating boundary; without a store it returns the single-hop SP8 explanation.

- [ ] **Step 3: Add the guide to `mkdocs.yml` nav and a CHANGELOG entry**

Add `clarion-taint-store.md` under the Guides section of `mkdocs.yml`. Add to `CHANGELOG.md` under `[Unreleased]`:

```markdown
### Added
- SP9: opt-in Clarion-backed persistent taint store (`wardline[clarion]` extra).
  `wardline scan --clarion-url` persists per-entity taint facts; `explain_taint`
  queries them with a never-serve-stale freshness gate and falls back to a local
  re-scan; the MCP `explain_taint` tool gains `chain: true` for the full N-hop
  taint chain. Base package stays zero-dependency; HMAC auth is stdlib.
```

- [ ] **Step 4: Build the docs strictly**

Run: `.venv/bin/mkdocs build --strict`
Expected: build succeeds with no warnings (the `docs` extra must be installed: `.venv/bin/pip install 'wardline[docs]'`).

- [ ] **Step 5: Commit**

```bash
git add docs/agents.md docs/guides/clarion-taint-store.md mkdocs.yml CHANGELOG.md
git commit -m "docs(sp9): Clarion taint-store integration guide + explain_taint chain note"
```

---

## Final verification (after all tasks)

- [ ] **Run the full default suite:** `.venv/bin/pytest -q` → all green; SP8 behavior unchanged (the standalone explain/scan tests are the oracle).
- [ ] **Run the type/lint gates the repo uses:** `.venv/bin/ruff check src tests` and `.venv/bin/mypy src` → clean.
- [ ] **Confirm zero-dependency base:** in a venv WITHOUT the `clarion` extra, `import wardline`, `wardline scan` (no `--clarion-url`), and `wardline mcp` all work, and `wardline scan --clarion-url …` fails loud with the "install `wardline[clarion]`" message (blake3 missing). 
- [ ] **Run the live round-trip once if a clarion binary is available:** `.venv/bin/pytest -m clarion_e2e -v`.
- [ ] Dispatch the final whole-diff review (subagent-driven-development's final reviewer) before finishing the branch.
