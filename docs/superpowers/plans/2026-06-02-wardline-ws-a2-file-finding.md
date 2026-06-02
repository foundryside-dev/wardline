# Workstream A2 — `file_finding` (one finding → a reconciling Filigree issue) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

> **STATUS — DRAFT, EXECUTION GATED ON FILIGREE.** The Wardline side below is fully
> specified and unit-testable now (fake transport, mirroring `FiligreeEmitter`). But
> `file_finding` cannot function end-to-end until Filigree ships the two changes in
> §1 — Wardline talks to Filigree only over HTTP-via-urllib, and the surface it needs
> does not exist yet. Treat §1 as the precondition; the contract in §1 may adjust to
> Filigree's final shape, in which case only `core/filigree_issue.py`'s response parser
> and the live e2e change.

**Goal:** Give a senior agent one call to turn a single true-positive finding into a tracked Filigree issue (returning its id), with close-on-fixed / reopen-on-regress handled automatically on subsequent scans — keyed on Wardline's stable fingerprint.

**Architecture:** A new `core/filigree_issue.FiligreeIssueFiler` (injectable transport, fail-soft, stdlib-urllib — a sibling of `core/filigree_emit.FiligreeEmitter`) POSTs to Filigree's new promote-by-fingerprint route and returns `{issue_id, created}`. Exposed identically on MCP (`file_finding` tool) and CLI (`wardline file-finding`), both delegating to one `core/` function. Reconciliation is NOT a second loop: Wardline's existing bulk scan-results POST is flipped to `mark_unseen=True` so every scan moves findings through Filigree's unseen→reopen machinery, and Filigree's new finding→issue cascade (ask #2) propagates that to the filed issues.

**Tech Stack:** Python 3.12+, stdlib-only (urllib), `pytest`, `ruff`, `mypy`. No new deps.

**Source spec:** `docs/superpowers/specs/2026-06-02-wardline-frictionless-agent-surface-spec.md` §4 Workstream A2. Contract investigation: the 2026-06-02 Filigree-reconciliation report (findings cited inline below).

---

## 1. Filigree dependency — what we need (the asks)

Evidence (all `/home/john/filigree/...`): the scan-results intake `_upsert_finding` (`db_files.py:1126`) already reconciles **finding rows** by `(scan_source, fingerprint)` idempotently, auto-reopens on regress (`db_files.py:1290`), and gates close-on-fixed behind `mark_unseen=True` + a separate clean-stale sweep. The single-finding→issue primitive `promote_finding_to_issue` (`db_files.py:2025`) is idempotent but **MCP/CLI-only and `finding_id`-keyed — no HTTP route, no fingerprint lookup**. And **no finding-status transition touches the linked issue's status** (verified: the only `issues` triggers are FTS sync). So:

### Ask #1 — HTTP promote-by-fingerprint, idempotent, returns `issue_id`
A new Loom HTTP route Wardline can POST to:

```
POST /api/loom/findings/promote
Request:  {"scan_source": "wardline", "fingerprint": "<sha256>", "priority": "P2"?, "labels": ["..."]?}
Response 200: {"issue_id": "<id>", "created": true|false}
Response 404 (fingerprint not ingested for this scan_source): {"error": "...", "code": "NOT_FOUND"}
```
Internally: resolve `(scan_source, fingerprint)` → `finding_id`, then call the existing idempotent `promote_finding_to_issue`. *Why:* this IS the `file_finding` operation; the core logic already exists, it just needs a fingerprint→finding_id resolve and an HTTP wrapper. Without it, A2 is impossible over Wardline's transport.

### Ask #2 — finding→issue status cascade
When a fingerprint-linked finding transitions to `fixed` (via the unseen→clean-stale path), **close its linked issue**; when it regresses `fixed/unseen → open`, **reopen its linked issue** (respecting terminal `false_positive`/`acknowledged`). *Why:* this is literally A2's "close when fixed / reopen on regress." Today the finding row flips but the filed issue is frozen. This is the load-bearing behavioral gap.

> **CORRECTION (2026-06-02, post-delivery) — the close trigger moved to ask #3.** Filigree
> shipped ask #2 exactly as written: reopen-on-regress is wired into `process_scan_results`
> (immediate on re-scan), but **close** is reachable only from `clean_stale_findings` (an
> age-gated retention sweep), which Wardline never calls. So as-shipped a re-scan moves a
> fixed finding to `unseen_in_latest` but does **not** close the linked issue. Reopen works;
> close does not — A2's auto-close DoD is unmet by ask #2 alone. The fix (user-chosen
> 2026-06-02) is a **symmetric close cascade wired into ingest**, requested in
> `docs/superpowers/specs/2026-06-02-filigree-ask-close-cascade-on-ingest.md` (ask #3). It
> needs **no further Wardline change** — Wardline already sends `mark_unseen=True` on
> non-empty scans, which is its input. Until ask #3 lands, A2 ships `file_finding` +
> reopen-on-regress; close-on-fixed is gated on Filigree's clean-stale sweep (the CHANGELOG
> entry states this honestly).

### (Wardline-side precondition, ours not Filigree's) — send `mark_unseen=True`
Wardline's `build_scan_results_body` must set `mark_unseen=True` on full-project scans so absent fingerprints enter `unseen_in_latest` (the input to ask #2). Implemented as Task 5 below. Safe today: the param exists and defaults False (`dashboard_routes/files.py:125`).

> **Hand the standalone brief to whoever owns Filigree:** `docs/superpowers/specs/2026-06-02-filigree-ask-promote-by-fingerprint.md` — it packages asks #1/#2 as a paste-able prompt with the exact contract, the Filigree source to reuse, and acceptance criteria. Asks #1 and #2 are the gate. Until #1 lands, Tasks 1-4 below are buildable and unit-test green against a fake transport, but the live e2e (Task 5) is `skip`-gated; until #2 lands, reconcile is finding-level only (the filed issue won't auto-close).

---

## File structure (Wardline side)

| File | Responsibility | Change |
|---|---|---|
| `src/wardline/core/filigree_issue.py` | `FiligreeIssueFiler` + `file_finding` core fn (fail-soft urllib promote) | Create |
| `src/wardline/core/filigree_emit.py` | bulk emitter | Modify: `mark_unseen` in the body (Task 5) |
| `src/wardline/mcp/server.py` | MCP `file_finding` tool | Modify: register tool + handler + `_filigree_filer()` |
| `src/wardline/cli/file_finding.py` | `wardline file-finding` verb | Create |
| `src/wardline/cli/main.py` | command group | Modify: register |
| `tests/unit/core/test_filigree_issue.py` | filer unit tests (fake transport) | Create |
| `tests/unit/mcp/test_server_file_finding.py` | MCP tool tests | Create |
| `tests/unit/cli/test_file_finding_cmd.py` | CLI verb tests | Create |
| `tests/e2e/test_filigree_promote_live.py` | opt-in live promote round-trip | Create (skip-gated) |
| `CHANGELOG.md` | release notes | Modify |

---

### Task 1: `FiligreeIssueFiler` — fail-soft HTTP promote (fake-transport unit tests)

**Files:**
- Create: `src/wardline/core/filigree_issue.py`
- Test: `tests/unit/core/test_filigree_issue.py`

This mirrors `core/filigree_emit.py` exactly: a pure body builder + a `Transport` protocol + an injectable-transport filer, stdlib-only. The promote URL is derived from the configured Loom scan-results URL (both live under `/api/loom/`).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/core/test_filigree_issue.py`:

```python
"""WS-A2: FiligreeIssueFiler — fail-soft HTTP promote-by-fingerprint. Mirrors the
FiligreeEmitter test shape: an injectable transport, no live Filigree needed."""

import pytest

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_issue import (
    FileResult,
    FiligreeIssueFiler,
    Response,
    promote_url_from_loom,
)


class FakeTransport:
    def __init__(self, status, body):
        self._status, self._body = status, body
        self.last = None

    def post(self, url, body, headers):
        import json

        self.last = {"url": url, "body": json.loads(body.decode()), "headers": dict(headers)}
        return Response(status=self._status, body=self._body)


def test_promote_url_derived_from_scan_results_url():
    assert (
        promote_url_from_loom("http://h:8628/api/loom/scan-results")
        == "http://h:8628/api/loom/findings/promote"
    )


def test_promote_url_rejects_non_loom_url():
    with pytest.raises(FiligreeEmitError, match="/api/loom/"):
        promote_url_from_loom("http://h/api/something/else")


def test_file_returns_issue_id_on_200():
    t = FakeTransport(200, '{"issue_id": "wardline-abc", "created": true}')
    filer = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=t)
    res = filer.file("fp123", priority="P2")
    assert res == FileResult(reachable=True, issue_id="wardline-abc", created=True)
    # The request carried the fingerprint + scan_source to the promote route.
    assert t.last["url"].endswith("/api/loom/findings/promote")
    assert t.last["body"] == {"scan_source": "wardline", "fingerprint": "fp123", "priority": "P2"}


def test_file_already_linked_created_false():
    t = FakeTransport(200, '{"issue_id": "wardline-abc", "created": false}')
    res = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=t).file("fp123")
    assert res.reachable and res.issue_id == "wardline-abc" and res.created is False


def test_file_404_unknown_fingerprint_is_reachable_not_found():
    t = FakeTransport(404, '{"error": "no finding", "code": "NOT_FOUND"}')
    res = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=t).file("missing")
    assert res.reachable is True and res.issue_id is None and res.not_found is True


def test_file_unreachable_is_soft():
    import urllib.error

    class Down:
        def post(self, url, body, headers):
            raise urllib.error.URLError("refused")

    res = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=Down()).file("fp")
    assert res.reachable is False and res.issue_id is None


def test_file_5xx_is_soft():
    res = FiligreeIssueFiler("http://h/api/loom/scan-results", transport=FakeTransport(503, "")).file("fp")
    assert res.reachable is False


def test_file_4xx_other_than_404_is_loud():
    # A 400 means Wardline sent a bad payload — loud, like the emitter's 4xx.
    t = FakeTransport(400, "bad request")
    with pytest.raises(FiligreeEmitError):
        FiligreeIssueFiler("http://h/api/loom/scan-results", transport=t).file("fp")
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/core/test_filigree_issue.py -v`
Expected: FAIL — `ModuleNotFoundError: wardline.core.filigree_issue`.

- [ ] **Step 3: Implement the filer**

Create `src/wardline/core/filigree_issue.py`:

```python
# src/wardline/core/filigree_issue.py
"""WS-A2: file ONE finding (by fingerprint) into a tracked Filigree issue, fail-soft.

Sibling of core/filigree_emit.py: same injectable-transport, same fail-soft charter
(sibling-absent / 5xx warn-and-continue; a 4xx other than 404 is a Wardline-bad-payload
bug and is loud). Talks the Loom HTTP promote-by-fingerprint route; imports no Filigree
package. A 404 means the fingerprint was never ingested for this scan_source (the agent
should emit findings to Filigree first) — surfaced as `not_found`, not an exception."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from wardline.core.errors import FiligreeEmitError

_ALLOWED_SCHEMES = ("http", "https")
_LOOM_MARKER = "/api/loom/"


def promote_url_from_loom(loom_url: str) -> str:
    """Derive the promote route from the configured Loom scan-results URL — both
    live under /api/loom/. Reject a URL that isn't a Loom endpoint (a clear config
    error rather than a 404 against a wrong host)."""
    idx = loom_url.find(_LOOM_MARKER)
    if idx == -1:
        raise FiligreeEmitError(f"filigree URL must be a Loom endpoint containing {_LOOM_MARKER!r}: {loom_url!r}")
    base = loom_url[: idx + len(_LOOM_MARKER)]
    return base + "findings/promote"


def build_promote_body(
    *, fingerprint: str, scan_source: str = "wardline", priority: str | None = None, labels: Sequence[str] | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {"scan_source": scan_source, "fingerprint": fingerprint}
    if priority is not None:
        body["priority"] = priority
    if labels:
        body["labels"] = list(labels)
    return body


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: str


@dataclass(frozen=True, slots=True)
class FileResult:
    reachable: bool
    issue_id: str | None = None
    created: bool = False
    not_found: bool = False  # reachable, but the fingerprint isn't known to Filigree
    disabled_reason: str | None = None


class Transport(Protocol):
    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response: ...


class UrllibTransport:
    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise FiligreeEmitError(f"filigree URL must use http or https; got scheme {scheme!r} in {url!r}")
        request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:  # noqa: S310
                return Response(status=resp.status, body=resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            with exc:
                return Response(status=exc.code, body=exc.read().decode("utf-8", "replace"))


class FiligreeIssueFiler:
    """POST a single fingerprint to the Loom promote route; return the issue id."""

    def __init__(self, loom_url: str, *, transport: Transport | None = None) -> None:
        self._url = promote_url_from_loom(loom_url)
        self._transport: Transport = transport if transport is not None else UrllibTransport()

    def file(
        self, fingerprint: str, *, scan_source: str = "wardline", priority: str | None = None,
        labels: Sequence[str] | None = None,
    ) -> FileResult:
        body = json.dumps(
            build_promote_body(fingerprint=fingerprint, scan_source=scan_source, priority=priority, labels=labels)
        ).encode("utf-8")
        try:
            resp = self._transport.post(self._url, body, {"Content-Type": "application/json"})
        except (urllib.error.URLError, OSError):
            return FileResult(reachable=False, disabled_reason="filigree unreachable")
        if resp.status >= 500:
            return FileResult(reachable=False, disabled_reason=f"filigree {resp.status}")
        if resp.status == 404:
            return FileResult(reachable=True, not_found=True)
        if not 200 <= resp.status < 300:
            raise FiligreeEmitError(f"Filigree rejected promote ({resp.status}) at {self._url}: {resp.body}")
        try:
            payload = json.loads(resp.body) if resp.body else {}
        except json.JSONDecodeError:
            payload = {}
        issue_id = payload.get("issue_id") if isinstance(payload, dict) else None
        created = bool(payload.get("created")) if isinstance(payload, dict) else False
        return FileResult(reachable=True, issue_id=issue_id, created=created)
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/core/test_filigree_issue.py -v`
Expected: PASS (8 passed).

- [ ] **Step 5: Commit (controller)**

---

### Task 2: MCP `file_finding` tool

**Files:**
- Modify: `src/wardline/mcp/server.py`
- Test: `tests/unit/mcp/test_server_file_finding.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/mcp/test_server_file_finding.py`:

```python
"""WS-A2: MCP file_finding tool — fail-soft, returns the issue id."""

import pytest

from wardline.core.filigree_issue import FileResult
from wardline.mcp.server import ToolError, WardlineMCPServer, _file_finding


class FakeFiler:
    def __init__(self, result):
        self._result = result
        self.seen = None

    def file(self, fingerprint, *, scan_source="wardline", priority=None, labels=None):
        self.seen = {"fingerprint": fingerprint, "priority": priority, "labels": labels}
        return self._result


def test_file_finding_returns_issue_id(tmp_path):
    out = _file_finding({"fingerprint": "fp1", "priority": "P2"}, tmp_path,
                        FakeFiler(FileResult(reachable=True, issue_id="wardline-abc", created=True)))
    assert out == {"reachable": True, "issue_id": "wardline-abc", "created": True,
                   "not_found": False, "fingerprint": "fp1", "disabled_reason": None}


def test_file_finding_requires_fingerprint(tmp_path):
    with pytest.raises(ToolError, match="fingerprint is required"):
        _file_finding({}, tmp_path, FakeFiler(FileResult(reachable=True)))


def test_file_finding_no_filer_is_toolerror(tmp_path):
    # No Filigree URL configured -> agent-actionable.
    with pytest.raises(ToolError, match="no Filigree URL"):
        _file_finding({"fingerprint": "fp1"}, tmp_path, None)


def test_file_finding_not_found_surfaces(tmp_path):
    out = _file_finding({"fingerprint": "ghost"}, tmp_path, FakeFiler(FileResult(reachable=True, not_found=True)))
    assert out["not_found"] is True and out["issue_id"] is None


def test_server_filer_none_without_url(tmp_path):
    assert WardlineMCPServer(root=tmp_path)._filigree_filer() is None


def test_server_filer_built_with_url(tmp_path):
    from wardline.core.filigree_issue import FiligreeIssueFiler

    srv = WardlineMCPServer(root=tmp_path, filigree_url="http://h/api/loom/scan-results")
    assert isinstance(srv._filigree_filer(), FiligreeIssueFiler)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/mcp/test_server_file_finding.py -v`
Expected: FAIL — `_file_finding` / `_filigree_filer` don't exist.

- [ ] **Step 3: Implement `_file_finding` + `_filigree_filer` + register the tool**

In `src/wardline/mcp/server.py`:

Add the handler function (near `_emit_filigree`):

```python
def _file_finding(args: dict[str, Any], root: Path, filer: Any) -> dict[str, Any]:
    """File ONE finding (by fingerprint) into a tracked Filigree issue, returning its
    id. Fail-soft on reachability; a 404 (unknown fingerprint) surfaces as not_found."""
    if filer is None:
        raise ToolError("no Filigree URL configured; launch `wardline mcp --filigree-url ...`")
    fp = _require(args, "fingerprint")
    labels = args.get("labels")
    res = filer.file(fp, priority=args.get("priority"), labels=labels)
    return {
        "reachable": res.reachable,
        "issue_id": res.issue_id,
        "created": res.created,
        "not_found": res.not_found,
        "fingerprint": fp,
        "disabled_reason": res.disabled_reason,
    }
```

Add the builder method (after `_filigree_emitter`):

```python
    def _filigree_filer(self) -> Any:
        """Build a FiligreeIssueFiler from this server's Loom URL, or None when unset."""
        if self.filigree_url is None:
            return None
        from wardline.core.filigree_issue import FiligreeIssueFiler

        return FiligreeIssueFiler(self.filigree_url)
```

Register the tool in `_register_tools`:

```python
        self.add_tool(
            Tool(
                name="file_finding",
                description="File ONE finding (by `fingerprint`) into a tracked Filigree issue and "
                "return its `issue_id`. Idempotent (re-filing returns the same issue). Emit findings "
                "to Filigree first (scan with a configured Filigree URL) so the fingerprint is known; "
                "a `not_found: true` result means it isn't. Reconciliation (close-on-fixed / "
                "reopen-on-regress) happens automatically on later scans. Fail-soft.",
                input_schema={
                    "type": "object",
                    "required": ["fingerprint"],
                    "properties": {
                        "fingerprint": {"type": "string"},
                        "priority": {"type": "string", "description": "Filigree priority, e.g. P2"},
                        "labels": {"type": "array", "items": {"type": "string"}},
                    },
                },
                handler=lambda args, root: _file_finding(args, root, self._filigree_filer()),
            )
        )
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/mcp/test_server_file_finding.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit (controller)**

---

### Task 3: CLI `wardline file-finding` verb (parity)

**Files:**
- Create: `src/wardline/cli/file_finding.py`
- Modify: `src/wardline/cli/main.py`
- Test: `tests/unit/cli/test_file_finding_cmd.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/cli/test_file_finding_cmd.py`:

```python
"""WS-A2 CLI parity: `wardline file-finding <fp>` over an injected filer."""

import json

from click.testing import CliRunner

from wardline.core.filigree_issue import FileResult


def test_file_finding_prints_issue_id(tmp_path, monkeypatch):
    from wardline.cli import file_finding as mod

    class FakeFiler:
        def __init__(self, url, **kw):
            pass

        def file(self, fingerprint, *, scan_source="wardline", priority=None, labels=None):
            return FileResult(reachable=True, issue_id="wardline-xyz", created=True)

    monkeypatch.setattr(mod, "FiligreeIssueFiler", FakeFiler)
    monkeypatch.setattr(mod, "resolve_filigree_url", lambda flag, root, cfg: "http://h/api/loom/scan-results")
    res = CliRunner().invoke(mod.file_finding, ["fp1", str(tmp_path)])
    assert res.exit_code == 0
    assert json.loads(res.output)["issue_id"] == "wardline-xyz"


def test_file_finding_no_url_exits_2(tmp_path, monkeypatch):
    from wardline.cli import file_finding as mod

    monkeypatch.setattr(mod, "resolve_filigree_url", lambda flag, root, cfg: None)
    res = CliRunner().invoke(mod.file_finding, ["fp1", str(tmp_path)])
    assert res.exit_code == 2
    assert "Filigree URL" in res.output
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/cli/test_file_finding_cmd.py -v`
Expected: FAIL — module/command does not exist.

- [ ] **Step 3: Implement the command**

Create `src/wardline/cli/file_finding.py`:

```python
# src/wardline/cli/file_finding.py
"""`wardline file-finding` — file ONE finding (by fingerprint) into a Filigree issue.

CLI counterpart of the MCP `file_finding` tool; both go through FiligreeIssueFiler."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.config import resolve_filigree_url
from wardline.core.filigree_issue import FiligreeIssueFiler


@click.command(name="file-finding")
@click.argument("fingerprint", type=str)
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--filigree-url", "filigree_url", default=None, help="Filigree Loom URL (else env/wardline.yaml).")
@click.option("--priority", default=None, help="Filigree priority, e.g. P2.")
@click.option("--label", "labels", multiple=True, help="Label to attach (repeatable).")
def file_finding(
    fingerprint: str, path: Path, config_path: Path | None, filigree_url: str | None,
    priority: str | None, labels: tuple[str, ...],
) -> None:
    """File the finding identified by FINGERPRINT into a tracked Filigree issue."""
    url = resolve_filigree_url(filigree_url, path, config_path)
    if url is None:
        click.echo("error: no Filigree URL (pass --filigree-url, set the env var, or wardline.yaml)", err=True)
        raise SystemExit(2)
    res = FiligreeIssueFiler(url).file(fingerprint, priority=priority, labels=list(labels) or None)
    click.echo(json.dumps({
        "reachable": res.reachable, "issue_id": res.issue_id, "created": res.created,
        "not_found": res.not_found, "fingerprint": fingerprint, "disabled_reason": res.disabled_reason,
    }))
    if not res.reachable:
        raise SystemExit(1)  # sibling absent — soft, but non-zero so a script notices
```

- [ ] **Step 4: Register the command**

In `src/wardline/cli/main.py`, add (mirroring `scan`):

```python
from wardline.cli.file_finding import file_finding
```
```python
cli.add_command(file_finding)
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/cli/test_file_finding_cmd.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit (controller)**

---

### Task 4: `mark_unseen=True` on the bulk scan-results emission (activates close-on-fixed)

**Files:**
- Modify: `src/wardline/core/filigree_emit.py` (`build_scan_results_body`)
- Test: `tests/unit/core/test_filigree_emit.py` (add assertion)

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/core/test_filigree_emit.py` (create if absent):

```python
def test_scan_results_body_sets_mark_unseen():
    """Wardline opts into Filigree's absent-fingerprint sweep so close-on-fixed
    activates: a whole-project scan declares its findings list authoritative."""
    from wardline.core.filigree_emit import build_scan_results_body

    body = build_scan_results_body([])
    assert body["mark_unseen"] is True
    assert body["scan_source"] == "wardline"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/core/test_filigree_emit.py -k mark_unseen -v`
Expected: FAIL — `KeyError: 'mark_unseen'`.

- [ ] **Step 3: Implement**

In `src/wardline/core/filigree_emit.py`, change `build_scan_results_body`:

```python
def build_scan_results_body(findings: Sequence[Finding], *, scan_source: str = "wardline") -> dict[str, Any]:
    """Build the ``POST /api/loom/scan-results`` request body. Emits ALL finding kinds.
    ``mark_unseen=True`` opts into Filigree's absent-fingerprint sweep: a fingerprint
    present before but absent now enters ``unseen_in_latest`` (the input to issue
    close-on-fixed). A whole-project Wardline scan is authoritative over its findings."""
    return {
        "scan_source": scan_source,
        "mark_unseen": True,
        "findings": [_finding_to_wire(f) for f in findings],
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/core/test_filigree_emit.py -v`
Expected: PASS. (Note: this changes the emitted body; if a CLI/MCP emission test asserts the exact body, update it to include `mark_unseen`.)

- [ ] **Step 5: Commit (controller)**

---

### Task 5: Opt-in live promote round-trip (GATED on Filigree ask #1)

**Files:**
- Create: `tests/e2e/test_filigree_promote_live.py`

This mirrors the `clarion_e2e` opt-in pattern: marked, deselected by default, and `skip`-gated so it stays green until a Filigree with the promote route is reachable. Do NOT block the suite on it.

- [ ] **Step 1: Write the gated e2e**

Create `tests/e2e/test_filigree_promote_live.py`:

```python
"""WS-A2 live oracle (opt-in): scan->emit->file_finding against a real Filigree with
the /api/loom/findings/promote route. Skips cleanly until that route exists.

Run: WARDLINE_FILIGREE_URL=http://localhost:PORT/api/loom/scan-results \
     uv run pytest -m filigree_e2e
"""

import os

import pytest

pytestmark = pytest.mark.filigree_e2e

_URL = os.environ.get("WARDLINE_FILIGREE_URL")

_SRC = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _promote_route_live(url: str) -> bool:
    import urllib.error
    import urllib.request

    from wardline.core.filigree_issue import promote_url_from_loom

    req = urllib.request.Request(promote_url_from_loom(url), data=b"{}", method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)  # noqa: S310
        return True
    except urllib.error.HTTPError as exc:
        return exc.code != 404  # route exists if it answers anything but 404-not-routed
    except OSError:
        return False


@pytest.mark.skipif(not _URL, reason="set WARDLINE_FILIGREE_URL to run the live promote oracle")
def test_scan_emit_then_file_finding(tmp_path):
    if not _promote_route_live(_URL):
        pytest.skip("Filigree promote route /api/loom/findings/promote not available (ask #1 not shipped)")
    from wardline.core.filigree_emit import FiligreeEmitter
    from wardline.core.filigree_issue import FiligreeIssueFiler
    from wardline.core.run import run_scan

    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    result = run_scan(tmp_path)
    finding = next(f for f in result.findings if f.rule_id == "PY-WL-101")
    emit = FiligreeEmitter(_URL).emit(result.findings)
    assert emit.reachable
    res = FiligreeIssueFiler(_URL).file(finding.fingerprint, priority="P2")
    assert res.reachable and res.issue_id and not res.not_found
    # Idempotent: re-filing returns the same issue, created=False.
    again = FiligreeIssueFiler(_URL).file(finding.fingerprint)
    assert again.issue_id == res.issue_id and again.created is False
```

- [ ] **Step 2: Register the marker**

In `pyproject.toml`, add `filigree_e2e` to the `[tool.pytest.ini_options]` markers list and to the default `addopts` deselection (mirror how `clarion_e2e`/`network` are deselected by default). Confirm:

Run: `uv run pytest -m filigree_e2e -q`
Expected: the live test is collected and SKIPS (no `WARDLINE_FILIGREE_URL`), exit 0; and a default `uv run pytest` does NOT collect it.

- [ ] **Step 3: Commit (controller)**

---

### Task 6: Docs + full gate

- [ ] **Step 1: CHANGELOG** — under `[Unreleased] → ### Added`:

```markdown
- `file_finding` (MCP tool + `wardline file-finding` CLI): file ONE finding by fingerprint
  into a tracked Filigree issue, returning its id (idempotent, fail-soft). Scan emission now
  sets `mark_unseen=True` so close-on-fixed/reopen-on-regress reconcile on later scans.
  Requires Filigree's promote-by-fingerprint route + finding→issue cascade. (WS-A2)
```

- [ ] **Step 2: Full local gate** — all green:
- `uv run ruff check src tests && uv run ruff format --check src tests`
- `uv run mypy`
- `uv run pytest`
- `uv run wardline scan src/wardline --fail-on ERROR` (dogfood, exit 0)

- [ ] **Step 3: Commit (controller)**

---

## Self-review

**Spec coverage (§4 A2):** the deliverable — "a new tool/command keyed on the stable fingerprint: `file_finding(fingerprint, priority?, ...) -> {issue_id, status, created|already_linked, fingerprint}`; re-scan reconciles (close-on-fixed, reopen-on-regress)" — is built as the filer + MCP tool + CLI verb (Tasks 1-3), with reconcile activated via `mark_unseen=True` (Task 4) riding the existing bulk POST, exactly as the spec's design note prescribes ("the link lives in the reconciliation layer, NOT by mutating Finding" — honored: `Finding` is untouched). The spec's "preserve the finding/issue boundary" is honored — Wardline never imports Filigree, only POSTs.

**Gating is explicit, not hidden:** §1 states the two Filigree asks; Tasks 1-4 are unit-green now against a fake transport; Task 5's live oracle skips until ask #1 ships. This matches the repo's `clarion_e2e` opt-in discipline.

**Placeholder scan:** none — all Wardline code is complete. The only undefined surface is the Filigree route (§1), which is the declared external dependency, not a placeholder.

**Type consistency:** `FiligreeIssueFiler.file(...) -> FileResult` (Task 1) is consumed identically by `_file_finding` (Task 2) and the CLI verb (Task 3); `FileResult` fields (`reachable/issue_id/created/not_found/disabled_reason`) match across all three plus the e2e. `promote_url_from_loom` is shared by the filer and the e2e's liveness probe.

**Contract risk localized:** if Filigree's final shape differs from §1, only `filigree_issue.py`'s response parsing (the `payload.get("issue_id"/"created")` lines + the 404 handling) and the e2e change — the tool/CLI/test scaffolding is contract-agnostic.
