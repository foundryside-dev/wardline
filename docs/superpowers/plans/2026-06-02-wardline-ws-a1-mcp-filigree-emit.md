# Workstream A1 — MCP Filigree-Emit Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the MCP `scan` tool emit findings to Filigree when a Filigree URL is configured, at parity with the CLI — closing the asymmetry where finding→Filigree is CLI-only today.

**Architecture:** The Filigree URL already resolves in `cli/mcp.py` and reaches `WardlineMCPServer.__init__` as `self.filigree_url` (today consumed only by `_dossier`). We add a `_filigree_emitter()` builder (mirroring the existing `_clarion_client()`), thread it into the `_scan` handler (mirroring how the Clarion client is already threaded), and return a `filigree` block alongside the existing `clarion` block. Emission is **fail-soft on the MCP surface** — the deliberate asymmetry already established for Clarion (`server.py:91-95`): the CLI is loud on a `FiligreeEmitError` (4xx → exit 2), but the MCP scan must survive an optional-write failure and report it in the block, never discard the scan payload.

**Tech Stack:** Python 3.12+, stdlib-only (`urllib` transport via the existing `FiligreeEmitter`), `pytest`, `ruff`, `mypy`. No new dependencies.

**Source spec:** `docs/superpowers/specs/2026-06-02-wardline-frictionless-agent-surface-spec.md` §4 Workstream A1.

**Out of scope (deferred):** A2 (`file_finding` — one finding → a reconciling Filigree issue) is a separate plan pending a Filigree-reconciliation contract design pass. This plan is the bulk-emission parity only.

---

## File structure

| File | Responsibility | Change |
|---|---|---|
| `src/wardline/mcp/server.py` | MCP tool handlers + server wiring | Modify: add `_emit_filigree` helper, extend `_scan` signature + return, add `_filigree_emitter()` method, thread it into the scan handler, update the scan tool description |
| `src/wardline/cli/mcp.py` | `wardline mcp` launcher | Modify: correct the `--filigree-url` help text (scan now emits) |
| `tests/unit/mcp/test_server_filigree_emit.py` | `_scan` Filigree-block behavior (present / null / error-soft / unreachable-soft) | Create |
| `tests/unit/mcp/test_server_filigree_wiring.py` | server `_filigree_emitter()` builder + handler threading | Create |
| `tests/unit/core/test_cli_mcp_parity.py` | CLI↔MCP differential | Modify: add a Filigree-emission parity test |
| `CHANGELOG.md` | release notes | Modify: `[Unreleased]` entry |

Existing call sites of `_scan` (`tests/unit/core/test_cli_mcp_parity.py:36`, `tests/unit/mcp/test_server_clarion_write.py`) use the 2- and 3-arg forms; the new 4th parameter defaults to `None`, so they are unaffected.

---

### Task 1: `_scan` consumes an injected Filigree emitter and returns a fail-soft `filigree` block

**Files:**
- Modify: `src/wardline/mcp/server.py:71-119` (the `_scan` function)
- Test: `tests/unit/mcp/test_server_filigree_emit.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/mcp/test_server_filigree_emit.py`:

```python
"""WS-A1: MCP `scan` emits to Filigree when an emitter is injected, fail-soft.

Mirrors test_server_clarion_write.py: inject a duck-typed emitter into `_scan`
and assert on the `filigree` block. The MCP surface is fail-soft — a rejected
payload (FiligreeEmitError) or an unreachable sibling is REPORTED in the block,
never allowed to discard the scan payload (the deliberate asymmetry from the
Clarion block at server.py:91-95).
"""

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_emit import EmitResult
from wardline.mcp.server import _scan

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


class FakeEmitter:
    """Duck-typed FiligreeEmitter: records the findings it was handed, returns a
    canned EmitResult."""

    def __init__(self, result):
        self._result = result
        self.seen = None

    def emit(self, findings):
        self.seen = list(findings)
        return self._result


class RaisingEmitter:
    def emit(self, findings):
        raise FiligreeEmitError("Filigree rejected scan-results (400) at http://x: bad payload")


def test_scan_emits_to_filigree_when_emitter_present(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, FakeEmitter(EmitResult(reachable=True, created=2, updated=1)))
    assert out["filigree"]["reachable"] is True
    assert out["filigree"]["created"] == 2
    assert out["filigree"]["updated"] == 1
    assert out["filigree"]["failed"] == 0


def test_scan_filigree_block_null_when_no_emitter(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, None)
    assert out["filigree"] is None


def test_scan_survives_filigree_emit_error(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, RaisingEmitter())
    assert out["filigree"]["reachable"] is False
    assert out["filigree"]["warnings"]  # carries the rejection text
    # The scan payload is intact, NOT discarded — assert keys _scan always returns.
    assert "summary" in out and "findings" in out and "gate" in out
    assert out["summary"]["total"] >= 1  # PY-WL-101 fires on _LEAKY


def test_scan_unreachable_filigree_is_soft(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, FakeEmitter(EmitResult(reachable=False)))
    assert out["filigree"]["reachable"] is False
    assert out["summary"]["total"] >= 1
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/mcp/test_server_filigree_emit.py -v`
Expected: FAIL — `_scan()` currently takes 3 positional args, so the 4-arg calls raise `TypeError: _scan() takes from 2 to 3 positional arguments but 4 were given`.

- [ ] **Step 3: Add the `_emit_filigree` helper**

In `src/wardline/mcp/server.py`, add this function immediately above `_scan` (after `_cfg`, around line 70):

```python
def _emit_filigree(findings: list[Finding], filigree: Any) -> dict[str, Any] | None:
    """Fail-soft Filigree emission for the MCP `scan`. Returns None when no emitter
    is injected (no URL). Mirrors the Clarion block's deliberate asymmetry: the CLI
    is LOUD on a FiligreeEmitError (4xx -> exit 2), but the MCP scan must SURVIVE an
    optional-write failure and report it, never discard the scan payload. An
    unreachable sibling / 5xx already returns a soft EmitResult(reachable=False)."""
    if filigree is None:
        return None
    from wardline.core.errors import FiligreeEmitError
    from wardline.core.filigree_emit import EmitResult

    try:
        er = filigree.emit(findings)
    except FiligreeEmitError as exc:
        er = EmitResult(reachable=False, warnings=(str(exc),))
    return {
        "reachable": er.reachable,
        "created": er.created,
        "updated": er.updated,
        "failed": er.failed,
        "warnings": list(er.warnings),
    }
```

- [ ] **Step 4: Extend `_scan` to take the emitter and return the block**

In `src/wardline/mcp/server.py`, change the `_scan` signature (line 71) from:

```python
def _scan(args: dict[str, Any], root: Path, clarion: Any = None) -> dict[str, Any]:
```

to:

```python
def _scan(args: dict[str, Any], root: Path, clarion: Any = None, filigree: Any = None) -> dict[str, Any]:
```

Then, in the same function, change the `return` dict (lines 102-119) from ending:

```python
    decision = gate_decision(result, threshold)
    return {
        "files_scanned": result.files_scanned,
        "findings": [_finding_to_dict(f) for f in result.findings],
        "summary": {
            "total": result.summary.total,
            "active": result.summary.active,
            "baselined": result.summary.baselined,
            "waived": result.summary.waived,
            "judged": result.summary.judged,
            "unanalyzed": result.summary.unanalyzed,
        },
        "gate": {"tripped": decision.tripped, "fail_on": decision.fail_on, "exit_class": decision.exit_class},
        "clarion": clarion_block,
    }
```

to:

```python
    decision = gate_decision(result, threshold)
    filigree_block = _emit_filigree(result.findings, filigree)
    return {
        "files_scanned": result.files_scanned,
        "findings": [_finding_to_dict(f) for f in result.findings],
        "summary": {
            "total": result.summary.total,
            "active": result.summary.active,
            "baselined": result.summary.baselined,
            "waived": result.summary.waived,
            "judged": result.summary.judged,
            "unanalyzed": result.summary.unanalyzed,
        },
        "gate": {"tripped": decision.tripped, "fail_on": decision.fail_on, "exit_class": decision.exit_class},
        "clarion": clarion_block,
        "filigree": filigree_block,
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/mcp/test_server_filigree_emit.py -v`
Expected: PASS (4 passed).

- [ ] **Step 6: Run the MCP test directory to catch any full-dict snapshot test**

Run: `uv run pytest tests/unit/mcp -q`
Expected: PASS. (The new `filigree` key is additive; existing tests assert on specific keys, not whole-dict equality. If any test fails on an unexpected key, that test is asserting whole-dict equality of a scan result — update it to include `"filigree": None`.)

- [ ] **Step 7: Commit**

```bash
git add src/wardline/mcp/server.py tests/unit/mcp/test_server_filigree_emit.py
git commit -m "feat(mcp): scan emits findings to Filigree, fail-soft (WS-A1)"
```

---

### Task 2: Server builds the emitter from its URL and threads it into the scan handler

**Files:**
- Modify: `src/wardline/mcp/server.py:287-317` (add `_filigree_emitter()`; update the scan handler lambda + tool description)
- Test: `tests/unit/mcp/test_server_filigree_wiring.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/mcp/test_server_filigree_wiring.py`:

```python
"""WS-A1: the server builds a FiligreeEmitter from its URL and threads it into
the scan handler — mirroring _clarion_client()."""

from wardline.core.filigree_emit import EmitResult, FiligreeEmitter
from wardline.mcp.server import WardlineMCPServer

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


class CapturingEmitter:
    def __init__(self):
        self.seen = None

    def emit(self, findings):
        self.seen = list(findings)
        return EmitResult(reachable=True, created=len(self.seen))


def test_filigree_emitter_none_without_url(tmp_path):
    srv = WardlineMCPServer(root=tmp_path)
    assert srv._filigree_emitter() is None


def test_filigree_emitter_built_with_url(tmp_path):
    srv = WardlineMCPServer(root=tmp_path, filigree_url="http://filigree.local/api/loom/scan-results")
    assert isinstance(srv._filigree_emitter(), FiligreeEmitter)


def test_scan_handler_threads_filigree_emitter(tmp_path, monkeypatch):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    srv = WardlineMCPServer(root=tmp_path, filigree_url="http://filigree.local/api")
    cap = CapturingEmitter()
    # The scan handler calls self._filigree_emitter() at call time, so patching the
    # bound method on the instance redirects it to our capturing fake.
    monkeypatch.setattr(srv, "_filigree_emitter", lambda: cap)
    out = srv._tools["scan"].handler({}, tmp_path)
    assert out["filigree"]["reachable"] is True
    assert cap.seen is not None and len(cap.seen) >= 1
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/mcp/test_server_filigree_wiring.py -v`
Expected: FAIL — `AttributeError: 'WardlineMCPServer' object has no attribute '_filigree_emitter'`.

- [ ] **Step 3: Add the `_filigree_emitter()` builder**

In `src/wardline/mcp/server.py`, add this method immediately after `_clarion_client` (after line 298):

```python
    def _filigree_emitter(self) -> Any:
        """Build a FiligreeEmitter for this server's URL, or None when no URL is set.
        Mirrors _clarion_client: the URL already resolves in cli/mcp.py and reaches
        __init__ as self.filigree_url."""
        if self.filigree_url is None:
            return None
        from wardline.core.filigree_emit import FiligreeEmitter

        return FiligreeEmitter(self.filigree_url)
```

- [ ] **Step 4: Thread the emitter into the scan handler and update the description**

In `src/wardline/mcp/server.py`, in `_register_tools`, change the `scan` tool's `description` (lines 304-306) and `handler` (line 315) from:

```python
                description="Whole-program taint scan of the project. Returns structured "
                "findings, the suppression summary (active = the gate population), "
                "and the gate verdict.",
```
```python
                handler=lambda args, root: _scan(args, root, self._clarion_client()),
```

to:

```python
                description="Whole-program taint scan of the project. Returns structured "
                "findings, the suppression summary (active = the gate population), "
                "and the gate verdict. When a Filigree URL is configured, also POSTs the "
                "findings to Filigree (fail-soft: an unreachable sibling or rejected payload "
                "is reported in the `filigree` block, never fails the scan).",
```
```python
                handler=lambda args, root: _scan(args, root, self._clarion_client(), self._filigree_emitter()),
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/mcp/test_server_filigree_wiring.py -v`
Expected: PASS (3 passed).

- [ ] **Step 6: Commit**

```bash
git add src/wardline/mcp/server.py tests/unit/mcp/test_server_filigree_wiring.py
git commit -m "feat(mcp): wire Filigree emitter into the scan handler (WS-A1)"
```

---

### Task 3: CLI↔MCP Filigree-emission parity test

**Files:**
- Modify: `tests/unit/core/test_cli_mcp_parity.py` (add one test)

- [ ] **Step 1: Write the failing (then-passing) parity test**

Append to `tests/unit/core/test_cli_mcp_parity.py`:

```python
def test_cli_and_mcp_emit_identical_filigree_body() -> None:
    """The Filigree emission set must be identical across surfaces. The CLI passes
    `result.findings` to FiligreeEmitter.emit (scan.py:83). The MCP scan must hand its
    injected emitter exactly the same finding set, so the POST body is byte-identical."""
    from wardline.core.filigree_emit import EmitResult, build_scan_results_body

    cli_findings = run_scan(_CORPUS).findings

    class _Capture:
        def __init__(self) -> None:
            self.seen: list = []

        def emit(self, findings):
            self.seen = list(findings)
            return EmitResult(reachable=True)

    cap = _Capture()
    _scan({}, root=_CORPUS, filigree=cap)

    # Byte-identical wire body is the real parity contract.
    assert build_scan_results_body(cap.seen) == build_scan_results_body(cli_findings)
```

- [ ] **Step 2: Run the test**

Run: `uv run pytest tests/unit/core/test_cli_mcp_parity.py -v`
Expected: PASS (both the pre-existing differential and the new emission-parity test).
If it FAILS because `_scan` does not yet accept `filigree=` — Tasks 1-2 must be merged first; this task depends on them.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/core/test_cli_mcp_parity.py
git commit -m "test(mcp): pin CLI<->MCP Filigree emission body parity (WS-A1)"
```

---

### Task 4: Correct the surface docs (mcp launcher help + CHANGELOG)

**Files:**
- Modify: `src/wardline/cli/mcp.py:28-32` (the `--filigree-url` help string)
- Modify: `CHANGELOG.md` (the `[Unreleased]` section, line 8)

- [ ] **Step 1: Fix the `--filigree-url` help text**

In `src/wardline/cli/mcp.py`, change the help on the `--filigree-url` option from:

```python
    help="Filigree URL: `dossier` reads entity-associations (open work) from it.",
```

to:

```python
    help="Filigree URL: `scan` POSTs findings to it (fail-soft); `dossier` reads entity-associations (open work) from it.",
```

- [ ] **Step 2: Add a CHANGELOG entry**

In `CHANGELOG.md`, under the `## [Unreleased]` heading (line 8), add this bullet (create an `### Added` subsection there if one does not already exist; otherwise append to it):

```markdown
### Added
- MCP `scan` now emits findings to Filigree when a `--filigree-url` is configured, at
  parity with the CLI (a `filigree` block in the scan result; fail-soft — an unreachable
  sibling or rejected payload is reported, never fails the scan). Closes the CLI/MCP
  finding-emission asymmetry. (WS-A1)
```

- [ ] **Step 3: Verify the docs build is unaffected**

Run: `uv run python -c "import wardline.cli.mcp"`
Expected: no output, exit 0 (the help-string edit is syntactically valid).

- [ ] **Step 4: Commit**

```bash
git add src/wardline/cli/mcp.py CHANGELOG.md
git commit -m "docs(mcp): note scan->Filigree emission in --filigree-url help + CHANGELOG (WS-A1)"
```

---

### Task 5: Full local gate

**Files:** none (verification only)

- [ ] **Step 1: Lint**

Run: `uv run ruff check src tests && uv run ruff format --check src tests`
Expected: no errors.

- [ ] **Step 2: Type-check**

Run: `uv run mypy`
Expected: `Success: no issues found`. (`_emit_filigree` and `_filigree_emitter` use `Any` for the duck-typed emitter, consistent with the existing `clarion: Any` parameter — no new strictness violations.)

- [ ] **Step 3: Full suite (random order)**

Run: `uv run pytest`
Expected: all pass. Confirms no snapshot/whole-dict test elsewhere broke on the additive `filigree` key, and the dogfood gate (Wardline scanning its own source) stays clean.

- [ ] **Step 4: Confirm the dogfood self-scan is still clean**

Run: `uv run wardline scan src/wardline --fail-on ERROR`
Expected: exit 0 (no active ERROR+ defect introduced by the change).

---

## Self-review

**Spec coverage (§4 Workstream A1):** A1's deliverable — "the MCP `scan` handler emits to `self.filigree_url` when set … and returns a `filigree:{created, updated, failed}` block mirroring the existing `clarion` block" — is implemented in Tasks 1-2; the A1 DoD "byte-identical emission to the CLI path" is pinned in Task 3; "return payload carries the structured counts" is asserted in Task 1. The A1 gate "CLI/MCP parity test" is Task 3. A2 is explicitly out of scope (own plan).

**Placeholder scan:** none — every code step shows complete code; every run step shows the exact command and expected outcome.

**Type consistency:** `_filigree_emitter()` (Task 2) returns the object `_scan`'s `filigree` parameter (Task 1) consumes via `.emit(findings) -> EmitResult`; the block keys `reachable/created/updated/failed/warnings` (Task 1's `_emit_filigree`) match the `EmitResult` fields used by `FakeEmitter`/`CapturingEmitter`/`_Capture` across Tasks 1-3. The `filigree` parameter is `Any` (duck-typed), matching the existing `clarion: Any` convention so mypy stays green.
