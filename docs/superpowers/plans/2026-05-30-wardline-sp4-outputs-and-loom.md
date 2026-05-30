# SP4 — Outputs + Loom Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three additive output paths to Wardline — a SARIF 2.1.0 emitter, a native
Filigree scan-results emitter, and a Clarion producer-side qualname conformance test —
without any runtime dependency on a sibling.

**Architecture:** Two pure findings→dict builders (`build_sarif`,
`build_scan_results_body`) plus an injectable-transport HTTP emitter, wired into the
existing `wardline scan` (`--format sarif`, `--filigree-url`). Conformance is a vendored
fixture + test, no production code.

**Tech Stack:** Python 3.12+, stdlib only (`json`, `urllib.request`), Click CLI, pytest.
Gate: `.venv/bin/python -m pytest -q`, `.venv/bin/ruff check src tests`,
`.venv/bin/mypy src`.

**Reference spec:** `docs/superpowers/specs/2026-05-30-wardline-sp4-outputs-and-loom-design.md`

---

## Task 1: SARIF 2.1.0 builder + sink

**Files:**
- Create: `src/wardline/core/sarif.py`
- Test: `tests/unit/core/test_sarif.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/core/test_sarif.py
from __future__ import annotations

import json
from pathlib import Path

from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.sarif import SarifSink, build_sarif


def _f(
    *,
    rule_id: str = "PY-WL-101",
    sev: Severity = Severity.ERROR,
    kind: Kind = Kind.DEFECT,
    path: str = "src/m.py",
    line_start: int | None = 10,
    fp: str = "a" * 64,
    suppressed: SuppressionState = SuppressionState.ACTIVE,
    reason: str | None = None,
    qualname: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id, message="msg", severity=sev, kind=kind,
        location=Location(path=path, line_start=line_start, line_end=line_start),
        fingerprint=fp, suppressed=suppressed, suppression_reason=reason, qualname=qualname,
    )


def test_log_shape_and_version() -> None:
    log = build_sarif([_f()])
    assert log["version"] == "2.1.0"
    assert "$schema" in log
    assert len(log["runs"]) == 1
    assert log["runs"][0]["tool"]["driver"]["name"] == "wardline"


def test_severity_maps_to_level() -> None:
    levels = {f["properties"]["internalSeverity"]: f["level"]
              for f in build_sarif([
                  _f(sev=Severity.CRITICAL), _f(sev=Severity.ERROR),
                  _f(sev=Severity.WARN), _f(sev=Severity.INFO), _f(sev=Severity.NONE),
              ])["runs"][0]["results"]}
    assert levels == {"CRITICAL": "error", "ERROR": "error", "WARN": "warning",
                      "INFO": "note", "NONE": "none"}


def test_partial_fingerprint_and_location() -> None:
    res = build_sarif([_f(line_start=42)])["runs"][0]["results"][0]
    assert res["partialFingerprints"] == {"wardlineFingerprint/v1": "a" * 64}
    region = res["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 42
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/m.py"


def test_no_line_finding_has_no_region() -> None:
    res = build_sarif([_f(line_start=None)])["runs"][0]["results"][0]
    phys = res["locations"][0]["physicalLocation"]
    assert "region" not in phys
    assert phys["artifactLocation"]["uri"] == "src/m.py"


def test_rules_array_is_first_seen_unique() -> None:
    log = build_sarif([_f(rule_id="B"), _f(rule_id="A"), _f(rule_id="B")])
    driver = log["runs"][0]["tool"]["driver"]
    assert [r["id"] for r in driver["rules"]] == ["B", "A"]
    # ruleIndex points back into the rules array
    results = log["runs"][0]["results"]
    assert results[0]["ruleIndex"] == 0 and results[1]["ruleIndex"] == 1
    assert results[2]["ruleIndex"] == 0


def test_suppressed_finding_emits_suppressions() -> None:
    baselined = build_sarif([_f(suppressed=SuppressionState.BASELINED)])["runs"][0]["results"][0]
    assert baselined["suppressions"] == [{"kind": "external", "status": "accepted"}]
    waived = build_sarif([
        _f(suppressed=SuppressionState.WAIVED, reason="false positive")
    ])["runs"][0]["results"][0]
    assert waived["suppressions"][0]["justification"] == "false positive"


def test_active_finding_has_no_suppressions() -> None:
    res = build_sarif([_f()])["runs"][0]["results"][0]
    assert "suppressions" not in res


def test_properties_omit_absent_optionals() -> None:
    props = build_sarif([_f(qualname=None)])["runs"][0]["results"][0]["properties"]
    assert "qualname" not in props
    assert props["kind"] == "defect"


def test_sink_writes_valid_json(tmp_path: Path) -> None:
    out = tmp_path / "findings.sarif"
    SarifSink(out).write([_f()])
    loaded = json.loads(out.read_text("utf-8"))
    assert loaded["version"] == "2.1.0"
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/core/test_sarif.py -q`
Expected: FAIL — `ModuleNotFoundError: wardline.core.sarif`.

- [ ] **Step 3: Implement `src/wardline/core/sarif.py`**

```python
# src/wardline/core/sarif.py
"""SARIF 2.1.0 emission (SP4a). Pure findings -> dict; stdlib-only.

A standard interchange format for any SARIF consumer (CI annotations, code-scanning
dashboards). Suppression rides SARIF's native ``result.suppressions`` channel;
the stable fingerprint rides ``partialFingerprints``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from wardline import __version__
from wardline.core.finding import Finding, Severity, SuppressionState

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/foundryside/wardline"

_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.ERROR: "error",
    Severity.WARN: "warning",
    Severity.INFO: "note",
    Severity.NONE: "none",
}


def _region(loc: Finding) -> dict[str, Any]:
    region: dict[str, Any] = {}
    location = loc.location
    if location.line_start is not None:
        region["startLine"] = location.line_start
    if location.line_end is not None:
        region["endLine"] = location.line_end
    if location.col_start is not None:
        region["startColumn"] = location.col_start
    if location.col_end is not None:
        region["endColumn"] = location.col_end
    return region


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": {"uri": finding.location.path}}
    region = _region(finding)
    if region:
        physical["region"] = region

    props: dict[str, Any] = {
        "kind": finding.kind.value,
        "internalSeverity": finding.severity.value,
    }
    if finding.qualname is not None:
        props["qualname"] = finding.qualname
    if finding.confidence is not None:
        props["confidence"] = finding.confidence
    if finding.related_entities:
        props["relatedEntities"] = list(finding.related_entities)
    if finding.properties:
        props["wardlineProperties"] = dict(finding.properties)

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {"wardlineFingerprint/v1": finding.fingerprint},
        "properties": props,
    }
    if finding.suppressed is not SuppressionState.ACTIVE:
        suppression: dict[str, Any] = {"kind": "external", "status": "accepted"}
        if finding.suppression_reason is not None:
            suppression["justification"] = finding.suppression_reason
        result["suppressions"] = [suppression]
    return result


def build_sarif(findings: Sequence[Finding]) -> dict[str, Any]:
    rule_index: dict[str, int] = {}
    for finding in findings:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rule_index)
    rules = [{"id": rid} for rid in rule_index]
    results = [_result(f, rule_index[f.rule_id]) for f in findings]
    return {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wardline",
                        "informationUri": _INFO_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


class SarifSink:
    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, findings: Sequence[Finding]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(build_sarif(findings), indent=2, ensure_ascii=False), encoding="utf-8"
        )
```

Note: confirm `wardline.__version__` exists (it's referenced by SP2d's vocab/`scan`
driver version use). If `from wardline import __version__` is not importable, read the
version from `importlib.metadata.version("wardline")` with a fallback to `"0+unknown"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/core/test_sarif.py -q`
Expected: PASS (all).

- [ ] **Step 5: Gate + commit**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src && .venv/bin/python -m pytest -q`
Expected: clean.

```bash
git add src/wardline/core/sarif.py tests/unit/core/test_sarif.py
git commit -m "feat(sp4a): SARIF 2.1.0 builder + sink"
```

---

## Task 2: Wire SARIF into `wardline scan --format sarif`

**Files:**
- Modify: `src/wardline/cli/scan.py`
- Test: `tests/unit/cli/test_cli.py` (add cases)

- [ ] **Step 1: Write the failing CLI tests**

Add to `tests/unit/cli/test_cli.py` (follow the existing `CliRunner`/`isolated`-fixture
style already in that file; use a tmp project that produces ≥1 defect, mirroring the
existing `test_scan_*` fixtures):

```python
def test_scan_format_sarif_writes_sarif_file(tmp_path: Path) -> None:
    # Build a minimal scannable project (reuse the helper the other scan tests use).
    project = _make_project_with_one_defect(tmp_path)  # existing helper pattern
    out = project / "out.sarif"
    result = CliRunner().invoke(cli, ["scan", str(project), "--format", "sarif", "--output", str(out)])
    assert result.exit_code == 0, result.output
    log = json.loads(out.read_text("utf-8"))
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["tool"]["driver"]["name"] == "wardline"


def test_scan_format_sarif_default_output_path(tmp_path: Path) -> None:
    project = _make_empty_project(tmp_path)  # existing helper pattern
    result = CliRunner().invoke(cli, ["scan", str(project), "--format", "sarif"])
    assert result.exit_code == 0, result.output
    assert (project / "findings.sarif").exists()


def test_scan_format_sarif_still_gates(tmp_path: Path) -> None:
    project = _make_project_with_error_defect(tmp_path)  # existing helper pattern
    result = CliRunner().invoke(
        cli, ["scan", str(project), "--format", "sarif", "--fail-on", "ERROR"]
    )
    assert result.exit_code == 1, result.output
```

If no reusable project helper exists in `test_cli.py`, build the tmp project inline the
same way the current `test_scan_*` tests do (write a `wardline.yaml` + a decorated `.py`
that trips `PY-WL-101`). Match the existing tests' construction exactly.

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/cli/test_cli.py -q -k sarif`
Expected: FAIL — current stub prints "not yet implemented" and exits 2.

- [ ] **Step 3: Replace the SARIF stub in `scan.py`**

Remove the early `if fmt == "sarif": ... raise SystemExit(2)` block. Choose the sink and
default output path by format. Replace the output/sink lines:

```python
from wardline.core.sarif import SarifSink

# ... inside scan(), replace the `output = ...` default + `JsonlSink(output).write(...)`:
    default_name = "findings.sarif" if fmt == "sarif" else "findings.jsonl"
    output = output if output is not None else (path / default_name)
    try:
        # ... unchanged: load cfg, cache, discover, analyze, suppress ...
        sink = SarifSink(output) if fmt == "sarif" else JsonlSink(output)
        sink.write(findings)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    # ... unchanged: summary line, gate ...
```

The suppression stage and `--fail-on` gate are unchanged — they operate on `findings`
regardless of output format.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/cli/test_cli.py -q -k sarif`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src && .venv/bin/python -m pytest -q`

```bash
git add src/wardline/cli/scan.py tests/unit/cli/test_cli.py
git commit -m "feat(sp4a): wire SARIF emitter into scan --format sarif"
```

---

## Task 3: Filigree scan-results body builder

**Files:**
- Create: `src/wardline/core/filigree_emit.py` (builder portion only this task)
- Test: `tests/unit/core/test_filigree_emit.py` (builder tests this task)

- [ ] **Step 1: Write the failing builder tests**

```python
# tests/unit/core/test_filigree_emit.py
from __future__ import annotations

from wardline.core.filigree_emit import build_scan_results_body
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState


def _f(**kw: object) -> Finding:
    base = dict(
        rule_id="PY-WL-101", message="m", severity=Severity.ERROR, kind=Kind.DEFECT,
        location=Location(path="src/m.py", line_start=5, line_end=6),
        fingerprint="a" * 64,
    )
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


def test_body_envelope() -> None:
    body = build_scan_results_body([_f()])
    assert body["scan_source"] == "wardline"
    assert isinstance(body["findings"], list) and len(body["findings"]) == 1


def test_finding_uses_path_not_file_path() -> None:
    wire = build_scan_results_body([_f()])["findings"][0]
    assert wire["path"] == "src/m.py"
    assert "file_path" not in wire


def test_fingerprint_is_top_level_and_severity_lowercased() -> None:
    wire = build_scan_results_body([_f()])["findings"][0]
    assert wire["fingerprint"] == "a" * 64
    assert wire["severity"] == "high"  # ERROR -> high
    assert wire["language"] == "python"
    assert wire["line_start"] == 5 and wire["line_end"] == 6


def test_metadata_namespaced_and_carries_suppression() -> None:
    wire = build_scan_results_body([
        _f(suppressed=SuppressionState.WAIVED, suppression_reason="fp")
    ])["findings"][0]
    assert set(wire["metadata"]) == {"wardline"}
    assert wire["metadata"]["wardline"]["suppressed"] == "waived"
    assert wire["metadata"]["wardline"]["suppression_reason"] == "fp"


def test_suggestion_capped_at_10k_and_omitted_when_none() -> None:
    none_wire = build_scan_results_body([_f()])["findings"][0]
    assert "suggestion" not in none_wire
    long = "x" * 20000
    capped = build_scan_results_body([_f(suggestion=long)])["findings"][0]["suggestion"]
    assert len(capped) <= 10000


def test_all_kinds_emitted() -> None:
    findings = [_f(kind=k, severity=Severity.NONE if k is not Kind.DEFECT else Severity.ERROR)
                for k in Kind]
    body = build_scan_results_body(findings)
    assert len(body["findings"]) == len(list(Kind))
    # facts/metrics map to info
    fact = next(w for w, f in zip(body["findings"], findings) if f.kind is Kind.FACT)
    assert fact["severity"] == "info"
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/core/test_filigree_emit.py -q`
Expected: FAIL — module/function missing.

- [ ] **Step 3: Implement the builder in `src/wardline/core/filigree_emit.py`**

```python
# src/wardline/core/filigree_emit.py
"""Native Filigree scan-results emission (SP4b).

A pure body builder (``build_scan_results_body``) plus an injectable-transport
HTTP emitter (``FiligreeEmitter``). stdlib-only; no runtime dependency on Filigree.
Federation discipline: a *sibling-absent* network failure warns and continues; an
HTTP *protocol error* (4xx/5xx) is a Wardline-built-a-bad-payload bug and fails loud.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from wardline.core.finding import Finding, severity_to_filigree, to_filigree_metadata

_SUGGESTION_LIMIT = 10000


def _cap_suggestion(suggestion: str | None) -> str | None:
    if suggestion is None:
        return None
    return suggestion if len(suggestion) <= _SUGGESTION_LIMIT else suggestion[:_SUGGESTION_LIMIT]


def _finding_to_wire(finding: Finding) -> dict[str, Any]:
    wire: dict[str, Any] = {
        "path": finding.location.path,
        "rule_id": finding.rule_id,
        "message": finding.message,
        "severity": severity_to_filigree(finding.severity),
        "line_start": finding.location.line_start,
        "line_end": finding.location.line_end,
        "fingerprint": finding.fingerprint,
        "metadata": to_filigree_metadata(finding),
        "language": "python",
    }
    suggestion = _cap_suggestion(finding.suggestion)
    if suggestion is not None:
        wire["suggestion"] = suggestion
    return wire


def build_scan_results_body(
    findings: Sequence[Finding], *, scan_source: str = "wardline"
) -> dict[str, Any]:
    """Build the ``POST /api/loom/scan-results`` request body. Emits ALL finding kinds."""
    return {
        "scan_source": scan_source,
        "findings": [_finding_to_wire(f) for f in findings],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/core/test_filigree_emit.py -q`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src && .venv/bin/python -m pytest -q`

```bash
git add src/wardline/core/filigree_emit.py tests/unit/core/test_filigree_emit.py
git commit -m "feat(sp4b): Filigree scan-results body builder"
```

---

## Task 4: Filigree emitter (transport + absent/protocol split)

**Files:**
- Modify: `src/wardline/core/filigree_emit.py`
- Modify: `src/wardline/core/errors.py` (add `FiligreeEmitError`)
- Test: `tests/unit/core/test_filigree_emit.py` (add emitter tests)

- [ ] **Step 1: Add `FiligreeEmitError` to errors.py**

Open `src/wardline/core/errors.py`, confirm `WardlineError` is the base, and add:

```python
class FiligreeEmitError(WardlineError):
    """Filigree rejected the scan-results payload (HTTP >= 400) — a Wardline bug."""
```

- [ ] **Step 2: Write the failing emitter tests**

```python
# append to tests/unit/core/test_filigree_emit.py
import json

import pytest

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_emit import EmitResult, FiligreeEmitter, Response


class _FakeTransport:
    def __init__(self, response: Response | None = None, exc: Exception | None = None) -> None:
        self._response, self._exc = response, exc
        self.calls: list[tuple[str, bytes]] = []

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> Response:
        self.calls.append((url, body))
        if self._exc is not None:
            raise self._exc
        assert self._response is not None
        return self._response


def _ok_body() -> str:
    return json.dumps({
        "succeeded": ["id1"], "failed": [],
        "stats": {"findings_created": 1, "findings_updated": 0},
        "warnings": ["severity coerced"],
    })


def test_success_surfaces_stats_and_warnings() -> None:
    t = _FakeTransport(response=Response(status=200, body=_ok_body()))
    res = FiligreeEmitter("http://x/api/loom/scan-results", transport=t).emit([_f()])
    assert res.reachable is True
    assert res.created == 1
    assert res.warnings == ["severity coerced"]
    # posted to exactly the given URL, with a JSON body carrying scan_source
    assert t.calls[0][0] == "http://x/api/loom/scan-results"
    assert json.loads(t.calls[0][1])["scan_source"] == "wardline"


def test_http_400_raises_filigree_emit_error() -> None:
    t = _FakeTransport(response=Response(status=400, body='{"error":"bad path key"}'))
    with pytest.raises(FiligreeEmitError) as exc:
        FiligreeEmitter("http://x", transport=t).emit([_f()])
    assert "bad path key" in str(exc.value)  # response body echoed


def test_connection_error_is_sibling_absent() -> None:
    t = _FakeTransport(exc=ConnectionRefusedError("no server"))
    res = FiligreeEmitter("http://x", transport=t).emit([_f()])
    assert res.reachable is False  # warns + continues; no raise
```

- [ ] **Step 3: Implement the emitter (append to `filigree_emit.py`)**

```python
import json as _json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: str


@dataclass(frozen=True, slots=True)
class EmitResult:
    reachable: bool
    created: int = 0
    updated: int = 0
    warnings: tuple[str, ...] = field(default_factory=tuple)


class Transport(Protocol):
    def post(self, url: str, body: bytes, headers: dict[str, str]) -> Response: ...


class UrllibTransport:
    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> Response:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                return Response(status=resp.status, body=resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # An HTTP status reached us — protocol-level outcome, not an outage.
            return Response(status=exc.code, body=exc.read().decode("utf-8", "replace"))


class FiligreeEmitter:
    """POST findings to a Filigree Loom scan-results URL with an injectable transport."""

    def __init__(self, url: str, *, transport: Transport | None = None) -> None:
        self._url = url
        self._transport = transport if transport is not None else UrllibTransport()

    def emit(self, findings: Sequence[Finding]) -> EmitResult:
        body = _json.dumps(build_scan_results_body(findings)).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        try:
            resp = self._transport.post(self._url, body, headers)
        except (urllib.error.URLError, OSError):
            # Connection refused / DNS / timeout — sibling absent. Enrichment is
            # non-load-bearing: warn (at the CLI) and continue.
            return EmitResult(reachable=False)
        if resp.status >= 400:
            raise FiligreeEmitError(
                f"Filigree rejected scan-results ({resp.status}) at {self._url}: {resp.body}"
            )
        payload = _json.loads(resp.body) if resp.body else {}
        stats = payload.get("stats", {}) or {}
        return EmitResult(
            reachable=True,
            created=int(stats.get("findings_created", 0)),
            updated=int(stats.get("findings_updated", 0)),
            warnings=tuple(payload.get("warnings", []) or ()),
        )
```

Note: `urllib.error.URLError` subclasses `OSError`; `ConnectionRefusedError` is an
`OSError`. The `except (urllib.error.URLError, OSError)` catches both the urllib wrapper
and a raw `OSError`/`ConnectionRefusedError` from an injected transport. `HTTPError`
(a `URLError` subclass carrying a status) is handled inside `UrllibTransport.post` and
surfaces as a `Response(status>=400)` — so it reaches the protocol-error branch, NOT the
absent branch. Keep that ordering exact.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/core/test_filigree_emit.py -q`
Expected: PASS (builder + emitter).

- [ ] **Step 5: Gate + commit**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src && .venv/bin/python -m pytest -q`

```bash
git add src/wardline/core/filigree_emit.py src/wardline/core/errors.py tests/unit/core/test_filigree_emit.py
git commit -m "feat(sp4b): Filigree emitter with absent/protocol-error split"
```

---

## Task 5: Wire `--filigree-url` into `wardline scan`

**Files:**
- Modify: `src/wardline/cli/scan.py`
- Test: `tests/unit/cli/test_cli.py` (add cases, injecting a fake transport)

- [ ] **Step 1: Write the failing CLI tests**

The CLI must use an injectable transport so the test needs no live server. Add a
private seam: `scan` constructs `FiligreeEmitter(url)` (default transport) — to test
without network, monkeypatch `wardline.cli.scan.FiligreeEmitter` with a factory binding
a fake transport, OR add a hidden `--_filigree-transport` (NOT this — no test-only CLI
flags). Use monkeypatch:

```python
def test_scan_filigree_emit_success(tmp_path, monkeypatch) -> None:
    project = _make_project_with_one_defect(tmp_path)
    captured = {}

    class _StubEmitter:
        def __init__(self, url, **kw): captured["url"] = url
        def emit(self, findings):
            from wardline.core.filigree_emit import EmitResult
            captured["n"] = len(findings)
            return EmitResult(reachable=True, created=len(findings), warnings=("w1",))

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _StubEmitter)
    result = CliRunner().invoke(
        cli, ["scan", str(project), "--filigree-url", "http://x/api/loom/scan-results"]
    )
    assert result.exit_code == 0, result.output
    assert captured["url"] == "http://x/api/loom/scan-results"
    assert "emitted" in result.output and "w1" in result.output  # stats + warning surfaced


def test_scan_filigree_protocol_error_exits_2(tmp_path, monkeypatch) -> None:
    project = _make_project_with_one_defect(tmp_path)
    from wardline.core.errors import FiligreeEmitError

    class _BadEmitter:
        def __init__(self, url, **kw): pass
        def emit(self, findings): raise FiligreeEmitError("Filigree rejected (400): bad path")

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _BadEmitter)
    result = CliRunner().invoke(cli, ["scan", str(project), "--filigree-url", "http://x"])
    assert result.exit_code == 2, result.output
    assert "bad path" in result.output


def test_scan_filigree_absent_continues(tmp_path, monkeypatch) -> None:
    project = _make_project_with_one_defect(tmp_path)

    class _AbsentEmitter:
        def __init__(self, url, **kw): pass
        def emit(self, findings):
            from wardline.core.filigree_emit import EmitResult
            return EmitResult(reachable=False)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _AbsentEmitter)
    # absent sibling must NOT change the exit code; with no --fail-on, stays 0
    result = CliRunner().invoke(cli, ["scan", str(project), "--filigree-url", "http://x"])
    assert result.exit_code == 0, result.output
    assert "could not reach" in result.output.lower() or "unreachable" in result.output.lower()
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/cli/test_cli.py -q -k filigree`
Expected: FAIL — no `--filigree-url` option.

- [ ] **Step 3: Wire it into `scan.py`**

Add the import and option, and the emission step inside the existing `try` (so a
`FiligreeEmitError` is caught by the `except WardlineError` → exit 2). Emit AFTER
writing local output, BEFORE the summary/gate:

```python
from wardline.core.filigree_emit import FiligreeEmitter

# new option (place near the other @click.option lines):
@click.option("--filigree-url", default=None,
              help="POST findings to this Filigree Loom scan-results URL (opt-in).")
# add `filigree_url: str | None,` to the signature.

# inside the try, after `sink.write(findings)`:
        emit_result = None
        if filigree_url is not None:
            emit_result = FiligreeEmitter(filigree_url).emit(findings)
# (FiligreeEmitError, a WardlineError, is caught below -> exit 2.)

# after the existing scan summary echo, before the gate:
    if emit_result is not None:
        if not emit_result.reachable:
            click.echo(f"warning: could not reach Filigree at {filigree_url}; "
                       f"findings written locally only.", err=True)
        else:
            line = (f"emitted {len(findings)} finding(s) to {filigree_url} — "
                    f"{emit_result.created} created / {emit_result.updated} updated")
            if emit_result.warnings:
                line += f"; {len(emit_result.warnings)} warning(s): " + "; ".join(emit_result.warnings)
            click.echo(line)
```

Keep the `--fail-on` gate exactly where it is (last). A protocol error already exited 2
via the exception; an absent sibling falls through to the gate unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/cli/test_cli.py -q -k filigree`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src && .venv/bin/python -m pytest -q`

```bash
git add src/wardline/cli/scan.py tests/unit/cli/test_cli.py
git commit -m "feat(sp4b): wire --filigree-url into scan (absent warns, protocol-error exits 2)"
```

---

## Task 6: Clarion producer qualname conformance

**Files:**
- Create: `tests/conformance/clarion_qualname_parity.json` (vendored copy)
- Test: `tests/conformance/test_clarion_qualname_parity.py`

- [ ] **Step 1: Vendor the fixture**

Copy the EXACT contents of
`/home/john/clarion/docs/federation/fixtures/wardline-qualname-normalization.json`
into `tests/conformance/clarion_qualname_parity.json`, **prepending** a provenance note
to the existing `$comment` array (or adding a `_wardline_provenance` key):

```
"_wardline_provenance": "Vendored copy of clarion/docs/federation/fixtures/wardline-qualname-normalization.json (clarion 1.0.0, 2026-05-30). Resync: copy that file here verbatim when Clarion's module_dotted_name rules change. The parity test fails loudly on divergence."
```

Do not alter any vector values — they are the contract.

- [ ] **Step 2: Write the conformance test**

```python
# tests/conformance/test_clarion_qualname_parity.py
"""Pin Wardline's qualname producer against Clarion's normative parity fixture.

The reconciliation CONSUMER is unbuilt in clarion 1.0.0; this converts the
producer byte-equality from assumption to a committed CI test. Wardline returns
``None`` where Clarion returns ``""`` for a top-level ``__init__.py`` — the
``None <-> ""`` mapping below is the documented, semantically-equivalent boundary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from wardline.core.qualname import module_dotted_name

_FIXTURE = json.loads((Path(__file__).parent / "clarion_qualname_parity.json").read_text("utf-8"))


@pytest.mark.parametrize(
    "vec", _FIXTURE["module_normalization_vectors"], ids=lambda v: v["file_path"]
)
def test_module_normalization(vec: dict[str, Any]) -> None:
    got = module_dotted_name(vec["file_path"])
    expected = vec["expected_module"]
    if expected == "":
        assert got is None  # Wardline's "emit no entity" sentinel == Clarion's empty+rejected
    else:
        assert got == expected


@pytest.mark.parametrize(
    "vec",
    [v for v in _FIXTURE["qualified_name_vectors"] if v["kind"] == "function"],
    ids=lambda v: v["expected_qualified_name"],
)
def test_function_qualified_name_composition(vec: dict[str, Any]) -> None:
    module = module_dotted_name(vec["file_path"])
    assert module is not None
    assert f"{module}.{vec['qualname']}" == vec["expected_qualified_name"]


def test_module_kind_vector_prefix_matches() -> None:
    # The single kind=="module" vector: Wardline emits no module ENTITY, but the
    # module dotted prefix it produces must equal the expected qualified_name.
    module_vecs = [v for v in _FIXTURE["qualified_name_vectors"] if v["kind"] == "module"]
    for vec in module_vecs:
        assert module_dotted_name(vec["file_path"]) == vec["expected_qualified_name"]
```

- [ ] **Step 3: Run the test**

Run: `.venv/bin/python -m pytest tests/conformance/test_clarion_qualname_parity.py -q`
Expected: PASS for every vector. If any divergence-trap vector fails, that is a real
producer bug — fix `core/qualname.py`, do not edit the fixture.

- [ ] **Step 4: Gate + commit**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src && .venv/bin/python -m pytest -q`

```bash
git add tests/conformance/clarion_qualname_parity.json tests/conformance/test_clarion_qualname_parity.py
git commit -m "test(sp4c): pin qualname producer against Clarion parity fixture"
```

---

## Task 7: End-to-end verification + memory

**Files:** none (verification only) — then update memory.

- [ ] **Step 1: SARIF e2e through the installed CLI**

```bash
.venv/bin/wardline scan src/wardline --format sarif --output /tmp/wln.sarif
.venv/bin/python -c "import json; d=json.load(open('/tmp/wln.sarif')); print(d['version'], len(d['runs'][0]['results']), 'results')"
```
Expected: `2.1.0 <N> results`, valid JSON.

- [ ] **Step 2: Filigree emitter against a real binary IF one is trivially available**

Only if a Filigree server is already running (do not stand one up — that would trip the
"stop if you need something from filigree" condition). If `~/filigree` exposes a quick
ethereal-mode launch and a server is up, point `--filigree-url` at
`<base>/api/loom/scan-results` and confirm a 200 + the summary line. Otherwise rely on
the hermetic transport tests and note live-e2e as deferred-to-availability.

- [ ] **Step 3: Full gate**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src && .venv/bin/python -m pytest -q`
Expected: all green; test count up from 610 by the SP4 additions.

- [ ] **Step 4: Update memory**

Update `project_generic_rebuild.md` with an SP4 DONE entry and resolve the SP4
forward-notes (fingerprint line-stability = documented no-change; suggestion-cap = done;
Clarion reconciliation = producer-pinned, consumer-deferred). Update `MEMORY.md` index.

---

## Self-Review notes (author)

- **Spec coverage:** SP4a (Tasks 1–2), SP4b (Tasks 3–5), SP4c (Task 6), e2e+memory
  (Task 7). Every §-numbered spec item maps to a task.
- **Type consistency:** `EmitResult`/`Response`/`Transport`/`FiligreeEmitter` names match
  across Tasks 4–5; `build_sarif`/`SarifSink` across Tasks 1–2; `build_scan_results_body`
  across Tasks 3–5.
- **No live-server dependency** in the unit suite (injectable transport; CLI monkeypatch).
- **Open implementer note:** Tasks 2 and 5 reference existing `test_cli.py` project-setup
  helpers; the implementer must read `tests/unit/cli/test_cli.py` first and reuse its
  exact fixture/scannable-project construction rather than invent a new one.
