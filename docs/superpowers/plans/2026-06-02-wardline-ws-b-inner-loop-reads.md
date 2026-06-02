# Workstream B — Inner-Loop Reads Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the MCP inner loop from wasting round-trips — let an agent (B1) filter findings server-side instead of pulling the whole corpus, and (B2) get each finding's taint provenance inline from a single `scan` call instead of one `explain_taint` re-scan per finding.

**Architecture:** Both features are MCP-surface plumbing of data the engine already computes. B1 adds a pure, shared `core/finding_query.filter_findings` consumed by the MCP `scan` tool (`where`) and a new read-only `wardline findings` CLI verb (parity). B2 extracts the existing per-finding provenance projection out of `_explain_local` into a shared `explanation_from_context` helper, then has `scan(explain=true)` apply it to each active defect from the scan's retained `result.context` — zero extra analysis, one scan total.

**Tech Stack:** Python 3.12+, stdlib-only, `pytest`, `ruff`, `mypy`. No new dependencies, no engine change.

**Source spec:** `docs/superpowers/specs/2026-06-02-wardline-frictionless-agent-surface-spec.md` §4 Workstream B (items B1, B2, B3-lineage is part of Workstream C, not here).

**Frictionless bar (every task):** one round-trip / structured output / no hand-config / CLI=MCP shared core / fail-closed honesty preserved.

---

## File structure

| File | Responsibility | Change |
|---|---|---|
| `src/wardline/core/finding_query.py` | pure conjunctive finding filter (shared read-lens) | Create |
| `src/wardline/core/explain.py` | provenance projection | Modify: extract `explanation_from_context` from `_explain_local` |
| `src/wardline/mcp/server.py` | MCP `scan` tool | Modify: `where` filter + `explain` inliner on `_scan`; schema + description |
| `src/wardline/cli/findings.py` | `wardline findings` read verb (CLI parity for B1) | Create |
| `src/wardline/cli/main.py` | CLI command group | Modify: register `findings` |
| `tests/unit/core/test_finding_query.py` | filter unit tests | Create |
| `tests/unit/core/test_explain.py` | `explanation_from_context` regression | Modify or create |
| `tests/unit/mcp/test_server_query_explain.py` | `_scan` where/explain behavior | Create |
| `tests/unit/cli/test_findings_cmd.py` | CLI `findings` verb | Create |
| `CHANGELOG.md` | release notes | Modify |

---

## PART B1 — Server-side finding query

### Task 1: Pure `filter_findings` core function

**Files:**
- Create: `src/wardline/core/finding_query.py`
- Test: `tests/unit/core/test_finding_query.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/core/test_finding_query.py`:

```python
"""WS-B1: pure conjunctive finding filter shared by MCP `scan(where=)` and CLI
`wardline findings --where`."""

import pytest

from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.finding_query import filter_findings


def _f(rule_id="PY-WL-101", qualname="pkg.mod.fn", path="pkg/mod.py", severity=Severity.ERROR,
       kind=Kind.DEFECT, suppressed=SuppressionState.ACTIVE, properties=None):
    return Finding(
        rule_id=rule_id, message="m", severity=severity, kind=kind,
        location=Location(path=path, line_start=3), fingerprint=rule_id + path + (qualname or ""),
        qualname=qualname, properties=properties or {},
    )


def test_no_where_returns_all():
    fs = [_f(), _f(rule_id="PY-WL-106")]
    assert filter_findings(fs, None) == fs
    assert filter_findings(fs, {}) == fs


def test_filter_by_rule_id():
    a, b = _f(rule_id="PY-WL-101"), _f(rule_id="PY-WL-106")
    assert filter_findings([a, b], {"rule_id": "PY-WL-106"}) == [b]


def test_filter_by_qualname():
    a, b = _f(qualname="pkg.a"), _f(qualname="pkg.b")
    assert filter_findings([a, b], {"qualname": "pkg.b"}) == [b]


def test_filter_by_severity_and_suppression_and_kind():
    a = _f(severity=Severity.ERROR, suppressed=SuppressionState.ACTIVE, kind=Kind.DEFECT)
    b = _f(severity=Severity.WARN, suppressed=SuppressionState.BASELINED, kind=Kind.FACT)
    assert filter_findings([a, b], {"severity": "ERROR"}) == [a]
    assert filter_findings([a, b], {"suppression": "baselined"}) == [b]
    assert filter_findings([a, b], {"kind": "fact"}) == [b]


def test_filter_by_path_glob():
    a, b = _f(path="src/api/h.py"), _f(path="src/core/x.py")
    assert filter_findings([a, b], {"path_glob": "src/api/**"}) == [a]


def test_filter_by_sink_property():
    a = _f(rule_id="PY-WL-106", properties={"sink": "pickle.loads", "tier": "ASSURED"})
    b = _f(rule_id="PY-WL-107", properties={"sink": "eval", "tier": "ASSURED"})
    assert filter_findings([a, b], {"sink": "pickle.loads"}) == [a]


def test_filter_by_tier_matches_any_tier_property():
    # 101 carries actual_return; 106 carries tier/arg_taint — `tier` matches either.
    a = _f(rule_id="PY-WL-101", properties={"actual_return": "EXTERNAL_RAW", "declared_return": "INTEGRAL"})
    b = _f(rule_id="PY-WL-106", properties={"tier": "ASSURED", "arg_taint": "UNKNOWN_RAW"})
    assert filter_findings([a, b], {"tier": "EXTERNAL_RAW"}) == [a]
    assert filter_findings([a, b], {"tier": "UNKNOWN_RAW"}) == [b]


def test_conjunction_all_must_match():
    a = _f(rule_id="PY-WL-101", qualname="pkg.a")
    b = _f(rule_id="PY-WL-101", qualname="pkg.b")
    assert filter_findings([a, b], {"rule_id": "PY-WL-101", "qualname": "pkg.b"}) == [b]


def test_unknown_key_raises_valueerror():
    with pytest.raises(ValueError, match="unknown filter key"):
        filter_findings([_f()], {"bogus": "x"})
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/core/test_finding_query.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.core.finding_query'`.

- [ ] **Step 3: Implement `filter_findings`**

Create `src/wardline/core/finding_query.py`:

```python
# src/wardline/core/finding_query.py
"""Server-side finding filtering — a pure, conjunctive read-lens over a scan's
findings. Shared by the MCP `scan` tool (`where`) and the CLI `wardline findings`
verb so the query capability is identical across surfaces. Filters the findings
list only; a scan's summary/gate remain whole-project facts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from fnmatch import fnmatch
from typing import Any

from wardline.core.finding import Finding

# Property keys that carry a trust-tier value across the rule set: 101/109 ->
# actual_return/declared_return; 106/107/108 -> tier/arg_taint; 104/105 ->
# body_taint/return_taint. A `tier` predicate matches a finding touching that
# tier on ANY of these.
_TIER_KEYS = ("actual_return", "declared_return", "tier", "arg_taint", "body_taint", "return_taint")

_ALLOWED = frozenset({"rule_id", "qualname", "severity", "suppression", "kind", "path_glob", "sink", "tier"})


def _matches(f: Finding, where: Mapping[str, Any]) -> bool:
    if (v := where.get("rule_id")) is not None and f.rule_id != v:
        return False
    if (v := where.get("qualname")) is not None and f.qualname != v:
        return False
    if (v := where.get("severity")) is not None and f.severity.value != v:
        return False
    if (v := where.get("suppression")) is not None and f.suppressed.value != v:
        return False
    if (v := where.get("kind")) is not None and f.kind.value != v:
        return False
    if (v := where.get("path_glob")) is not None and not fnmatch(f.location.path, v):
        return False
    if (v := where.get("sink")) is not None and f.properties.get("sink") != v:
        return False
    if (v := where.get("tier")) is not None and not any(f.properties.get(k) == v for k in _TIER_KEYS):
        return False
    return True


def filter_findings(findings: Sequence[Finding], where: Mapping[str, Any] | None) -> list[Finding]:
    """Return findings matching every predicate in `where` (conjunction). A falsy
    `where` returns all. An unknown key is agent-actionable -> ValueError."""
    if not where:
        return list(findings)
    unknown = set(where) - _ALLOWED
    if unknown:
        raise ValueError(f"unknown filter key(s): {sorted(unknown)}; allowed: {sorted(_ALLOWED)}")
    return [f for f in findings if _matches(f, where)]
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/core/test_finding_query.py -v`
Expected: PASS (9 passed).

- [ ] **Step 5: Commit (controller does this — implementer: skip, leave uncommitted)**

---

### Task 2: Wire `where` into the MCP `scan` tool

**Files:**
- Modify: `src/wardline/mcp/server.py` (`_scan` + the scan tool schema/description)
- Test: `tests/unit/mcp/test_server_query_explain.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/mcp/test_server_query_explain.py`:

```python
"""WS-B1/B2: MCP `scan` server-side `where` filter and `explain` inliner."""

import pytest

from wardline.mcp.server import ToolError, _scan

# Two boundaries + two trusted leaks → PY-WL-101 fires on both leaks.
_SRC = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_a(p):\n    return p\n"
    "@external_boundary\ndef read_b(p):\n    return p\n"
    "@trusted\ndef leak_a(p):\n    return read_a(p)\n"
    "@trusted\ndef leak_b(p):\n    return read_b(p)\n"
)


def test_where_filters_findings_by_qualname(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    full = _scan({}, tmp_path)
    qualnames = {f["qualname"] for f in full["findings"] if f["rule_id"] == "PY-WL-101"}
    assert "svc.leak_a" in qualnames and "svc.leak_b" in qualnames

    filtered = _scan({"where": {"qualname": "svc.leak_a"}}, tmp_path)
    got = [f for f in filtered["findings"] if f["rule_id"] == "PY-WL-101"]
    assert {f["qualname"] for f in got} == {"svc.leak_a"}


def test_where_summary_and_gate_describe_whole_project(tmp_path):
    # The filter is a read-lens on `findings`; summary/gate stay whole-project.
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    full = _scan({}, tmp_path)
    filtered = _scan({"where": {"qualname": "svc.leak_a"}}, tmp_path)
    assert filtered["summary"] == full["summary"]
    assert filtered["gate"] == full["gate"]


def test_where_unknown_key_is_toolerror(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    with pytest.raises(ToolError, match="unknown filter key"):
        _scan({"where": {"bogus": "x"}}, tmp_path)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/mcp/test_server_query_explain.py -v`
Expected: FAIL — the `where` arg is ignored today, so `test_where_filters_findings_by_qualname` returns both qualnames (assertion fails), and `test_where_unknown_key_is_toolerror` raises nothing.

- [ ] **Step 3: Implement the `where` filter in `_scan`**

In `src/wardline/mcp/server.py`, add the import near the other `core` imports (top of file):

```python
from wardline.core.finding_query import filter_findings
```

Then in `_scan`, replace the findings serialization. Change:

```python
    decision = gate_decision(result, threshold)
    filigree_block = _emit_filigree(result.findings, filigree)
    return {
        "files_scanned": result.files_scanned,
        "findings": [_finding_to_dict(f) for f in result.findings],
```

to:

```python
    decision = gate_decision(result, threshold)
    filigree_block = _emit_filigree(result.findings, filigree)
    try:
        selected = filter_findings(result.findings, args.get("where"))
    except ValueError as exc:
        # An unknown filter key is agent-actionable -> isError result, not a crash.
        raise ToolError(str(exc)) from exc
    return {
        "files_scanned": result.files_scanned,
        "findings": [_finding_to_dict(f) for f in selected],
```

(`summary` and `gate` are unchanged — they remain whole-project facts; Filigree emission also uses the full `result.findings`, not the filtered view.)

- [ ] **Step 4: Add `where` to the scan tool schema + description**

In `_register_tools`, extend the scan tool. Add to its `input_schema` `properties`:

```python
                        "where": {
                            "type": "object",
                            "description": "Filter the returned findings (conjunctive). Keys: "
                            "rule_id, qualname, severity, suppression, kind, path_glob, sink, tier. "
                            "summary/gate still describe the whole project.",
                            "properties": {
                                "rule_id": {"type": "string"},
                                "qualname": {"type": "string"},
                                "severity": {"type": "string", "enum": _SEVERITY_ENUM},
                                "suppression": {"type": "string", "enum": ["active", "baselined", "waived", "judged"]},
                                "kind": {"type": "string"},
                                "path_glob": {"type": "string"},
                                "sink": {"type": "string"},
                                "tier": {"type": "string"},
                            },
                        },
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/mcp/test_server_query_explain.py -v`
Expected: the three B1 tests PASS (the B2 tests added in Part B2 are not yet present).

- [ ] **Step 6: Commit (controller)**

---

### Task 3: CLI parity — `wardline findings` read verb

**Files:**
- Create: `src/wardline/cli/findings.py`
- Modify: `src/wardline/cli/main.py` (register the command)
- Test: `tests/unit/cli/test_findings_cmd.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/cli/test_findings_cmd.py`:

```python
"""WS-B1 CLI parity: `wardline findings` runs a scan and prints filtered findings
as JSONL to stdout (read-only; no emission side effects)."""

import json

from click.testing import CliRunner

from wardline.cli.main import cli

_SRC = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_a(p):\n    return p\n"
    "@trusted\ndef leak_a(p):\n    return read_a(p)\n"
)


def test_findings_filters_by_rule_id(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(cli, ["findings", str(tmp_path), "--where", json.dumps({"rule_id": "PY-WL-101"})])
    assert res.exit_code == 0
    lines = [json.loads(line) for line in res.output.splitlines() if line.strip()]
    assert lines and all(d["rule_id"] == "PY-WL-101" for d in lines)


def test_findings_unknown_key_exits_2(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    res = CliRunner().invoke(cli, ["findings", str(tmp_path), "--where", json.dumps({"bogus": 1})])
    assert res.exit_code == 2
    assert "unknown filter key" in res.output
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/cli/test_findings_cmd.py -v`
Expected: FAIL — no `findings` command registered (`res.exit_code == 2` with "No such command", but the assertions on output/JSONL fail).

- [ ] **Step 3: Implement the command**

Create `src/wardline/cli/findings.py`:

```python
# src/wardline/cli/findings.py
"""`wardline findings` — read-only: scan and print filtered findings as JSONL.

The CLI counterpart of the MCP `scan(where=)` query, sharing core/finding_query
so the capability is identical across surfaces. No file output, no Filigree/Clarion
emission — a pure read lens for an agent driving the CLI."""

from __future__ import annotations

import json
from pathlib import Path

import click

from wardline.core.finding_query import filter_findings
from wardline.core.run import run_scan


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--where", "where_json", default=None, help='JSON filter object, e.g. \'{"rule_id":"PY-WL-106"}\'.')
def findings(path: Path, config_path: Path | None, where_json: str | None) -> None:
    """Scan PATH and print filtered findings as JSONL (read-only)."""
    where = None
    if where_json is not None:
        try:
            where = json.loads(where_json)
        except json.JSONDecodeError as exc:
            click.echo(f"error: --where must be valid JSON: {exc}", err=True)
            raise SystemExit(2) from exc
        if not isinstance(where, dict):
            click.echo("error: --where must be a JSON object", err=True)
            raise SystemExit(2)
    result = run_scan(path, config_path=config_path)
    try:
        selected = filter_findings(result.findings, where)
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    for f in selected:
        click.echo(f.to_jsonl())
```

- [ ] **Step 4: Register the command**

In `src/wardline/cli/main.py`, import and register `findings` next to the other subcommands (mirror how `scan` is registered). Find the existing `from wardline.cli.scan import scan` / `cli.add_command(scan)` pattern and add the analogous two lines:

```python
from wardline.cli.findings import findings
```
```python
cli.add_command(findings)
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/cli/test_findings_cmd.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit (controller)**

---

## PART B2 — Inline explanation (kill the N+1)

### Task 4: Extract `explanation_from_context` (behavior-preserving refactor)

**Files:**
- Modify: `src/wardline/core/explain.py` (extract the projection from `_explain_local`)
- Test: `tests/unit/core/test_explain.py` (add a regression assertion if not already covered)

- [ ] **Step 1: Write the (regression) test**

Add to `tests/unit/core/test_explain.py` (create the file if absent):

```python
"""WS-B2: explanation_from_context is the shared projection; explain_finding still
returns identical output after the extraction."""

from pathlib import Path

from wardline.core.explain import explain_finding

_SRC = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def test_explain_finding_still_projects_provenance(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    # Find the PY-WL-101 fingerprint via a scan, then explain it.
    from wardline.core.run import run_scan

    finding = next(f for f in run_scan(tmp_path).findings if f.rule_id == "PY-WL-101")
    exp = explain_finding(tmp_path, fingerprint=finding.fingerprint)
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"
    assert exp.immediate_tainted_callee == "read_raw"
    assert exp.source_boundary_qualname == "svc.read_raw"
```

- [ ] **Step 2: Run to verify it passes against current code (baseline green)**

Run: `uv run pytest tests/unit/core/test_explain.py -v`
Expected: PASS (this pins current behavior BEFORE the refactor — a refactor guard, not a red-first test).

- [ ] **Step 3: Extract the helper**

In `src/wardline/core/explain.py`, add the `AnalysisContext` type import under the existing `TYPE_CHECKING` block:

```python
if TYPE_CHECKING:
    from wardline.core.finding import Finding
    from wardline.scanner.context import AnalysisContext
```

Add a new public function immediately after the `TaintExplanation` dataclass (after line 38):

```python
def explanation_from_context(finding: Finding, context: AnalysisContext) -> TaintExplanation:
    """Project the cheap provenance slice for one finding from an ALREADY-COMPUTED
    analysis context (no re-analysis). Shared by `_explain_local` (single-finding
    re-run) and the MCP `scan(explain=true)` inliner, so both produce identical
    provenance. Resolves the source boundary ONE hop only (full N-hop chain is the
    Clarion-backed `explain_chain`)."""
    qualname = finding.qualname
    immediate_tainted_callee = context.function_return_callee.get(qualname) if qualname is not None else None
    source_boundary_qualname: str | None = None
    if (
        immediate_tainted_callee is not None
        and "." not in immediate_tainted_callee
        and qualname is not None
        and "." in qualname
    ):
        module = qualname.rsplit(".", 1)[0]
        candidate = f"{module}.{immediate_tainted_callee}"
        if candidate in context.entities and context.function_return_callee.get(candidate) is None:
            source_boundary_qualname = candidate
    prov = context.taint_provenance.get(qualname) if qualname is not None else None
    return TaintExplanation(
        fingerprint=finding.fingerprint,
        rule_id=finding.rule_id,
        sink_qualname=qualname,
        path=finding.location.path,
        line=finding.location.line_start,
        tier_in=finding.properties.get("actual_return"),
        tier_out=finding.properties.get("declared_return"),
        immediate_tainted_callee=immediate_tainted_callee,
        source_boundary_qualname=source_boundary_qualname,
        resolved_call_count=prov.resolved_call_count if prov is not None else 0,
        unresolved_call_count=prov.unresolved_call_count if prov is not None else 0,
    )
```

Then replace the body of `_explain_local` from the `assert result.context is not None` line through its `return TaintExplanation(...)` (lines 77-117) with:

```python
    # A matched finding means analyze() ran to completion, which always sets
    # last_context; ScanResult.context is typed Optional only for the empty-scan
    # case that produces no findings to match here.
    assert result.context is not None
    return explanation_from_context(finding, result.context)
```

- [ ] **Step 4: Run to verify behavior is preserved**

Run: `uv run pytest tests/unit/core/test_explain.py tests/unit/mcp -v`
Expected: PASS — identical provenance output (the extraction is a pure move).

- [ ] **Step 5: Commit (controller)**

---

### Task 5: `scan(explain=true)` inlines provenance on active defects

**Files:**
- Modify: `src/wardline/mcp/server.py` (`_scan` + schema/description + the loop prompt)
- Test: `tests/unit/mcp/test_server_query_explain.py` (add B2 tests)

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/mcp/test_server_query_explain.py`:

```python
def test_explain_inlines_provenance_on_active_defects(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    out = _scan({"explain": True}, tmp_path)
    by_q = {f["qualname"]: f for f in out["findings"] if f["rule_id"] == "PY-WL-101"}
    exp = by_q["svc.leak_a"]["explanation"]
    assert exp["immediate_tainted_callee"] == "read_a"
    assert exp["source_boundary_qualname"] == "svc.read_a"
    assert "tier_in" in exp and "tier_out" in exp


def test_explain_absent_by_default(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    out = _scan({}, tmp_path)
    assert all("explanation" not in f for f in out["findings"])


def test_explain_matches_single_finding_explain(tmp_path):
    # The inlined slice must equal what explain_taint returns for the same finding.
    from wardline.mcp.server import _explain_taint

    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    out = _scan({"explain": True}, tmp_path)
    f = next(f for f in out["findings"] if f["qualname"] == "svc.leak_a" and f["rule_id"] == "PY-WL-101")
    single = _explain_taint({"fingerprint": f["fingerprint"]}, tmp_path)
    assert f["explanation"]["immediate_tainted_callee"] == single["immediate_tainted_callee"]
    assert f["explanation"]["source_boundary_qualname"] == single["source_boundary_qualname"]
    assert f["explanation"]["resolved_call_count"] == single["resolved_call_count"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/mcp/test_server_query_explain.py -k explain -v`
Expected: FAIL — `explain` is ignored, so no `explanation` key exists (KeyError).

- [ ] **Step 3: Implement the inliner**

In `src/wardline/mcp/server.py`, extend the `finding.py` import to add `Kind` and `SuppressionState`, and add the explain helper import (top of file):

```python
from wardline.core.finding import Finding, Kind, Severity, SuppressionState
```
```python
from wardline.core.explain import explanation_from_context
```

Then in `_scan`, replace the findings serialization (the block you wrote in Task 2):

```python
    try:
        selected = filter_findings(result.findings, args.get("where"))
    except ValueError as exc:
        raise ToolError(str(exc)) from exc
    explain = bool(args.get("explain"))
    findings_out: list[dict[str, Any]] = []
    for f in selected:
        d = _finding_to_dict(f)
        if (
            explain
            and f.kind is Kind.DEFECT
            and f.suppressed is SuppressionState.ACTIVE
            and f.qualname is not None
            and result.context is not None
        ):
            exp = explanation_from_context(f, result.context)
            d["explanation"] = {
                "tier_in": exp.tier_in,
                "tier_out": exp.tier_out,
                "immediate_tainted_callee": exp.immediate_tainted_callee,
                "source_boundary_qualname": exp.source_boundary_qualname,
                "resolved_call_count": exp.resolved_call_count,
                "unresolved_call_count": exp.unresolved_call_count,
            }
        findings_out.append(d)
    return {
        "files_scanned": result.files_scanned,
        "findings": findings_out,
```

(Delete the old `"findings": [_finding_to_dict(f) for f in selected],` line — it's replaced by `findings_out`.)

- [ ] **Step 4: Add `explain` to the scan schema + description; update the loop prompt**

In `_register_tools`, add to the scan tool `input_schema` `properties`:

```python
                        "explain": {
                            "type": "boolean",
                            "description": "Inline each active defect's taint provenance "
                            "(immediate tainted callee, source boundary, trust tiers, resolution "
                            "counts) — one call instead of an explain_taint per finding.",
                        },
```

Update the scan tool description to mention it, and rewrite `_LOOP_PROMPT` step 1-2 from the per-finding explain to the one-call shape:

```python
    _LOOP_PROMPT = (
        "Wardline is whole-program and on-disk. The loop:\n"
        "1. Call `scan` with `explain: true` (whole project). Each active defect carries an "
        "inline `explanation` (immediate tainted callee, source boundary, trust tiers) — no "
        "per-finding round-trip. Read `summary.active` and `gate.tripped`.\n"
        "2. For the FULL N-hop chain to the originating boundary (needs a configured Clarion "
        "store), call `explain_taint` with the finding's `qualname` as `sink_qualname` and "
        "`chain: true`.\n"
        "3. Fix at the BOUNDARY, not the sink — add validation/rejection at the right hop.\n"
        "4. Re-`scan`. Only baseline/waiver a finding you have judged a true non-issue, with a reason."
    )
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/mcp/test_server_query_explain.py -v`
Expected: PASS (all B1 + B2 tests).

- [ ] **Step 6: Commit (controller)**

---

### Task 6: Docs + full gate

**Files:**
- Modify: `CHANGELOG.md`
- Verification only otherwise

- [ ] **Step 1: CHANGELOG entry**

Under `## [Unreleased]` → `### Added` in `CHANGELOG.md`, add:

```markdown
- MCP `scan` gains a server-side `where` filter (rule_id/qualname/severity/suppression/kind/
  path_glob/sink/tier) and an `explain: true` mode that inlines each active defect's taint
  provenance — killing the scan-then-N-explains round-trips. New read-only `wardline findings`
  CLI verb shares the same filter core. (WS-B1, WS-B2)
```

- [ ] **Step 2: Full local gate**

Run, expecting all green:
- `uv run ruff check src tests && uv run ruff format --check src tests`
- `uv run mypy`
- `uv run pytest`
- `uv run wardline scan src/wardline --fail-on ERROR`  (dogfood, exit 0)

- [ ] **Step 3: Commit (controller)**

---

## Self-review

**Spec coverage (§4 B1, B2):** B1 (server-side query) = Tasks 1-3 (core filter + MCP `where` + CLI parity verb). B2 (inline/batch explain, kill the N+1) = Tasks 4-5 (`explanation_from_context` extraction + `scan(explain=true)` inliner + loop-prompt rewrite). B3 (lineage) is correctly NOT here — it belongs to Workstream C (delta gate). The frictionless "one round-trip" + "CLI=MCP shared core" criteria are pinned by the parity verb and the inline-vs-single explain equality test.

**Placeholder scan:** none — complete code in every step.

**Type consistency:** `filter_findings(findings, where)` (Task 1) is consumed identically by `_scan` (Task 2) and the CLI `findings` verb (Task 3). `explanation_from_context(finding, context)` (Task 4) returns `TaintExplanation`, whose fields the inliner (Task 5) reads into the `explanation` dict and the parity test compares against `_explain_taint`'s output keys (`immediate_tainted_callee`, `source_boundary_qualname`, `resolved_call_count`). `Kind`/`SuppressionState` imports added in Task 5 match `run.py`'s usage.

**Known limitation (honest, in-scope):** the inline `tier_in`/`tier_out` are populated from `properties.actual_return`/`declared_return`, present for PY-WL-101/109 but not the sink rules (106/107/108 store `tier`/`arg_taint`). This exactly mirrors the existing `explain_taint` behavior (parity preserved); enriching sink-rule explanations is a separate engine task, not part of B.
