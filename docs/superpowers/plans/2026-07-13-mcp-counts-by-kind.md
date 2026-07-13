# MCP Scan `counts_by_kind` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to implement this plan task-by-task. Use
> `superpowers:test-driven-development` for every production change and
> `superpowers:verification-before-completion` before any completion claim.

**Goal:** Add a required, deterministic `counts_by_kind` object to the top-level MCP
`scan.summary`, containing zero-filled counts for every canonical Wardline finding kind
and preserving all existing agent-summary and non-MCP output contracts.

**Architecture:** Keep this additive contract in the MCP adapter. A private pure helper
beside `_scan` counts the unfiltered `ScanResult.findings` population using the canonical
`Kind` enumeration. `_scan` adds that value to its top-level summary before any response-body
filtering, and `_SCAN_OUTPUT_SCHEMA` declares the same exact five-key object. No core summary,
agent-summary, CLI, scan-job, JSONL, SARIF, Legis, or Plainweave artifact contract changes.

**Tech Stack:** Python 3.12+, `StrEnum`, pytest, jsonschema, Ruff, mypy, Wardline MCP,
the committed MCP output-schema golden, and the Wardline trust-boundary gate.

---

## Execution Preconditions

- Execute in the dedicated worktree `.worktrees/mcp-counts-by-kind` on branch
  `codex/mcp-counts-by-kind`, based on approved design commit `f7502b97`.
- Read and preserve
  `docs/superpowers/specs/2026-07-12-mcp-counts-by-kind-design.md` unchanged.
- Start only Filigree issue `wardline-8ae1d6a995`. Do not start or modify the state of
  `wardline-6114834aef`; that is a separate Plainweave federation-seam task.
- Use RED-GREEN-REFACTOR: run every named RED test before the production change that
  makes it pass.
- The counts are computed from `result.findings`, not the body-filtered `selected` list
  and not any `agent_summary` bucket.
- Do not modify the separate summary contract in `_SCAN_FILE_FINDINGS_OUTPUT_SCHEMA`.
- Do not modify the pre-existing unrelated formatting drift in
  `tests/unit/install/test_doctor_filigree_auth.py`.

## File Map

- Modify `src/wardline/mcp/server.py` — import `Kind`, add `_counts_by_kind`, emit the
  field, and declare its exact schema.
- Create `tests/unit/mcp/test_scan_counts_by_kind.py` — pure counting, runtime scope,
  filtering/paging invariance, exact schema, and compatibility regressions.
- Modify `tests/unit/mcp/test_scan_affected_mcp.py` — pin affected-scan sum semantics.
- Modify `tests/conformance/mcp_output_schemas.golden.json` — deliberately regenerate
  the frozen output-schema contract from the live tool surface.
- Modify `tests/conformance/test_mcp_output_schema_golden.py` — update the same-commit
  blob pin for the regenerated golden.
- Modify `docs/reference/mcp.md` — document the exact five-key top-level summary member.
- Modify `docs/guides/agents.md` — explain whole-scan counts versus filtered/paged bodies.
- Modify `CHANGELOG.md` — record the additive MCP output-schema change.
- Modify `docs/reference/finding-lifecycle-vocabulary.md` and
  `tests/docs/test_glossary_vocabulary.py` only if the server source-line anchors shift;
  update the anchors to the live lines without changing their semantic target.

### Task 1: Count the canonical finding-kind population with a pure helper

**Files:**
- Create: `tests/unit/mcp/test_scan_counts_by_kind.py`
- Modify: `src/wardline/mcp/server.py:40,982-988`

- [ ] **Step 1: Write the failing pure-helper tests**

Create `tests/unit/mcp/test_scan_counts_by_kind.py` with the following foundation:

```python
from __future__ import annotations

from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.mcp.server import _counts_by_kind


def _finding(
    kind: Kind,
    index: int,
    *,
    suppressed: SuppressionState = SuppressionState.ACTIVE,
) -> Finding:
    severity = Severity.ERROR if kind is Kind.DEFECT else Severity.NONE
    return Finding(
        rule_id=f"TEST-{index}",
        message=f"test finding {index}",
        severity=severity,
        kind=kind,
        location=Location(path="fixture.py", line_start=index + 1),
        fingerprint=f"fp-{index}",
        suppressed=suppressed,
    )


def test_counts_by_kind_uses_canonical_order_and_counts_suppressed_findings() -> None:
    findings = [
        _finding(Kind.DEFECT, 0),
        _finding(Kind.FACT, 1),
        _finding(Kind.CLASSIFICATION, 2),
        _finding(Kind.METRIC, 3),
        _finding(Kind.SUGGESTION, 4),
        _finding(Kind.DEFECT, 5, suppressed=SuppressionState.BASELINED),
    ]

    counts = _counts_by_kind(findings)

    assert list(counts) == [kind.value for kind in Kind]
    assert counts == {
        "defect": 2,
        "fact": 1,
        "classification": 1,
        "metric": 1,
        "suggestion": 1,
    }
    assert sum(counts.values()) == len(findings)


def test_counts_by_kind_zero_fills_absent_kinds() -> None:
    counts = _counts_by_kind([_finding(Kind.FACT, 0)])

    assert counts == {
        "defect": 0,
        "fact": 1,
        "classification": 0,
        "metric": 0,
        "suggestion": 0,
    }
```

- [ ] **Step 2: Run the pure-helper tests to verify RED**

Run:

```bash
uv run pytest -q \
  tests/unit/mcp/test_scan_counts_by_kind.py::test_counts_by_kind_uses_canonical_order_and_counts_suppressed_findings \
  tests/unit/mcp/test_scan_counts_by_kind.py::test_counts_by_kind_zero_fills_absent_kinds
```

Expected: collection fails because `wardline.mcp.server` has no `_counts_by_kind`.

- [ ] **Step 3: Implement the pure helper beside `_scan`**

In `src/wardline/mcp/server.py`, widen the existing import:

```python
from wardline.core.finding import Finding, Kind, Severity
```

Add this helper immediately after `_scan` and before `_SCAN_OUTPUT_SCHEMA`:

```python
def _counts_by_kind(findings: list[Finding]) -> dict[str, int]:
    """Count the complete finding population in canonical Kind order."""
    counts = {kind.value: 0 for kind in Kind}
    for finding in findings:
        counts[finding.kind.value] += 1
    return counts
```

Do not coerce strings and do not add an `unknown` bucket. A non-`Kind` internal value
must fail loudly.

- [ ] **Step 4: Verify GREEN and local static quality**

Run:

```bash
uv run pytest -q tests/unit/mcp/test_scan_counts_by_kind.py
uv run ruff check src/wardline/mcp/server.py tests/unit/mcp/test_scan_counts_by_kind.py
uv run ruff format --check src/wardline/mcp/server.py tests/unit/mcp/test_scan_counts_by_kind.py
uv run mypy src/wardline/mcp/server.py tests/unit/mcp/test_scan_counts_by_kind.py
```

Expected: two tests pass and all static checks are clean.

- [ ] **Step 5: Commit the helper and its direct tests**

```bash
git add src/wardline/mcp/server.py tests/unit/mcp/test_scan_counts_by_kind.py
git commit -m "feat(mcp): count findings by canonical kind"
```

### Task 2: Expose exact whole-scan counts in the runtime response and schema

**Files:**
- Modify: `tests/unit/mcp/test_scan_counts_by_kind.py`
- Modify: `tests/unit/mcp/test_scan_affected_mcp.py:67-79`
- Modify: `src/wardline/mcp/server.py:944-959,989-1019`
- Modify: `tests/conformance/mcp_output_schemas.golden.json`
- Modify: `tests/conformance/test_mcp_output_schema_golden.py`

- [ ] **Step 1: Add failing runtime invariance and compatibility tests**

Extend `tests/unit/mcp/test_scan_counts_by_kind.py`:

```python
from pathlib import Path

from wardline.mcp.server import _SCAN_OUTPUT_SCHEMA, _scan


def _many_leaks(count: int) -> str:
    head = (
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\n"
        "def raw(p):\n"
        "    return p\n"
    )
    leaks = "".join(
        f"@trusted\ndef leak_{index}(p):\n    return raw(p)\n"
        for index in range(count)
    )
    return head + leaks


def _baseline_defects(root: Path) -> None:
    from wardline.core.baseline import write_baseline
    from wardline.core.paths import baseline_path
    from wardline.core.run import run_scan

    defects = [finding for finding in run_scan(root).findings if finding.kind is Kind.DEFECT]
    path = baseline_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_baseline(path, defects)


def test_scan_counts_by_kind_describe_whole_result_under_body_controls(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_many_leaks(4), encoding="utf-8")
    _baseline_defects(tmp_path)

    common = {"trust_suppressions": True}
    full = _scan({**common, "full": True}, root=tmp_path)
    variants = (
        _scan({**common, "where": {"qualname": "svc.leak_0"}}, root=tmp_path),
        _scan({**common, "offset": 1, "max_findings": 1}, root=tmp_path),
        _scan({**common, "summary_only": True}, root=tmp_path),
        _scan({**common, "include_suppressed": False}, root=tmp_path),
    )

    counts = full["summary"]["counts_by_kind"]
    assert list(counts) == [kind.value for kind in Kind]
    assert counts["defect"] == 4
    assert full["summary"]["baselined"] == 4
    assert sum(counts.values()) == full["summary"]["total"]
    assert all(result["summary"]["counts_by_kind"] == counts for result in variants)


def test_scan_counts_by_kind_schema_is_exact_and_required() -> None:
    summary = _SCAN_OUTPUT_SCHEMA["properties"]["summary"]
    counts = summary["properties"]["counts_by_kind"]

    assert counts == {
        "type": "object",
        "description": (
            "Whole-scan finding counts by canonical finding kind, "
            "including active and suppressed findings."
        ),
        "properties": {
            "defect": {"type": "integer", "minimum": 0},
            "fact": {"type": "integer", "minimum": 0},
            "classification": {"type": "integer", "minimum": 0},
            "metric": {"type": "integer", "minimum": 0},
            "suggestion": {"type": "integer", "minimum": 0},
        },
        "required": ["defect", "fact", "classification", "metric", "suggestion"],
        "additionalProperties": False,
    }
    assert "counts_by_kind" in summary["required"]


def test_nested_agent_summary_contract_is_unchanged(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_many_leaks(1), encoding="utf-8")

    output = _scan({"full": True}, root=tmp_path)

    assert output["agent_summary"]["schema"] == "wardline-agent-summary-1"
    assert "counts_by_kind" not in output["agent_summary"]
    assert "counts_by_kind" not in output["agent_summary"]["summary"]
```

In `test_inline_entity_list_scopes_analysis` in
`tests/unit/mcp/test_scan_affected_mcp.py`, add:

```python
    assert sum(out["summary"]["counts_by_kind"].values()) == out["summary"]["total"]
    assert out["summary"]["counts_by_kind"]["defect"] == 1
```

The second assertion pins the actual affected result, not the whole project: the
unaffected `other.py` defect must not be counted.

- [ ] **Step 2: Run the new runtime and schema tests to verify RED**

Run:

```bash
uv run pytest -q \
  tests/unit/mcp/test_scan_counts_by_kind.py::test_scan_counts_by_kind_describe_whole_result_under_body_controls \
  tests/unit/mcp/test_scan_counts_by_kind.py::test_scan_counts_by_kind_schema_is_exact_and_required \
  tests/unit/mcp/test_scan_affected_mcp.py::test_inline_entity_list_scopes_analysis
```

Expected: failures show the top-level runtime member and schema member are absent.

- [ ] **Step 3: Add the runtime member from the unfiltered result**

In `_scan`'s top-level `response["summary"]`, immediately after `unanalyzed`, add:

```python
            "counts_by_kind": _counts_by_kind(result.findings),
```

Do not use `selected`, `agent_summary`, `include_suppressed`, or a page slice.

- [ ] **Step 4: Add the exact closed output schema**

In `_SCAN_OUTPUT_SCHEMA` only, change the summary description from “Whole-project”
to “Whole-scan” and expand its informational wording to include suggestions. Add:

```python
                "counts_by_kind": {
                    "type": "object",
                    "description": (
                        "Whole-scan finding counts by canonical finding kind, "
                        "including active and suppressed findings."
                    ),
                    "properties": {
                        "defect": {"type": "integer", "minimum": 0},
                        "fact": {"type": "integer", "minimum": 0},
                        "classification": {"type": "integer", "minimum": 0},
                        "metric": {"type": "integer", "minimum": 0},
                        "suggestion": {"type": "integer", "minimum": 0},
                    },
                    "required": ["defect", "fact", "classification", "metric", "suggestion"],
                    "additionalProperties": False,
                },
```

Append `"counts_by_kind"` to the top-level scan summary's `required` list. Do not
touch the similarly shaped summary in `_SCAN_FILE_FINDINGS_OUTPUT_SCHEMA` or the
nested `agent_summary` schema.

- [ ] **Step 5: Demonstrate the frozen-contract RED and regenerate it from the live surface**

First run:

```bash
uv run pytest -q tests/conformance/test_mcp_output_schema_golden.py
```

Expected: the live `scan` output schema differs from the committed golden. Do not
weaken or skip the check. Regenerate the golden immediately, before committing the
schema change:

```bash
uv run python - <<'PY'
import json
from pathlib import Path

from wardline.mcp.protocol import PROTOCOL_VERSION
from wardline.mcp.server import WardlineMCPServer

server = WardlineMCPServer(root=Path("tests/fixtures/sample_project"))
response = server.rpc.dispatch(
    {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}},
    }
)
assert response is not None and "error" not in response, response
assert server.rpc.dispatch(
    {"jsonrpc": "2.0", "method": "notifications/initialized"}
) is None
response = server.rpc.dispatch(
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
)
assert response is not None and "error" not in response, response
schemas = {
    tool["name"]: tool["outputSchema"]
    for tool in response["result"]["tools"]
}
Path("tests/conformance/mcp_output_schemas.golden.json").write_text(
    json.dumps(schemas, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
git hash-object tests/conformance/mcp_output_schemas.golden.json
```

Replace `VENDORED_BLOB_SHA` in
`tests/conformance/test_mcp_output_schema_golden.py` with the printed hash using
`apply_patch`. Inspect the golden diff: only the `scan.summary` contract may change.

- [ ] **Step 6: Verify GREEN across runtime, schema, body controls, parity, and the frozen contract**

Run:

```bash
uv run pytest -q \
  tests/unit/mcp/test_scan_counts_by_kind.py \
  tests/unit/mcp/test_scan_affected_mcp.py \
  tests/unit/mcp/test_server_query_explain.py \
  tests/unit/core/test_cli_mcp_parity.py \
  tests/unit/cli/test_agent_summary_cmd.py \
  tests/conformance/test_mcp_structured_output.py \
  tests/conformance/test_mcp_output_schema_golden.py
uv run ruff check src/wardline/mcp/server.py \
  tests/unit/mcp/test_scan_counts_by_kind.py \
  tests/unit/mcp/test_scan_affected_mcp.py
uv run ruff format --check src/wardline/mcp/server.py \
  tests/unit/mcp/test_scan_counts_by_kind.py \
  tests/unit/mcp/test_scan_affected_mcp.py
uv run mypy src/wardline/mcp/server.py tests/unit/mcp/test_scan_counts_by_kind.py
```

Expected: all focused runtime/parity checks pass, the live schema equals the committed
golden, and its byte pin matches. The schema code, golden bytes, and pin are one atomic
review unit.

- [ ] **Step 7: Commit the MCP runtime and frozen schema contract together**

```bash
git add src/wardline/mcp/server.py \
  tests/unit/mcp/test_scan_counts_by_kind.py \
  tests/unit/mcp/test_scan_affected_mcp.py \
  tests/conformance/mcp_output_schemas.golden.json \
  tests/conformance/test_mcp_output_schema_golden.py
git commit -m "feat(mcp): expose finding-kind counts in scan summary"
```

### Task 3: Document semantics and verify compatibility

**Files:**
- Modify: `docs/reference/mcp.md`
- Modify: `docs/guides/agents.md`
- Modify: `CHANGELOG.md`
- Modify if required: `docs/reference/finding-lifecycle-vocabulary.md`
- Modify if required: `tests/docs/test_glossary_vocabulary.py`

- [ ] **Step 1: Document the exact semantics and compatibility boundary**

Update `docs/reference/mcp.md` and `docs/guides/agents.md` to state:

- `summary.counts_by_kind` is required and always has exactly `defect`, `fact`,
  `classification`, `metric`, and `suggestion` in canonical order;
- missing kinds are zero-filled and the five values sum to `summary.total`;
- it describes the current complete scan result (including suppressed findings), so
  body filters, pagination, `summary_only`, and `include_suppressed` do not change it;
- affected scans count the affected result, while `scope` remains authoritative about
  advisory versus gate-of-record status; and
- the nested `wardline-agent-summary-1` contract remains unchanged.

Correct stale wording in the touched sections: do not call an affected result
“whole-project,” include classifications and suggestions in non-defect descriptions,
and say `where` filters the `agent_summary` finding arrays rather than a removed
top-level `findings` list.

Add an `[Unreleased]` changelog bullet for this additive required MCP scan-summary
member. Do not mention or implement `completeness`, `confidence`, or `advisory`.

- [ ] **Step 2: Repair only genuinely shifted source-line anchors**

Run:

```bash
uv run pytest -q tests/docs/test_glossary_vocabulary.py
```

If it fails because the inserted server lines moved the documented schema anchor,
update the relevant line reference in
`docs/reference/finding-lifecycle-vocabulary.md` and the paired expectation in
`tests/docs/test_glossary_vocabulary.py` to the new live location. Do not broaden or
remove the anchor test.

- [ ] **Step 3: Verify the focused contract and compatibility suite**

Run:

```bash
uv run pytest -q \
  tests/unit/mcp/test_scan_counts_by_kind.py \
  tests/unit/mcp/test_scan_affected_mcp.py \
  tests/unit/mcp/test_server_query_explain.py \
  tests/unit/core/test_cli_mcp_parity.py \
  tests/unit/cli/test_agent_summary_cmd.py \
  tests/cli/test_scan_summary_vocab.py \
  tests/conformance/test_mcp_structured_output.py \
  tests/conformance/test_mcp_output_schema_golden.py \
  tests/docs/test_glossary_vocabulary.py
```

Expected: all tests pass, the live schema equals the committed golden, and both
agent-summary compatibility surfaces remain on `wardline-agent-summary-1` without
`counts_by_kind`.

- [ ] **Step 4: Run full repository verification**

Run:

```bash
uv run ruff check src tests
uv run ruff format --check \
  src/wardline/mcp/server.py \
  tests/unit/mcp/test_scan_counts_by_kind.py \
  tests/unit/mcp/test_scan_affected_mcp.py \
  tests/conformance/test_mcp_output_schema_golden.py \
  tests/docs/test_glossary_vocabulary.py
uv run mypy
git diff --check
git diff --check f7502b97..HEAD
git diff --stat f7502b97..HEAD
uv run pytest -q
uv run wardline scan . --fail-on ERROR --local-only
```

Expected: Ruff and mypy are clean, changed files are formatted, the full pytest suite
passes, `git diff --check` is clean, and the Wardline gate exits 0. Do not run the
known-dirty repo-wide `ruff format --check` as completion evidence; the unchanged
`tests/unit/install/test_doctor_filigree_auth.py` baseline is outside this task.

- [ ] **Step 5: Commit the documentation and any required anchor repair**

```bash
git add CHANGELOG.md \
  docs/reference/mcp.md \
  docs/guides/agents.md
# If and only if Step 2 changed the paired anchor files, inspect their diff and add them explicitly:
# git add docs/reference/finding-lifecycle-vocabulary.md tests/docs/test_glossary_vocabulary.py
git commit -m "docs(mcp): publish finding-kind count contract"
```

Before committing, use `git diff --cached --name-only` and confirm it contains every
changed documentation/anchor file and no unrelated file. Do not mask staging errors.

## Final Audit and Tracker Closeout

- [ ] Inspect `git diff f7502b97...HEAD` and prove every approved-design requirement
  is covered by code, tests, or documentation.
- [ ] Confirm `docs/superpowers/specs/2026-07-12-mcp-counts-by-kind-design.md` is
  byte-identical to commit `f7502b97`.
- [ ] Confirm there are no changes to `ScanSummary`, `AgentSummary`, scan-job artifacts,
  JSONL, SARIF, Legis serialization, configuration, CLI flags, or Plainweave files.
- [ ] Run the path-scoped compatibility guard and require an empty diff:

  ```bash
  git diff --exit-code f7502b97..HEAD -- \
    src/wardline/core/agent_summary.py \
    src/wardline/core/run.py \
    src/wardline/core/scan_jobs.py \
    src/wardline/cli \
    tests/unit/cli
  ```

- [ ] Run `git diff --check f7502b97..HEAD`, `git diff --stat f7502b97..HEAD`, and
  `git status --short`; require the final worktree to be clean.
- [ ] Use `superpowers:requesting-code-review` for a specification-compliance review and
  then a code-quality review; resolve findings and rerun affected verification.
- [ ] Add the implementation commits and verification evidence to
  `wardline-8ae1d6a995`, close that issue, and leave `wardline-6114834aef` untouched.
- [ ] Use `superpowers:finishing-a-development-branch` to present the verified branch
  integration choices; do not merge without the user's selected integration action.
