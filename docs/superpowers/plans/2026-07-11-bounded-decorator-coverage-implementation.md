# Bounded Decorator Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `decorator_coverage` server-filtered, bounded by default, cursor-honest, and behaviorally identical across MCP and CLI while preserving whole-project summary counts.

**Architecture:** Refactor the core into three phases: build unenriched base rows, compute the whole-project summary, then conjunctively filter and page before optional Loomweave/Filigree enrichment. A frozen query/page contract carries `where`, `max_rows`, `offset`, and `full`; both MCP and CLI pass that contract to the same builder. The response always distinguishes whole-project `summary`, `filtered_total`, returned `rows`, and an advancing `truncation` block.

**Tech Stack:** Python dataclasses, stdlib `fnmatch`, Click, MCP JSON Schema, pytest, golden JSON, Filigree CLI

---

## File map

- Modify: `src/wardline/core/decorator_coverage.py:1-243` — pure base-row construction, filter validation, page calculation, and page-only enrichment.
- Modify: `src/wardline/weft_decorator_coverage.py:1-53` — pass shared query controls without changing optional-provider behavior.
- Modify: `src/wardline/mcp/server.py:2936-3140, 3142-3175` — handler inputs, structured output schema, tool schema, and loud argument errors.
- Modify: `src/wardline/cli/decorator_coverage.py:14-89` — parity options, JSON response, and human truncation text.
- Modify: `tests/unit/core/test_decorator_coverage.py:1-134` — filter/page ordering, whole-summary, page-only enrichment, and invalid-input tests.
- Modify: `tests/unit/mcp/test_server_decorator_coverage.py:1-34` — default bound, paging, filtering, full escape hatch, and tool errors.
- Modify: `tests/unit/cli/test_decorator_coverage_cmd.py:1-32` — CLI/MCP query parity and human truncation output.
- Modify: `tests/conformance/test_mcp_structured_output.py:294-297` — validate the expanded structured response.
- Modify: `tests/conformance/mcp_output_schemas.golden.json:475` — regenerate only the `decorator_coverage` schema through the repository golden workflow.

## Task 1: Claim the ticket and pin the response contract in core tests

**Files:**
- Modify: `tests/unit/core/test_decorator_coverage.py:1-134`
- Tracker: `wardline-550ea44e53`

- [ ] **Step 1: Start work atomically on the current release branch**

```bash
filigree start-work wardline-550ea44e53 \
  --assignee codex --actor john --advance \
  --commit "release/consolidation-2026-06-26@388f3841d4d0"
filigree add-comment wardline-550ea44e53 \
  "Root cause: decorator_coverage constructs identity and work enrichment for every declared row before returning one unbounded rows array. There is no shared core query/page contract, so neither MCP nor CLI can bound the expensive/open-world work." \
  --actor john
```

Expected: task is `in_progress`, assigned to `codex`, with the release branch/head claim anchor.

- [ ] **Step 2: Expand the core fixture to exceed the default page**

Replace the fixed three-row-only helper with a generator while retaining `_SRC` for the existing detailed assertions:

```python
def _many_project(tmp_path: Path, count: int = 30) -> Path:
    source = "from wardline.decorators import trusted\n" + "\n".join(
        f"@trusted\ndef f{i:02d}():\n    return {i}\n" for i in range(count)
    )
    (tmp_path / "many.py").write_text(source, encoding="utf-8")
    return tmp_path
```

- [ ] **Step 3: Write failing default-page and whole-summary tests**

```python
def test_default_page_is_bounded_and_summary_is_whole_project(tmp_path: Path) -> None:
    out = build_decorator_coverage(_many_project(tmp_path)).to_dict()

    assert out["summary"]["total"] == 30
    assert out["filtered_total"] == 30
    assert len(out["rows"]) == 25
    assert out["truncation"] == {
        "truncated": True,
        "shown": 25,
        "total": 30,
        "page_size": 25,
        "next_offset": 25,
    }

def test_second_page_advances_and_finishes(tmp_path: Path) -> None:
    out = build_decorator_coverage(_many_project(tmp_path), offset=25).to_dict()

    assert [row["qualname"] for row in out["rows"]] == [f"many.f{i:02d}" for i in range(25, 30)]
    assert out["summary"]["total"] == 30
    assert out["filtered_total"] == 30
    assert out["truncation"]["truncated"] is False
    assert out["truncation"]["next_offset"] is None
```

- [ ] **Step 4: Write the full conjunctive filter matrix**

Use hand-built `DecoratorCoverageBaseRow` objects for a pure query unit test so no scan behavior obscures filter failures:

```python
@pytest.mark.parametrize(
    ("where", "expected"),
    [
        ({"qualname": "svc.clean"}, ["svc.clean"]),
        ({"path_glob": "svc/*.py"}, ["svc.clean", "svc.leaky"]),
        ({"declared_tier": "ASSURED"}, ["svc.clean"]),
        ({"actual_tier": "UNKNOWN_RAW"}, ["svc.leaky"]),
        ({"verdict": "defect"}, ["svc.leaky"]),
        ({"finding_state": "suppressed"}, ["svc.old"]),
        ({"has_active_findings": True}, ["svc.leaky"]),
        (
            {"path_glob": "svc/*.py", "verdict": "defect", "has_active_findings": True},
            ["svc.leaky"],
        ),
    ],
)
def test_filter_base_rows_is_conjunctive(where: dict[str, object], expected: list[str]) -> None:
    assert [row.qualname for row in filter_decorator_rows(_base_rows(), where)] == expected
```

Add negative cases:

```python
@pytest.mark.parametrize(
    "where",
    [
        {"unknown": "x"},
        {"verdict": "green"},
        {"finding_state": "waived"},
        {"has_active_findings": "false"},
    ],
)
def test_invalid_filter_fails_loudly(where: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="filter|allowed|boolean"):
        filter_decorator_rows(_base_rows(), where)

@pytest.mark.parametrize(("kwargs", "message"), [({"offset": -1}, "offset"), ({"max_rows": -1}, "max_rows"), ({"max_rows": 0}, "positive")])
def test_invalid_page_controls_fail_loudly(tmp_path: Path, kwargs: dict[str, int], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_decorator_coverage(_project(tmp_path), **kwargs)
```

- [ ] **Step 5: Prove filtering and paging happen before enrichment**

Make `_Bindings` and `_Work` record calls, then add:

```python
def test_only_returned_page_is_enriched(tmp_path: Path) -> None:
    bindings = _RecordingBindings()
    work = _RecordingWork()

    out = build_decorator_coverage(
        _many_project(tmp_path),
        where={"path_glob": "many.py"},
        max_rows=2,
        offset=1,
        binding_provider=bindings,
        work_provider=work,
    ).to_dict()

    shown = [row["qualname"] for row in out["rows"]]
    assert shown == ["many.f01", "many.f02"]
    assert bindings.calls == shown
    assert work.calls == [f"loomweave:eid:{name}" for name in shown]
```

- [ ] **Step 6: Run the core tests to verify red behavior**

Run: `uv run pytest tests/unit/core/test_decorator_coverage.py -q`

Expected: FAIL because the current report has only `summary`/`rows`, accepts no query arguments, and enriches all rows.

## Task 2: Implement local query, paging, then page-only enrichment

**Files:**
- Modify: `src/wardline/core/decorator_coverage.py:1-243`
- Modify: `src/wardline/weft_decorator_coverage.py:29-52`

- [ ] **Step 1: Add closed query vocabularies and base/page values**

Add near the top of `core/decorator_coverage.py`:

```python
from collections.abc import Mapping, Sequence
from fnmatch import fnmatch

DEFAULT_DECORATOR_COVERAGE_ROWS = 25
_FILTER_KEYS = frozenset(
    {"qualname", "path_glob", "declared_tier", "actual_tier", "verdict", "finding_state", "has_active_findings"}
)
_VERDICTS = frozenset({"clean", "defect", "unknown"})
_FINDING_STATES = frozenset({"clean", "defect", "unknown", "suppressed"})

@dataclass(frozen=True, slots=True)
class DecoratorCoverageBaseRow:
    qualname: str
    path: str | None
    line: int | None
    decorators: tuple[str, ...]
    declared_tier: str | None
    actual_tier: str | None
    verdict: str
    finding_state: str
    active_finding_fingerprints: tuple[str, ...] = ()
    suppressed_finding_fingerprints: tuple[str, ...] = ()

@dataclass(frozen=True, slots=True)
class CoverageTruncation:
    truncated: bool
    shown: int
    total: int
    page_size: int | None
    next_offset: int | None
```

Keep `DecoratorCoverageRow` as the externally serialized enriched row. Convert tuples back to lists in `to_dict()`.

- [ ] **Step 2: Implement strict conjunctive filtering**

```python
def filter_decorator_rows(
    rows: Sequence[DecoratorCoverageBaseRow],
    where: Mapping[str, object] | None,
) -> list[DecoratorCoverageBaseRow]:
    if not where:
        return list(rows)
    unknown = set(where) - _FILTER_KEYS
    if unknown:
        raise ValueError(f"unknown filter key(s): {sorted(unknown)}; allowed: {sorted(_FILTER_KEYS)}")
    if (value := where.get("has_active_findings")) is not None and not isinstance(value, bool):
        raise ValueError("filter 'has_active_findings' must be a boolean")
    if (value := where.get("verdict")) is not None and value not in _VERDICTS:
        raise ValueError(f"unknown verdict {value!r}; allowed: {sorted(_VERDICTS)}")
    if (value := where.get("finding_state")) is not None and value not in _FINDING_STATES:
        raise ValueError(f"unknown finding_state {value!r}; allowed: {sorted(_FINDING_STATES)}")

    def matches(row: DecoratorCoverageBaseRow) -> bool:
        return (
            (where.get("qualname") is None or row.qualname == where["qualname"])
            and (where.get("path_glob") is None or (row.path is not None and fnmatch(row.path, str(where["path_glob"]))))
            and (where.get("declared_tier") is None or row.declared_tier == where["declared_tier"])
            and (where.get("actual_tier") is None or row.actual_tier == where["actual_tier"])
            and (where.get("verdict") is None or row.verdict == where["verdict"])
            and (where.get("finding_state") is None or row.finding_state == where["finding_state"])
            and (
                where.get("has_active_findings") is None
                or bool(row.active_finding_fingerprints) is where["has_active_findings"]
            )
        )

    return [row for row in rows if matches(row)]
```

Validate all string-valued filters are strings before matching; tier values remain open vocabulary, while verdict/finding state are closed.

- [ ] **Step 3: Split base-row construction from enrichment and page before network work**

Refactor `decorator_coverage_from_scan` into this sequence:

```python
base_rows = _base_rows_from_scan(result, context)  # sorted by qualname; no provider calls
summary = _summary(base_rows)                     # whole project, before where
selected = filter_decorator_rows(base_rows, where)
filtered_total = len(selected)
limit = None if full else (max_rows if max_rows is not None else DEFAULT_DECORATOR_COVERAGE_ROWS)
if offset < 0:
    raise ValueError("offset must be a non-negative integer")
if limit is not None and limit < 1:
    raise ValueError("max_rows must be a positive integer")
page = selected[offset:] if limit is None else selected[offset : offset + limit]
end = offset + len(page)
truncated = end < filtered_total
if truncated and end <= offset:
    raise ValueError("truncated decorator coverage page did not advance")
next_offset = end if truncated else None
rows = [_enrich(row, binding_provider, work_provider) for row in page]
```

Change `DecoratorCoverageReport` to carry `summary`, `filtered_total`, `rows`, and `truncation` as stored frozen fields. `summary` must never be recomputed from the returned page.

- [ ] **Step 4: Thread the same arguments through the live builder**

Add keyword-only `where: Mapping[str, object] | None = None`, `max_rows: int | None = None`, `offset: int = 0`, and `full: bool = False` to `build_decorator_coverage()` and `build_weft_decorator_coverage()`. Pass values unchanged into core; do not perform Loomweave capability discovery or construct the Filigree provider until after `run_scan`, but provider construction may remain before the core call because no per-row network requests occur until `_enrich`.

- [ ] **Step 5: Run core tests green**

Run: `uv run pytest tests/unit/core/test_decorator_coverage.py -q`

Expected: PASS; the 30-row fixture returns 25 rows by default, next offset 25, and exactly the displayed page is enriched.

## Task 3: Add MCP query/page inputs and structured output

**Files:**
- Modify: `tests/unit/mcp/test_server_decorator_coverage.py:1-34`
- Modify: `src/wardline/mcp/server.py:2936-3175`
- Modify: `tests/conformance/test_mcp_structured_output.py:294-297`

- [ ] **Step 1: Write MCP red tests for bounds, paging, filtering, full, and errors**

Add a helper that creates 30 decorated functions and assert:

```python
def test_mcp_default_is_bounded_and_pageable(tmp_path: Path) -> None:
    _write_many(tmp_path, 30)
    server = WardlineMCPServer(root=tmp_path)
    first = _mcp_call(server, "decorator_coverage", {})
    second = _mcp_call(server, "decorator_coverage", {"offset": first["truncation"]["next_offset"]})
    assert len(first["rows"]) == 25
    assert first["summary"]["total"] == first["filtered_total"] == 30
    assert second["truncation"]["next_offset"] is None

def test_mcp_where_is_server_side_and_full_lifts_cap(tmp_path: Path) -> None:
    _write_many(tmp_path, 30)
    server = WardlineMCPServer(root=tmp_path)
    filtered = _mcp_call(server, "decorator_coverage", {"where": {"qualname": "svc.f29"}})
    full = _mcp_call(server, "decorator_coverage", {"full": True})
    assert [row["qualname"] for row in filtered["rows"]] == ["svc.f29"]
    assert filtered["summary"]["total"] == 30 and filtered["filtered_total"] == 1
    assert len(full["rows"]) == 30 and full["truncation"]["truncated"] is False
```

Parameterize raw RPC error tests for unknown `where`, `offset=-1`, `max_rows=-1`, `max_rows=0`, and string `full="false"`; expected result has `isError: true` and no report payload.

- [ ] **Step 2: Parse MCP controls before invoking the core builder**

In `_decorator_coverage`, mirror the scan handler's strict guards:

```python
where = args.get("where")
if where is not None and not isinstance(where, dict):
    raise ToolError("where must be an object")
max_rows = args.get("max_rows")
if max_rows is not None and (
    not isinstance(max_rows, int) or isinstance(max_rows, bool) or max_rows < 1
):
    raise ToolError("max_rows must be a positive integer")
offset = args.get("offset", 0)
if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
    raise ToolError("offset must be a non-negative integer")
full = _bool_arg(args, "full", False)
try:
    report = build_weft_decorator_coverage(
        path,
        loomweave_client=loomweave,
        filigree_url=filigree_url,
        config_path=_cfg(args, root),
        confine_to_root=True,
        where=where,
        max_rows=max_rows,
        offset=offset,
        full=full,
    )
except ValueError as exc:
    raise ToolError(str(exc)) from exc
```

- [ ] **Step 3: Expand MCP schemas without duplicating row definitions**

Add `where`, `max_rows` (integer, minimum 1), `offset` (integer, minimum 0), and `full` (boolean) to `_DECORATOR_COVERAGE_TOOL.input_schema`. In `_DECORATOR_COVERAGE_OUTPUT_SCHEMA`, retain the existing row item schema unchanged and add:

```python
"filtered_total": {"type": "integer", "minimum": 0},
"truncation": {
    "type": "object",
    "properties": {
        "truncated": {"type": "boolean"},
        "shown": {"type": "integer", "minimum": 0},
        "total": {"type": "integer", "minimum": 0},
        "page_size": {"type": ["integer", "null"], "minimum": 1},
        "next_offset": {"type": ["integer", "null"], "minimum": 0},
    },
    "required": ["truncated", "shown", "total", "page_size", "next_offset"],
    "additionalProperties": False,
},
```

Require `summary`, `filtered_total`, `rows`, and `truncation`. Describe `summary` as whole-project and `truncation.total` as filtered total.

- [ ] **Step 4: Validate structured output**

Update `test_decorator_coverage_structured_output` to assert `filtered_total == 0`, `rows == []`, and a complete non-truncated block on the empty fixture, then run:

```bash
uv run pytest tests/unit/mcp/test_server_decorator_coverage.py tests/conformance/test_mcp_structured_output.py -q
```

Expected: PASS; malformed controls return typed tool errors before scanning/enrichment.

## Task 4: Add CLI parity and human truncation honesty

**Files:**
- Modify: `tests/unit/cli/test_decorator_coverage_cmd.py:1-32`
- Modify: `src/wardline/cli/decorator_coverage.py:14-89`

- [ ] **Step 1: Write failing CLI parity tests**

```python
def test_cli_query_page_matches_core_contract(tmp_path: Path) -> None:
    _write_many(tmp_path, 30)
    result = CliRunner().invoke(
        cli,
        ["decorator-coverage", str(tmp_path), "--where", "qualname=svc.f29", "--max-rows", "2", "--offset", "0"],
    )
    assert result.exit_code == 0, result.output
    out = json.loads(result.output)
    assert out["summary"]["total"] == 30
    assert out["filtered_total"] == 1
    assert [row["qualname"] for row in out["rows"]] == ["svc.f29"]

def test_cli_human_announces_truncation(tmp_path: Path) -> None:
    _write_many(tmp_path, 30)
    result = CliRunner().invoke(cli, ["decorator-coverage", str(tmp_path), "--format", "human"])
    assert result.exit_code == 0
    assert "Showing 25 of 30 filtered rows; next offset: 25" in result.output
```

Add failure assertions for `--offset -1`, `--max-rows 0`, unknown filter key, invalid closed vocabulary, and non-boolean `has_active_findings`.

- [ ] **Step 2: Expose the same controls through Click**

Add repeatable `--where KEY=VALUE`, `--max-rows` with `IntRange(min=1)`, `--offset` with `IntRange(min=0)`, and `--full/--no-full`. Parse `has_active_findings=true|false` into a real boolean; reject malformed pairs and any other boolean spelling with `click.BadParameter`. Pass the resulting dict and controls to `build_weft_decorator_coverage` unchanged.

Do not add CLI-only filter keys. Core remains the authority for allowed keys and closed vocabularies; catch its `ValueError` alongside `WardlineError` and exit 2.

- [ ] **Step 3: Update human rendering**

After the whole-project summary line, print:

```python
truncation = report["truncation"]
assert isinstance(truncation, dict)
if truncation["truncated"]:
    click.echo(
        f"Showing {truncation['shown']} of {report['filtered_total']} filtered rows; "
        f"next offset: {truncation['next_offset']}"
    )
else:
    click.echo(f"Showing {truncation['shown']} of {report['filtered_total']} filtered rows")
```

- [ ] **Step 4: Run CLI and core parity tests**

Run:

```bash
uv run pytest tests/unit/cli/test_decorator_coverage_cmd.py tests/unit/core/test_decorator_coverage.py -q
```

Expected: PASS; JSON shape matches MCP/core, and human output never silently truncates.

## Task 5: Update the frozen schema, verify, commit, and close

**Files:**
- Modify: `tests/conformance/mcp_output_schemas.golden.json:475`
- All files listed above.
- Tracker: `wardline-550ea44e53`.

- [ ] **Step 1: Run the golden test to see the expected schema-only failure**

Run: `uv run pytest tests/conformance/test_mcp_output_schema_golden.py -q`

Expected: FAIL showing only the `decorator_coverage` schema changed.

- [ ] **Step 2: Regenerate with the repository-approved golden update mode**

Run: `UPDATE_GOLDENS=1 uv run pytest tests/conformance/test_mcp_output_schema_golden.py -q`

Expected: PASS and only `tests/conformance/mcp_output_schemas.golden.json` changes; inspect the diff to confirm existing row schemas were not weakened.

- [ ] **Step 3: Run focused contract suites**

```bash
uv run pytest \
  tests/unit/core/test_decorator_coverage.py \
  tests/unit/mcp/test_server_decorator_coverage.py \
  tests/unit/cli/test_decorator_coverage_cmd.py \
  tests/conformance/test_mcp_structured_output.py \
  tests/conformance/test_mcp_output_schema_golden.py -q
```

Expected: PASS.

- [ ] **Step 4: Run the complete repository gate**

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest -q
uv run wardline scan . --fail-on ERROR
git diff --check
git status --short
```

Expected: every command exits 0; scan gate is clean; no generated scan artifacts or unrelated files appear.

- [ ] **Step 5: Commit exactly this ticket**

```bash
git add \
  src/wardline/core/decorator_coverage.py \
  src/wardline/weft_decorator_coverage.py \
  src/wardline/mcp/server.py \
  src/wardline/cli/decorator_coverage.py \
  tests/unit/core/test_decorator_coverage.py \
  tests/unit/mcp/test_server_decorator_coverage.py \
  tests/unit/cli/test_decorator_coverage_cmd.py \
  tests/conformance/test_mcp_structured_output.py \
  tests/conformance/mcp_output_schemas.golden.json
git commit -m "feat: bound and filter decorator coverage"
TICKET_SHA="$(git rev-parse HEAD)"
```

Expected: one ticket-isolated commit on `release/consolidation-2026-06-26`.

- [ ] **Step 6: Attach verification and close the ticket**

```bash
filigree add-comment wardline-550ea44e53 \
  "Implemented shared core where/max_rows/offset/full semantics. Summary remains whole-project; filtered_total and truncation describe the filtered page; only returned rows receive Loomweave/Filigree enrichment. MCP schema, structured output, CLI JSON/human output, and golden are green. Full Ruff, format, mypy, pytest, Wardline gate, and diff checks pass. Commit ${TICKET_SHA}." \
  --actor john
filigree close wardline-550ea44e53 \
  --reason "Bounded decorator coverage implemented and verified" \
  --commit "release/consolidation-2026-06-26@${TICKET_SHA}" \
  --actor john
```

Expected: `wardline-550ea44e53` is `closed`; its parent `wardline-8528e67192` is not changed by this plan.
