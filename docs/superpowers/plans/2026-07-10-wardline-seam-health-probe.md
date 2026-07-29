# Wardline Seam-Health Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement PRD-0002 criteria 1 and 2: a read-only `wardline doctor --seams` report with a mandatory reason for every Wardline-owned seam, plus optional consumer probe results that never confuse unsupported, partial, stale, or drifted data with a clean result.

**Architecture:** Put the serialisable seam model, fixed six-seam inventory, local adapters, and optional consumer-probe adapters in `wardline.install.seam_health`; this keeps the logic independent of Click, MCP dispatch, and scan orchestration. CLI renders that one report directly. MCP adds exactly the same report under an optional `seams` property in its existing doctor envelope. Existing production clients/parsers remain the only consumption paths: `LoomweaveClient`/`SeiResolver` for SEI and `parse_affected_scope` for worklists. Current peers do not advertise a reserved-sentinel probe carrier, so the default runtime adapters must return explicit `amber / peer_probe_unsupported`; injected producer fixtures prove Wardline’s real consumer paths and make a future peer capability additive rather than a rewrite.

**Tech Stack:** Python 3.13, Click, MCP JSON Schema, standard-library dataclasses and typing, existing Wardline core/loomweave/filigree helpers, pytest. No new runtime dependencies.

**Design:** `docs/superpowers/specs/2026-07-10-wardline-seam-health-probe-design.md`

---

## File Structure

- Create: `src/wardline/install/seam_health.py` — immutable report model, reason vocabulary, six local adapters, two probe adapters, report builder, and safe JSON projection.
- Modify: `src/wardline/cli/doctor.py` — `--seams`, `--probe`, and `--format json`; preserve all legacy doctor modes byte-for-byte.
- Modify: `src/wardline/mcp/server.py` — typed `seams`/`probe` arguments, optional `seams` output-schema block, shared builder wiring, and accurate network-policy selection.
- Modify: `src/wardline/core/delta_scope.py` — export the one canonical Warpline worklist schema identifier used by the parser and seam adapter; do not change parsing behavior.
- Modify: `src/wardline/_live_oracle.py` — export the named SEI/worklist drift-marker set so the source-drift adapter checks code-owned evidence rather than looking in `tests/` at runtime.
- Modify: `tests/unit/cli/test_doctor.py` — CLI flag validation, human rows, JSON equality, read-only behavior, and Layer-1 exit policy.
- Modify: `tests/unit/mcp/test_server_doctor.py` — MCP validation, report parity, capability policy, and legacy-envelope preservation.
- Modify: `tests/conformance/test_mcp_structured_output.py` — schema-valid `doctor({seams:true})` structured content.
- Modify: `tests/conformance/test_mcp_output_schema_golden.py` and `tests/conformance/mcp_output_schemas.golden.json` — deliberately re-freeze only the existing `doctor` output schema.
- Modify: `tests/unit/core/test_delta_scope.py` — pin the exported worklist schema identifier without changing accepted input shapes.
- Create: `tests/unit/install/test_seam_health.py` — report-model, Layer-1, probe-adapter, redaction, and no-confident-empty tests.
- Create: `tests/conformance/test_seam_health_probe.py` — cross-surface contract and production-client/parser round-trip tests with deterministic injected producer responses.
- Modify: `docs/reference/cli.md` and `docs/reference/mcp.md` — document opt-in read-only seam diagnostics, reason/status meanings, and the MCP input/output additions.

## Contract Decisions Locked Before Coding

1. The report object is always shaped as:

   ```json
   {
     "version": "wardline.seam_health.v1",
     "probe_requested": false,
     "seams": [
       {
         "seam_id": "wardline.filigree_emit",
         "layer1": {"status": "ok", "reason": {"code": "ok", "message": "local evidence is valid"}},
         "layer2": {"status": "not_run", "reason": {"code": "probe_not_requested", "message": "consumer probe was not requested"}}
       }
     ]
   }
   ```

   `key_id`, `next_action`, and `evidence` are optional. Every layer always has a `status` and a non-empty `reason.code` / `reason.message`.

2. The stable seam order is exactly:

   ```python
   SEAM_IDS = (
       "wardline.filigree_emit",
       "wardline.legis_attest",
       "wardline.loomweave_sei_read",
       "wardline.warpline_worklist_read",
       "wardline.delta_scope_artifact",
       "wardline.sei_source_drift",
   )
   ```

3. The allowed reason codes are exactly the design vocabulary: `ok`, `probe_not_requested`, `not_configured`, `dependency_missing`, `peer_unreachable`, `authentication_failed`, `key_missing`, `key_mismatch`, `schema_mismatch`, `scheme_mismatch`, `freshness_mismatch`, `malformed_response`, `partial_result`, `peer_probe_unsupported`, and `local_check_failed`. Validate this at construction time; an adapter may not invent a new reason string.

4. `doctor --seams` runs only the seam builder and exits non-zero only when a Layer-1 result is `error`. `--probe` changes report content but not that exit rule. It never invokes `scan`, writes a file, mints a key, repairs install state, or changes a scan verdict.

5. `doctor --seams --format json` prints the report object above, byte-for-byte equal after JSON decoding to MCP `doctor({"seams": true})["seams"]`. `--format json` and `--probe` are invalid without `--seams`; `--seams` is invalid with legacy `--repair` or `--fix`.

6. Existing no-argument CLI doctor, `--repair`, `--fix`, and MCP `doctor({})` retain their current behavior and output shape. MCP only adds the `seams` member when requested.

7. Evidence must be allowlisted scalar facts only (schema/version, capability name, redacted origin, key-set names, content-hash presence). Never serialize a token, raw key, request URL path/query, raw peer body, traceback, or caller-provided peer URL.

## Task 1: Pin the report contract and fixed inventory

**Files:**
- Create: `tests/unit/install/test_seam_health.py`
- Create: `src/wardline/install/seam_health.py`

- [ ] **Step 1: Write failing model tests.**

Create `tests/unit/install/test_seam_health.py` with tests that construct representative `SeamLayerResult` values and assert all of the following:

```python
import pytest

from wardline.install.seam_health import (
    REASON_CODES,
    SEAM_IDS,
    SeamHealthReport,
    SeamLayerResult,
    SeamPosture,
    SeamReason,
)


def test_report_always_has_the_fixed_six_rows_in_order() -> None:
    report = SeamHealthReport.from_layer_results(
        probe_requested=False,
        layer1={seam: SeamLayerResult.ok("checked") for seam in SEAM_IDS},
    )
    payload = report.to_dict()
    assert [row["seam_id"] for row in payload["seams"]] == list(SEAM_IDS)
    assert all(row["layer2"]["reason"]["code"] == "probe_not_requested" for row in payload["seams"])


def test_every_serialized_layer_has_a_nonempty_reason() -> None:
    layer1 = {seam: SeamLayerResult.ok("local evidence is valid") for seam in SEAM_IDS}
    layer1["wardline.legis_attest"] = SeamLayerResult.amber(
        "key_missing", "no Wardline legis artifact key is configured", next_action="configure WARDLINE_LEGIS_ARTIFACT_KEY"
    )
    report = SeamHealthReport.from_layer_results(probe_requested=False, layer1=layer1)
    for posture in report.to_dict()["seams"]:
        for layer_name in ("layer1", "layer2"):
            reason = posture[layer_name]["reason"]
            assert reason["code"] in REASON_CODES
            assert reason["message"]


def test_unknown_reason_code_is_rejected_at_the_model_boundary() -> None:
    with pytest.raises(ValueError, match="unknown seam-health reason code"):
        SeamReason(code="made_up", message="no")
```

Also assert `to_dict()` omits unset `key_id`, `next_action`, and empty `evidence`; rejects non-string evidence; and never emits a key named `token`, `secret`, `url`, `body`, or `traceback`.

- [ ] **Step 2: Run the focused test and confirm it fails.**

Run: `uv run pytest tests/unit/install/test_seam_health.py -q`

Expected: FAIL because `wardline.install.seam_health` does not exist.

- [ ] **Step 3: Add the pure model and projection.**

Create `src/wardline/install/seam_health.py`. Use frozen, slotted dataclasses and no Click/MCP imports. Define `REASON_CODES`, `SEAM_IDS`, `SeamReason`, `SeamLayerResult`, `SeamPosture`, and `SeamHealthReport`. Give `SeamLayerResult` constructors for `ok`, `amber`, `error`, and `not_run`, but route all of them through the same reason validation.

Implement `SeamHealthReport.from_layer_results()` so it iterates `SEAM_IDS`, raises when an adapter row is absent, and supplies a `not_run("probe_not_requested")` Layer 2 result when `probe_requested` is false. Implement `to_dict()` with explicit dictionaries, not `dataclasses.asdict()`, so only allowlisted optional fields leave the process.

Use these exact serialization rules:

```python
layer = {
    "status": result.status,
    "reason": {"code": result.reason.code, "message": result.reason.message},
}
if result.reason.next_action is not None:
    layer["reason"]["next_action"] = result.reason.next_action
if result.key_id is not None:
    layer["key_id"] = result.key_id
if result.evidence:
    layer["evidence"] = dict(result.evidence)
```

- [ ] **Step 4: Re-run the focused model tests.**

Run: `uv run pytest tests/unit/install/test_seam_health.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the model contract.**

```bash
git add src/wardline/install/seam_health.py tests/unit/install/test_seam_health.py
git commit -m "feat(doctor): add seam-health report model"
```

## Task 2: Add Layer-1 adapters with distinct, redacted reasons

**Files:**
- Modify: `src/wardline/install/seam_health.py`
- Modify: `src/wardline/core/delta_scope.py`
- Modify: `src/wardline/_live_oracle.py`
- Modify: `tests/unit/install/test_seam_health.py`
- Modify: `tests/unit/core/test_delta_scope.py`

- [ ] **Step 1: Write failing Layer-1 tests.**

Extend `tests/unit/install/test_seam_health.py` with injected dependency fakes. Cover this matrix:

| Seam | Green proof | Non-green proof |
| --- | --- | --- |
| Filigree emit | configured URL + accepted existing `FiligreeEmitter.verify_token()` result | no URL → `amber/not_configured`; unreachable → `amber/peer_unreachable`; rejected auth → `amber/authentication_failed`; a partial emit-accounting capability → `amber/partial_result` |
| Legis attest | `load_legis_artifact_key(root)` gives a key and its `wardline.core.legis.key_id()` | absent key → `amber/key_missing`; when ambient existing `LEGIS_WARDLINE_ARTIFACT_KEY` is present but its derived id differs → `amber/key_mismatch`; neither secret appears in `to_dict()` |
| Loomweave SEI read | resolved URL, `require_blake3()` works, and `LoomweaveClient` can be constructed | no URL → `amber/not_configured`; missing extra → `amber/dependency_missing`; construction failure → `error/local_check_failed` |
| Warpline worklist read | `WORKLIST_SCHEMA == "warpline.reverify_worklist.v1"` and the exported parser is callable | altered injected schema capability → `error/schema_mismatch` |
| Delta scope artifact | one exported `DELTA_SCOPE_ARTIFACT_SCHEMA == "wardline.delta_scope.v1"` | altered injected version → `error/schema_mismatch` |
| SEI source drift | exported marker set includes `sei_drift` and `worklist_drift` | missing marker → `error/local_check_failed` |

Use a fake `FiligreeProbe` / `LoomweaveFactory` dependency object passed into the `build_seam_health_report` function; do not monkeypatch global imports. Add a regression asserting every failure has a `next_action` and every message/evidence field excludes `secret-token`, `?query=`, and `/private/path` fixture values.

In `tests/unit/core/test_delta_scope.py`, first assert the new canonical worklist constant is exactly `"warpline.reverify_worklist.v1"` and that current valid full/bare worklist tests still pass.

- [ ] **Step 2: Run these tests and confirm the expected failures.**

Run: `uv run pytest tests/unit/install/test_seam_health.py tests/unit/core/test_delta_scope.py -q`

Expected: FAIL for missing builder/adapters and missing exported contract constants.

- [ ] **Step 3: Implement the adapters and one-source contract constants.**

In `src/wardline/core/delta_scope.py`, define next to the parser limits:

```python
WARPLINE_REVERIFY_WORKLIST_SCHEMA = "warpline.reverify_worklist.v1"
DELTA_SCOPE_ARTIFACT_SCHEMA = "wardline.delta_scope.v1"
```

Use `WARPLINE_REVERIFY_WORKLIST_SCHEMA` in the parser docstrings and the seam adapter; use `DELTA_SCOPE_ARTIFACT_SCHEMA` in `tests/conformance/test_wardline_delta_scope_contract.py` instead of duplicating its literal. Do not reject an existing bare-data worklist or otherwise alter `parse_affected_scope()` behavior in this task.

In `src/wardline/_live_oracle.py`, export:

```python
WARDLINE_SEAM_DRIFT_MARKERS = frozenset({"sei_drift", "worklist_drift"})
```

and build `LIVE_ORACLE_MARKERS` from that constant so the current CI behavior remains identical.

In `src/wardline/install/seam_health.py`, add a small injected `SeamHealthDependencies` dataclass containing resolved Filigree/Loomweave URLs and factories/probes. Its production constructor must use the existing URL resolution and token loaders, `FiligreeEmitter.verify_token`, `load_legis_artifact_key`, `wardline.core.legis.key_id`, `require_blake3`, `LoomweaveClient`, the two delta constants, and `WARDLINE_SEAM_DRIFT_MARKERS`—not duplicate credential or URL resolution.

Map expected operational failures only at the adapter boundary. A missing/not-configured peer is `amber`; an impossible local invariant is `error`; no exception text, URL, or raw response is copied to the report. For Legis, compare only in-memory derived ids when the already-existing peer env name `LEGIS_WARDLINE_ARTIFACT_KEY` happens to be present; its absence must not make setup mandatory or turn a configured Wardline key amber.

- [ ] **Step 4: Re-run focused Layer-1 and existing doctor checks.**

Run: `uv run pytest tests/unit/install/test_seam_health.py tests/unit/core/test_delta_scope.py tests/unit/install/test_doctor_filigree_auth.py -q`

Expected: PASS.

- [ ] **Step 5: Commit Layer 1.**

```bash
git add src/wardline/install/seam_health.py src/wardline/core/delta_scope.py src/wardline/_live_oracle.py \
  tests/unit/install/test_seam_health.py tests/unit/core/test_delta_scope.py tests/conformance/test_wardline_delta_scope_contract.py
git commit -m "feat(doctor): report local seam health"
```

## Task 3: Implement the two consumer probe adapters without trusted status fields

**Files:**
- Modify: `src/wardline/install/seam_health.py`
- Modify: `tests/unit/install/test_seam_health.py`
- Create: `tests/conformance/test_seam_health_probe.py`

- [ ] **Step 1: Write failing adapter tests through Wardline’s real consumers.**

Add tests using a narrow injected `ProducerProbeSource` protocol. It has only two methods: `loomweave_identity_probe()` and `warpline_worklist_probe()`. Each returns a producer-originated payload plus its declared key set and freshness anchor, or an explicit unsupported result. Test it with real Wardline consumption methods, not copied decoders:

For the SEI case, the fake transport must serve a producer-originated `wlprobe:sei:v1:case-001` through `LoomweaveClient`'s existing `/api/v1/identity/resolve` and `/api/v1/identity/sei/<escaped-sei>` requests. Assert that the adapter calls `SeiResolver.resolve_locator()` followed by `SeiResolver.resolve_identity_status()`, checks `current_locator` and `content_hash`, and returns Layer 2 `ok`. Serve the same response under `wlprobe:sei:v2:case-001` and assert the result is non-`ok` with `reason.code == "scheme_mismatch"`.

For the Warpline case, feed `parse_affected_scope()` a producer-originated `warpline.reverify_worklist.v1` envelope containing `wlprobe:worklist:v1:case-001` in the entity identity fields. Assert that the adapter checks the worklist schema, consumer-accepted keys, item count, and completeness/freshness facts. A changed key set, stale generated-at/completeness evidence, malformed body, partial worklist, or `wlprobe:worklist:v2:case-001` must return an explicit non-`ok` reason.

Add cases for `peer_probe_unsupported`, `malformed_response`, `partial_result`, `freshness_mismatch`, and `peer_unreachable`. Assert a zero-item or `None` result can never yield `ok`. Add a conformance test that runs `build_seam_health_report(probe=True, deps=fakes)` and proves both probe seams pass only when all retrievability, key-set, and freshness assertions pass.

- [ ] **Step 2: Run the probe tests and confirm they fail.**

Run: `uv run pytest tests/unit/install/test_seam_health.py tests/conformance/test_seam_health_probe.py -q`

Expected: FAIL because the probe protocol and adapters do not exist.

- [ ] **Step 3: Implement bounded probe inputs and production-path consumers.**

In `src/wardline/install/seam_health.py`:

- Define `SEI_PROBE_PREFIX = "wlprobe:sei:v1:"` and `WORKLIST_PROBE_PREFIX = "wlprobe:worklist:v1:"`; accept only bounded ASCII values with those exact v1 prefixes.
- Define a structural `ProducerProbeSource` protocol and two result dataclasses carrying `payload`, `emitted_keys`, `freshness_anchor`, and a non-secret capability name. It must not carry URLs, tokens, raw response text, or exceptions.
- Make the production source inspect only already-advertised capability data. If the current Loomweave/Warpline peer cannot provide the reserved-prefix producer value through its existing supported surface, return `amber/peer_probe_unsupported` with a next action naming the missing capability. Do not add an HTTP endpoint, mutate a peer, write a sentinel, invoke a scan, or add a new configuration option.
- For the SEI adapter, drive `LoomweaveClient` and `SeiResolver`; require a non-empty opaque returned SEI, `IdentityStatus.ALIVE`, exact v1 prefix, matching required keys (`sei`, `current_locator`, `content_hash`, `alive`), and matching content-hash freshness anchor. Classify v2/missing-prefix as `scheme_mismatch`, missing required keys as `schema_mismatch`, an unavailable/malformed response as `malformed_response` or `peer_unreachable`, and hash disagreement as `freshness_mismatch`.
- For the worklist adapter, drive `parse_affected_scope()` directly; require `WARPLINE_REVERIFY_WORKLIST_SCHEMA`, a non-empty `AffectedScope`, the v1 sentinel retained in the declared entity identity, the producer’s required key subset, and non-partial/current completeness evidence. Classify parser failures as `malformed_response`, a missing required field as `schema_mismatch`, an empty/partial worklist as `partial_result`, and a v2/mismatched sentinel as `scheme_mismatch`.
- Keep Layer 2 as `not_run/probe_not_requested` when `probe=False`; only the two consumer seams receive a non-not-run Layer 2 result. The other four always carry the explicit not-run reason.

- [ ] **Step 4: Re-run unit and conformance probe tests.**

Run: `uv run pytest tests/unit/install/test_seam_health.py tests/conformance/test_seam_health_probe.py tests/unit/loomweave/test_sei_client_wire.py tests/conformance/test_warpline_worklist_drift.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the consumer adapters.**

```bash
git add src/wardline/install/seam_health.py tests/unit/install/test_seam_health.py tests/conformance/test_seam_health_probe.py
git commit -m "feat(doctor): add seam consumer probes"
```

## Task 4: Add the read-only CLI surface and exit policy

**Files:**
- Modify: `src/wardline/cli/doctor.py`
- Modify: `tests/unit/cli/test_doctor.py`

- [ ] **Step 1: Write failing CLI tests.**

Add Click `CliRunner` tests for these exact invocations:

```python
result = runner.invoke(cli, ["doctor", "--root", str(tmp_path), "--seams"])
assert "wardline.legis_attest" in result.output
assert "key_missing" in result.output

result = runner.invoke(cli, ["doctor", "--root", str(tmp_path), "--seams", "--format", "json"])
payload = json.loads(result.output)
assert payload["version"] == "wardline.seam_health.v1"
assert len(payload["seams"]) == 6

assert runner.invoke(cli, ["doctor", "--probe"]).exit_code == 2
assert runner.invoke(cli, ["doctor", "--format", "json"]).exit_code == 2
assert runner.invoke(cli, ["doctor", "--seams", "--repair"]).exit_code == 2
assert runner.invoke(cli, ["doctor", "--seams", "--fix"]).exit_code == 2
```

Add a fake dependency builder assertion that a Layer-1 `error` exits 1, while Layer-2 `error` with all Layer-1 rows non-error exits 0. Snapshot the temp tree before/after `--seams --probe --format json` and assert it is unchanged. Keep the existing `--fix` JSON test unchanged as the regression for legacy output.

- [ ] **Step 2: Run CLI tests and confirm they fail.**

Run: `uv run pytest tests/unit/cli/test_doctor.py -q`

Expected: FAIL because Click does not recognise the new flags.

- [ ] **Step 3: Implement CLI parsing and rendering.**

In `src/wardline/cli/doctor.py` add:

```python
@click.option("--seams", is_flag=True, help="Report read-only posture for every Wardline-owned federation seam.")
@click.option("--probe", is_flag=True, help="With --seams, run read-only consumer probes.")
@click.option("--format", "output_format", type=click.Choice(["json"]), default=None)
```

Validate combinations before any existing repair/fix code runs. Call `build_seam_health_report(root, probe=probe)` once. For human output, emit one row per stable seam with `seam_id`, Layer-1 status/reason code, Layer-2 status/reason code, and `next_action` when present; do not print evidence that is absent from the safe report. For JSON, call `json.dumps(report.to_dict(), indent=2, sort_keys=True)` and nothing else. Return exit 1 only when `any(row.layer1.status == "error" for row in report.seams)`.

Do not route the seam mode through `machine_readable_doctor`; legacy `--fix` remains the legacy repair JSON envelope.

- [ ] **Step 4: Re-run CLI tests.**

Run: `uv run pytest tests/unit/cli/test_doctor.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the CLI surface.**

```bash
git add src/wardline/cli/doctor.py tests/unit/cli/test_doctor.py
git commit -m "feat(cli): add doctor seam posture report"
```

## Task 5: Add the optional MCP projection, schema, and policy enforcement

**Files:**
- Modify: `src/wardline/mcp/server.py`
- Modify: `tests/unit/mcp/test_server_doctor.py`
- Modify: `tests/conformance/test_mcp_structured_output.py`
- Modify: `tests/conformance/test_mcp_output_schema_golden.py`
- Modify: `tests/conformance/mcp_output_schemas.golden.json`

- [ ] **Step 1: Write failing MCP tests.**

Add tests that pin all of these behaviors:

```python
payload = _doctor({"seams": True}, tmp_path, started_at=time.time())
assert payload["seams"] == build_seam_health_report(tmp_path, probe=False).to_dict()
assert "seams" not in _doctor({}, tmp_path, started_at=time.time())

with pytest.raises(ToolError, match="probe requires seams"):
    _doctor({"probe": True}, tmp_path, started_at=time.time())
with pytest.raises(ToolError, match="seams must be a boolean"):
    _doctor({"seams": "true"}, tmp_path, started_at=time.time())
```

Through RPC, assert `doctor({"seams": true, "probe": true})` is denied under `allow_network=False` only when a configured Loomweave probe would reach the network; the no-seams default keeps its current policy behavior. Assert caller-supplied `filigree_url` is still rejected and never becomes a seam URL. In `test_mcp_structured_output.py`, validate an actual `{seams: true}` response against the live output schema. In the golden test, first add an assertion that only the `doctor` schema changes.

- [ ] **Step 2: Run MCP tests and confirm they fail.**

Run: `uv run pytest tests/unit/mcp/test_server_doctor.py tests/conformance/test_mcp_structured_output.py tests/conformance/test_mcp_output_schema_golden.py -q`

Expected: FAIL because input schema, handler validation, and `seams` output schema are missing.

- [ ] **Step 3: Wire the shared builder and update schemas deliberately.**

In `_doctor` in `src/wardline/mcp/server.py`:

1. Parse `seams = _bool_arg(args, "seams", False)` and `probe = _bool_arg(args, "probe", False)`.
2. Raise `ToolError("probe requires seams=true")` before calling any networked helper when `probe and not seams`.
3. Preserve the current `machine_readable_doctor` call, rejected caller URL check, and `attach_server_identity` behavior.
4. Only after that existing envelope is built, create `deps = SeamHealthDependencies.from_resolved_config(root=root, filigree_url=filigree_url, filigree_url_source=filigree_url_source, loomweave_url=loomweave_url, loomweave_url_source=loomweave_url_source)` and set `payload["seams"] = build_seam_health_report(root, probe=probe, deps=deps).to_dict()` when `seams` is true. This constructor never takes a URL or token from MCP arguments.

Add `seams` and `probe` boolean properties to `_DOCTOR_TOOL["input_schema"]`. Add an optional `_DOCTOR_OUTPUT_SCHEMA["properties"]["seams"]` object whose nested objects have `additionalProperties: false`, require `version`, `probe_requested`, `seams`, `seam_id`, `layer1`, `layer2`, `status`, and `reason`, and enumerate the exact status and reason-code vocabularies. Do not add `seams` to the top-level `required` list.

Update `_effective_tool_capabilities()` so `doctor` gains `NETWORK` for `seams && probe` when a Loomweave URL resolves. Keep `WRITE` tied only to `repair`; all seam modes are read-only.

Regenerate, never hand-edit, the frozen output schema:

```bash
uv run python -c 'import json; from wardline.mcp.server import WardlineMCPServer; from pathlib import Path; s=WardlineMCPServer(root=Path("tests/fixtures/sample_project")); r=s.rpc.dispatch({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}); p=Path("tests/conformance/mcp_output_schemas.golden.json"); p.write_text(json.dumps({t["name"]: t["outputSchema"] for t in r["result"]["tools"]}, indent=2, sort_keys=True) + "\\n", encoding="utf-8")'
git hash-object tests/conformance/mcp_output_schemas.golden.json
```

Replace `VENDORED_BLOB_SHA` in `tests/conformance/test_mcp_output_schema_golden.py` with the printed hash in the same commit.

- [ ] **Step 4: Re-run MCP unit/conformance tests.**

Run: `uv run pytest tests/unit/mcp/test_server_doctor.py tests/conformance/test_mcp_structured_output.py tests/conformance/test_mcp_output_schema_golden.py -q`

Expected: PASS.

- [ ] **Step 5: Commit the MCP surface.**

```bash
git add src/wardline/mcp/server.py tests/unit/mcp/test_server_doctor.py \
  tests/conformance/test_mcp_structured_output.py tests/conformance/test_mcp_output_schema_golden.py \
  tests/conformance/mcp_output_schemas.golden.json
git commit -m "feat(mcp): expose doctor seam health"
```

## Task 6: Prove parity, non-interference, and documentation

**Files:**
- Modify: `tests/conformance/test_seam_health_probe.py`
- Modify: `tests/unit/cli/test_scan_inert_posture.py`
- Modify: `docs/reference/cli.md`
- Modify: `docs/reference/mcp.md`

- [ ] **Step 1: Write failing end-to-end regression tests.**

In `tests/conformance/test_seam_health_probe.py`, run CLI `doctor --seams --format json` and MCP `doctor({"seams": true})` against the same isolated root and assert decoded report equality. Repeat for `--probe` with injected supported producer sources, and assert the drifted v2 sentinel is non-`ok` in both surfaces.

In `tests/unit/cli/test_scan_inert_posture.py`, add a probe-call counter around the seam-health builder/dependencies, run the ordinary `wardline scan` CLI path, and assert the counter remains zero. Record the active-finding fingerprints from a baseline scan, invoke `doctor --seams --probe`, run the same scan again, and assert the active-finding fingerprint set and exit class are identical. Use a temporary root and a fake producer source; the test must prove no project artifact was created by doctor.

- [ ] **Step 2: Run the new regressions and confirm they fail.**

Run: `uv run pytest tests/conformance/test_seam_health_probe.py tests/unit/cli/test_scan_inert_posture.py -q`

Expected: FAIL until both projections share the same builder and the non-interference test is in place.

- [ ] **Step 3: Document the shipped surface.**

Update `docs/reference/cli.md` under `doctor` with the four supported commands, exact invalid combinations, the Layer-1-only exit policy, and the fact that `amber` is useful diagnostic evidence rather than a clean pass. Update `docs/reference/mcp.md` `doctor` input/output entries with `seams`, `probe`, the optional `seams` report, and the no-caller-peer-URL policy. State that a current peer without a reserved-probe capability returns `peer_probe_unsupported`; do not imply this writes a sentinel or gates scans.

- [ ] **Step 4: Run the parity and non-interference suite.**

Run: `uv run pytest tests/conformance/test_seam_health_probe.py tests/unit/cli/test_scan_inert_posture.py tests/unit/cli/test_doctor.py tests/unit/mcp/test_server_doctor.py -q`

Expected: PASS.

- [ ] **Step 5: Commit regressions and docs.**

```bash
git add tests/conformance/test_seam_health_probe.py tests/unit/cli/test_scan_inert_posture.py \
  docs/reference/cli.md docs/reference/mcp.md
git commit -m "test: pin seam health parity and scan isolation"
```

## Task 7: Run full verification and review the bounded contract

**Files:** no planned source changes unless a verification failure identifies one.

- [ ] **Step 1: Run targeted tests in one clean command.**

Run:

```bash
uv run pytest \
  tests/unit/install/test_seam_health.py \
  tests/conformance/test_seam_health_probe.py \
  tests/unit/cli/test_doctor.py \
  tests/unit/mcp/test_server_doctor.py \
  tests/conformance/test_mcp_structured_output.py \
  tests/conformance/test_mcp_output_schema_golden.py \
  tests/unit/core/test_delta_scope.py \
  tests/conformance/test_warpline_delta_scope.py \
  tests/conformance/test_warpline_worklist_drift.py \
  tests/conformance/test_sei_oracle.py \
  tests/unit/cli/test_scan_inert_posture.py -q
```

Expected: PASS.

- [ ] **Step 2: Run the full default suite.**

Run: `uv run pytest -q`

Expected: PASS. Default excludes the existing live-oracle markers, as configured in `pyproject.toml`.

- [ ] **Step 3: Run required source-drift and self-scan checks.**

Run:

```bash
WARDLINE_LIVE_ORACLE_REQUIRED=1 uv run pytest tests/conformance -m "sei_drift or worklist_drift" -v
uv run wardline scan . --fail-on ERROR
git diff --check
git status --short
```

Expected: the required drift run passes against available sibling sources; Wardline self-scan has no new active findings; whitespace check is clean; status contains only intentional implementation changes.

- [ ] **Step 4: Review scope before handoff.**

Confirm all of these are true before requesting review:

- No `scan`/run path imports or calls `build_seam_health_report`.
- No new base dependency appears in `pyproject.toml`.
- No report field can contain a raw secret, token, peer body, or caller-supplied URL.
- `doctor({})`, CLI `doctor`, `doctor --repair`, and `doctor --fix` tests prove existing behavior is preserved.
- Both default peer sources classify absent reserved-probe capability as `amber/peer_probe_unsupported`, never `ok` or an empty result.
- The output-schema golden update changes only `doctor` and its blob hash is updated in the same commit.

- [ ] **Step 5: Commit any verification-only corrections, then hand off.**

```bash
git add -A
git commit -m "test: verify seam health contract"
```

Do not combine this work with peer endpoint changes, a Layer-3 roll-up, analyzer rules, or a generic doctor JSON migration. Those are outside PRD-0002 scope B.
