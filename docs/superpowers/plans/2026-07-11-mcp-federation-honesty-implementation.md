# MCP Federation Honesty Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pin every current destructive MCP boolean in degraded validation mode, preserve Loomweave authentication truth through every identity consumer, and ensure an MCP legis artifact uses the exact in-process configuration object that produced its scan.

**Architecture:** Keep the existing strict `_bool_arg()` boundary and add dispatch-level regression coverage only. Replace the nullable shared identity result with a frozen `BindingResolution` carrying the binding and honest unavailability metadata, then thread it through dossier, decorator, attestation, and legacy Filigree attachment surfaces. Finally, retain the effective `WardlineConfig` on `ScanResult` as in-process provenance and pass that same object to legis artifact construction instead of loading policy twice.

**Tech Stack:** Python 3.12+, frozen slotted dataclasses, pytest/monkeypatch, MCP JSON-RPC dispatch, Wardline core scan/attestation/dossier APIs, Filigree CLI, Ruff, mypy, Wardline trust-boundary scan.

---

## Scope and delivery map

The approved design separates three independently reviewable tickets plus one split cleanup. Do not combine their commits. Task file lists below are the authoritative change map.

Loomweave orientation found two direct production callers of `resolve_entity_binding()` (`build_weft_dossier` and `LoomweaveBindingProvider.binding_for`) and live source found the additional direct attestation caller. The Filigree legacy-locator branch consumes `ResolveResult` independently and must use the same status-aware wording. The Loomweave index was stale, so task file lists are based on live source verification, not the graph alone.

Lifecycle commands use audit actor `john` and worker assignee `codex`. Run `filigree transitions <id> --json` before any manual status update; never force-close normal implementation work.

### Task 1: Pin all destructive MCP boolean guards (`wardline-2e6ad7772c`)

**Files:**
- Modify: `tests/unit/mcp/test_server_arg_hardening.py:16-151`
- Verify only: `src/wardline/mcp/server.py:652-661,681-709,3513,3624,3927,4164-4166,4524`

- [ ] **Step 1: Start the ticket atomically and record the root cause**

```bash
filigree start-work wardline-2e6ad7772c --assignee codex --actor john
filigree add-comment wardline-2e6ad7772c \
  "Root cause: strict runtime conversion is present, but degraded tools/call dispatch has no regression matrix for the nine current write/destructive booleans. This change is test-only; waiver tools have no boolean control and are intentionally excluded." \
  --actor john --expected-assignee codex
```

Expected: the task enters `in_progress`; the comment is recorded. If `start-work` returns `INVALID_TRANSITION`, run `filigree transitions wardline-2e6ad7772c --json` and use the named legal transition rather than forcing it.

- [ ] **Step 2: Add the degraded dispatch matrix and side-effect spies**

Add `pytest`, `SimpleNamespace`, and `wardline.mcp.server as server_mod` imports, then add this exact matrix below the existing degraded-mode tests:

```python
import pytest


@pytest.mark.parametrize(
    ("tool", "arguments", "field", "side_effect"),
    [
        pytest.param("judge", {"write": "false"}, "write", "run_judge", id="judge.write"),
        pytest.param("baseline", {"overwrite": "false"}, "overwrite", "generate_baseline", id="baseline.overwrite"),
        pytest.param("scan_job_start", {"local_only": "false"}, "local_only", "start_scan_job", id="scan-job.local-only"),
        pytest.param("doctor", {"repair": "false"}, "repair", "doctor", id="doctor.repair"),
        pytest.param("rekey", {"apply": "false"}, "apply", "run_scan", id="rekey.apply"),
        pytest.param("rekey", {"apply": False, "resume": "false"}, "resume", "run_scan", id="rekey.resume"),
        pytest.param(
            "rekey",
            {"apply": False, "resume": False, "rollback": "false"},
            "rollback",
            "run_scan",
            id="rekey.rollback",
        ),
    ],
)
def test_destructive_boolean_rejected_before_side_effect_without_jsonschema(
    tmp_path, monkeypatch, tool, arguments, field, side_effect
) -> None:
    _block_jsonschema(monkeypatch)
    called = False

    def forbidden(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("side effect ran before boolean validation")

    if side_effect == "doctor":
        monkeypatch.setattr("wardline.install.doctor.machine_readable_doctor", forbidden)
    else:
        monkeypatch.setattr(f"wardline.mcp.server.{side_effect}", forbidden)
    server = WardlineMCPServer(root=_leaky_project(tmp_path))

    resp = _dispatch(server, tool, arguments)

    assert resp["result"]["isError"] is True
    assert f"{field} must be a boolean" in resp["result"]["content"][0]["text"]
    assert called is False
```

The matrix is the exhaustive approved inventory: `fix.apply`, `fix.dry_run`, `judge.write`, `baseline.overwrite`, `scan_job_start.local_only`, `doctor.repair`, and `rekey.apply/resume/rollback`. `fix` needs a `PY-WL-111` fixture; `dry_run` also needs real `apply: true` because its expression short-circuits. Earlier rekey flags must be real `False` to reach the named guard.

- [ ] **Step 3: Add the two `fix` cases with a fixable fixture**

```python
_ASSERT_ONLY = (
    "from wardline.decorators import external_boundary\n"
    "@external_boundary\n"
    "def boundary(value):\n"
    "    assert isinstance(value, str)\n"
    "    return value\n"
)


@pytest.mark.parametrize(
    ("arguments", "field"),
    [
        pytest.param({"apply": "false"}, "apply", id="fix.apply"),
        pytest.param({"apply": True, "dry_run": "false"}, "dry_run", id="fix.dry-run"),
    ],
)
def test_fix_boolean_rejected_before_autofix_without_jsonschema(tmp_path, monkeypatch, arguments, field) -> None:
    _block_jsonschema(monkeypatch)
    root = tmp_path / "project"
    root.mkdir()
    source = root / "boundary.py"
    source.write_text(_ASSERT_ONLY, encoding="utf-8")
    before = source.read_bytes()
    called = False

    def forbidden(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("autofix ran before boolean validation")

    monkeypatch.setattr("wardline.core.autofix.run_autofix", forbidden)
    resp = _dispatch(WardlineMCPServer(root=root), "fix", arguments)

    assert resp["result"]["isError"] is True
    assert f"{field} must be a boolean" in resp["result"]["content"][0]["text"]
    assert called is False
    assert source.read_bytes() == before
```

- [ ] **Step 4: Run the new tests and confirm they pass without production changes**

Run:

```bash
uv run pytest tests/unit/mcp/test_server_arg_hardening.py -k 'destructive_boolean or fix_boolean' -vv
```

Expected: `9 passed`. If a case fails because its spy target is dynamically imported, patch the defining module named in the table; do not weaken the pre-side-effect assertion.

- [ ] **Step 5: Run the focused MCP suite and repository verification**

```bash
uv run pytest tests/unit/mcp/test_server_arg_hardening.py tests/unit/mcp/test_server_rekey.py tests/unit/mcp/test_server_scan_jobs.py -q
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest -q
uv run wardline scan . --fail-on ERROR
git diff --check
```

Expected: all commands exit 0. `wardline scan` must report no ERROR gate trip; an inert/no-boundary scan is not a substitute for the nine focused assertions.

- [ ] **Step 6: Commit, attach evidence, and close the ticket**

```bash
git add tests/unit/mcp/test_server_arg_hardening.py
git commit -m "test: pin destructive MCP boolean guards"
BOOL_SHA=$(git rev-parse HEAD)
filigree add-comment wardline-2e6ad7772c \
  "Verified all nine current destructive/write-enabling booleans reject string false without jsonschema before side effects; focused MCP tests and full repository gates passed at ${BOOL_SHA}." \
  --actor john --expected-assignee codex
filigree transitions wardline-2e6ad7772c --json
filigree close wardline-2e6ad7772c --commit "release/consolidation-2026-06-26@${BOOL_SHA}" \
  --reason "Degraded dispatch matrix is green for the complete approved boolean inventory." \
  --actor john --expected-assignee codex
```

Expected: one ticket-scoped commit; ticket terminal with `close_commit` set. Do not include waiver booleans or the unrelated `no_files_scanned` surface in this commit.

### Task 2: Introduce authentication-honest binding resolution (`wardline-6f9eece880`)

**Files:**
- Modify: `src/wardline/loomweave/dossier_sources.py:35-40,82-101`
- Test: `tests/unit/loomweave/test_dossier_sources.py:19-35,124-145`

- [ ] **Step 1: Start the bug with soft-transition advancement and record the root cause**

```bash
filigree start-work wardline-6f9eece880 --assignee codex --actor john --advance
filigree add-comment wardline-6f9eece880 \
  "Root cause: LoomweaveClient.resolve preserves 401/403 in ResolveResult.auth_status, but resolve_entity_binding collapses every missing locator to None. Downstream dossier, decorator, attestation, and legacy attachment surfaces therefore describe authentication rejection as entity absence." \
  --actor john --expected-assignee codex
```

Expected: the bug walks `triage -> confirmed -> fixing` atomically.

- [ ] **Step 2: Write failing value-object and wording tests**

Extend `_FakeClient` with `auth_status: int | None`, return it from `ResolveResult`, and add:

```python
@pytest.mark.parametrize(
    ("status", "must_contain", "must_not_contain"),
    [
        (401, ("401", "federation/HMAC credential", "clock"), ("not indexed",)),
        (403, ("403", "project", "scope", "permission"), ("set a token", "not indexed")),
    ],
)
def test_resolve_entity_binding_preserves_auth_rejection(status, must_contain, must_not_contain) -> None:
    resolution = resolve_entity_binding(_FakeClient(auth_status=status), _NeverResolver(), "svc.leaky", plugin="python")

    assert resolution.binding is None
    assert resolution.auth_status == status
    assert resolution.unavailable_reason is not None
    assert all(text in resolution.unavailable_reason for text in must_contain)
    assert all(text not in resolution.unavailable_reason for text in must_not_contain)


def test_resolve_entity_binding_genuine_unresolved_keeps_no_binding_language() -> None:
    resolution = resolve_entity_binding(_FakeClient(resolved={}), _NeverResolver(), "svc.unknown")
    assert resolution == BindingResolution(
        binding=None,
        unavailable_reason="Loomweave returned no identity for svc.unknown",
        auth_status=None,
    )
```

Run:

```bash
uv run pytest tests/unit/loomweave/test_dossier_sources.py -k 'preserves_auth or genuine_unresolved' -vv
```

Expected: FAIL because `resolve_entity_binding()` returns `EntityBinding | None` and auth metadata is absent.

- [ ] **Step 3: Implement the frozen result and centralized wording**

In `src/wardline/loomweave/dossier_sources.py`, add:

```python
from dataclasses import dataclass


def binding_unavailable_reason(qualname: str, auth_status: int | None) -> str:
    if auth_status == 401:
        return (
            "Loomweave authentication rejected (401): align the federation/HMAC "
            "credential and clock, then retry"
        )
    if auth_status == 403:
        return (
            "Loomweave authorization rejected (403): verify the project, scope, and "
            "permission; setting a token alone may not grant access"
        )
    return f"Loomweave returned no identity for {qualname}"


@dataclass(frozen=True, slots=True)
class BindingResolution:
    binding: EntityBinding | None
    unavailable_reason: str | None
    auth_status: int | None

    def __post_init__(self) -> None:
        if self.binding is not None and (self.unavailable_reason is not None or self.auth_status is not None):
            raise ValueError("a resolved binding cannot also be unavailable")
        if self.auth_status not in (None, 401, 403):
            raise ValueError("auth_status must be 401, 403, or None")
```

Replace the resolver body with:

```python
def resolve_entity_binding(
    client: _ResolveClient, resolver: _Resolver, qualname: str, *, plugin: str | None = None
) -> BindingResolution:
    rr = client.resolve([qualname], plugin=plugin)
    if rr is None:
        return BindingResolution(None, "Loomweave unreachable while resolving identity", None)
    locator = rr.resolved.get(qualname)
    if not locator:
        return BindingResolution(None, binding_unavailable_reason(qualname, rr.auth_status), rr.auth_status)
    return BindingResolution(resolver.resolve_locator(locator), None, None)
```

Update the two existing success/unresolved assertions to inspect `.binding`, then run:

```bash
uv run pytest tests/unit/loomweave/test_dossier_sources.py -q
```

Expected: PASS.

### Task 3: Thread resolution through dossier and decorator identity/work reasons

**Files:**
- Modify: `src/wardline/core/dossier.py:661-691,760-815`
- Modify: `src/wardline/weft_dossier.py:79-108,119-129`
- Modify: `src/wardline/core/decorator_coverage.py:26-29,151-170,190-220`
- Modify: `src/wardline/weft_decorator_coverage.py:17-27`
- Test: `tests/unit/core/test_weft_dossier.py:129-165`
- Test: `tests/unit/core/test_decorator_coverage.py:88-106`

- [ ] **Step 1: Add failing 401/403 consumer tests**

Add a `_FakeLoomweave(auth_status=...)` mode and assert the dossier stays fail-soft while both optional sections name authentication truth:

```python
@pytest.mark.parametrize("status", [401, 403])
def test_dossier_surfaces_loomweave_auth_rejection_in_linkage_and_work_reasons(tmp_path, status) -> None:
    d = build_weft_dossier(
        "svc.leaky",
        root=_proj(tmp_path),
        loomweave_client=_FakeLoomweave(auth_status=status),
        filigree_url="http://filigree.example",
        filigree_transport=_FakeFiligreeTransport('{"associations": []}'),
    )
    assert d.trust.gate_verdict == "defect"
    assert str(status) in (d.linkages.reason or "")
    assert str(status) in (d.work.reason or "")
```

Add a `BindingProvider` double returning `BindingResolution(None, reason, status)` and assert both decorator fields use the same reason:

```python
@pytest.mark.parametrize("status", [401, 403])
def test_decorator_coverage_surfaces_auth_reason_for_identity_and_work(tmp_path, status) -> None:
    reason = binding_unavailable_reason("svc.clean", status)
    report = build_decorator_coverage(
        _project(tmp_path),
        binding_provider=_UnavailableBindings(reason, status),
        work_provider=_Work(),
    )
    row = next(row for row in report.to_dict()["rows"] if row["qualname"] == "svc.clean")
    assert row["identity"]["reason"] == reason
    assert row["work"]["reason"] == reason
```

Run:

```bash
uv run pytest tests/unit/core/test_weft_dossier.py tests/unit/core/test_decorator_coverage.py -k auth -vv
```

Expected: FAIL because consumers accept only `EntityBinding | None` and manufacture generic no-binding reasons.

- [ ] **Step 2: Thread one resolution without making Loomweave load-bearing**

Make `build_dossier()` accept `binding_unavailable_reason: str | None = None`; pass it to `_linkages_from()` and `_work_from()`, and use it only when `binding is None`:

```python
if binding is None:
    return LinkagesSection.unavailable(
        binding_unavailable_reason or "no entity binding: cannot resolve linkages"
    )
```

Apply the same fallback to work. In `build_weft_dossier()`:

```python
resolution = resolve_entity_binding(loomweave_client, resolver, entity)
binding = resolution.binding
binding_reason = resolution.unavailable_reason
# ...
return build_dossier(
    entity,
    root=root,
    binding=binding,
    binding_unavailable_reason=binding_reason,
    linkage_provider=linkage_provider,
    work_provider=work_provider,
    # unchanged arguments
)
```

Change `BindingProvider.binding_for()` to return `BindingResolution`; update `_identity_for()` to return `(IdentityCoverage, BindingResolution)`, and update `_work_for()` to use `resolution.unavailable_reason` when no usable binding exists. Do not catch and relabel `BindingResolution`; exception paths remain fail-soft with `loomweave unreachable: ...`.

Run:

```bash
uv run pytest tests/unit/core/test_weft_dossier.py tests/unit/core/test_decorator_coverage.py tests/unit/mcp/test_server_dossier.py tests/unit/mcp/test_server_decorator_coverage.py -q
```

Expected: PASS; no schema change yet because existing `reason: string|null` fields carry the new truth.

### Task 4: Thread resolution through attestation diagnostics and legacy Filigree attachment

**Files:**
- Modify: `src/wardline/core/attest.py:136-172,216-243`
- Modify: `src/wardline/core/filigree_issue.py:442-467`
- Modify: `src/wardline/mcp/server.py:3301-3352`
- Modify: `tests/conformance/mcp_output_schemas.golden.json` (regenerated)
- Test: `tests/unit/core/test_attest.py:500-560`
- Test: `tests/unit/core/test_filigree_issue.py:360-540`

- [ ] **Step 1: Add failing attestation and legacy tests for both statuses**

```python
@pytest.mark.parametrize("status", [401, 403])
def test_attestation_records_auth_rejection_per_boundary(tmp_path, status) -> None:
    payload = build_attestation(
        _annotated_tree(tmp_path),
        _KEY,
        loomweave_client=_AuthRejectedLoomweave(status),
        today=_PINNED,
    )["payload"]
    assert payload["sei_source"] == "unavailable"
    assert payload["sei_diagnostics"]
    assert all(item["auth_status"] == status for item in payload["sei_diagnostics"])
    assert all(str(status) in item["reason"] for item in payload["sei_diagnostics"])
```

```python
@pytest.mark.parametrize("status", [401, 403])
def test_legacy_locator_attachment_names_auth_rejection(status) -> None:
    client = LegacyAuthRejectedLoomweave(status)
    result = attach_loomweave_identity_for_qualname(
        qualname="pkg.mod.leaky",
        issue_id="wardline-1",
        filer=FiligreeIssueFiler("http://f/api/weft/scan-results", transport=RecordingTransport()),
        loomweave_client=client,
    )
    assert result.attached is False
    assert result.reason is not None and str(status) in result.reason
    assert "not resolve legacy locator" not in result.reason
    assert client.fact_calls == []
```

Run:

```bash
uv run pytest tests/unit/core/test_attest.py tests/unit/core/test_filigree_issue.py -k auth_rejection -vv
```

Expected: FAIL because attestation drops diagnostics and legacy attachment reports ordinary unresolved identity.

- [ ] **Step 2: Add deterministic signed diagnostics and reuse centralized wording**

Change `_enrich_seis()` to return `(sei_source, diagnostics)` where diagnostics are appended in already-sorted boundary order:

```python
diagnostics: list[dict[str, Any]] = []
# per boundary
resolution = resolve_entity_binding(loomweave_client, resolver, boundary["qualname"], plugin="python")
binding = resolution.binding
if binding is None:
    diagnostics.append(
        {
            "qualname": boundary["qualname"],
            "reason": resolution.unavailable_reason or "Loomweave identity unavailable",
            "auth_status": resolution.auth_status,
        }
    )
    continue
```

Always add top-level `"sei_diagnostics": diagnostics` to the attestation payload, including `[]` when there are no boundaries or no client. Extend `_ATTEST_OUTPUT_SCHEMA` with an array of objects requiring `qualname`, `reason`, and `auth_status` (`integer|null`, enum `[401, 403, null]`), and add `sei_diagnostics` to `required`.

In `_legacy_locator_binding()`, inspect `resolved.auth_status` before `resolved.resolved`:

```python
auth_status = getattr(resolved, "auth_status", None)
if auth_status in (401, 403):
    return IdentityAttachResult.skipped(
        binding_unavailable_reason(qualname, auth_status),
        binding_kind="locator",
    )
```

Import the wording helper from `wardline.loomweave.dossier_sources`. Do not call `get_taint_fact()` after authentication rejection and do not guess a locator.

- [ ] **Step 3: Regenerate the MCP schema golden and run all resolver consumers**

```bash
uv run pytest tests/conformance/test_mcp_structured_output.py --update-goldens
uv run pytest \
  tests/unit/loomweave/test_dossier_sources.py \
  tests/unit/core/test_weft_dossier.py \
  tests/unit/core/test_decorator_coverage.py \
  tests/unit/core/test_attest.py \
  tests/unit/core/test_filigree_issue.py \
  tests/unit/mcp/test_server_dossier.py \
  tests/unit/mcp/test_server_decorator_coverage.py \
  tests/conformance/test_mcp_structured_output.py -q
```

Expected: PASS. Inspect `git diff -- tests/conformance/mcp_output_schemas.golden.json`; only the deterministic `sei_diagnostics` schema addition should appear.

- [ ] **Step 4: Run ticket verification, commit, and close**

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest -q
uv run wardline scan . --fail-on ERROR
git diff --check
git add \
  src/wardline/loomweave/dossier_sources.py \
  src/wardline/core/dossier.py src/wardline/weft_dossier.py \
  src/wardline/core/decorator_coverage.py src/wardline/weft_decorator_coverage.py \
  src/wardline/core/attest.py src/wardline/core/filigree_issue.py src/wardline/mcp/server.py \
  tests/unit/loomweave/test_dossier_sources.py tests/unit/core/test_weft_dossier.py \
  tests/unit/core/test_decorator_coverage.py tests/unit/core/test_attest.py \
  tests/unit/core/test_filigree_issue.py tests/conformance/mcp_output_schemas.golden.json
git commit -m "fix: preserve Loomweave authentication truth"
AUTH_SHA=$(git rev-parse HEAD)
filigree add-comment wardline-6f9eece880 \
  "BindingResolution now carries 401/403 truth through dossier linkage/work, decorator identity/work, attestation diagnostics, and Filigree legacy attachment. Genuine unresolved entities retain no-binding language. Full gates passed at ${AUTH_SHA}." \
  --actor john --expected-assignee codex
filigree transitions wardline-6f9eece880 --json
filigree close wardline-6f9eece880 --commit "release/consolidation-2026-06-26@${AUTH_SHA}" \
  --reason "Every approved resolver consumer now distinguishes auth rejection from entity absence." \
  --actor john --expected-assignee codex
```

Expected: one authentication-root-cause commit and a terminal bug. No generic exception is raised; Loomweave remains optional.

### Task 5: Split the zero-fact/comment cleanup from authentication

**Files:**
- Modify: `src/wardline/loomweave/write.py:21-26`
- Test: `tests/unit/cli/test_cli.py:1257-1337`

- [ ] **Step 1: Create and start a separate cleanup task**

```bash
CLEANUP_ID=$(filigree create \
  "Pin zero-fact Loomweave CLI warning and correct stale constant comment" \
  --type task --priority 3 --label review-2026-07-03 \
  --description "Split from wardline-6f9eece880: DELTA_SKIP_REASON and NO_FACTS_REASON are stable producer labels, not imported consumer constants. Add a CLI surface regression proving zero facts reports no write attempt without failing the scan." \
  --actor john --json | python -c 'import json,sys; print(json.load(sys.stdin)["issue_id"])')
test -n "$CLEANUP_ID"
filigree start-work "$CLEANUP_ID" --assignee codex --actor john
```

Expected: a distinct task id and `in_progress` status. Record it in the parent auth ticket comment if local policy requires explicit split lineage.

- [ ] **Step 2: Add the failing CLI surface test**

```python
def test_scan_zero_facts_names_no_attempt_without_failing(tmp_path, monkeypatch) -> None:
    from wardline.loomweave.client import WriteResult
    from wardline.loomweave.write import NO_FACTS_REASON

    root = tmp_path / "project"
    root.mkdir()
    (root / "README.md").write_text("docs only\n", encoding="utf-8")
    monkeypatch.setattr(
        "wardline.loomweave.write.write_facts_to_loomweave",
        lambda *args, **kwargs: WriteResult(reachable=False, disabled_reason=NO_FACTS_REASON),
    )
    result = CliRunner().invoke(
        scan,
        [str(root), "--output", str(root / "scan.jsonl"), "--loomweave-url", "http://loomweave/api"],
    )
    assert result.exit_code == 0
    assert NO_FACTS_REASON in result.output
    assert "Loomweave taint store not written" in result.output
```

Run:

```bash
uv run pytest tests/unit/cli/test_cli.py -k zero_facts -vv
```

Expected: PASS if the surface is already correct; this task is a pin plus comment correction, not a behavior rewrite.

- [ ] **Step 3: Correct only the stale comment, verify, commit, and close**

Replace:

```python
# Stable ``disabled_reason`` labels for the two no-attempt skips below. Consumers
# compare against these constants, never the prose.
```

with:

```python
# Stable producer labels for the two no-attempt skips below. Consumer surfaces carry
# the returned ``disabled_reason`` verbatim; tests import these constants only to pin
# the producer and user-visible wording to the same value.
```

Then:

```bash
uv run pytest tests/unit/loomweave/test_write.py tests/unit/cli/test_cli.py -k 'zero_facts or no_facts' -q
uv run ruff check src/wardline/loomweave/write.py tests/unit/cli/test_cli.py
uv run ruff format --check src/wardline/loomweave/write.py tests/unit/cli/test_cli.py
git diff --check
git add src/wardline/loomweave/write.py tests/unit/cli/test_cli.py
git commit -m "test: pin zero-fact Loomweave warning"
CLEANUP_SHA=$(git rev-parse HEAD)
filigree add-comment "$CLEANUP_ID" "CLI zero-fact warning pin and comment correction passed at ${CLEANUP_SHA}." \
  --actor john --expected-assignee codex
filigree close "$CLEANUP_ID" --commit "release/consolidation-2026-06-26@${CLEANUP_SHA}" \
  --reason "The split surface cleanup is independently verified." \
  --actor john --expected-assignee codex
```

Expected: a separate small commit and ticket; no authentication code in this commit.

### Task 6: Retain the exact effective scan configuration (`wardline-b40ad59ddb`)

**Files:**
- Modify: `src/wardline/core/run.py:15-30,121-176,287-380,650-690`
- Modify: `src/wardline/mcp/server.py:809-825,983-993,2129-2195`
- Test: `tests/unit/core/test_run.py:752-850`
- Test: `tests/unit/mcp/test_server_arg_hardening.py:154-207`

- [ ] **Step 1: Start the ticket and record the remaining gap**

```bash
filigree start-work wardline-b40ad59ddb --assignee codex --actor john
filigree add-comment wardline-b40ad59ddb \
  "Residual root cause after root-relative path repair: run_scan loads the effective WardlineConfig, discards its identity at the return boundary, and _attach_legis_artifact independently calls config_mod.load again. Matching arguments are not proof of same policy object." \
  --actor john --expected-assignee codex
```

- [ ] **Step 2: Add the failing five-mode load/identity matrix**

In `tests/unit/mcp/test_server_arg_hardening.py`, add:

```python
@pytest.mark.parametrize(
    ("case", "args", "scan_kwargs"),
    [
        ("explicit", {"config": "weft.toml", "legis_artifact": True}, {}),
        ("implicit", {"legis_artifact": True}, {}),
        ("trusted-pack", {"legis_artifact": True, "trust_packs": ["operator-pack"]}, {}),
        ("local-pack", {"legis_artifact": True}, {"trust_local_packs": True}),
        ("strict-default", {"legis_artifact": True}, {"strict_defaults": True}),
    ],
)
def test_legis_artifact_reuses_exact_scan_config_once(tmp_path, monkeypatch, case, args, scan_kwargs) -> None:
    from wardline.core import legis as legis_mod

    monkeypatch.delenv(LEGIS_ARTIFACT_KEY_ENV, raising=False)
    root = _subpath_project(tmp_path)
    loads = []
    built_with = []
    real_load = config_mod.load
    real_build = legis_mod.build_legis_artifact

    def recording_load(*load_args, **load_kwargs):
        config = real_load(*load_args, **load_kwargs)
        loads.append(config)
        return config

    def recording_build(result, *, root, config, key, allow_dirty=False):
        built_with.append(config)
        return real_build(result, root=root, config=config, key=key, allow_dirty=allow_dirty)

    monkeypatch.setattr(config_mod, "load", recording_load)
    monkeypatch.setattr(legis_mod, "build_legis_artifact", recording_build)

    out = _scan(args, root, None, None, **scan_kwargs)

    assert "legis_artifact" in out
    assert len(loads) == 1, case
    assert built_with == [loads[0]]
    assert out["legis_artifact"]["rule_set_version"] == ruleset_hash(loads[0])
```

Run:

```bash
uv run pytest tests/unit/mcp/test_server_arg_hardening.py -k reuses_exact_scan_config_once -vv
```

Expected before implementation: all five cases FAIL at `assert len(loads) == 1` with `2 == 1`. If the trusted-pack case needs an empty declared pack fixture, create the minimal configured pack used by existing config tests; do not mock away `config_mod.load()` because the single-load proof is the acceptance criterion.

- [ ] **Step 3: Add an in-process-only effective config field to `ScanResult`**

Import `WardlineConfig` under `TYPE_CHECKING`, then add this tail field so existing direct `ScanResult(...)` fixtures remain source-compatible:

```python
@dataclass(frozen=True, slots=True)
class ScanResult:
    # existing fields unchanged
    effective_config: WardlineConfig | None = None
```

Document: “Exact configuration object used for discovery/analyzer/ruleset; retained in-process for provenance consumers and never serialized.” In `run_scan()`'s return:

```python
return ScanResult(
    # existing fields unchanged
    effective_config=cfg,
)
```

Add a core identity test:

```python
def test_run_scan_retains_effective_config_in_process(tmp_path, monkeypatch) -> None:
    seen = []
    real_load = config_mod.load

    def recording_load(*args, **kwargs):
        cfg = real_load(*args, **kwargs)
        seen.append(cfg)
        return cfg

    monkeypatch.setattr(config_mod, "load", recording_load)
    result = run_scan(_empty_proj(tmp_path))
    assert len(seen) == 1
    assert result.effective_config is seen[0]
```

Run:

```bash
uv run pytest tests/unit/core/test_run.py -k retains_effective_config -vv
```

Expected: PASS after the field is populated. The object must not be added to MCP output, agent summary, JSONL, SARIF, or legis wire payloads.

- [ ] **Step 4: Remove the second load and narrow `_attach_legis_artifact()`**

Change the call at `src/wardline/mcp/server.py:983` to pass `config=result.effective_config`; fail loudly on an impossible internal missing value before artifact activation:

```python
if result.effective_config is None:
    raise ToolError("scan result did not retain its effective configuration")
_attach_legis_artifact(response, result, path, args, config=result.effective_config)
```

Change `_attach_legis_artifact()` to accept only `config: WardlineConfig`, delete `config_path`, `trust_local_packs`, `trusted_packs`, and `strict_defaults`, and delete its `config_mod.load(...)` block:

```python
def _attach_legis_artifact(
    response: dict[str, Any],
    result: ScanResult,
    path: Path,
    args: dict[str, Any],
    *,
    config: WardlineConfig,
) -> None:
    # activation guards unchanged
    artifact = build_legis_artifact(
        result,
        root=path,
        config=config,
        key=key_bytes,
        allow_dirty=allow_dirty,
    )
```

Keep the existing fail-soft signing refusal behavior. This removes the policy reload; it does not change configuration resolution rules.

- [ ] **Step 5: Run focused provenance and artifact suites**

```bash
uv run pytest \
  tests/unit/core/test_run.py \
  tests/unit/mcp/test_server_arg_hardening.py \
  tests/unit/mcp/test_server_legis_artifact.py \
  tests/unit/core/test_legis_artifact.py -q
```

Expected: PASS. The matrix earns one load and `is` identity for explicit, implicit, trusted-pack, local-pack, and strict-default modes; existing root/subpath hashes and signing status remain unchanged.

- [ ] **Step 6: Run full verification, commit, and close**

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest -q
uv run wardline scan . --fail-on ERROR
git diff --check
git add src/wardline/core/run.py src/wardline/mcp/server.py \
  tests/unit/core/test_run.py tests/unit/mcp/test_server_arg_hardening.py
git commit -m "fix: reuse scan config for legis artifacts"
CONFIG_SHA=$(git rev-parse HEAD)
filigree add-comment wardline-b40ad59ddb \
  "run_scan now retains its exact effective WardlineConfig in-process; MCP legis artifacts consume that same object. One-load/object-identity matrix passed in explicit, implicit, trusted-pack, local-pack, and strict-default modes at ${CONFIG_SHA}." \
  --actor john --expected-assignee codex
filigree transitions wardline-b40ad59ddb --json
filigree close wardline-b40ad59ddb --commit "release/consolidation-2026-06-26@${CONFIG_SHA}" \
  --reason "Artifact provenance now shares the scan's exact policy object with one configuration load." \
  --actor john --expected-assignee codex
```

Expected: one ticket-scoped commit and terminal ticket.

## Final program closeout

- [ ] **Step 1: Re-run the complete gate after all ticket commits**

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest -q
uv run wardline scan . --fail-on ERROR
git diff --check
git status --short
```

Expected: all checks exit 0; `git status --short` is empty. Confirm the four concrete tickets are terminal with their respective commit anchors. Inspect any generated artifact before removing it; never stage generated scan output accidentally. No umbrella ticket is closed by this plan.
