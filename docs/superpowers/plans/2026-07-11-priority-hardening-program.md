# Priority Hardening Program Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile the stale tracker records, execute every approved hardening sub-plan in risk order, and prove that no requested concrete work remains open.

**Architecture:** This is the orchestration plan. It performs tracker-only acceptance first, creates narrowly scoped child tickets for broad parents, delegates code work to the subsystem plans, and ends with a live completion audit. Every code-bearing ticket retains its own commit and Filigree lifecycle.

**Tech Stack:** Filigree MCP 3.1, Git, pytest, Ruff, mypy, Wardline CLI/MCP.

---

### Task 1: Establish the live execution baseline

**Files:**
- Inspect: `docs/superpowers/specs/2026-07-11-priority-hardening-burndown-design.md`
- Inspect: `docs/superpowers/plans/2026-07-11-*-implementation.md`

- [ ] **Step 1: Verify repository and tracker health**

Run:

```bash
git status --short
git branch --show-current
git rev-parse --short HEAD
filigree mcp-status --json
filigree stats --json
```

Expected: clean worktree, branch `release/consolidation-2026-06-26`, Filigree schema compatible, and verified actor `john`.

- [ ] **Step 2: Verify every requested issue is still in the expected category**

Call `mcp__filigree__issue_get` for:

```text
wardline-da175547cf
wardline-2e6ad7772c
wardline-6f9eece880
wardline-8a1399a8b5
wardline-7b4c550e21
wardline-550ea44e53
wardline-80e457bc41
wardline-18499aaa2d
wardline-b40ad59ddb
wardline-c66f62894b
```

Expected: no issue has been concurrently closed or claimed by another worker. If live state differs, reconcile the plan to the live record before writing.

### Task 2: Accept and close the landed federation refactors

**Files:**
- Verify: `src/wardline/core/federation_status.py`
- Verify: `src/wardline/core/http.py`
- Test: `tests/conformance/test_federation_status_envelope_parity.py`
- Test: `tests/unit/core/test_http.py`

- [ ] **Step 1: Verify the shared federation-status implementation**

Run:

```bash
uv run pytest -q tests/conformance/test_federation_status_envelope_parity.py
```

Expected: PASS; MCP, CLI, scan jobs, and schema projections agree.

- [ ] **Step 2: Record acceptance and close `wardline-80e457bc41`**

Call `mcp__filigree__comment_add`:

```json
{
  "actor": "john",
  "issue_id": "wardline-80e457bc41",
  "text": "Live acceptance: commit 9f0c4d18 introduced the canonical core/federation_status.py builders; MCP, CLI, scan jobs, scan-file workflow, and agent-summary adapters delegate to them. tests/conformance/test_federation_status_envelope_parity.py passes and pins runtime plus schema parity. The remaining wrappers are presentation adapters, not duplicate projectors."
}
```

Then call `mcp__filigree__issue_close`:

```json
{
  "actor": "john",
  "issue_id": "wardline-80e457bc41",
  "commit": "release/consolidation-2026-06-26@9f0c4d18",
  "reason": "Accepted landed federation-status single-source refactor after live parity verification."
}
```

Expected: status `closed`.

- [ ] **Step 3: Verify the shared HTTP implementation**

Run:

```bash
uv run pytest -q tests/unit/core/test_http.py tests/unit/core/test_http_redirect_federation.py
```

Expected: PASS; shared scheme gate, redirect refusal, bounded reads, and response mapping remain pinned.

- [ ] **Step 4: Record acceptance and close `wardline-18499aaa2d`**

Call `mcp__filigree__comment_add`:

```json
{
  "actor": "john",
  "issue_id": "wardline-18499aaa2d",
  "text": "Live acceptance: commit 5b0dcf24 introduced core.http.WeftHttp and the originally cited federation clients consume it while retaining client-owned authentication/signing. Shared HTTP and redirect-refusal suites pass. Residual adapter protocols are intentional test seams, not independent urllib transports."
}
```

Then call `mcp__filigree__issue_close`:

```json
{
  "actor": "john",
  "issue_id": "wardline-18499aaa2d",
  "commit": "release/consolidation-2026-06-26@5b0dcf24",
  "reason": "Accepted landed WeftHttp consolidation after live transport verification."
}
```

Expected: status `closed`.

### Task 3: Split the broad security and FastAPI parents

**Files:**
- Tracker only; no repository files.

- [ ] **Step 1: Create the gate-population child**

Call `mcp__filigree__issue_create`:

```json
{
  "actor": "john",
  "type": "task",
  "priority": 1,
  "parent_issue_id": "wardline-8a1399a8b5",
  "title": "Replace parallel gate fields with a tagged GatePopulation contract",
  "description": "Secure-default gating is encoded by independently optional gate_findings and gate_honors_suppressions fields. Replace them with one frozen tagged GatePopulation value carrying findings plus UNSUPPRESSED or HONORS_SUPPRESSIONS posture. Preserve full/default, trusted-suppression, delta, and full-fallback semantics with illegal-state regressions.",
  "labels": ["arch-analysis-2026-06-28", "security-invariant", "gate-soundness"]
}
```

Expected: a new child issue ID; record it in the gate-hardening plan execution notes.

Created 2026-07-11: `wardline-84e470ea62`.

- [ ] **Step 2: Create the confinement-contract child**

Call `mcp__filigree__issue_create`:

```json
{
  "actor": "john",
  "type": "task",
  "priority": 2,
  "parent_issue_id": "wardline-8a1399a8b5",
  "title": "Make Wardline's two-stage confinement policy explicit",
  "description": "Preserve direct request confinement and config-derived discovery confinement as distinct defenses, but replace ambiguous shared-entry booleans with an explicit policy and document that a confined config path does not certify paths named inside it. Pin direct, source-root, symlink, secure-default, and legacy-opt-out behavior.",
  "labels": ["arch-analysis-2026-06-28", "security-invariant", "path-confinement"]
}
```

Expected: a new child issue ID.

Created 2026-07-11: `wardline-07fa744fe1`.

- [ ] **Step 3: Create the fingerprint-enforcement disposition child**

Call `mcp__filigree__issue_create`:

```json
{
  "actor": "john",
  "type": "task",
  "priority": 3,
  "parent_issue_id": "wardline-8a1399a8b5",
  "title": "Verify and document fingerprint determinism enforcement ownership",
  "description": "Audit the frozen identity corpus, FINGERPRINT_SCHEME mismatch guard, cross-interpreter CI matrix, and producer-source seam record. Close as already enforced if all remain mandatory; repair only missing enforcement. Do not relocate stable AST serialization solely for nominal locality.",
  "labels": ["arch-analysis-2026-06-28", "security-invariant", "fingerprint-determinism"]
}
```

Expected: a new child issue ID.

Created 2026-07-11: `wardline-a9fc850424`.

- [ ] **Step 4: Create the precise FastAPI request-source child**

Call `mcp__filigree__issue_create`:

```json
{
  "actor": "john",
  "type": "task",
  "priority": 2,
  "parent_issue_id": "wardline-7b4c550e21",
  "title": "Cover precise FastAPI Request re-export and nested raw query sources",
  "description": "Recognize fastapi.requests.Request, req.url.query, and req.scope[query_string] without tainting url or scope wholesale. Preserve clean controls and add pins for already-working async stream, multidict, and Depends behavior.",
  "labels": ["dogfood-2026-06-28", "wardline-expansion", "fastapi"]
}
```

Expected: a new child issue ID.

Created 2026-07-11: `wardline-4b728106c8`.

- [ ] **Step 5: Create the Pydantic route-body child**

Call `mcp__filigree__issue_create`:

```json
{
  "actor": "john",
  "type": "task",
  "priority": 2,
  "parent_issue_id": "wardline-7b4c550e21",
  "title": "Seed Pydantic body models only at recognized FastAPI routes",
  "description": "Add route-aware parameter classification so a Pydantic model parameter is attacker-controlled only when the function is a recognized FastAPI route and the annotation resolves to a Pydantic model. Preserve non-route and validated-provider controls.",
  "labels": ["dogfood-2026-06-28", "wardline-expansion", "fastapi", "pydantic"]
}
```

Expected: a new child issue ID.

Created 2026-07-11: `wardline-fff71be81a`.

### Task 4: Execute the subsystem plans in risk order

**Files:**
- Execute: `docs/superpowers/plans/2026-07-11-gate-hardening-implementation.md`
- Execute: `docs/superpowers/plans/2026-07-11-mcp-federation-honesty-implementation.md`
- Execute: `docs/superpowers/plans/2026-07-11-fastapi-input-coverage-implementation.md`
- Execute: `docs/superpowers/plans/2026-07-11-bounded-decorator-coverage-implementation.md`

- [ ] **Step 1: Execute lineless-defect fail-closed work**

Run the `wardline-da175547cf` section of the gate-hardening plan with a fresh implementation subagent and two-stage review.

Expected: red/green proof, focused and full verification, one commit, issue closed.

- [ ] **Step 2: Execute destructive MCP boolean pins**

Run the `wardline-2e6ad7772c` section of the MCP/federation plan.

Expected: every approved destructive boolean rejects string `"false"` without side effects; one test-only commit; issue closed.

- [ ] **Step 3: Execute authentication-honest identity resolution**

Run the `wardline-6f9eece880` section of the MCP/federation plan. Use `work_start` with `advance=true`, set severity before closing, and split the unrelated zero-facts cleanup.

Expected: 401/403 remain fail-soft but are distinguishable from genuine entity absence on every resolver consumer; one commit; bug closed through its required workflow.

- [ ] **Step 4: Execute the split security-invariant children**

Run the three child sections of the gate-hardening plan in gate-population, confinement, fingerprint order.

Expected: each child has an independent evidence-backed disposition. Close parent `wardline-8a1399a8b5` only after all three are terminal.

- [ ] **Step 5: Execute the split FastAPI children**

Run the FastAPI plan in precise request-source then route-body order.

Expected: confirmed false negatives close without broad non-route over-tainting. Close parent `wardline-7b4c550e21` only after both children are terminal.

- [ ] **Step 6: Execute bounded decorator coverage**

Run the decorator-coverage plan.

Expected: bounded default, server-side filtering, page-before-enrichment, explicit truncation, CLI/MCP parity, one commit, issue closed.

- [ ] **Step 7: Execute the Legis exact-config residual**

Run the `wardline-b40ad59ddb` section of the MCP/federation plan.

Expected: one policy load, exact config object passed into artifact construction, matrix regressions green, one commit, issue closed.

### Task 5: Refresh the seam-conformance program tracker

**Files:**
- Tracker only; inspect: `docs/product/decisions/0002-rotate-now-to-weft-seam-conformance.md`

- [ ] **Step 1: Re-read live child state and the authoritative Weft program decision**

Call `mcp__filigree__issue_get` for `wardline-c66f62894b`, `wardline-23c8e4bef4`, and `wardline-da883a2d07`; read the current PDR.

Expected: closed children are excluded from the live frontier; the two P4 children and their gating posture are explicit.

- [ ] **Step 2: Replace the parent description with current state**

Call `mcp__filigree__issue_update` with actor `john`, issue `wardline-c66f62894b`, and a description that:

```text
- records c0563eee74 and 79ba05f464 as closed with their acceptance commits;
- lists only 23c8e4bef4 and da883a2d07 as open Wardline-resident children;
- states that both are P4 and non-gating;
- names cross-repo work as hub-owned references, not Wardline blockers;
- defines parent completion as all Wardline-resident children terminal plus the hub acceptance ledger recording the cross-repo disposition.
```

Expected: parent remains `in_progress` unless that done definition is already satisfied by live hub evidence.

### Task 6: Perform the final completion audit

**Files:**
- Audit: `docs/superpowers/specs/2026-07-11-priority-hardening-burndown-design.md`
- Audit: `/home/john/.codex/attachments/2ec5fb61-f373-4ffe-bc00-3898eca00f20/pasted-text-1.txt`

- [ ] **Step 1: Run the complete repository verification stack**

Run:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest -q
uv run wardline scan . --fail-on ERROR
git diff --check
git status --short
```

Expected: every command exits 0; no unexpected generated or untracked files remain. Record any inert-gate warning without using it as proof of ticket behavior.

- [ ] **Step 2: Audit every requested ticket and child from live Filigree**

Query all original and created issue IDs. Build a checklist mapping each design requirement to code, test, commit, and terminal tracker evidence.

Expected:

```text
- six original implementation priorities have terminal evidence-backed dispositions;
- all split children are terminal;
- 80e457bc41 and 18499aaa2d are closed by acceptance;
- b40ad59ddb is closed after exact-config repair;
- c66f62894b accurately reflects its live frontier;
- no concrete requested ticket remains open.
```

- [ ] **Step 3: Mark the persistent goal complete only after the audit passes**

Call `update_goal({"status":"complete"})` only when every expected condition above is proven by current evidence.

Expected: goal status `complete`; report final verification and tracker state to the user.
