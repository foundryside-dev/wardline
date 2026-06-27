# weft-seam-conformance crit-3 — Reality Validation + Scoped Plan

> **For Claude:** This is a *reality-validation + decision-gate* document, not yet an
> executable plan. The implementation-planning skill's reality pass found the two
> tickets materially stale: most of crit-3 already shipped, and the genuinely-remaining
> slice hinges on a design fork + one owner-gated decision. Resolve the gate (below)
> THEN expand the task skeleton into a full TDD plan and run `/review-plan`.

**Source bet:** PRD-0002 (weft-seam-conformance), criterion 3 — "producer artifacts peers
can verify against." Tickets `wardline-c0563eee74` (warpline↔wardline contract) +
`wardline-79ba05f464` (SEI-oracle producer-source drift required in CI).

**Validated at:** HEAD `c7fa4580` on `release/consolidation-2026-06-26`, 2026-06-28.

---

## Ground truth (what actually exists at HEAD)

### crit-3a — `wardline.delta_scope.v1` producer artifact + in-CI drift check → **DONE**

- **Artifact published:** `tests/conformance/wardline_delta_scope_contract.v1.json`
  (schema `wardline.delta_scope.v1`, 13 fields).
- **In-CI drift check (unconditional):**
  `tests/conformance/test_wardline_delta_scope_contract.py::test_delta_scope_matches_published_contract`
  — asserts `DeltaScopeReport.to_dict()` field-set == the published contract. Carries **no
  marker**, so it runs in the default `test` job on every PR (`pyproject.toml:147` only
  deselects e2e/drift markers). A producer field add/remove reds CI until the artifact is
  bumped. **This is exactly crit-3a's acceptance — already satisfied. Bank it.**

### Consumer-side seams (`c0563eee74`) — Layer-1 done, Layer-2 not in CI

- **Layer-1 byte-pin (default CI, fail-closed):**
  `test_warpline_worklist_drift.py::test_vendored_wire_matches_upstream_blob_pin`
  + `test_vendored_wire_is_accepted_by_the_consumer`. ANY edit to the vendored warpline
  wire reds the default suite. **Done.**
- **Layer-2 source drift (marker `worklist_drift` — NEVER runs in CI):**
  `test_warpline_worklist_drift.py::test_vendored_wire_matches_warpline_source` — byte-compares
  the vendored copy against the real warpline source; **skips when the sibling is absent**,
  and `worklist_drift` is deselected by `pyproject.toml:147`. No CI job runs it.
- **Fixtures-vs-published-schema (skip unless `WARPLINE_REPO` set):**
  `test_warpline_delta_scope.py::test_vendored_worklist_matches_published_artifact` — validates
  every vendored worklist fixture against warpline's published
  `contracts/reverify_worklist.v1.schema.json`. **NEW: warpline has now published that schema**
  (`~/warpline/contracts/reverify_worklist.v1.schema.json` exists), so this is unblocked.
  ⚠️ env-var inconsistency: this test reads `WARPLINE_REPO`; the sibling-drift tests read
  `WARDLINE_WARPLINE_REPO` / `WARDLINE_LOOMWEAVE_REPO`. Normalize to the `WARDLINE_*` form.

### crit-3b — SEI-oracle producer-source drift required in CI (`79ba05f464`) → **real gap**

- **Layer-1 blob-pin (default CI, fail-closed):**
  `test_sei_oracle.py::test_vendored_oracle_matches_upstream_blob_pin` + the six §8 behavior
  tests + `test_every_oracle_scenario_is_covered`. **Done.**
- **Layer-2 source drift (marker `sei_drift` — NEVER runs in CI):**
  `test_sei_oracle.py::test_vendored_oracle_matches_loomweave_source` — byte-compares vs
  loomweave's authoritative source; **skips when the sibling is absent**, and `sei_drift` is
  deselected by `pyproject.toml:147`. No CI job runs it. Loomweave's source IS present locally
  (`~/loomweave/docs/federation/fixtures/sei-conformance-oracle.json`).

### CI shape (`.github/workflows/ci.yml`)

- `test` job: `uv run pytest --cov…` with the default `addopts` that **deselects** every
  `*_drift` and `*_e2e` marker. → drift markers never run on PRs.
- `live-oracles` matrix (schedule/`workflow_dispatch` only): runs `loomweave_e2e` /
  `warpline_e2e` / etc. **fail-closed** via `WARDLINE_LIVE_ORACLE_REQUIRED=1` (a conftest
  `pytest_runtest_makereport` hook turns SKIP→FAIL). It provisions sibling **binaries** via
  secrets (`WARDLINE_LOOMWEAVE_BIN`, `WARDLINE_WARPLINE_BIN`) — **not source checkouts**.
- **No job provisions sibling source**, so the `sei_drift` / `worklist_drift` source
  byte-compares have no home. This is the whole remaining gap.

---

## The deliberate design this work changes (state it consciously)

The codebase intentionally made the source-drift checks **release-gate, skip-in-CI-by-default**:
Layer-1 blob-pins are the per-PR fail-closed guard ("…the protection that lets the Layer-2
recheck skip clean when the sibling checkout is absent"). Making the source-drift required is
the conscious posture change the ticket/PRD asks for — it does **not** replace Layer-1; it adds
a cross-repo authority check on a cadence. The natural low-coupling fit is the **existing
weekly/dispatch `live-oracles` cadence**, not every PR (keeps PRs hermetic + fast).

## Decision gate (resolve before writing the full plan)

**Fork — how does CI see the authoritative producer source?**

- **(A) Sibling source checkout in CI.** Add a fail-closed job (or extend `live-oracles`) that
  `actions/checkout`s loomweave + warpline, sets `WARDLINE_LOOMWEAVE_REPO` /
  `WARDLINE_WARPLINE_REPO`, and runs `pytest -m "sei_drift or worklist_drift"` with
  `WARDLINE_LIVE_ORACLE_REQUIRED=1`. *Pro:* compares against authoritative HEAD; matches the
  existing fail-closed pattern; wardline-side. *Con:* couples to sibling repo availability/ref
  and **needs a cross-repo read credential** for private siblings.
- **(B) Producer-published-artifact fetch.** Peers publish the artifact to a stable *fetchable*
  location (release asset / pinned raw URL); wardline CI fetches + byte-compares. *Pro:* looser
  coupling, versioned. *Con:* peers currently publish to a local repo **path**, not a URL — a
  fetch endpoint is unshipped peer work (**partial scope C**); more moving parts.

**Owner action (not a grant escalation):** path A needs wardline CI to gain **read access** to
the loomweave + warpline repos — a GitHub secret only the owner can add. This is routine
first-party infra (all foundryside repos, reversible, no release / deprecation / pricing /
external-party action), gated *solely* because (a) the agent cannot add a repo secret and (b) the
credential's security scope is a least-privilege choice. Recommended: a read-only **deploy key per
sibling** (narrowest), or a fine-grained PAT scoped to `contents:read` on just those two repos.

**Scope check (PDR-0002 reversal trigger #1):** the peer *artifacts* now exist, so this is **not**
blocked on unshipped peer code — it is wardline-side CI + one owner credential decision. If path
(B) is chosen and a peer must stand up a *fetch endpoint*, that leg is scope C.

## Recommended routing (revised — leaner than a full design cycle)

The evidence already decides the design: **path A, folded into the existing weekly/dispatch
`live-oracles` matrix** (which already runs fail-closed via `WARDLINE_LIVE_ORACLE_REQUIRED=1`).
Path B is partial scope-C (peers publish to local repo *paths*, not fetchable URLs). Adding a
checkout step + marker selection + one env-var rename does not warrant a
`/axiom-solution-architect` cycle (the planning skill's "don't use for well-established patterns").

1. **crit-3a banked** — DONE (ticket `c0563eee74` commented + narrowed 2026-06-28).
2. **T2 env-var normalize** — DONE this session (verified red→green).
3. **Owner action** — provision the cross-repo read credential (above). The only blocker for T3.
4. **T3** — once the credential exists: fold the source-drift markers into `live-oracles`,
   fail-closed. Small + mechanical; `/review-plan` optional given the size.

---

## Task skeleton (expand after the gate resolves)

- **T1 — Bank crit-3a. ✅ DONE 2026-06-28.** `test_wardline_delta_scope_contract.py` confirmed
  green/unconditional in the default suite; `c0563eee74` commented + narrowed to the
  consumer-source-drift CI leg.
- **T2 — Normalize the env var. ✅ DONE 2026-06-28.** `test_warpline_delta_scope.py` read a stale
  `WARPLINE_REPO`; unified to `WARDLINE_WARPLINE_REPO` (one resolution contract across all `_drift`
  rechecks). Verified red→green: skipped pre-fix with the standard var set; now runs + passes vs
  warpline's published schema. ruff clean. *(wardline-only, no gate.)*
- **T3 — CI job for source drift (gated on the fork).** New/extended fail-closed job that
  provisions sibling source and runs `pytest -m "sei_drift or worklist_drift"` (+ the
  published-schema validation) with `WARDLINE_LIVE_ORACLE_REQUIRED=1`. Each leg lands with a
  test/CI assertion that fails pre-fix (e.g. a planted drifted byte reds the job).
- **T4 — Guardrail proof (PRD crit 5).** Confirm G1 (byte-identical active-finding set before/after
  — these are test/CI-only changes, no engine touch), G3 (no new required human config — the
  credential is CI-secret infra, not a `wardline scan` config step), G4 (no new base runtime dep;
  `jsonschema` already an extra used by the published-schema test).
