# 05 — Code Quality Assessment

**Target:** `wardline` @ `e4668abc` · **Date:** 2026-06-28
**Basis:** the 12 validated catalog entries (`02-subsystem-catalog.md`), re-verified against source for the
headline items, with each concern mapped to a live Filigree issue ID or flagged genuinely-new. Severity is
by **blast radius** (would this produce a wrong gate verdict / silent security regression / broad refactor
hazard), not by line count.

## Scorecard

| Dimension | Grade | Note |
|---|---|---|
| Correctness discipline | A | Fail-closed everywhere; weakest-link meet; monotone fixed point with guardrails |
| Security posture | A− | Secure-by-default gate, layered confinement, HMAC caches/wires; invariants split across seams |
| Test investment | A− | 367 test files (~2:1), conformance + golden + hypothesis + `clarion_e2e`; 90% coverage gate |
| Dependency hygiene | A | Zero-dep base verified clean by all 12 reviewers; lazy `require_*` extras |
| Modularity / cohesion | B− | Real subsystem boundaries, but god-functions + porous private-name seams |
| Layering / acyclicity | B | One contract passes; ~102 deferred imports still mask real `core/` cycles |
| Docs/tracker fidelity | B− | Stale "BROKEN" comment, non-gating CI, several largely-done open tickets |
| **Overall** | **B+** | Strong, coherent, well-tested; debt is concentrated and well-understood |

---

## High severity

### H1 — `core/` layering goal is only partially realized; the passing contract is left non-gating, with a stale "BROKEN" comment
- **Evidence:** `pyproject.toml:170-182` declares the contract "BROKEN today (wardline.scanner.pipeline /
  .taint.project_resolver import wardline.core.attest)"; reality at HEAD — no `core.attest` import in
  `scanner/`, both files import `core.ruleset.ruleset_hash` (`pipeline.py:134`, `project_resolver.py:28`),
  `lint-imports` → **1 kept, 0 broken** (run by orchestrator + validator). CI runs it as
  `uv run lint-imports || true` (`.github/workflows/ci.yml:38`) so the now-passing contract is non-gating.
  The narrow ticket `wardline-9ec283d168` is **CLOSED (2026-06-20)** — but its close-note records the
  *broad* goal as residual: deferred-import count 158→**102**, "remaining graph hotspots can be tracked by
  future layering work," with real cycles still latent (`run → … → attest → assure → run`).
- **Impact:** Two distinct problems. (a) Cheap correctness-of-record fix: the comment misleads every reader
  and the gate is needlessly off. (b) Real structural debt: ~102 function-local imports mask cycles, so a
  reorg or a new top-level import can surface masked breakage at runtime.
- **Filigree:** narrow contract = `wardline-9ec283d168` (CLOSED, correctly). The **broad layering residual
  is untracked** → **NEW issue** recommended (parent `wardline-bf004e2aea`). Quick win (flip CI to gating +
  fix comment) is also untracked → fold into the new issue or a tiny PR.

### H2 — Security invariants are enforced across a caller/callee seam, not locally (3 instances)
- **Evidence:** (a) Secure-by-default gating — `gate_trips`/`gate_breakdown` are population-agnostic
  (`suppression.py:88-126`); the "evaluate the un-suppressed population" property is enforced by S4
  *choosing* which population to pass (`run.py:486-489`). A future caller handing the suppressed population
  silently defeats it. (b) THREAT-001 confinement is split `resolve_under_root` (S10 `mcp/tooling.py:78`) +
  `confine_to_root`/`safe_paths` (S4). (c) Fingerprint determinism — the join key every baseline/waiver
  rests on is computed in `scanner/rules/_fingerprint.py:_canonical_ast_dump` (S1/S2), with **no S8-local
  guard** (S8 owns the identity domain).
- **Impact:** Each is correct today and guarded by conformance tests
  (`test_axis7_gate_population_not_narrowed`, the identity oracle), but each is a *split invariant* a
  refactor on one side can break with no local failure — and the fingerprint case already drifted once
  (the 3.12↔3.13 fix at `_fingerprint.py:18-24`).
- **Filigree:** untracked as an architectural class → **NEW issue** recommended (umbrella: "promote split
  security invariants to type-/assertion-enforced where feasible; document the seam contracts").

### H3 — `pytest`-coupled handshake bypass in production MCP code
- **Evidence:** `JsonRpcServer.__init__` sets `_initialized = _initializing = ("pytest" in sys.modules)`
  (`mcp/protocol.py:43-46`), so under pytest the server is born initialized and the "server not
  initialized" gate (`protocol.py:99-100`) is silently disabled.
- **Impact:** Harmless in the shipped CLI launch, but it couples production code to the test runner's
  module table; any embedding that imports pytest (or a future in-process test of the real handshake)
  misfires. A test affordance leaking into a protocol-correctness gate.
- **Filigree:** untracked → **NEW issue** recommended (small, surgical: inject the initialized-state for
  tests instead of sniffing `sys.modules`).

---

## Medium severity

### M1 — God-functions / god-modules (change-risk hotspots)
- **Evidence:** `core/run.py:run_scan` ~374 lines (`run.py:221-594`); `scanner/analyzer.py:_analyze_inner`
  ~857 lines + ~17 closures (`analyzer.py:249-1105`); `scanner/taint/variable_level.py` ~2,481 LOC;
  `mcp/server.py` 5,003 lines (~3,000 inline JSON Schema); `install/doctor.py` ~947 lines multi-concern.
- **Impact:** High cyclomatic complexity, only end-to-end testable, easy to regress. The `server.py` size is
  partly deliberate (declaration-next-to-handler) and lower-risk; `run_scan`/`_analyze_inner`/`variable_level`
  are the load-bearing ones.
- **Filigree:** untracked → **NEW issue(s)** recommended, scoped per-function with the conformance suite as
  the safety net (this is a refactor, not a behavior change).

### M2 — `decorator_coverage` (and `scan_file_findings`) return unbounded inventories on the MCP surface
- **Evidence:** `_DECORATOR_COVERAGE_TOOL` input schema is only `{path, config}` — no `where`/`offset`/
  truncation (`server.py:3092-3115`); handler returns one row per decorated entity (`server.py:2886-2903`).
  `scan_file_findings.active_defects` is the same class, lower volume (`server.py:399-560`). This is the
  exact context-overflow class `scan` was already hardened against.
- **Filigree:** `decorator_coverage` = **`wardline-550ea44e53` (OPEN, P2)** — confirmed live in the ready
  queue; `scan_file_findings` where/paging = **`wardline-a3eacc5d36` (OPEN, P3)**; the sibling judge-slice
  is **`wardline-88104b44f1` (OPEN, P3)**. All tracked — no new issue.

### M3 — Lineless-DEFECT downgrade leaves the gate population (fail-open-leaning)
- **Evidence:** a `Kind.DEFECT` with `location.line_start is None` (not `ENGINE_PATH`) is *replaced* by a
  `Severity.NONE` `Kind.FACT` (`WLN-ENGINE-LINELESS-DEFECT`, `suppression.py:47-67`), so it no longer gates.
- **Impact:** Deliberate (avoids fingerprint-collision on lineless defects) and mitigated by an
  always-emitted warning fact, but a class of DEFECT silently exits the gate population. Worth a guard/test
  that this can only happen for known-safe rule families.
- **Filigree:** untracked → **NEW issue** recommended (low-medium; document + pin the safe set).

### M4 — Porous private-name coupling across subsystem seams
- **Evidence:** S2 rules import `decorator_provider._is_builtin_decorator_fqn`/`_shadowed_builtin_roots`
  (`contradictory_trust.py:30`, `invalid_decorator_level.py:20`); S1 `grammar.py:196` imports
  `variable_level._SERIALISATION_SINKS`; S6 `delta_resolve.py:350` reaches `sei_resolver._client`; S11
  `cli/doctor.py:12-22` reaches seven `install.doctor` privates; S8 `rekey.py:54` hand-mirrors a scanner
  constant. Import-linter cannot see most of these.
- **Impact:** A refactor of an underscore-prefixed helper silently breaks a consumer (two of them security
  rules). The natural fix is to promote each to a small shared public surface.
- **Filigree:** untracked → **NEW issue** recommended (umbrella: "promote cross-subsystem `_private`
  dependencies to public seams").

### M5 — `cli/doctor` and the MCP `doctor` render from independent assemblies (human/machine drift)
- **Evidence:** the MCP path goes through the single public `machine_readable_doctor` (`server.py:3853`,
  pinning test exists), but `cli/doctor.py` re-assembles the human report from seven `install.doctor`
  private helpers independently (`cli/doctor.py:12-22`) — so the two renderings can drift.
- **Filigree:** untracked → fold into **M4's** new issue or a small dedicated one.

---

## Low severity

| ID | Finding | Evidence | Filigree |
|----|---------|----------|----------|
| L1 | `safe_paths` parent-dir TOCTOU window (O_NOFOLLOW on final component only) | `safe_paths.py:82-93` | NEW (low; narrow window, documented) |
| L2 | `install/pre_commit.py` is the weakest install writer (substring detect, string-concat YAML, bare `except`) | `pre_commit.py:16,19,42` | NEW (low; harden to a YAML parser like `block.py`/`mcp_json.py`) |
| L3 | `autofix.py` "codemod engine" framing oversells a single hard-coded PY-WL-111 fixer | `autofix.py:1,110` | NEW (doc/naming, or generalize dispatch) |
| L4 | N-hop taint provenance is single-hop without the optional Loomweave store; standalone explain/attach triggers a full re-scan | `explain.py:8-9,235`; `filigree_issue.py:276` | `wardline-82f49ec3c3` is **CLOSED (2026-06-01)** — it shipped *single-hop* return-indirection only; the broader **N-hop-without-store completeness residual is UNTRACKED → NEW**. (Note: `ROADMAP.md` still lists this as a near-term thread — itself stale, another tracker-drift instance.) By design; completeness gap |
| L5 | `verify_attestation` missing-schema / non-dict-payload paths exist but are unpinned | `attest.py:329,336` | `wardline-d59f35c626` (OPEN, P3) — tracked |
| L6 | Federation transport/envelope extraction largely landed; residual is thin per-client adapter shells | `core/http.py:47`, `federation_status.py` | `wardline-18499aaa2d` (P3) + `wardline-80e457bc41` (P2) — **triage close-or-rescope**, not net-new |
| L7 | Rust FN gaps (mid-chain `?`/`.await`; block/inner doc-comment markers) — all fail-closed | `dataflow.py:254-281`; `provider.py:64-83` | `wardline-535c9531cc` (P3) + `wardline-9c3a76b257` (P3); note sub-item #4 of the latter is since-addressed (`analyzer.py:175-181`) |
| L8 | Rust `config` accepted-but-unused; `last_context` always `None` (delta/SARIF degrade to file scope); `edges.py` unwired | `analyzer.py:67-76,88-91`; `edges.py:38-44` | NEW or fold into a Rust-preview tracker |
| L9 | Stale staging docstrings ("SP1 ships only…") in the taint provider | `provider.py:5-8`, `resolver_metadata.py:30-34` | NEW (doc rot; trivial) |
| L10 | `node_id.py` `NodeId` contract consumed only by Rust; Python path still keys on raw `id(node)` | `node_id.py:9-16` | NEW (half-laid contract; finish or document deferral) |

---

## Tracker-fidelity summary (the meta-finding)

The analysis repeatedly found **the code ahead of its own tracker/docs**. Confirmed:
- `wardline-9ec283d168` (layering) — **CLOSED**, fix landed, but `pyproject.toml` + CI still say/treat
  "BROKEN."
- `wardline-18499aaa2d`, `wardline-80e457bc41` — **OPEN but largely already implemented** (shared `WeftHttp`
  + `federation_status` exist and are consumed by all surfaces); residual is thin shells → triage.
- `wardline-9c3a76b257` sub-item #4 — **since-addressed** in source; issue text stale.

**Recommendation:** a short tracker-reconciliation pass (re-triage the largely-done tickets, fix the
stale comment, flip CI to gating) is the highest-leverage, lowest-risk work available — it converts
"silent partial completion" into accurate state before any new construction. Routing in
`06-architect-handover.md`.
