# 04 — Architecture Analysis: Final Report

**Target:** `wardline` — generic semantic-tainting static analyzer for Python (+ preview Rust frontend)
**Commit:** `e4668abc` (branch `release/consolidation-2026-06-26`) · **Version:** 1.0.7 (dev) / 1.0.6 shipped
**Date:** 2026-06-28 · **Deliverable:** Option C (Architect-Ready)
**Method:** Loomweave-indexed holistic scan → 12 parallel `codebase-explorer` agents (graph-derived
dependencies, `file:line` evidence) → `analysis-validator` gate (PASS-WITH-NOTES) → orchestrator synthesis.
Headline findings re-verified directly against source + `lint-imports` + Filigree.

---

## 1. Executive summary

Wardline is a **mature, deliberately-scoped, production-stable** static analyzer (~42.5K LOC Python, 182
source files, 367 test files — a ~2:1 test:source file ratio). Its thesis is sharp and consistently
executed: **silent until opt-in.** Undecorated code is "unknown-trust" and produces no findings; a
developer declares trust with three decorators and only then is enforcement active. This is what lets it
scan large codebases (including its own) with zero noise, and it is visible in the code, not just the docs.

Two engineering invariants are upheld with unusual discipline across all 12 subsystems:

1. **Zero-dependency base.** `dependencies = []`; every capability (scanner, Rust, Loomweave, judge, docs)
   lives behind a small extra reached through lazy `require_*` gates. The four validators independently
   confirmed no base module imports a third-party package — even crypto and HTTP are stdlib
   (`hmac`/`hashlib`/`urllib`).
2. **Identical-by-construction surfaces.** CLI, MCP, and LSP all route through one shared
   `run_scan`/`gate_decision` keystone (S4), so findings and gate verdicts cannot drift between surfaces —
   asserted by a parity test and enforced by a `GateDecision` invariant that makes a "tripped-but-PASSED"
   verdict unrepresentable.

The codebase is **security-conscious by default**: secure-by-default gating (the gate evaluates the
*un-suppressed* population unless `--trust-suppressions`), layered path-confinement against an untrusted
scan tree (read-side `discover`, write-side `safe_paths` O_NOFOLLOW, config-value confinement, MCP
`resolve_under_root`), fail-closed engine diagnostics (an unparseable file becomes a gate-eligible DEFECT,
never a silent skip), and HMAC-authenticated caches/wires.

**Overall architecture grade: B+ / strong.** The design is coherent, the boundaries are real, and the
test investment is serious. The debt is concentrated and well-understood: a handful of **god-functions**
(`run_scan`, `_analyze_inner`, `variable_level.py`), **porous private-name coupling at subsystem seams**,
and a set of **security invariants enforced across a caller/callee seam rather than locally** — correct
today, fragile to refactor. Most strikingly, the analysis surfaced **tracker/documentation drift**: the
single most-cited "known violation" is already fixed.

---

## 2. What the system does (architecture in one pass)

A scan flows **discover → analyze → suppress → gate → emit** (see `03-diagrams.md` sequence):

- **Engine floor (S1/S2/S3).** `WardlineAnalyzer` parses with stdlib `ast`, indexes entities, and drives a
  staged taint computation: L1 trust-decorator seeding → **L3 SCC fixed point** over the inter-module call
  graph → L2 flow-sensitive per-variable walk *consuming* the refined L3 output. All aggregation uses a
  weakest-link meet (never a join), every unknown defaults to `UNKNOWN_RAW` (fail-closed, never launders
  untrusted→trusted). The result is a frozen, deep-immutable `AnalysisContext`. The **rule lattice** (26
  PY-WL rules, 15 stable + 11 preview) is a duck-typed, centrally-registered set where each rule is a
  `check(context) -> list[Finding]`; the dangerous-sink family shares a `TaintedSinkRule` template.
- **Policy / orchestration (S4/S6/S8).** `run_scan` composes discovery, optional `--affected` delta
  scoping, suppression (baseline/waivers/judged), gate-population materialisation, and scope reporting;
  `gate_decision` turns it into a pass/fail verdict. S6 owns the secure-by-default gate predicates,
  git-committable baseline, expiry-aware waivers, the advisory (never-narrows-the-gate) delta scan, and a
  single-rule autofix. S8 is the **baseline-stability backbone**: the interpreter-stable finding
  fingerprint, qualname production, SEI resolution, and the crash-safe `rekey` migration.
- **Evidence & outputs (S5/S7).** S5 is the `Finding` model + every projection (JSONL, SARIF 2.1.0, native
  Filigree emit, agent-summary, taint-chain explain). S7 turns a scan into *evidence*: a signed
  reproducible `attest` bundle, the `assure` coverage posture, a cross-tool `dossier`, and the opt-in,
  network-fenced LLM triage `judge` whose FALSE_POSITIVE verdicts become auditable committed suppressions.
- **Federation (S9).** Stdlib-urllib-only, byte-exact replicas of each sibling's verifier (Loomweave HMAC,
  legis canonical-signing, Filigree bearer), all fail-soft.
- **Surfaces (S10/S11).** A dependency-free hand-rolled JSON-RPC MCP server (18 tools, the "primary agent
  surface") + an LSP diagnostics server; and a thin `click` CLI (one module per command) plus the
  `install` package that pushes activation (instruction blocks, `.mcp.json`, skills, pre-commit) into a
  project so an agent gets a working gate first-run.
- **Rust frontend (S12).** A preview tree-sitter frontend implementing the same `Analyzer` protocol,
  contributing a narrow command-injection slice (RS-WL-108/112) with crate-prefixed, baseline-eligible
  identity.

---

## 3. Architectural strengths (evidence-backed)

1. **The opt-in thesis is enforced in the type system and severity model, not just docs.** `modulate`
   sends the developer-freedom zone (`UNKNOWN_RAW`) to `NONE`; declaration-gated rules emit only when a
   decorator is present. (`severity_model.py:47`, `_sink_helpers.py:849`)
2. **Surface parity is a structural guarantee.** One keystone, two-plus surfaces, a parity test, and a
   `GateDecision.__post_init__` that hard-rejects an inconsistent verdict — the dogfood-#2 regression can't
   recur. (`run.py:181`, `test_cli_mcp_parity.py`)
3. **Fail-closed is the house style.** Unparseable file → gate-eligible DEFECT; non-convergent fixed point
   → demote-to-`UNKNOWN_RAW`; empty `--affected` scope → full-tree fallback; malformed store → loud
   `ConfigError`. The analyzer prefers a loud over-approximation to a silent gap everywhere.
4. **Defense-in-depth against an untrusted corpus.** Three independent path-confinement layers + O_NOFOLLOW
   writes + HMAC-authenticated summary cache (a repo JSON cannot become analyzer truth) + strict
   loopback-IP parsing before a bearer token is sent.
5. **Determinism as a contract.** Position-free canonical-AST fingerprint, byte-stable across CPython
   3.12/3.13, pinned by a golden identity oracle — the thing baselines/waivers/SEI all rest on.
6. **Honest degradation over false-green.** `coverage_pct=None` on an empty surface, three-valued trust
   verdicts, per-finding failure reasons (PDR-0023), `mark_unseen` suppressed when analysis is incomplete —
   the product refuses to read "nothing found" as "all clear."

---

## 4. Key risks & debt (the cross-cutting five)

Detailed, file-cited in `05-quality-assessment.md`; summarized here by blast radius.

1. **God-functions/modules** — `run_scan` (~374 lines), `_analyze_inner` (~857 lines),
   `variable_level.py` (~2,481 LOC), `server.py` (5,003 lines), `install/doctor.py` (~947 lines). High
   change-risk, defended by conformance suites rather than decomposition.
2. **Security invariants split across a seam** — secure-by-default gating, THREAT-001 confinement, and
   fingerprint determinism are each enforced by a *cooperating pair* of subsystems, not locally. Correct,
   but a refactor on one side silently defeats the property; guarded only by tests.
3. **Porous private-name coupling** — rules import engine `_private` helpers; `explain` reads engine
   internals; S6 reaches `sei_resolver._client`; `cli/doctor` reaches seven `install.doctor` privates.
   Import-linter cannot see these.
4. **Tracker/documentation drift** — the layering "violation" is fixed and its issue closed, yet
   `pyproject.toml` still says "BROKEN" and CI runs the now-passing contract non-gating (`|| true`).
   Several other open tickets are largely-already-done. The map has drifted from the territory.
5. **`pytest`-coupled production code** — `_initialized = "pytest" in sys.modules` disables the MCP
   not-initialized handshake gate whenever pytest is importable. (`protocol.py:43`)

---

## 5. Scope & non-goals (correctly bounded)

Wardline is deliberately **L1–L2 with an L3 project fixed point**, not a path-sensitive whole-program
prover, and **Python-first** with a command-injection-only Rust *preview*. It is not a broad SAST suite
(26 rules, 11 preview), not a hosted service (local-first), and finds nothing on un-annotated code *by
design*. The team has resisted scope creep; the documented under-approximations (star imports, module-
global channel, single-block Rust dataflow) all **under-approximate (fail-closed)** — precision/recall
debt, not unsoundness. This is a healthy, defensible boundary, not a gap to close.

---

## 6. Verdict

A focused, well-tested, security-literate tool that does exactly what it claims and refuses to do more.
The architecture is sound; the risks are concentrated and named; the most actionable immediate wins are
*cleanups of drift the team has already half-finished* (close the layering loop, retire stale tickets)
rather than new construction. Proceed to `05-quality-assessment.md` for the prioritized debt catalog and
`06-architect-handover.md` for the tracked-issue routing.
