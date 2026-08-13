# S1 — Facets + Evidence Spine — Implementation Plan (rev 1.0)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Git discipline (non-negotiable):** subagents NEVER run git — no `git add/commit/stash/checkout/restore/reset/diff/status`, nothing. Every "Commit" step is executed by the orchestrator. Cross-repo tasks (12–14) touch fixed targets only. The target must be clean before its task starts; before commit, intended edits are expected, but every changed path must be in that task's explicit file list. The orchestrator runs `git diff --check`, inspects `git diff --stat`, stages explicit paths only (never `-A`), and inspects `git diff --cached --name-status`. Any unexpected path is a hard stop. Every `.claude/worktrees/*` checkout and every sibling-repo `.worktrees/*` checkout is a non-target.
>
> **Status:** rev 1.0 — first cut, authored 2026-08-13 while the S0 receipt (`wardline-5a795253f1`) is under review. This plan consumes S0's produced interfaces as they exist at wardline `release/2.0.0` @ `0e1371af`; if the S0 review re-cuts an anchor this plan names, the anchor is re-verified before its task starts (Unexpected-drift discipline below). This plan has **not** yet had its adversarial review pass; §"Decisions this plan takes" enumerates every judgement call so the panel can ratify or reverse each one explicitly.

**Goal:** Ship the first new declaration kind — facets (`@audit_record`, weft-markers 0.2.0, `PY-WL-129`/WL-005) — together with the complete evidence spine (declarations inventory factory, `wardline-attest-3` emission, the legis `declarations` member, baseline v2, per-group posture counts and arming), so no declaration ever exists outside the ledger (spec P6/P7).

**Architecture:** S1 is the spec's designed "zero engine risk" stage: the facet plane is a new, unserialised, empty-defaulting side-channel (`SeedResult.facets` → `AnalysisContext.function_facets`) that seeds no taint and cannot become a trust claim; the evidence spine is one pure factory (`build_declarations_inventory`, the `gate_decision()` no-drift precedent) consumed by attest, assure/dossier, and the legis artifact. Every wire move (vocabulary v2 + generic-3, attest-3, baseline v2, legis additive member) lands against consumers that S0 already taught to dual-read, and every first real serialization is compared against its S0 preview before the preview is replaced (§13.3 S1 producer preflight).

**Tech Stack:** Python 3.12 engine (`src/wardline`), py3.9-floor runtime markers (`packages/weft-markers`), pytest + frozen byte goldens, HMAC-SHA256 conformance vectors, filigree tracking. Cross-repo: loomweave (`release/1.5.0`), warpline (`main`), legis (`main`).

**Spec:** `docs/superpowers/specs/2026-08-09-declaration-surface-v2-design.md` — **rev 10**, committed blob `f4ba87c488778f2c315de1944818db12707d981f` at commit `aa10dd3d` (the same pin S0 carries). Governing sections for S1: §4.1 (weft-markers 0.2.0), §4.3 (S1 emission: vocabulary v2, generic-3, resolver bump; extension checklist), §7 (facets, WL-005), §11.1–11.4 (inventory, attest-3, legis, baseline v2, posture honesty), §12 (per-kind QE gates, P11a/P12), §13.1–13.3 (stage row `wardline-7342234667`, rollout fence). PRD-0003 is **not** this plan's contract — the G2 bet's residue (`wardline-b857b50b54`, `wardline-69a58cb05f`, `wardline-70a8bb3875`) stays owned outside this plan (see "Adjacent threads" below).

## Global Constraints

- **Execution start gate.** No task starts until the S0 receipt `wardline-5a795253f1` is **CLOSED** (its five conditions (i)–(v) recorded) and the S0 review's fixes are merged to `release/2.0.0`. This plan's anchors were verified at `0e1371af`; after the review merges, any task whose named anchor has drifted re-verifies the anchor before editing (drift is expected line movement, not a STOP — a STOP is a *semantic* change to a named interface).
- **Scan-golden discipline, re-cut for S1.** S0's list survives with exactly **two spec-sanctioned moves and no third**: (1) `src/wardline/core/vocabulary.yaml` + `tests/conformance/fixtures/wardline-vocabulary-descriptor.golden.yaml` + its `UPSTREAM_BLOB_SHA` (`tests/conformance/test_vocabulary_descriptor_wire_golden.py:62`) regenerate **exactly once, in Task 4** (the v2/generic-3 move — spec §4.3 S1 emission); (2) `tests/grammar/golden/builtin_findings.jsonl` re-freezes **exactly once, in Task 7, via `regen.py --reason`** (spec §12's once-per-kind allowance — the new facet corpus fixtures unavoidably co-fire STABLE `PY-WL-103`/`PY-WL-104`, so the byte oracle absorbs those co-fires; `PY-WL-129` itself is PREVIEW and stays out of the golden). NO regeneration, ever, of: `tests/golden/identity/corpus/*.json`, `tests/corpus/rust/**`, `tests/golden/identity/rust/corpus/*.json`, `tests/golden/identity/rust/fixtures/**`. **The identity corpus zero-byte delta is the per-kind shipping gate** (spec §12): on the no-declaration path the identity corpus is byte-identical to its pre-S1 baseline — no facet fixture may be added under any identity or Rust tree, and every new exit-code or behaviour repro lives in `tmp_path` tests. If a forbidden golden goes red, the change is wrong — stop and fix the change, never the golden.
- **Version-bump ledger (CHANGELOG "Version-bump discipline" table, `CHANGELOG.md:122-137`, each clause named).** S1 moves exactly six constants and no others:
  - `REGISTRY_VERSION` `"wardline-generic-2"` → `"wardline-generic-3"` (`src/wardline/core/registry.py:24`) — Task 4.
  - `DESCRIPTOR_SCHEMA` `"wardline.vocabulary/v1"` → `"wardline.vocabulary/v2"` (`src/wardline/core/descriptor.py:39`) — Task 4.
  - `_RESOLVER_VERSION` `"sp1h"` → `"sp1i"` (`src/wardline/scanner/taint/project_resolver.py:60`) — Task 4, same commit (new vocabulary changes seeding, spec §4.3).
  - `ATTEST_SCHEMA` `"wardline-attest-2"` → `"wardline-attest-3"` (`src/wardline/core/attest.py:63`) — Task 10.
  - `BASELINE_VERSION` `1` → `2` (`src/wardline/core/baseline.py:31`) — Task 11.
  - `packages/weft-markers/pyproject.toml:7` `version = "0.1.0"` → `"0.2.0"` — Task 4.
  - **Explicitly NOT moved:** `SUMMARY_SCHEMA_VERSION` (stays `1`; the facet carrier is unserialised — the summary cache stores `FunctionSummary` tuples only and the summariser drops every non-`FunctionSummary` seed field, the §4.2.1 precedent verbatim) and `_CACHE_FILE_SCHEMA_VERSION` (stays `1`; envelope unchanged). The **builtin provider fingerprint moves implicitly and exactly once** — it is `f"decorator-vocab:{REGISTRY_VERSION}"` (`decorator_provider.py:1578-1584`), so Task 4's bump is also the fingerprint move and every warm summary misses; no separate fingerprint edit exists or is permitted.
  - The **legis artifact stays v1**: `declarations` is the additive, signature-covered, digest-shifting member S0's preview proved legis accepts within v1 (`ingest.py` copies every non-signature key with no allowlist). The CHANGELOG table's "artifact shape change mints the next vN" clause governs *breaking* shape changes; this is the additive path that S0 Task 22 pinned on both sides. No vN is minted.
- **MCP output-schema golden re-freezes: exactly three, each named at its owning task** — `tests/conformance/mcp_output_schemas.golden.json` re-freezes at Task 9 (resolution-posture keys gain `declaration_counts`/`armed_groups` wherever the schema pins `resolution`), Task 10 (attest/verify surfaces that pin payload keys), and at no other task. Each follows the module's RE-FREEZE PROCEDURE in `tests/conformance/test_mcp_output_schema_golden.py` and moves the pin at `:69` in the same commit. S0's "budget fully spent" language was S0-scoped; this plan mints S1's budget as exactly these three, in advance. A task discovering it needs a fourth is a STOP-and-re-plan, not a quiet fourth.
- **Preview/vector moves, enumerated exhaustively.** `tests/conformance/fixtures/wardline-attest-3.vector.json` moves exactly twice: Task 2 (erratum re-sign, `wardline-b59cbea4bc`) and Task 10 (replacement by the first real producer bytes, after the semantic+bytewise preflight compare). `tests/conformance/vectors/wardline_scan_artifact.v1.json` + `VENDORED_BLOB_SHA` (`tests/conformance/test_wardline_scan_artifact_shared_vector.py:48`) move exactly once, in Task 12's coordinated two-sided re-pin. Loomweave's `wardline-vocabulary-descriptor.generic-3.preview.yaml` is replaced by the real frozen descriptor bytes exactly once, in Task 13. Warpline's vendored `tests/fixtures/wardline-attest-3.vector.json` re-vendors byte-identically at Tasks 2 and 10. Every move lands with its cross-repo receipt re-run in the same task.
- **The three shipped trust markers' runtime signatures are frozen** — `@external_boundary`, `@trust_boundary`, `@trusted` gain no arguments and no edits. `audit_record` is a **new** export: bare-only, argument-less, runtime no-op, in **both** roots (`wardline.decorators`, `weft_markers`), py3.9-compatible syntax in `weft_markers` (TypeVar, not PEP 695) and PEP 695 in `wardline.decorators` — the two packages deliberately do not share source.
- **Facets are builtin-only and can never become a trust claim.** No custom-pack surface changes; `PY-WL-130` still never validates custom marker kwargs; a facet marker never seeds taint, never enters `declared_qualnames`, never joins the `anchored` posture bucket, and never clears base inertness (spec §7, §11.4). The load-time facet tripwire (Task 4) makes a level-bearing group-3 entry unconstructible.
- **Rollout fence (spec §13.3), restated as this plan's outcome boundary.** Everything here is **local coordinated emission only**. S1 closes with `published_emission_ready=false`. The published-emission gate (published Loomweave/Warpline/Legis releases containing the recorded consumer commits, cold-install probes, release-train owner authorization) is an owner decision outside this plan. Producer-first rollback stands: revert the wardline producer first, never the consumers' dual-read.
- **P11a survives S1.** `WLN-ENGINE-UNKNOWN-MARKER` must keep firing on unknown vocabulary names after `audit_record` registers. Task 3 re-cuts every specimen that used `audit_record` as its unknown-marker exemplar to the permanently-fictional `weft_markers.retention_class`, and Task 3's grep is of the **premise** (any specimen that must stay unknown forever), not the token.
- New rule id is exactly **`PY-WL-129`** (reserved by the spec for WL-005; `docs/concepts/rules.md:3-5` currently records 127–129 as unallocated — Task 6 truths that up). No new FACT id ships in S1 except `WLN-BASELINE-DECLARATIONS-DRIFT` (Task 11; flagged in "Decisions this plan takes"). The next free numeric rule id after this plan is **131** (127/128 stay reserved for S2).
- Conventions: FACTs are `Severity.NONE` + `Kind.FACT`; `PY-WL-129` is `Severity.ERROR` + `Kind.DEFECT`, `maturity=Maturity.PREVIEW`, `multi_emit=True`. Test commands run from `/home/john/wardline` unless a task names another repo. Full suite = `uv run pytest -q`. Commit messages follow `feat(scope):`/`fix(scope):`/`test(scope):`/`docs(scope):`.
- Fixed targets: Wardline `release/2.0.0`, Loomweave `release/1.5.0`, Warpline `main`, Legis `main`. "Current branch" is never accepted as a substitute. **No consumer version bumps** (Loomweave's plugin version stays CI-lockstepped to its Rust workspace; the rollout floor is recorded as commits).
- **Unexpected-red discipline.** A red in a file the current task does not name is STOP-and-report, not permission to broaden scope. Never relabel findings, regenerate scan goldens, or stash shared-tree work to force green.

## Adjacent threads this plan names and does not own

- **`wardline-b857b50b54`** (Rust marker shape, spec §4.4's separately-owned thread) — owns PRD-0003 criterion 6, closes before G2 is read, five closure conditions in §4.4. Decoupled from S1 (different frontend, no shared reader); may run in parallel.
- **`wardline-69a58cb05f`** (cross-module re-export drops the seed with zero channels — the fourth hole, PDR-0020). **`@audit_record` inherits this hole verbatim**: a re-exported facet marker resolves through the project package's namespace, misses the exact-export rule, and the facet drops with no channel — WL-005 then goes silent on that function. S1 does not fix the alias mechanism (that is the hole's own thread, which needs its own spec treatment); Task 7 records the inherited axis in the drop-coverage matrix prose exactly as the matrix already records it for trust markers.
- **`wardline-70a8bb3875`** (`--fail-on-inert` silently no-ops on Rust scans). Task 9 extends the inert gate for per-group arming on the Python path and must not touch or mask the Rust defect; its tests pin the Python path only and the task names the ticket in a comment beside the trip logic.
- **`wardline-7e0a3b1e3d`** (posture undercount: `config`/`callgraph` buckets never emitted). Task 9 adds per-group declaration counters to `WLN-ENGINE-METRICS` without touching the taint-source bucket projection; the denominator contract is unchanged (spec §11.4 names this defect as not altering it).
- **`wardline-c0563eee74`** (attest schema versioning tracker) — Task 10's contract-doc updates cite it, per `docs/contracts/wardline-attest-3.md:117`.

## Decisions this plan takes (each needs panel ratification; none is settled by the spec verbatim)

1. **Attest-3 preview erratum shape** (`wardline-b59cbea4bc`, Task 2): `posture` = the 11 `AssurancePosture.to_dict()` keys **plus an additive `declaration_debt` sub-object** (spec §11.2's "declaration debt in the posture", read literally); the vector's top-level `declaration_debt` sibling is deleted; `kind` becomes the **plural group name** (`"facets"`, matching `declaration_counts` keys, §11.4's counters, and `tests/corpus/harness.py:54`); the facet example's `verification_class` becomes `"recorded_unverified"` (§7 forbids claiming wardline verified the legal record; no predicate verifies a facet's claim).
2. **WL-005 v1 predicate** (Task 6): fires where a call resolving to an `@audit_record` function sits in the **`try` body** of a `try`/`try*` statement one of whose handlers **swallows** — `(is_broad_except(h) or is_silent_handler(h)) and not _contains_reraise(h)` — in a trusted-tier function (tier via `enclosing_declared_tier`, modulated via `modulate`). Builtin exception-**hierarchy** subsumption (`except OSError:` around an I/O-failing audit write) is a **recorded v1 FN** with a clean specimen, because no raise-analysis substrate exists in the engine (verified: no hierarchy table anywhere in `src/wardline/`) and inventing one mid-stage is S2-scale work. "Subsumption" in v1 is what `is_broad_except` already reasons about — bare/`Exception`/`BaseException`, attribute forms, tuple membership — plus the re-raise carve-out, pinned by paired specimens in both directions.
3. **`PY-WL-129` metadata**: `Severity.ERROR` base (a swallowed legal-record failure is an integrity/repudiation defect, the rule's whole reason to exist), `Maturity.PREVIEW` (the post-121-wave convention; PREVIEW gates identically to STABLE since `wardline-4ada23bb09`), `multi_emit=True` with a call-anchored `taint_path`.
4. **`Facet` is a `StrEnum`** with one member, `AUDIT_RECORD = "audit_record"`, in the new engine-floor `src/wardline/scanner/facet_types.py`; `SeedResult.facets`/`FunctionSeed.facets` are `frozenset[Facet]` (spec §7's `frozenset[Facet]` realized as a string-valued enum so serialization surfaces stay plain strings).
5. **Arming semantics, literal reading** (Task 9): facets' consuming-rule set is `{"PY-WL-129"}`; a group is armed iff any consuming rule is enabled after `rules_enable` resolution; `--fail-on-inert` (an opt-in flag) trips when an armed group recognised zero declarations on a non-trivial scan (≥5 analysed functions). Consequence stated plainly: a team opting into `--fail-on-inert` without using `@audit_record` trips the gate, and the sanctioned escape is disabling `PY-WL-129` in `rules_enable` — config the team already owns. Documented in the flag's help text and `docs/`.
6. **Baseline v2 drift channel**: the declarations section is compared on load and drift is reported via a new `WLN-BASELINE-DECLARATIONS-DRIFT` FACT (`Severity.NONE`, `Kind.FACT`) — observable, unsuppressible by construction (`Kind.DEFECT` short-circuit), never gating.
7. **Inventory ordering and id**: records sort by `(kind, subject, declaration_id)`; `declaration_id = "wlds1:" + sha256("wlds1" NUL kind NUL subject NUL field-or-empty)` (NUL-joined parts — the spec spells the parts, this plan pins the join; the vector's `wlds1:<64hex>` format is kept).
8. **Legis `declarations` member is always present** (empty list on a declaration-free scan) so the `_BASE` key-set equality tests stay exact rather than conditional.
9. **Vocabulary v2 group numbering**: `registry.py` gains the group constants (contracts 2, facets 3, restoration 4, sensitivity 5) per §4.3, but only group 3 has entries in S1; the v2 descriptor emits `entries:` (group 1, unchanged three) + `facets:` (group 3, `audit_record`) and no empty sections for unpopulated groups.
10. **`AssurancePosture` gains two additive keys** — `declaration_counts` (per-group ints) and `declaration_debt` (`{lapsed_expiries, stale_dependency_pins, record_only_claims}`, all zero in S1) — because attest's `posture` **is** `AssurancePosture.to_dict()` and §11.2 puts the debt in the posture. Dossier gains a budget-elidable `DeclarationsSection`. Both are the §11.1 "assure/dossier consume the inventory" obligation, kept minimal.

## Execution preflight and target checkouts

Before Task 1, the orchestrator performs these read-only checks, then atomically claims the S1 stage ticket:

```bash
cd /home/john/wardline
git status --short --branch
git rev-parse HEAD
git worktree list --porcelain
filigree session-context
# GATE: the S0 receipt must be CLOSED before any S1 task runs.
filigree show wardline-5a795253f1   # status must be closed; if not, STOP.
# The S1 stage ticket is dependency-blocked by Phase 0 (wardline-3baba7e42f).
# If Phase 0 is still open when execution starts, surface that to John — the
# design phase closes by owner action, and this plan does not close it.
filigree start-work wardline-7342234667 --assignee claude  # use the executing session's actor
```

Recheck the committed spec pin (identical constant and rule to S0's: the blob at commit `aa10dd3d`, spec rev 10; a failure is STOP-and-re-review, never a licence to re-derive the constant from the working tree):

```bash
test "$(git -C /home/john/wardline show aa10dd3d:docs/superpowers/specs/2026-08-09-declaration-surface-v2-design.md | git hash-object --stdin)" = \
  "f4ba87c488778f2c315de1944818db12707d981f"
```

Before Tasks 12–14 (cross-repo), run S0's exact clean-target preflight over the four repos (any `status --porcelain` output on a target is a hard stop; never stash, delete, absorb, or commit unrelated files):

```bash
(
set -euo pipefail
while IFS='|' read -r S1_REPO_PATH S1_TARGET_BRANCH; do
  test "$(git -C "$S1_REPO_PATH" rev-parse --show-toplevel)" = "$S1_REPO_PATH"
  test "$(git -C "$S1_REPO_PATH" branch --show-current)" = "$S1_TARGET_BRANCH"
  S1_DIRTY_STATE="$(git -C "$S1_REPO_PATH" status --porcelain=v1 --untracked-files=all)"
  if test -n "$S1_DIRTY_STATE"; then
    printf 'STOP: dirty target checkout %s\n%s\n' "$S1_REPO_PATH" "$S1_DIRTY_STATE" >&2
    exit 1
  fi
  git -C "$S1_REPO_PATH" rev-parse HEAD
  git -C "$S1_REPO_PATH" worktree list --porcelain
done <<'EOF'
/home/john/wardline|release/2.0.0
/home/john/loomweave|release/1.5.0
/home/john/warpline|main
/home/john/legis|main
EOF
)
```

For every non-target worktree, inspect `git status --short --branch` and check the owning agent/session; if a live or dirty worktree overlaps a named file, STOP and coordinate. Clean status alone is not a liveness proof.

**Pre-Task-1 measurement (discharged at execution, recorded in the task log).** The identity-corpus zero-byte-delta gate needs its baseline read before anything moves: record `git hash-object` of every file under `tests/golden/identity/corpus/` and `tests/golden/identity/rust/corpus/`, and confirm by grep that no file under `tests/golden/identity/**`, `tests/corpus/rust/**`, or `tests/corpus/fixtures/**` contains the token `audit_record` (measured true at `0e1371af`: the only `audit_record` occurrences in frozen trees are the unknown-marker specimens Task 3 re-cuts, and none live in a golden-feeding tree). Task 16 re-reads the same hashes.

## Task dependency order

T1 → T3 → T4 → T5 → T6 → T7 (the engine chain: checklist test, specimen sweep, registration, seeding, rule, corpus). T2 (attest preview erratum) is independent of the engine chain and may run any time before T10; it requires the warpline target and re-runs the attest receipt. T8 (inventory factory + assure/dossier) needs T5 (the facet plane exists). T9 (posture/arming) needs T6 (the consuming rule id) and T5 (facet counts). T10 (attest-3 flip) needs T2 + T8 (+T9 for the posture keys it serializes). T11 (baseline v2) needs T8. T12 (legis) needs T8 and runs after T10 so the coordinated window is one contiguous span. T13 (loomweave byte-freeze) needs T4 only. T14 (seam registry truth-up) needs T10 + T12 + T13. T15 (changelog/docs) after all content tasks. T16 (final verification) last. Recommended execution order is numeric with T2 slotted wherever the warpline checkout is convenient before T10.

## Filigree discipline

- Before T1: `work_start` on `wardline-7342234667` (atomic claim; never claim-then-update). Its stored description predates spec rev 3's staging and still carries operation-semantics scope — it has already been re-scoped by comment to match spec §13.2's S1 row (see the 2026-08-13 comment); do not "restore" the old scope.
- `wardline-b59cbea4bc` (attest-3 preview contradictions) is Task 2's owning ticket: claim it at T2 start, close it at T2's green with the re-signed vector's blob sha and the warpline receipt in the close comment. **If the S0 review fixes the vector first, T2 collapses to a verification step and the ticket is closed by whoever fixed it — check its status before claiming.**
- The stage ticket closes only at Task 16, with: (i) the per-kind QE receipt for `facets` (counts + `sentinel-gated-low-sample` status if active defects < 10), (ii) the identity-corpus zero-byte-delta receipt, (iii) the version-move ledger (all six constants at final values, `SUMMARY_SCHEMA_VERSION` unmoved), (iv) all three cross-repo receipts (loomweave byte-freeze, warpline vector, legis two-sided re-pin) with consumer commit shas, and (v) `published_emission_ready=false` stated in the close comment with the pointer to the owner-held published-emission gate.
- S1's close does **not** close PRD-0003 criterion 6 or the G2 bet — those stay with `wardline-b857b50b54` and PDR-0020's re-baselined count. State that in the close comment so neither goes ownerless.

---

### Task 1: The §4.3 extension-checklist conformance test (authored green on the shipped three-marker surface)

The spec's extension checklist ("all in one commit: `REGISTRY`, boundary/facet registries, `vocabulary_star_exports()`, `diagnostics._BUILTIN_MARKER_IMPORTS`, the drift tripwire" — §4.3) is *pinned by a conformance test* that **does not exist**: today four partial pins cover registry↔boundary-types and the descriptor bytes, but **nothing** pins `vocabulary_star_exports()` against `REGISTRY` and **nothing** references `_BUILTIN_MARKER_IMPORTS` (verified at `0e1371af`). Task 4 is the first checklist run, so the test that forces its one-commit shape must exist first — green on today's surface, red the moment any checklist member moves without the others.

**Files:**
- Create: `tests/conformance/test_extension_checklist.py`
- (No src changes.)

**Interfaces:**
- Consumes: `wardline.core.registry.REGISTRY`, `wardline.scanner.taint.decorator_provider.vocabulary_star_exports`, `wardline.scanner.diagnostics._BUILTIN_MARKER_IMPORTS`, `wardline.scanner.boundary_types.BUILTIN_BOUNDARY_TYPES`, `wardline.core.descriptor.build_vocabulary_descriptor`.
- Produces: the conformance module Task 4 must keep green in its single registration commit. Task 4 additionally extends this module with the facet-registry cross-checks (`BUILTIN_FACET_TYPES`) — the assertions below are written so that extension is additive.

- [ ] **Step 1: Write the test** — `tests/conformance/test_extension_checklist.py`:

```python
"""Extension checklist (declaration-surface-v2 §4.3): every surface that names a
builtin marker moves together, in one commit. Pinned as cross-equalities so a
partial registration reds here rather than shipping a marker that one surface
recognises and another silently drops."""

from __future__ import annotations

from wardline.core.descriptor import build_vocabulary_descriptor
from wardline.core.registry import REGISTRY
from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES
from wardline.scanner.diagnostics import _BUILTIN_MARKER_IMPORTS
from wardline.scanner.taint.decorator_provider import vocabulary_star_exports

_TRUST_GROUP = 1


def _registry_names() -> frozenset[str]:
    return frozenset(REGISTRY)


def _trust_names() -> frozenset[str]:
    return frozenset(n for n, e in REGISTRY.items() if e.group == _TRUST_GROUP)


def test_star_exports_mirror_the_registry_exactly() -> None:
    exports = vocabulary_star_exports()
    assert set(exports) == {"wardline.decorators", "weft_markers"}
    for root, names in exports.items():
        assert frozenset(names) == _registry_names(), root
        assert all(fqn == f"{root}.{name}" for name, fqn in names.items())


def test_builtin_marker_imports_cover_every_registry_name_per_root() -> None:
    # Root keys carry EVERY registry name; the trust ghost-path key carries the
    # trust group only (there is no wardline.decorators.trust.<facet> export).
    assert _BUILTIN_MARKER_IMPORTS["wardline.decorators"] == _registry_names()
    assert _BUILTIN_MARKER_IMPORTS["weft_markers"] == _registry_names()
    assert _BUILTIN_MARKER_IMPORTS["wardline.decorators.trust"] == _trust_names()
    assert set(_BUILTIN_MARKER_IMPORTS) == {
        "wardline.decorators",
        "wardline.decorators.trust",
        "weft_markers",
    }


def test_boundary_registry_covers_exactly_the_trust_group() -> None:
    # Every group-1 registry row has exactly two boundary-type rows (one per
    # root); no boundary type exists for a non-trust group.
    per_name: dict[str, int] = {}
    for bt in BUILTIN_BOUNDARY_TYPES:
        per_name[bt.name] = per_name.get(bt.name, 0) + 1
    assert frozenset(per_name) == _trust_names()
    assert set(per_name.values()) == {2}


def test_descriptor_carries_every_registry_row_exactly_once() -> None:
    desc = build_vocabulary_descriptor()
    listed = [e["canonical_name"] for e in desc.get("entries", [])] + [
        e["canonical_name"] for e in desc.get("facets", [])
    ]
    assert sorted(listed) == sorted(_registry_names())
    assert len(listed) == len(set(listed))


def test_runtime_packages_export_every_registry_name() -> None:
    import wardline.decorators as wd

    assert _registry_names() <= frozenset(wd.__all__)
    # weft_markers is not installed in the dev venv; read its source directly.
    from pathlib import Path
    import ast

    src = Path("packages/weft-markers/src/weft_markers/__init__.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(src)
    for stmt in tree.body:
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and stmt.targets[0].id == "__all__"
        ):
            exported = frozenset(
                elt.value for elt in stmt.value.elts if isinstance(elt, ast.Constant)
            )
            assert _registry_names() <= exported
            break
    else:  # pragma: no cover - structural guard
        raise AssertionError("weft_markers/__init__.py has no __all__")
```

- [ ] **Step 2: Run it green on the shipped surface**

Run: `uv run pytest tests/conformance/test_extension_checklist.py -v`
Expected: 5 passed. (If `test_descriptor_carries_every_registry_row_exactly_once` errors on the absent `facets` key, the `.get(..., [])` guard above is the intended v1-compatible read — fix the test, not the descriptor.)

- [ ] **Step 3: Full-suite spot check** — `uv run pytest tests/conformance -q` — Expected: green, no other module touched.

- [ ] **Step 4: Commit**

```bash
git add tests/conformance/test_extension_checklist.py
git commit -m "test(conformance): pin the §4.3 extension checklist before its first S1 run"
```

### Task 2: Attest-3 preview erratum — `wardline-b59cbea4bc` (wardline + warpline)

> **DONE before S1 started — SKIP THIS TASK ENTIRELY. Do not re-sign the vector.**
> Landed 2026-08-13 as wardline `8a9aaed2` + warpline `44b0d4e`; `wardline-b59cbea4bc`
> is closed. All seven steps are complete, not just through Step 4. Three corrections
> to the text below, recorded so a later reader does not re-derive them:
> - **The Files list was incomplete.** This was a two-sided *source* change, not a
>   fixture edit plus a re-vendor: warpline's `parse_attest_bundle` read
>   `payload["declaration_debt"]` and had to move to `payload.posture.declaration_debt`
>   (`src/warpline/_attest.py`, `tests/test_attest.py` — neither was listed).
> - **Step 3 was a no-op.** `test_attest_3_vector_signature_is_internally_consistent`
>   re-derives the HMAC; there is no hex pin anywhere in the repo to update.
> - **Two of the Step-1 suggested values were wrong** and were not used: `unknown` is a
>   list of `UnknownBoundary` objects, not a count, and `boundaries_total: 3` against a
>   one-row `boundaries[]` describes a scan that cannot exist. The vector is now
>   generated against `AssurancePosture.to_dict()` rather than transcribed, and
>   `boundaries[]` carries three rows so the counters and the rows agree.
>
> Task 10 is unaffected: this was the first of the vector's two sanctioned moves, and
> Task 10 remains the second.

The S0-staged preview vector contradicts the live producer and the spec in four places (the ticket carries the full statement): `posture` is a three-key `ResolutionPosture`-ish stub where the live attest-2 `posture` is `AssurancePosture.to_dict()` (11 keys); `declaration_debt` sits top-level where §11.2 puts it in the posture; `kind` is singular `"facet"` against the plural group vocabulary everywhere else; and the facet example claims `machine_verified` against §7's own text discipline. S1's Task 10 preflight compares real bytes against this vector, so it must be corrected while it is still cheap — it is DRAFT by its own terms. **Check the ticket first: if the S0 review already fixed it, verify and skip to Step 5.**

**Files:**
- Modify: `tests/conformance/fixtures/wardline-attest-3.vector.json`
- Modify: `docs/contracts/wardline-attest-3.md` (the `## Payload` table: `declaration_debt` row moves under a `posture` description; the posture sentence at :39-42 re-cut to name the 11 v2 keys plus the additive `declaration_debt` sub-object; `kind` example pluralised)
- Modify: `tests/conformance/test_attest_dual_read.py` (re-derive the vector HMAC pin; the `GOLDEN_KEY` / `sign_artifact(` / `*_FIELD` tokens must survive verbatim — they are the seam registry's grep targets)
- Modify (warpline, `/home/john/warpline`): `tests/fixtures/wardline-attest-3.vector.json` (byte-identical re-vendor)

**Interfaces:**
- Consumes: `_sign` (`src/wardline/core/attest.py:129`), the public conformance key literal `wardline-attest-3-conformance-vector-key`, `AssurancePosture.to_dict()` key set (`src/wardline/core/assure.py:123-137`).
- Produces: the corrected preview payload shape Task 10's producer must reproduce byte-for-byte on the vector's inputs: `posture` = `{boundaries_total, proven, defect_total, unknown, engine_limited, coverage_pct, unanalyzed_total, unanalyzed_rule_ids, waiver_debt, baselined_total, judged_total, declaration_debt}` where `declaration_debt` = `{lapsed_expiries: 0, record_only_claims: 0, stale_dependency_pins: 0}`; no top-level `declaration_debt`; `declarations[0].kind == "facets"`; `declarations[0].verification_class == "recorded_unverified"`. Everything else in the vector is unchanged.

- [ ] **Step 1: Re-cut the vector payload** with plausible draft values for the 11 posture keys (e.g. `boundaries_total: 3, proven: 2, defect_total: 0, unknown: 1, engine_limited: 0, coverage_pct: 66.7, unanalyzed_total: 0, unanalyzed_rule_ids: [], waiver_debt: [], baselined_total: 0, judged_total: 0` plus the zeroed `declaration_debt` sub-object), delete the top-level `declaration_debt`, set `kind: "facets"` and `verification_class: "recorded_unverified"`.
- [ ] **Step 2: Re-sign** with the vector's own public key via a one-off script call through `wardline.core.attest._sign` (schema `"wardline-attest-3"`), write the new `signature.value`, keep `alg`/`key_id` derivation identical.
- [ ] **Step 3: Re-pin the dual-read test** — run `uv run pytest tests/conformance/test_attest_dual_read.py -v`; update only the HMAC/blob pins its RE-PIN procedure names. Expected: green, with the three seam-registry tokens untouched (grep the file for `GOLDEN_KEY`, `sign_artifact(`, `_FIELD` after editing).
- [ ] **Step 4: Contract doc truth-up** — the Payload section states the corrected posture sentence and pluralised kind; the DRAFT status line is untouched (`test_attest_3_contract_doc_states_its_draft_terms` still greps for `DRAFT`).
- [ ] **Step 5: Warpline re-vendor + receipt** — copy the vector byte-identically to `/home/john/warpline/tests/fixtures/wardline-attest-3.vector.json`; run wardline's cross-repo receipt: `WARPLINE_REPO=/home/john/warpline uv run pytest tests/conformance/test_attest_dual_read.py -v` — Expected: green including the Layer-2 byte comparison; then run warpline's own suite gate for its attest consumer (`cd /home/john/warpline && uv run pytest tests -q -k attest`). Expected: green.
- [ ] **Step 6: Seam-registry check** — `uv run pytest tests/conformance/test_seam_registry.py -q` — Expected: green (evidence paths unchanged; only bytes moved).
- [ ] **Step 7: Commit (both repos, orchestrator), close `wardline-b59cbea4bc`**

```bash
cd /home/john/wardline
git add tests/conformance/fixtures/wardline-attest-3.vector.json docs/contracts/wardline-attest-3.md tests/conformance/test_attest_dual_read.py
git commit -m "fix(attest): re-cut the attest-3 DRAFT preview onto the live posture shape (wardline-b59cbea4bc)"
cd /home/john/warpline
git add tests/fixtures/wardline-attest-3.vector.json
git commit -m "test(attest): re-vendor the corrected wardline-attest-3 preview vector byte-identically"
```

### Task 3: Unknown-marker specimen sweep — `audit_record` stops being a valid "unknown" exemplar

S0's P11a machinery uses `@weft_markers.audit_record` as its unknown-marker specimen. The moment Task 4 registers it, every such specimen inverts (the FACT stops firing, `unknown_markers` counts drop to zero) and sweeps of red appear in tests whose subject is the *channel*, not the marker. Re-cut every specimen to `weft_markers.retention_class` — a name in no spec table, no staged export list (§4.1's unscheduled exports are `operation`/`Semantics`), already used as a second unknown specimen in-tree. **Grep the premise, not the token** (the S0 plan's rev-3.4 lesson): the sweep target is "any test input that must resolve as unknown vocabulary forever", found via `WLN-ENGINE-UNKNOWN-MARKER`, `unknown_markers`, `unrecognised_vocabulary`, and `audit_record` greps together.

**Files (verified inventory at `0e1371af`; the Step-1 grep re-verifies):**
- Modify: `tests/grammar/test_unknown_marker.py` (:36, :41, :50, :53, :94, :107-108, :122, :143)
- Modify: `tests/unit/cli/test_decorator_coverage_cmd.py` (:11)
- Modify: `tests/unit/core/test_decorator_coverage.py` (:207, :271 — :271 stacks `audit_record` + `retention_class`; it becomes `retention_class` + `provenance_seal`, keeping the two-distinct-unknowns property)
- Modify: `tests/unit/scanner/test_pipeline.py` (:304, :318)
- Modify: `tests/unit/mcp/test_server_decorator_coverage.py` (:9)
- Modify: `tests/conformance/test_mcp_structured_output.py` (:103)
- Modify: `src/wardline/scanner/marker_reader.py` (:613 docstring — the prose example "``@weft_markers.audit_record`` on a wardline that predates facets resolves here" is about *forward* skew and stays TRUE after S1 only from an old engine's viewpoint; re-word to `retention_class` so the module's own example is not a registered marker)

**Interfaces:**
- Consumes: nothing new. Produces: a test corpus in which `audit_record` appears nowhere as an unknown-vocabulary specimen, so Task 4 cannot invert a channel test.

- [ ] **Step 1: Premise grep** — `grep -rn "audit_record" tests/ src/ --include='*.py'` and `grep -rln "unrecognised_vocabulary\|WLN-ENGINE-UNKNOWN-MARKER\|unknown_markers" tests/` — reconcile against the file list above; any additional hit joins the sweep (STOP if a hit is in a frozen golden tree).
- [ ] **Step 2: Mechanical re-cut** of every listed site `audit_record` → `retention_class` (and :271's second unknown → `provenance_seal`), including the asserted FQN strings (`weft_markers.retention_class`) and the `properties["marker"]` assertions.
- [ ] **Step 3: Run the touched modules** — `uv run pytest tests/grammar/test_unknown_marker.py tests/unit/cli/test_decorator_coverage_cmd.py tests/unit/core/test_decorator_coverage.py tests/unit/scanner/test_pipeline.py tests/unit/mcp/test_server_decorator_coverage.py tests/conformance/test_mcp_structured_output.py -q` — Expected: green (behaviour-neutral: one unknown name replaced by another).
- [ ] **Step 4: Full suite** — `uv run pytest -q` — Expected: green, zero golden movement.
- [ ] **Step 5: Commit**

```bash
git add tests/grammar/test_unknown_marker.py tests/unit/cli/test_decorator_coverage_cmd.py tests/unit/core/test_decorator_coverage.py tests/unit/scanner/test_pipeline.py tests/unit/mcp/test_server_decorator_coverage.py tests/conformance/test_mcp_structured_output.py src/wardline/scanner/marker_reader.py
git commit -m "test(grammar): retire audit_record as the unknown-marker specimen ahead of its S1 registration"
```

### Task 4: The one-commit registration — `audit_record` across every checklist surface, vocabulary v2, `wardline-generic-3`, weft-markers 0.2.0

The §4.3 checklist run, forced into one commit by Task 1's conformance test. This commit and no other moves `REGISTRY_VERSION`, `DESCRIPTOR_SCHEMA`, `_RESOLVER_VERSION`, the descriptor golden, and the weft-markers version. The builtin provider fingerprint moves implicitly with `REGISTRY_VERSION` (its whole preimage at builtin-only grammar) — every warm summary misses, which is the intended §4.3 epoch move.

**Files:**
- Modify: `src/wardline/core/registry.py` (`:24` version bump; group constants; the `audit_record` entry in `_ENTRIES`)
- Create: `src/wardline/scanner/facet_types.py` (`Facet` StrEnum, `FacetType`, `BUILTIN_FACET_TYPES`, load-time tripwire)
- Modify: `src/wardline/core/descriptor.py` (`:39` schema bump; group-split emission — `entries:` group 1, `facets:` group 3)
- Modify: `src/wardline/core/vocabulary.yaml` (regenerated — sanctioned move #1)
- Modify: `tests/conformance/fixtures/wardline-vocabulary-descriptor.golden.yaml` + `tests/conformance/test_vocabulary_descriptor_wire_golden.py:62` (`UPSTREAM_BLOB_SHA`) — same sanctioned move
- Modify: `src/wardline/scanner/diagnostics.py` (`:25-29` `_BUILTIN_MARKER_IMPORTS` — `audit_record` joins the two ROOT keys only, never `wardline.decorators.trust`)
- Create: `src/wardline/decorators/facets.py`; Modify: `src/wardline/decorators/__init__.py` (import + `__all__`)
- Modify: `packages/weft-markers/src/weft_markers/__init__.py` (py39-syntax `audit_record` + `__all__`), `packages/weft-markers/pyproject.toml:7` (`0.2.0`), `packages/weft-markers/README.md`
- Modify: `src/wardline/scanner/taint/project_resolver.py:60` (`_RESOLVER_VERSION = "sp1i"`)
- Modify: `tests/conformance/test_extension_checklist.py` (add the facet-registry cross-check test below)
- Modify: `tests/unit/core/test_registry.py`, `tests/unit/core/test_descriptor.py` (new-entry and v2-shape assertions per their existing idioms)

**Interfaces:**
- Consumes: Task 1's checklist test; the shipped `RegistryEntry` grammar (`kwargs`/`arg_kinds`/`call_form`, `registry.py:53-82`).
- Produces (frozen for Tasks 5–13):
  - `registry.py`: `TRUST_GROUP = 1`, `CONTRACTS_GROUP = 2`, `FACETS_GROUP = 3`, `RESTORATION_GROUP = 4`, `SENSITIVITY_GROUP = 5` (module constants); `REGISTRY["audit_record"] = RegistryEntry(canonical_name="audit_record", group=FACETS_GROUP, attrs={}, kwargs=frozenset(), arg_kinds={}, call_form=MarkerCallForm.BARE_ONLY)`; `REGISTRY_VERSION = "wardline-generic-3"`.
  - `facet_types.py`: `class Facet(StrEnum): AUDIT_RECORD = "audit_record"`; `@dataclass(frozen=True, slots=True) class FacetType: name: str; module_prefix: str; group: int; facet: Facet`; `BUILTIN_FACET_TYPES: tuple[FacetType, ...]` — exactly two rows (`wardline.decorators` / `weft_markers` × `audit_record`); a load-time tripwire mirroring `boundary_types.py:131-153` that raises `ValueError` if any `FacetType` drifts from its REGISTRY row on group/kwargs/call-form, **and** raises if any group-3 REGISTRY entry carries `attrs`, non-empty `kwargs`, or any `ArgKind` — the "a facet can never become a trust claim" gate made unconstructible.
  - `descriptor.py`: v2 emission — top-level keys in order `schema`, `version`, `entries`, `facets`; `entries` = group-1 rows exactly as v1 emitted them (byte-stable shape); `facets` = group-3 rows in the same `{canonical_name, group, attrs}` row shape; no empty sections for groups 2/4/5.
  - Runtime: `wardline.decorators.audit_record` and `weft_markers.audit_record` — bare, argument-less, return-the-function no-ops. **Accepted scanner import paths are exactly those two FQNs**; `wardline.decorators.trust.audit_record` does not exist at runtime and never enters `_BUILTIN_MARKER_IMPORTS`; facet matching (Task 5) exact-matches the two `FacetType` FQNs and never consults `is_builtin_decorator_fqn`'s trust-ghost rule.

- [ ] **Step 1: Write the failing checklist extension** — append to `tests/conformance/test_extension_checklist.py`:

```python
def test_facet_registry_covers_exactly_the_facet_group() -> None:
    from wardline.core.registry import FACETS_GROUP
    from wardline.scanner.facet_types import BUILTIN_FACET_TYPES

    facet_names = frozenset(n for n, e in REGISTRY.items() if e.group == FACETS_GROUP)
    per_name: dict[str, int] = {}
    for ft in BUILTIN_FACET_TYPES:
        per_name[ft.name] = per_name.get(ft.name, 0) + 1
    assert frozenset(per_name) == facet_names == frozenset({"audit_record"})
    assert set(per_name.values()) == {2}
```

Also extend `test_boundary_registry_covers_exactly_the_trust_group`'s expectations if it hard-codes counts, and write the two direct pins in `tests/unit/core/test_registry.py`:

```python
def test_audit_record_entry_shape() -> None:
    e = REGISTRY["audit_record"]
    assert (e.group, e.call_form) == (FACETS_GROUP, MarkerCallForm.BARE_ONLY)
    assert e.kwargs == frozenset() and dict(e.arg_kinds) == {} and dict(e.attrs) == {}


def test_registry_version_is_generic_3() -> None:
    assert REGISTRY_VERSION == "wardline-generic-3"
```

- [ ] **Step 2: Run to verify red** — `uv run pytest tests/conformance/test_extension_checklist.py tests/unit/core/test_registry.py -q` — Expected: FAIL (`ImportError: facet_types` / missing entry / version literal).
- [ ] **Step 3: Implement the whole checklist in one pass** — registry entry + group constants + version bump; `facet_types.py` with tripwire; both runtime exports; `_BUILTIN_MARKER_IMPORTS` root keys; descriptor group-split + schema bump; `_RESOLVER_VERSION = "sp1i"`; weft-markers `0.2.0` + README line. The descriptor emission change in full:

```python
# descriptor.py — build_vocabulary_descriptor()
entries = [_entry_dict(e) for e in REGISTRY.values() if e.group == TRUST_GROUP]
facets = [_entry_dict(e) for e in REGISTRY.values() if e.group == FACETS_GROUP]
descriptor: dict[str, object] = {
    "schema": DESCRIPTOR_SCHEMA,      # "wardline.vocabulary/v2"
    "version": REGISTRY_VERSION,      # "wardline-generic-3"
    "entries": entries,
}
if facets:
    descriptor["facets"] = facets
return descriptor
```

- [ ] **Step 4: Regenerate the two sanctioned descriptor artifacts** — `uv run wardline vocab > src/wardline/core/vocabulary.yaml`, copy to the conformance golden, and update `UPSTREAM_BLOB_SHA` from `git hash-object src/wardline/core/vocabulary.yaml`. Verify the byte-drift tripwire agrees: `uv run pytest tests/unit/core/test_descriptor.py tests/conformance/test_vocabulary_descriptor_wire_golden.py -q` — Expected: green.
- [ ] **Step 5: Full suite** — `uv run pytest -q` — Expected: green. **The specific reds this step is watching for:** any unknown-marker test still using `audit_record` (Task 3 missed a site → fix the specimen, not the registry), any loomweave-facing wardline test pinning `wardline-generic-2` outside the two sanctioned artifacts (STOP — that is an unenumerated consumer pin; report it), and any identity-corpus movement (STOP — the change is wrong).
- [ ] **Step 6: Warm-cache epoch check** — run `uv run wardline scan . --fail-on ERROR` twice; Expected: exit 0 both runs, second run rebuilds summaries (fingerprint moved), byte-identical findings.
- [ ] **Step 7: Commit (one commit — the checklist's own rule)**

```bash
git add src/wardline/core/registry.py src/wardline/scanner/facet_types.py src/wardline/core/descriptor.py \
  src/wardline/core/vocabulary.yaml tests/conformance/fixtures/wardline-vocabulary-descriptor.golden.yaml \
  tests/conformance/test_vocabulary_descriptor_wire_golden.py src/wardline/scanner/diagnostics.py \
  src/wardline/decorators/facets.py src/wardline/decorators/__init__.py \
  packages/weft-markers/src/weft_markers/__init__.py packages/weft-markers/pyproject.toml packages/weft-markers/README.md \
  src/wardline/scanner/taint/project_resolver.py tests/conformance/test_extension_checklist.py \
  tests/unit/core/test_registry.py tests/unit/core/test_descriptor.py
git commit -m "feat(vocab): register audit_record — vocabulary v2, wardline-generic-3, weft-markers 0.2.0 (§4.3 checklist, one commit)"
```

### Task 5: Provider facet seeding — the facet plane exists and cannot become a trust claim

**Files:**
- Modify: `src/wardline/scanner/taint/provider.py` (`SeedResult` gains `facets: frozenset[Facet] = frozenset()` after `unreadable_level_values`; `SeedContext` untouched)
- Modify: `src/wardline/scanner/taint/function_level.py` (`FunctionSeed.facets: frozenset[Facet] = frozenset()`; the seeder copies it through)
- Modify: `src/wardline/scanner/taint/decorator_provider.py` (facet recognition in the decorator walk beside `_match` (`:1604`): resolve each decorator FQN via the existing alias machinery; exact-match against `BUILTIN_FACET_TYPES` FQNs; on match run `call_shape_offences(deco, call_form=BARE_ONLY, declared=frozenset(), required=frozenset())` — a clean shape adds `ft.facet` to the seed's facets, a shape offence routes to the existing malformed channel exactly as a trust marker's does and records **no** facet)
- Modify: `src/wardline/scanner/context.py` (`AnalysisContext.function_facets: Mapping[str, frozenset[Facet]] = field(default_factory=dict)`, frozen in `__post_init__` like its siblings)
- Modify: `src/wardline/scanner/analyzer.py` + `src/wardline/scanner/taint/project_resolver.py` + `src/wardline/scanner/taint/resolver_metadata.py` (plumb `{qualname: seed.facets}` from the unconditional per-module seeding pass to the context, following the same route `declared_qualnames` rides; the parse loop re-derives facets every scan, warm or cold — the §4.2.1 unconditional-seeding fact — so nothing is serialised)
- Modify: `src/wardline/scanner/taint/module_summariser.py` — **no functional edit**; add the one-line comment that `facets` is deliberately dropped at the summary boundary (the same sentence `unprovable_boundaries` carries)
- Test: `tests/unit/scanner/test_facet_seeding.py` (new)

**Interfaces:**
- Consumes: Task 4's `BUILTIN_FACET_TYPES` / `Facet`; the shipped `call_shape_offences` (`marker_reader.py:486`).
- Produces: `AnalysisContext.function_facets` — the exact mapping Task 6's rule and Task 8's factory read: `{scan-root-relative qualname: frozenset[Facet]}`, present for every scanned function that carries ≥1 well-formed facet marker, absent otherwise. Facet-decorated functions do **not** enter `declared_qualnames`, `declared_body_taints`, or any posture boundary bucket.

- [ ] **Step 1: Write the failing tests** — `tests/unit/scanner/test_facet_seeding.py`, using the standard `_analyze(tmp_path, files)` idiom:

```python
_SRC = (
    "from weft_markers import audit_record, trusted\n\n"
    "@audit_record\n"
    "def write_event(e):\n    return e\n\n"
    "@audit_record\n"
    "@trusted(level='ASSURED')\n"
    "def stacked(e):\n    return e\n\n"
    "def plain(e):\n    return e\n"
)


def test_facet_seeds_and_stacks_without_touching_trust(tmp_path):
    ctx = _analyze(tmp_path, {"svc.py": _SRC})
    assert ctx.function_facets["svc.write_event"] == frozenset({Facet.AUDIT_RECORD})
    # A facet alone declares no trust: not in the declared set, no seed opinion.
    assert "svc.write_event" not in ctx.declared_qualnames
    # Stacking is legal and independent: the trust marker still declares.
    assert ctx.function_facets["svc.stacked"] == frozenset({Facet.AUDIT_RECORD})
    assert "svc.stacked" in ctx.declared_qualnames
    assert "svc.plain" not in ctx.function_facets


def test_registered_facet_is_no_longer_an_unknown_marker(tmp_path):
    result = _scan(tmp_path, {"svc.py": _SRC})  # full pipeline, findings out
    assert not [f for f in result.findings if f.rule_id == "WLN-ENGINE-UNKNOWN-MARKER"]


def test_called_facet_marker_is_a_shape_offence_and_seeds_no_facet(tmp_path):
    src = "from weft_markers import audit_record\n@audit_record()\ndef f(e):\n    return e\n"
    result = _scan(tmp_path, {"svc.py": src})
    offences = [f for f in result.findings if f.rule_id == "PY-WL-130"]
    assert offences and "call_not_allowed" in offences[0].message
    assert "svc.f" not in _ctx(result).function_facets


def test_facet_only_module_does_not_clear_base_inertness(tmp_path):
    # Six facet-only functions: non-trivial scan, zero recognised boundaries.
    src = "from weft_markers import audit_record\n" + "\n".join(
        f"@audit_record\ndef f{i}(e):\n    return e\n" for i in range(6)
    )
    posture = _posture(tmp_path, {"svc.py": src})
    assert posture.inert is True
```

(The helper spellings `_scan`/`_ctx`/`_posture` follow the module-local idioms in `tests/unit/scanner/test_pipeline.py` and `tests/unit/core/test_resolution_posture.py` — thin wrappers over `WardlineAnalyzer`/`run_scan`/`compute_resolution_posture`, written in this test file.)

- [ ] **Step 2: Run to verify red** — `uv run pytest tests/unit/scanner/test_facet_seeding.py -q` — Expected: FAIL (`function_facets` does not exist).
- [ ] **Step 3: Implement** the carrier fields, the provider walk, and the context plumbing per the Files list. The provider arm must sit **after** the unknown-marker resolution so a registered facet never reaches `unknown_vocabulary_marker`, and must reuse the malformed-marker channel the trust arm already routes shape offences to (one shared validator, spec §4.2 — no facet-specific offence vocabulary).
- [ ] **Step 4: Run green** — `uv run pytest tests/unit/scanner/test_facet_seeding.py tests/grammar -q` — Expected: green, including the drop-coverage matrix (untouched until Task 7).
- [ ] **Step 5: Full suite + byte-identity spot check** — `uv run pytest -q`; Expected: green. The identity corpus is declaration-free w.r.t. facets, so zero movement.
- [ ] **Step 6: Commit**

```bash
git add src/wardline/scanner/taint/provider.py src/wardline/scanner/taint/function_level.py \
  src/wardline/scanner/taint/decorator_provider.py src/wardline/scanner/context.py \
  src/wardline/scanner/analyzer.py src/wardline/scanner/taint/project_resolver.py \
  src/wardline/scanner/taint/resolver_metadata.py src/wardline/scanner/taint/module_summariser.py \
  tests/unit/scanner/test_facet_seeding.py
git commit -m "feat(engine): facet plane — SeedResult.facets through AnalysisContext.function_facets, unserialised"
```

### Task 6: `PY-WL-129` — audit-record write swallowed by a broad or silent handler (WL-005)

**Files:**
- Create: `src/wardline/scanner/rules/audit_record_swallowed.py`
- Modify: `src/wardline/scanner/rules/_ast_helpers.py` (two new helpers: `own_try_statements`, `calls_in_statements`)
- Modify: `src/wardline/scanner/rules/__init__.py` (import + append `AuditRecordSwallowed` **after** `MalformedMarkerCall` — registration order is emission order)
- Modify: `tests/unit/scanner/rules/test_default_registry.py` (ids set), `tests/grammar/test_grammar_model.py` (ordered rule list), `tests/grammar/test_analyzer_wiring.py` (`_BUILTIN_IDS`), `tests/unit/scanner/rules/test_vocabulary_shape_pin.py` (`_EXPECTED_RULE_SHAPE` gains `"PY-WL-129": (Severity.ERROR, Kind.DEFECT, Maturity.PREVIEW)`)
- Modify: `tests/unit/scanner/rules/test_rule_examples_meta.py` (`_IMPORTS` gains `audit_record` so the examples resolve)
- Modify: `tests/unit/scanner/rules/test_tier_gate_negative.py` (`AuditRecordSwallowed` joins the enrolled tier-gated rules with its paired positive/negative shapes)
- Modify: `docs/concepts/rules.md` (`:3-5` — 129 leaves "unallocated"; table row; a prose section following the module's pattern; the declaration-gated-vs-tier-modulated list)
- Test: `tests/unit/scanner/rules/test_audit_record_swallowed.py` (new)

**Interfaces:**
- Consumes: `context.function_facets` (Task 5), `context.call_site_callees` / `call_site_candidate_callees`, `enclosing_declared_tier` (`_sink_helpers.py:65`), `modulate` (`severity_model.py:47`), `is_broad_except` / `is_silent_handler` / `_contains_reraise` (`_ast_helpers.py:272/:289/:560`), `entity_relative_span` (`_sink_helpers.py:138`), `compute_finding_fingerprint`.
- Produces: rule id `PY-WL-129`, one finding per swallowed audit call, fingerprint parts `(rule_id, path, qualname, taint_path=f"{entity_relative_span(call, base)}:audit")` — call-anchored, source-only, disjoint from 103/104's handler-anchored `:except` shape by the trailing token and the rule id alone.

- [ ] **Step 1: Write the failing tests** — `tests/unit/scanner/rules/test_audit_record_swallowed.py`. The table is the task's contract; every row is a `(label, source, fires, note)` case run through `_analyze(tmp_path, ...)` with an `@trusted(level='ASSURED')`-declared caller:

```python
_PREAMBLE = "from weft_markers import audit_record, trusted\n\n@audit_record\ndef write_event(e):\n    return e\n\n"

_CASES = [
    # (label, caller body, fires?)
    ("broad_swallow",        "try:\n        write_event(e)\n    except Exception:\n        log(e)",            True),
    ("bare_swallow",         "try:\n        write_event(e)\n    except:\n        pass",                        True),
    ("silent_narrow",        "try:\n        write_event(e)\n    except ValueError:\n        pass",             True),
    ("tuple_member_broad",   "try:\n        write_event(e)\n    except (ValueError, Exception):\n        log(e)", True),
    ("broad_reraise",        "try:\n        write_event(e)\n    except Exception:\n        log(e)\n        raise", False),
    ("narrow_handled",       "try:\n        write_event(e)\n    except ValueError:\n        log(e)",           False),
    ("hierarchy_fn_recorded","try:\n        write_event(e)\n    except OSError:\n        log(e)",              False),  # recorded v1 FN — decision 2
    ("no_try",               "write_event(e)",                                                                  False),
    ("non_audit_callee",     "try:\n        other(e)\n    except Exception:\n        pass",                     False),
    ("call_in_handler_body", "try:\n        other(e)\n    except Exception:\n        write_event(e)",           False),  # handler-body write is the RECOVERY, not the swallowed record
]
```

Plus the non-table pins: tier gating (`@external_boundary` caller → declared freedom zone → silent; undecorated caller → `UNKNOWN_RAW` → silent; `@trust_boundary(to_level='GUARDED')` caller → WARN via `_DOWNGRADE`), the `try*`/`TryStar` variant of `broad_swallow` (fires), the 103-co-fire de-confliction pin (`broad_swallow` yields **both** a PY-WL-103 and a PY-WL-129 finding with distinct fingerprints, and running with `rules_enable = ["PY-WL-103", "PY-WL-104"]` — 129 disabled — still yields the 103 finding), the candidate-callee pin (a branch-conditional callee where one candidate is the audit function fires — via `call_site_candidate_callees`), and two-decorator stacking (the audit function itself also `@trusted` — caller finding unchanged).

- [ ] **Step 2: Run to verify red** — `uv run pytest tests/unit/scanner/rules/test_audit_record_swallowed.py -q` — Expected: FAIL (module not found).
- [ ] **Step 3: Implement.** Helpers first:

```python
# _ast_helpers.py
def own_try_statements(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.Try | ast.TryStar]:
    for stmt in _own_statements(node):
        if isinstance(stmt, (ast.Try, ast.TryStar)):
            yield stmt


def calls_in_statements(stmts: Sequence[ast.stmt]) -> Iterator[ast.Call]:
    """Every Call in the given statements, excluding nested def/class bodies."""
    for stmt in stmts:
        for sub in ast.walk(stmt):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and sub is not stmt:
                break  # replaced by an explicit stack walk in the implementation — see note
            ...
```

(The implementation uses the module's existing `_own_statements`-style explicit-stack walk rather than `ast.walk`-with-break — copy that idiom; the docstring contract above is what the tests pin.) Rule body:

```python
# audit_record_swallowed.py (shape mirrors broad_exception.py end to end)
METADATA = RuleMetadata(
    rule_id="PY-WL-129",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    maturity=Maturity.PREVIEW,
    multi_emit=True,
    description=(
        "A call to an @audit_record function is guarded by an exception handler "
        "that swallows its failure (broad or silent, without re-raise) in a "
        "trusted-tier function. The code declares the callee the legal record; "
        "wardline verified the failure-handling discipline around it — a "
        "swallowed failure is an action with no record."
    ),
    examples_violation=(...,),  # the broad_swallow and silent_narrow case sources
    examples_clean=(...,),      # broad_reraise, narrow_handled, hierarchy_fn_recorded
)

def _swallows(handler: ast.ExceptHandler) -> bool:
    return (is_broad_except(handler) or is_silent_handler(handler)) and not _contains_reraise(handler)

def _audit_callee(call, context) -> str | None:
    callee = context.call_site_callees.get(id(call))
    candidates = (callee,) if callee else tuple(context.call_site_candidate_callees.get(id(call), ()))
    for c in candidates:
        if c and Facet.AUDIT_RECORD in context.function_facets.get(c, frozenset()):
            return c
    return None

# check(): per entity → tier → modulate → skip NONE; per own_try_statements:
#   swallowing = [h for h in t.handlers if _swallows(h)]; skip if empty;
#   for call in calls_in_statements(t.body):
#       callee = _audit_callee(call, context); skip None;
#       emit Finding(rule_id, message naming callee + first swallowing handler line,
#                    severity, Kind.DEFECT,
#                    Location(path, line_start=call.lineno),
#                    fingerprint=_fp(rule_id=..., path=..., qualname=...,
#                                    taint_path=f"{entity_relative_span(call, base)}:audit"),
#                    qualname=qualname,
#                    properties={"tier": tier.value, "audit_callee": callee,
#                                "handler_line": handler.lineno})
```

- [ ] **Step 4: Registration surfaces** — append the class, then update the five pin files named above. Run: `uv run pytest tests/unit/scanner/rules tests/grammar/test_grammar_model.py tests/grammar/test_analyzer_wiring.py -q` — Expected: green.
- [ ] **Step 5: Examples meta + discriminator lint** — `uv run pytest tests/unit/scanner/rules/test_rule_examples_meta.py tests/unit/scanner/rules/test_discriminator_shape.py tests/unit/core/test_preview_gating.py -q` — Expected: green (129 auto-enrolls in preview gating and the multi-emit lint).
- [ ] **Step 6: Full suite** — `uv run pytest -q` — Expected: green; the grammar byte golden does NOT move (129 is PREVIEW and no corpus fixture exists yet — Task 7 owns that move).
- [ ] **Step 7: Commit**

```bash
git add src/wardline/scanner/rules/audit_record_swallowed.py src/wardline/scanner/rules/_ast_helpers.py \
  src/wardline/scanner/rules/__init__.py tests/unit/scanner/rules/ tests/grammar/test_grammar_model.py \
  tests/grammar/test_analyzer_wiring.py docs/concepts/rules.md
git commit -m "feat(rules): PY-WL-129 — audit-record write swallowed by a broad/silent handler (WL-005)"
```

### Task 7: Facets corpus — fixtures, sentinels, manifest rows, the one grammar-golden re-freeze, drop-coverage rows, per-kind receipt

**Files:**
- Create: `tests/corpus/fixtures/facet_swallowed_broad.py`, `tests/corpus/fixtures/facet_swallowed_silent.py`, `tests/corpus/fixtures/facet_swallowed_tuple.py` (≥3 TP fixture files; ≥5 TP `PY-WL-129` specimen rows between them, each also carrying its co-fired 103/104 rows)
- Create: `tests/corpus/sentinels/clean_facet_reraise.py`, `tests/corpus/sentinels/clean_facet_narrow_handled.py`, `tests/corpus/sentinels/clean_facet_hierarchy_fn.py` (≥3 clean/FALSE_POSITIVE sentinel files; `clean_facet_narrow_handled.py` carries `interaction: match` — the discipline matches the declaration; one TP fixture row carries `interaction: contradiction`)
- Modify: `tests/corpus/MANIFEST.yaml` (rows with `kind: facets`, `maturity: preview` for 129; `kind: core` rows for every co-fired 103/104)
- Modify: `tests/grammar/golden/builtin_findings.jsonl` — **sanctioned move #2, exactly once, via `regen.py --reason "S1 facets kind: corpus gains facet fixtures; STABLE 103/104 co-fires absorbed (spec §12 once-per-kind allowance)"`**
- Modify: `tests/grammar/test_drop_coverage_matrix.py` (facet rows: a **called** `@audit_record()` names the `PY-WL-130` channel present with the facet dropped; the module prose gains the inherited re-export axis note naming `wardline-69a58cb05f`, beside the existing trust-marker note)
- Create: `tests/unit/cli/test_facet_kind_receipt.py` (the per-kind QE receipt assertion — see Step 5)

**Interfaces:**
- Consumes: Tasks 5–6. Produces: the `facets` kind live in the corpus harness (`_ALLOWED_KINDS` already admits it, `harness.py:54`), reconciliation clean, and the per-kind floors met: ≥3 clean sentinel files, ≥3 TP fixture files, ≥5 TP rows, ≥5 active defects; if active defects < 10 the receipt records `sentinel-gated-low-sample` and **no rate claim is made** (spec §12).

- [ ] **Step 1: Author the fixtures and sentinels.** Every file declares its own `@audit_record` writer plus `@trusted(level="ASSURED")` callers so the corpus stays self-contained; every construct that fires ANY defect gets a manifest row (unaccounted findings fail `test_fp_rate_within_budget`). The `hierarchy_fn` sentinel is the recorded-FN specimen from decision 2 (`except OSError: log(e)` — no 129 row, and a comment naming the recorded FN).
- [ ] **Step 2: Manifest rows** — follow the header idiom (`MANIFEST.yaml:1-33`); 129 rows carry `maturity: preview`, `kind: facets`; co-fire rows carry `kind: core`. The interaction pair follows the PY-WL-110 template (`test_fp_rate.py:538+`).
- [ ] **Step 3: Reconcile red-then-green** — `uv run pytest tests/corpus -q`. First run after adding fixtures: Expected FAIL (`unaccounted` non-empty / golden byte drift). Add the missing manifest rows, then regenerate the grammar golden once via `regen.py --reason` (Expected: the only diff lines are 103/104 findings in the three new fixture files — inspect the diff and STOP if any other rule id or file appears). Re-run: Expected green, including `test_per_kind_fp_rate_within_budget` with the `facets` kind present.
- [ ] **Step 4: Drop-coverage rows** — extend the matrix with the called-facet row and re-run `uv run pytest tests/grammar/test_drop_coverage_matrix.py -q` — Expected: green, every row naming a non-empty channel.
- [ ] **Step 5: The per-kind receipt test** — `tests/unit/cli/test_facet_kind_receipt.py` computes the reconciliation for `kind == "facets"` and asserts the floors, recording the receipt values in the assertion messages (kind, active-defect count, FP count, clean-sentinel count, TP-specimen count, and `sentinel-gated-low-sample` when defects < 10) so the numbers land in the test output the close comment cites.
- [ ] **Step 6: Two-run determinism** — `uv run pytest tests/grammar/test_output_determinism.py tests/corpus -q` twice — Expected: identical green.
- [ ] **Step 7: Commit**

```bash
git add tests/corpus/fixtures/facet_swallowed_broad.py tests/corpus/fixtures/facet_swallowed_silent.py \
  tests/corpus/fixtures/facet_swallowed_tuple.py tests/corpus/sentinels/clean_facet_reraise.py \
  tests/corpus/sentinels/clean_facet_narrow_handled.py tests/corpus/sentinels/clean_facet_hierarchy_fn.py \
  tests/corpus/MANIFEST.yaml tests/grammar/golden/builtin_findings.jsonl \
  tests/grammar/test_drop_coverage_matrix.py tests/unit/cli/test_facet_kind_receipt.py
git commit -m "test(corpus): facets kind — fixtures, sentinels, interaction pair, one sanctioned golden re-freeze, per-kind receipt"
```

### Task 8: The declarations inventory factory + assure/dossier consumption (§11.1)

**Files:**
- Create: `src/wardline/core/declarations.py`
- Modify: `src/wardline/core/assure.py` (`AssurancePosture` gains `declaration_counts: Mapping[str, int]` and `declaration_debt: Mapping[str, int]`, both empty-defaulting; `to_dict()` emits them as its 12th/13th keys; `posture_from_scan` fills them from the factory; `_empty_posture` zeroes them)
- Modify: `src/wardline/core/dossier.py` (a budget-elidable `DeclarationsSection` dataclass — per-entity declaration records — wired through `_list_for`/`_with_list` and `bound_to_budget` like its section siblings)
- Test: `tests/unit/core/test_declarations.py`, extensions to `tests/unit/core/test_assure.py` and the dossier tests' existing modules

**Interfaces:**
- Consumes: `AnalysisContext.function_facets` (Task 5) — reached the way `posture_from_scan` reaches scan outputs today (the factory takes plain data, never the context object: `build_declarations_inventory(function_facets: Mapping[str, frozenset[str]]) -> tuple[DeclarationRecord, ...]`).
- Produces (frozen for Tasks 9–12):

```python
DECLARATION_ID_SCHEME = "wlds1"
GROUPS = ("contracts", "dependency_taint", "facets", "restoration", "sensitivity")

@dataclass(frozen=True, slots=True)
class DeclarationRecord:
    declaration_id: str            # "wlds1:<64 hex>"
    kind: str                      # plural group name, one of GROUPS
    subject: str                   # scan-root-relative qualname / FQN / table key
    content_digest: str            # "sha256:<64 hex>"
    verification_class: str        # machine_verified | structurally_verified | recorded_unverified
    sei: str | None = None         # optional metadata, NEVER part of the id
    def to_dict(self) -> dict[str, object]: ...   # sorted keys; sei omitted when None

def declaration_id(kind: str, subject: str, field: str | None = None) -> str
def content_digest(content: Mapping[str, object]) -> str
def build_declarations_inventory(function_facets) -> tuple[DeclarationRecord, ...]
def declaration_counts(records) -> dict[str, int]      # all five GROUPS keys, zero-filled
def declaration_debt(records) -> dict[str, int]        # {lapsed_expiries, record_only_claims, stale_dependency_pins} — all zero in S1
def inventory_digest(records) -> str                   # "sha256:<hex>" over the canonical encoding of the sorted records (baseline v2's comparand)
```

  - `declaration_id` = `f"wlds1:{sha256(NUL.join(('wlds1', kind, subject, field or '')))}"` (decision 7). `content_digest` = SHA-256 over the canonical encoding: sorted keys; type-tagged scalars (`s:` + NFC-normalised text, `i:`, `b:`, `f:` forbidden in v1, `n:` for null); tuples in declared order. Facet record content is `{"facet": "audit_record"}`, `verification_class="recorded_unverified"` (decision 1/7). Records sort by `(kind, subject, declaration_id)`.

- [ ] **Step 1: Write the failing tests** — determinism (`declaration_id` stable across runs and orderings), type-tagging (`content_digest({"v": "1"}) != content_digest({"v": 1})`), NFC (`"café"` composed vs decomposed → one digest), reformat-stability (same mapping, different construction order → one digest), sorting, `declaration_counts` zero-fills all five groups, facet inventory round-trip from a two-facet `function_facets` mapping, `to_dict()` omits `sei` when None, and the assure keys (`AssurancePosture.to_dict()` carries `declaration_counts`/`declaration_debt`; `_empty_posture` zero-shapes both).
- [ ] **Step 2: Red** — `uv run pytest tests/unit/core/test_declarations.py -q` — Expected: FAIL (module missing).
- [ ] **Step 3: Implement** the module (one pure factory, no I/O, no context import — the `gate_decision()` shape: consumers receive the same records and cannot re-derive), then the assure and dossier consumption.
- [ ] **Step 4: Green + full suite** — `uv run pytest tests/unit/core -q && uv run pytest -q` — Expected: green. **Watch for:** any MCP output schema that pins `assure`'s key set — if one reds here, that re-freeze belongs to Task 9's sanctioned move, so STOP this task's commit and re-order the schema edit into Task 9 rather than minting a fourth re-freeze.
- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/declarations.py src/wardline/core/assure.py src/wardline/core/dossier.py tests/unit/core/
git commit -m "feat(core): declarations inventory factory (wlds1) + assure/dossier consumption"
```

### Task 9: Posture — per-group counts, arming, and the `--fail-on-inert` extension (§11.4, P12)

**Files:**
- Modify: `src/wardline/scanner/diagnostics.py` (`build_metric_finding` gains a `declaration_counts` property — per-group ints derived from the seeds the pipeline already holds; zero new analysis)
- Modify: `src/wardline/core/resolution_posture.py` (`ResolutionPosture` gains `declaration_counts: Mapping[str, int]` and `armed_groups: tuple[str, ...]`; `to_dict()` emits both plus `inert_groups` (armed ∩ zero-count, non-trivial scan only); `compute_resolution_posture(findings, *, armed_groups: frozenset[str] | None = None)` — reads counts from the `WLN-ENGINE-METRICS` finding exactly as it reads `taint_source_counts`)
- Modify: `src/wardline/scanner/rules/__init__.py` (`GROUP_CONSUMING_RULES: Mapping[str, frozenset[str]] = {"facets": frozenset({"PY-WL-129"})}` + `armed_groups(config) -> frozenset[str]` derived via `_resolve_enabled_rules`)
- Modify: `src/wardline/core/run.py` (`gate_decision` threads `armed_groups` into its posture computation at `:817`; `inert_tripped` extends: base inert **or** any armed group inert; `GateDecision` gains `inert_groups: tuple[str, ...] = ()` with the matching `__post_init__` invariant — non-empty requires `fail_on_inert`; the reason string names the tripping group(s). A comment beside the trip names `wardline-70a8bb3875`: the Rust no-op is that ticket's, untouched here)
- Modify: `src/wardline/cli/scan.py` (`--fail-on-inert` help text gains the per-group sentence + the `rules_enable` escape; the always-on warning path at `:774` passes the same `armed_groups`), `src/wardline/core/agent_summary.py:163` (same threading)
- Modify: `tests/conformance/mcp_output_schemas.golden.json` + `tests/conformance/test_mcp_output_schema_golden.py:69` — **sanctioned MCP re-freeze #1 of 3** (every output schema that pins the `resolution` dict's key set)
- Test: `tests/unit/core/test_resolution_posture.py` (extend), `tests/unit/core/test_gate_decision_inert_groups.py` (new)

**Interfaces:**
- Consumes: Task 5's seeds (counts), Task 6's rule id (arming map). Produces: `to_dict()` keys `declaration_counts` (five zero-filled groups), `armed_groups`, `inert_groups`; the extended trip semantics — **base inertness is unchanged** (`recognized_boundaries == 0 and functions_analyzed >= 5`), facet declarations never count toward `recognized_boundaries` (Task 5's posture-neutrality pin), and per-group inertness never *clears* anything (spec: "nothing clears it").

- [ ] **Step 1: Failing tests.** Posture: armed facets group + zero facet declarations + ≥5 functions → `inert_groups == ("facets",)`; same scan with `PY-WL-129` disabled → `armed_groups` empty, `inert_groups` empty; a scan carrying one facet → counts `{"facets": 1, ...}` and no facet trip; trust boundaries present + facets armed-and-zero → base `inert` False **and** `inert_groups == ("facets",)` (the gate trips on the group even though the base posture is healthy — the literal §11.4 reading, decision 5). Gate: `fail_on_inert=False` → `inert_groups` never populated (the `GateDecision` invariant); trip reason names the group.
- [ ] **Step 2: Red, then implement** per the Files list. `compute_resolution_posture`'s new parameter defaults `None` = no arming information = per-group logic entirely inert (every existing caller keeps its behaviour; only `gate_decision` and the CLI warning pass the real set).
- [ ] **Step 3: MCP re-freeze #1** — re-run the schema golden test, follow the RE-FREEZE PROCEDURE, move the pin in the same commit. Expected diff: only `resolution`-bearing schema blocks gain the three keys.
- [ ] **Step 4: Full suite** — `uv run pytest -q` — Expected: green.
- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/diagnostics.py src/wardline/core/resolution_posture.py src/wardline/scanner/rules/__init__.py \
  src/wardline/core/run.py src/wardline/cli/scan.py src/wardline/core/agent_summary.py \
  tests/conformance/mcp_output_schemas.golden.json tests/conformance/test_mcp_output_schema_golden.py tests/unit/core/
git commit -m "feat(posture): per-group declaration counts + arming; --fail-on-inert trips on an armed, empty group"
```

### Task 10: `wardline-attest-3` emission — the producer preflight, the flip, the vector replacement (§11.2, §13.3)

**Files:**
- Modify: `src/wardline/core/attest.py` (`ATTEST_SCHEMA` → `"wardline-attest-3"` at `:63`; `_build_payload` gains the six v3 members from the corrected contract: `declarations` (sorted `to_dict()` records), `declaration_counts`, `grants` (`{trusted_packs: [...], trust_dependency_taint: false, strict_defaults: false}` — the two unshipped flags emitted as literal `false` until S2/S4 exist), `dependency_taint_digest: null`, `authorship_note` (the fixed D3 sentence), and the posture's `declaration_debt` sub-object via Task 8's assure change; `ACCEPTED_ATTEST_SCHEMAS` unchanged — the literals tuple already carries both)
- Modify: `tests/conformance/test_attest_contract_freeze.py` (`test_attest_schema_tag_frozen` re-pins to `"wardline-attest-3"`; `test_accepted_schemas_are_frozen_literals` gains the **now-live** guard S0 recorded as inert: assert the tuple is exactly `("wardline-attest-2", "wardline-attest-3")` **and** `ATTEST_SCHEMA == "wardline-attest-3"` **and** a signed attest-2 bundle still verifies with `schema_recognized=True`; `test_attest_3_contract_doc_states_its_draft_terms` is re-cut to `test_attest_3_contract_doc_states_its_normative_terms` — the doc leaves DRAFT in this same commit)
- Modify: `docs/contracts/wardline-attest-3.md` (status → normative; payload table reflects emission), `docs/contracts/wardline-attest-2.md` (+ consumer prompt: "superseded as producer format; still accepted"), `docs/guides/attestation.md`, `docs/reference/mcp.md` (only if a Returns line names the payload keys)
- Modify: `tests/conformance/fixtures/wardline-attest-3.vector.json` — replaced by real producer bytes (sanctioned move; the second and last of this vector's two)
- Modify: `tests/conformance/test_attest_dual_read.py` (pins move with the vector; the three seam-registry tokens survive)
- Modify: `tests/conformance/mcp_output_schemas.golden.json` + pin — **sanctioned MCP re-freeze #2 of 3** (attest/verify surfaces whose schemas pin payload keys, if any red — otherwise this re-freeze is recorded as unused, not spent elsewhere)
- Modify (warpline): `tests/fixtures/wardline-attest-3.vector.json` (byte-identical re-vendor #2 + its consumer receipt)
- Test: `tests/unit/core/test_attest.py` extensions; `tests/conformance/test_attest_producer_preflight.py` (new — the §13.3 gate, kept green permanently)

**Interfaces:**
- Consumes: Task 2's corrected preview, Task 8's factory + assure keys, Task 9's posture keys.
- Produces: the frozen attest-3 producer format; `build_attestation()` returns `{"schema": "wardline-attest-3", "payload": <14 keys: the nine v2 keys + declarations, declaration_counts, grants, dependency_taint_digest, authorship_note>, "signature": {...}}`.

- [ ] **Step 1: The producer preflight test FIRST** (§13.3: compare before replacing) — `test_attest_producer_preflight.py` builds a real attestation over a `tmp_path` project shaped to the vector's inputs (one clean `ASSURED` boundary, one `@audit_record` function), signs with the public conformance key, and compares against the Task-2 vector **semantically** (key sets and every non-environmental value; `attested_at`/`commit`/`dirty`/`wardline_version`/SEI values are environmental and compared by shape) and **bytewise over the non-environmental subtree** (canonical-JSON of the payload with environmental keys normalised to the vector's literals). Run it against the *shipped* attest-2 producer: Expected FAIL (v3 keys absent) — that failure is the preflight's red baseline.
- [ ] **Step 2: Implement the payload extension + schema flip.** Run the preflight: Expected PASS semantically. **Any semantic mismatch is a STOP**: the divergence is adjudicated (fix the producer, or record a reviewed preview erratum on `wardline-b59cbea4bc`'s trail) — never absorbed silently into the replacement.
- [ ] **Step 3: Replace the vector with real producer bytes** (environmental keys pinned to the vector's draft literals via the same normalisation the preflight uses), re-derive the HMAC, move the dual-read pins, keep the three grep tokens. The preflight test now compares producer-vs-vector byte-for-byte on the normalised form and stays in the suite as the permanent freeze.
- [ ] **Step 4: Freeze-test and doc re-cut** per the Files list; `--reproduce` behaviour pin: a pre-S1 attest-2 bundle still verifies (`schema_recognized=True`, `signature_valid=True`) and reproduces with the v3-only keys as honest `mismatches` (the contract doc's Migration sentence, now tested).
- [ ] **Step 5: Warpline re-vendor + receipt** — byte-identical copy; `WARPLINE_REPO=/home/john/warpline uv run pytest tests/conformance/test_attest_dual_read.py -v` green; warpline's attest consumer suite green.
- [ ] **Step 6: Full suite both repos; commit (wardline then warpline), citing `wardline-c0563eee74`**

```bash
cd /home/john/wardline
git add src/wardline/core/attest.py tests/conformance/ docs/contracts/ docs/guides/attestation.md docs/reference/mcp.md tests/unit/core/test_attest.py
git commit -m "feat(attest): emit wardline-attest-3 — declarations ledger, counts, grants; preview compared then frozen (§13.3)"
cd /home/john/warpline
git add tests/fixtures/wardline-attest-3.vector.json
git commit -m "test(attest): vendor the frozen wardline-attest-3 producer vector byte-identically"
```

### Task 11: Baseline v2 — the declaration-digest section (§11.2)

**Files:**
- Modify: `src/wardline/core/baseline.py` (`BASELINE_VERSION = 2` at `:31`; `ACCEPTED_BASELINE_VERSIONS = (1, 2)` literals; the `:273` hard equality becomes membership; `build_baseline_document` emits the fourth top-level key `declarations: {digest: <inventory_digest(records)>, count: <len(records)>}`; `load_baseline` returns the section when present; a v1 document loads with no section and no comparison; `inspect_baseline_store` messages updated)
- Modify: `src/wardline/core/baseline_ops.py` (threads the inventory records into the writer)
- Modify: `src/wardline/core/rekey.py` (`:50`/`:436`/`:501` — the carry logic rewrites `entries` and must carry the `declarations` section **verbatim**; a pin proves rekey does not drop it)
- Modify: `src/wardline/scanner/diagnostics.py` or the scan assembly point `run.py` (the drift report: when a loaded baseline carries a declarations section whose digest ≠ the current scan's `inventory_digest`, emit `WLN-BASELINE-DECLARATIONS-DRIFT` — `Severity.NONE`, `Kind.FACT`, `location=ENGINE_PATH`, fingerprint `_fp("WLN-BASELINE-DECLARATIONS-DRIFT", ENGINE_PATH)` identity-keyed, properties `{"baseline_digest": ..., "current_digest": ..., "baseline_count": ..., "current_count": ...}`)
- Modify: `src/wardline/mcp/server.py:4189,:4477` + `src/wardline/cli/main.py:109` (probe/docstring version text)
- Test: `tests/unit/core/test_baseline.py` (extend), `tests/unit/core/test_baseline_declarations_drift.py` (new)

**Interfaces:**
- Consumes: Task 8's `inventory_digest`. Produces: baseline v2 documents; the drift FACT — **compared and reported, never suppressible** (it is `Kind.FACT`, so `apply_suppressions`' `Kind.DEFECT` short-circuit makes a waiver or baseline row naming its fingerprint inert — the §4.2.1 condition-3 argument verbatim, and the same both-channels regression pins it).

- [ ] **Step 1: Failing tests** — v1 document loads unchanged (no section, no comparison, no FACT); v2 round-trip (write → load → section intact); digest match → no FACT; digest mismatch → exactly one FACT with both digests in properties; the FACT survives `apply_suppressions` unchanged when a baseline **and** a waiver both carry its fingerprint; `rekey` carries the section verbatim; `inspect_baseline_store` names v2.
- [ ] **Step 2: Red → implement → green** — `uv run pytest tests/unit/core/test_baseline.py tests/unit/core/test_baseline_declarations_drift.py tests/unit/core/test_rekey*.py -q`.
- [ ] **Step 3: Full suite; commit**

```bash
git add src/wardline/core/baseline.py src/wardline/core/baseline_ops.py src/wardline/core/rekey.py \
  src/wardline/scanner/diagnostics.py src/wardline/core/run.py src/wardline/mcp/server.py src/wardline/cli/main.py tests/unit/core/
git commit -m "feat(baseline): v2 — declaration-digest section, v1 loads unchanged, drift is an unsuppressible FACT"
```

### Task 12: Legis — the `declarations` member emitted, the two-sided main-vector re-pin (§11.3) — repos `/home/john/wardline` + `/home/john/legis`

**Files:**
- Modify (wardline): `src/wardline/core/legis.py` (`build_legis_artifact` assembles `declarations` — the sorted `to_dict()` records, **always present**, empty list on a declaration-free scan (decision 8) — into the artifact **before** `artifact_signature` is computed, on both the signed and the `dirty` unsigned paths)
- Modify (wardline): `tests/conformance/test_legis_artifact_contract_freeze.py` (`_BASE` at `:70` gains `"declarations"` — the one edit that propagates to all four derived key sets)
- Modify (wardline): `tests/conformance/vectors/wardline_scan_artifact.v1.json` + `tests/conformance/test_wardline_scan_artifact_shared_vector.py:48` (`VENDORED_BLOB_SHA`) — the coordinated two-sided re-pin: every case's artifact gains its `declarations` member and its `expected_signature` hex is re-derived
- Modify (wardline): `tests/conformance/test_legis_scan_wire_golden.py` + `legis_scan_wire.golden.json` + `legis_dirty_scan_wire.golden.json` (the wire goldens carry the new member)
- Create (wardline): `tests/unit/core/test_legis_declarations_member.py` (live emission: a `tmp_path` project with one facet → `build_legis_artifact` output carries the record, `sign_artifact` covers it, and stripping it breaks verification — the wardline-side sign/verify proof S0 deliberately left to legis)
- Modify (legis, `/home/john/legis`): the authored-in-legis source of `wardline_scan_artifact.v1.json` + its expected signatures + the re-derived `scan_digest` pins; its `test_unknown_artifact_key_tolerance.py` stays green unchanged (the S0 preview keeps proving the *tolerance* property; the main vector now carries the *real* member)

**Interfaces:**
- Consumes: Task 8's records. Produces: the legis seam's new wire truth — `declarations` signature-covered and `scan_digest`-shifting by design (legis `ingest.py` copies every non-signature key; digest = sha256 over artifact-minus-signature). The artifact stays **v1** (Global Constraints: additive path, no vN mint).

- [ ] **Step 1 (wardline): the live-emission test red → green** — implement the `build_legis_artifact` change; `uv run pytest tests/unit/core/test_legis_declarations_member.py -q` green; `_BASE` edit; `uv run pytest tests/conformance/test_legis_artifact_contract_freeze.py -q` green.
- [ ] **Step 2 (coordinated pair): re-pin the shared vector on both sides in one coordinated pair of commits.** Author the widened cases + re-derived hexes in the legis repo (its authority), vendor byte-identically into wardline, bump `VENDORED_BLOB_SHA`, regenerate the two wire goldens from the live producer. Run both repos' conformance suites: `uv run pytest tests/conformance -q` (wardline) and legis's contract suite (`cd /home/john/legis && uv run pytest tests/contract -q`). Expected: green both sides; the legis `scan_digest` pins record the shifted digests.
- [ ] **Step 3: Full suites both repos; commits (wardline and legis, orchestrator, cross-referencing shas)**

```bash
cd /home/john/wardline
git add src/wardline/core/legis.py tests/conformance/ tests/unit/core/test_legis_declarations_member.py
git commit -m "feat(legis): emit the additive declarations member — signature-covered, digest-shifting; two-sided vector re-pin"
cd /home/john/legis
git add tests/contract/weft/
git commit -m "test(weft): re-pin the wardline scan-artifact vector for the declarations member (coordinated with wardline)"
```

### Task 13: Loomweave — byte-freeze the generic-3 descriptor from real producer bytes (§13.1 item 1 completed) — repo `/home/john/loomweave`

**Files (all under `/home/john/loomweave`; NEVER touch `.worktrees/`):**
- Modify: `plugins/python/tests/fixtures/wardline-vocabulary-descriptor.generic-3.preview.yaml` — replaced by the exact bytes of wardline's re-frozen `tests/conformance/fixtures/wardline-vocabulary-descriptor.golden.yaml` (Task 4's output), and renamed `...generic-3.yaml` (no longer a preview) with its references updated
- Modify: `plugins/python/tests/test_wardline_descriptor.py` + `test_wardline_vocabulary_descriptor_conformance.py` (the semantic fixture assertions become byte-pinned: a blob-sha pin against wardline's golden, mirroring wardline's `UPSTREAM_BLOB_SHA` convention, so the two repos hold one byte truth)
- Modify: `plugins/python/src/loomweave_plugin_python/wardline_descriptor.py` constants + `scripts/check-wardline-version-bounds.py` + `plugins/python/tests/test_package.py:47-49` + CI `verify.yml:82-85` (`EXPECTED_DESCRIPTOR_VERSION` `"wardline-generic-2"` → `"wardline-generic-3"` — the S0 Task 19 constraint said "stays generic-2 everywhere in S0"; this is its designed S1 move)
- Test: the existing end-to-end facet-attribution test now runs against real bytes

**Interfaces:**
- Consumes: Task 4's frozen descriptor bytes. Produces: loomweave reading `(wardline.vocabulary/v2, wardline-generic-3)` byte-for-byte as emitted, `facet_for_decorator()` attributing `audit_record` at extraction sites, and the dual-accept of `(v1, generic-2)` still green (the pair-gate tests are untouched).

- [ ] **Step 1: Copy the bytes; run the descriptor suite** — `cd /home/john/loomweave && uv run pytest plugins/python/tests/test_wardline_descriptor.py plugins/python/tests/test_wardline_vocabulary_descriptor_conformance.py -q`. If the real bytes differ from the S0 semantic fixture in any **shape** the acceptance tests pinned (key order aside), STOP: that is a consumer-contract divergence to adjudicate against spec §4.3, not to absorb.
- [ ] **Step 2: Move the four `EXPECTED_DESCRIPTOR_VERSION` pins; full loomweave suite** — Expected: green; the version-skew tests still prove a *future* generic-4 skews cleanly.
- [ ] **Step 3: Cold-install probe (local-coordination gate evidence)** — build wardline from the release/2.0.0 head archive, install into a scratch venv with loomweave, run `wardline vocab` and loomweave's descriptor load against it; record both shas in the receipt.
- [ ] **Step 4: Commit (loomweave)**

```bash
cd /home/john/loomweave
git add plugins/python/ scripts/check-wardline-version-bounds.py .github/workflows/verify.yml
git commit -m "feat(wardline): byte-freeze the generic-3 descriptor from the real producer; expect wardline-generic-3"
```

### Task 14: Seam-registry truth-up + receipts

**Files:**
- Modify: `tests/conformance/seam_registry.json` — the attest row (index 28): evidence paths now name the frozen (post-Task-10) vector and the normative contract doc; the legis scan-artifact row (index 9): `wire_change` `"none"` → the additive-declarations description, evidence paths gain `test_legis_declarations_member.py`; a new row (or the registry's documented amendment shape, whichever `test_seam_registry.py`'s validator requires) binding the descriptor seam to the loomweave byte-pin from Task 13.
- Test: `uv run pytest tests/conformance/test_seam_registry.py -q` (the validator IS the spec of what a row may say — fit the rows to it, never weaken it)

- [ ] **Step 1: Re-cut the rows; run the validator red→green.** The attest row's `oracle_test` grep contract (`GOLDEN_KEY` / `sign_artifact(` / `*_FIELD` in `test_attest_dual_read.py`) must still hold — verify by grep before running.
- [ ] **Step 2: Commit**

```bash
git add tests/conformance/seam_registry.json
git commit -m "test(conformance): seam registry — attest frozen, legis wire_change recorded, descriptor byte-pin bound"
```

### Task 15: CHANGELOG + docs truth-up

**Files:**
- Modify: `CHANGELOG.md` (`## [Unreleased]` → `### Added`: bold-lead prose entries, one per Version-bump-discipline clause tripped — vocabulary v2/generic-3 (+ resolver epoch + provider fingerprint move), the facet plane + `@audit_record` + `PY-WL-129`, attest-3 emission, baseline v2 + the drift FACT, the legis declarations member, per-group posture counts/arming; every factual claim verified against shipped code, per the `a39a63a4` discipline; nothing dated or versioned)
- Modify: `docs/concepts/rules.md` (done in Task 6 — verify), `docs/guides/attestation.md` (done in Task 10 — verify), `docs/agents.md` (the agent-facing loop mentions `@audit_record` and per-group inertness where it documents `--fail-on-inert`), `packages/weft-markers/README.md` (done in Task 4 — verify)
- Modify: `docs/contracts/wardline-attest-2.md` / `-consumer-prompt.md` (verified superseded-as-producer wording from Task 10)

- [ ] **Step 1: Write the entries; cross-check each claim against the shipped constant/test it describes.**
- [ ] **Step 2: `uv run pytest tests/conformance -q`** (doc-grepping freeze tests) — Expected: green.
- [ ] **Step 3: Commit** — `git add CHANGELOG.md docs/ packages/weft-markers/README.md && git commit -m "docs(changelog): S1 entries — every wire move named under its version-bump clause"`

### Task 16: Final verification and close

- [ ] **Step 1: Full suites, all four repos** — `uv run pytest -q` in wardline, loomweave, warpline, legis. Expected: all green, no skips in the coordinated conformance tests (`WARPLINE_REPO`/`LEGIS_REPO` set so the Layer-2 receipts arm).
- [ ] **Step 2: Self-hosting gate** — `uv run wardline scan . --fail-on ERROR` — Expected: exit 0 with **zero committed suppressions** (spec §12). Then the same scan with `--fail-on-inert`: wardline's own tree carries no `@audit_record` yet, so the facets group is armed-and-empty — Expected: exit 1 **by design**; record this as the receipt that per-group arming is live (the spec's per-kind self-hosting gate reads `--fail-on ERROR`, which stays green; the inert-trip receipt is evidence, not a regression).
- [ ] **Step 3: Identity-corpus zero-byte-delta receipt** — re-hash every file recorded at the pre-Task-1 measurement; Expected: identical hashes; `git status --porcelain` clean over `tests/golden/identity/**`, `tests/corpus/rust/**`.
- [ ] **Step 4: Version-move ledger receipt** — assert the six moved constants at their final literals and the two unmoved ones (`SUMMARY_SCHEMA_VERSION == 1`, `_CACHE_FILE_SCHEMA_VERSION == 1`) — one script, output pasted into the close comment.
- [ ] **Step 5: Warm/cold byte-identity** — two consecutive `wardline scan .` runs byte-identical; the first post-S1 run rebuilt summaries (fingerprint + resolver epoch moved).
- [ ] **Step 6: Filigree close** — close `wardline-7342234667` with the five receipts named in Filigree discipline (per-kind QE receipt incl. `sentinel-gated-low-sample` status if applicable, zero-byte-delta receipt, version ledger, three cross-repo receipts with consumer commit shas, `published_emission_ready=false` + the owner-held published-emission pointer). State that S1's close does not close the G2 bet, PRD-0003 criterion 6, or `wardline-b857b50b54`/`wardline-69a58cb05f`/`wardline-70a8bb3875`.
- [ ] **Step 7: Merge discipline** — surface to John that `release/2.0.0` carries S1 and ask for the push/PR call (the branch's unpushed-commit durability risk predates this plan; merging finished green work back to the working release is the standing directive).

---

## Self-review (rev 1.0, run before handoff)

**Spec coverage against §13.2's S1 row:** `FacetType` → T4; `@audit_record` (weft-markers 0.2.0) → T4; WL-005 → T6/T7; vocabulary v2 + `wardline-generic-3` (consumers ready per §13.1) → T4/T13; inventory factory → T8; `wardline-attest-3` → T2/T10; legis `declarations` member → T12; baseline v2 → T11; per-group posture counts → T9. §12 per-kind gates → T7 (floors, interaction pair, low-sample receipt) + T16 (self-hosting, identity zero-byte delta, two-run determinism). §13.3 producer preflight → T10 Step 1; rollout fence → Global Constraints + T16. §4.3 extension checklist → T1/T4. P11a survival → T3. **Known non-coverage, deliberate:** `@operation`/`Semantics` (spec §4.1: unscheduled, not exported before its ACF-R2 rule); `RefArg`/`TokenSetArg` generic readers (S2, spec §4.2); the S1 tracker's stale "operation-semantics" scope (re-scoped by comment, decision recorded in filigree).
**Placeholder scan:** the two `...` sites in Task 6/10 code blocks are deliberate elisions of case-table content defined immediately above them (examples tuples name their source rows; the `check()` skeleton's `...` lines are each specified by the adjacent comment lines) — an implementer has the full contract; no TBD/TODO items exist.
**Type consistency:** `Facet`/`FacetType`/`BUILTIN_FACET_TYPES` (T4) are consumed by those names in T5/T6/T8; `function_facets: Mapping[str, frozenset[Facet]]` is uniform across T5/T6/T8/T9; `DeclarationRecord`/`build_declarations_inventory`/`inventory_digest`/`declaration_counts`/`declaration_debt` (T8) are consumed by those names in T10/T11/T12; the six version literals appear identically in Global Constraints and their owning tasks.

