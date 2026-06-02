# Wardline Track 1 — engine-quality floor (design)

**Date:** 2026-06-02
**Status:** Track spec — the first body of work under
`2026-06-02-wardline-first-class-body-of-work-design.md` (the program spec). This
is the detailed, implementation-ready layout of **Track 1**; the agent executing it
may produce its own TDD plan (writing-plans) from this.
**Gate:** none — fully autonomous. No sibling dependency.
**Parent program spec:** `2026-06-02-wardline-first-class-body-of-work-design.md` §2 Track 1.

> **Why this is first.** The extensible trust grammar (Track 2) and every Loom-citizen
> layer build *on* the engine. A grammar over an unsound engine inherits the
> unsoundness. So the engine-quality floor is the foundation — it ships first, and it
> is entirely Wardline's own work.

---

## 1. Scope & definition of done

**In scope:** T1.1–T1.4 — close the known soundness/completeness gaps, establish a
false-positive measurement substrate, and hold the precision/determinism bars.

**Deferred (explicitly NOT this body of work):** T1.5 (rule-set breadth, 4 → ≥10
rules) sequences **after** the Track 2 grammar, so new rules are authored on the
grammar rather than built the legacy way and migrated. SEI/dossier/legis work is
other tracks.

**Done when every gate is green:**

| Gate | Bar |
|---|---|
| Soundness | the known fail-open / under-taint and FN gaps (T1.1–T1.3) are closed; **every closed hole has a regression test** that fails on the pre-fix engine |
| False-positive rate | **≤5%** of active findings are false positives on the labeled corpus (§3); every suppression in real use carries a waiver reason; waiver count does not grow faster than rule count |
| Coverage | **90%** global floor; **95%** on `src/wardline/scanner/taint/` |
| Determinism | the warm/cold **byte-identical findings** test stays green (cold scan ≡ warm-cache scan, byte-for-byte) |
| Dogfood | `wardline scan src/wardline --fail-on ERROR` stays **finding-clean or fully baselined** |

---

## 2. Work units

### T1.1 — Taint-combination engine hardening *(Filigree `wardline-2b138b3662`, P2 epic)*

The "first-class hardening" epic from the 2026-05-31 audit. Harden the
taint-combination core so the two operators and the control-flow joins are correct at
the edges.

- **Goal:** close the `least_trusted` (rank-meet / weakest-link) and `taint_join`
  (provenance-clash → `MIXED_RAW`) edge cases, and the control-flow-join paths
  (if/try/match/with merges) surfaced by the audit. The two operators must stay
  distinct (never collapse `least_trusted` into `taint_join`).
- **Deliverables:** the fixes, each with a regression test that reproduces the defect
  on the pre-fix engine (RED), plus the audit's findings closed or explicitly
  dispositioned.
- **Acceptance:** the audit's enumerated cases each have a passing test; the
  `MIXED_RAW`-discrimination tests still guard against operator collapse; soundness
  is monotone (no fix introduces an under-taint).

### T1.2 — Star-import FN resolution *(Filigree `wardline-2b427a9579`, P3)*

- **Goal:** resolve decorator markers through `from x import *` so trust decorators
  imported via star-import are recognised. Today this is a false-negative, observable
  as a `WLN-ENGINE-UNKNOWN-IMPORT` FACT.
- **Deliverables:** star-import materialisation in the import-alias / decorator
  resolution path; a fixture where a `@trust_boundary` reached via `from x import *`
  is correctly seeded (was silently missed).
- **Acceptance:** the fixture fires the correct finding; the `WLN-ENGINE-UNKNOWN-IMPORT`
  FACT is no longer emitted for the resolved case; unresolved cases still emit the
  honest FACT (fail-closed preserved).

### T1.3 — Return-indirection in `compute_return_callee` *(Filigree `wardline-82f49ec3c3`, P3)*

- **Goal:** resolve return indirection so the explain surface names the real
  contributing callee for anchored PY-WL-101 (the SP8 `compute_return_callee` work
  left N-hop indirection incomplete).
- **Deliverables:** return-indirection resolution in `compute_return_callee`; explain
  output names the actual contributing callee, not `None`.
- **Acceptance:** an explain fixture over a return-indirection chain names the correct
  callee; the `compute_return_taint` **values are unchanged** (this is an
  explain-surface completeness fix, not a taint-value change — pin that invariant).

### T1.4 — FP economics: measurement substrate + waiver discipline

- **Goal:** make the FP-rate gate measurable and the waiver discipline enforceable.
  (Without this, "FP ≤5%" is unverifiable.)
- **Deliverables:**
  - A **labeled corpus** (§3) — annotated fixtures with per-finding ground-truth
    `TRUE_POSITIVE` / `FALSE_POSITIVE` labels, deliberately including the FP-prone
    shapes (branch joins, validators, broad-except in trusted tiers, aliased stdlib).
  - An **FP-rate measurement** harness/test that runs the engine over the corpus and
    asserts FP-rate ≤5%.
  - **Waiver discipline:** a test that every waiver carries a reason, and a check that
    waiver count does not outgrow rule count (a simple ratio assertion).
- **Acceptance:** the FP-rate test passes at ≤5%; the waiver-discipline checks pass.

---

## 3. The labeled corpus (resolving the program-spec open detail)

Wardline is opt-in / declaration-gated — findings fire only on trust-annotated code,
so the **dogfood tree (undecorated) is clean by construction** and is *not* an
FP-measurement corpus; it is the self-hosting gate (the Dogfood DoD row).

The FP corpus is therefore a curated set of **annotated** fixtures that exercise the
rules, each finding labeled with ground truth:

- Build on the existing per-rule `examples_violation` / `examples_clean` fixture
  discipline (from SP2); extend it into a labeled corpus under a dedicated path
  (e.g. `tests/corpus/`), each module annotated and each expected finding tagged
  `TRUE_POSITIVE` / `FALSE_POSITIVE`.
- **Must include the FP-prone shapes:** control-flow-join merges, validators
  (`@trust_boundary` with/without a rejection path), broad/silent except in trusted
  tiers, aliased-stdlib sinks, match-arm assignments, return indirection.
- **FP rate** = (active findings labeled `FALSE_POSITIVE`) / (total active findings)
  over the corpus, asserted **≤5%**.
- The corpus is the shared substrate the Track 2 grammar and Track 1.5 breadth work
  reuse — design it to grow.

---

## 4. Intra-track sequencing

1. **T1.4 corpus first (thin slice):** stand up the labeled-corpus harness and the
   FP-rate measurement *before* the fixes, so each fix in T1.1–T1.3 is validated
   against a real FP/precision baseline rather than in the dark. (A minimal corpus
   first; grow it as the fixes surface new shapes.)
2. **T1.1 → T1.2 → T1.3:** the soundness/completeness fixes, each RED-first
   (regression test reproduces the defect on the pre-fix engine, then fix to green).
3. **Close-out:** confirm all DoD gates green together (FP ≤5%, coverage 90%/95%,
   byte-identical, dogfood clean), and that no fix regressed another.

---

## 5. Invariants & process

**Invariants (hold throughout):**
- **Fail-closed / no false-green.** Every state the engine cannot prove is an
  observable `WLN-ENGINE-*` FACT; a silent skip is a bug. Over-taint (safe) is
  acceptable; under-taint (a fix that hides a real flow) is a defect.
- **Two operators stay distinct** — `least_trusted` ≠ `taint_join`.
- **Byte-identical warm/cold** — any caching/summary change must keep cold ≡ warm.
- **Determinism** — tests run under `pytest-randomly`; order-dependence is a real
  failure.
- **Zero-dep base** — no new runtime dependency in the base package.

**Process:**
- **TDD, RED-first.** Every soundness fix starts with a failing regression test that
  reproduces the defect on the current engine.
- **The repo gate is the bar:** `make ci` (ruff check + ruff format --check + mypy
  strict + pytest + the 90% coverage floor) must pass; add the 95%-on-`taint/`
  check for this track.
- **Filigree workflow:** claim each issue with `start-work` (atomic), close on
  completion; the epic `wardline-2b138b3662` is a `bug`/epic — use `--advance` if a
  triage→working transition is needed.
- **Review discipline:** per repo norms, run a review panel on the engine changes
  (soundness work warrants the default code-review panel); fix convergent must-fixes
  before close.

---

## 6. Out of scope

- **T1.5 rule-set breadth** (4 → ≥10 rules) — deferred to *after* Track 2 (author on
  the grammar). Do not add new rules in this body of work.
- **The trust grammar itself** (Track 2) — do not begin refactoring the lattice /
  decorators / rules into a grammar here; this track hardens the *current* engine.
- **SEI / dossier / legis** — other tracks, gated on siblings.
