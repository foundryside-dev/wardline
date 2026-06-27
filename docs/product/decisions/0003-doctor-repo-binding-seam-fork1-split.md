# PDR 0003 — doctor.repo_binding seam: absent baseline stays silent (Fork-1 split)

`Date: 2026-06-28` · `Status: Accepted` · `Decider: product-owner agent (within
grant; the global-install activation step was user-confirmed in-session via
AskUserQuestion)`

## Context

Execution of the **Now** bet (weft-seam-conformance, PDR-0002). Lacuna's
MCP-attachment regression harness needs every federation MCP server to prove it is
not merely *attached* but *bound to and able to read its repo-scoped store* — born
of the 2026-06-26 loomweave incident (a stale binary started cleanly, `initialize`
+ `tools/list` both succeeded, but it could not read its store, so its findings
silently went dark). The wardline obligation (canonical prompt, recovered from the
crashed lacuna session's scratchpad): extend the MCP `doctor` tool with a read-only
store-read check whose **non-tautological** signal is the baseline schema version
read from *inside* `.weft/wardline/baseline.yaml` — not a `root == cwd` path
identity, which is tautological under the harness's spawn model.

The literal consumer prompt specified: **baseline absent → check `status: "error"`**.
Taken at face value, that flips the overall `doctor.ok` false and emits a "run
baseline" nag on *every* repo without a baseline — and baseline gating is an opt-in
wardline feature. That directly collides with a vision anti-goal: *"Not noisy.
Silent until opted in… an analyzer that cries wolf gets turned off."*

## Options

- **(a) Implement the prompt literally** — absent → error, unreadable → error. *Rejected:*
  over-broad; nags every baseline-less repo for an opt-in feature; violates the
  not-noisy anti-goal; would flip `doctor.ok` false across the fleet.
- **(b) Make the check always informational** — never flip `doctor.ok`. *Rejected:* it
  would also swallow the *unreadable* (stale-binary) case, which is the whole incident
  the harness exists to catch.
- **(c) Split the two cases (chosen).** Present-but-**unreadable**/corrupt (the
  stale-binary incident) → `status: "error"`, flips `doctor.ok`. **Absent** (opt-in
  feature not set up) → `status: "ok"`, never nags. `binding_ok=false` in the structured
  block for *both*.

## The call

**Ship option (c).** The property the harness needs — catch a stale binary that can't
read a present store — is fully satisfied by *unreadable→error*; *absent→error* is
over-broad mechanism, not the requirement (the property-vs-mechanism distinction). The
consumer reads `repo_binding.binding_ok` / `repo_binding.store.schema_version`, **not**
the doctor check status, so the split is **contract-safe by construction** — proven
live: a freshly-spawned installed `wardline mcp doctor` returns `binding_ok=true` /
`schema_version=1` for a repo *with* a baseline (the staged lacuna case-1 shape).

Delivered: commit `c661286f` on `release/consolidation-2026-06-26` (read-only
`inspect_baseline_store` in `core/baseline.py`; `_check_repo_binding` +
`repo_binding` block in `install/doctor.py`; `_DOCTOR_OUTPUT_SCHEMA` + golden
re-freeze). Built via an ultracode workflow (1 TDD implementer + 5 adversarial
verifiers, all pass) + 3 follow-up fixes (strict-from-disk `schema_version`,
content-free redaction of the unreadable diagnostic, golden re-vendor). Full suite
4472 passed; ruff/mypy clean; self-gate exit 0 / 0 active.

**Activation (user-confirmed):** the global `~/.local/bin/wardline` was a stale pinned
PyPI 1.0.7 lacking this code; the owner chose (AskUserQuestion) to reinstall it
**editable** from local source (`[scanner,rust]`), shifting the global toolchain from
released-1.0.7 to local working-tree code across all repos — verified the installed
binary now serves the contract via a subprocess stdio smoke.

## Rationale

Within-grant execution of the Now bet; the deviation from the literal prompt is a
product-principle call (the vision's not-noisy anti-goal), not a scope change, and it
does not weaken the consumer contract (live-proven). The non-tautological store-read
fact is what makes the seam honest — it can now say "I can't read my store" instead of
looking healthy, the core seam-honesty thesis.

## Reversal trigger

Metric-bound, tied to `metrics.md` **G2-seam** + the not-noisy anti-goal:

1. **Consumer contradiction.** If the Lacuna owner (or any consumer) is found to assert
   on the doctor *check status* / `doctor.ok` for the absent case — making `absent→ok`
   a false-green for them rather than the structured `repo_binding.binding_ok` — revisit
   the split (surface absent more loudly for that consumer, without re-nagging every
   baseline-less repo).
2. **Honesty-invariant breach.** If this `doctor.repo_binding` surface is ever found
   returning a confident `binding_ok`/empty with no machine-readable reason (the
   G2-seam P0 class), that is a reversal of the whole point — treat as P0, same as a
   fail-open taint hole.
