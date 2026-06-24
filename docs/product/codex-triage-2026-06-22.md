# Codex security batch — deep triage (2026-06-22)

> Ground-truth re-triage of the 26 open `codex-security` bugs against current HEAD
> (`09eae7a2`), grounded in the actual code, not the import-time scanner labels.
> Method: 26 triage agents + 26 independent adversarial verifiers (52 agents,
> ~2.9M tokens). Every verdict was re-checked against live code. The full agent
> output is ephemeral; this file is the durable record.

## Bottom line

- **2 tickets are already fixed** (by `b1a9de36`) but still sat in `triage` — closed.
- **Nothing is P0.** The default `wardline scan --fail-on` gate of record is clean.
  Residual risk lives on **opt-in surfaces** (Filigree emit, MCP, the Rust
  *preview*, Loomweave enrichment, `doctor`/install).
- Re-grade: **2 P1, 1 P2, 21 P3** (down from a flat 14 P2 / 12 P3 import labeling).

## Already fixed — closed
| Ticket | Title | Closed by |
|---|---|---|
| `wardline-8c576deeb3` | Rust assignment drops self-referential taint | `b1a9de36` (live-repro verified) |
| `wardline-124edc2a7a` | Rust shadowing erases taint before RHS | `b1a9de36` (live-repro verified) |

## Priority re-grade
**P1** — `wardline-c797baf28b` (unbounded lambda candidate sets — **only finding on the default gate**, O(N³) from one `.py`); `wardline-d96b94d4e9` (doctor leaks Filigree federation token via planted `.weft/.../ephemeral.port`).
**P2** — `wardline-4e664591e6` (invalid-UTF-8 `federation_token` crashes any Filigree-emitting scan).
**P3** — remaining 21 (gradient: real-bypass/soundness on opt-in/preview surfaces → hygiene/enrichment/CI).

Relabeled P2→P3 during this pass: `a456b4f662`, `c852f6d8b5`, `2ab78ad8ed`, `bdabb69446`, `8489bbb3fc`, `31540f8492`, `dbe1117440`, `a1bcb70c15`, `ea10bcd5c9`.

Adversarial overrides of triage: downgraded `8c576deeb3`/`e441f8ef43`; **upgraded `a6d8b5efce`** back to still-present P3 (triage wrongly thought it fixed).

## Concurrency (from actual fix-files)

**Hard sequential chains (same file → serialize):**
- `doctor.py`: `d96b94d4e9` → `cb66016a5c`
- `core/finding.py`: `31540f8492` → `a1bcb70c15`
- `mcp/server.py`: `2ab78ad8ed` → `bdabb69446` → `66bd8ced4b`
- `rust/analyzer.py`(+`mounts.py`): `8489bbb3fc` ↔ `a6d8b5efce` ↔ `dbe1117440`

**Shallow seams (same file / different function → rebase):** `filigree_emit.py` (`66bd8ced4b` ∩ `a456b4f662`); `cli/scan.py` (`66bd8ced4b` ∩ `e441f8ef43`). Land `66bd8ced4b`'s URL-redaction first to clear both.

Everything else is file-disjoint → fully parallel.

## Batches + assigned agents
| # | Batch | Tickets (internal order) | Implementation | Review |
|---|---|---|---|---|
| B1 | Credential & Filigree-emit | `d96b`(P1)→`cb66`; `4e66`(P2); `a456`; `2def` | general-purpose + `controls-designer` (d96b token-provenance gate) | `threat-analyst` + `silent-failure-hunter` + `python-code-reviewer` |
| B2 | MCP capability/policy | `2ab7`→`bdab`→`66bd` | general-purpose (MCP/policy) | `threat-analyst` + `silent-failure-hunter` + `python-code-reviewer` |
| B3 | Rust frontend (preview) | crash: `8489`↔`a6d8`↔`dbe1`,`87ef`; soundness: `ef9a`,`b757`,`6169` | general-purpose (Rust-dialect) | `false-positive-analyst` + `silent-failure-hunter` + `test-suite-reviewer` |
| B4 | Finding-identity / fingerprint | `31540`→`a1bc` | general-purpose (static-analysis) | `false-positive-analyst` + `python-code-reviewer` + `test-suite-reviewer` |
| B5 | Scanner & installer DoS bounds | `c797`(P1); `044a` | general-purpose (perf) | `python-code-reviewer` + `test-suite-reviewer` + `false-positive-analyst` |
| B6 | Path-safety & enrichment integrity | `e441`,`56189`,`f55e`,`ea10` | general-purpose | `python-code-reviewer` + `threat-analyst` (e441) |
| B7 ⚠️ | Supply-chain / CI (outward-facing) | `c852` | general-purpose (devops) | `pipeline-reviewer` |

In-progress `wardline-14359d070b` (waiver_add MCP network bypass, claimed by codex) belongs to B2.

## Execution
1. Close the 2 fixed tickets (done).
2. Wave 1 (parallel): B1 (d96b P1), B5 (c797 P1), B3, B4.
3. Wave 2 (parallel): B2, B6, B7 — after `66bd` lands the redaction.
4. Respect the 4 sequential chains within batches.

## ⚠️ Escalation
B7 / `c852f6d8b5` modifies the GitHub Pages deploy pipeline for `wardline.foundryside.dev` (outward-facing). Pinning the `@weft/site-kit` fetch to a SHA is internal hardening but touches the publish path — gated for owner confirmation before dispatch.
