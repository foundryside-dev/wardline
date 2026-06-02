# Filigree ask #3 — close-on-fixed cascade *during scan-results ingest* (for Wardline A2)

**Date:** 2026-06-02
**From:** Wardline (Loom analyzer) · **To:** whoever owns Filigree
**Status:** Request brief. One change so Wardline's `file_finding` (A2) actually *closes* a tracked issue when the agent fixes the code and re-scans — without an out-of-band retention sweep.

> **This whole file is the prompt — hand it to a Filigree agent/maintainer verbatim.** Self-contained: cites the exact Filigree source to reuse and gives acceptance criteria. File:line references are from a 2026-06-02 read of `/home/john/filigree`; verify against current source.

> **Supersedes the close half of ask #2** in `2026-06-02-filigree-ask-promote-by-fingerprint.md`. That brief asked for close "via the existing `unseen_in_latest` → clean-stale path" — and you implemented exactly that. The problem is on *our* side: Wardline drives reconciliation purely through `POST /api/loom/scan-results` and never calls `/findings/clean-stale`, so the close never fires from an agent's inner loop. This ask moves the close trigger to where the reopen trigger already lives: ingest itself. The **reopen** half of ask #2 is correct and needs no change.

---

## Context — what works today, and the exact gap

Verified in `src/filigree/db_files.py`:

- **Reopen-on-regress is wired into ingest and is immediate.** `process_scan_results` collects `regressed_issue_ids` during the write window (a finding whose stored status was `fixed`/`unseen_in_latest` that re-appears flips back to `open` — `db_files.py:1209-1210`) and, **post-commit**, reopens each linked issue via `_reopen_issue_for_regressed_finding` (`db_files.py:1447-1464`, gated on `_issue_last_closed_by_cascade` at `:1853` so a human's terminal decision is preserved). 

- **Close-on-fixed is NOT wired into ingest.** `_close_issue_for_fixed_finding` (`db_files.py:1822`) has exactly one caller — `clean_stale_findings`'s transaction body (`db_files.py:1973`, under `@_in_immediate_tx("clean_stale_findings")` at `:1902`). `clean_stale_findings` is invoked only by the `/findings/clean-stale` route, the `filigree finding clean-stale` CLI, and the admin command — **never by `process_scan_results`.**

- **The `mark_unseen` sweep already runs in ingest.** When Wardline POSTs scan-results with `mark_unseen=True`, `_mark_unseen_findings` (`db_files.py:1331-1350`) flips every previously-seen, non-terminal finding that is absent from this batch (within a `(file_id, scan_source)` present in the batch) to `unseen_in_latest`. So **ingest already knows, in-transaction, exactly which findings just went unseen** — it simply doesn't propagate that to their linked issues.

**Net effect today:** agent files a finding → issue opens; agent fixes the code, re-scans → the finding flips to `unseen_in_latest` **but the issue stays open**, because the only thing that closes it is an age-gated retention sweep the agent's loop never triggers. A2's headline DoD ("fix → issue auto-closes on re-scan") is therefore unmet.

---

## The ask — a close cascade symmetric to the existing reopen cascade

When a fingerprint-linked finding transitions to `unseen_in_latest` **during a scan-results ingest** (i.e. via the `mark_unseen` sweep), **close its linked issue in the same post-commit cascade that already handles reopen** — reusing `_close_issue_for_fixed_finding`, which already records the cascade-close actor (`CASCADE_ACTOR`, `db_files.py:74-76`) so the reopen path can later distinguish a cascade close from a human one.

Concretely (mirror the reopen wiring exactly):

1. **In the write window** (`_ingest_resolved_findings` / `_mark_unseen_findings`), collect the linked `issue_id`s of findings that this sweep flips `open`/`new` → `unseen_in_latest` *and that have a non-null `issue_id`*. Call it `resolved_issue_ids` (the symmetric twin of `regressed_issue_ids`). The UPDATE at `db_files.py:1344-1349` already selects exactly these rows — capture their `issue_id`s (e.g. a `RETURNING issue_id` or a pre-UPDATE SELECT of the same predicate).

2. **Post-commit** (right beside the reopen loop at `db_files.py:1447-1464`), for each `resolved_issue_ids`, call `_close_issue_for_fixed_finding(issue_id, warnings=...)` — best-effort, each in its own transaction, never failing the ingest; log a one-line cascade summary as the reopen path does.

3. **Respect terminal human decisions** — `_close_issue_for_fixed_finding` should not move an issue a human already set to a terminal/won't-fix state, exactly as `_reopen_issue_for_regressed_finding` is gated. (If the existing close helper doesn't already guard this, add the symmetric guard.)

### Why close on `unseen_in_latest`, not on `fixed`

`unseen_in_latest` means "absent from the latest authoritative scan of its file." That is precisely the agent-loop signal "the fix worked." It is **safely reversible**: if the finding reappears on a later scan, the existing regress path (`db_files.py:1209-1210` + `:1447-1464`) reopens the cascade-closed issue. So closing on first-unseen gives the immediate DoD the agent needs, and a false "fixed" (e.g. the agent only commented the code out, then reverts) self-heals via reopen.

This does **not** retire the clean-stale path — clean-stale still soft-archives stale `unseen_in_latest` findings to `fixed` for retention. After this change its `_close_issue_for_fixed_finding` call is simply idempotent (the issue is already closed). The two coexist: **ingest closes the issue eagerly; clean-stale archives the finding row eventually.**

### Wardline side (already shipped — no Filigree dependency)

Wardline already POSTs `mark_unseen=True` on non-empty scans (`core/filigree_emit.build_scan_results_body`; it sends `mark_unseen=False` on an empty batch because you correctly reject empty+`mark_unseen` at `db_files.py:1396-1399`). So the input to this cascade — findings entering `unseen_in_latest` during ingest — is already being produced. **No further Wardline change is needed once this lands.**

---

## Acceptance criteria (an oracle Wardline can run against a live Filigree)

Building on the ask #1/#2 oracle (`/api/loom/findings/promote` + scan-results), with **no `/findings/clean-stale` call anywhere in the test**:

1. **Close-on-fixed is immediate from ingest.** Ingest fingerprint F (open) → `POST /api/loom/findings/promote` (issue I open) → re-POST `/api/loom/scan-results` with `mark_unseen:true` and F **absent** (but the batch non-empty, ≥1 other finding in F's file or another file) → F is `unseen_in_latest` **AND issue I is closed/resolved**, with **no clean-stale invocation**.
2. **Reopen-on-regress still works (unchanged).** From state (1), re-POST scan-results **including** F → F flips to `open` AND issue I reopens (because it was cascade-closed).
3. **Terminal human state preserved.** An issue a human set to `false_positive`/`acknowledged`/won't-fix is **not** flipped closed by (1) nor reopened by (2).
4. **Idempotent with clean-stale.** Running `/findings/clean-stale` after (1) does not error and does not double-transition I (already closed); F is soft-archived to `fixed`.
5. **No spurious close.** A scan-results POST that re-includes all prior fingerprints (nothing went unseen) closes nothing.

Wardline's opt-in live oracle (`tests/e2e/test_filigree_promote_live.py`, marker `filigree_e2e`) will be extended to assert criteria 1–2 once this lands; today it covers file + idempotent-promote and skips cleanly until the routes exist.

---

## Notes / non-asks

- **No new route or payload.** This is purely internal wiring inside `process_scan_results`; the scan-results envelope is a frozen passthrough, so (like the reopen cascade) the close cascade is logged, not surfaced on the wire. Wardline doesn't need it echoed back.
- **No change to ask #1** (`/api/loom/findings/promote`) — it's correct as shipped.
- **Scope:** one cascade, symmetric to the one you already wrote. The cleanest framing is "do for `unseen_in_latest` what `process_scan_results` already does for the regress→`open` transition."

---

*Wardline contact artifact:* consuming code is `src/wardline/core/filigree_issue.py` + `src/wardline/core/filigree_emit.py` (the `mark_unseen` opt-in) and the A2 plan `docs/superpowers/plans/2026-06-02-wardline-ws-a2-file-finding.md`. If you choose a different transition point (e.g. close only on `fixed` via an ingest-time retention check rather than on first-unseen), tell us — the only thing Wardline asserts is criterion 1 (fix → issue closes on re-scan, with no separate sweep call).
