# Filigree ask — HTTP promote-by-fingerprint + finding→issue cascade (for Wardline A2)

**Date:** 2026-06-02
**From:** Wardline (Loom analyzer) · **To:** whoever owns Filigree
**Status:** Request brief. Two changes Wardline needs to ship `file_finding` (Workstream A2 of the frictionless-agent-surface spec). The Wardline side is already built and unit-green against a fake transport; it is gated on these.

> **This whole file is the prompt — hand it to a Filigree agent/maintainer verbatim.** It is self-contained: it cites the exact Filigree source to reuse and gives acceptance criteria. File:line references are from a 2026-06-02 read of `/home/john/filigree`; verify against current source.

---

## Context (why Wardline is asking)

A senior coding agent driving Wardline wants one call to turn a single true-positive finding into a tracked Filigree issue, and have that issue auto-close when the finding is fixed / reopen if it regresses — keyed on Wardline's stable **fingerprint** (a sha256). Wardline talks to Filigree **only over HTTP via stdlib urllib** — it imports no Filigree package and does not shell out to the `filigree` CLI. So everything Wardline needs must be an HTTP route.

What already works well in Filigree today (no change needed — context for the asks):
- The scan-results intake `_upsert_finding` (`db_files.py:1126`) reconciles **finding rows** by `(scan_source, fingerprint)` idempotently (`db_files.py:1162-1165`): re-POST of a known fingerprint UPDATEs, never duplicates.
- **Reopen-on-regress at the finding-row level** is automatic (`db_files.py:1290`: a re-seen `fixed`/`unseen_in_latest` finding flips back to `open`).
- `promote_finding_to_issue` (`db_files.py:2025`) is **already idempotent**: if the finding already links an issue (or an issue with `fields.source_finding_id == finding_id` exists), it returns that issue instead of creating a duplicate (`db_files.py:2050-2071`).

The two gaps below are what's missing.

---

## Ask #1 — HTTP promote-by-fingerprint, returning the issue id (idempotent)

**Gap:** `promote_finding_to_issue` exists and is idempotent, but it's exposed only as the MCP tool `promote_finding` / CLI `filigree finding promote` and is keyed by **`finding_id`**. There is **no HTTP route** and **no fingerprint lookup** (`list_findings_global` filters are severity/status/scan_source/scan_run_id/file_id/issue_id only — no fingerprint). An HTTP caller holding a fingerprint cannot get an issue.

**Request:** add a Loom HTTP route:

```
POST /api/loom/findings/promote
Content-Type: application/json

Request body:
  {
    "scan_source": "wardline",        // required; bounds the fingerprint lookup
    "fingerprint": "<sha256 hex>",    // required
    "priority": "P2",                 // optional; applied to a newly-created issue
    "labels": ["security"]            // optional
  }

Response 200 (created or already-linked):
  { "issue_id": "<id>", "created": true|false }

Response 404 (no finding with that (scan_source, fingerprint)):
  { "error": "no finding for fingerprint", "code": "NOT_FOUND" }
```

**Implementation:** this is a thin wrapper — resolve `(scan_source, fingerprint)` → `finding_id` (add a fingerprint filter to the finding lookup, or a small dedicated query), then call the existing idempotent `promote_finding_to_issue(finding_id, ...)`. Apply `priority`/`labels` to the issue on first creation. `created` reflects whether a new issue was made vs an existing link returned.

**Why it must be HTTP and fingerprint-keyed:** Wardline only knows the fingerprint (its own stable identity) and only speaks HTTP. The scan-results response's `succeeded` list returns only **newly-created** finding ids (`adapters.py:351`), so even right after emitting, Wardline cannot map an *updated/existing* fingerprint to its finding_id. Without this route, A2 is impossible over Wardline's transport.

**Error model:** please use Filigree's existing `ErrorCode` discipline (`VALIDATION` for a missing/blank fingerprint or scan_source; `NOT_FOUND` for an unknown fingerprint). Wardline treats 404 as a soft "not_found" (the agent should emit findings first), a 5xx as a soft outage, and any other 4xx as a loud "Wardline sent a bad payload."

---

## Ask #2 — finding→issue status cascade (close-on-fixed / reopen-on-regress)

**Gap (the load-bearing one):** **no finding-status transition touches the linked issue's status.** Verified: the only triggers on `issues` are FTS-index sync (`db_schema.py:115-123`); `_cascade_dismiss_observations_for_finding` (`db_files.py:1744`) touches only observations. `promote_finding_to_issue` sets up the `scan_findings.issue_id` link, but nothing re-reads it to move the issue when the finding later changes. So an agent files an issue, fixes the code, re-scans — the finding row goes `fixed`, but the **filed issue stays open forever**.

**Request:** when a fingerprint-linked finding transitions status, cascade to its linked issue:
- finding → `fixed` (via the existing `unseen_in_latest` → clean-stale path): **close/resolve the linked issue**.
- finding regresses `fixed`/`unseen_in_latest` → `open` (the existing `db_files.py:1290` flip): **reopen the linked issue**.
- **Respect terminal human decisions:** do NOT reopen/close an issue a human set to a terminal state (mirror how the finding upsert preserves `false_positive`/`acknowledged` at `db_files.py:1290`). If the issue was manually closed as won't-fix, a regressed finding should not silently reopen it (or should, but via a distinguishable transition you choose — your call; please just make it intentional, not accidental).

**Why:** this is literally A2's "close when fixed / reopen on regress." Ask #1 files the issue; ask #2 keeps it honest as the code changes. The finding-row machinery for both directions already exists — this is wiring its transitions through the `issue_id` link to the issue's own status.

**Wardline-side precondition (already in Wardline's A2 plan, not your work):** Wardline will start sending `mark_unseen=True` on its scan-results POST so absent fingerprints enter `unseen_in_latest` (the input to the close path). The param already exists and defaults False (`dashboard_routes/files.py:125`), so this is backward-compatible — no Filigree change needed for it, just noting the interplay.

---

## Acceptance criteria (an oracle Wardline can run against a live Filigree)

1. **Promote returns an id.** `POST /api/loom/findings/promote {scan_source:"wardline", fingerprint:F}` for an ingested fingerprint F returns `200 {issue_id, created:true}` on first call.
2. **Idempotent.** A second identical POST returns `200 {issue_id:<same>, created:false}` — no duplicate issue.
3. **Unknown fingerprint.** A POST for a fingerprint never ingested under that scan_source returns `404 {code:"NOT_FOUND"}`.
4. **Close-on-fixed cascades.** Ingest F (open) → promote (issue open) → re-POST scan-results with `mark_unseen:true` and F absent → run clean-stale → the finding is `fixed` AND **its linked issue is closed/resolved**.
5. **Reopen-on-regress cascades.** From state (4), re-POST scan-results including F again → the finding flips to `open` AND **its linked issue reopens** (unless the issue is in a terminal human state).
6. **Terminal human state preserved.** An issue manually set `false_positive`/`acknowledged` (or your won't-fix terminal) is not silently flipped by (4)/(5).

Wardline ships a matching opt-in live test (`tests/e2e/test_filigree_promote_live.py`, marker `filigree_e2e`) that probes `/api/loom/findings/promote` and skips cleanly until it exists — so landing ask #1 turns that test green, and ask #2 lets us extend it to assert the cascade.

---

## Notes / non-asks

- **SEI:** not required for this. A2 keys on Wardline's fingerprint, not on a Clarion SEI. (If you'd rather key the issue's `fields` on SEI too for the dossier story, that's additive and welcome, but not on the A2 critical path.)
- **No new auth scheme needed** beyond whatever the existing Loom routes use; Wardline's emitter already posts to `/api/loom/scan-results` unauthenticated-or-as-configured today.
- **Scope:** Wardline is not asking for a bulk promote or a query-by-fingerprint *list* route — just the single idempotent promote in ask #1 and the cascade in ask #2. A `fingerprint` filter on `GET /api/loom/findings` would be a nice-to-have (it would let Wardline confirm an issue link without re-promoting), but it's optional.

---

*Wardline contact artifact:* the consuming code is `src/wardline/core/filigree_issue.py` (the `FiligreeIssueFiler` + `promote_url_from_loom`) and the A2 plan `docs/superpowers/plans/2026-06-02-wardline-ws-a2-file-finding.md` §1. If your final route/payload shape differs from the contract above, tell us the deltas and we'll adjust the filer's response parser — only that one file changes.
