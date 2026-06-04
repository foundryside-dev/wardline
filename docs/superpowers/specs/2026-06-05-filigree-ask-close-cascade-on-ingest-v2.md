# Filigree ask #3 (v2) — close-on-fixed cascade *during scan-results ingest*

**Date:** 2026-06-05 · **From:** Wardline (Loom analyzer) · **To:** whoever owns Filigree
**Status:** Request brief. One change so Wardline's `file_finding` (A2) *closes* a tracked
issue when the agent fixes the code and re-scans — without an out-of-band retention sweep.

> **This whole file is the prompt — hand it to a Filigree agent/maintainer verbatim.**
> Self-contained. All `file:line` references verified against `/home/john/filigree` at
> **HEAD `54cdd65` (v2.3.0)** on 2026-06-05. Re-verify against current source before editing.

> **Supersedes** `2026-06-02-filigree-ask-close-cascade-on-ingest.md`. That brief told you to
> "reuse `_close_issue_for_fixed_finding`" — which is right in spirit but **silently no-ops as
> written** (see ⚠️ below). Asks #1/#2 (`/api/loom/findings/promote`) are **already shipped and
> live** in 2.3.0.

> ## ⚠️ PREREQUISITE — ask #3b: the sweep must be driven by `scanned_paths`, not by findings
>
> **Ask #3 (close cascade) does not deliver the DoD on its own.** Verified 2026-06-05: the
> `mark_unseen` sweep (`_mark_unseen_findings`, `db_files.py:1335`) iterates `seen_finding_ids`
> — **only files that still have ≥1 finding in the batch**. When an agent fixes the last/only
> finding in a file, that file goes clean → it has zero findings in the batch → it is **never
> swept** → its prior finding stays `open` → the close cascade has nothing to fire on.
>
> Wardline already sends the authoritative scanned-file set as **`scanned_paths`** (full set
> incl. clean files — `core/run.py:226`), and sets `mark_unseen = bool(findings or scanned)`.
> **Filigree silently drops it:** the loom scan-results validator extracts 6 fields and not
> `scanned_paths` (`dashboard_routes/files.py:265-272`); `grep scanned_paths filigree/src` =
> **zero hits**. So the clean-file→unseen contract is unilateral — Wardline emits it, Filigree
> has never consumed it (Wardline's own tests only assert what it *sends*, never the round-trip).
>
> **Required (ships with #3, two separable changes both needed):**
> 1. **Extract `scanned_paths`** in the loom route validator (list[str], optional) and thread it
>    into `process_scan_results` → `_ingest_resolved_findings` → `_mark_unseen_findings`.
> 2. **Drive the sweep off the union** of {files with findings in batch} ∪ {`scanned_paths`}.
>    For a clean scanned path its seen-set is empty, so *all* its prior non-terminal findings go
>    `unseen_in_latest`. Resolve clean paths by **lookup, not upsert** — an unknown clean path
>    has nothing to sweep, so **skip it, don't error**.
> 3. **Relax the empty-batch guard** at `db_files.py:1390-1392` so `mark_unseen=True` with
>    `findings=[]` but non-empty `scanned_paths` sweeps instead of rejecting (a fully-clean scan).
>    The guard's own message — "an empty batch cannot identify which (file, scan_source) pairs to
>    sweep" — is exactly the assumption `scanned_paths` removes.
>
> Only once the sweep visits clean files does the close cascade below have a candidate to close.
> **Do not gate close-on-fixed acceptance on a same-file decoy finding** — that masks this gap.

---

## The gap (verified in current source)

- **Reopen-on-regress is wired into ingest.** `process_scan_results`'s write window
  (`_ingest_resolved_findings`) collects `regressed_issue_ids` (a finding whose stored status
  was `fixed`/`unseen_in_latest` that re-appears flips back to `open`), and **post-commit**
  reopens each linked issue via `_reopen_issue_for_regressed_finding`
  (`db_files.py:1450-1464`), gated on `_issue_last_closed_by_cascade` so a human's terminal
  decision is preserved.

- **Close-on-fixed is NOT wired into ingest.** `_close_issue_for_fixed_finding`
  (`db_files.py:1825`) has exactly one caller — `clean_stale_findings` (`db_files.py:1958`),
  the age-gated `/findings/clean-stale` retention sweep. **Wardline never calls clean-stale**;
  its inner loop drives everything through `POST /api/loom/scan-results`.

- **The `mark_unseen` sweep already runs in ingest.** When Wardline POSTs `mark_unseen=True`,
  `_mark_unseen_findings` (`db_files.py:1323-1343`, a `@staticmethod`) flips every previously
  seen, non-terminal finding absent from this batch (within a present `(file_id, scan_source)`)
  to `unseen_in_latest`. **Ingest already knows, in-transaction, exactly which findings just
  went unseen — it just doesn't propagate that to their linked issues.**

**Net effect:** agent files finding → issue opens; agent fixes code, re-scans → finding flips
to `unseen_in_latest` **but the issue stays open**. A2's headline DoD ("fix → issue auto-closes
on re-scan") is unmet. (Confirmed live 2026-06-05: clean scan ingested, linked issue left open.)

---

## The ask — a close cascade symmetric to the existing reopen cascade

When a fingerprint-linked finding transitions to `unseen_in_latest` **during ingest** (via the
`mark_unseen` sweep), **close its linked issue in the same post-commit cascade that already
handles reopen.** Mirror the reopen wiring exactly:

### 1. Capture the resolved findings in the write window

`_mark_unseen_findings` (`db_files.py:1323`) currently does a blind per-file `UPDATE … SET
status='unseen_in_latest'` and returns `None`. Thread a mutable `resolved: set[tuple[str, str]]`
through it (symmetric to how `regressed_issue_ids: set[str]` is threaded into
`_ingest_resolved_findings` and **cleared on entry** at `db_files.py:1528`). For each file,
**before** the UPDATE, SELECT the `(id, issue_id)` of rows that are about to genuinely
transition — i.e. rows whose **prior** status is a live, un-resolved state:

```sql
SELECT id, issue_id FROM scan_findings
WHERE file_id = ? AND scan_source = ? AND issue_id IS NOT NULL
  AND status NOT IN (<terminal>)          -- same terminal set the UPDATE already excludes
  AND status != 'unseen_in_latest'        -- only fire on a real open/new → unseen transition
  AND id NOT IN (<seen ids for this file>)
```

Collect each `(finding_id, issue_id)` into `resolved`. (Capturing pairs — not just `issue_id` —
matters; see ⚠️.) Then run the existing UPDATE unchanged.

> Restricting to prior-status `open`/`new` (not already `unseen_in_latest`) satisfies
> acceptance criterion 5 (a re-scan that re-includes everything resolves nothing → closes
> nothing) and mirrors the reopen path firing only on a genuine transition.

### 2. ⚠️ Widen the close-tx status guard — the part the v1 brief missed

`_close_issue_for_fixed_finding_tx` (`db_files.py:1842-1847`) re-reads the finding under the
writer lock and bails unless it's still `fixed`:

```python
finding = self.conn.execute(
    "SELECT status FROM scan_findings WHERE id = ? AND issue_id = ?", (finding_id, issue_id)
).fetchone()
if finding is None or finding["status"] != "fixed":   # ← unseen_in_latest fails this → no-op
    return False
```

This is the post-commit race guard ("if ingest reopened the finding after the sweep, observe
`open` and skip"). Its semantics generalize cleanly — **widen the accepted set to both resolved
states:**

```python
if finding is None or finding["status"] not in ("fixed", "unseen_in_latest"):
    return False
```

This keeps the race guard intact for **both** callers (clean-stale finding is `fixed`; ingest
finding is `unseen_in_latest`; either reopened to `open` → still correctly skipped). **Without
this change the new cascade compiles, runs, logs nothing, and closes nothing.**

### 3. Close post-commit, beside the reopen loop

Right after the reopen loop (`db_files.py:1450-1464`), add the symmetric loop:

```python
closed_issue_ids = [
    issue_id
    for finding_id, issue_id in sorted(resolved)
    if self._close_issue_for_fixed_finding(finding_id, issue_id, warnings=stats["warnings"])
]
```

`_close_issue_for_fixed_finding` already: stamps the close with `FINDING_CASCADE_MARKER` (so the
regress path can later reopen it), skips issues already in a `done` category
(`db_files.py:1850` — terminal human/cascade decisions preserved), runs in its own
`BEGIN IMMEDIATE` (best-effort, never fails ingest), and records reconciliation-debt on failure.
Log a one-line cascade summary as the reopen path does (`db_files.py:1456-1464`).

---

## Why close on `unseen_in_latest`, not on `fixed`

`unseen_in_latest` = "absent from the latest authoritative scan of its file" = the agent-loop
signal "the fix worked." It's **safely reversible**: if the finding reappears, the existing
regress path reopens the cascade-closed issue. This does **not** retire clean-stale — that still
archives stale `unseen_in_latest` rows to `fixed` for retention; after this change its
`_close_issue_for_fixed_finding` call is simply idempotent (the issue is already `done`, so the
`== "done"` guard returns `False`). **Ingest closes eagerly; clean-stale archives eventually.**

---

## Acceptance criteria (oracle Wardline runs against live Filigree, **no clean-stale call**)

1. **Close-on-fixed for a file that goes clean (HEADLINE — no decoy).** Ingest fingerprint F in
   `a.py` (the only finding there) → promote (issue I open) → re-POST scan-results with
   `mark_unseen:true`, **F absent and `a.py` carrying NO finding**, `a.py` present only in
   `scanned_paths` (batch may be fully empty findings, or carry findings for *other* files) → F
   is `unseen_in_latest` **AND I is closed**, no `/findings/clean-stale` call. *This is the case
   ask #3b exists for; it must pass without a same-file decoy.*
1b. **Close-on-fixed in a multi-finding file.** F and sibling G both in `a.py` → fix F, re-POST
   with G still present → F `unseen_in_latest` AND I closed (covers the seen_finding_ids path).
2. **Reopen-on-regress still works.** From (1), re-POST including F → F → `open` AND I reopens
   (it was cascade-closed, so `_issue_last_closed_by_cascade` is true).
3. **Terminal human decision preserved.** An issue a human moved to a `done`-category state is
   not reopened by (2); a finding's linked issue already `done` is not re-closed by (1). (Matches
   existing clean-stale semantics — the `== "done"` guard is the authority.)
4. **Idempotent with clean-stale.** Running `/findings/clean-stale` after (1) does not error and
   does not double-transition I; F is soft-archived to `fixed`.
5. **No spurious close.** A scan-results POST re-including all prior fingerprints closes nothing.

Wardline's opt-in live oracle (`tests/e2e/test_filigree_promote_live.py`, marker `filigree_e2e`)
will be extended to assert criteria 1–2 once this lands.

## Non-asks

- **No new route or payload.** Purely internal wiring inside `process_scan_results`; the
  scan-results envelope is a frozen passthrough, so (like reopen) the close cascade is logged,
  not surfaced on the wire.
- **No change to asks #1/#2** — correct as shipped in 2.3.0.
- **No Wardline change** — Wardline already POSTs `mark_unseen=True` on non-empty scans.

*Wardline contact artifact:* `src/wardline/core/filigree_emit.py` (`mark_unseen` opt-in) +
`src/wardline/core/filigree_issue.py`. The only thing Wardline asserts is criterion 1.
