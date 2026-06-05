# Filigree close-on-fixed cascade — GAP-CLOSURE plan (ask #3 + #3b)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

> **STATUS — read first.** Ask #3 (close cascade) **and** #3b (sweep clean files via `scanned_paths`) were **already implemented in Filigree's working tree** (uncommitted, on top of HEAD `54cdd65`) by the Filigree session, in parallel with this review. This is **no longer a greenfield plan** — the bulk is done and the implementation is sound (it even nails the no-decoy headline test). This document covers only the **verified remaining gaps** found by the plan-review panel against the live code. Anchors verified 2026-06-05 against the modified working tree; re-check before editing.

**Goal:** Close the two correctness/coverage gaps in Filigree's already-landed close-on-fixed cascade so it never closes an issue that still has an unresolved finding, and prove the under-tested invariants.

> **HAND THIS TO THE FILIGREE SESSION — do not execute from another repo's session.** Filigree's working tree currently holds **broad uncommitted work beyond this feature** (`git status`: `CHANGELOG.md`, `db_base.py`, `db_entity_associations.py`, `doctor.py`, `detail.js`, `test_finding_triage.py`, a contract fixture). Editing it from a parallel session would collide with the owner, and a `git add -A` would sweep their unrelated work into these commits. Every commit step below stages **named files only**, and the owner runs them.
>
> **Scope note:** G3/G4 are coverage-only — the live code already behaves correctly (verified: `scan_source = ?` is in both the sweep UPDATE and the capture SELECT; `status != 'unseen_in_latest'` blocks re-capture). **G1 is the only behavior change in this plan, and it is new scope discovered in review** — it is NOT one of ask #3's original 1–5 acceptance criteria. It is a legitimate bug (an issue closed while a sibling finding is still open), but because it changes another session's working code, accepting it is the **Filigree owner's call**. G1 is verified safe against the existing suite: `test_mixed_file_closes_only_the_disappeared_finding` promotes its two findings to **separate** issues (test_finding_issue_cascade.py:318-319), so the guard does not block it.

## What Filigree already built (verified — do NOT re-implement)

- Route: `scanned_paths` parsed, type-checked, per-element non-empty-checked, and capped at `_MAX_SCANNED_PATHS_PER_REQUEST` (`dashboard_routes/files.py:266-285`).
- `process_scan_results(... scanned_paths: Sequence[str] = ())` (`db_files.py:1391`); empty-batch guard relaxed to `not findings and not scanned_paths` (`db_files.py:1435`).
- Clean-file union: `for path in scanned_paths: record = self.get_file_by_path(path); ... seen_finding_ids.setdefault(record.id, [])` (`db_files.py:1644-1648`). `get_file_by_path` normalizes via `_normalize_scan_path` internally — **path normalization is handled**.
- `_mark_unseen_findings` handles empty `fids` and captures `resolved` pairs (`db_files.py:1331+`, called with `resolved=resolved` at `:1655`).
- Post-commit close loop, mirroring reopen (`db_files.py:1525-1539`).
- Close-tx status guard already widened to `("fixed", "unseen_in_latest")` (`db_files.py:1938`); `== "done"` terminal-human guard intact (`db_files.py:1942`).
- Tests `TestCloseOnFixedFromIngest` (`tests/core/test_finding_issue_cascade.py:277-434`): no-decoy headline, mixed-file, reopen-after-close, terminal-human, idempotent-with-clean-stale, no-spurious-close, empty-batch-rejected, unknown-path-noop, close-failure-surfaced. **The no-decoy headline case is correct.**

## Verified remaining gaps

| Gap | Type | Evidence |
|-----|------|----------|
| **G1** Close-tx has no sibling-open-finding guard | Correctness | `_close_issue_for_fixed_finding_tx` (`db_files.py:1924-1955`) closes on the single finding's status alone. `scan_findings.issue_id` has no UNIQUE (`db_schema.py:150`); `update_finding(issue_id=…)` + the existing-issue promote path produce 1:N. An issue linked to F1 (resolved) and F2 (still open) is closed with F2 active. |
| **G2** No 1:N sibling test | Coverage | `TestCloseOnFixedFromIngest` has no two-findings-one-issue case. |
| **G3** No `scan_source` isolation test | Coverage | Sweep correctness rests solely on `AND scan_source = ?`; nothing pins it (a wardline clean scan must not close a codex-linked issue sharing a file). |
| **G4** No consecutive-clean idempotency test | Coverage | Two clean ingests in a row (the `status != 'unseen_in_latest'` capture guard should make the 2nd a no-op) is untested. |
| **G5** Clean-path lookup unbatched | Perf (minor) | `get_file_by_path` per path under the writer lock; bounded by the cap but O(N) round-trips. Optional. |

---

## Task 1: Add the sibling-open-finding guard (G1) — TDD via G2

**Files:**
- Test: `tests/core/test_finding_issue_cascade.py` (append to `TestCloseOnFixedFromIngest`)
- Modify: `src/filigree/db_files.py:1938-1943` (inside `_close_issue_for_fixed_finding_tx`)

- [ ] **Step 1: Write the failing test (G2)** — an issue linked to two findings; fixing one must NOT close it while the other is open.

```python
    def test_issue_with_open_sibling_finding_not_closed(self, db: FiligreeDB) -> None:
        f1 = _ingest(db, "fp-sib1")  # src/a.py
        db.process_scan_results(scan_source="wardline", findings=[_wln("src/c.py", "fp-sib2")])
        f2 = db.find_finding_by_fingerprint("wardline", "fp-sib2")["id"]
        issue = db.promote_finding_to_issue(f1, actor="t")["issue"]
        db.update_finding(f2, issue_id=issue.id)  # link the second finding to the SAME issue
        # Clean a.py (f1 disappears); c.py still carries f2.
        db.process_scan_results(
            scan_source="wardline",
            findings=[_wln("src/c.py", "fp-sib2")],
            mark_unseen=True,
            scanned_paths=["src/a.py", "src/c.py"],
        )
        assert db.get_finding(f1)["status"] == "unseen_in_latest"
        assert db.get_finding(f2)["status"] == "open"
        assert not _is_done(db, issue.id)  # MUST stay open — f2 is still active
```

(Verify `db.update_finding(finding_id, issue_id=…)` is the relink API — confirmed present at `db_files.py:1756` with an `issue_id` kwarg. If the kwarg name differs, use the actual relink call.)

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /home/john/filigree && uv run pytest tests/core/test_finding_issue_cascade.py::TestCloseOnFixedFromIngest::test_issue_with_open_sibling_finding_not_closed -v`
Expected: FAIL — `assert not _is_done(...)` is False (the issue is wrongly closed).

- [ ] **Step 3: Add the sibling guard** in `_close_issue_for_fixed_finding_tx`, after the `== "done"` guard (`db_files.py:1942-1943`), before `self.close_issue(...)`:

```python
        if self._resolve_status_category(issue.type, issue.status) == "done":
            return False  # already terminal (human or a prior cascade) — leave it
        # Do not close an issue that still has an unresolved finding linked to it.
        # scan_findings.issue_id has no UNIQUE (db_schema.py:150): one issue can
        # link many findings. Closing on a single resolved finding while a sibling
        # is still open would leave the issue closed with an active defect, and —
        # combined with the post-commit reopen→close ordering — could thrash. Only
        # close when EVERY linked finding is resolved.
        sibling = self.conn.execute(
            "SELECT 1 FROM scan_findings WHERE issue_id = ? AND id != ? "
            "AND status NOT IN ('fixed', 'false_positive', 'unseen_in_latest') LIMIT 1",
            (issue_id, finding_id),
        ).fetchone()
        if sibling is not None:
            return False
```

This is strictly more conservative and applies to both callers (ingest close and clean-stale close) — a correctness improvement for each.

- [ ] **Step 4: Add the cheap same-batch fast-path** in the post-commit close loop (`db_files.py:1526-1530`) so a finding that regressed *and* resolved in one batch never even attempts the close (the sibling guard also covers it, but this avoids a spurious warning):

```python
        closed_issue_ids = [
            issue_id
            for finding_id, issue_id in sorted(resolved)
            if issue_id not in regressed_issue_ids
            and self._close_issue_for_fixed_finding(finding_id, issue_id, warnings=stats["warnings"])
        ]
```

- [ ] **Step 5: Run the test + the full cascade suite**

Run: `cd /home/john/filigree && uv run pytest tests/core/test_finding_issue_cascade.py -v`
Expected: the new test PASSES; all pre-existing cascade tests still PASS (the guard only blocks closes that should not happen — `test_clean_stale_closes_linked_issue` and the no-decoy headline use single-finding issues, so they still close).

- [ ] **Step 6: Commit**

```bash
# Owner runs this — stage ONLY the cascade files (the tree has unrelated WIP).
git add src/filigree/db_files.py tests/core/test_finding_issue_cascade.py
git commit -m "fix(cascade): never cascade-close an issue with an unresolved sibling finding"
```

---

## Task 2: Pin scan_source isolation and consecutive-clean idempotency (G3, G4)

**Files:**
- Test: `tests/core/test_finding_issue_cascade.py` (append to `TestCloseOnFixedFromIngest`)

- [ ] **Step 1: Write both tests**

```python
    def test_clean_scan_does_not_close_other_scan_source_issue(self, db: FiligreeDB) -> None:
        db.process_scan_results(scan_source="codex", findings=[_wln("src/a.py", "fp-codex")])
        codex = db.find_finding_by_fingerprint("codex", "fp-codex")
        assert codex is not None
        codex_issue = db.promote_finding_to_issue(codex["id"], actor="t")["issue"]
        # Wardline clean scan of the SAME file src/a.py.
        db.process_scan_results(
            scan_source="wardline", findings=[_wln("src/b.py", "fp-wo")],
            mark_unseen=True, scanned_paths=["src/a.py", "src/b.py"],
        )
        assert db.get_finding(codex["id"])["status"] == "open"  # wardline sweep must not touch codex
        assert not _is_done(db, codex_issue.id)

    def test_consecutive_clean_scans_idempotent(self, db: FiligreeDB) -> None:
        finding_id = _ingest(db, "fp-idem")
        issue = db.promote_finding_to_issue(finding_id, actor="t")["issue"]
        body = dict(scan_source="wardline", findings=[], scanned_paths=["src/a.py"], mark_unseen=True)
        db.process_scan_results(**body)
        assert _is_done(db, issue.id)
        stats2 = db.process_scan_results(**body)  # 2nd clean scan: no re-fire, no error
        assert _is_done(db, issue.id)
        assert [w for w in stats2["warnings"] if "close cascade" in w] == []
```

- [ ] **Step 2: Run them**

Run: `cd /home/john/filigree && uv run pytest tests/core/test_finding_issue_cascade.py::TestCloseOnFixedFromIngest -k "other_scan_source or consecutive" -v`
Expected: PASS as written (the live code already filters by `scan_source` and guards re-capture with `status != 'unseen_in_latest'`). If either FAILS, that is a second real defect — stop and investigate before proceeding.

- [ ] **Step 3: Commit**

```bash
# Owner runs this — stage ONLY the test file.
git add tests/core/test_finding_issue_cascade.py
git commit -m "test(cascade): pin scan_source isolation and consecutive-clean idempotency"
```

---

## Task 3 (OPTIONAL — G5): Batch the clean-path lookup

Only do this if a large-repo scan (tens of thousands of `scanned_paths`) is a real workload; the cap bounds the worst case. Replace the per-path `get_file_by_path` loop (`db_files.py:1644-1648`) with a chunked query, applying the same normalization `get_file_by_path` uses:

- [ ] **Step 1:** Replace the loop:

```python
            from filigree.db_files import _normalize_scan_path  # already module-level; use directly
            norm = list(dict.fromkeys(
                np for np in (_normalize_scan_path(p) for p in scanned_paths) if np
            ))
            CHUNK = 500
            for i in range(0, len(norm), CHUNK):
                chunk = norm[i : i + CHUNK]
                ph = ",".join("?" * len(chunk))
                for row in self.conn.execute(
                    f"SELECT id FROM file_records WHERE path IN ({ph})", chunk
                ).fetchall():
                    seen_finding_ids.setdefault(row["id"], [])
```

- [ ] **Step 2:** Run `tests/core/test_finding_issue_cascade.py` — all green; **Step 3:** commit.

---

## Task 4: Verification gate

- [ ] **Step 1:** `cd /home/john/filigree && uv run pytest tests/core/test_finding_issue_cascade.py tests/core/test_scans.py tests/api/test_files_dashboard.py --tb=short` → PASS
- [ ] **Step 2:** `cd /home/john/filigree && uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/ && uv run mypy src/filigree/` → clean
- [ ] **Step 3:** `cd /home/john/filigree && uv run pytest --tb=short` → PASS
- [ ] **Step 4 (the real DoD — Wardline side, tracked by `wardline-7a56cd1b83`, NOT this plan):** restart the dashboard on the new build, then `cd /home/john/wardline && WARDLINE_FILIGREE_URL=http://localhost:8628/api/loom/scan-results uv run pytest -m filigree_e2e -v`. Do not commit/close the Filigree work until this and the Filigree suite are green.

## Notes / non-asks

- Do not re-implement Tasks the working tree already has (see "What Filigree already built").
- `clean_stale_findings` stays; its close now also benefits from the sibling guard (Task 1).
- No Wardline change. The Wardline oracle extension + closing `wardline-7a56cd1b83` is downstream, once this Filigree build runs.
