# Plan Review: CHANGES_REQUESTED

**Plan:** `docs/superpowers/plans/2026-04-12-wardline-site-restructure.md`
**Reviewed:** 2026-04-12
**Reviewers:** Reality, Architecture, Quality, Systems, Synthesizer

## Verdict

**CHANGES_REQUESTED** — Do not execute as written. The plan is architecturally sound and the overall approach is correct, but it contains factual errors and collides with active in-progress work. Five blockers must be fixed before green-lighting execution; none are deep rewrites.

---

## Blockers

### B1. Hub page content for §13 is fabricated
Plan lines 1001–1010 claim §13 has "ten residual risks" with names like "Dynamic import taint opacity, Reflection, C-extensions." Actual §13 has **17 risks** with completely different names (Declaration correctness, Governance decay, Serialisation boundary blindness, etc.).

**Fix:** Re-derive the §13 hub summary from the actual chapter. Audit every hub page that enumerates spec content.

### B2. Hallucinated anchor fragments throughout hub pages
Hub pages link to `#wl-001`, `#phase-1`, `#retention`, `#effective-states`, `#golden-corpus`, `#formal-properties`. Actual spec uses numeric-prefixed slugs (`#821-structural-guarantee-defaults-and-wl-001`, `#### 15.1`). §13 has no subsections at all. `mkdocs --strict` does **not** validate inline fragment anchors — these silently 404.

**Fix:** Enumerate actual anchors from each referenced chapter. Add lychee or linkchecker to the Phase 3 validation gate.

### B3. Active work collision
Two problems, one root cause:
- `docs/verification/2026-04-12-v1-0-compliance-ledger.md` is the output of the currently in-progress P1 issue `wardline-fae28f1be3`. Not in preserve list. Phase 2 orphans or destroys it.
- Phase 6 adds frontmatter to all 20 spec chapters. Current git diff shows unstaged edits to `docs/spec/wardline-01-15-conformance.md` and six `requirements/spec-fitness/*.yaml` files. 27 ready P1 tasks touch `wardline-01-11-*` and `wardline-01-15-*`. Guaranteed merge conflicts.

**Fix:** Add `docs/verification/**` and `docs/superpowers/**` to an explicit preserve allowlist. Sequence Phase 6 after the obligation-ledger issue closes. This is dependency sequencing, not deferral.

### B4. CLI and nav errors
- `requirements/spec-fitness/` used as a nav entry with no `index.md` → `--strict` build failure in Phase 4.
- `wardline preview` documented as a subcommand — it is a **flag on `scan`**, not a command.
- `wardline project` exists but is omitted from the quick reference.

**Fix:** Add `index.md` stub (or drop nav entry). Run `wardline --help` on every subcommand and reconcile the quick reference against actual output.

### B5. `overrides/main.html` clobber destroys RC announcement banner
Task 6.1 provides a complete `main.html` replacement with no `{% block announce %}`, despite prose saying "preserve existing." The current file carries the v1.0 RC announcement banner.

**Fix:** Read current `overrides/main.html` first. Merge new blocks rather than replace. Preserve `{% block announce %}` verbatim.

---

## Concerns (should fix, not blocking)

### C1. `follow_links` / mkdocs symlink behavior — verify empirically
Quality reviewer asserted mkdocs 1.6 does not follow symlinks by default. This varies across versions. **Do not accept at face value.** Before Phase 1 Step 4, run a 30-second empirical test: create one symlink under `site-src/`, run `mkdocs build --strict`, observe.

### C2. `edit_uri` for symlinked pages unresolved
All four reviewers flagged this. Plan defers to "test and adjust." Deterministic fix: either rewrite edit URL for symlinked content in `main.html`, or set `hide: [edit]` on symlinked chapters. Pick one before execution.

### C3. Phase 3 `--strict` bypass has no re-enable gate
Plan disables `--strict` mid-phase without a concrete trigger for re-enabling it. Session interrupt → silent persistence.

**Fix:** Re-enable `--strict` as the last step of Phase 3; make it a Phase 3 exit criterion. Add linkchecker pass here.

### C4. Working tree is dirty — no pre-flight check
Plan starts destructive operations (`git rm -r docs/archive`) with 12 modified files and 5 untracked paths already present. Three untracked files are today-dated adjudications under `docs/archive/reviews/` that will be stranded mid-phase.

**Fix:** Add Phase 0 pre-flight: working tree must be clean OR every dirty path explicitly tracked. Commit or relocate the three `2026-04-12-*.md` adjudication files before Phase 2.

### C5. Audits hub link path unverified
Task 3.4 Step 6 links to `../../audits/rule-conformance-audit-2026-03-25.md`. Actual audit file may live under `docs/archive/reviews/`.

---

## Recommended Pre-Execution Action List

Apply in order, then re-run `/review-plan`:

1. Re-derive §13 hub content from actual chapter. (B1)
2. Audit every inline anchor fragment against actual chapter headings. Add lychee/linkchecker to Phase 3. (B2, C3)
3. Add preserve allowlist to Phase 2: `docs/verification/**`, `docs/superpowers/**`, the three `docs/archive/reviews/2026-04-12-*.md` files. (B3, C4)
4. **Ask user:** re-sequence Phase 6 after `wardline-fae28f1be3` closes, or split frontmatter work across affected chapters? This is a dependency question. (B3)
5. Fix CLI quick reference: add `requirements/spec-fitness/index.md`, remove `wardline preview` as a command, add `wardline project`. Reconcile against live `--help`. (B4)
6. Merge-don't-replace `overrides/main.html`. Preserve `{% block announce %}`. (B5)
7. Run the mkdocs symlink test empirically. Document actual result. (C1)
8. Pick an `edit_uri` strategy and commit it in the plan text. (C2)
9. Add Phase 0 pre-flight for clean working tree. (C4)
10. Verify the audits hub file path exists where the hub page links to. (C5)

---

## Reviewer Summary

| Reviewer     | Verdict             | Blocking       | Warnings |
|--------------|---------------------|----------------|----------|
| Reality      | Issues found        | 4              | 4        |
| Architecture | Pass with concerns  | 0              | 3        |
| Quality      | Issues found        | 4 (1 downgraded) | 13     |
| Systems      | Issues found        | 2              | 9        |

**Net:** 5 consolidated blockers, 5 consolidated concerns.

No reviewer disputed the plan's overall shape — symlink-based split, content-before-nav ordering, and scope are all endorsed by Architecture. Failures are factual (hallucinated content, wrong anchors, wrong CLI surface) and coordination (active work collision, dirty tree). All fixable in under an hour of plan edits plus one empirical mkdocs test.

**Go/no-go:** **No-go as written. Go after items 1–10 above.** Item 4 (Phase 6 sequencing) needs your decision before re-review.
