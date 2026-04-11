# Wardline.dev Site Move — Implementation Plan (Plan A)

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move the wardline.dev website source out of `docs/` into a new `site-src/` directory, leaving `docs/` as a pure authoritative-content store. **Move only.** No nav rewrite, no new hub content, no cross-link protocol, no template work, no deletions.

**Why split from the larger plan:** The full site restructure (`2026-04-12-wardline-site-restructure.md`) collides with active v1.0 recertification work — seven P1 spec-edit tasks touch the same files Phase 6 adds frontmatter to, and the obligation-ledger issue (`wardline-fae28f1be3`) is actively producing `docs/verification/` output. This plan does the structural move **now** (low risk, no content edits), and the content restructure work waits until cert closes.

**Architecture:** Two-directory split via symlinks. `docs/` retains only authoritative source material. New `site-src/` holds website source (homepage, reference, guides, stylesheets, javascripts, assets, overrides). Five symlinks inside `site-src/` expose authoritative directories to mkdocs at stable URL paths.

**Tech stack:** mkdocs Material 1.6.1 (verified empirically to follow symlinks). No new dependencies. No runtime code changes.

**Scope — what this plan does NOT do (deferred to Plan B, post-cert):**

- No deletions (`docs/archive/`, `docs/design/`, `docs/plans/`, `docs/verification/*PROMPT*` — stay put)
- No new hub content (specification landing page, Quick Reference, conformance-roadmap, assurance section)
- No nav rewrite in `mkdocs.yml`
- No cross-link protocol (authority banners, prerequisites boxes, ADR admonitions, §8 ↔ semantic-equivalents links)
- No spec chapter frontmatter
- No template override (`main.html` stays as-is except for path relocation)
- No home page rewrite
- No `site_description` rewrite

The existing nav and all existing URLs remain unchanged after this plan. Users see no difference.

---

## Baseline facts (verified empirically before writing this plan)

1. **mkdocs 1.6.1 follows directory symlinks inside `docs_dir`.** Verified with a throwaway build at `/tmp/mkdocs-symlink-test/`. No `follow_links` flag exists or is needed.
2. **Current build does NOT pass `--strict`.** There are 33 pre-existing warnings, 18 of them from `spec/wardline-01-00-front-matter.md` (broken TOC anchors). These are unrelated to the move and should be fixed separately. This plan uses `mkdocs build` (non-strict) with a **baseline-diff gate**: no new warnings introduced.
3. **`edit_uri` and symlinks.** mkdocs generates edit URLs from the symlink path, not the underlying path. Setting `edit_uri: edit/main/docs/` would break homepage/reference/guides (real path `site-src/...`, would get `edit/main/docs/...`). Setting `edit_uri: edit/main/site-src/` would break spec/ADR/audits (real path `docs/spec/...`, would get `edit/main/site-src/spec/...` via symlink). **There is no single `edit_uri` value that works for both content surfaces.** This plan removes `edit_uri` entirely — edit buttons disappear during the transition. Plan B restores them via a template override or `hide: [edit]` frontmatter.
4. **Working tree is dirty.** `git status` at plan-write time shows 12 modified files and 5 untracked paths. Phase 0 handles this.

---

## File Structure

### Moved (renamed via `git mv`)

| From | To |
|---|---|
| `docs/index.md` | `site-src/index.md` |
| `docs/getting-started.md` | `site-src/getting-started.md` |
| `docs/specification.md` | `site-src/specification.md` |
| `docs/reference/` (11 files) | `site-src/reference/` |
| `docs/guides/` (6 files) | `site-src/guides/` |
| `docs/stylesheets/` | `site-src/stylesheets/` |
| `docs/javascripts/` | `site-src/javascripts/` |
| `docs/assets/` | `site-src/assets/` |
| `overrides/` (repo root) | `site-src/overrides/` |

### Created (symlinks)

| Symlink | Target |
|---|---|
| `site-src/spec` | `../docs/spec` |
| `site-src/adr` | `../docs/adr` |
| `site-src/audits` | `../docs/audits` |
| `site-src/verification` | `../docs/verification` |
| `site-src/requirements` | `../docs/requirements` |

### Modified

- `mkdocs.yml` — three edits: `docs_dir: site-src`, `theme.custom_dir: site-src/overrides`, remove `edit_uri` line.

### Untouched

Everything else. Nav, site_description, spec chapters, ADRs, verification content, requirements, all hub content — nothing is edited.

---

## Phase 0: Pre-flight

**Goal:** Clean working tree, establish warning baseline, stage active session artifacts.

---

### Task 0.1: Snapshot the current warning baseline

- [ ] **Step 1: Capture current warning count**

```bash
cd /home/john/wardline
.venv/bin/mkdocs build 2>&1 | tee /tmp/mkdocs-baseline.log | grep -c WARNING
```

Record the exact number. Expected: 33 (as of 2026-04-12; may shift if other work has changed spec files). This is the baseline. Plan A is green iff the post-move build produces **the same number or fewer** warnings.

- [ ] **Step 2: Capture the baseline warning set for exact-diff later**

```bash
.venv/bin/mkdocs build 2>&1 | grep WARNING | sort > /tmp/mkdocs-baseline-warnings.txt
wc -l /tmp/mkdocs-baseline-warnings.txt
```

---

### Task 0.2: Address dirty working tree

**Goal:** Start from a clean tree so `git mv` is unambiguous.

- [ ] **Step 1: Review current state**

```bash
cd /home/john/wardline
git status
```

Expected: 12 modified files, 5 untracked paths (see below). If the state has drifted, re-read each modified/untracked path and decide: commit, stash with a named stash, or explicitly leave as dirty.

- [ ] **Step 2: Handle the three today-dated adjudication files**

```bash
ls docs/archive/reviews/2026-04-12-*.md
```

These are active-session review artifacts. **Decision required from user** before proceeding: commit them to `main`, move them to `docs/superpowers/reviews/`, or leave untracked.

**If committing:** `git add docs/archive/reviews/2026-04-12-*.md && git commit -m "chore: archive 2026-04-12 adjudication artifacts"`.

This plan assumes the decision is made and executed before Task 0.3.

- [ ] **Step 3: Handle the untracked `docs/verification/` content**

```bash
ls docs/verification/
```

`2026-04-12-v1-0-cell-certification-matrix.md` and `2026-04-12-v1-0-compliance-ledger.md` are both untracked and both are active v1.0 cert artifacts. They must be committed (or explicitly staged) before this plan runs, so they are not stranded. The compliance ledger is the output of in-progress issue `wardline-fae28f1be3`.

**Decision required from user:** commit them on `main`? Or on the cert branch? Do not proceed with Plan A until this is resolved.

- [ ] **Step 4: Handle the other 12 modified files**

```bash
git diff --stat
```

These are v1.0 cert edits (spec fitness YAML, §15 conformance, ADR-004, etc.). Plan A does not touch any of these files. They can remain dirty during the move, since Plan A only touches homepage/reference/guides/stylesheets/javascripts/assets/overrides + mkdocs.yml — disjoint from the modified set. **Verify disjointness** before proceeding:

```bash
git diff --name-only | grep -E '^(docs/index\.md|docs/getting-started\.md|docs/specification\.md|docs/reference/|docs/guides/|docs/stylesheets/|docs/javascripts/|docs/assets/|overrides/|mkdocs\.yml)' || echo "disjoint: safe"
```

Expected: `disjoint: safe`. If any matches print, stop and reconcile before proceeding.

- [ ] **Step 5: Handle untracked `.codex` and `docs/superpowers/`**

`.codex` is unrelated. `docs/superpowers/` holds this plan file and the parent plan — must be committed before execution so this plan file itself survives. `git add docs/superpowers/ && git commit -m "chore: track superpowers plans directory"`.

---

## Phase 1: Move

**Goal:** Move website source into `site-src/`, create symlinks, update `mkdocs.yml`. Single commit at the end.

---

### Task 1.1: Create site-src and move top-level pages

- [ ] **Step 1: Create site-src/**

```bash
cd /home/john/wardline
mkdir site-src
```

- [ ] **Step 2: Move homepage, getting-started, specification landing**

```bash
git mv docs/index.md site-src/index.md
git mv docs/getting-started.md site-src/getting-started.md
git mv docs/specification.md site-src/specification.md
```

- [ ] **Step 3: Verify**

```bash
ls site-src/index.md site-src/getting-started.md site-src/specification.md
test ! -e docs/index.md && echo "docs/index.md gone"
```

---

### Task 1.2: Move reference and guides

- [ ] **Step 1: Move reference/**

```bash
git mv docs/reference site-src/reference
```

- [ ] **Step 2: Move guides/**

```bash
git mv docs/guides site-src/guides
```

- [ ] **Step 3: Verify**

```bash
ls site-src/reference/ site-src/guides/ | head
test ! -e docs/reference && test ! -e docs/guides && echo "docs/reference and docs/guides gone"
```

---

### Task 1.3: Move web chrome directories

- [ ] **Step 1: Move stylesheets, javascripts, assets**

```bash
git mv docs/stylesheets site-src/stylesheets
git mv docs/javascripts site-src/javascripts
git mv docs/assets site-src/assets
```

- [ ] **Step 2: Move repo-root `overrides/`**

```bash
git mv overrides site-src/overrides
```

- [ ] **Step 3: Check for stray web-chrome files at docs root**

```bash
ls docs/*.html docs/sitemap* docs/tags.json 2>/dev/null
```

If any exist, `git mv` each to `site-src/`. Otherwise proceed.

- [ ] **Step 4: Verify**

```bash
ls -d site-src/stylesheets site-src/javascripts site-src/assets site-src/overrides
```

---

### Task 1.4: Create the five symlinks

- [ ] **Step 1: Create symlinks**

```bash
cd /home/john/wardline/site-src
ln -s ../docs/spec spec
ln -s ../docs/adr adr
ln -s ../docs/audits audits
ln -s ../docs/verification verification
ln -s ../docs/requirements requirements
```

- [ ] **Step 2: Verify symlinks resolve**

```bash
cd /home/john/wardline
ls site-src/spec/wardline-01-01-document-scope.md \
   site-src/adr/ADR-001-rename-taint-states-to-posture-vocabulary.md \
   site-src/audits/ \
   site-src/verification/ \
   site-src/requirements/spec-fitness/
```

Expected: all five paths resolve and list content.

- [ ] **Step 3: Stage symlinks for git**

```bash
git add site-src/spec site-src/adr site-src/audits site-src/verification site-src/requirements
git ls-files --stage site-src/spec site-src/adr site-src/audits site-src/verification site-src/requirements
```

Expected: five entries with mode `120000` (symlink).

---

### Task 1.5: Update mkdocs.yml

**Goal:** Three edits — `docs_dir`, `theme.custom_dir`, remove `edit_uri`. Nothing else.

- [ ] **Step 1: Add `docs_dir: site-src` after `copyright` block**

Use Edit to add a new `docs_dir: site-src` line after the `copyright:` block (before `theme:`).

- [ ] **Step 2: Update `theme.custom_dir`**

Edit `custom_dir: overrides` → `custom_dir: site-src/overrides`.

- [ ] **Step 3: Remove `edit_uri` line**

Delete the line `edit_uri: edit/main/docs/`. This disables edit buttons temporarily. Plan B restores them.

- [ ] **Step 4: Verify mkdocs.yml looks right**

```bash
grep -n 'docs_dir:\|custom_dir:\|edit_uri' mkdocs.yml
```

Expected: `docs_dir: site-src` present, `custom_dir: site-src/overrides` present, `edit_uri` absent.

---

### Task 1.6: Build verification with baseline diff

- [ ] **Step 1: Run build (non-strict)**

```bash
cd /home/john/wardline
.venv/bin/mkdocs build 2>&1 | tee /tmp/mkdocs-postmove.log
```

Expected: build succeeds. Look at the tail for warning count.

- [ ] **Step 2: Diff against baseline**

```bash
grep WARNING /tmp/mkdocs-postmove.log | sort > /tmp/mkdocs-postmove-warnings.txt
diff /tmp/mkdocs-baseline-warnings.txt /tmp/mkdocs-postmove-warnings.txt
```

Expected: no diff output, OR only differences in the path prefix (e.g., warnings that reference `reference/...` are unchanged because the path is identical through the symlinks). **Any new warning class is a regression — investigate before committing.**

- [ ] **Step 3: Spot-check key URLs resolve**

```bash
.venv/bin/mkdocs serve -a 127.0.0.1:8000 &
SERVE_PID=$!
sleep 3

# Verify it actually started
curl -sf http://127.0.0.1:8000/ > /dev/null && echo "home OK" || echo "HOME FAILED"
curl -sf http://127.0.0.1:8000/getting-started/ > /dev/null && echo "getting-started OK" || echo "GS FAILED"
curl -sf http://127.0.0.1:8000/spec/wardline-01-05-authority-tier-model/ > /dev/null && echo "spec §5 OK" || echo "SPEC FAILED"
curl -sf http://127.0.0.1:8000/adr/ADR-001-rename-taint-states-to-posture-vocabulary/ > /dev/null && echo "ADR-001 OK" || echo "ADR FAILED"
curl -sf http://127.0.0.1:8000/reference/rules/ > /dev/null && echo "reference/rules OK" || echo "REF FAILED"
curl -sf http://127.0.0.1:8000/guides/adoption/ > /dev/null && echo "guides/adoption OK" || echo "GUIDES FAILED"
curl -sf http://127.0.0.1:8000/verification/2026-04-12-v1-0-cell-certification-matrix/ > /dev/null && echo "verification OK" || echo "VER FAILED"

kill $SERVE_PID 2>/dev/null
wait $SERVE_PID 2>/dev/null
```

Expected: seven `OK` lines. Any `FAILED` line must be investigated before committing. (Note: the cell certification matrix URL only works if that file is in the current nav OR mkdocs is configured with `use_directory_urls` — verify by checking the current `mkdocs.yml` nav for how verification content is currently served. If the baseline site does not expose the cell matrix, the spot-check line can be dropped.)

- [ ] **Step 4: Test PDF build still works**

```bash
tools/pdf/build-spec.sh 2>&1 | tail -10
```

Expected: build succeeds. PDF pipeline reads from `docs/spec/` directly — unaffected by the move — this is a paranoia check.

---

### Task 1.7: Commit

- [ ] **Step 1: Review staged changes**

```bash
git status
git diff --stat --cached
```

Expected: renames under `site-src/`, 5 new symlinks, `mkdocs.yml` modified. No other files touched.

- [ ] **Step 2: Commit**

```bash
git add mkdocs.yml site-src/
git commit -m "$(cat <<'EOF'
site: separate authoritative content from website source

Move website source (homepage, getting-started, specification,
reference, guides, stylesheets, javascripts, assets, overrides)
from docs/ and repo root into a new site-src/ directory. Symlink
docs/{spec,adr,audits,verification,requirements} into site-src/
so mkdocs serves them at unchanged URL paths.

docs/ now holds only authoritative source material.
site-src/ holds website source.

No nav changes, no content edits, no deletions. URL paths and
rendered content are unchanged. Edit buttons are temporarily
disabled while the edit_uri / symlink interaction is resolved
in the follow-up plan (post-v1.0 cert).

Follow-up: docs/superpowers/plans/2026-04-12-wardline-site-restructure.md
(to run after v1.0 recertification closes).
EOF
)"
```

---

## Rollback

If anything regresses:

```bash
git revert HEAD
```

The commit is atomic — a single revert restores the pre-move state. The symlinks, moves, and `mkdocs.yml` edits all go away together.

If a partial failure leaves the working tree in an inconsistent state mid-Phase 1 (nothing committed yet):

```bash
git restore --staged site-src/ mkdocs.yml overrides/
git clean -fd site-src/   # remove untracked site-src dir
# Manually restore any files git mv touched — git should have left them under site-src/
git checkout HEAD -- docs/ overrides/ mkdocs.yml
```

---

## Success criteria

1. `site-src/` exists and contains: `index.md`, `getting-started.md`, `specification.md`, `reference/`, `guides/`, `stylesheets/`, `javascripts/`, `assets/`, `overrides/`, and 5 symlinks.
2. `docs/` no longer contains: `index.md`, `getting-started.md`, `specification.md`, `reference/`, `guides/`, `stylesheets/`, `javascripts/`, `assets/`.
3. `overrides/` no longer exists at repo root.
4. `mkdocs.yml` sets `docs_dir: site-src`, `theme.custom_dir: site-src/overrides`, and has no `edit_uri` key.
5. `mkdocs build` succeeds and produces the **same set of warnings** as the pre-move baseline — zero new warnings.
6. `mkdocs serve` responds 200 on home, getting-started, spec chapters, ADRs, reference, guides, and verification content.
7. `tools/pdf/build-spec.sh` still succeeds.
8. Git log shows exactly one new commit on top of the pre-plan `HEAD`.

---

## Summary

- **Phases:** 2 (Phase 0 pre-flight + Phase 1 move)
- **Total tasks:** 9 (0.1, 0.2, 1.1–1.7)
- **Total steps:** ~35
- **Estimated effort:** 1–2 hours
- **Total commits:** 1 (plus any Phase 0 cleanup commits)
- **Files moved:** ~30
- **Files created:** 5 (symlinks)
- **Files deleted:** 0
- **Files edited:** 1 (`mkdocs.yml`)
- **Spec content touched:** 0

This plan deliberately leaves the specification content, nav, hub pages, cross-links, template override, and home page rewrite for Plan B (post-cert). The move is a load-bearing prerequisite — doing it now unblocks Plan B later while carrying no risk to in-flight recertification work.
