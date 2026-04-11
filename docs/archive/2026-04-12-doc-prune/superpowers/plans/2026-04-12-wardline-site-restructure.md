# Wardline.dev Site Restructure — Implementation Plan (Plan B — post-cert)

> **⚠️ Split on 2026-04-12. This is Plan B.**
>
> **Phase 1 of this plan (the structural move) was extracted into a standalone plan:** `docs/superpowers/plans/2026-04-12-wardline-site-move.md` (Plan A). Run Plan A first, independently of v1.0 cert work.
>
> **This plan (Plan B) covers everything else:** deletions, new hub content, nav rewrite, cross-link protocol, spec chapter frontmatter, template override, and home page rewrite. It is **deferred until v1.0 recertification closes** because Phase 6 (spec chapter frontmatter) collides with seven P1 recertification tasks that edit the same files, and the content it creates depends on stable spec text.
>
> **Before running this plan, also address the review blockers from** `docs/superpowers/plans/2026-04-12-wardline-site-restructure.review.md`:
>
> - B1: §13 hub content is fabricated — re-derive from actual 17-risk chapter
> - B2: hallucinated inline anchor fragments — enumerate real slugs from each referenced chapter
> - B4: CLI quick reference errors (`wardline preview` is not a subcommand; `wardline project` is missing; `requirements/spec-fitness/` nav entry needs an `index.md`)
> - B5: `overrides/main.html` template clobber — merge rather than replace, preserve `{% block announce %}`
> - C2: `edit_uri` + symlinks — pick a deterministic strategy (template rewrite or `hide: [edit]`)
>
> **Phase 1 below is redundant with Plan A** and should be treated as already complete when this plan runs. Start at Phase 2.
>
> ---

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the wardline.dev website to make the frozen v1.0 RC specification the discoverable, authoritative core of the site, separating authoritative content (`docs/`) from website source (new `site-src/`) via symlinks, surfacing currently-hidden spec material, and adding a new Assurance & Decisions section.

**Architecture:** Two-directory split. `docs/` holds only authoritative source material (frozen spec, ADRs, audits, V&V matrix, requirements). `site-src/` holds website source (homepage, reference, guides, assurance hubs, stylesheets, overrides). Five symlinks inside `site-src/` expose the authoritative directories to mkdocs at stable URL paths. Cross-link protocol (info admonitions + auto-injected chapter headers) wires derived pages bidirectionally to their spec chapters.

**Tech Stack:** mkdocs Material (static site generator), Jinja2 templates for mkdocs Material overrides, Markdown content, Python 3.12 for building. No runtime code changes. No new dependencies.

**Design spec:** `docs/superpowers/specs/2026-04-12-wardline-site-restructure-design.md`

**Phase order (corrected from spec):** The spec's Section 10 listed nav restructure (Phase 3) before new hub content (Phase 4). That is inverted — nav cannot reference files that do not exist without `--strict` failing. This plan creates hub content first (Phase 3 here) and restructures nav second (Phase 4 here).

---

## File Structure

### New files

| Path | Purpose |
|---|---|
| `site-src/` | Root of website source (new top-level directory) |
| `site-src/specification.md` | Grouped spec landing page with Start Here, Part I groups, Part II, Companion |
| `site-src/reference/index.md` | Wardline Quick Reference data sheet (tables-only, Cmd+F target) |
| `site-src/guides/index.md` | "Choose your guide" index |
| `site-src/guides/conformance-roadmap.md` | Consolidated §15 Phase 0→1→2→3 roadmap |
| `site-src/assurance/index.md` | Assurance & Decisions section overview |
| `site-src/assurance/verification/index.md` | Verification Properties hub (Cell Certification Matrix headline) |
| `site-src/assurance/residual-risks/index.md` | Residual Risks hub (§13 navigator) |
| `site-src/assurance/audits/index.md` | Chronological audits index |
| `site-src/assurance/decisions/index.md` | ADR index with status-sorted table |
| `site-src/overrides/main.html` | mkdocs Material template override for spec chapter header/footer |
| `site-src/stylesheets/extra.css` | Extended with classes for spec chapter header/footer and admonitions |

### Moved files (from `docs/` to `site-src/`)

| From | To |
|---|---|
| `docs/index.md` | `site-src/index.md` |
| `docs/getting-started.md` | `site-src/getting-started.md` |
| `docs/specification.md` | `site-src/specification.md` (will be rewritten) |
| `docs/reference/*.md` (all 11 files) | `site-src/reference/*.md` |
| `docs/guides/*.md` (all 6 files) | `site-src/guides/*.md` |
| `docs/stylesheets/` | `site-src/stylesheets/` |
| `docs/javascripts/` | `site-src/javascripts/` |
| `docs/assets/` | `site-src/assets/` |
| `docs/404.html` (if present) | `site-src/404.html` |
| `overrides/` (at repo root) | `site-src/overrides/` |

### Symlinks (new)

| Symlink | Target |
|---|---|
| `site-src/spec` | `../docs/spec` |
| `site-src/adr` | `../docs/adr` |
| `site-src/audits` | `../docs/audits` |
| `site-src/verification` | `../docs/verification` |
| `site-src/requirements` | `../docs/requirements` |

### Deleted files

| Path | Reason |
|---|---|
| `docs/archive/` | Historical; git has it |
| `docs/design/` | Internal drafts |
| `docs/plans/` | Project plans |
| `docs/session-log-2026-03-28/` | Session handoff |
| `docs/spec/README.md` | Superseded by new spec landing page |
| `docs/verification/MINISPEC-PROMPT.md` | Claude prompt |
| `docs/verification/RENAME-EXECUTE-PROMPT.md` | Claude prompt |
| `docs/verification/RENAME-IMPACT-PROMPT.md` | Claude prompt |
| `docs/verification/rename-migration-manifest.md` | Rename scratchpad |
| `docs/verification/SESSION-PICKUP-2026-03-29.md` | Session handoff |
| `docs/verification/SPEC-PART1-RENAME-PROMPT.md` | Claude prompt |
| `docs/verification/v1.0-review-prompt.md` | Claude prompt |
| `docs/verification/VERIFY-SUBSYSTEM-PROMPT.md` | Claude prompt |
| `docs/verification/VERIFY-SYNTHESIS-PROMPT.md` | Claude prompt |
| `site-src/reference/severity-matrix.md` | Merged into Quick Reference |
| `site-src/reference/governance-retention.md` | Merged into Manifest reference |

### Modified files

- `mkdocs.yml` — `docs_dir: site-src`, full nav rewrite, corrected `site_description`
- `site-src/index.md` — language-independent pitch + audience routing cards
- `site-src/getting-started.md` — inline spec refs, "Next steps" footer
- `site-src/reference/*.md` (9 files) — authority banner header
- `site-src/guides/*.md` (6 files) — prerequisites box header
- `docs/adr/ADR-001..004.md` — status admonitions
- `docs/spec/wardline-01-08-pattern-rules.md` — per-rule cross-links to semantic-equivalents
- `docs/spec/semantic-equivalents/py-wl-00{1..9}.md` — header banners to §8
- `docs/spec/wardline-01-{01..15}-*.md` (15 files) — add `spec_chapter` frontmatter
- `docs/spec/wardline-02-{00,A,B}-*.md` (3 files) — add `spec_chapter` frontmatter
- `docs/spec/wardline-lite.md` — add `spec_chapter` frontmatter for Start Here rendering

---

## Phase 1: Repository Layout Separation

**Goal:** Move website source to `site-src/`, create symlinks to authoritative directories, update `mkdocs.yml` `docs_dir`. At end of phase the site still builds with the **existing** nav structure (no nav rewrite yet).

---

### Task 1.1: Create site-src skeleton and move homepage + getting-started

**Files:**
- Create: `site-src/` (new directory)
- Move: `docs/index.md` → `site-src/index.md`
- Move: `docs/getting-started.md` → `site-src/getting-started.md`

- [ ] **Step 1: Create site-src directory**

```bash
mkdir -p /home/john/wardline/site-src
```

- [ ] **Step 2: Move index.md and getting-started.md**

```bash
cd /home/john/wardline
git mv docs/index.md site-src/index.md
git mv docs/getting-started.md site-src/getting-started.md
```

- [ ] **Step 3: Verify files moved**

Run:
```bash
ls /home/john/wardline/site-src/ /home/john/wardline/docs/index.md 2>&1
```
Expected: `site-src/` contains `index.md` and `getting-started.md`. `docs/index.md` does not exist (error).

---

### Task 1.2: Move reference, guides, specification

**Files:**
- Move: `docs/reference/` → `site-src/reference/`
- Move: `docs/guides/` → `site-src/guides/`
- Move: `docs/specification.md` → `site-src/specification.md`

- [ ] **Step 1: Move reference directory**

```bash
cd /home/john/wardline
git mv docs/reference site-src/reference
```

- [ ] **Step 2: Move guides directory**

```bash
cd /home/john/wardline
git mv docs/guides site-src/guides
```

- [ ] **Step 3: Move specification landing file**

```bash
cd /home/john/wardline
git mv docs/specification.md site-src/specification.md
```

- [ ] **Step 4: Verify moves**

Run:
```bash
ls /home/john/wardline/site-src/reference/ /home/john/wardline/site-src/guides/ /home/john/wardline/site-src/specification.md
```
Expected: all three paths exist; `docs/reference/`, `docs/guides/`, `docs/specification.md` are gone.

---

### Task 1.3: Move web chrome directories

**Files:**
- Move: `docs/stylesheets/` → `site-src/stylesheets/`
- Move: `docs/javascripts/` → `site-src/javascripts/`
- Move: `docs/assets/` → `site-src/assets/`
- Move: `overrides/` (at repo root) → `site-src/overrides/`

- [ ] **Step 1: Move stylesheets**

```bash
cd /home/john/wardline
git mv docs/stylesheets site-src/stylesheets
```

- [ ] **Step 2: Move javascripts**

```bash
cd /home/john/wardline
git mv docs/javascripts site-src/javascripts
```

- [ ] **Step 3: Move assets**

```bash
cd /home/john/wardline
git mv docs/assets site-src/assets
```

- [ ] **Step 4: Move overrides**

```bash
cd /home/john/wardline
git mv overrides site-src/overrides
```

- [ ] **Step 5: Check for 404.html or other site chrome files**

```bash
ls /home/john/wardline/docs/*.html /home/john/wardline/docs/sitemap* /home/john/wardline/docs/tags.json 2>/dev/null
```
If any exist, move them too:
```bash
cd /home/john/wardline
git mv docs/404.html site-src/404.html 2>/dev/null || true
git mv docs/sitemap.xml site-src/sitemap.xml 2>/dev/null || true
git mv docs/sitemap.xml.gz site-src/sitemap.xml.gz 2>/dev/null || true
git mv docs/tags.json site-src/tags.json 2>/dev/null || true
```

- [ ] **Step 6: Verify chrome moves**

Run:
```bash
ls /home/john/wardline/site-src/stylesheets /home/john/wardline/site-src/javascripts /home/john/wardline/site-src/assets /home/john/wardline/site-src/overrides
```
Expected: all four directories exist under `site-src/`.

---

### Task 1.4: Create symlinks to authoritative directories

**Files:**
- Create: `site-src/spec` → `../docs/spec`
- Create: `site-src/adr` → `../docs/adr`
- Create: `site-src/audits` → `../docs/audits`
- Create: `site-src/verification` → `../docs/verification`
- Create: `site-src/requirements` → `../docs/requirements`

- [ ] **Step 1: Create the five symlinks**

```bash
cd /home/john/wardline/site-src
ln -s ../docs/spec spec
ln -s ../docs/adr adr
ln -s ../docs/audits audits
ln -s ../docs/verification verification
ln -s ../docs/requirements requirements
```

- [ ] **Step 2: Verify symlinks resolve**

Run:
```bash
ls -la /home/john/wardline/site-src/ | grep '^l'
```
Expected: five symlink entries, each pointing into `../docs/`.

Run:
```bash
ls /home/john/wardline/site-src/spec/ /home/john/wardline/site-src/adr/ /home/john/wardline/site-src/audits/ /home/john/wardline/site-src/verification/ /home/john/wardline/site-src/requirements/
```
Expected: symlinks resolve and show directory contents (spec chapters, ADR files, etc.).

- [ ] **Step 3: Stage symlinks for git**

```bash
cd /home/john/wardline
git add site-src/spec site-src/adr site-src/audits site-src/verification site-src/requirements
```

- [ ] **Step 4: Verify git tracks symlinks**

Run:
```bash
git -C /home/john/wardline ls-files --stage site-src/spec site-src/adr site-src/audits site-src/verification site-src/requirements
```
Expected: five entries with mode `120000` (symlink).

---

### Task 1.5: Update mkdocs.yml docs_dir

**Files:**
- Modify: `mkdocs.yml` (add `docs_dir: site-src`)

- [ ] **Step 1: Read current mkdocs.yml top section**

Run:
```bash
head -20 /home/john/wardline/mkdocs.yml
```
Note the current structure — `docs_dir` is likely absent (implicit `docs`).

- [ ] **Step 2: Add docs_dir directive**

Edit `mkdocs.yml` to add `docs_dir: site-src` near the top (after `site_url`, before `theme`):

```yaml
site_name: Wardline
site_url: https://www.wardline.dev
site_description: >-
  Semantic boundary enforcement for Python. Statically verify that untrusted
  input never reaches privileged code — via AST analysis with taint propagation.
site_author: Tachyon Beep
repo_url: https://github.com/tachyon-beep/wardline
repo_name: tachyon-beep/wardline
edit_uri: edit/main/docs/
copyright: >-
  Copyright &copy; 2026 Tachyon Beep —
  <a href="https://github.com/tachyon-beep/wardline/blob/main/LICENSE">MIT License</a>

docs_dir: site-src

theme:
  name: material
  custom_dir: site-src/overrides
  ...
```

**Important:** Also update `theme.custom_dir` from `overrides` to `site-src/overrides` since overrides moved.

- [ ] **Step 3: Check for other path references in mkdocs.yml**

Run:
```bash
grep -n 'docs/\|overrides' /home/john/wardline/mkdocs.yml
```
Expected: `custom_dir: site-src/overrides` (updated), no other references to `docs/` except possibly in `edit_uri` which references the git repo path (leave that as-is because edit links should still go to `docs/` sources, but note edit_uri points to the source file location in the repo, not docs_dir).

Actually — `edit_uri: edit/main/docs/` will produce broken edit links for pages that now live in `site-src/`. Update needed:
```yaml
edit_uri: edit/main/
```
This makes edit links resolve relative to repo root, so `site-src/index.md` edits to `edit/main/site-src/index.md` and `spec/wardline-01-05-*.md` edits to `edit/main/docs/spec/wardline-01-05-*.md` (symlink traversal).

Actually, edit_uri + symlinks is tricky — when editing via symlink, the edit URL will point to `site-src/spec/...` but git's real file is `docs/spec/...`. Test this in Step 5 and adjust if edit links are broken.

- [ ] **Step 4: Build the site with existing nav**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tee /tmp/mkdocs-phase1.log
```
Expected: build succeeds with no errors. Warnings about nav-referenced files in old paths (e.g. `spec/...` nav entries) should still work because symlinks expose them.

If build fails with "cannot find docs_dir" errors, verify `site-src/` exists and contains `index.md`.

If build fails with nav reference errors for paths like `spec/wardline-01-*.md`, verify the `site-src/spec` symlink resolves.

- [ ] **Step 5: Serve and spot-check a few URLs**

```bash
cd /home/john/wardline
mkdocs serve -a 127.0.0.1:8000 &
SERVE_PID=$!
sleep 3
curl -sf http://127.0.0.1:8000/ -o /dev/null && echo "home OK"
curl -sf http://127.0.0.1:8000/getting-started/ -o /dev/null && echo "getting-started OK"
curl -sf http://127.0.0.1:8000/spec/wardline-01-05-authority-tier-model/ -o /dev/null && echo "spec chapter OK"
curl -sf http://127.0.0.1:8000/adr/ADR-001-rename-taint-states-to-posture-vocabulary/ -o /dev/null && echo "ADR OK"
kill $SERVE_PID
```
Expected: all four "OK" lines print. Stops the serve process.

---

### Task 1.6: Commit Phase 1

- [ ] **Step 1: Review staged changes**

```bash
cd /home/john/wardline
git status
```
Expected: renames from `docs/` → `site-src/`, 5 new symlinks, `mkdocs.yml` modified.

- [ ] **Step 2: Commit**

```bash
cd /home/john/wardline
git add mkdocs.yml site-src/
git commit -m "$(cat <<'EOF'
site: separate authoritative content from website source

Move website source (homepage, reference, guides, stylesheets,
javascripts, assets, overrides) from docs/ to new site-src/
directory. Symlink docs/spec, docs/adr, docs/audits,
docs/verification, docs/requirements into site-src/ so mkdocs
builds through them at stable URLs.

docs/ now holds only authoritative source material. site-src/
holds website source. URL paths unchanged.

Refs: docs/superpowers/specs/2026-04-12-wardline-site-restructure-design.md §8
EOF
)"
```

---

## Phase 2: Deletions

**Goal:** Remove orphaned internal artifacts. No content referenced from nav is touched. Site still builds.

---

### Task 2.1: Delete top-level internal directories

**Files:**
- Delete: `docs/archive/`
- Delete: `docs/design/`
- Delete: `docs/plans/`
- Delete: `docs/session-log-2026-03-28/`
- Delete: `docs/spec/README.md`

- [ ] **Step 1: Confirm no nav references to these paths**

```bash
grep -E 'archive|design/|plans/|session-log|spec/README' /home/john/wardline/mkdocs.yml
```
Expected: no output (these paths are not referenced from nav).

- [ ] **Step 2: Delete**

```bash
cd /home/john/wardline
git rm -r docs/archive docs/design docs/plans docs/session-log-2026-03-28 docs/spec/README.md
```

- [ ] **Step 3: Verify deletion**

```bash
ls /home/john/wardline/docs/archive /home/john/wardline/docs/design /home/john/wardline/docs/plans /home/john/wardline/docs/session-log-2026-03-28 2>&1
```
Expected: four "No such file or directory" errors.

---

### Task 2.2: Delete verification process artifacts

**Files:**
- Delete: `docs/verification/MINISPEC-PROMPT.md`
- Delete: `docs/verification/RENAME-EXECUTE-PROMPT.md`
- Delete: `docs/verification/RENAME-IMPACT-PROMPT.md`
- Delete: `docs/verification/rename-migration-manifest.md`
- Delete: `docs/verification/SESSION-PICKUP-2026-03-29.md`
- Delete: `docs/verification/SPEC-PART1-RENAME-PROMPT.md`
- Delete: `docs/verification/v1.0-review-prompt.md`
- Delete: `docs/verification/VERIFY-SUBSYSTEM-PROMPT.md`
- Delete: `docs/verification/VERIFY-SYNTHESIS-PROMPT.md`

- [ ] **Step 1: Delete process prompts and session logs**

```bash
cd /home/john/wardline
git rm docs/verification/MINISPEC-PROMPT.md \
       docs/verification/RENAME-EXECUTE-PROMPT.md \
       docs/verification/RENAME-IMPACT-PROMPT.md \
       docs/verification/rename-migration-manifest.md \
       docs/verification/SESSION-PICKUP-2026-03-29.md \
       docs/verification/SPEC-PART1-RENAME-PROMPT.md \
       docs/verification/v1.0-review-prompt.md \
       docs/verification/VERIFY-SUBSYSTEM-PROMPT.md \
       docs/verification/VERIFY-SYNTHESIS-PROMPT.md
```

- [ ] **Step 2: Verify only the cell certification matrix (and possibly README) remain**

```bash
ls /home/john/wardline/docs/verification/
```
Expected: `2026-04-12-v1-0-cell-certification-matrix.md` remains. `README.md` may remain (check contents in Step 3).

- [ ] **Step 3: Inspect docs/verification/README.md**

```bash
cat /home/john/wardline/docs/verification/README.md 2>/dev/null
```

- If the README describes the V&V program (authoritative, mentions formal properties, cell matrix, etc.), **keep it**.
- If the README describes process/workflow (Claude sessions, prompts, how-to-run verification), **delete it**:
  ```bash
  cd /home/john/wardline
  git rm docs/verification/README.md
  ```

---

### Task 2.3: Build and commit Phase 2

- [ ] **Step 1: Build to verify site still works**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tail -20
```
Expected: build succeeds.

- [ ] **Step 2: Commit**

```bash
cd /home/john/wardline
git commit -m "$(cat <<'EOF'
site: delete orphaned internal artifacts

Remove docs/archive (superseded — git preserves history),
docs/design, docs/plans, docs/session-log-2026-03-28 (internal
process detritus), docs/spec/README.md (superseded by upcoming
new specification landing page), and docs/verification/*-PROMPT.md
plus session-pickup and rename migration files (Claude process
artifacts).

docs/verification/ retains only the v1.0 cell certification
matrix as the authoritative V&V single source of truth.
EOF
)"
```

---

## Phase 3: Create New Hub Content

**Goal:** Create all new hub pages and the Quick Reference data sheet. At end of phase these files exist but are not yet reachable from nav.

---

### Task 3.1: Create specification landing page

**Files:**
- Modify: `site-src/specification.md` (full rewrite of existing file)

- [ ] **Step 1: Rewrite site-src/specification.md with the grouped landing page**

Replace the entire contents of `site-src/specification.md` with:

```markdown
---
title: Wardline Specification
hide:
  - navigation
---

# Wardline Specification

<p class="spec-status-strip">
  <strong>v1.0 RC</strong> · Normative · 4,649 lines ·
  <a href="/assets/wardline-specification.pdf">Download PDF</a>
</p>

The normative definition of the Wardline framework. Frozen for v1.0.

!!! info "Start here first"
    - **[Reading Guide](spec/wardline-01-00-front-matter.md)** — Which chapters you need, by role.
    - **[Wardline Lite](spec/wardline-lite.md)** — Practical 5-question review guide for reviewers without tooling.

## Part I — Framework

Language-independent. Fifteen chapters.

### Foundations

- [§1. Document Scope](spec/wardline-01-01-document-scope.md)
- [§2. What a Wardline Is](spec/wardline-01-02-what-a-wardline-is.md)
- [§3. The Problem a Wardline Solves](spec/wardline-01-03-the-problem-a-wardline-solves.md)
- [§4. Non-Goals](spec/wardline-01-04-non-goals.md)

### Trust Model *(foundational — read these before the rest)*

- [§5. Authority Tier Model](spec/wardline-01-05-authority-tier-model.md)
- [§6. Authority Tier Enforcement Spec](spec/wardline-01-06-authority-tier-enforcement-spec.md)

### Annotations and Rules

- [§7. Annotation Vocabulary](spec/wardline-01-07-annotation-vocabulary.md)
- [§8. Pattern Rules](spec/wardline-01-08-pattern-rules.md)
- [§9. Enforcement Layers](spec/wardline-01-09-enforcement-layers.md)

### Governance and Verification

- [§10. Governance Model](spec/wardline-01-10-governance-model.md)
- [§11. Verification Properties](spec/wardline-01-11-verification-properties.md)

### Portability and Conformance

- [§12. Language Evaluation Criteria](spec/wardline-01-12-language-evaluation-criteria.md)
- [§13. Residual Risks](spec/wardline-01-13-residual-risks.md)
- [§14. Portability & Manifest Format](spec/wardline-01-14-portability-and-manifest-format.md)
- [§15. Conformance Profiles](spec/wardline-01-15-conformance.md)

## Part II — Language Bindings

- [Part II Overview](spec/wardline-02-00-front-matter.md)
- [A. Python Binding](spec/wardline-02-A-python-binding.md) — Normative Python contract. 863 lines.
- [B. Java Binding](spec/wardline-02-B-java-binding.md) — Normative Java contract. 676 lines.

## Companion

- **Semantic Equivalents** — Per-rule syntactic pattern catalogues (living doc).
    - [Overview](spec/semantic-equivalents/README.md)
    - [PY-WL-001](spec/semantic-equivalents/py-wl-001.md) ·
      [PY-WL-002](spec/semantic-equivalents/py-wl-002.md) ·
      [PY-WL-003](spec/semantic-equivalents/py-wl-003.md) ·
      [PY-WL-004](spec/semantic-equivalents/py-wl-004.md) ·
      [PY-WL-005](spec/semantic-equivalents/py-wl-005.md) ·
      [PY-WL-006](spec/semantic-equivalents/py-wl-006.md) ·
      [PY-WL-007](spec/semantic-equivalents/py-wl-007.md) ·
      [PY-WL-008](spec/semantic-equivalents/py-wl-008.md) ·
      [PY-WL-009](spec/semantic-equivalents/py-wl-009.md)
```

- [ ] **Step 2: Verify file written**

```bash
head -20 /home/john/wardline/site-src/specification.md
```
Expected: shows the new frontmatter and title.

---

### Task 3.2: Create Reference Quick Reference data sheet

**Files:**
- Create: `site-src/reference/index.md` (replaces current index if any)

- [ ] **Step 1: Gather rule data from source**

```bash
grep -E '^\s+(PY_WL|SCN|SUP)' /home/john/wardline/src/wardline/core/severity.py | head -20
grep -E 'class TaintState' /home/john/wardline/src/wardline/core/taints.py -A 20
ls /home/john/wardline/src/wardline/decorators/
```
Use this output to populate the tables below.

- [ ] **Step 2: Write site-src/reference/index.md**

Write the following content to `site-src/reference/index.md`:

```markdown
---
title: Wardline Quick Reference
---

# Wardline Quick Reference

Tables only. For narrative explanations and normative definitions, follow the
links into the Specification.

## Rule matrix

| Rule ID    | Name (summary)                            | Severity band | Normative source |
|------------|-------------------------------------------|---------------|------------------|
| PY-WL-001  | Dict key access with fallback default     | ERROR/WARN    | [§8](../spec/wardline-01-08-pattern-rules.md#wl-001) |
| PY-WL-002  | Permissive type annotations on input      | ERROR/WARN    | [§8](../spec/wardline-01-08-pattern-rules.md#wl-002) |
| PY-WL-003  | External data reaching privileged call    | ERROR         | [§8](../spec/wardline-01-08-pattern-rules.md#wl-003) |
| PY-WL-004  | Structural revalidation missing           | ERROR/WARN    | [§8](../spec/wardline-01-08-pattern-rules.md#wl-004) |
| PY-WL-005  | External data in format/string interp     | ERROR/WARN    | [§8](../spec/wardline-01-08-pattern-rules.md#wl-005) |
| PY-WL-006  | Missing restoration evidence              | ERROR/WARN    | [§8](../spec/wardline-01-08-pattern-rules.md#wl-006) |
| PY-WL-007  | Restoration boundary without rejection    | ERROR         | [§8](../spec/wardline-01-08-pattern-rules.md#wl-007) |
| PY-WL-008  | Delegated rejection path missing          | ERROR/WARN    | [§8](../spec/wardline-01-08-pattern-rules.md#wl-008) |
| PY-WL-009  | Validation ordering / effect placement    | ERROR/WARN    | [§8](../spec/wardline-01-08-pattern-rules.md#wl-009) |
| SCN-021    | Scanner structural guarantee (supplementary) | WARN       | [§8.4](../spec/wardline-01-08-pattern-rules.md#scn-021) |
| SUP-001    | Supplementary group rule                  | WARN          | [§8.4](../spec/wardline-01-08-pattern-rules.md#sup-001) |
| SCN-022    | Scanner supplementary                     | WARN          | [§8.4](../spec/wardline-01-08-pattern-rules.md#scn-022) |

For per-rule detail, see [Rules reference](rules.md).

## Taint states

Eight canonical taint states form the join lattice. See [§6.1](../spec/wardline-01-06-authority-tier-enforcement-spec.md#effective-states) for the full formal definition.

| State              | Tier | Coding posture  | Typical source                         |
|--------------------|------|-----------------|----------------------------------------|
| INTEGRAL           | T1   | Absolute trust  | System configuration, constants        |
| ASSURED            | T2   | Verified        | Validated payload post-`@validates_shape` |
| GUARDED            | T3   | Structurally safe | Session data behind a guard            |
| UNKNOWN_ASSURED    | T2/T3 | Claimed verified | Unverified assertion of verification    |
| UNKNOWN_GUARDED    | T3   | Claimed guarded | Weakly-guarded data                    |
| UNKNOWN_RAW        | T4   | Unknown         | Untrusted, source unclear              |
| EXTERNAL_RAW       | T4   | Raw external    | HTTP request, CLI argv, env vars       |
| MIXED_RAW          | T4   | Mixed taint     | Join of incompatible states (absorbing) |

**Join lattice essentials:**
- `taint_join(a, a) == a` — self-joins return the identity.
- `join(UNKNOWN_ASSURED, UNKNOWN_RAW) == UNKNOWN_RAW` — demote to weaker validation.
- `join(UNKNOWN_GUARDED, UNKNOWN_RAW) == UNKNOWN_RAW` — same.
- `join(UNKNOWN_ASSURED, UNKNOWN_GUARDED) == UNKNOWN_GUARDED` — demote assurance to guard.
- All other incompatible pairs → `MIXED_RAW`.

For the full definition and examples, see [Taint States reference](taint-states.md).

## Decorator groups

See [Decorators reference](decorators.md) for the full per-decorator table with `_wardline_*` attribute lists.

| Group | Purpose                            | Representative decorators |
|-------|------------------------------------|---------------------------|
| 1     | Integral source/read/construction  | `@integral_source`, `@integral_read`, `@integral_construction` |
| 2     | External source declaration        | `@external_boundary`, `@external_raw` |
| 3     | Validation — shape                 | `@validates_shape` |
| 4     | Validation — semantic              | `@validates_semantic` |
| 5–16  | Governance, authority, audit, restoration boundaries, supplementary groups | See Decorators reference |
| 17    | Restoration boundary declaration   | `@restoration_boundary` |

## Manifest keys (`wardline.yaml`)

See [Manifest reference](manifest.md) for the full field-level documentation.

| Top-level key    | Purpose                                            |
|------------------|----------------------------------------------------|
| `profile`        | Conformance profile: lite, core, assured           |
| `tiers`          | Tier assignments per path / package                |
| `boundaries`     | Boundary declarations with `serialization_boundary` flag |
| `exceptions`     | Exception register (governance)                    |
| `overlays`       | Overlay manifests for monorepo support             |
| `thresholds`     | Finding severity thresholds                        |

## CLI command tree

See [CLI reference](cli.md) for the full per-command options.

```
wardline scan              — run scanner against a path
wardline explain           — explain a finding or rule
wardline manifest          — manifest validation and introspection
wardline corpus            — corpus verification commands
wardline coherence         — cross-manifest coherence checks
wardline fingerprint       — fingerprint operations
wardline resolve           — resolve tier/taint for a symbol
wardline regime            — governance regime commands
wardline exception         — exception register operations
wardline preview           — preview mode operations
```

## SARIF output top-level keys

See [SARIF Format reference](sarif-format.md) for the full schema.

| Key              | Purpose                                    |
|------------------|--------------------------------------------|
| `version`        | SARIF version (2.1.0)                      |
| `runs`           | Array of scan runs                         |
| `runs[].tool`    | Tool metadata (wardline, rules)            |
| `runs[].results` | Array of findings                          |
| `runs[].invocations` | Run invocation metadata                |
| `runs[].properties` | Wardline-specific provenance             |
```

- [ ] **Step 3: Verify file written**

```bash
wc -l /home/john/wardline/site-src/reference/index.md
```
Expected: ~120 lines.

---

### Task 3.3: Create guides/index.md and guides/conformance-roadmap.md

**Files:**
- Create: `site-src/guides/index.md`
- Create: `site-src/guides/conformance-roadmap.md`

- [ ] **Step 1: Write site-src/guides/index.md**

```markdown
---
title: Guides
---

# Wardline Guides

Procedural how-to content. Each guide names the specification chapter it implements, so you can always trace back to the normative source.

## Choose your guide

- **[Conformance Roadmap](conformance-roadmap.md)** — The full Phase 0 → Phase 1 → Phase 2 → Phase 3 adoption arc, with the three governance profiles (Lite, Core, Assured).
- **[Adopting Wardline](adoption.md)** — Practical Phase 0 and Phase 1 walkthrough for a first rollout.
- **[CI Integration](ci-integration.md)** — Wiring the scanner into CI, SARIF upload, findings gating.
- **[Governance](governance.md)** — Exception register operations, review workflow.
- **[Governance Profiles](profiles.md)** — Selecting between Lite, Core, and Assured governance.
- **[Analysis Levels](analysis-levels.md)** — Level 1/2/3 call-graph analysis and what each level buys you.
- **[Troubleshooting](troubleshooting.md)** — Common failures, diagnostic commands, fixes.
```

- [ ] **Step 2: Write site-src/guides/conformance-roadmap.md**

```markdown
---
title: Conformance Roadmap
---

!!! info "Prerequisites"
    This guide is the navigator for **Specification §15 — Conformance Profiles**
    (518 lines). It consolidates the four phases and three profiles into one
    page so you can see the whole adoption arc.

# Conformance Roadmap

Wardline defines a four-phase adoption path from Phase 0 (baseline discovery) through Phase 3 (assured conformance), crossed with three governance profiles (Lite, Core, Assured). This page is the navigator.

## The four phases

### Phase 0 — Baseline discovery

Run the scanner in advisory mode against an existing codebase to map its current tier distribution, exception count, and rule violations. No gating, no governance. You are measuring, not enforcing.

**Goal:** understand what you have.

→ Normative definition: [Specification §15.2](../spec/wardline-01-15-conformance.md#phase-0)

### Phase 1 — Lite Governance

Enforce the scanner with a lightweight exception register. Findings are gated, but the governance ceremony is minimal: exceptions are documented, not approved through a formal review board.

**Goal:** stop new violations while tolerating legacy.

→ Normative definition: [Specification §15.3](../spec/wardline-01-15-conformance.md#phase-1)
→ Implementation guide: [Adopting Wardline](adoption.md)

### Phase 2 — Core Governance

Formal exception register with review workflow, retention policies, and governance capacity model. Exceptions require approval; stale exceptions are flagged.

**Goal:** institution-quality control over trust boundary violations.

→ Normative definition: [Specification §15.4](../spec/wardline-01-15-conformance.md#phase-2)
→ Implementation guide: [Governance](governance.md)

### Phase 3 — Assured Conformance

Full verification: corpus-level testing, formal property checks, golden-specimen conformance, independent audit. The tool is trusted as the basis for downstream assurance claims.

**Goal:** assurance-quality trust boundary enforcement.

→ Normative definition: [Specification §15.5](../spec/wardline-01-15-conformance.md#phase-3)
→ Implementation guide: [Governance Profiles](profiles.md)

## The three governance profiles

The profile is independent of the phase — you can be in Phase 2 with Lite governance, or Phase 1 with Core governance.

| Profile  | Governance weight | Who reviews exceptions | Retention policy |
|----------|-------------------|------------------------|------------------|
| Lite     | Minimal           | Author self-declares   | None              |
| Core     | Standard          | Review board           | Time-bounded     |
| Assured  | Heavy             | Independent auditor    | Full audit trail |

→ Normative definition: [Specification §15.4](../spec/wardline-01-15-conformance.md#governance-profiles)

## Graduation criteria

A tier of conformance graduation (e.g. Phase 1 → Phase 2, or Lite → Core) has formal criteria documented in §15.6. Briefly:

- Exception count must be stable or declining.
- No unresolved high-severity findings.
- Manifest tier assignments cover the full target surface.
- Governance capacity must match the new tier.

→ Normative definition: [Specification §15.6](../spec/wardline-01-15-conformance.md#graduation)

## Assessment procedures

How a tool / organization assessment is conducted — what an assessor checks, what artifacts are required, what the pass/fail criteria are. See §15.7.

→ Normative definition: [Specification §15.7](../spec/wardline-01-15-conformance.md#assessment)
```

- [ ] **Step 3: Verify both files written**

```bash
wc -l /home/john/wardline/site-src/guides/index.md /home/john/wardline/site-src/guides/conformance-roadmap.md
```
Expected: ~20 and ~70 lines respectively.

---

### Task 3.4: Create assurance section index and hub pages

**Files:**
- Create: `site-src/assurance/index.md`
- Create: `site-src/assurance/verification/index.md`
- Create: `site-src/assurance/residual-risks/index.md`
- Create: `site-src/assurance/audits/index.md`
- Create: `site-src/assurance/decisions/index.md`

- [ ] **Step 1: Create site-src/assurance directory tree**

```bash
mkdir -p /home/john/wardline/site-src/assurance/verification
mkdir -p /home/john/wardline/site-src/assurance/residual-risks
mkdir -p /home/john/wardline/site-src/assurance/audits
mkdir -p /home/john/wardline/site-src/assurance/decisions
```

- [ ] **Step 2: Write site-src/assurance/index.md**

```markdown
---
title: Assurance & Decisions
---

# Assurance & Decisions

This section collects the artifacts that demonstrate the Wardline specification is **trustworthy** (assurance) and the artifacts that document how it **evolves** (decisions).

## The three assurance pillars

Wardline's assurance story has three complementary directions:

### [Verification Properties](verification/index.md)
**Spec → Evidence.** "Here is what the spec says must be true, and here is how we demonstrate it is." Includes the authoritative Cell Certification Matrix, the golden corpus, and the seven formal properties from §11.

### [Residual Risks](residual-risks/index.md)
**Spec → Limits.** "Here is what the spec deliberately does not verify, and what must be done outside the tool to cover those gaps." §13 enumerates ten residual risks with compensating controls.

### [Audits](audits/index.md)
**Spec → Observation.** "Here is what we found when we checked our own implementation against the spec." Chronological audit records.

## Decisions

### [Architectural Decision Records](decisions/index.md)
Proposals, accepted decisions, and draft extensions. Includes ADR-004 (ELSPETH Enhancements), which is **DRAFT** and not yet part of the v1.0 RC specification.

### [Requirements](../requirements/spec-fitness/)
Spec fitness requirements — the commitments about the spec itself as a whole.
```

- [ ] **Step 3: Write site-src/assurance/verification/index.md**

```markdown
---
title: Verification Properties
---

# Verification Properties

The normative verification framework is defined in **[Specification §11 — Verification Properties](../../spec/wardline-01-11-verification-properties.md)** (380 lines — the largest chapter in Part I).

The authoritative V&V record for the Wardline tool implementation is the **Cell Certification Matrix** below.

## V&V Single Source of Truth

→ **[Cell Certification Matrix (v1.0)](../../verification/2026-04-12-v1-0-cell-certification-matrix.md)**

The cell certification matrix is the authoritative record of what has been verified, by whom, with what method, and at what confidence level for every cell of the trust model. It is the primary artifact an assessor examines when asking "is this tool trustworthy for my assurance claim?"

## Golden Corpus

The golden corpus at `corpus/` in the Wardline repository contains annotated specimens for every rule. Each specimen is a Python file with a YAML metadata sidecar declaring the expected finding (or its absence, for true-negative specimens). The `wardline corpus verify` CLI command runs the scanner against every specimen and reports matches, misses, and spurious detections.

**What the corpus proves:** the scanner detects exactly the violations the spec says it should, and does not fire on patterns the spec says are safe.

→ Normative definition: [§11.2 — Golden Corpus](../../spec/wardline-01-11-verification-properties.md#golden-corpus)

## Formal Properties

Seven formal properties define correct tool behaviour. Each is defined normatively in §11.3:

1. **Soundness** — Every finding reported corresponds to a real violation.
2. **Completeness** — Every violation within the rule set is reported.
3. **Idempotence** — Running the scanner twice produces identical results.
4. **Monotonicity** — Adding decorators cannot introduce new findings of lower severity.
5. **Determinism** — Scan output is reproducible from the same input.
6. **Corpus Coverage** — Every rule has at least one true-positive and one true-negative specimen.
7. **Manifest Coherence** — Manifest declarations are consistent across overlays.

→ Normative definitions: [§11.3](../../spec/wardline-01-11-verification-properties.md#formal-properties)

## Testing Requirements

A conformant Wardline tool must demonstrate all seven formal properties via:

- Running the golden corpus (`wardline corpus verify`).
- Running the coherence checks (`wardline coherence`).
- Providing deterministic SARIF output.
- Publishing a cell certification matrix.

→ Normative definition: [§11.4 — Testing Requirements](../../spec/wardline-01-11-verification-properties.md#testing-requirements)
```

- [ ] **Step 4: Write site-src/assurance/residual-risks/index.md**

```markdown
---
title: Residual Risks
---

# Residual Risks

The normative catalogue of residual risks is in **[Specification §13](../../spec/wardline-01-13-residual-risks.md)** (63 lines). This page surfaces it as a quick-scan table for assessors.

Wardline is a static analysis framework with deliberate boundaries. §13 enumerates ten categories of risk that the tool either cannot detect or detects only partially, together with compensating controls an adopter is expected to implement outside the tool.

## Risk catalogue

| # | Risk | Compensating control | Normative ref |
|---|------|---------------------|---------------|
| 1 | Dynamic import taint opacity | Manifest boundary declaration for dynamic entry points | [§13.1](../../spec/wardline-01-13-residual-risks.md) |
| 2 | Reflection-based field access | Manual review for `getattr`/`setattr` patterns | [§13.2](../../spec/wardline-01-13-residual-risks.md) |
| 3 | C-extension boundaries | Explicit `@external_boundary` at native calls | [§13.3](../../spec/wardline-01-13-residual-risks.md) |
| 4 | Deserialisation invariants | `@restoration_boundary` with evidence categories | [§13.4](../../spec/wardline-01-13-residual-risks.md) |
| 5 | Shallow immutability (mutable container in frozen dataclass) | Supplementary SUP rules in binding | [§13.5](../../spec/wardline-01-13-residual-risks.md) |
| 6 | Cross-module transitive taint | Level 3 call-graph analysis; manifest scope | [§13.6](../../spec/wardline-01-13-residual-risks.md) |
| 7 | Governance review capacity | Capacity model (§10.4) + retention policy | [§13.7](../../spec/wardline-01-13-residual-risks.md) |
| 8 | Incremental analysis drift | Coherence checks between incremental runs | [§13.8](../../spec/wardline-01-13-residual-risks.md) |
| 9 | Third-party code outside manifest | Explicit manifest boundary at integration points | [§13.9](../../spec/wardline-01-13-residual-risks.md) |
| 10 | Tool bug / false negative | Golden corpus maintenance + audit cadence | [§13.10](../../spec/wardline-01-13-residual-risks.md) |

For the complete narrative discussion of each risk, compensating control, and rationale, read [§13 in full](../../spec/wardline-01-13-residual-risks.md).
```

*Note: the risk numbers and descriptions above are indicative. The exact enumeration should be verified against `docs/spec/wardline-01-13-residual-risks.md` during Step 5 — if the spec lists risks under different identifiers or wordings, update this table to match.*

- [ ] **Step 5: Verify residual risks content against spec**

```bash
cat /home/john/wardline/docs/spec/wardline-01-13-residual-risks.md
```

Compare each numbered risk in the file against the table in Step 4. Edit the table if the spec's actual risk list differs in count, wording, or numbering.

- [ ] **Step 6: Write site-src/assurance/audits/index.md**

```markdown
---
title: Audits
---

# Audits

Chronological record of audits conducted against the Wardline specification and the reference implementation.

| Date       | Audit | Scope | Verdict |
|------------|-------|-------|---------|
| 2026-03-25 | [Rule Conformance](../../audits/rule-conformance-audit-2026-03-25.md) | Full rule set (PY-WL-001..009, SCN-021, SUP-001) against corpus | See audit |

New audits are added as they are performed.
```

- [ ] **Step 7: Write site-src/assurance/decisions/index.md**

```markdown
---
title: Decisions (ADRs)
---

# Architectural Decision Records

ADRs document decisions about the Wardline specification. Draft ADRs are proposals under review; accepted ADRs are folded into the spec in subsequent releases.

## Status key

| Status        | Meaning                                                  |
|---------------|----------------------------------------------------------|
| **DRAFT**     | Under review; **not yet normative**. Do not implement.   |
| **ACCEPTED**  | Decision made. May or may not yet be in the shipped spec. |
| **SUPERSEDED**| Replaced by a later decision.                            |
| **REJECTED**  | Proposed but not adopted.                                |

## Decisions

| ID       | Title                                   | Status      | Affects      | Date       |
|----------|-----------------------------------------|-------------|--------------|------------|
| [ADR-004](../../adr/ADR-004-elspeth-enhancements.md) | ELSPETH Enhancements (WL-009 refinement + SUP-010/011) | **DRAFT**   | §7 §8 Part II-A | 2026-04-09 |
| [ADR-003](../../adr/ADR-003-split-rule-matrix-independence.md) | Rule Matrix Independence Split | ACCEPTED  | §8           | 2026-03-18 |
| [ADR-002](../../adr/ADR-002-rename-tier-source-decorators.md) | Rename Tier Source Decorators | ACCEPTED  | §7           | 2026-03-14 |
| [ADR-001](../../adr/ADR-001-rename-taint-states-to-posture-vocabulary.md) | Taint State Rename (Posture vocabulary) | ACCEPTED  | §6 §7        | 2026-03-12 |

Draft ADRs are sorted first so that pending proposals are visible at a glance.
```

*Note: the dates and "Affects" columns are indicative. During Step 8, read each ADR file and verify the dates and affected chapters match.*

- [ ] **Step 8: Verify ADR metadata**

```bash
head -15 /home/john/wardline/docs/adr/ADR-001-rename-taint-states-to-posture-vocabulary.md
head -15 /home/john/wardline/docs/adr/ADR-002-rename-tier-source-decorators.md
head -15 /home/john/wardline/docs/adr/ADR-003-split-rule-matrix-independence.md
head -15 /home/john/wardline/docs/adr/ADR-004-elspeth-enhancements.md
```

Compare the "Date" and "Affects" metadata in the table against each ADR's header. If any disagree, update the table in Step 7.

---

### Task 3.5: Merge reference/severity-matrix.md into Quick Reference, delete

**Files:**
- Delete: `site-src/reference/severity-matrix.md`

- [ ] **Step 1: Read severity-matrix.md content**

```bash
cat /home/john/wardline/site-src/reference/severity-matrix.md
```

- [ ] **Step 2: Verify Quick Reference rule matrix is sufficient**

Compare the severity info in `severity-matrix.md` to the "Rule matrix" table already in `site-src/reference/index.md` (from Task 3.2). The Quick Reference's "Severity band" column captures the essential severity information.

If `severity-matrix.md` contains additional cells (e.g. taint-state axis), extend the Quick Reference rule matrix to include a severity-by-taint-state breakdown. If it's only per-rule severity, the current Quick Reference covers it.

- [ ] **Step 3: Delete severity-matrix.md**

```bash
cd /home/john/wardline
git rm site-src/reference/severity-matrix.md
```

---

### Task 3.6: Merge reference/governance-retention.md into reference/manifest.md, delete

**Files:**
- Modify: `site-src/reference/manifest.md` (append governance retention section)
- Delete: `site-src/reference/governance-retention.md`

- [ ] **Step 1: Read both files**

```bash
cat /home/john/wardline/site-src/reference/governance-retention.md
cat /home/john/wardline/site-src/reference/manifest.md
```

- [ ] **Step 2: Append governance-retention content to manifest.md**

Append a new section to the end of `site-src/reference/manifest.md`:

```markdown

## Governance retention

*This section was formerly on a dedicated `governance-retention.md` page. It is now part of the Manifest reference because retention policy is a manifest-level configuration concern.*

> **Normative source:** [Specification §10.5 — Exception Register Retention](../spec/wardline-01-10-governance-model.md#retention)

[... paste content of governance-retention.md here, preserving existing headings and tables ...]
```

Copy the body of `governance-retention.md` verbatim below the new section header (omitting its own title heading if it duplicates "Governance retention").

- [ ] **Step 3: Delete governance-retention.md**

```bash
cd /home/john/wardline
git rm site-src/reference/governance-retention.md
```

---

### Task 3.7: Build and commit Phase 3

- [ ] **Step 1: Build with strict mode**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tee /tmp/mkdocs-phase3.log
```
Expected: build succeeds. New files are created but not yet in nav — mkdocs should still build (orphaned pages produce a warning with `--strict`, which may fail the build).

**If build fails with "orphaned pages" warnings:** that is expected — the new files will be added to nav in Phase 4. Run without `--strict` for Phase 3 verification:

```bash
mkdocs build 2>&1 | grep -i error
```
Expected: no errors (warnings about orphaned pages are OK for this phase).

- [ ] **Step 2: Commit**

```bash
cd /home/john/wardline
git add site-src/specification.md site-src/reference/index.md site-src/guides/index.md site-src/guides/conformance-roadmap.md site-src/assurance/ site-src/reference/manifest.md
git rm -f site-src/reference/severity-matrix.md site-src/reference/governance-retention.md 2>/dev/null || true
git commit -m "$(cat <<'EOF'
site: create new hub content

Create Specification landing page, Reference Quick Reference
data sheet, Conformance Roadmap guide, Assurance section hubs
(Verification Properties, Residual Risks, Audits, Decisions).

Merge severity-matrix.md into Quick Reference and
governance-retention.md into Manifest reference.

Files are not yet referenced from nav — Phase 4 restructures
mkdocs.yml nav to surface them.
EOF
)"
```

---

## Phase 4: Navigation Restructure

**Goal:** Rewrite `mkdocs.yml` nav to the target IA, surfacing the hidden §01-00 reading guide, Wardline Lite, Part II overview, semantic-equivalents, and the new hub pages. Correct the `site_description`.

---

### Task 4.1: Rewrite mkdocs.yml nav

**Files:**
- Modify: `mkdocs.yml` (full nav rewrite + site_description correction)

- [ ] **Step 1: Read current mkdocs.yml for nav position**

```bash
grep -n 'nav:\|site_description:' /home/john/wardline/mkdocs.yml
```
Note the line numbers.

- [ ] **Step 2: Correct site_description**

Replace the current `site_description` in `mkdocs.yml`:

```yaml
site_description: >-
  Semantic boundary enforcement framework. Defines a four-tier trust
  hierarchy and statically verifies that data flows respect those
  boundaries. Language-independent; reference bindings exist for
  Python and Java.
```

- [ ] **Step 3: Replace nav section**

Replace the existing `nav:` block in `mkdocs.yml` with the target tree:

```yaml
nav:
  - Home: index.md
  - Getting Started: getting-started.md
  - Specification:
      - specification.md
      - Start Here:
          - Reading Guide: spec/wardline-01-00-front-matter.md
          - Wardline Lite: spec/wardline-lite.md
      - Part I — Framework:
          - 1. Scope: spec/wardline-01-01-document-scope.md
          - 2. What a Wardline Is: spec/wardline-01-02-what-a-wardline-is.md
          - 3. The Problem: spec/wardline-01-03-the-problem-a-wardline-solves.md
          - 4. Non-Goals: spec/wardline-01-04-non-goals.md
          - 5. Authority Tier Model: spec/wardline-01-05-authority-tier-model.md
          - 6. Enforcement Spec: spec/wardline-01-06-authority-tier-enforcement-spec.md
          - 7. Annotation Vocabulary: spec/wardline-01-07-annotation-vocabulary.md
          - 8. Pattern Rules: spec/wardline-01-08-pattern-rules.md
          - 9. Enforcement Layers: spec/wardline-01-09-enforcement-layers.md
          - 10. Governance Model: spec/wardline-01-10-governance-model.md
          - 11. Verification Properties: spec/wardline-01-11-verification-properties.md
          - 12. Language Evaluation Criteria: spec/wardline-01-12-language-evaluation-criteria.md
          - 13. Residual Risks: spec/wardline-01-13-residual-risks.md
          - 14. Portability & Manifest Format: spec/wardline-01-14-portability-and-manifest-format.md
          - 15. Conformance: spec/wardline-01-15-conformance.md
      - Part II — Language Bindings:
          - Overview: spec/wardline-02-00-front-matter.md
          - A. Python Binding: spec/wardline-02-A-python-binding.md
          - B. Java Binding: spec/wardline-02-B-java-binding.md
      - Companion:
          - Semantic Equivalents:
              - Overview: spec/semantic-equivalents/README.md
              - PY-WL-001: spec/semantic-equivalents/py-wl-001.md
              - PY-WL-002: spec/semantic-equivalents/py-wl-002.md
              - PY-WL-003: spec/semantic-equivalents/py-wl-003.md
              - PY-WL-004: spec/semantic-equivalents/py-wl-004.md
              - PY-WL-005: spec/semantic-equivalents/py-wl-005.md
              - PY-WL-006: spec/semantic-equivalents/py-wl-006.md
              - PY-WL-007: spec/semantic-equivalents/py-wl-007.md
              - PY-WL-008: spec/semantic-equivalents/py-wl-008.md
              - PY-WL-009: spec/semantic-equivalents/py-wl-009.md
  - Reference:
      - reference/index.md
      - Rules: reference/rules.md
      - Taint States: reference/taint-states.md
      - Decorators: reference/decorators.md
      - Manifest: reference/manifest.md
      - CLI: reference/cli.md
      - SARIF Format: reference/sarif-format.md
      - Supplementary Groups: reference/supplementary-groups.md
      - Error Messages: reference/error-messages.md
      - Glossary: reference/glossary.md
  - Guides:
      - guides/index.md
      - Conformance Roadmap: guides/conformance-roadmap.md
      - Adopting Wardline: guides/adoption.md
      - CI Integration: guides/ci-integration.md
      - Governance: guides/governance.md
      - Governance Profiles: guides/profiles.md
      - Analysis Levels: guides/analysis-levels.md
      - Troubleshooting: guides/troubleshooting.md
  - Assurance & Decisions:
      - assurance/index.md
      - Verification Properties:
          - assurance/verification/index.md
          - "V&V Single Source of Truth — Cell Certification Matrix": verification/2026-04-12-v1-0-cell-certification-matrix.md
      - Residual Risks:
          - assurance/residual-risks/index.md
      - Audits:
          - assurance/audits/index.md
          - "Rule Conformance 2026-03-25": audits/rule-conformance-audit-2026-03-25.md
      - Decisions (ADRs):
          - assurance/decisions/index.md
          - "ADR-001 Taint State Rename": adr/ADR-001-rename-taint-states-to-posture-vocabulary.md
          - "ADR-002 Tier Source Decorators": adr/ADR-002-rename-tier-source-decorators.md
          - "ADR-003 Rule Matrix Split": adr/ADR-003-split-rule-matrix-independence.md
          - "ADR-004 ELSPETH Enhancements [DRAFT]": adr/ADR-004-elspeth-enhancements.md
      - Requirements:
          - "Spec Fitness": requirements/spec-fitness/
```

- [ ] **Step 4: Run strict build**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tee /tmp/mkdocs-phase4.log
```
Expected: build succeeds with no errors and no warnings.

Common failures:
- Missing file: check the path is correct and the file exists (use symlinks for `spec/`, `adr/`, etc.).
- Orphaned page: a page exists in `site-src/` but is not referenced in nav. Either add it to nav or remove it.

- [ ] **Step 5: Serve and spot-check key paths**

```bash
cd /home/john/wardline
mkdocs serve -a 127.0.0.1:8000 &
SERVE_PID=$!
sleep 3

# Verify previously-hidden content is reachable
curl -sf http://127.0.0.1:8000/spec/wardline-01-00-front-matter/ -o /dev/null && echo "§01-00 reading guide OK"
curl -sf http://127.0.0.1:8000/spec/wardline-lite/ -o /dev/null && echo "Wardline Lite OK"
curl -sf http://127.0.0.1:8000/spec/semantic-equivalents/py-wl-001/ -o /dev/null && echo "Semantic equivalents OK"

# Verify new hub pages render
curl -sf http://127.0.0.1:8000/reference/ -o /dev/null && echo "Quick Reference OK"
curl -sf http://127.0.0.1:8000/guides/conformance-roadmap/ -o /dev/null && echo "Conformance Roadmap OK"
curl -sf http://127.0.0.1:8000/assurance/ -o /dev/null && echo "Assurance index OK"
curl -sf http://127.0.0.1:8000/assurance/decisions/ -o /dev/null && echo "ADR index OK"
curl -sf http://127.0.0.1:8000/verification/2026-04-12-v1-0-cell-certification-matrix/ -o /dev/null && echo "Cell matrix OK"

kill $SERVE_PID
```
Expected: all eight "OK" lines print.

- [ ] **Step 6: Commit**

```bash
cd /home/john/wardline
git add mkdocs.yml
git commit -m "$(cat <<'EOF'
site: restructure navigation and correct site description

Rewrite mkdocs.yml nav to the target IA:
- Specification section becomes the anchor with Start Here group
  (exposing the hidden §01-00 reading guide and Wardline Lite),
  grouped Part I, Part II Overview (previously hidden), and
  Companion → Semantic Equivalents (previously orphaned).
- Reference section opens with Quick Reference data sheet.
- Guides section opens with Conformance Roadmap hub.
- New Assurance & Decisions top-level section surfaces the
  V&V cell certification matrix, residual risks, audits, and
  ADRs (ADR-004 flagged DRAFT).

Correct site_description from Python-first framing to language-
independent (Part I is language-agnostic, Part II has bindings).
EOF
)"
```

---

## Phase 5: Cross-Link Protocol

**Goal:** Add authority banners to Reference pages, prerequisites boxes to Guide pages, status admonitions to ADRs (with DRAFT warning on ADR-004), and bidirectional cross-links between spec §8 and the semantic-equivalents pages.

---

### Task 5.1: Add authority banners to 9 Reference pages

**Files:** Modify each of:
- `site-src/reference/rules.md`
- `site-src/reference/taint-states.md`
- `site-src/reference/decorators.md`
- `site-src/reference/manifest.md`
- `site-src/reference/cli.md`
- `site-src/reference/sarif-format.md`
- `site-src/reference/supplementary-groups.md`
- `site-src/reference/error-messages.md`
- `site-src/reference/glossary.md`

- [ ] **Step 1: Add banner to rules.md**

At the very top of `site-src/reference/rules.md`, immediately after any existing frontmatter but before the first `#` heading, insert:

```markdown
!!! info "Normative source"
    **Specification [§8 — Pattern Rules](../spec/wardline-01-08-pattern-rules.md)**
    This page is a quick reference for the rule set. For the canonical rule
    definitions, severity derivation, and exceptionability classes, read the
    spec chapter.
```

- [ ] **Step 2: Add banner to taint-states.md**

At the top of `site-src/reference/taint-states.md`, insert:

```markdown
!!! info "Normative source"
    **Specification [§6.1 — Effective States](../spec/wardline-01-06-authority-tier-enforcement-spec.md)**
    This page summarises the eight taint states and the join lattice.
    For the formal definition, restoration boundaries, and cross-language
    propagation, read the spec chapter.
```

- [ ] **Step 3: Add banner to decorators.md**

```markdown
!!! info "Normative source"
    **Specification [§7 — Annotation Vocabulary](../spec/wardline-01-07-annotation-vocabulary.md)**
    This page lists the decorator catalogue with `_wardline_*` attributes.
    For the normative decorator group definitions and transition semantics,
    read the spec chapter.
```

- [ ] **Step 4: Add banner to manifest.md**

```markdown
!!! info "Normative source"
    **Specification [§14 — Portability & Manifest Format](../spec/wardline-01-14-portability-and-manifest-format.md)**
    This page is a field-level reference for `wardline.yaml`. For the
    normative manifest design, overlay semantics, and JSON Schema, read
    the spec chapter. Governance retention details are anchored at
    [§10.5](../spec/wardline-01-10-governance-model.md).
```

- [ ] **Step 5: Add banner to cli.md**

```markdown
!!! info "Normative source"
    **Specification [§11.4 — Testing Requirements](../spec/wardline-01-11-verification-properties.md)** and [§14 — Manifest Format](../spec/wardline-01-14-portability-and-manifest-format.md)
    This page documents tool-specific CLI commands and flags. The
    commands implement the normative verification and manifest operations
    defined in the spec.
```

- [ ] **Step 6: Add banner to sarif-format.md**

```markdown
!!! info "Normative source"
    **Specification [§11.5 — Findings Interchange Format](../spec/wardline-01-11-verification-properties.md)**
    This page describes Wardline's SARIF v2.1.0 output. For the normative
    findings interchange requirements, read §11.5.
```

- [ ] **Step 7: Add banner to supplementary-groups.md**

```markdown
!!! info "Normative source"
    **Specification [§8.4 — Supplementary Rule Groups](../spec/wardline-01-08-pattern-rules.md)**
    This page explains how SCN-* and SUP-* rule groups relate to the
    canonical WL-* rules. For the normative organising principle, read §8.4.
```

- [ ] **Step 8: Add banner to error-messages.md**

```markdown
!!! info "Normative source"
    **Specification [§8 — Pattern Rules](../spec/wardline-01-08-pattern-rules.md)**
    This page catalogues canonical error messages produced by the scanner.
    Error text is tool-specific; the underlying rule definitions and
    severity are normative per §8.
```

- [ ] **Step 9: Add banner to glossary.md**

```markdown
!!! info "Normative source"
    **Specification [§2 — What a Wardline Is](../spec/wardline-01-02-what-a-wardline-is.md)**
    This glossary expands on the core definitions table in §2.1. For the
    normative definitions, read the spec chapter.
```

- [ ] **Step 10: Verify banners render**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tail -20
```
Expected: build succeeds.

Spot-check one rendered page:
```bash
mkdocs serve -a 127.0.0.1:8000 &
SERVE_PID=$!
sleep 3
curl -s http://127.0.0.1:8000/reference/rules/ | grep -c "Normative source" && echo "banner renders"
kill $SERVE_PID
```
Expected: grep finds "Normative source" (count ≥ 1).

- [ ] **Step 11: Commit**

```bash
cd /home/john/wardline
git add site-src/reference/*.md
git commit -m "site: add authority banners to reference pages (cross-link protocol → spec)"
```

---

### Task 5.2: Add prerequisites boxes to 6 Guide pages

**Files:** Modify each of:
- `site-src/guides/adoption.md`
- `site-src/guides/ci-integration.md`
- `site-src/guides/governance.md`
- `site-src/guides/profiles.md`
- `site-src/guides/analysis-levels.md`
- `site-src/guides/troubleshooting.md`

(`guides/index.md` and `guides/conformance-roadmap.md` already have their own intro sections from Task 3.3.)

- [ ] **Step 1: Add prereq box to adoption.md**

At the top of `site-src/guides/adoption.md` (after frontmatter, before first heading):

```markdown
!!! info "Prerequisites"
    This guide implements [Specification §15.3 — Phase 1: Lite Governance](../spec/wardline-01-15-conformance.md).
    Before you start, read [§5 Authority Tier Model](../spec/wardline-01-05-authority-tier-model.md)
    and [§7 Annotation Vocabulary](../spec/wardline-01-07-annotation-vocabulary.md) for the
    concepts this guide uses.
```

- [ ] **Step 2: Add prereq box to ci-integration.md**

```markdown
!!! info "Prerequisites"
    This guide wires the Wardline scanner into CI. Before you start, read
    [§14 Manifest Format](../spec/wardline-01-14-portability-and-manifest-format.md) for
    `wardline.yaml` structure and [§11.5 Findings Interchange](../spec/wardline-01-11-verification-properties.md)
    for the SARIF output contract.
```

- [ ] **Step 3: Add prereq box to governance.md**

```markdown
!!! info "Prerequisites"
    This guide implements the operational workflow for the exception register
    defined in [Specification §10 — Governance Model](../spec/wardline-01-10-governance-model.md).
    Read §10 in full before configuring governance in production.
```

- [ ] **Step 4: Add prereq box to profiles.md**

```markdown
!!! info "Prerequisites"
    This guide explains how to select between Lite, Core, and Assured
    governance profiles as defined in
    [Specification §15.4](../spec/wardline-01-15-conformance.md) and
    the governance capacity model in [§10.4](../spec/wardline-01-10-governance-model.md).
```

- [ ] **Step 5: Add prereq box to analysis-levels.md**

```markdown
!!! info "Prerequisites"
    This guide explains Level 1 / Level 2 / Level 3 call-graph analysis.
    The underlying enforcement layer model is defined in
    [Specification §9 — Enforcement Layers](../spec/wardline-01-09-enforcement-layers.md).
```

- [ ] **Step 6: Add prereq box to troubleshooting.md**

```markdown
!!! info "Prerequisites"
    Common scanner failures and their fixes. For the normative rule
    definitions behind each error, see
    [Specification §8 — Pattern Rules](../spec/wardline-01-08-pattern-rules.md).
```

- [ ] **Step 7: Build and verify**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tail -10
```
Expected: build succeeds.

- [ ] **Step 8: Commit**

```bash
cd /home/john/wardline
git add site-src/guides/*.md
git commit -m "site: add prerequisites boxes to guide pages (cross-link protocol → spec)"
```

---

### Task 5.3: Add ADR status admonitions

**Files:** Modify each of:
- `docs/adr/ADR-001-rename-taint-states-to-posture-vocabulary.md`
- `docs/adr/ADR-002-rename-tier-source-decorators.md`
- `docs/adr/ADR-003-split-rule-matrix-independence.md`
- `docs/adr/ADR-004-elspeth-enhancements.md`

- [ ] **Step 1: Read ADR-001 dates**

```bash
head -15 /home/john/wardline/docs/adr/ADR-001-rename-taint-states-to-posture-vocabulary.md
```
Note the exact acceptance date.

- [ ] **Step 2: Add ACCEPTED admonition to ADR-001**

Insert at the very top of `docs/adr/ADR-001-rename-taint-states-to-posture-vocabulary.md` (before any existing heading):

```markdown
!!! success "ACCEPTED 2026-03-12"
    This decision is accepted and folded into the v1.0 RC specification.
    Affects: §6 (Authority Tier Enforcement) · §7 (Annotation Vocabulary).
```

**If the actual date differs from 2026-03-12**, use the correct one from Step 1.

- [ ] **Step 3: Add ACCEPTED admonition to ADR-002**

```markdown
!!! success "ACCEPTED 2026-03-14"
    This decision is accepted and folded into the v1.0 RC specification.
    Affects: §7 (Annotation Vocabulary).
```

Adjust date to match the file.

- [ ] **Step 4: Add ACCEPTED admonition to ADR-003**

```markdown
!!! success "ACCEPTED 2026-03-18"
    This decision is accepted and folded into the v1.0 RC specification.
    Affects: §8 (Pattern Rules).
```

Adjust date to match the file.

- [ ] **Step 5: Add DRAFT warning to ADR-004**

Insert at the very top of `docs/adr/ADR-004-elspeth-enhancements.md`:

```markdown
!!! warning "DRAFT — NOT YET NORMATIVE"
    ADR-004 is a draft proposal under review. Its proposals — WL-009
    refinement, SUP-010, SUP-011 — are **not part of the v1.0 RC
    specification**. Do not implement against this ADR until it is
    accepted and folded into a subsequent spec release.

    Affects: §7 · §8 · Part II-A (Python Binding).
    Target release: post-v1.0 RC.
```

- [ ] **Step 6: Build and verify admonitions render**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tail -10
```
Expected: build succeeds.

```bash
mkdocs serve -a 127.0.0.1:8000 &
SERVE_PID=$!
sleep 3
curl -s http://127.0.0.1:8000/adr/ADR-004-elspeth-enhancements/ | grep -c 'DRAFT' && echo "ADR-004 DRAFT banner renders"
curl -s http://127.0.0.1:8000/adr/ADR-001-rename-taint-states-to-posture-vocabulary/ | grep -c 'ACCEPTED' && echo "ADR-001 ACCEPTED banner renders"
kill $SERVE_PID
```
Expected: both greps return non-zero counts.

- [ ] **Step 7: Commit**

```bash
cd /home/john/wardline
git add docs/adr/
git commit -m "site: add status admonitions to ADRs (ADR-004 flagged DRAFT)"
```

---

### Task 5.4: Cross-link spec §8 ↔ semantic-equivalents

**Files:**
- Modify: `docs/spec/wardline-01-08-pattern-rules.md` (add 9 per-rule footer links)
- Modify: `docs/spec/semantic-equivalents/py-wl-001.md` through `py-wl-009.md` (add 9 header banners)

- [ ] **Step 1: Read the spec §8 rule definitions to find anchor points**

```bash
grep -n '^### WL-\|^### PY-WL-\|^## WL-\|^## PY-WL-' /home/john/wardline/docs/spec/wardline-01-08-pattern-rules.md
```
Note the line numbers for each rule definition (WL-001 through WL-009).

- [ ] **Step 2: Append cross-reference to each WL-00x rule in §8**

For each rule WL-001 through WL-009, immediately after its definition (at the end of the rule's subsection, before the next `###` heading), insert:

```markdown

> → See [PY-WL-00X syntactic patterns](semantic-equivalents/py-wl-00x.md) for the living pattern catalogue.
```

Replace `00X`/`00x` with the actual rule number.

Use the Edit tool per-rule, since each insertion is unique to its rule context. You can find the next `###` heading or end of file and insert the cross-reference line right before it.

- [ ] **Step 3: Add header banner to semantic-equivalents/py-wl-001.md**

At the very top of `docs/spec/semantic-equivalents/py-wl-001.md` (after any existing frontmatter, before the first heading), insert:

```markdown
!!! info "Normative source"
    **Specification [§8 — Pattern Rules, WL-001](../wardline-01-08-pattern-rules.md#wl-001)**
    This page is a living catalogue of syntactic patterns that trigger
    WL-001. For the normative rule definition, severity, and
    exceptionability, see §8.
```

- [ ] **Step 4: Add the same banner to py-wl-002.md through py-wl-009.md**

Repeat Step 3 for each of `py-wl-002.md`, `py-wl-003.md`, `py-wl-004.md`, `py-wl-005.md`, `py-wl-006.md`, `py-wl-007.md`, `py-wl-008.md`, `py-wl-009.md`, adjusting the rule number (`WL-002`, `WL-003`, ...) in each banner.

- [ ] **Step 5: Build and verify cross-links resolve**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tail -20
```
Expected: build succeeds. No broken link errors.

- [ ] **Step 6: Commit**

```bash
cd /home/john/wardline
git add docs/spec/wardline-01-08-pattern-rules.md docs/spec/semantic-equivalents/
git commit -m "spec: cross-link §8 ↔ semantic-equivalents pattern catalogues"
```

---

## Phase 6: Spec Chapter Metadata + Template Override

**Goal:** Add `spec_chapter` frontmatter to 20 spec files and create the mkdocs Material template override that injects the chapter header and footer.

---

### Task 6.1: Create the template override

**Files:**
- Create: `site-src/overrides/main.html` (or modify if exists)

- [ ] **Step 1: Check current overrides directory**

```bash
ls /home/john/wardline/site-src/overrides/
cat /home/john/wardline/site-src/overrides/main.html 2>/dev/null
```
If `main.html` does not exist, create it from scratch. If it exists, extend it (preserve the existing blocks and add the new spec chapter blocks).

- [ ] **Step 2: Write site-src/overrides/main.html**

```jinja2
{% extends "base.html" %}

{#
  Wardline spec chapter template override.

  When a page has `spec_chapter` in its meta, inject a header and footer
  that identify it as part of the normative specification and link to
  previous/next chapters and derived pages.
#}

{% block content %}
  {% if page.meta and page.meta.spec_chapter %}
    <div class="spec-chapter-header">
      <strong>
        Specification · Part {{ page.meta.spec_part }} · Chapter {{ page.meta.spec_chapter }}
      </strong>
      <span class="spec-chapter-status">v1.0 RC · Normative</span>
    </div>
  {% endif %}

  {{ super() }}

  {% if page.meta and page.meta.spec_chapter %}
    <div class="spec-chapter-footer">
      <h3>Related</h3>
      <ul class="spec-chapter-related">
        {% if page.meta.spec_prev %}
          <li><strong>Previous:</strong>
            <a href="../{{ page.meta.spec_prev }}/">{{ page.meta.spec_prev_title | default(page.meta.spec_prev) }}</a>
          </li>
        {% endif %}
        {% if page.meta.spec_next %}
          <li><strong>Next:</strong>
            <a href="../{{ page.meta.spec_next }}/">{{ page.meta.spec_next_title | default(page.meta.spec_next) }}</a>
          </li>
        {% endif %}
        {% if page.meta.derived_pages %}
          <li><strong>Derived pages:</strong>
            <ul>
              {% for p in page.meta.derived_pages %}
                <li><a href="/{{ p.path }}/">{{ p.title }}</a></li>
              {% endfor %}
            </ul>
          </li>
        {% endif %}
        <li><strong>Source:</strong>
          <code>docs/spec/{{ page.file.src_uri | replace('spec/', '') }}</code>
        </li>
      </ul>
    </div>
  {% endif %}
{% endblock %}
```

- [ ] **Step 3: Add supporting CSS to stylesheets**

Append to `site-src/stylesheets/extra.css` (create if missing):

```css
/* Spec chapter header/footer */

.spec-chapter-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem 0.75rem;
  margin-bottom: 1rem;
  background: var(--md-default-fg-color--lightest, #eee);
  border-left: 3px solid var(--md-primary-fg-color, #4051b5);
  font-size: 0.85rem;
}

.spec-chapter-status {
  color: var(--md-default-fg-color--light, #666);
  font-variant: small-caps;
  letter-spacing: 0.05em;
}

.spec-chapter-footer {
  margin-top: 3rem;
  padding: 1rem 1.25rem;
  background: var(--md-default-fg-color--lightest, #f7f7f7);
  border-top: 2px solid var(--md-primary-fg-color, #4051b5);
}

.spec-chapter-footer h3 {
  margin-top: 0;
  font-size: 1rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--md-default-fg-color--light, #666);
}

.spec-chapter-related {
  list-style: none;
  padding-left: 0;
}

.spec-chapter-related > li {
  margin-bottom: 0.5rem;
}

.spec-chapter-related ul {
  list-style: disc;
  margin-left: 1.5rem;
}
```

- [ ] **Step 4: Ensure mkdocs.yml references the extra CSS**

```bash
grep -n 'extra_css\|stylesheets' /home/john/wardline/mkdocs.yml
```
Expected: `extra_css:` block exists. If `stylesheets/extra.css` is not listed, add it:

```yaml
extra_css:
  - stylesheets/extra.css
```

- [ ] **Step 5: Build to confirm template compiles**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tail -20
```
Expected: build succeeds. No Jinja2 template errors.

If Jinja2 raises errors about `page.meta`, the test pages without `spec_chapter` frontmatter trigger the `if` fallthrough — should be safe because `{% if page.meta and page.meta.spec_chapter %}` guards against missing meta.

- [ ] **Step 6: Commit**

```bash
cd /home/john/wardline
git add site-src/overrides/main.html site-src/stylesheets/extra.css mkdocs.yml
git commit -m "site: add mkdocs template override for spec chapter header/footer"
```

---

### Task 6.2: Add spec_chapter frontmatter to Part I chapters (15 files)

**Files:** Modify each of `docs/spec/wardline-01-01-*.md` through `docs/spec/wardline-01-15-*.md`.

- [ ] **Step 1: Add frontmatter to §1 (Document Scope)**

Insert at the very top of `docs/spec/wardline-01-01-document-scope.md`:

```yaml
---
spec_chapter: 1
spec_part: "I"
spec_title: "Document Scope"
spec_prev: "wardline-01-00-front-matter"
spec_prev_title: "Reading Guide"
spec_next: "wardline-01-02-what-a-wardline-is"
spec_next_title: "§2 What a Wardline Is"
derived_pages: []
---
```

- [ ] **Step 2: Add frontmatter to §2 (What a Wardline Is)**

```yaml
---
spec_chapter: 2
spec_part: "I"
spec_title: "What a Wardline Is"
spec_prev: "wardline-01-01-document-scope"
spec_prev_title: "§1 Document Scope"
spec_next: "wardline-01-03-the-problem-a-wardline-solves"
spec_next_title: "§3 The Problem"
derived_pages:
  - { title: "Glossary", path: "reference/glossary" }
---
```

- [ ] **Step 3: Add frontmatter to §3 (The Problem)**

```yaml
---
spec_chapter: 3
spec_part: "I"
spec_title: "The Problem a Wardline Solves"
spec_prev: "wardline-01-02-what-a-wardline-is"
spec_prev_title: "§2 What a Wardline Is"
spec_next: "wardline-01-04-non-goals"
spec_next_title: "§4 Non-Goals"
derived_pages: []
---
```

- [ ] **Step 4: Add frontmatter to §4 (Non-Goals)**

```yaml
---
spec_chapter: 4
spec_part: "I"
spec_title: "Non-Goals"
spec_prev: "wardline-01-03-the-problem-a-wardline-solves"
spec_prev_title: "§3 The Problem"
spec_next: "wardline-01-05-authority-tier-model"
spec_next_title: "§5 Authority Tier Model"
derived_pages: []
---
```

- [ ] **Step 5: Add frontmatter to §5 (Authority Tier Model)**

```yaml
---
spec_chapter: 5
spec_part: "I"
spec_title: "Authority Tier Model"
spec_prev: "wardline-01-04-non-goals"
spec_prev_title: "§4 Non-Goals"
spec_next: "wardline-01-06-authority-tier-enforcement-spec"
spec_next_title: "§6 Enforcement Spec"
derived_pages:
  - { title: "Getting Started (Tier model intro)", path: "getting-started" }
  - { title: "Reference: Taint States", path: "reference/taint-states" }
---
```

- [ ] **Step 6: Add frontmatter to §6 (Authority Tier Enforcement Spec)**

```yaml
---
spec_chapter: 6
spec_part: "I"
spec_title: "Authority Tier Enforcement Spec"
spec_prev: "wardline-01-05-authority-tier-model"
spec_prev_title: "§5 Authority Tier Model"
spec_next: "wardline-01-07-annotation-vocabulary"
spec_next_title: "§7 Annotation Vocabulary"
derived_pages:
  - { title: "Reference: Taint States", path: "reference/taint-states" }
  - { title: "Guide: Analysis Levels", path: "guides/analysis-levels" }
---
```

- [ ] **Step 7: Add frontmatter to §7 (Annotation Vocabulary)**

```yaml
---
spec_chapter: 7
spec_part: "I"
spec_title: "Annotation Vocabulary"
spec_prev: "wardline-01-06-authority-tier-enforcement-spec"
spec_prev_title: "§6 Enforcement Spec"
spec_next: "wardline-01-08-pattern-rules"
spec_next_title: "§8 Pattern Rules"
derived_pages:
  - { title: "Reference: Decorators", path: "reference/decorators" }
---
```

- [ ] **Step 8: Add frontmatter to §8 (Pattern Rules)**

```yaml
---
spec_chapter: 8
spec_part: "I"
spec_title: "Pattern Rules"
spec_prev: "wardline-01-07-annotation-vocabulary"
spec_prev_title: "§7 Annotation Vocabulary"
spec_next: "wardline-01-09-enforcement-layers"
spec_next_title: "§9 Enforcement Layers"
derived_pages:
  - { title: "Reference: Rules", path: "reference/rules" }
  - { title: "Reference: Quick Reference (rule matrix)", path: "reference" }
  - { title: "Semantic Equivalents", path: "spec/semantic-equivalents/README" }
---
```

- [ ] **Step 9: Add frontmatter to §9 (Enforcement Layers)**

```yaml
---
spec_chapter: 9
spec_part: "I"
spec_title: "Enforcement Layers"
spec_prev: "wardline-01-08-pattern-rules"
spec_prev_title: "§8 Pattern Rules"
spec_next: "wardline-01-10-governance-model"
spec_next_title: "§10 Governance Model"
derived_pages:
  - { title: "Guide: Analysis Levels", path: "guides/analysis-levels" }
---
```

- [ ] **Step 10: Add frontmatter to §10 (Governance Model)**

```yaml
---
spec_chapter: 10
spec_part: "I"
spec_title: "Governance Model"
spec_prev: "wardline-01-09-enforcement-layers"
spec_prev_title: "§9 Enforcement Layers"
spec_next: "wardline-01-11-verification-properties"
spec_next_title: "§11 Verification Properties"
derived_pages:
  - { title: "Guide: Governance", path: "guides/governance" }
  - { title: "Guide: Governance Profiles", path: "guides/profiles" }
---
```

- [ ] **Step 11: Add frontmatter to §11 (Verification Properties)**

```yaml
---
spec_chapter: 11
spec_part: "I"
spec_title: "Verification Properties"
spec_prev: "wardline-01-10-governance-model"
spec_prev_title: "§10 Governance Model"
spec_next: "wardline-01-12-language-evaluation-criteria"
spec_next_title: "§12 Language Evaluation Criteria"
derived_pages:
  - { title: "Assurance: Verification Properties hub", path: "assurance/verification" }
  - { title: "V&V Cell Certification Matrix", path: "verification/2026-04-12-v1-0-cell-certification-matrix" }
---
```

- [ ] **Step 12: Add frontmatter to §12 (Language Evaluation Criteria)**

```yaml
---
spec_chapter: 12
spec_part: "I"
spec_title: "Language Evaluation Criteria"
spec_prev: "wardline-01-11-verification-properties"
spec_prev_title: "§11 Verification Properties"
spec_next: "wardline-01-13-residual-risks"
spec_next_title: "§13 Residual Risks"
derived_pages: []
---
```

- [ ] **Step 13: Add frontmatter to §13 (Residual Risks)**

```yaml
---
spec_chapter: 13
spec_part: "I"
spec_title: "Residual Risks"
spec_prev: "wardline-01-12-language-evaluation-criteria"
spec_prev_title: "§12 Language Evaluation Criteria"
spec_next: "wardline-01-14-portability-and-manifest-format"
spec_next_title: "§14 Portability & Manifest Format"
derived_pages:
  - { title: "Assurance: Residual Risks hub", path: "assurance/residual-risks" }
---
```

- [ ] **Step 14: Add frontmatter to §14 (Portability & Manifest Format)**

```yaml
---
spec_chapter: 14
spec_part: "I"
spec_title: "Portability and Manifest Format"
spec_prev: "wardline-01-13-residual-risks"
spec_prev_title: "§13 Residual Risks"
spec_next: "wardline-01-15-conformance"
spec_next_title: "§15 Conformance"
derived_pages:
  - { title: "Reference: Manifest", path: "reference/manifest" }
  - { title: "Guide: CI Integration", path: "guides/ci-integration" }
---
```

- [ ] **Step 15: Add frontmatter to §15 (Conformance)**

```yaml
---
spec_chapter: 15
spec_part: "I"
spec_title: "Conformance Profiles"
spec_prev: "wardline-01-14-portability-and-manifest-format"
spec_prev_title: "§14 Portability & Manifest Format"
spec_next: "wardline-02-00-front-matter"
spec_next_title: "Part II Overview"
derived_pages:
  - { title: "Guide: Conformance Roadmap", path: "guides/conformance-roadmap" }
  - { title: "Guide: Adopting Wardline", path: "guides/adoption" }
  - { title: "Guide: Governance Profiles", path: "guides/profiles" }
---
```

- [ ] **Step 16: Build and verify**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tail -20
```
Expected: build succeeds.

- [ ] **Step 17: Spot-check §5 renders with header and footer**

```bash
mkdocs serve -a 127.0.0.1:8000 &
SERVE_PID=$!
sleep 3
curl -s http://127.0.0.1:8000/spec/wardline-01-05-authority-tier-model/ | grep -c 'Specification · Part I · Chapter 5'
curl -s http://127.0.0.1:8000/spec/wardline-01-05-authority-tier-model/ | grep -c 'spec-chapter-footer'
kill $SERVE_PID
```
Expected: both greps return count ≥ 1.

- [ ] **Step 18: Commit**

```bash
cd /home/john/wardline
git add docs/spec/wardline-01-*.md
git commit -m "spec: add chapter metadata frontmatter for auto-rendered header/footer (Part I)"
```

---

### Task 6.3: Add spec_chapter frontmatter to Part II + front matter + Lite (5 files)

**Files:**
- `docs/spec/wardline-01-00-front-matter.md`
- `docs/spec/wardline-02-00-front-matter.md`
- `docs/spec/wardline-02-A-python-binding.md`
- `docs/spec/wardline-02-B-java-binding.md`
- `docs/spec/wardline-lite.md`

- [ ] **Step 1: Frontmatter for wardline-01-00-front-matter.md (Reading Guide)**

```yaml
---
spec_chapter: 0
spec_part: "I"
spec_title: "Reading Guide"
spec_prev: ""
spec_next: "wardline-01-01-document-scope"
spec_next_title: "§1 Document Scope"
derived_pages: []
---
```

- [ ] **Step 2: Frontmatter for wardline-02-00-front-matter.md (Part II Overview)**

```yaml
---
spec_chapter: 0
spec_part: "II"
spec_title: "Language Bindings Overview"
spec_prev: "wardline-01-15-conformance"
spec_prev_title: "§15 Conformance"
spec_next: "wardline-02-A-python-binding"
spec_next_title: "Part II-A Python Binding"
derived_pages: []
---
```

- [ ] **Step 3: Frontmatter for wardline-02-A-python-binding.md**

```yaml
---
spec_chapter: "A"
spec_part: "II"
spec_title: "Python Binding"
spec_prev: "wardline-02-00-front-matter"
spec_prev_title: "Part II Overview"
spec_next: "wardline-02-B-java-binding"
spec_next_title: "Part II-B Java Binding"
derived_pages:
  - { title: "Reference: Decorators", path: "reference/decorators" }
  - { title: "Reference: Rules", path: "reference/rules" }
---
```

- [ ] **Step 4: Frontmatter for wardline-02-B-java-binding.md**

```yaml
---
spec_chapter: "B"
spec_part: "II"
spec_title: "Java Binding"
spec_prev: "wardline-02-A-python-binding"
spec_prev_title: "Part II-A Python Binding"
spec_next: "wardline-lite"
spec_next_title: "Wardline Lite (Companion)"
derived_pages: []
---
```

- [ ] **Step 5: Frontmatter for wardline-lite.md**

```yaml
---
spec_chapter: "Lite"
spec_part: "Companion"
spec_title: "Wardline Lite — 5-Question Review Guide"
spec_prev: "wardline-02-B-java-binding"
spec_prev_title: "Part II-B Java Binding"
spec_next: ""
derived_pages: []
---
```

- [ ] **Step 6: Build and verify**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tail -20
```
Expected: build succeeds.

```bash
mkdocs serve -a 127.0.0.1:8000 &
SERVE_PID=$!
sleep 3
curl -s http://127.0.0.1:8000/spec/wardline-02-A-python-binding/ | grep -c 'Part II'
curl -s http://127.0.0.1:8000/spec/wardline-lite/ | grep -c 'Companion'
kill $SERVE_PID
```
Expected: both greps return non-zero counts.

- [ ] **Step 7: Commit**

```bash
cd /home/john/wardline
git add docs/spec/wardline-01-00-front-matter.md docs/spec/wardline-02-*.md docs/spec/wardline-lite.md
git commit -m "spec: add chapter metadata frontmatter for Part II, front matter, and Lite"
```

---

## Phase 7: Home and Getting Started Polish

**Goal:** Rewrite the home page pitch and add audience routing cards; add inline spec references and a "Next steps" footer to Getting Started.

---

### Task 7.1: Rewrite the home page

**Files:**
- Modify: `site-src/index.md`

- [ ] **Step 1: Read current index.md**

```bash
cat /home/john/wardline/site-src/index.md
```
Note the current structure — it likely has a hero section, maybe feature cards, maybe links.

- [ ] **Step 2: Replace pitch with language-independent framing**

Rewrite the top of `site-src/index.md` (preserving any existing hero imagery or theme markers, but replacing the text). The new pitch:

```markdown
---
title: Wardline
hide:
  - navigation
  - toc
---

# Wardline

**Semantic boundary enforcement framework.**

Wardline defines a four-tier trust hierarchy and statically verifies that data flows respect those boundaries. The framework is language-independent; reference bindings exist for **Python** and **Java**.

## Where do you want to start?

<div class="grid cards" markdown>

- :material-rocket-launch: **New here?**

    ---

    Install, run your first scan, and read your first finding in under an hour.

    [:octicons-arrow-right-24: Getting Started](getting-started.md)

- :material-account-group: **Adopting it?**

    ---

    The full Phase 0 → Phase 1 → Phase 2 → Phase 3 roll-out arc, with governance profiles.

    [:octicons-arrow-right-24: Conformance Roadmap](guides/conformance-roadmap.md)

- :material-shield-check: **Assessing it?**

    ---

    Verification properties, residual risks, audit evidence, and the V&V cell certification matrix.

    [:octicons-arrow-right-24: Assurance & Decisions](assurance/index.md)

- :material-wrench: **Implementing a binding?**

    ---

    Language evaluation criteria, the normative binding contract, Python and Java references.

    [:octicons-arrow-right-24: Specification Part II](specification.md)

</div>

## What Wardline is

Wardline is *not* a Python linter or a taint tracker. It is a semantic boundary enforcement framework — a formal model of trust relationships between data sources and the code that acts on them. The scanner is one enforcement layer among four; governance is another; structural type guarantees are a third; the annotation vocabulary itself is the fourth.

For the complete definition, read [Specification §2 — What a Wardline Is](spec/wardline-01-02-what-a-wardline-is.md).
```

- [ ] **Step 3: Build and spot-check**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tail -10
```
Expected: build succeeds.

```bash
mkdocs serve -a 127.0.0.1:8000 &
SERVE_PID=$!
sleep 3
curl -s http://127.0.0.1:8000/ | grep -c 'Semantic boundary enforcement framework'
curl -s http://127.0.0.1:8000/ | grep -c 'language-independent'
kill $SERVE_PID
```
Expected: both greps return count ≥ 1.

- [ ] **Step 4: Commit**

```bash
cd /home/john/wardline
git add site-src/index.md
git commit -m "site: rewrite home page with language-independent pitch and audience routing cards"
```

---

### Task 7.2: Add inline spec references to Getting Started

**Files:**
- Modify: `site-src/getting-started.md`

- [ ] **Step 1: Read current getting-started.md**

```bash
cat /home/john/wardline/site-src/getting-started.md
```

- [ ] **Step 2: Add inline spec references**

Find sections that introduce the core concepts and add parenthetical spec refs. Typical edits:

- After first mention of the "four-tier trust model" / "authority tiers", add: `(see [Specification §5](spec/wardline-01-05-authority-tier-model.md) for the formal model)`
- After first mention of decorators / `@integral_source` / `@external_boundary` / `@validates_shape`, add: `(see [Specification §7](spec/wardline-01-07-annotation-vocabulary.md) for the complete vocabulary)`
- After first mention of rules / PY-WL-001, add: `(see [Specification §8](spec/wardline-01-08-pattern-rules.md) for the complete rule set)`
- After first mention of `wardline.yaml` / manifest, add: `(see [Specification §14](spec/wardline-01-14-portability-and-manifest-format.md) for the full manifest format)`

Use Edit with exact context to make each insertion.

- [ ] **Step 3: Append "Next steps" footer**

At the very end of `site-src/getting-started.md`, append:

```markdown

---

## Where next?

You've run your first scan and read your first findings. Here are the three most common next steps:

- **Adopt Wardline in your team** — Read the [Conformance Roadmap](guides/conformance-roadmap.md) for the full Phase 0 → Phase 1 → Phase 2 → Phase 3 adoption arc.
- **Understand the model** — Read the [Specification Start Here](specification.md) page for the reading guide and choose your path through the normative spec.
- **Look something up** — The [Quick Reference](reference/index.md) has rule, taint state, decorator, manifest, and CLI cheat-sheets on one page.
```

- [ ] **Step 4: Build and verify**

```bash
cd /home/john/wardline
mkdocs build --strict 2>&1 | tail -10
```
Expected: build succeeds.

- [ ] **Step 5: Commit**

```bash
cd /home/john/wardline
git add site-src/getting-started.md
git commit -m "site: add inline spec refs and next-steps footer to Getting Started"
```

---

## Phase 8: Final Validation

**Goal:** Walk the 17 acceptance criteria from the design spec Section 9, run strict build, verify every key navigation path, confirm no regressions.

---

### Task 8.1: Full strict build + link spot-check

- [ ] **Step 1: Clean build from scratch**

```bash
cd /home/john/wardline
rm -rf site/
mkdocs build --strict 2>&1 | tee /tmp/mkdocs-final.log
```
Expected: build succeeds with no errors, no warnings.

- [ ] **Step 2: Verify all acceptance criteria URLs resolve**

```bash
cd /home/john/wardline
mkdocs serve -a 127.0.0.1:8000 &
SERVE_PID=$!
sleep 3

# Criteria 1–5: navigation and discoverability
curl -sf http://127.0.0.1:8000/specification/ -o /dev/null && echo "1. specification landing OK"
! curl -sf http://127.0.0.1:8000/spec/ -o /dev/null 2>/dev/null && echo "   /spec/ root is not a separate landing"
curl -sf http://127.0.0.1:8000/spec/wardline-01-00-front-matter/ -o /dev/null && echo "2. §01-00 reading guide OK"
curl -sf http://127.0.0.1:8000/spec/wardline-lite/ -o /dev/null && echo "3. Wardline Lite OK"
curl -sf http://127.0.0.1:8000/spec/wardline-02-00-front-matter/ -o /dev/null && echo "4. Part II overview OK"
curl -sf http://127.0.0.1:8000/spec/semantic-equivalents/py-wl-001/ -o /dev/null && echo "5. semantic-equivalents OK"

# Criteria 6–10: cross-link protocol
curl -s http://127.0.0.1:8000/reference/rules/ | grep -c 'Normative source' | xargs -I{} test {} -gt 0 && echo "6. Reference banner OK"
curl -s http://127.0.0.1:8000/guides/adoption/ | grep -c 'Prerequisites' | xargs -I{} test {} -gt 0 && echo "7. Guide prereq box OK"
curl -s http://127.0.0.1:8000/spec/wardline-01-05-authority-tier-model/ | grep -c 'spec-chapter-footer' | xargs -I{} test {} -gt 0 && echo "8. Spec chapter footer OK"
curl -s http://127.0.0.1:8000/adr/ADR-004-elspeth-enhancements/ | grep -c 'DRAFT' | xargs -I{} test {} -gt 0 && echo "9. ADR-004 DRAFT warning OK"

# Criteria 11–14: new derived content
curl -s http://127.0.0.1:8000/reference/ | grep -c 'Quick Reference' | xargs -I{} test {} -gt 0 && echo "11. Quick Reference data sheet OK"
curl -sf http://127.0.0.1:8000/guides/conformance-roadmap/ -o /dev/null && echo "12. Conformance Roadmap OK"
curl -sf http://127.0.0.1:8000/assurance/ -o /dev/null && echo "13a. Assurance index OK"
curl -sf http://127.0.0.1:8000/assurance/verification/ -o /dev/null && echo "13b. Verification Properties hub OK"
curl -sf http://127.0.0.1:8000/assurance/residual-risks/ -o /dev/null && echo "13c. Residual Risks hub OK"
curl -sf http://127.0.0.1:8000/assurance/audits/ -o /dev/null && echo "13d. Audits index OK"
curl -sf http://127.0.0.1:8000/assurance/decisions/ -o /dev/null && echo "13e. Decisions index OK"
curl -s http://127.0.0.1:8000/assurance/verification/ | grep -c 'Cell Certification Matrix' | xargs -I{} test {} -gt 0 && echo "14. Cell matrix headline OK"

# Criterion 17: Home page framing
curl -s http://127.0.0.1:8000/ | grep -c 'language-independent' | xargs -I{} test {} -gt 0 && echo "17. language-independent framing OK"

kill $SERVE_PID
```

Expected: every line prints its "OK" message. Any missing or failing line must be investigated before proceeding.

---

### Task 8.2: Repository hygiene check

- [ ] **Step 1: Verify docs/ contains only authoritative content**

```bash
ls /home/john/wardline/docs/
```
Expected output (in some order):
```
adr
audits
requirements
spec
superpowers
verification
```
No `archive`, `design`, `plans`, `session-log-*`, `index.md`, `getting-started.md`, `reference`, `guides`, `specification.md`, `stylesheets`, `javascripts`, `assets`, or `404.html`.

- [ ] **Step 2: Verify site-src/ contains website + symlinks**

```bash
ls -la /home/john/wardline/site-src/
```
Expected:
- Directories: `assets`, `javascripts`, `stylesheets`, `overrides`, `reference`, `guides`, `assurance`
- Symlinks: `spec -> ../docs/spec`, `adr -> ../docs/adr`, `audits -> ../docs/audits`, `verification -> ../docs/verification`, `requirements -> ../docs/requirements`
- Files: `index.md`, `getting-started.md`, `specification.md`, maybe `404.html`, `sitemap.xml`, `tags.json`

- [ ] **Step 3: Verify docs/verification/ is clean**

```bash
ls /home/john/wardline/docs/verification/
```
Expected: `2026-04-12-v1-0-cell-certification-matrix.md` and possibly `README.md` (if retained as authoritative). No `*-PROMPT.md`, `SESSION-PICKUP-*.md`, or `RENAME-*.md` files.

---

### Task 8.3: Visual walk

Manual walk (do this in a real browser, not curl):

- [ ] **Step 1: Start serve**

```bash
cd /home/john/wardline
mkdocs serve -a 127.0.0.1:8000
```
Leave running in a terminal. Open `http://127.0.0.1:8000/` in a browser.

- [ ] **Step 2: Walk the five audience journeys**

1. **Home → Getting Started card → spec §5 link → Related footer → back to Getting Started.**
   - Click the "New here?" card → verify it lands on Getting Started.
   - Click the inline `§5` link → verify spec chapter 5 loads with the header strip and footer box.
   - In the footer, click the "Getting Started" derived-page link → verify navigation back.

2. **Home → Adopting it? card → Conformance Roadmap → §15.3 Phase 1 → back.**
   - Click "Adopting it?" → lands on Conformance Roadmap.
   - Click the Phase 1 normative link → lands on §15.
   - Back button twice.

3. **Home → Assessing it? card → Assurance index → Verification Properties → Cell Certification Matrix.**
   - Click "Assessing it?" → lands on Assurance index.
   - Click "Verification Properties" → lands on hub.
   - Click the Cell Certification Matrix link → lands on the matrix page.

4. **Home → Specification landing → Start Here → Reading Guide → §1.**
   - Click the Specification link in top nav → lands on grouped landing page.
   - Click "Reading Guide" in Start Here → §01-00 front matter renders.
   - Click "§1 Document Scope" in footer "Next" → §1 renders with header.

5. **ADR path: top nav → Assurance & Decisions → Decisions → ADR-004.**
   - Verify ADR-004 page opens with the **DRAFT** admonition visible at the top.
   - Verify the admonition text says "not part of the v1.0 RC specification" and "do not implement".

- [ ] **Step 3: Walk the cross-link protocol**

1. **Reference → Rules page → banner → spec §8 → footer Related: Rules → back.**
2. **Guides → Adoption → prereq box → spec §15.3 → footer → back.**

- [ ] **Step 4: Stop serve**

Press Ctrl+C in the serve terminal.

---

### Task 8.4: Final commit and acceptance sign-off

- [ ] **Step 1: Check git status**

```bash
cd /home/john/wardline
git status
git log --oneline main..HEAD
```
Expected: clean working tree; 8-10 commits ahead of main, one per phase plus the cross-link subphases.

- [ ] **Step 2: Verify the 17 acceptance criteria**

Walk the list from the design spec Section 9 one more time, checking each against the built site. For each criterion, mark pass/fail:

1. [ ] Exactly one specification landing page exists; `/spec/` does not render a separate index.
2. [ ] `wardline-01-00-front-matter.md` reachable from nav at Specification → Start Here → Reading Guide.
3. [ ] `wardline-lite.md` reachable from nav at Specification → Start Here → Wardline Lite.
4. [ ] `wardline-02-00-front-matter.md` reachable from nav at Specification → Part II → Overview.
5. [ ] All nine `semantic-equivalents/py-wl-00N.md` reachable at Specification → Companion → Semantic Equivalents.
6. [ ] Every individual Reference page begins with `!!! info "Normative source"` admonition.
7. [ ] Every Guide page begins with `!!! info "Prerequisites"` admonition.
8. [ ] Every spec chapter ends with an auto-rendered "Related" footer.
9. [ ] Every ADR has a status admonition; ADR-004 has DRAFT warning.
10. [ ] `spec/wardline-01-08-pattern-rules.md` has per-rule footers to semantic-equivalents; each `py-wl-00N.md` has header banner to §8.
11. [ ] `site-src/reference/index.md` renders the Quick Reference data sheet with six table groups.
12. [ ] `site-src/guides/conformance-roadmap.md` exists and links into the six §15 sub-sections.
13. [ ] `assurance/index.md`, `verification/index.md`, `residual-risks/index.md`, `audits/index.md`, `decisions/index.md` all exist.
14. [ ] Verification Properties hub lists Cell Certification Matrix as headline piece.
15. [ ] `docs/` contains only authoritative content (spec, adr, audits, requirements, verification, superpowers).
16. [ ] `site-src/` contains website source plus five symlinks.
17. [ ] Home page pitch no longer says "for Python" — reflects language-independent framing.

If any fail: fix inline with targeted commits before final merge.

- [ ] **Step 3: Final commit or tag**

If all 17 pass and the build is clean, the restructure is complete. No additional commit is needed — the phase commits are the final state.

Optionally tag the restructure completion:
```bash
cd /home/john/wardline
git tag site-restructure-complete
```

---

## Rollback

If a regression is discovered after any phase:

- **Phases 1–4:** `git revert <commit>` each phase commit. Each phase leaves a buildable state, so partial rollback is safe.
- **Phases 5–7:** Individual cross-link banners, spec chapter metadata, and home/getting-started changes can be reverted file-by-file without affecting nav structure.
- **Template override (Task 6.1):** Reverting `site-src/overrides/main.html` disables the auto-injected headers/footers without breaking page content (the `spec_chapter` frontmatter is ignored if the template doesn't reference it).

At no point does the restructure cause data loss: all content moves are git-tracked, and all deletions are of files preserved in git history.

---

## Summary

- **Phases:** 8
- **Total tasks:** 30 (Phase 1: 6 · Phase 2: 3 · Phase 3: 7 · Phase 4: 1 · Phase 5: 4 · Phase 6: 3 · Phase 7: 2 · Phase 8: 4)
- **Total steps:** ~180
- **Estimated effort:** 15–20 hours
- **Total commits:** ~13 (one per phase sub-unit)
- **New files created:** 10
- **Files moved:** ~30
- **Files deleted:** ~15 plus whole directories
- **Files edited:** ~50 (9 reference + 6 guides + 4 ADRs + 20 spec frontmatter + 10 semantic-equivalents links + home + getting-started + mkdocs.yml + overrides/main.html + extra.css + spec §8 cross-links)

Every phase ends with a green `mkdocs build --strict` and a buildable site.
