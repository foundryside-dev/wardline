# Wardline.dev Site Restructure — Design Spec

**Date:** 2026-04-12
**Status:** Approved (brainstorming session)
**Target:** wardline.dev v1.0 launch (days away)
**Scope:** Information architecture restructure + repository layout separation

---

## 1. Problem

The wardline.dev website was audited against the canonical specification at `docs/spec/` and found to have structural and discoverability problems that undermine the authority of the frozen v1.0 RC specification.

### 1.1 Findings from the audit

1. **Hidden content.** `wardline-01-00-front-matter.md` (79 lines — the spec's own audience reading guide), `wardline-02-00-front-matter.md` (21 lines), and all nine files in `spec/semantic-equivalents/` (per-rule syntactic pattern catalogues) are deployed to the site but absent from the navigation.
2. **Two competing spec landing pages.** `/specification/` (40 KB, from `docs/specification.md`) and `/spec/` (30 KB, from `docs/spec/README.md`) both exist with overlapping but inconsistent content.
3. **Unacknowledged duplication.** Six Reference pages and two Guide pages duplicate spec chapter material without any backlink to the spec, creating two sources of truth with no authority signal.
4. **Fragmented conformance roadmap.** `spec §15` (518 lines) defines a coherent Phase 0/1/2/3 adoption arc with three governance profiles. That model is scattered across `guides/adoption.md` (Phase 1 only), `guides/profiles.md`, and `specification.md` with no single entry point.
5. **Orphaned assurance content.** `/adr/`, `/audits/`, `/verification/`, `/requirements/`, `/plans/`, `/design/`, `/session-log-2026-03-28/`, `/superpowers/`, `/archive/` are all deployed publicly on wardline.dev without nav links. Some (ADRs, audits, verification matrix) are legitimate public content. Others (session logs, Claude prompts, WP plans) are process artifacts that should not be published.
6. **Authoritative and derived content mixed in the same directory.** `docs/` contains both the frozen-RC specification source and the website source (homepage, tutorials, reference pages, stylesheets, JavaScript, image assets), making it impossible to tell at a filesystem level what is authoritative and what is derived.

### 1.2 Impact on readers

- **First-time readers** cannot find the spec's official reading guide and do not know which chapters to read in which order.
- **Adopters** following `guides/adoption.md` do not know they are implementing Conformance Phase 1 or that Phases 0/2/3 exist.
- **Security assessors** have no landing page — the verification framework, residual risks, and audit evidence exist but are scattered across unlinked directories.
- **Reviewers without tooling** cannot find Wardline Lite, the 591-line practical review guide written specifically for them, because it is buried under `Specification → Part II Language Bindings → Companion`.
- **Rule implementers** cannot navigate from `spec §8` to the `semantic-equivalents/` pattern catalogue that describes how each rule is detected, because those pages are orphaned.

---

## 2. Scope and constraints

### 2.1 In scope

- Complete information-architecture restructure of wardline.dev.
- Separation of authoritative content (`docs/`) from website source (new `site-src/`).
- Navigation restructure, cross-link protocol, new hub pages, Reference section overhaul.
- Cleanup of orphaned and internal directories.

### 2.2 Out of scope

- Rewriting any specification chapter content. The spec is frozen at RC.
- Renaming spec chapter files or changing their URLs.
- Changing the PDF build pipeline (`tools/pdf/build-spec.sh`).
- Changing the scanner source, test corpus, or any runtime behaviour.
- Adding new specification chapters (ADR-004's proposals are DRAFT and not part of v1.0 RC).

### 2.3 Constraints

- **Timeline.** v1.0 launch is days away. The restructure must ship in one PR and be reversible.
- **URL freedom.** No existing wardline.dev URLs are cited externally or indexed in a way that forbids breakage. Breaking `/spec/` in favour of `/specification/` is acceptable.
- **Frozen spec files.** The 20 spec files in `docs/spec/` keep their current filenames and URLs because renaming cascades through internal cross-references and the PDF build.
- **`docs/superpowers/` is immovable.** It is baked into editor/agent skill defaults that cannot be edited. It stays in its current location but is excluded from the mkdocs build.
- **Single source of truth for the Cell Certification Matrix.** `docs/verification/2026-04-12-v1-0-cell-certification-matrix.md` is the authoritative V&V record, not evidence adjacent to the spec.

---

## 3. Design decisions (brainstorming resolutions)

Six decisions were made during the brainstorming session:

| # | Decision | Resolution |
|---|---|---|
| 1 | URL stability | Full URL freedom — site is pre-launch |
| 2 | Reference-vs-spec treatment | Summaries with authority banners (not thin pointers, not generated from spec) |
| 3 | Orphaned artifact directories | Bimodal split — ADRs, audits, verification, requirements exposed in a new Assurance section; plans, design, session logs, superpowers excluded from build; archive deleted |
| 4 | Wardline Lite positioning | Under `Specification → Start Here` alongside the `§01-00` reading guide |
| 5 | Draft extensions | ADRs with status discipline (DRAFT / ACCEPTED / SUPERSEDED / REJECTED); ADR-004 gets prominent "not yet normative, do not implement" warning |
| 6 | Separation of authoritative and derived | `docs/` contains only authoritative source; website source moves to `site-src/`; symlinks stitch authoritative directories into the build |

---

## 4. Information architecture

### 4.1 Top-level navigation

Five top-level sections, ordered for both first-time discovery and frequent-user access:

```
Home
Getting Started          pragmatic onboarding (install → first scan → decorators)
Specification            THE AUTHORITATIVE CORE
    Start Here
        Reading Guide    (from §01-00 front matter, currently hidden)
        Wardline Lite    (591-line reviewer guide, currently buried)
    Part I — Framework
        Chapters §1–§15  (15 chapters, grouped visually on landing page)
    Part II — Language Bindings
        Overview         (from §02-00 front matter, currently hidden)
        A. Python Binding
        B. Java Binding
    Companion
        Semantic Equivalents (9 per-rule pattern pages, currently orphaned)
Reference                quick-lookup summaries with authority banners
Guides                   procedural how-to with spec prerequisite boxes
Assurance & Decisions    NEW: ADRs, audits, verification, residual risks hub
```

### 4.2 Section purposes — what belongs where, what does not

| Section | Purpose | Authority | What does NOT belong |
|---|---|---|---|
| **Home** | Pitch plus routing to the section the reader actually needs. States what Wardline is (from `spec §2`) in at most three paragraphs. | — | Tutorials, rule lists, API reference |
| **Getting Started** | First-hour experience: install, manifest, first scan, read findings, add first decorators. Links back to `spec §5` and `§7` for conceptual grounding. | Non-normative | Governance detail, conformance phases, full rule catalogue |
| **Specification** | The normative text. Frozen at RC. Single source of truth. | **Normative** | Tutorials, generated API docs, ADRs, audits |
| **Reference** | Quick-lookup summaries — tables, one-liners, field references. Every page opens with an authority banner pointing to the spec chapter it summarises. | Non-normative | Narrative explanations, procedural how-to |
| **Guides** | "How do I do X?" procedures: adoption roadmap, CI wiring, governance ops, troubleshooting. Every guide opens with a prerequisites box naming the spec chapter it implements. | Non-normative | Normative rule definitions |
| **Assurance & Decisions** | Everything that demonstrates the spec is trustworthy or evolving: ADRs (decisions), audits (conformance evidence), verification framework, residual-risks hub. Assessor entry point. | Mixed — ADRs are proposals, audits are evidence | Tutorials, rule lists |

### 4.3 Key invariants the skeleton enforces

1. Single specification landing page. `/specification/` is the only entry. `/spec/` collapses into it.
2. Start Here group is visible first inside the Specification section — the reading guide and Wardline Lite are unmissable.
3. Semantic Equivalents are in navigation for the first time — under `Specification → Companion`.
4. Reference and Guides are derived content — they never pretend to be normative, and every page points back at the spec chapter it relates to.
5. Assurance & Decisions is the assessor entry point — `spec §11`, `§13`, `§10` flow into this section's hub pages, not just Reference pages.

---

## 5. Specification section detail

### 5.1 Landing page (`/specification/`)

Replace the current `specification.md` content with a layout that routes by audience, shows the structure, and signals frozen-RC authority:

```
WARDLINE SPECIFICATION                    [v1.0 RC · 4,649 lines · PDF]

The normative definition of the Wardline framework. Frozen for v1.0.

┌─ START HERE ─────────────────────────────────────────────────┐
│ First time? Read one of these before Part I:                 │
│                                                              │
│   Reading Guide     Which chapters you need, by role.        │
│   Wardline Lite     Practical 5-question review guide.       │
│                     For reviewers without tooling.           │
└──────────────────────────────────────────────────────────────┘

PART I — FRAMEWORK              (language-independent, 15 chapters)
  Foundations                   §1 Scope · §2 What a Wardline Is · §3 Problem · §4 Non-Goals
  Trust model                   §5 Authority Tier Model · §6 Enforcement Spec  [FOUNDATIONAL]
  Annotations and rules         §7 Vocabulary · §8 Pattern Rules · §9 Enforcement Layers
  Governance and verification   §10 Governance Model · §11 Verification Properties
  Portability and conformance   §12 Language Criteria · §13 Residual Risks
                                §14 Manifest Format · §15 Conformance Profiles

PART II — LANGUAGE BINDINGS
  Overview                      Which binding? Shared contract.
  A. Python Binding             Normative Python contract. 863 lines.
  B. Java Binding               Normative Java contract. 676 lines.

COMPANION
  Semantic Equivalents          Per-rule syntactic pattern catalogues (living doc).
                                PY-WL-001 … PY-WL-009.
```

Features:

- **Grouped Part I chapters.** The 15 chapters are chunked into five conceptual groups so a first-time reader sees structure, not a 15-item list.
- **`[FOUNDATIONAL]` markers** on §5 and §6 signal "read these first even if you skip others".
- **PDF download link** at the top — the spec already builds to PDF via `tools/pdf/build-spec.sh`.
- **Version and line-count status strip** — makes "v1.0 RC, frozen" visible.

### 5.2 Start Here group

```yaml
Specification:
  - Start Here:
      - index.md                       # short "how to read the spec" page
      - Reading Guide: spec/wardline-01-00-front-matter.md
      - Wardline Lite:  spec/wardline-lite.md
```

The Start Here index is roughly 30 lines and routes by role: "Developer? → §5, §7, Part II-A. Adopter? → §15, §10. Assessor? → §11, §13. Reviewer without tooling? → Wardline Lite."

### 5.3 Part I and Part II — no URL changes

**Decision:** keep existing chapter filenames and URLs. Renaming would:

- Cascade through every internal cross-reference in the 4,649-line spec.
- Break `tools/pdf/build-spec.sh` which concatenates files by filename pattern.
- Add rename risk for no shipping value.

Navigation gets restructured; files stay put. Part I renders as 15 chapter links (grouped visually on the landing page, flat in the sidebar). Part II gets the missing `§02-00` front matter exposed as "Part II Overview".

### 5.4 Companion — Semantic Equivalents exposed

```yaml
- Companion:
    - Semantic Equivalents:
        - Overview:    spec/semantic-equivalents/README.md
        - PY-WL-001:   spec/semantic-equivalents/py-wl-001.md
        - PY-WL-002:   spec/semantic-equivalents/py-wl-002.md
        # ... through py-wl-009
```

**Cross-link protocol.** Each rule definition in `spec/wardline-01-08-pattern-rules.md` gets a one-line footer linking to its syntactic pattern catalogue:

> *See [PY-WL-00X syntactic patterns](../semantic-equivalents/py-wl-00x/) for the living pattern catalogue.*

And each `semantic-equivalents/py-wl-00x.md` gets a header banner:

> *Normative definition: [Specification §8 — Pattern Rules](../wardline-01-08-pattern-rules/#wl-00x).*

### 5.5 Chapter page conventions

Every spec chapter gets a consistent header and footer injected via an mkdocs Material template override. No per-file markdown body editing.

**Header (auto-rendered):**

```
Specification · Part I · Chapter 5            [v1.0 RC · Normative]
```

**Footer (auto-rendered):**

```
Related:
  Previous: §4 Non-Goals      Next: §6 Authority Tier Enforcement
  Derived pages: Reference/Taint States, Guides/Adoption
  Source: docs/spec/wardline-01-05-authority-tier-model.md
```

Implementation: per-chapter frontmatter + custom `main.html` template. See Section 8.1.

### 5.6 Resolving `/spec/` vs `/specification/` collision

- Delete `docs/spec/README.md` — its content is superseded by the new `/specification/` landing page.
- The `docs/spec/*.md` files stay in place; under the new repo layout (Section 8) they are exposed to the mkdocs build via a symlink at `site-src/spec/`. URLs stay as `/spec/wardline-01-NN-.../` — readers don't look at URL structure, they look at the breadcrumb.
- The visible duplication (two landing pages titled "Specification") collapses when `docs/spec/README.md` is deleted.

---

## 6. Reference, Guides, Getting Started, Home

### 6.1 Reference section — Quick Reference data sheet + individual pages

```
/reference/                  WARDLINE QUICK REFERENCE (data sheet)
/reference/rules/            per-rule detail (PY-WL-001..009, SCN-021, SUP-001)
/reference/taint-states/     8-state table + full join lattice + provenance
/reference/decorators/       full decorator catalogue with _wardline_* attrs
/reference/manifest/         wardline.yaml field reference (absorbs governance-retention)
/reference/cli/              command tree with all flags
/reference/sarif-format/     SARIF v2.1.0 output schema + field reference
/reference/supplementary-groups/  SCN-* and SUP-* organizing principles
/reference/error-messages/   canonical error catalogue
/reference/glossary/         term definitions (cross-linked from spec §2)
```

**Changes from current:**

- **`/reference/` index page** is replaced with a Wardline Quick Reference data sheet — tables only, aggregating the content readers Cmd+F for:
    - Rule ID × severity × taint-state matrix (PY-WL-001..009, SCN-*, SUP-*)
    - Taint state lattice (8 states, join table)
    - Decorator inventory (name → group → `_wardline_*` attrs)
    - `wardline.yaml` top-level key cheat-sheet
    - CLI command tree
    - SARIF output top-level keys
- **`severity-matrix.md` merges into the Quick Reference** — it is one table.
- **`governance-retention.md` merges into `/reference/manifest/`** — retention is a manifest-configuration concern. The merged page has a banner pointing to `spec §10.5` for the normative governance retention model.

**Authority banner — every individual Reference page gets this header once:**

```
!!! info "Normative source"
    **Specification §8 — Pattern Rules**
    This page is a quick reference. For the canonical rule
    definitions and severity derivation, read the spec chapter.
```

Styling: mkdocs Material `info` admonition with a custom `spec-ref` class so it is visually consistent and easy to scan past for repeat visitors.

### 6.2 Guides section

```
/guides/                          index: "Choose your guide"
/guides/conformance-roadmap/      NEW: Phase 0/1/2/3 + Lite/Core/Assured overview
/guides/adoption/                 Phase 0 → Phase 1 walkthrough
/guides/ci-integration/           CI wiring, SARIF upload
/guides/governance/               exception register ops, review workflow
/guides/profiles/                 governance profile selection
/guides/analysis-levels/          Level 1/2/3 call-graph analysis
/guides/troubleshooting/          common failures and diagnostics
```

**New page — `/guides/conformance-roadmap/`** — consolidates `spec §15` (518 lines) into one navigable roadmap:

```
Phase 0: Baseline discovery         →  links to §15.2
Phase 1: Lite Governance            →  links to §15.3 + /guides/adoption/
Phase 2: Core Governance            →  links to §15.4 + /guides/governance/
Phase 3: Assured Conformance        →  links to §15.5 + /guides/profiles/
Graduation criteria                 →  links to §15.6
Assessment procedures               →  links to §15.7
```

No prose duplication — the guide is a roadmap of hyperlinks. Readers see the whole adoption arc in one place; each section is a "jump to detail" link.

**Prerequisites box — every guide opens with:**

```
!!! info "Prerequisites"
    This guide implements **Specification §15 Phase 1**.
    Before you start, read **§5 (Authority Tier Model)** and
    **§7 (Annotation Vocabulary)** for the concepts this guide uses.
```

Each guide lists specifically which spec chapters its procedures derive from.

### 6.3 Getting Started — inline annotation only

No restructure. Add two things:

1. **Inline spec references** after each concept introduction:
   > *Wardline uses four trust tiers (see [Specification §5](../specification/wardline-01-05-authority-tier-model/) for the formal model).*

2. **"Next steps" footer** with three routes:
   > **Where next?**
   > - **Adopt in your team** → Conformance Roadmap
   > - **Understand the model** → Start Here
   > - **Look something up** → Quick Reference

### 6.4 Home — routing block and correct framing

Two changes:

1. **Replace the pitch** with a language-independent framing pulled from `spec §2`:
   > *Wardline is a semantic boundary enforcement framework. It defines a four-tier trust hierarchy and statically verifies that data flows respect those boundaries. The framework is language-independent; reference bindings exist for Python and Java.*
   
   The current home/`site_description` says "for Python". The spec is explicitly language-independent in Part I, with bindings in Part II.

2. **Four audience routing cards:**
   ```
   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
   │ New here?    │  │ Adopting it? │  │ Assessing it?│  │ Implementing?│
   │ Get running  │  │ Roll it out  │  │ Verify rigor │  │ New binding  │
   │              │  │              │  │              │  │              │
   │ → Getting    │  │ → Conformance│  │ → Assurance  │  │ → Spec Part  │
   │   Started    │  │   Roadmap    │  │   & Decisions│  │   II + §12   │
   └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
   ```

### 6.5 The cross-link protocol

One convention, five instantiations. The single most important mechanism in the restructure.

| Location | Direction | Format |
|---|---|---|
| Reference page header | derived → spec | `!!! info "Normative source"` admonition with link to chapter + section |
| Guide page header | derived → spec | `!!! info "Prerequisites"` admonition listing spec chapters to read first |
| Getting Started inline | derived → spec | parenthetical `(see Specification §X)` after concept intros |
| Spec chapter footer | spec → derived | auto-injected "Related" box listing derived pages |
| Home routing cards | home → all | four audience-path cards |

All five use the same visual style (mkdocs Material admonitions with custom classes) so readers learn the pattern once and recognise it everywhere.

---

## 7. Assurance & Decisions section

A new top-level section, purpose-built for security assessors and contributors.

### 7.1 Section structure

```
Assurance & Decisions/
  Overview                       explains the three pillars (below)

  Verification Properties        hub for §11 content
    - Framework overview         summary + link to §11
    - V&V Cell Certification Matrix   HEADLINE: docs/verification/2026-04-12-*
    - Golden Corpus              points to corpus/ + CLI verify command
    - Formal Properties          seven properties, each linked to §11.x

  Residual Risks                 hub for §13 content
    - Risk Catalogue             10 risks as a table, linked to §13.x
    - Compensating Controls      which control mitigates which risk

  Audits                         evidence of conformance
    - Index                      chronological list
    - Rule Conformance 2026-03-25

  Decisions (ADRs)               proposals and accepted decisions
    - Overview + status key
    - ADR-001: Taint State Rename       [ACCEPTED]
    - ADR-002: Tier Source Decorators   [ACCEPTED]
    - ADR-003: Rule Matrix Split        [ACCEPTED]
    - ADR-004: ELSPETH Enhancements     [DRAFT — not yet normative]

  Requirements                   spec fitness requirements
    - Spec Fitness               from docs/requirements/spec-fitness/
```

### 7.2 The three pillars

| Pillar | Direction | Purpose |
|---|---|---|
| **Verification Properties** | Spec → Evidence | "Here is what the spec says must be true, and here is how we demonstrate it is." |
| **Residual Risks** | Spec → Limits | "Here is what the spec deliberately does not verify, and what must be done outside the tool to cover those gaps." |
| **Audits** | Spec → Observation | "Here is what we found when we checked our own implementation against the spec." |
| **Decisions (ADRs)** | Meta | "Here is what we decided about the spec itself, including proposals that are not yet part of it." |
| **Requirements** | Spec → Fitness | "Here is what we commit to testing about the spec as a whole." |

### 7.3 Verification Properties hub — Cell Certification Matrix is the headline

`docs/verification/2026-04-12-v1-0-cell-certification-matrix.md` is the authoritative V&V single source of truth. It is not buried as one item among many — it is the headline piece of the Verification Properties pillar.

Nav entry:

```yaml
- Verification Properties:
    - assurance/verification/index.md
    - "V&V Single Source of Truth — Cell Certification Matrix":
        verification/2026-04-12-v1-0-cell-certification-matrix.md
    - Golden Corpus: assurance/verification/golden-corpus.md
    - Formal Properties: assurance/verification/formal-properties.md
```

Hub page lead paragraph:

> The normative verification framework is defined in **Specification §11**. The authoritative V&V record for the Wardline tool implementation is the **Cell Certification Matrix** below.

### 7.4 ADR discipline

Every ADR page gets:

1. **Status badge in the header** — mkdocs Material admonition:
   - `!!! success "ACCEPTED 2026-03-15"` — green
   - `!!! warning "DRAFT — NOT YET NORMATIVE"` — yellow
   - `!!! abstract "SUPERSEDED by ADR-NNN"` — grey
   - `!!! danger "REJECTED"` — red

2. **Draft banner for ADR-004 specifically:**
   ```
   !!! warning "This is a draft proposal"
       ADR-004 is under review. Its proposals (WL-009 refinement,
       SUP-010, SUP-011) are **not part of the v1.0 RC specification**.
       Do not implement against this ADR until it is accepted and
       folded into a subsequent spec release.
   ```

3. **"Affects" metadata line** listing spec chapters the decision touches.

**ADR index page** is a single table sorted by status (DRAFT first), then ID:

```
| ID      | Title                            | Status   | Affects   | Date       |
|---------|----------------------------------|----------|-----------|------------|
| ADR-004 | ELSPETH Enhancements (WL-009++)  | DRAFT    | §7 §8 II-A| 2026-04-09 |
| ADR-001 | Taint State Rename               | ACCEPTED | §6 §7     | 2026-03-12 |
| ADR-002 | Tier Source Decorators           | ACCEPTED | §7        | 2026-03-14 |
| ADR-003 | Rule Matrix Split                | ACCEPTED | §8        | 2026-03-18 |
```

### 7.5 Source directory mapping

| Source | Destination | Note |
|---|---|---|
| `docs/adr/ADR-001..ADR-004.md` | `/assurance/decisions/` | Stays in `docs/adr/`; nav label changes. Add status admonitions. |
| `docs/audits/rule-conformance-audit-2026-03-25.md` | `/assurance/audits/` | Stays in `docs/audits/`; nav exposes it. |
| `docs/audits/2026-03-25-rule-conformance/` | `/assurance/audits/2026-03-25/` | Detail directory, surfaced under the index. |
| `docs/verification/2026-04-12-v1-0-cell-certification-matrix.md` | Verification Properties headline | Stays in `docs/verification/`; nav promotes it. |
| `docs/requirements/spec-fitness/` | `/assurance/requirements/spec-fitness/` | Stays in `docs/requirements/`; exposed under Requirements. |

---

## 8. Repository layout separation

### 8.1 The core principle

**`docs/` holds only authoritative source material. The website lives elsewhere.**

```
/docs/                                AUTHORITATIVE CONTENT ONLY
  /docs/spec/                         frozen RC specification (Part I, II, Lite, semantic-equivalents)
  /docs/adr/                          decision records (ADR-001..004)
  /docs/audits/                       audit evidence
  /docs/requirements/spec-fitness/    spec fitness requirements
  /docs/verification/                 verification evidence (cell certification matrix)
  /docs/superpowers/                  IMMOVABLE: baked into skills; stays but excluded from build

/site-src/                            WEBSITE SOURCE (new)
  /site-src/index.md                  homepage
  /site-src/getting-started.md        onboarding
  /site-src/specification.md          specification landing page (derived)
  /site-src/reference/                Quick Reference + per-topic pages
  /site-src/guides/                   procedural guides + conformance-roadmap
  /site-src/assurance/                hub pages (verification, residual-risks, audits, decisions)
  /site-src/stylesheets/              web chrome
  /site-src/javascripts/
  /site-src/assets/
  /site-src/overrides/                mkdocs Material theme overrides
  /site-src/spec          → ../docs/spec          (symlink)
  /site-src/adr           → ../docs/adr           (symlink)
  /site-src/audits        → ../docs/audits        (symlink)
  /site-src/verification  → ../docs/verification  (symlink)
  /site-src/requirements  → ../docs/requirements  (symlink)

/mkdocs.yml                           stays at repo root; docs_dir: site-src
```

### 8.2 What moves

**From `docs/` → `site-src/` (website content):**

| Current | New |
|---|---|
| `docs/index.md` | `site-src/index.md` |
| `docs/getting-started.md` | `site-src/getting-started.md` |
| `docs/specification.md` | `site-src/specification.md` |
| `docs/reference/*.md` | `site-src/reference/*.md` |
| `docs/guides/*.md` | `site-src/guides/*.md` |
| `docs/stylesheets/` | `site-src/stylesheets/` |
| `docs/javascripts/` | `site-src/javascripts/` |
| `docs/assets/` | `site-src/assets/` |
| `overrides/` (at repo root) | `site-src/overrides/` |
| `docs/404.html` and other site chrome | `site-src/` |

**Stays in `docs/` (authoritative):**

| Path | Reason |
|---|---|
| `docs/spec/` | Frozen RC specification — single source of truth |
| `docs/adr/` | Decision records — authoritative |
| `docs/audits/` | Audit evidence — authoritative |
| `docs/requirements/spec-fitness/` | Requirements — authoritative |
| `docs/verification/2026-04-12-v1-0-cell-certification-matrix.md` | V&V SSOT |
| `docs/superpowers/` | Immovable — baked into skills; excluded from build instead |

**Deleted outright (git preserves):**

| Path | Reason |
|---|---|
| `docs/archive/` | Historical — git has it |
| `docs/design/` | Internal design drafts |
| `docs/plans/` | Project plans / WP tracking |
| `docs/session-log-2026-03-28/` | Session handoff |
| `docs/spec/README.md` | Superseded by `site-src/specification.md` landing page |
| `docs/verification/*-PROMPT.md` | Claude prompts |
| `docs/verification/SESSION-PICKUP-*.md` | Session handoffs |
| `docs/verification/rename-migration-manifest.md` | Rename migration scratchpad |
| `docs/verification/RENAME-*.md` | Rename migration scratchpads |
| `docs/verification/MINISPEC-PROMPT.md` | Claude prompt |
| `docs/verification/SPEC-PART1-RENAME-PROMPT.md` | Claude prompt |
| `docs/verification/v1.0-review-prompt.md` | Claude prompt |
| `docs/verification/VERIFY-SUBSYSTEM-PROMPT.md` | Claude prompt |
| `docs/verification/VERIFY-SYNTHESIS-PROMPT.md` | Claude prompt |

The Cell Certification Matrix and `docs/verification/README.md` (if it describes the V&V program rather than process) are the only files that stay in `docs/verification/`.

### 8.3 How the website reaches authoritative content — symlinks

Five symlinks inside `site-src/` expose authoritative directories at stable names:

```
site-src/spec          → ../docs/spec
site-src/adr           → ../docs/adr
site-src/audits        → ../docs/audits
site-src/verification  → ../docs/verification
site-src/requirements  → ../docs/requirements
```

This keeps mkdocs URLs stable (`/spec/wardline-01-05-.../`, `/adr/ADR-004-.../`) while cleanly separating authoritative source from website chrome in the filesystem.

**Why symlinks rather than a build-step copy:**

- `mkdocs serve` live-reload still works — editing `docs/spec/wardline-01-08-pattern-rules.md` immediately updates the served page.
- Zero build complexity — no new script, no new dependency, no second stitching phase.
- Linux-native project — symlinks are uncontroversial here.
- Single file mastery — there is no ambiguity about where to edit a spec chapter. Only one path is writable.

### 8.4 `mkdocs.yml` changes

Three edits:

1. **`docs_dir: site-src`** (was implicit `docs`).
2. **Full nav rewrite** — see Appendix A.
3. **Corrected `site_description`** from the Python-first framing to language-independent.

**No `exclude_docs` directive is needed.** `docs/superpowers/` stays invisible to mkdocs by construction: `site-src/` only symlinks five specific directories (`spec`, `adr`, `audits`, `verification`, `requirements`). Nothing under `docs/` is visible to the build unless it is inside one of those five symlinks. `docs/superpowers/` is not, so it is not published.

### 8.5 Template override for chapter headers/footers

From Section 5.5, each spec chapter gets an auto-injected header and footer.

**Implementation:**

1. **Per-chapter frontmatter** in each of the 20 spec files (spec chapters + Part II + Lite):
   ```yaml
   ---
   spec_chapter: 5
   spec_part: I
   spec_title: Authority Tier Model
   spec_prev: wardline-01-04-non-goals
   spec_next: wardline-01-06-authority-tier-enforcement-spec
   derived_pages:
     - { title: "Reference: Taint States", path: "reference/taint-states" }
     - { title: "Guide: Adoption", path: "guides/adoption" }
   ---
   ```

2. **Custom mkdocs Material template** at `site-src/overrides/main.html` that extends the mkdocs Material base and injects the header and footer blocks when `spec_chapter` is set in `page.meta`.

The frontmatter addition is the only edit to the spec files themselves — the markdown body is untouched, preserving spec-text fidelity.

### 8.6 What does NOT change

- `tools/pdf/build-spec.sh` — still reads `docs/spec/`.
- `wardline.yaml` and `wardline.toml` — reference `src/wardline/`, not `docs/`.
- The test corpus (`corpus/`), scanner source (`src/`), and tests (`tests/`).
- Internal code references to `docs/spec/`.
- Published URLs on wardline.dev — the nav is rebuilt but the underlying URL paths stay the same via the symlinks.

---

## 9. Acceptance criteria

Seventeen checks, grouped by theme. Every one is binary.

### Navigation and discoverability

1. Exactly one specification landing page exists; `/spec/` does not render a separate index.
2. `wardline-01-00-front-matter.md` is reachable from nav at `Specification → Start Here → Reading Guide`.
3. `wardline-lite.md` is reachable from nav at `Specification → Start Here → Wardline Lite`.
4. `wardline-02-00-front-matter.md` is reachable from nav at `Specification → Part II → Overview`.
5. All nine `semantic-equivalents/py-wl-00N.md` files are reachable from nav at `Specification → Companion → Semantic Equivalents`.

### Cross-link protocol

6. Every individual Reference page begins with a `!!! info "Normative source"` admonition linking to its spec chapter.
7. Every Guide page begins with a `!!! info "Prerequisites"` admonition listing spec chapters.
8. Every spec chapter ends with an auto-rendered "Related" footer listing derived pages (from the frontmatter `derived_pages` field).
9. Every ADR begins with a status admonition. ADR-004 additionally has a "not yet normative, do not implement" warning.
10. `spec/wardline-01-08-pattern-rules.md` has per-rule footers linking to `semantic-equivalents/py-wl-00N.md`, and each `py-wl-00N.md` has a header banner linking back to §8.

### New derived content

11. `site-src/reference/index.md` renders the Quick Reference data sheet with the six table groups.
12. `site-src/guides/conformance-roadmap.md` exists and links into the six `§15` sub-sections.
13. `site-src/assurance/index.md`, `verification/index.md`, `residual-risks/index.md`, `audits/index.md`, `decisions/index.md` all exist.
14. The Verification Properties hub lists the Cell Certification Matrix as its headline piece.

### Repository hygiene

15. `docs/` contains only: `spec/`, `adr/`, `audits/`, `requirements/`, `verification/` (matrix only), and `superpowers/` (immovable, excluded from build).
16. `site-src/` contains the website source plus five symlinks to `../docs/{spec,adr,audits,verification,requirements}`.
17. Home page pitch no longer says "for Python" — reflects language-independent Part I with Python/Java bindings in Part II.

### Automated validation

**Strict mkdocs build:** `mkdocs build --strict` succeeds. `--strict` promotes broken-link warnings to errors, catching missing nav-referenced files, broken cross-link banners, missing `derived_pages` references, and orphaned pages.

**Visual smoke test:** `mkdocs serve` and manually walk:

1. Home → each audience routing card → expected landing.
2. Getting Started → spec §5 link → back via "Derived pages" footer → back to Getting Started.
3. `/reference/` Quick Reference → click a rule row → `/reference/rules/#py-wl-001` → banner → spec §8 → footer → back.
4. `/guides/conformance-roadmap/` → click Phase 2 section → spec §15.4 → back.
5. `/assurance/decisions/` → ADR-004 → DRAFT warning visible above the abstract.

---

## 10. Phasing and rollback

Eight phases, one PR. Each phase leaves the site in a buildable state, so work can stop after any phase if something goes wrong.

| Phase | Work | Verification after |
|---|---|---|
| **1. Repo layout** | Create `site-src/`. Move homepage, getting-started, reference, guides, stylesheets, javascripts, assets, overrides into `site-src/`. Create the five symlinks. Update `mkdocs.yml` `docs_dir: site-src`. | `mkdocs build --strict` succeeds on existing nav; `mkdocs serve` reaches a page from every symlinked directory |
| **2. Deletions** | Delete `docs/archive/`, `docs/design/`, `docs/plans/`, `docs/session-log-2026-03-28/`, `docs/verification/*-PROMPT.md`, `docs/verification/SESSION-PICKUP-*.md`, `docs/verification/rename-*.md`, `docs/verification/RENAME-*.md`, `docs/verification/MINISPEC-PROMPT.md`, `docs/verification/SPEC-PART1-RENAME-PROMPT.md`, `docs/verification/v1.0-review-prompt.md`, `docs/verification/VERIFY-SUBSYSTEM-PROMPT.md`, `docs/verification/VERIFY-SYNTHESIS-PROMPT.md`, `docs/spec/README.md`. | `mkdocs build --strict` still succeeds |
| **3. Nav restructure** | Rewrite `mkdocs.yml` nav to the target tree. Surfaces `§01-00`, Wardline Lite, Part II Overview, Semantic Equivalents. Correct `site_description` from Python-first framing. | Visual walk of every top-level section |
| **4. New hub content + Reference merges** | Create `site-src/specification.md` (landing), `site-src/reference/index.md` (Quick Reference — absorbs `severity-matrix.md` content), `site-src/guides/conformance-roadmap.md`, `site-src/guides/index.md`, `site-src/assurance/` (five hub pages). Merge `site-src/reference/governance-retention.md` into `site-src/reference/manifest.md`. Delete `site-src/reference/severity-matrix.md` and `site-src/reference/governance-retention.md` after their content is absorbed. | Each new page renders; links resolve; merged content is present in Quick Reference and Manifest pages |
| **5. Cross-link protocol** | Add authority banner to eight Reference pages. Add prerequisites box to six Guide pages. Add status admonitions to four ADRs (ADR-004 gets the DRAFT warning). Add `§8 ↔ semantic-equivalents` cross-links. | Spot-check ten pages; run `mkdocs build --strict` |
| **6. Spec chapter metadata + template** | Add `spec_chapter` frontmatter to 20 spec files. Create `site-src/overrides/main.html` template override to render the header and footer blocks. | Spot-check three spec chapters render with header and footer |
| **7. Home + Getting Started updates** | Revise `site-src/index.md` pitch and audience routing cards. Add inline `(see Spec §X)` references to `site-src/getting-started.md`. | Visual walk of Home and Getting Started |
| **8. Final validation** | Run full acceptance criteria checklist. Run `mkdocs build --strict`. Deploy to staging, spot-check. | All 17 criteria pass |

**Estimated effort:** 15–20 hours total. Phases 1–3 are roughly 1–2 hours each; Phase 4 is the largest (3–5 hours for new content writing); Phases 5–8 are 1–2 hours each.

**Rollback:** Each phase is a separate commit. `git revert` individual phase commits if a regression appears. At no point does the restructure cause data loss — all content moves are git-tracked, and deletions are of files preserved in git history.

---

## Appendix A — full `mkdocs.yml` nav tree

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
          - "V&V Single Source of Truth — Cell Certification Matrix":
              verification/2026-04-12-v1-0-cell-certification-matrix.md
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

---

## Appendix B — files created, edited, deleted

### Created (new)

| Path | Purpose | Est. lines |
|---|---|---|
| `site-src/specification.md` | Grouped landing page with Start Here, Part I, Part II, Companion | ~150 |
| `site-src/reference/index.md` | Wardline Quick Reference data sheet | ~400 |
| `site-src/guides/index.md` | "Choose your guide" index | ~40 |
| `site-src/guides/conformance-roadmap.md` | Consolidated §15 roadmap | ~200 |
| `site-src/assurance/index.md` | Assurance section overview | ~80 |
| `site-src/assurance/verification/index.md` | Verification Properties hub (Cell Certification Matrix headline + Golden Corpus + Formal Properties inline sections) | ~150 |
| `site-src/assurance/residual-risks/index.md` | Residual risks hub | ~100 |
| `site-src/assurance/audits/index.md` | Chronological audit table | ~30 |
| `site-src/assurance/decisions/index.md` | ADR index with status table | ~60 |
| `site-src/overrides/main.html` | Spec chapter header/footer template | ~40 |

**Total new content: approximately 1,250 lines across 10 files.** No spec content is rewritten.

### Edited

**Home and Getting Started:**

- `site-src/index.md` — new pitch, four audience routing cards
- `site-src/getting-started.md` — inline spec refs, "Next steps" footer

**Reference pages (add authority banner):**

- `site-src/reference/rules.md` → banner to §8
- `site-src/reference/taint-states.md` → banner to §6.1
- `site-src/reference/decorators.md` → banner to §7
- `site-src/reference/manifest.md` → banner to §14 (+ merged governance-retention content)
- `site-src/reference/cli.md` → banner to §6/§14
- `site-src/reference/sarif-format.md` → banner to §11 findings interchange
- `site-src/reference/supplementary-groups.md` → banner to §8.4
- `site-src/reference/error-messages.md` → banner (tool-specific, links to rule IDs)
- `site-src/reference/glossary.md` → banner to §2.1

**Guides (add prerequisites box):**

- `site-src/guides/adoption.md` → prereq §15.3, §5, §7
- `site-src/guides/ci-integration.md` → prereq §14, §11
- `site-src/guides/governance.md` → prereq §10
- `site-src/guides/profiles.md` → prereq §15.4, §10.4
- `site-src/guides/analysis-levels.md` → prereq §9
- `site-src/guides/troubleshooting.md` → prereq §8

**ADRs (add status admonitions):**

- `docs/adr/ADR-001-rename-taint-states-to-posture-vocabulary.md` → ACCEPTED
- `docs/adr/ADR-002-rename-tier-source-decorators.md` → ACCEPTED
- `docs/adr/ADR-003-split-rule-matrix-independence.md` → ACCEPTED
- `docs/adr/ADR-004-elspeth-enhancements.md` → DRAFT with "not yet normative" warning

**Spec cross-links:**

- `docs/spec/wardline-01-08-pattern-rules.md` → per-rule footers to semantic-equivalents
- `docs/spec/semantic-equivalents/py-wl-00{1..9}.md` → 9 files get header banners to §8

**Spec chapter frontmatter (20 files):**

- `docs/spec/wardline-01-{01..15}-*.md` → add `spec_chapter`, `spec_part`, `spec_title`, `spec_prev`, `spec_next`, `derived_pages` frontmatter
- `docs/spec/wardline-02-{00,A,B}-*.md` → same
- `docs/spec/wardline-lite.md` → same (part of Start Here)

**Configuration:**

- `mkdocs.yml` → `docs_dir: site-src`, full nav rewrite, `exclude_docs: ../docs/superpowers/`, corrected `site_description`

### Deleted

- `docs/archive/` (whole directory; git preserves history)
- `docs/design/` (whole directory)
- `docs/plans/` (whole directory)
- `docs/session-log-2026-03-28/` (whole directory)
- `docs/spec/README.md` (superseded)
- `docs/verification/MINISPEC-PROMPT.md`
- `docs/verification/RENAME-EXECUTE-PROMPT.md`
- `docs/verification/RENAME-IMPACT-PROMPT.md`
- `docs/verification/rename-migration-manifest.md`
- `docs/verification/SESSION-PICKUP-2026-03-29.md`
- `docs/verification/SPEC-PART1-RENAME-PROMPT.md`
- `docs/verification/v1.0-review-prompt.md`
- `docs/verification/VERIFY-SUBSYSTEM-PROMPT.md`
- `docs/verification/VERIFY-SYNTHESIS-PROMPT.md`
- `site-src/reference/severity-matrix.md` (after merge into Quick Reference — delete from `site-src/` after the file is moved there in Phase 1)
- `site-src/reference/governance-retention.md` (after merge into `reference/manifest.md`)

### Excluded (via `mkdocs.yml` `exclude_docs`)

- `docs/superpowers/` — immovable, baked into skills; stays in place but not published

---

## Appendix C — out-of-scope items and rationale

| Item | Why out of scope |
|---|---|
| Renaming spec chapter files to cleaner URLs | Cascades through internal cross-references and breaks `tools/pdf/build-spec.sh` |
| Adding WL-009 refinement / SUP-010 / SUP-011 to the spec | ADR-004 is DRAFT; these are not part of v1.0 RC |
| Rewriting any spec chapter content | Spec is frozen at RC |
| Moving `docs/superpowers/` | Baked into skills that cannot be edited |
| Generating Reference pages from spec at build time | Simpler to hand-sync; spec is frozen so drift risk is minimal |
| Adding mkdocs plugins (monorepo, multirepo, linkcheck) | Symlinks are simpler; `--strict` catches most regressions |
| Full audience-first IA (For Developers / For Adopters / …) | Audiences overlap; cross-cutting content would be duplicated or arbitrarily placed |
| Replacing mkdocs with a different SSG (Astro, Hugo) | Out of timeline; mkdocs Material is working |
