# Wardline Website Evaluation Report

**Date:** 2026-04-12  
**Evaluator:** Site Designer Agent  
**Scope:** First-principles assessment of wardline.dev information architecture, content quality, and technology choices

---

## Executive Summary

**Recommendation: Ship as-is with targeted incremental improvements.**

The Wardline site is substantially above average for a developer tool documentation site. It demonstrates clear information architecture, consistent design language, well-structured reference material, and practical guides that address real user workflows. The MkDocs Material implementation is competent and the custom CSS (navy+teal design system) creates a professional, cohesive appearance.

There are no fundamental architectural problems that would justify a major rewrite. The issues identified are refinements, not rework. The site is ready to support a v1.0 launch; the recommended improvements can be phased in post-release without disrupting existing users.

---

## What Is Working

### 1. Information Architecture Is Sound

The five-tab structure (Home, Getting Started, Reference, Guides, Specification) correctly separates content by user intent:

- **Home**: Orientation and persona routing (works as designed)
- **Getting Started**: Linear 15-minute tutorial (correctly scoped)
- **Reference**: Lookup tables and definitions (correctly dense)
- **Guides**: Task-oriented how-to content (correctly procedural)
- **Specification**: Normative reference (correctly separated)

This is the canonical structure for developer documentation. No reorganization needed.

### 2. Reference Section Is Well-Designed

The Reference index page (`reference/index.md`) uses a "I need to..." table that routes users by question rather than document title. This is excellent UX for a lookup-heavy section:

```
| Question | Start here |
|----------|-----------|
| Understand why a rule fired on my code | Rules then Severity Matrix |
| Know what severity/exceptionability applies | Severity Matrix |
```

The individual reference pages (Rules, Severity Matrix, Taint States, Glossary) are appropriately dense. The Glossary is comprehensive (50+ terms) and correctly links to deeper content.

### 3. The Severity Matrix Visualization Works

The 72-cell matrix (`reference/severity-matrix.md`) is the right tool for a (rule x taint-state) lookup table. The legend is clear (E/W/S, U/St/R/T) and the "Notable Patterns" section explains the anomalies. Interactive severity-matrix.js enhancement is a nice touch but not load-bearing.

### 4. Getting Started Is Correctly Scoped

The tutorial covers: install, manifest, decorators, scan, reading findings, CI integration, worked examples. This is the right sequence. The three worked examples demonstrate violation-fix patterns without being exhaustive. The "Next Steps" section correctly routes users to deeper content.

### 5. Design System Is Consistent

The custom CSS (`stylesheets/custom.css`) defines clear design tokens:
- Color palette: `--wl-navy`, `--wl-teal`, `--wl-teal-light`
- Surface hierarchy: `--wl-surface`, `--wl-surface-raised`
- Typography: JetBrains Mono for code, Inter for body
- Dark/light mode with correct contrast

The hero section, feature cards, audience path boxes, and code comparison panels all use consistent styling. No visual inconsistencies observed.

### 6. Homepage Persona Routing Works

The three persona boxes (Developers, Reviewers, Adopters) correctly identify the primary audiences and route them to appropriate starting points. The links are specific:

- Developers: Install, Decorators, Error Messages, Taint States
- Reviewers: Rules, Severity Matrix, SARIF Format, Glossary
- Adopters: Adoption Guide, CI Integration, Governance, Manifest

This is better than a generic "Get Started" link for all audiences.

### 7. Specification Integration Is Handled Well

The spec landing page (`specification.md`) uses a chapter grid with section numbers and one-line descriptions. The "Download PDF" button is prominent. The Part I / Part II / Companion structure is clear. Embedding spec chapters as subnav items is appropriate for this content type.

---

## Problems Identified

### P1 (High): Specification Nav Depth Creates Friction

**Severity:** Medium  
**Impact:** Navigation ergonomics, spec accessibility

The Specification nav section has 18 subitems (15 Part I chapters + 2 Part II bindings + Wardline Lite). This creates a visually overwhelming sidebar when expanded. Users who want to jump between spec chapters must scroll the sidebar or collapse/expand sections.

**However:** This is inherent to the content, not the site structure. The spec has 17 chapters; they need to be addressable. The alternative (hiding chapters behind a single "Specification" link) would force users to the landing page for every chapter navigation.

**Verdict:** Acceptable tradeoff. The spec landing page provides a better browsing experience; the sidebar provides direct linking. Consider adding `navigation.sections` collapse behavior if MkDocs Material supports per-section config.

### P2 (Medium): Missing "Spec Readers" Persona Path

**Severity:** Low  
**Impact:** Discoverability for implementers and auditors

The homepage has three persona boxes (Developers, Reviewers, Adopters) but not "Spec Readers" (implementers of other language bindings, compliance auditors, security reviewers). This audience exists and has different needs:

- Direct link to PDF download
- Link to conformance chapter
- Link to Java binding (for cross-language comparison)
- Link to residual risks chapter

**Recommendation:** Add a fourth persona box: "For implementers" or "For auditors" with links to Spec (PDF), Conformance, Language Bindings, Residual Risks.

### P3 (Medium): Reference Section Missing "Quick Reference Card"

**Severity:** Low  
**Impact:** Developer efficiency for common lookups

The reference section has individual pages for Rules, Decorators, Severity Matrix, etc. It lacks a single-page "quick reference" that a developer could print or keep in a split-screen while coding. This would include:

- The 9 rule IDs with one-line summaries (from rules.md)
- The 4 tier-aligned decorators (from decorators.md, Group 1)
- The severity matrix (from severity-matrix.md)
- The taint state join rules (from taint-states.md)

**Recommendation:** Create `reference/quick-reference.md` as a dense single-page summary of the above. Link from Getting Started "Next Steps."

### P4 (Low): No Search Result Preview Content

**Severity:** Low  
**Impact:** Search usability

MkDocs Material search highlights matching terms but does not show surrounding context in the dropdown. For a tool with many rule IDs and technical terms, this makes search less useful. Users often know a term but not which page it appears on.

**Recommendation:** This is a limitation of MkDocs Material's built-in search. Accept it or investigate Algolia DocSearch (free for open source) for better search UX.

### P5 (Low): Guides Section Ordering

**Severity:** Very Low  
**Impact:** Minor navigation friction

The Guides nav lists:
1. Adopting Wardline
2. CI Integration
3. Governance
4. Analysis Levels
5. Profiles
6. Troubleshooting

This is roughly the adoption sequence, but "Troubleshooting" should arguably be more prominent (it is what users search for when stuck). Consider reordering to: Adoption, CI, Troubleshooting, Governance, Analysis Levels, Profiles.

### P6 (Informational): Spec Files Symlinked

The spec files live in `docs/spec/` and are symlinked into `site-src/spec`. This is a valid approach for single-source publishing (spec source is also used for PDF generation). No action needed, but worth noting for maintainability: changes to spec files require rebuilding the PDF separately.

---

## Recommendations by Effort

### Quick Wins (< 1 hour each)

1. **Add fourth persona box for spec readers.** Copy the pattern from existing boxes; add links to PDF, Conformance (15), Residual Risks (13), Language Bindings.

2. **Reorder Guides nav.** Move Troubleshooting to position 3 (after CI Integration).

3. **Add "Edit this page" links.** MkDocs Material supports this via `edit_uri` in mkdocs.yml. Already partially configured (`content.action.edit` feature enabled) but verify it resolves correctly for symlinked spec files.

### Medium Term (1-4 hours each)

4. **Create quick-reference.md.** Single-page dense summary: rules table, core decorators, severity matrix, join rules. Format for split-screen use (narrow column, no full-width tables). Link from Getting Started.

5. **Add spec chapter summaries to sidebar tooltips.** MkDocs Material supports nav item descriptions that appear on hover. Add one-sentence summaries to each spec chapter nav entry.

6. **Review mobile navigation.** Test the hamburger menu behavior with 18 spec chapters expanded. If it scrolls off-screen, consider using MkDocs Material's `navigation.prune` or `navigation.indexes` more aggressively.

### Major (4+ hours, consider post-v1.0)

7. **Implement Algolia DocSearch.** Apply at https://docsearch.algolia.com/ (free for open source). Requires adding their JS snippet and verifying indexing. Provides better search UX with context previews.

8. **Add versioned documentation.** Already partially configured (`version.provider: mike`). Implement version selector for v0.3, v1.0. Requires build pipeline changes.

9. **Create interactive severity matrix.** The current static table with JS enhancement is adequate. A more sophisticated version could highlight rows/columns on hover, filter by severity, or show full rule descriptions inline. Low priority.

---

## Technology Assessment

### MkDocs Material: Keep

MkDocs Material is the correct choice for this project:

- Zero runtime JS dependencies for core functionality
- Built-in dark mode, search, responsive nav
- Extensive markdown extensions (tabs, admonitions, code annotations)
- Active maintenance, large community
- Social cards plugin for link previews
- Git revision dates for content freshness

Alternatives considered:

- **Astro/Starlight**: More flexible but requires more custom build. Overkill for documentation-primary site.
- **Hugo**: Faster builds but weaker Python tooling ecosystem. No clear benefit.
- **Docusaurus**: React-based, heavier bundle. Wrong technology fit.
- **Plain HTML**: Would lose search, dark mode, navigation features. Maintenance burden.

### Custom CSS: Keep

The custom CSS is well-organized with clear design tokens. The navy+teal palette is distinctive and aligns with the PDF specification styling. No framework bloat (no Bootstrap, no Tailwind). The CSS is ~800 lines, which is appropriate for the customization scope.

---

## Content Assessment

### Completeness

The documentation covers:
- Installation and basic usage (Getting Started)
- All 9 canonical rules + 3 supplementary rules (Rules reference)
- All 38 decorators in 17 groups (Decorators reference)
- All 8 taint states (Taint States reference)
- Severity/exceptionability matrix (Severity Matrix reference)
- CLI commands and flags (CLI reference)
- SARIF output format (SARIF Format reference)
- Manifest schema (Manifest reference)
- Governance exception workflow (Governance guide)
- CI integration for GitHub/GitLab (CI guide)
- Adoption strategy (Adoption guide)
- Analysis levels (Analysis Levels guide)
- Profiles (Profiles guide)
- Troubleshooting (Troubleshooting guide)
- Full normative specification (17 chapters)
- Glossary (50+ terms)

**Missing content identified:**

1. **Changelog / Release Notes**: No version history visible. Users need to know what changed between releases. Add `changelog.md` or link to GitHub Releases.

2. **FAQ**: No frequently asked questions page. Consider adding common questions like "Why does PY-WL-001 fire on my validated data?" or "How is wardline different from bandit/semgrep?"

3. **Integration examples beyond CI**: No content on IDE integration (VS Code SARIF Viewer), pre-commit usage beyond the basic hook, or monorepo overlay patterns.

### Redundancy

No significant redundancy detected. The spec chapters and reference pages serve different purposes (normative vs operational) and do not duplicate content. Cross-links are appropriate.

---

## If Major Rewrite Were Warranted (It Is Not)

For reference, a major rewrite would involve:

1. **Flattening the nav structure**: Combine Reference + Guides into a single "Docs" section with subsections. Reduce spec to PDF-only.

2. **Task-based reorganization**: Replace topic-based nav with workflow-based nav ("Fix a PY-WL-001", "Add governance to my project", "Integrate with GitHub Actions").

3. **Search-first paradigm**: Minimize nav depth, maximize search quality with Algolia, add "quick answers" inline.

4. **Static site generator switch**: Move to Astro for more control, custom components, partial hydration.

**Why this is not warranted:**

- The current structure serves the identified audiences well.
- MkDocs Material is adequate for the content type.
- The custom CSS is already professional quality.
- The content is complete for v1.0 launch.
- Rewrite effort would delay release for marginal benefit.

---

## Conclusion

The Wardline website is ready for v1.0 launch. The information architecture is sound, the reference material is comprehensive, the guides are practical, and the design is professional. Implement the quick wins (persona box, nav reorder) before launch; defer medium and major recommendations to post-release iteration.

**Specific files reviewed:**
- `/home/john/wardline/mkdocs.yml`
- `/home/john/wardline/site-src/index.md`
- `/home/john/wardline/site-src/getting-started.md`
- `/home/john/wardline/site-src/specification.md`
- `/home/john/wardline/site-src/reference/index.md`
- `/home/john/wardline/site-src/reference/rules.md`
- `/home/john/wardline/site-src/reference/severity-matrix.md`
- `/home/john/wardline/site-src/reference/taint-states.md`
- `/home/john/wardline/site-src/reference/decorators.md`
- `/home/john/wardline/site-src/reference/glossary.md`
- `/home/john/wardline/site-src/guides/adoption.md`
- `/home/john/wardline/site-src/guides/ci-integration.md`
- `/home/john/wardline/site-src/guides/governance.md`
- `/home/john/wardline/site-src/stylesheets/custom.css`
- `/home/john/wardline/docs/spec/wardline-01-05-authority-tier-model.md`
