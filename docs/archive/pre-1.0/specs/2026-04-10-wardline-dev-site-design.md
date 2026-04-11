# wardline.dev Documentation Site

## Purpose

Build a static documentation site at `https://www.wardline.dev/` that serves as the single source of truth for Wardline reference documentation. The site renders existing markdown docs from the repository using MkDocs Material, deployed as static files to the Caddy-served directory at `/var/www/wardline.dev`.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Generator | MkDocs Material 9.7.4 | Already installed, industry standard for Python tools, renders existing markdown with zero rewriting |
| Tone | Formal, authoritative | Security/governance tool — understated professionalism over developer-friendly playfulness |
| Default theme | Dark (indigo base `#1a1a2e`, cyan accent `#06b6d4`) | Dark-default with light/dark toggle via MkDocs Material's native palette switcher |
| Landing page | Task-oriented routing | "I need to..." table routes users to the right page in one click; brief description, not a marketing page |
| Specification | PDF download + GitHub link | Not rendered as site pages — too dense for web consumption; formal PDF for offline reference |
| Severity matrix | Interactive (colour-coded, tooltips, clickable cells) | Custom CSS/JS enhancement — the highest-value visual in the entire site |

## Navigation Structure

```
wardline.dev
├── Home                          index.md — task-oriented routing page
├── Getting Started               getting-started.md
├── Reference
│   ├── Rules                     reference/rules.md
│   ├── Severity Matrix           reference/severity-matrix.md (enhanced with custom CSS/JS)
│   ├── Taint States              reference/taint-states.md
│   ├── Decorators                reference/decorators.md
│   ├── Supplementary Groups      reference/supplementary-groups.md
│   ├── CLI                       reference/cli.md
│   ├── Manifest                  reference/manifest.md
│   ├── SARIF Format              reference/sarif-format.md
│   ├── Error Messages            reference/error-messages.md
│   ├── Governance Retention      reference/governance-retention.md
│   └── Glossary                  reference/glossary.md
├── Guides
│   ├── Adopting Wardline         guides/adoption.md
│   ├── CI Integration            guides/ci-integration.md
│   ├── Governance                guides/governance.md
│   ├── Analysis Levels           guides/analysis-levels.md
│   └── Profiles                  guides/profiles.md
├── Troubleshooting               guides/troubleshooting.md (promoted to top-level nav)
└── Specification                 Links: PDF download + GitHub repo spec/ directory
```

## Theme Configuration

### Palette

Dark mode (default):
- Background: `#1a1a2e` (deep indigo)
- Surface: `#2a2a4a` (raised cards/code blocks)
- Text primary: `#e0e7ff`
- Text secondary: `#8b9dc3`
- Text muted: `#5a6b8a`
- Accent/links: `#06b6d4` (cyan)
- Border: `#334155`

Light mode (toggle):
- Background: `#f8fafc`
- Surface: `#ffffff`
- Text primary: `#1e293b`
- Text secondary: `#475569`
- Accent/links: `#0891b2`

Severity colours (consistent across themes):
- ERROR: `#ef4444` (red)
- WARNING: `#f59e0b` (amber)
- SUPPRESS: `#64748b` (slate gray)

### Typography

- Body: system font stack (MkDocs Material default)
- Code: `JetBrains Mono` or system monospace
- No custom web fonts beyond what Material provides

## Landing Page (index.md)

Structure:
1. **Title**: "Wardline" — one line
2. **Tagline**: "Semantic boundary enforcement for Python. Catches untrusted input reaching privileged code before it ships." — two lines max
3. **"I need to..." routing table**: Task → destination link (adapted from existing `reference/index.md`)
4. **Action buttons**: Getting Started (primary CTA), GitHub (secondary), Specification PDF (secondary)
5. **No feature cards, no marketing copy, no illustrations**

## Severity Matrix Enhancement

The severity matrix page (`reference/severity-matrix.md`) receives custom CSS and a small JS enhancement:

### Colour-coded cells
- Each cell in the 9×8 table is coloured by severity:
  - `E/*` cells: red background (subtle, not garish — `rgba(239,68,68,0.15)` with red text)
  - `W/*` cells: amber background (`rgba(245,158,11,0.15)` with amber text)
  - `S/*` cells: gray background (default table cell, muted text)
- Exceptionability indicated by text weight or a small badge character

### Hover tooltips
- Hovering a cell shows: "ERROR / UNCONDITIONAL — cannot be excepted" (or equivalent)
- Implemented via CSS `::after` pseudo-element or `title` attribute

### Clickable cells
- Each cell links to the relevant rule's section in `rules.md`
- Implemented by wrapping cell content in anchor tags within the markdown, or via JS click handler

### Implementation approach
- Custom CSS in `docs/stylesheets/severity-matrix.css` (loaded via `extra_css` in `mkdocs.yml`)
- Small JS in `docs/javascripts/severity-matrix.js` (loaded via `extra_javascript`)
- The JS targets the severity matrix table by matching the page URL path (`/reference/severity-matrix/`) and selecting the first `<table>` element. No markdown modifications needed — the script parses cell text content (`E/U`, `W/R`, `S/T`) to apply classes

## Deployment

### Build
```bash
mkdocs build --site-dir /var/www/wardline.dev
```

### Configuration file
`mkdocs.yml` at project root. Committed to the repository.

### Specification PDF
- Placed at `docs/assets/wardline-specification.pdf`
- MkDocs copies it to the built site as a static asset
- Linked from nav and landing page as a download

### Caddy
No changes required. Caddy already serves static files from `/var/www/wardline.dev` with TLS, compression, and security headers.

### Rebuild workflow
Manual `mkdocs build` for now. Future: GitHub Actions on push to main that builds and deploys via rsync/scp.

## What This Does Not Include

- **No custom JavaScript framework** — vanilla JS only for the matrix enhancement
- **No search customisation** — MkDocs Material's built-in search is sufficient
- **No analytics** — can be added later if needed
- **No blog or changelog** — this is reference documentation only
- **No rendered specification chapters** — spec stays as PDF + GitHub link
- **No API or dynamic content** — pure static site
