# Wardline — front-door site

Static front door for **Wardline**, a faithful sibling of the Weft Federation hub site at
`~/weft/www/`. Hand-rolled HTML/CSS/JS, no build step, no runtime dependencies.
GitHub-Pages-deployable as-is.

This www front door is the **canonical root** of `wardline.foundryside.dev`. The MkDocs
reference docs (`~/wardline/docs/`) are served from the **`/docs/` subpath** under the same
domain. The CI `docs-deploy` job assembles both into one GitHub-Pages tree (this `www/` at the
root, `mkdocs build` into `publish/docs/`) and force-pushes it to the `gh-pages` branch — see
**Deployment** below.

## Files

| File | Purpose |
|---|---|
| `index.html` | The page: header, hero (what Wardline does + install strip + PY-WL-101 finding panel + metric strip + CI gate example), trust model (3 decorators + 8-state lattice + opt-in explanation), command surface (CLI + MCP + install layers), **federation role** (enrich-only, SEI keying, 3 bindings, sibling member links), footer. Content-complete server-side. |
| `colors_and_type.css` | **Token source of truth, copied verbatim from the Weft design system** (`~/weft/www/colors_and_type.css`). Surfaces, text, accent, the per-member thread palette, radii, elevation, spacing, the mono/display type roles, light theme, and the `ddMenuIn` keyframe. **Do not edit tokens here — re-copy from the design system on any update.** |
| `styles.css` | Wardline layout + components, layered on the tokens. Coral (`--thread-wardline: #F0875E`) is the identity color for left-rules, glyph, eyebrow, and section accents. Amber (`--accent`) is reserved for interactive affordances (links, focus rings), exactly as the Weft hub does. |
| `main.js` | Progressive enhancement only: copy-to-clipboard on the install strip; hover-reveal anchor links on section headings; member row hover treatment. Content-complete with JS disabled. |
| `fonts/` | JetBrains Mono (upright + italic) and Space Grotesk variable TTFs + OFL licenses. Copied verbatim from `~/weft/www/fonts/`. Bundled locally — fully offline, no CDN. |
| `assets/marks/` | Federation glyph SVGs: `wardline.svg`, `weft.svg`, `foundryside.svg`, `loomweave.svg`, `filigree.svg`, `legis.svg`. Copied verbatim from `~/weft/www/assets/marks/`. Inlined in `index.html` to inherit thread color via `currentColor`. |
| `.nojekyll` | Serve files verbatim on GitHub Pages (no Jekyll processing). |

## Preview locally

```
cd /home/john/wardline/www
python3 -m http.server 8000
```

Then open `http://localhost:8000/`. Use `localhost` (not `file://`) so the preloaded fonts
resolve under a normal origin.

## Design fidelity and deliberate decisions

### Token copy discipline

`colors_and_type.css` is copied verbatim from the Weft design system. The comment at its top
says not to edit tokens locally — follow that. On a design-system update, replace the whole file
rather than patching individual tokens.

### Identity colors

Coral (`--thread-wardline: #F0875E`) is Wardline's strand. It appears on:
- The header glyph
- Left-rule borders on content cards
- Eyebrow labels on each section
- The trust-flow panel's left rule

Amber (`--accent: #E9B04A`) is the shared interactive affordance color:
- All `<a>` links
- Focus rings
- The CI gate callout border (shared infrastructure concept, not Wardline-specific)
- The "The federation axiom / connective tissue" facts (amber = shared concern)

### No rule count

The brief is explicit: do not state a rule count. The rules section names rule families
qualitatively (trust-boundary leaks, untrusted data reaching deserialization/exec/shell/SQL/SSRF/
path-traversal, fail-open boundaries, non-rejecting validators) and links to the repo as authority.
The "Four policy rules" phrasing in the README and the "~20 rules" phrasing in members/wardline.md
are both off-limits — they conflict and drift.

### A-1 binding tag

Tagged `A-1 · LIVE — until Loomweave-absent path demonstrated end-to-end`, per the brief and
the current weft www hub text. The native Filigree emitter has shipped; the asterisk stays live
until the Loomweave-absent composition path is demonstrated end-to-end.

### Version

Shows `v1.0.0rc4` (from the brief). The working branch is `rc5` at the time of writing — noted
as an open fact for the user.

### Dark only

The warm espresso theme is canonical and the Weft kit ships no toggle, so none is added. The
`colors_and_type.css` tokens include a full light theme under `[data-theme="light"]` if it is
wanted later.

### No theme-flash / font-flash

Both brand faces are `<link rel="preload">`-ed before first paint.

### Content-complete without JS

The entire page is readable with JS disabled. The JS file only adds:
- Copy-to-clipboard on the install command strip
- Hover-reveal anchor links on section headings
- Member row hover treatment

### Federation section

The Federation section is first-class — it precedes the footer and has the same weight as the
Trust Model and Commands sections. It covers, in order: the enrich-only axiom, SEI keying, the
three bindings (Wardline→Loomweave, Wardline→Filigree A-1, Wardline→Legis), and a live sibling
member strip linking back to each member's repo.

### Hero finding panel

The PY-WL-101 motif is re-colored from the old teal palette onto the warm-Loom palette:
- The panel uses a pinned dark editor surface (`#131E24`/`#0F1A20`) regardless of theme
- Syntax tokens use sky (`#56B7E2`), amber (`#E9B04A`), aqua (`#52C9B8`), warm-emerald (`#5FB98E`)
  — colors derived from the Loom thread palette
- The trust leak (`fp-raw`) reads stale-red (`#E2604E`)
- The verdict wash uses `rgba(226, 96, 78, 0.10)` (the Loom stale-red at low opacity)

## Links — wired to `foundryside-dev`

- Repo: `github.com/foundryside-dev/wardline`
- Docs: `wardline.foundryside.dev/docs/` (the MkDocs reference docs, served from the subpath)
- Weft hub: `github.com/foundryside-dev/weft`
- Sibling repos: `github.com/foundryside-dev/<member>` (Loomweave repo = `clarion`)

## Deployment

This front door owns the site root; the MkDocs docs are served from `/docs/`. Both ship as a
single GitHub-Pages tree assembled by the `docs-deploy` job in `.github/workflows/ci.yml` (runs
only on `push` to `main`):

1. `cp -r www/. publish/` — this front door becomes the publish root.
2. `mkdocs build --strict -d publish/docs` — the reference docs build into the `/docs/` subpath
   (`site_url` in `mkdocs.yml` is pinned to `https://wardline.foundryside.dev/docs/` so internal
   links and the canonical resolve under the subpath).
3. `publish/CNAME` (copied from `www/CNAME`) and `publish/.nojekyll` sit at the root; the
   `gh-pages` branch is force-pushed with the combined tree.

**CNAME single source of truth:** `www/CNAME`. There is intentionally no `docs/CNAME` — if there
were, `mkdocs build -d publish/docs` would emit a stray `publish/docs/CNAME`, and a bare
`mkdocs gh-deploy` would publish the docs domain-less. The assembly path is the only correct deploy.

To preview the **assembled** tree exactly as it ships:

```
cd /home/john/wardline
rm -rf publish && cp -r www/. publish/ && uv run mkdocs build --strict -d "$PWD/publish/docs"
cd publish && python3 -m http.server 8000   # root → /  ·  docs → /docs/
```

The trimmed MkDocs landing (`docs/index.md`, no longer using the deleted `overrides/home.html`
template) is a plain reference-docs index; the marketing/front-door role lives here in `www/`.
