# Wardline — `www/` (LEGACY / SUPERSEDED front door)

> **This directory is no longer the deployed site.** It is a hand-rolled static
> front door that has been **superseded by the Astro build in [`site/`](../site/)**.
> `www/` is retained as historical / reference content only. It is **not built,
> not deployed, and not served.** Do not edit it expecting changes to reach the
> live site.

## What is live instead

The live site is the **Astro build in [`site/`](../site/)**, which consumes the
shared **`@weft/site-kit`** design system (a `file:` dependency sparse-fetched
from the `foundryside-dev/weft` repo). It is deployed to the apex
**https://wardline.foundryside.dev** by `.github/workflows/deploy-site.yml`
(GitHub Actions → GitHub Pages; CNAME from `site/public/CNAME`). The workflow
runs on pushes to `main` that touch `site/**` or the workflow file.

The current site is a **single landing page** (`site/src/pages/index.astro`).
There is **no `/docs/` subpath** and **no separately published HTML docs site.**
The landing page links the reference docs as **GitHub repo markdown**, e.g.
`https://github.com/foundryside-dev/wardline/tree/main/docs/getting-started.md`.
(The MkDocs config was removed from the repo — see commit `192462e7`,
"retire mkdocs + www/ gh-pages deploy". The `wardline[docs]` extra still builds
a *local* MkDocs render of `docs/`, but it does not publish anything.)

## What used to be true (and is now wrong)

For the historical record, the old model this `www/` directory was written for —
all of which is now **retired**:

- `www/` was the canonical root of `wardline.foundryside.dev`, deployed via a
  `docs-deploy` CI job that copied `www/` to the publish root, ran
  `mkdocs build` into a `/docs/` subpath, and force-pushed the combined tree to
  the `gh-pages` branch. **That job and `mkdocs.yml` are gone.**
- Docs were served at `wardline.foundryside.dev/docs/`. **They are not** — docs
  now live as repo markdown under `github.com/foundryside-dev/wardline/tree/main/docs/`.

## The `www/` assets (reference content)

The files below are the hand-rolled static page. They still render if opened
directly (see local preview), but they are decoupled from the live site and may
drift from current brand/version facts.

| File | Purpose |
|---|---|
| `index.html` | The page: header, hero, trust model (decorators + 8-state lattice), command surface, federation role, footer. Content-complete server-side. |
| `colors_and_type.css` | Design tokens copied verbatim from the Weft design system (`~/weft/www/colors_and_type.css`). Tokens were not meant to be edited locally. |
| `styles.css` | Layout + components layered on the tokens. Coral (`--thread-wardline: #F0875E`) is Wardline's identity color; amber (`--accent`) is reserved for interactive affordances. |
| `main.js` | Progressive enhancement only: copy-to-clipboard on the install strip; hover-reveal anchor links; member-row hover. Content-complete with JS disabled. |
| `fonts/` | JetBrains Mono + Space Grotesk TTFs + OFL licenses, bundled locally (offline, no CDN). |
| `assets/marks/` | Federation glyph SVGs, inlined in `index.html` to inherit thread color via `currentColor`. |
| `.nojekyll` | Serve files verbatim on GitHub Pages (no Jekyll processing). |

> Note: the static `index.html` is a historical snapshot and may show a stale
> version string. The authoritative version comes from the package
> (`wardline --version`), and the authoritative site is `site/`.

## Preview the legacy page locally

The static page still serves over plain HTTP:

```
cd /home/john/wardline/www
python3 -m http.server 8000
```

Then open `http://localhost:8000/`. Use `localhost` (not `file://`) so the
preloaded fonts resolve under a normal origin.

To preview the **live** site instead, work in [`site/`](../site/) (`npm install`
then `npm run dev`, per that directory's tooling).

## Links

- Repo: `github.com/foundryside-dev/wardline`
- Docs: repo markdown under `github.com/foundryside-dev/wardline/tree/main/docs/`
- Live site: https://wardline.foundryside.dev (built from `site/`)
- Weft hub: `github.com/foundryside-dev/weft`
