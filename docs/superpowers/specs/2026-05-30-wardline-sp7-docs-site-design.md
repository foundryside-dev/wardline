# Wardline SP7 — Documentation Site Design

**Status:** Approved (autonomous /goal execution, 2026-05-30)
**Supersedes:** the README stub as the primary user-facing documentation.

## 1. Goal

Ship a published documentation site for Wardline `0.1.0` that lets a one-to-two
developer team — and the coding agents they're arming — get from `pip install`
to a useful scan, judge run, and Loom integration without reading source code.

The site embodies the product thesis: **enterprise-class tooling without
enterprise-class weight.** It is lean, task-oriented, and grounded entirely in
shipped behavior. It documents what exists today; it does not promise what is
merely planned.

## 2. Non-goals (explicitly out of scope)

- **Versioned docs** (`mike`/version selector). Single current version only;
  revisit when releases accumulate.
- **Auto-generated API reference** (`mkdocstrings`). The public import surface
  is three decorators; a hand-written reference page is lighter and fully
  controlled.
- **Custom theming / bespoke front-end.** Material for MkDocs defaults, lightly
  configured. No custom CSS beyond what a logo/palette needs.
- **Documenting the SP8 MCP server.** It does not ship yet. The agent-integration
  page may mention it as an explicit "coming" note, nothing more.
- **Tutorials beyond a single getting-started path.** No multi-part course.
- **Blog, changelog duplication.** The site links to `CHANGELOG.md`; it does not
  re-host it.

## 3. Architecture

| Concern | Decision |
|---|---|
| Generator | **Material for MkDocs** (`mkdocs` + `mkdocs-material`) |
| Tooling deps | New **`docs` optional-dependency group** in `pyproject.toml`; never in `scanner`/base. Base package keeps zero runtime deps. |
| Docs source root | `docs_dir: docs` with `exclude_docs:` excluding `superpowers/` and `integration/` (our process docs, not published). |
| Build output | `site/` (git-ignored). |
| Strictness | `mkdocs build --strict` is the docs gate — fails on broken links, missing nav entries, orphan pages. |
| Deploy | GitHub Pages via `mkdocs gh-deploy --force` in a CI job on push to `main`. |
| Config home | A single `mkdocs.yml` at repo root. |

### 3.1 `docs_dir` collision (resolved)

mkdocs' default `docs_dir` is `docs/`, which already contains
`docs/superpowers/` (16 plans + 7 specs) and `docs/integration/` (the Loom
integration brief). We keep `docs_dir: docs` and add:

```yaml
exclude_docs: |
  superpowers/
  integration/
```

(mkdocs ≥ 1.5 supports `exclude_docs`.) Published pages live directly under
`docs/` (`docs/index.md`, `docs/getting-started.md`, `docs/concepts/…`, etc.).
The process directories stay where the brainstorming/writing-plans skills put
them and are simply excluded from the build. The integration brief is read as
*source material* for a published Loom-integration page; the raw brief itself is
not published.

### 3.2 Deploy and the manual repo step

CI runs `mkdocs gh-deploy --force` to push the built site to the `gh-pages`
branch. This requires, as a **one-time manual action by the maintainer** (the
analog of SP6's PyPI Trusted-Publisher setup):

1. GitHub repo **Settings → Pages → Source = "Deploy from a branch", branch =
   `gh-pages` / root** (created on first deploy).
2. The deploy workflow needs **`permissions: contents: write`** (set in the
   workflow file, not repo settings).

The deploy job is additive to the existing `ci.yml`; it does not alter the
`gate` / `self-hosting-scan` / `network` jobs.

## 4. Information architecture

```
Home (index.md)                         what/why, install, 30-second example
Getting Started (getting-started.md)    install, first scan, reading a finding
Concepts/
  Taint & trust model (concepts/model.md)   lattice, propagation, boundaries
  Rules (concepts/rules.md)                  PY-WL-101..104, severities
Guides/
  Configuration (guides/configuration.md)    wardline.yaml, schema-grounded
  Suppressing findings (guides/suppression.md) baseline, waivers, judged.yaml
  LLM triage judge (guides/judge.md)         opt-in, OpenRouter, key handling
  Loom integration (guides/loom.md)          SARIF, Filigree emitter, Clarion
Using Wardline with your coding agent (agents.md)   ← signature page
Reference/
  CLI (reference/cli.md)                     scan, judge, vocab, baseline
  Trust vocabulary (reference/vocabulary.md) @trusted/@trust_boundary/@external_boundary
```

Top-level "About"-style links (Contributing, Changelog, License) go in the nav
footer or an `About` section pointing at the existing repo files / GitHub.

### 4.1 Page content contracts

Each page is grounded in a named source of truth. Subagents MUST read the cited
source and MUST NOT invent flags, options, or output.

| Page | Source of truth |
|---|---|
| Home | `README.md`, `pyproject.toml` (extras), a real `wardline scan` run |
| Getting Started | real `pip install`, real `wardline scan` + finding output |
| Concepts/Model | `src/wardline/scanner/taint/`, `src/wardline/core/` lattice + descriptor |
| Concepts/Rules | `src/wardline/scanner/rules/*.py` rule docstrings + metadata |
| Configuration | `src/wardline/core/config_schema.py` (`WARDLINE_SCHEMA`), `config.py` |
| Suppression | `baseline create/update`, `src/wardline/core/baseline.py`, `waivers.py` |
| Judge | `src/wardline/cli/judge.py`, SP5 spec, real `wardline judge --help` |
| Loom integration | `docs/integration/2026-05-29-wardline-loom-integration-brief.md`, SP4 spec |
| Agents | shipped CLI only (`scan`, `judge`); MCP server = "coming" note |
| Reference/CLI | real `wardline <cmd> --help` output, pasted verbatim |
| Reference/Vocabulary | `src/wardline/decorators/__init__.py` + `trust.py`, `wardline vocab` |

## 5. Content discipline (the docs failure mode)

Documentation's characteristic failure is the confidently-invented flag or the
plausible-but-wrong example output. Two hard rules:

1. **Every example command is executed for real**, and its actual output pasted.
   No hand-written "expected output." This applies to CLI examples, install
   commands, and finding samples.
2. **Every flag, option, config key, rule ID, and decorator name is verified
   against the source** cited in §4.1 before it appears on a page.

The `mkdocs build --strict` gate catches structural breakage (links/nav). It
does **not** catch a hallucinated flag — only running the command does. The
`muna-wiki-management:self-sufficiency-reviewer` checks completeness, not
factual accuracy; factual accuracy is enforced by execution.

## 6. Execution model

Subagent-driven (controller does ALL git; subagents NEVER run git — not
`add`/`commit`/`push`/`stash`/`checkout`/`restore`/`reset`/`branch`). Subagents
Write/Edit files and run read-only commands; the controller runs the gate and
commits. Roles: `lyra-site-designer` for structure/nav/theme; the `muna`
document/wiki-management agents for content and reference sheets. Two-stage
review per content task (spec compliance, then quality).

## 7. Testing / acceptance

- `mkdocs build --strict` succeeds locally and in CI (zero warnings).
- Every documented CLI invocation has been executed; pasted output matches.
- Nav has no orphan pages; no broken internal links.
- The base package still installs with zero runtime dependencies (`docs` extra
  is opt-in and isolated).
- The deploy job is present in `ci.yml` and gated to `push: main`.
- Site builds to a working local preview (`mkdocs serve`).

## 8. Deliverables

- `mkdocs.yml`, `docs` optional-dependency group, `site/` gitignored.
- ~12 content pages per §4.
- CI deploy job (`docs` job) in `.github/workflows/ci.yml`.
- A README pointer to the published docs URL.
- Maintainer handoff note for the one-time GitHub Pages settings step.
