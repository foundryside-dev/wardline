# Wardline SP7 — Documentation Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a published Material-for-MkDocs documentation site for Wardline `0.1.0`, deployed to GitHub Pages via CI, lean per the small-team product thesis.

**Architecture:** A single `mkdocs.yml` at repo root drives Material for MkDocs over `docs/` (with `exclude_docs` hiding our `superpowers/` and `integration/` process trees). A new `docs` optional-dependency group isolates the tooling from the zero-runtime-deps base package. CI builds `--strict` on every push/PR and `gh-deploy`s on `main`.

**Tech Stack:** mkdocs, mkdocs-material, GitHub Pages, GitHub Actions.

---

## GIT DISCIPLINE (controller-enforced)

**Subagents NEVER run git.** Not `add`, `commit`, `push`, `stash`, `checkout`,
`restore`, `reset`, `branch`, `merge`, `rebase`, `tag`, or any other git verb.
Subagents Write/Edit files and run read-only/build commands only. **The
controller runs the gate and performs every commit.** A subagent that touches
git has failed its task.

**Use `.venv/bin/` binaries**, never bare `python`/`mkdocs`/`pytest`.

**Content discipline (spec §5):** every example command is *executed for real*
and its actual output pasted — no hand-written output. Every flag/key/rule
ID/decorator name is verified against the cited source before it appears.

---

### Task 1: Tooling + scaffold (build-able skeleton)

Stand up the `docs` extra, `mkdocs.yml`, and stub pages for the entire nav so
`mkdocs build --strict` passes from the start. Later tasks fill the stubs.

**Files:**
- Modify: `pyproject.toml` (add `docs` extra)
- Modify: `.gitignore` (ignore `site/`)
- Create: `mkdocs.yml`
- Create: `docs/index.md`, `docs/getting-started.md`, `docs/agents.md`,
  `docs/concepts/model.md`, `docs/concepts/rules.md`,
  `docs/guides/configuration.md`, `docs/guides/suppression.md`,
  `docs/guides/judge.md`, `docs/guides/loom.md`,
  `docs/reference/cli.md`, `docs/reference/vocabulary.md`

- [ ] **Step 1: Add the `docs` extra to `pyproject.toml`**

In `[project.optional-dependencies]`, after the `loom` line, add:

```toml
docs = ["mkdocs>=1.6", "mkdocs-material>=9.5"]
```

- [ ] **Step 2: Ignore the build output**

Append to `.gitignore` under the "Python" section (after `*.egg-info/`):

```
# MkDocs build output
site/
```

- [ ] **Step 3: Create `mkdocs.yml` at repo root**

```yaml
site_name: Wardline
site_description: Generic semantic-tainting static analyzer for Python
site_url: https://foundryside-dev.github.io/wardline/
repo_url: https://github.com/foundryside-dev/wardline
repo_name: foundryside-dev/wardline
edit_uri: edit/main/docs/

theme:
  name: material
  palette:
    - scheme: default
      primary: indigo
      accent: indigo
      toggle:
        icon: material/brightness-7
        name: Switch to dark mode
    - scheme: slate
      primary: indigo
      accent: indigo
      toggle:
        icon: material/brightness-4
        name: Switch to light mode
  features:
    - navigation.sections
    - navigation.top
    - navigation.instant
    - content.code.copy
    - search.suggest

markdown_extensions:
  - admonition
  - toc:
      permalink: true
  - pymdownx.highlight
  - pymdownx.inlinehilite
  - pymdownx.superfences
  - pymdownx.details

exclude_docs: |
  superpowers/
  integration/

nav:
  - Home: index.md
  - Getting Started: getting-started.md
  - Concepts:
      - Taint & trust model: concepts/model.md
      - Rules: concepts/rules.md
  - Guides:
      - Configuration: guides/configuration.md
      - Suppressing findings: guides/suppression.md
      - LLM triage judge: guides/judge.md
      - Loom integration: guides/loom.md
  - Using Wardline with your coding agent: agents.md
  - Reference:
      - CLI: reference/cli.md
      - Trust vocabulary: reference/vocabulary.md
```

- [ ] **Step 4: Create stub pages**

Each of the 11 pages listed under **Files** gets a minimal stub so `--strict`
finds every nav target. Use the page's eventual H1 plus a one-line placeholder.
Example for `docs/index.md`:

```markdown
# Wardline

_Documentation in progress._
```

For each other page use its nav title as the H1 (e.g. `docs/concepts/rules.md`
→ `# Rules`) and the same placeholder line. Do **not** add nav-absent pages.

- [ ] **Step 5: Install the docs extra into the venv**

Run: `.venv/bin/python -m pip install -e ".[docs]"`
Expected: installs mkdocs + mkdocs-material successfully.

- [ ] **Step 6: Verify a strict build**

Run: `.venv/bin/mkdocs build --strict`
Expected: `INFO - Documentation built in …` with **zero** WARNING lines, exit 0.
If strict fails on a nav/orphan complaint, fix the offending stub/nav entry.

- [ ] **Step 7: Controller commits** (`docs(sp7): mkdocs scaffold + docs extra`)

---

### Task 2: CI build + deploy job

Add a `docs` job to the existing workflow: build `--strict` on every push/PR,
`gh-deploy` only on `main`.

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Append the `docs` job**

After the `network` job in `.github/workflows/ci.yml`, add:

```yaml
  docs:
    name: Docs (build + deploy)
    runs-on: ubuntu-latest
    needs: gate
    if: github.event_name != 'schedule'
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install
        run: python -m pip install -e ".[docs]"
      - name: Build (strict)
        run: mkdocs build --strict
      - name: Deploy (main only)
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        run: mkdocs gh-deploy --force
```

- [ ] **Step 2: Validate the workflow YAML parses**

Run: `.venv/bin/python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"`
Expected: `ok`

- [ ] **Step 3: Controller commits** (`ci(sp7): build + gh-deploy docs job`)

> **Maintainer action (do not script):** after this merges to `main` and first
> deploys, enable **Settings → Pages → Deploy from branch → `gh-pages`/root**.
> Surface this to the user at handoff (spec §3.2).

---

### Task 3: Home + Getting Started

**Files:**
- Modify: `docs/index.md`, `docs/getting-started.md`
- Read (source of truth): `README.md`, `pyproject.toml`

- [ ] **Step 1: Run the real examples** the pages will show, and capture output:

```
.venv/bin/wardline --version
.venv/bin/wardline scan src/wardline --format jsonl | head -5
.venv/bin/wardline scan --help
```

Paste *actual* output. Do not invent.

- [ ] **Step 2: Write `docs/index.md`** — sections:
  - One-paragraph "what is Wardline" (from `README.md`), framed by the thesis
    (enterprise-class trust-boundary analysis at small-team weight).
  - **Install:** `pip install "wardline[scanner]"` (note base vs `scanner` vs
    `loom` extras from `pyproject.toml`).
  - **30-second example:** a real `wardline scan` invocation + its real output.
  - "Next steps" links to Getting Started, Concepts, the agent page.

- [ ] **Step 3: Write `docs/getting-started.md`** — a single linear path:
  install → run first scan on a sample → read one finding (explain the fields
  of the real JSONL output) → point to Configuration + Suppression for next.

- [ ] **Step 4: Strict build** — `.venv/bin/mkdocs build --strict` → zero warnings.

- [ ] **Step 5: Controller commits** (`docs(sp7): home + getting-started`)

---

### Task 4: Concepts (model + rules)

**Files:**
- Modify: `docs/concepts/model.md`, `docs/concepts/rules.md`
- Read: `src/wardline/scanner/taint/`, `src/wardline/core/descriptor.py`,
  `src/wardline/core/vocabulary.yaml`, `src/wardline/scanner/rules/*.py`,
  `src/wardline/scanner/rules/severity_model.py`, `docs/superpowers/specs/2026-05-29-wardline-sp1-analyzer-core-design.md`,
  `docs/superpowers/specs/2026-05-30-wardline-sp2-rules-and-vocabulary-design.md`

- [ ] **Step 1: Write `docs/concepts/model.md`** — explain, at a user's level
  (not internals): trust tiers/lattice, what "tainted/untrusted" means, how
  taint propagates through calls, and what a "trust boundary" is. Ground every
  claim in the SP1/SP2 specs and the taint package. No invented tier names —
  use the descriptor's actual vocabulary (cross-check `wardline vocab`).

- [ ] **Step 2: Run** `.venv/bin/wardline vocab` and reference the real tier
  names/decorators it emits.

- [ ] **Step 3: Write `docs/concepts/rules.md`** — a table of the four shipped
  rules with their **exact** IDs, one-line descriptions (from each rule
  module's docstring), and default severities (from rule metadata /
  `severity_model.py`):
  - `PY-WL-101` untrusted data reaches a trusted producer
  - `PY-WL-102` trust boundary with no rejection path
  - `PY-WL-103` broad exception handler in a trusted-tier function
  - `PY-WL-104` silently swallowed exception in a trusted-tier function

  Verify each ID/description/severity against the source before writing. Link
  to Configuration for per-rule enable/severity overrides.

- [ ] **Step 4: Strict build** → zero warnings.

- [ ] **Step 5: Controller commits** (`docs(sp7): concepts (model + rules)`)

---

### Task 5: Guides (configuration, suppression, judge, loom)

**Files:**
- Modify: `docs/guides/configuration.md`, `docs/guides/suppression.md`,
  `docs/guides/judge.md`, `docs/guides/loom.md`
- Read: `src/wardline/core/config_schema.py` (`WARDLINE_SCHEMA`),
  `src/wardline/core/config.py`, `src/wardline/core/baseline.py`,
  `src/wardline/core/waivers.py`, `src/wardline/cli/judge.py`,
  `src/wardline/cli/main.py` (baseline cmds),
  `docs/integration/2026-05-29-wardline-loom-integration-brief.md`,
  `docs/superpowers/specs/2026-05-30-wardline-sp4-outputs-and-loom-design.md`,
  `docs/superpowers/specs/2026-05-30-wardline-sp5-llm-triage-judge-design.md`

- [ ] **Step 1: `docs/guides/configuration.md`** — document **every** top-level
  `wardline.yaml` key from `WARDLINE_SCHEMA` (source_roots, exclude, rules
  {enable, severity}, baseline, waivers, judge {model, context_lines,
  max_findings, policy_file, write_confidence_floor}, filigree, clarion), with
  types and a complete valid example. Note that unknown/mistyped keys are hard
  errors (fail-loud jsonschema). Verify key names/constraints against the
  schema source.

- [ ] **Step 2: `docs/guides/suppression.md`** — the three suppression layers:
  baseline (`wardline baseline create|update`, run the real `--help`), waivers
  (with expiry, `.wardline` location), and judged false-positives
  (`.wardline/judged.yaml`, written by the judge). Explain when to use which.
  Paste real `wardline baseline --help` / `wardline baseline create --help`.

- [ ] **Step 3: `docs/guides/judge.md`** — the opt-in LLM triage judge:
  what it does, that it's dependency-free (stdlib urllib → OpenRouter),
  `WARDLINE_OPENROUTER_API_KEY` / `.env` handling, the `--write` confidence
  floor, and a real `wardline judge --help`. Frame as opt-in and never
  required. Mention it writes confirmed FPs to `.wardline/judged.yaml`.

- [ ] **Step 4: `docs/guides/loom.md`** — Loom integration: SARIF output
  (`--format sarif --output`), the native Filigree emitter (`--filigree-url`),
  and Clarion producer conformance. Ground in the integration brief + SP4 spec.
  Note SARIF works with any consumer (e.g. GitHub code scanning), as the
  project dogfoods in its own CI.

- [ ] **Step 5: Strict build** → zero warnings.

- [ ] **Step 6: Controller commits** (`docs(sp7): guides (config/suppression/judge/loom)`)

---

### Task 6: Reference (CLI + trust vocabulary)

**Files:**
- Modify: `docs/reference/cli.md`, `docs/reference/vocabulary.md`
- Read: `src/wardline/decorators/__init__.py`,
  `src/wardline/decorators/trust.py`

- [ ] **Step 1: Capture real `--help` for every command:**

```
.venv/bin/wardline --help
.venv/bin/wardline scan --help
.venv/bin/wardline judge --help
.venv/bin/wardline vocab --help
.venv/bin/wardline baseline --help
.venv/bin/wardline baseline create --help
.venv/bin/wardline baseline update --help
```

- [ ] **Step 2: `docs/reference/cli.md`** — one section per command, each with
  its **pasted real `--help`** in a fenced block plus a one-line purpose and a
  realistic example. Cover: `scan`, `judge`, `vocab`, `baseline create`,
  `baseline update`, and `--version`.

- [ ] **Step 3: `docs/reference/vocabulary.md`** — the three importable
  decorators with their **exact** names from `decorators/__init__.py`
  (`trusted`, `trust_boundary`, `external_boundary`), what each declares,
  signatures from `trust.py`, and a short usage example for each. Cross-check
  against `wardline vocab` output. Note these are static-analysis markers (no
  runtime behavior).

- [ ] **Step 4: Strict build** → zero warnings.

- [ ] **Step 5: Controller commits** (`docs(sp7): reference (cli + vocabulary)`)

---

### Task 7: Signature page — "Using Wardline with your coding agent"

**Files:**
- Modify: `docs/agents.md`
- Read: `src/wardline/cli/scan.py`, `src/wardline/cli/judge.py`, this spec §2/§4

- [ ] **Step 1: Write `docs/agents.md`** — the thesis page. Grounded **entirely
  in today's shipped CLI**:
  - Why: a 1–2 dev team arming agents wants a trust-boundary gate the agent can
    run itself.
  - **Wire `wardline scan` into the loop:** a pre-commit hook or CI step using
    real flags (`--fail-on`, `--format sarif --output`). Show a real working
    pre-commit snippet and a real `--fail-on` invocation + output.
  - **Let the agent triage with `wardline judge`:** opt-in, how an agent reads
    judged output, the confidence floor.
  - **SARIF hand-off** to other Loom tools / code scanning.
  - A single explicit **"Coming: MCP server"** admonition — one sentence, no
    invented API. Nothing else about MCP.

- [ ] **Step 2: Verify** every flag used exists (re-check against `scan.py` /
  `judge.py`) and run each shown command for real.

- [ ] **Step 3: Strict build** → zero warnings.

- [ ] **Step 4: Controller commits** (`docs(sp7): agent-integration signature page`)

---

### Task 8: README pointer + final pass

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a docs link to `README.md`** — a short "Documentation"
  section pointing at `https://foundryside-dev.github.io/wardline/`, kept to a
  couple of lines (README stays a stub-plus-pointer; the site is canonical).

- [ ] **Step 2: Full strict build + local serve smoke check:**

```
.venv/bin/mkdocs build --strict
```
Expected: zero warnings. (Reviewer may also run `.venv/bin/mkdocs serve` and
spot-check rendering, then Ctrl-C.)

- [ ] **Step 3: Grep for un-run example commands / invented flags** across
  `docs/*.md` (every fenced `wardline …` line must correspond to a command that
  was actually executed). Fix any that slipped through.

- [ ] **Step 4: Controller commits** (`docs(sp7): README docs pointer`)

---

## Final review

After all tasks: dispatch a final reviewer over the whole `docs/` tree +
`mkdocs.yml` + `ci.yml` docs job for (a) factual accuracy of every flag/key/rule
against source, (b) `--strict` cleanliness, (c) nav completeness, (d) thesis
alignment (lean, task-oriented, no unshipped promises). Then finish the branch
(merge to `main`) and surface the GitHub Pages settings handoff to the user.
