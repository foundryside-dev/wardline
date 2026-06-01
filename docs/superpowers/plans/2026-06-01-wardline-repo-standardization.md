# Wardline Repo Standardization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Wardline repo up to the filigree presentation standard (README, CONTRIBUTING, ROADMAP, Makefile, pre-commit, hardened CI, full uv parity) and document the use ⇄ develop split — with zero engine/source behavior changes.

**Architecture:** Pure tooling + docs pass. Migrate the dev workflow to `uv` (PEP 735 dependency-groups, `uv.lock`, `.python-version`), keep hatchling as the build backend and `scanner`/`clarion`/`docs` as runtime extras. Split CI into lint/typecheck/test(matrix)+coverage and keep the dogfood/network/docs jobs. Rewrite the README to filigree class, expand the project docs, and mirror developer guidance into `CLAUDE.md` + `AGENTS.md` while leaving the user-facing surfaces (install block, `wardline-gate` skill, `docs/agents.md`) untouched.

**Tech Stack:** uv 0.10.2, hatchling, ruff, mypy (strict), pytest + pytest-cov, GitHub Actions (`astral-sh/setup-uv@v7`), mkdocs-material, PyPI Trusted Publishing.

**Spec:** `docs/superpowers/specs/2026-06-01-wardline-repo-standardization-design.md`
**Branch:** `docs/repo-standardization` (already created off `main`)

---

## File Structure

**Create:**
- `.python-version` — pins the dev interpreter (3.13)
- `uv.lock` — generated lockfile
- `Makefile` — dev task entry points
- `.pre-commit-config.yaml` — ruff hooks
- `ROADMAP.md` — current state + near-term direction

**Modify:**
- `pyproject.toml` — `dev` extra → `[dependency-groups]`; add `[tool.coverage.*]`
- `.github/workflows/ci.yml` — uv + split jobs + matrix + coverage floor
- `.github/workflows/release.yml` — build step → `uv build` (publish job unchanged)
- `README.md` — 9-line stub → filigree-class
- `CONTRIBUTING.md` — expand to filigree depth (uv, conventional commits, PR gate)
- `CODE_OF_CONDUCT.md` — stub → canonical Contributor Covenant (fetched, not inlined here)
- `CLAUDE.md` — add Audience banner
- `AGENTS.md` — mirror developer guidance above the Filigree block + Audience banner
- Possibly `src/wardline/**`, `tests/**` — formatting-only churn from `ruff format` (Task 2)

**Leave untouched (use-surface, by design):** `src/wardline/install/block.py`, `src/wardline/skills/wardline-gate/SKILL.md`, `docs/agents.md`, `SECURITY.md`, the mkdocs doc-site pages.

---

## Task 1: Migrate the dev toolchain to uv

**Files:**
- Modify: `pyproject.toml` (the `[project.optional-dependencies].dev` block at lines ~28-38; add coverage config)
- Create: `.python-version`
- Create: `uv.lock` (generated)

- [ ] **Step 1: Replace the `dev` optional-dependency with a PEP 735 dependency-group**

In `pyproject.toml`, delete the `dev = [...]` entry from `[project.optional-dependencies]` (keep `scanner`, `docs`, `clarion`). The block becomes:

```toml
[project.optional-dependencies]
scanner = ["pyyaml>=6.0", "jsonschema>=4.0", "click>=8.0"]
docs = ["mkdocs>=1.6", "mkdocs-material>=9.5"]
clarion = ["blake3>=1.0"]
# The SP5 LLM triage judge is dependency-free (stdlib urllib -> OpenRouter); no extra needed.
```

Then add a new top-level table (after `[project.optional-dependencies]`):

```toml
[dependency-groups]
# Tooling only. Runtime deps live in the extras above; `uv sync --all-extras
# --group dev` installs base + scanner + clarion + docs + this group, which is
# the canonical dev sync used by the Makefile, CI, and CONTRIBUTING.
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-randomly",
    "ruff>=0.8.0",
    "mypy>=1.13.0",
    "types-PyYAML",
    "types-jsonschema",
]
```

- [ ] **Step 2: Add coverage configuration**

Append to `pyproject.toml`:

```toml
[tool.coverage.run]
source = ["wardline"]
branch = true

[tool.coverage.report]
show_missing = true
```

Do NOT add `--cov-fail-under` to `[tool.pytest.ini_options].addopts` — the floor lives in CI and `make test-cov` so bare `pytest` stays fast. Leave `addopts = "-m 'not network and not clarion_e2e'"` as-is.

- [ ] **Step 3: Create `.python-version`**

```
3.13
```

- [ ] **Step 4: Generate the lockfile and sync**

Run:
```bash
uv lock
uv sync --all-extras --group dev
```
Expected: `uv.lock` is created; sync creates/updates `.venv` and reports the resolved packages with no error.

- [ ] **Step 5: Verify the suite still passes under uv**

Run: `uv run pytest -q`
Expected: `1001 passed, 2 deselected` (same as the pip venv).

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .python-version uv.lock
git commit -m "build: adopt uv (dependency-groups, lockfile, .python-version)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Format the tree once so `ruff format --check` will pass

**Files:**
- Modify: `src/wardline/**`, `tests/**` (formatting-only, if any)

CI (Task 5) introduces `ruff format --check`. The repo was previously linted but never `ruff format`-ed, so format once now and confirm the diff is formatting-only.

- [ ] **Step 1: Run the formatter**

Run: `uv run ruff format src tests`
Expected: prints `N files reformatted, M files left unchanged` (N may be 0).

- [ ] **Step 2: Confirm the diff is formatting-only**

Run: `git diff --stat` then spot-check `git diff`.
Expected: only whitespace/quote/line-wrap changes — NO logic changes. If any change looks semantic, stop and investigate (ruff format should never alter behavior).

- [ ] **Step 3: Verify lint + types + tests still green**

Run:
```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest -q
```
Expected: ruff check clean; `format --check` reports all files already formatted; mypy clean; `1001 passed`.

- [ ] **Step 4: Commit (skip if Step 1 reformatted 0 files)**

```bash
git add -A
git commit -m "style: apply ruff format across src and tests

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Add the Makefile

**Files:**
- Create: `Makefile`

- [ ] **Step 1: Write the Makefile**

```makefile
.DEFAULT_GOAL := help
.PHONY: help install lint format typecheck test test-cov scan-self docs build clean ci

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install all extras + dev tooling
	uv sync --all-extras --group dev

lint:  ## Run linter + format check
	uv run ruff check src tests
	uv run ruff format --check src tests

format:  ## Auto-format and fix lint
	uv run ruff format src tests
	uv run ruff check --fix src tests

typecheck:  ## Run mypy strict
	uv run mypy

test:  ## Run tests (no coverage)
	uv run pytest -q

test-cov:  ## Run tests with coverage gate (90%)
	uv run pytest --cov=wardline --cov-report=term-missing --cov-fail-under=90

scan-self:  ## Dogfood: scan wardline's own source
	uv run wardline scan src/wardline --fail-on ERROR

docs:  ## Serve the docs site locally
	uv run mkdocs serve

build:  ## Build sdist + wheel
	uv build

clean:  ## Remove build + cache artifacts
	rm -rf dist/ build/ *.egg-info .mypy_cache .ruff_cache .pytest_cache .coverage coverage.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

ci: lint typecheck test-cov  ## Run the full local CI gate
```

- [ ] **Step 2: Verify each target resolves**

Run: `make help`
Expected: prints the target list with descriptions.

Run: `make ci`
Expected: ruff check + format-check + mypy clean, then pytest reports `1001 passed` and coverage `TOTAL ... 94%` (≥90%, gate passes).

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "build: add Makefile with ci/lint/format/test targets

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Add the pre-commit config

**Files:**
- Create: `.pre-commit-config.yaml`

- [ ] **Step 1: Write the config**

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.8.6
    hooks:
      - id: ruff-check
        args: [--fix]
      - id: ruff-format
```

(mypy is deliberately a CI/`make` gate, not a pre-commit hook, to keep commits fast.)

- [ ] **Step 2: Verify it parses**

Run: `python -c "import yaml,sys; yaml.safe_load(open('.pre-commit-config.yaml')); print('ok')"`
Expected: `ok`.

(If `pre-commit` is installed: `uv run --with pre-commit pre-commit run --all-files` — optional; not required to pass since the tree was just formatted in Task 2.)

- [ ] **Step 3: Commit**

```bash
git add .pre-commit-config.yaml
git commit -m "build: add ruff pre-commit hooks

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Harden CI

**Files:**
- Modify: `.github/workflows/ci.yml` (full rewrite)

- [ ] **Step 1: Rewrite `ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 2 * * 0"

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read
  security-events: write

jobs:
  lint:
    name: Lint + Format
    runs-on: ubuntu-latest
    if: github.event_name != 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v7
        with:
          enable-cache: true
          python-version: "3.13"
      - run: uv sync --all-extras --group dev
      - run: uv run ruff check src tests
      - run: uv run ruff format --check src tests

  typecheck:
    name: Types (mypy strict)
    runs-on: ubuntu-latest
    if: github.event_name != 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v7
        with:
          enable-cache: true
          python-version: "3.13"
      - run: uv sync --all-extras --group dev
      - run: uv run mypy

  test:
    name: Tests + Coverage
    runs-on: ubuntu-latest
    if: github.event_name != 'schedule'
    strategy:
      matrix:
        python-version: ["3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v7
        with:
          enable-cache: true
          python-version: ${{ matrix.python-version }}
      - run: uv sync --all-extras --group dev
      - run: uv run pytest --cov=wardline --cov-report=term-missing --cov-fail-under=90

  self-hosting-scan:
    name: Self-Hosting Scan (dogfood)
    runs-on: ubuntu-latest
    needs: test
    if: github.event_name != 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v7
        with:
          enable-cache: true
          python-version: "3.13"
      - run: uv sync --all-extras --group dev
      - name: Scan self -> SARIF
        run: uv run wardline scan src/wardline --format sarif --output results.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: wardline-self-hosting

  network:
    name: Live judge e2e (weekly)
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v7
        with:
          enable-cache: true
          python-version: "3.13"
      - run: uv sync --all-extras --group dev
      - name: Network tests
        run: uv run pytest -m network -v
        env:
          WARDLINE_OPENROUTER_API_KEY: ${{ secrets.WARDLINE_OPENROUTER_API_KEY }}

  docs:
    name: Docs (build + deploy)
    runs-on: ubuntu-latest
    needs: test
    if: github.event_name != 'schedule'
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v7
        with:
          enable-cache: true
          python-version: "3.13"
      - run: uv sync --extra docs
      - name: Build (strict)
        run: uv run mkdocs build --strict
      - name: Deploy (main only)
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        run: uv run mkdocs gh-deploy --force
```

- [ ] **Step 2: Validate the workflow YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Locally reproduce each gate the CI runs**

Run:
```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest --cov=wardline --cov-report=term-missing --cov-fail-under=90
uv run wardline scan src/wardline --format sarif --output /tmp/results.sarif && echo "scan ok"
uv run mkdocs build --strict
```
Expected: every command exits 0; coverage ≥90%; mkdocs builds with no warnings; `scan ok` prints.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: uv + 3.12/3.13 matrix + 90% coverage floor + format check

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Switch the release build to `uv build` (keep PyPI publish)

**Files:**
- Modify: `.github/workflows/release.yml` (the `build` job only)

- [ ] **Step 1: Replace the build step**

In `release.yml`, the `build` job's steps become:

```yaml
  build:
    name: Build distributions
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v7
        with:
          enable-cache: true
          python-version: "3.13"
      - name: Build
        run: uv build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
```

Leave the `publish` job EXACTLY as it is (download-artifact → `pypa/gh-action-pypi-publish@release/v1`, `environment: pypi`, `permissions: id-token: write`). This is the hard constraint: packages must still publish to PyPI via Trusted Publishing.

- [ ] **Step 2: Validate YAML + local build**

Run:
```bash
python -c "import yaml; d=yaml.safe_load(open('.github/workflows/release.yml')); assert 'publish' in d['jobs'] and d['jobs']['publish']['environment']=='pypi'; print('publish job intact')"
uv build
ls dist/
uv run --with twine twine check dist/*
```
Expected: `publish job intact`; `dist/` contains a `.tar.gz` sdist and a `.whl`; `twine check` reports `PASSED` for both. Confirm the wheel includes the force-included data files:
```bash
python -c "import zipfile,glob; w=glob.glob('dist/*.whl')[0]; names=zipfile.ZipFile(w).namelist(); assert any('stdlib_taint.yaml' in n for n in names) and any('vocabulary.yaml' in n for n in names) and any('SKILL.md' in n for n in names); print('data files packaged')"
```
Expected: `data files packaged`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: build release artifacts with uv build (publish job unchanged)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Rewrite the README

**Files:**
- Modify: `README.md` (full replace)

- [ ] **Step 1: Write the new README**

````markdown
# Wardline

Generic, lightweight semantic-tainting static analyzer for Python — track untrusted data across your codebase and gate trust-boundary violations, with zero runtime dependencies.

[![CI](https://github.com/foundryside-dev/wardline/actions/workflows/ci.yml/badge.svg)](https://github.com/foundryside-dev/wardline/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/wardline)](https://pypi.org/project/wardline/)
[![Python 3.12+](https://img.shields.io/pypi/pyversions/wardline)](https://pypi.org/project/wardline/)
[![License: MIT](https://img.shields.io/pypi/l/wardline)](https://github.com/foundryside-dev/wardline/blob/main/LICENSE)

```python
from wardline.decorators import trusted, external_boundary

@external_boundary
def read_request(req):
    return req.body            # raw, untrusted (EXTERNAL_RAW)

@trusted(level="ASSURED")
def build_record(req):
    return read_request(req)   # claims ASSURED, returns raw — no validation
```

```console
$ wardline scan . --fail-on ERROR
demo.build_record declares return trust ASSURED but actually returns
EXTERNAL_RAW (less trusted) — untrusted data reaches a trusted producer  [PY-WL-101]
  demo.py:7
gate: tripped (1 active defect >= ERROR)
$ echo $?
1
```

## What is Wardline?

Wardline reads your Python statically — it never runs your code — and asks one
question of every trust-annotated function: **is the data this function works
with as trusted as it claims?** It tracks a *taint* (a trust level) for every
value and propagates it across the whole project, flagging the places where
untrusted data reaches a trusted producer with no validation in between.

Wardline is part of the **Loom** suite alongside **Clarion** (code intelligence)
and **Filigree** (issue tracking). It is built for small teams who want capable
analysis tooling without enterprise weight.

**Opt-in by design.** Wardline is silent until you opt in. Undecorated code sits
in the developer-freedom zone — unknown-trust, no findings. You declare trust on
the functions that matter, and only then does Wardline enforce it. That is what
lets it scan a large untouched codebase (including its own) with zero noise.

## Key Features

- **Deterministic whole-program taint** — function-, variable-, and project-level
  analysis over an inter-module call graph; no runtime instrumentation.
- **Opt-in trust model** — three decorators (`@external_boundary`,
  `@trust_boundary`, `@trusted`) mark your boundaries; the engine infers the rest.
- **Four policy rules** — untrusted-reaches-trusted, non-rejecting boundary,
  broad exception handler, and silently-swallowed exception.
- **Zero-dependency base** — `pip install wardline` pulls nothing; functionality
  lives behind small extras.
- **Structured output** — JSONL, SARIF (GitHub code-scanning), and native
  Filigree emit.
- **Agent-native** — `wardline mcp` is a dependency-free MCP-over-stdio server;
  `wardline install` wires Wardline into your coding agent in one command.
- **Opt-in LLM triage** — `wardline judge` labels findings TRUE/FALSE positive
  (dependency-free; never runs automatically).
- **Light-touch suppression** — baselines and time-boxed, reasoned waivers.
- **Clarion integration** — persist per-entity taint facts to a Clarion store.

## Quick Start

```bash
pip install wardline[scanner]
```

```python
# app.py
from wardline.decorators import trusted, external_boundary

@external_boundary
def read_request(req):
    return req.body

@trusted(level="ASSURED")
def build_record(req):
    return read_request(req)
```

```bash
wardline scan . --fail-on ERROR   # exit 0 = clean, 1 = gate tripped, 2 = wardline error
```

Fix findings at the **boundary** (validate before returning), not at the sink.

## Installation

```bash
pip install wardline            # zero-dependency base (library + decorators)
pip install wardline[scanner]   # the scan/judge/baseline CLI + MCP server
```

| Extra | Pulls | Enables |
|-------|-------|---------|
| `scanner` | pyyaml, jsonschema, click | the `wardline` CLI and `wardline mcp` server |
| `clarion` | blake3 | persisting taint facts to a Clarion store |
| `docs` | mkdocs, mkdocs-material | building the documentation site |

The LLM triage judge (`wardline judge`) is dependency-free (stdlib `urllib` →
OpenRouter) and needs no extra.

## Use Wardline with your coding agent

```bash
wardline install
```

This injects a hash-fenced instruction block into `CLAUDE.md`/`AGENTS.md`,
installs the `wardline-gate` skill, merges a `wardline` entry into `.mcp.json`,
and records Clarion/Filigree bindings if present. Agents then run the
scan → explain → fix-at-boundary → rescan loop natively. The `wardline mcp`
server exposes `scan`, `explain_taint`, `judge`, baseline, and waiver tools over
JSON-RPC with no SDK.

## Where Wardline fits

Use Wardline when you want a deterministic, opt-in trust-boundary gate you can
run in CI and hand to an agent — lightweight, Python-native, no external service.

It is **not** the right tool when you need:

- **Full interprocedural everything.** Wardline is precise at the function and
  project-call-graph level (L1–L2 with an L3 fixed point), not an exhaustive,
  path-sensitive whole-program prover.
- **A broad SAST suite.** Wardline checks trust boundaries and a small set of
  exception-handling rules; it is not a replacement for a general-purpose
  scanner that covers dozens of vulnerability classes.
- **Non-Python code.** Wardline analyzes Python ≥3.12 only.
- **Zero-config coverage.** Wardline is silent until you declare trust — that is
  the point, but it means it finds nothing on an un-annotated codebase.

## Documentation

Full documentation lives at **<https://foundryside-dev.github.io/wardline/>**.

| Document | Description |
|----------|-------------|
| [Getting Started](https://foundryside-dev.github.io/wardline/getting-started/) | Install, decorate, first scan |
| [Taint & Trust Model](https://foundryside-dev.github.io/wardline/concepts/model/) | The lattice, decorators, and propagation |
| [Rules](https://foundryside-dev.github.io/wardline/concepts/rules/) | The four policy rules |
| [Configuration](https://foundryside-dev.github.io/wardline/guides/configuration/) | `wardline.yaml`: rules, severity, excludes |
| [Suppression](https://foundryside-dev.github.io/wardline/guides/suppression/) | Baselines and waivers |
| [LLM Triage Judge](https://foundryside-dev.github.io/wardline/guides/judge/) | Opt-in TRUE/FALSE-positive labelling |
| [Clarion Taint Store](https://foundryside-dev.github.io/wardline/guides/clarion-taint-store/) | Persisting taint facts |
| [CLI Reference](https://foundryside-dev.github.io/wardline/reference/cli/) | Every command and flag |
| [Trust Vocabulary](https://foundryside-dev.github.io/wardline/reference/vocabulary/) | The decorators and their arguments |
| [Agent Integration](https://foundryside-dev.github.io/wardline/agents/) | Using Wardline from a coding agent |

## Development

Requires Python ≥3.12. Developed on 3.13 with [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/foundryside-dev/wardline
cd wardline
uv sync --all-extras --group dev

make ci          # ruff check + format check + mypy strict + pytest (90% coverage floor)
make lint        # ruff check + format --check
make format      # auto-format and fix
make typecheck   # mypy strict
make test        # pytest
make scan-self   # dogfood: scan wardline's own source
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow and
[CLAUDE.md](CLAUDE.md) for the developer architecture guide.

## Acknowledgements

Wardline is one of the **Loom** tools (with Clarion and Filigree) — small,
local-first, agent-native developer tooling.

## License

[MIT](LICENSE) — Copyright (c) 2026 John Morrissey
````

- [ ] **Step 2: Verify links and that the hero example matches the docs**

Run: `grep -c "foundryside-dev.github.io/wardline" README.md`
Expected: ≥10 (the doc table + intro).

Confirm the hero `PY-WL-101` example matches `docs/concepts/model.md` (the `read_request`/`build_record` pair). Read both and check they agree.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: filigree-class README (features, quick start, agent setup, fit)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Expand CONTRIBUTING

**Files:**
- Modify: `CONTRIBUTING.md` (full replace)

- [ ] **Step 1: Write the new CONTRIBUTING**

````markdown
# Contributing to Wardline

Wardline is a lightweight semantic-tainting static analyzer for Python, built
for small teams who want capable tooling without enterprise weight. Bug reports,
feature ideas, docs fixes, and code changes are all welcome.

## Reporting bugs

Open a [bug report](https://github.com/foundryside-dev/wardline/issues/new?template=bug_report.yml). Include:

- Wardline version (`wardline --version`)
- Whether you hit it via the CLI or the MCP server
- A minimal decorated snippet that reproduces the finding (or its absence)
- Expected vs actual behavior
- Python version and OS

## Suggesting features

Open a [feature request](https://github.com/foundryside-dev/wardline/issues/new?template=feature_request.yml). Describe the problem you are solving and your proposed approach.

## Development setup

Wardline uses [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/foundryside-dev/wardline
cd wardline
uv sync --all-extras --group dev
```

This installs the base package, every runtime extra (`scanner`, `clarion`,
`docs`), and the dev tooling (ruff, mypy, pytest) into `.venv`.

## Code style

- **Linter / formatter:** [ruff](https://docs.astral.sh/ruff/) (config in `pyproject.toml`, line-length 120)
- **Type checker:** mypy in strict mode (`src/wardline` only)
- **Tests:** pytest, run under `pytest-randomly` (order-dependence is a real bug)

Before committing:

```bash
make format      # auto-fix formatting and lint
make lint        # check without modifying (same as CI)
make typecheck   # mypy strict
```

A ruff pre-commit hook is available — `uv run --with pre-commit pre-commit install`.

## Running tests

```bash
make test        # quick run
make test-cov    # with coverage; CI enforces a 90% floor
```

The `network` (live OpenRouter judge) and `clarion_e2e` (real `clarion serve`)
suites are deselected by default. Opt in with `uv run pytest -m network` /
`uv run pytest -m clarion_e2e` (the latter needs a route-capable Clarion binary —
see `CLAUDE.md`).

## Conventions

- **TDD.** Write the failing test first.
- Keep PRs focused — one logical change per PR.
- New behavior needs tests. New `wardline.yaml` keys need a `config_schema.py` update.
- No back-compat shims for unreleased specs — make clean changes.
- Wardline scans its own source as a CI gate; keep the tree finding-clean (or baselined).

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>
```

| Type | When to use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding or updating tests |
| `ci` | CI/CD pipeline changes |
| `build` | Build system or packaging changes |
| `refactor` | Neither fixes a bug nor adds a feature |
| `style` | Formatting only |
| `chore` | Maintenance (deps, config) |

Use `!` after the type for breaking changes: `refactor!: rename public API`.

## Pull request process

1. Branch from `main`.
2. Make your change (test-first).
3. Run `make ci` until green (ruff check + format check + mypy strict + pytest with the 90% coverage floor).
4. Open a PR against `main`, describing what and why; link related issues.
5. Ensure the CI checks pass.

## First-time contributors

Good starting points: documentation improvements, tests for uncovered paths, and
CLI help-text polish.

## Architecture

The big-picture developer guide — the L1/L2/L3 taint pipeline, the package map,
and the conventions — lives in [CLAUDE.md](CLAUDE.md). Read it before a
non-trivial change.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## License

By contributing, you agree your contributions are licensed under the [MIT License](LICENSE).
````

- [ ] **Step 2: Verify**

Run: `python -c "open('CONTRIBUTING.md').read().index('Conventional Commits'); print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs: expand CONTRIBUTING (uv, conventional commits, PR gate)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Add ROADMAP

**Files:**
- Create: `ROADMAP.md`

- [ ] **Step 1: Write ROADMAP.md**

```markdown
# Wardline Roadmap

Wardline is a lightweight, opt-in semantic-tainting analyzer for Python. This is
a direction sketch, not a commitment — dates are deliberately omitted.

## Where we are

**0.3.0 — shipped.** The staged build (SP0–SP9) is complete:

- Function-, variable-, and project-level taint over an inter-module call graph
  (L1–L2 with an L3 fixed point).
- The NG-25 trust vocabulary and three opt-in decorators.
- Four policy rules (PY-WL-101..104), severity/enable config, baselines + waivers.
- JSONL + SARIF + native Filigree emit.
- Dependency-free MCP-over-stdio server (`wardline mcp`).
- Opt-in LLM triage judge (`wardline judge`).
- `wardline install` agent enablement.
- Opt-in Clarion taint-store integration.
- Published to PyPI; docs site live; CI dogfoods Wardline on its own source.

## Scope

Wardline is deliberately **L1–L2 with an L3 project fixed point**, not an
exhaustive path-sensitive whole-program prover, and Python-only. We favor a
small, precise, opt-in rule set over broad SAST coverage.

## Near-term threads

Tracked in the project's Filigree issues:

- **N-hop `explain_taint` chain completeness** — full boundary-chain reconstruction
  on the explain surface (`wardline-82f49ec3c3`).
- **Return-indirection in `compute_return_callee`** — explain-surface completeness
  for returns routed through intermediates (`wardline-82f49ec3c3`).
- **Taint-combination hardening** — first-class hardening from the 2026-05-31
  audit (`wardline-2b138b3662`).
- **Star-import decorator markers** — resolve `from x import *` so trust markers
  are not missed (`wardline-2b427a9579`).

## Out of scope (for now)

- Languages other than Python.
- A general-purpose, dozens-of-rules SAST suite.
- A hosted/cloud service — Wardline stays local-first.
```

- [ ] **Step 2: Verify the referenced issues exist**

Run: `filigree get wardline-82f49ec3c3 2>/dev/null | head -1 || filigree list-issues 2>/dev/null | grep -E "2b138b3662|2b427a9579|82f49ec3c3"`
Expected: the issue IDs resolve. If an ID has changed, update the ROADMAP to match the current open issues before committing.

- [ ] **Step 3: Commit**

```bash
git add ROADMAP.md
git commit -m "docs: add ROADMAP (current state, scope, near-term threads)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Expand the Code of Conduct

**Files:**
- Modify: `CODE_OF_CONDUCT.md` (full replace)

> Do NOT paste the Contributor Covenant text into this plan (copyright). Fetch the
> canonical Markdown and fill in the contact.

- [ ] **Step 1: Fetch the canonical Contributor Covenant v2.1 Markdown**

Obtain the official text from <https://www.contributor-covenant.org/version/2/1/code_of_conduct/code_of_conduct.md> (or `WebFetch` it). It is published under CC BY 4.0; keep its attribution footer intact.

- [ ] **Step 2: Write `CODE_OF_CONDUCT.md`**

Write the fetched Contributor Covenant v2.1 verbatim, with the single
enforcement-contact placeholder (`[INSERT CONTACT METHOD]`) replaced by
`john@wardline.dev`. Keep the trailing attribution/links section the license
requires.

- [ ] **Step 3: Verify**

Run: `grep -q "john@wardline.dev" CODE_OF_CONDUCT.md && grep -qi "Contributor Covenant" CODE_OF_CONDUCT.md && echo ok`
Expected: `ok`. Confirm the placeholder `[INSERT CONTACT METHOD]` is gone:
`! grep -q "INSERT CONTACT" CODE_OF_CONDUCT.md && echo "placeholder removed"`.

- [ ] **Step 4: Commit**

```bash
git add CODE_OF_CONDUCT.md
git commit -m "docs: adopt Contributor Covenant v2.1

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Document the use ⇄ develop split (Audience banner + mirror to AGENTS.md)

**Files:**
- Modify: `CLAUDE.md` (add Audience banner near the top of the Wardline section)
- Modify: `AGENTS.md` (insert the full Wardline developer guidance above the Filigree block)

The Wardline developer guidance currently lives only in `CLAUDE.md`, above the
`<!-- filigree:instructions ... -->` block. `AGENTS.md` currently holds ONLY the
Filigree block. This task adds an Audience banner to both and mirrors the
guidance into `AGENTS.md`.

- [ ] **Step 1: Add the Audience banner to `CLAUDE.md`**

In `CLAUDE.md`, immediately after the `# CLAUDE.md` header line and its
"This file provides guidance..." line, the existing blockquote about the Filigree
block stays. Add this Audience banner as the FIRST line of the
"## What Wardline is" section (insert immediately before that heading):

```markdown
> **Audience — developing Wardline.** This file (and `AGENTS.md`) is for people
> and agents changing Wardline itself. End-user "how to *use* Wardline" guidance
> is NOT here — it lives in the `wardline install` instruction block, the
> `wardline-gate` skill (`src/wardline/skills/wardline-gate/SKILL.md`), and the
> docs site. Keep usage guidance out of this file.

```

- [ ] **Step 2: Build `AGENTS.md` = banner + Wardline guidance + Filigree block**

`AGENTS.md` must become: the same Wardline developer guidance that is in
`CLAUDE.md` (everything from the `# CLAUDE.md` header through the end of the
"## Conventions" section, i.e. everything ABOVE the `<!-- filigree:instructions`
marker), followed by the existing Filigree block that is already in `AGENTS.md`.

Mechanically:
1. Read `CLAUDE.md`. Copy everything from the top down to (but NOT including) the
   line `<!-- filigree:instructions:v2.2.0:9dff6e6d -->`. Call this `WG` (Wardline guidance, now including the Audience banner from Step 1).
2. In that copied text, change the first line from `# CLAUDE.md` to `# AGENTS.md`
   and the second sentence from "...when working with code in this repository."
   to read "This file provides guidance to coding agents (Claude Code, Codex,
   etc.) when working with code in this repository." (Adjust the existing
   blockquote note that currently says "AGENTS.md is the byte-identical Filigree
   twin of this file; the Wardline guidance here is not mirrored there." — it is
   now inaccurate. Replace that sentence in BOTH files with: "Its twin
   `CLAUDE.md`/`AGENTS.md` carries the same Wardline guidance; the Filigree block
   below is auto-managed in each.")
3. Read the current `AGENTS.md` and copy the Filigree block (from
   `<!-- filigree:instructions:v2.2.0:9dff6e6d -->` through
   `<!-- /filigree:instructions -->`). Call this `FB`.
4. Write `AGENTS.md` = `WG` + `\n` + `FB` + `\n`.

- [ ] **Step 3: Verify both files**

Run:
```bash
grep -q "Audience — developing Wardline" CLAUDE.md && echo "claude banner ok"
grep -q "Audience — developing Wardline" AGENTS.md && echo "agents banner ok"
grep -q "## What Wardline is" AGENTS.md && grep -q "filigree:instructions" AGENTS.md && echo "agents has both sections"
head -1 AGENTS.md   # expect: # AGENTS.md
# Confirm the stale "not mirrored there" sentence is gone from both:
! grep -q "not mirrored there" CLAUDE.md && ! grep -q "not mirrored there" AGENTS.md && echo "stale note removed"
```
Expected: all four `echo`s print, `head -1` shows `# AGENTS.md`, and "stale note removed" prints.

- [ ] **Step 4: Confirm the Filigree block is byte-identical in both (markers intact)**

Run:
```bash
sed -n '/<!-- filigree:instructions/,/<!-- \/filigree:instructions -->/p' CLAUDE.md > /tmp/fb_claude
sed -n '/<!-- filigree:instructions/,/<!-- \/filigree:instructions -->/p' AGENTS.md > /tmp/fb_agents
diff /tmp/fb_claude /tmp/fb_agents && echo "filigree block identical"
```
Expected: `filigree block identical`.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md AGENTS.md
git commit -m "docs: audience banner + mirror developer guidance into AGENTS.md

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Final verification gate

**Files:** none (verification only)

- [ ] **Step 1: Clean-room sync + full local CI**

Run:
```bash
rm -rf .venv
uv sync --all-extras --group dev
make ci
```
Expected: sync succeeds from clean; `make ci` is green (ruff check + format check + mypy strict + pytest `1001 passed` + coverage ≥90%).

- [ ] **Step 2: Build + package integrity**

Run:
```bash
make build
uv run --with twine twine check dist/*
```
Expected: sdist + wheel built; `twine check` PASSED for both.

- [ ] **Step 3: Docs strict build**

Run: `uv run mkdocs build --strict`
Expected: builds with zero warnings.

- [ ] **Step 4: Dogfood scan still clean**

Run: `make scan-self`
Expected: exit 0 (no active defect ≥ ERROR in `src/wardline`).

- [ ] **Step 5: Workflow YAML lint**

Run:
```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); yaml.safe_load(open('.github/workflows/release.yml')); print('workflows ok')"
```
Expected: `workflows ok`.

- [ ] **Step 6: Push the branch and open a PR**

```bash
git push -u origin docs/repo-standardization
gh pr create --title "Bring repo up to the filigree standard" --body "$(cat <<'EOF'
Implements docs/superpowers/specs/2026-06-01-wardline-repo-standardization-design.md.

- uv toolchain (dependency-groups, uv.lock, .python-version); build stays hatchling
- CI: 3.12/3.13 matrix + ruff format check + 90% coverage floor; dogfood/network/docs jobs preserved
- release.yml builds with `uv build`; PyPI Trusted Publishing job unchanged
- Makefile + ruff pre-commit
- filigree-class README; expanded CONTRIBUTING; ROADMAP; Contributor Covenant
- Audience banner + developer guidance mirrored into CLAUDE.md and AGENTS.md
- No engine/source behavior changes (formatting-only churn from `ruff format`)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```
Expected: PR opens against `main`; remote CI runs green.

---

## Self-Review

**Spec coverage:**
- Use ⇄ develop split → Task 11 (banner + AGENTS mirror); user surfaces left untouched (stated, no task — correct).
- README → Task 7. uv migration → Task 1. CI hardening → Task 5. release `uv build` + PyPI preserved → Task 6. Makefile → Task 3. pre-commit → Task 4. CONTRIBUTING → Task 8. ROADMAP → Task 9. CoC → Task 10. `ruff format --check` precondition → Task 2. Final verification → Task 12. All spec sections covered.

**Placeholder scan:** No "TBD/TODO". The only intentional non-inline content is the Contributor Covenant body (Task 10) — copyright; the plan instructs fetching it and gives exact verification. All config/doc files have complete content.

**Type/name consistency:** Canonical dev command is `uv sync --all-extras --group dev` everywhere (Tasks 1, 3, 5, 6, 8, 12, README). Coverage floor `--cov-fail-under=90` consistent (Tasks 3, 5, 8, 12). `[dependency-groups].dev` (Task 1) matches every `uv sync` invocation. Job name `test` referenced by `needs: test` (Task 5) matches the defined job. README badges/links use `foundryside-dev/wardline` and `pypi.org/project/wardline` consistently.
