# Wardline repo standardization — design

**Date:** 2026-06-01
**Status:** approved (brainstorming → ready for plan)
**Branch:** `docs/repo-standardization`

## Problem

Wardline's engine, docs site, and test suite are first-class, but the *repo
presentation* lags its sibling [filigree](/home/john/filigree): the README is a
9-line pointer, CI is single-Python with no coverage gate, there is no Makefile,
pre-commit, or ROADMAP, and CONTRIBUTING is a stub. The project "feels like an
afterthought" next to filigree.

A second, equally important problem: there is no crisp line between **how to
*use* Wardline** (guidance that ships into every user's agent context) and **how
to *develop* Wardline** (guidance that belongs only in this repo). The two must
not blur.

## Goals

1. Bring the repo up to the filigree standard: rich README, fuller CONTRIBUTING,
   ROADMAP, Makefile, pre-commit, hardened CI, full uv toolchain parity.
2. Establish and document the **use ⇄ develop** split so each surface has one
   unambiguous home.
3. Change **no engine/source behavior** and **no analyzer features**. This is a
   presentation + tooling + docs pass.

## Non-goals

- No changes to `src/wardline/` engine, scanner, rules, or CLI behavior.
- No restructure of the mkdocs doc site (`docs/concepts`, `docs/guides`,
  `docs/reference`). The README *surfaces* those pages; it does not replace them.
- No change to the *wording* of the install-injected instruction block
  (`install/block.py` `_BODY`) — only its role is documented. (Note: editing
  `_BODY` would change its body hash and the `inject_block` fence; deliberately
  avoided here.)

## The use ⇄ develop split

This is the organizing principle, not a side note.

| Audience | Surface | Owns |
|---|---|---|
| **Users** (agents armed with Wardline in *their* projects) | The `wardline install` instruction block (`install/block.py`), the `wardline-gate` skill (`src/wardline/skills/wardline-gate/SKILL.md`), and `docs/agents.md` | The scan → explain → fix-at-boundary → rescan loop; baseline-vs-waiver discipline; exit codes; CLI vs MCP usage. |
| **Developers** (anyone changing Wardline itself) | This repo's `CLAUDE.md` and `AGENTS.md` | Dev commands (uv/make), the L1/L2/L3 architecture, package map, conventions, error model. |

**Actions:**

- `CLAUDE.md` already carries the developer guidance (added 2026-06-01). Add a
  one-line **Audience** banner near the top: *"This file is for developing
  Wardline. End-user 'how to use Wardline' guidance lives in the
  install-injected instruction block, the `wardline-gate` skill, and the docs
  site — not here."*
- **Mirror** the developer guidance into `AGENTS.md` (above the auto-managed
  Filigree block, same as filigree treats its `AGENTS.md`), with the same
  Audience banner. The two files carry identical Wardline guidance; the Filigree
  block below the markers stays as-is in both.
- The user-facing surfaces are left functionally unchanged; the spec records
  them as canonical so future edits land in the right place.

## Deliverables

### 1. README.md (replace the 9-line stub)

Target ~150–180 lines, filigree-class. Sections, in order:

- Title + one-line tagline + badges: CI status, PyPI version, supported
  Python versions, license (shields.io, pointed at
  `github.com/foundryside-dev/wardline` and `pypi.org/project/wardline`).
- **Hero block.** Wardline has no GUI, so in place of filigree's dashboard
  screenshot, show a short real terminal session: a decorated source snippet and
  the resulting `PY-WL-101` finding + gate exit. (Use the canonical
  `read_request`/`build_record` example from `docs/concepts/model.md` so it
  stays consistent with the docs.)
- **What is Wardline?** Trust-tainting in two sentences; part of the **Loom**
  suite (Wardline + Clarion + Filigree); the opt-in / zero-dependency-base
  stance.
- **Key Features** (bullets): deterministic whole-program taint; opt-in trust
  decorators; four policy rules; zero-dep base + extras; SARIF + JSONL + native
  Filigree emit; dep-free MCP-over-stdio server; optional LLM triage judge;
  baseline/waiver suppression; `wardline install` agent enablement; Clarion
  taint-store integration.
- **Quick Start**: `pip install wardline[scanner]`, decorate a boundary +
  producer, `wardline scan . --fail-on ERROR`, read the finding.
- **Installation** + extras table (`scanner`, `clarion`, `docs`; base is
  zero-dep; judge needs no extra).
- **Agent setup**: `wardline install` (what it wires), the `wardline-gate`
  skill, `wardline mcp`.
- **Where Wardline fits / When NOT to use it**: L1–L2 taint, not full L3
  interprocedural everything; Python ≥3.12 only; opt-in (silent on undecorated
  code by design); not a replacement for a SAST suite. Honest framing, no
  combative feature-matrix against Bandit/Semgrep/CodeQL.
- **Documentation** table linking the live mkdocs pages
  (getting-started, concepts/model, concepts/rules, guides/configuration,
  guides/suppression, guides/judge, guides/clarion-taint-store, reference/cli,
  reference/vocabulary, agents).
- **Development**: `uv sync --all-extras --group dev`; `make ci`; pointer to
  CONTRIBUTING and CLAUDE.md.
- **License** (MIT) + **Acknowledgements** (the Loom siblings).

### 2. uv toolchain migration (full filigree parity)

- Convert the `dev` optional-dependency to a PEP 735 `[dependency-groups].dev`
  containing pure tooling: `pytest`, `pytest-cov`, `pytest-randomly`, `ruff`,
  `mypy`, `types-PyYAML`, `types-jsonschema`. (The current `dev` extra's
  self-references `wardline[scanner]`/`wardline[clarion]` do not translate to
  dependency-groups; runtime deps come from the extras instead — see below.)
- Keep runtime extras `scanner` / `clarion` / `docs` as
  `[project.optional-dependencies]` (the source of truth for runtime deps).
- Canonical dev sync everywhere (Makefile, CI, CONTRIBUTING):
  **`uv sync --all-extras --group dev`** — installs base + scanner + clarion +
  docs + dev tooling, so tests that need pyyaml/jsonschema/click/blake3 and the
  docs build all have what they need.
- Build backend stays **hatchling** (uv only manages the environment/lockfile).
- Add `uv.lock` (generated via `uv lock`) and `.python-version` = `3.13`.
- Add `[tool.coverage.run] source = ["wardline"]` and a `[tool.coverage.report]`
  block to pyproject; do **not** add `--cov-fail-under` to default pytest
  `addopts` (keeps bare `pytest`/`uv run pytest` fast — the floor lives in the CI
  test job and `make test-cov`).
- `release.yml`: replace the `pip install build` + `python -m build` step with
  `uv build`. **The publish job is unchanged** — `pypa/gh-action-pypi-publish`
  with PyPI Trusted Publishing (id-token) stays exactly as is. Packages still
  ship to PyPI.

### 3. CI hardening (`.github/workflows/ci.yml`)

- Add `concurrency: { group: ..., cancel-in-progress: true }`.
- Switch installs to `astral-sh/setup-uv` (with cache) + `uv sync --all-extras
  --group dev`.
- Split the single `gate` job into:
  - **lint** — `uv run ruff check src tests` + `uv run ruff format --check src tests`.
  - **typecheck** — `uv run mypy`.
  - **test** — matrix `python-version: ["3.12", "3.13"]`, `uv run pytest
    --cov=wardline --cov-report=term-missing --cov-fail-under=90`. (Current
    coverage is 94% / 4165 stmts; 90% is an honest floor with headroom.)
- Keep, rewired onto uv, and gated on the new jobs as appropriate:
  - **self-hosting-scan** (dogfood `wardline scan src/wardline --format sarif` →
    upload-sarif), `needs` the test job.
  - **network** (weekly `pytest -m network`, schedule-only).
  - **docs** (mkdocs `build --strict`; `gh-deploy` on push to main).
- `ruff format` is introduced as a check; the repo must be formatted once so the
  check passes from day one (see Risks).

### 4. Makefile

filigree-style with a `help` default target. Targets (all via `uv run` /
`uv sync`): `install`, `lint`, `format`, `typecheck`, `test`, `test-cov`
(`--cov-fail-under=90`), `scan-self` (dogfood), `docs` (`mkdocs serve`),
`build` (`uv build`), `clean`, and `ci` (`lint typecheck test-cov`).

### 5. .pre-commit-config.yaml

`astral-sh/ruff-pre-commit` with `ruff-check --fix` and `ruff-format`. (No mypy
in pre-commit — keep commits fast; mypy is a CI/`make` gate.)

### 6. Project docs

- **CONTRIBUTING.md** expanded to filigree depth: uv dev setup, code-style
  (ruff line-length 120, mypy strict), a Conventional Commits type table, PR
  process gated on `make ci`, bug/feature report template links, a "first-time
  contributors" pointer, and an Architecture section that points at `CLAUDE.md`
  rather than duplicating it. TDD expectation retained from the current file.
- **ROADMAP.md** — short and honest: current state (0.3.0, SP0–SP9 shipped),
  the deliberate **L1–L2 scope** (not full L3), and near-term threads linked to
  the open Filigree issues (N-hop `explain_taint` chain completeness;
  return-indirection in `compute_return_callee`; taint-combination hardening
  epic; star-import decorator-marker FN). No invented dates.
- **CODE_OF_CONDUCT.md** — expand the 279-byte stub to the standard Contributor
  Covenant v2.1, contact `john@wardline.dev`.
- **SECURITY.md** — already adequate; leave as-is.

## Risks & mitigations

- **`ruff format --check` may fail on the existing tree.** Mitigation: run
  `uv run ruff format src tests` once as part of this work and commit the
  (expected-minimal) reformat before the check goes live. Verify the diff is
  formatting-only.
- **uv.lock drift / uv not in CI.** Mitigation: generate `uv.lock` locally with
  the available `uv 0.10.2`; CI uses `astral-sh/setup-uv` pinned. `uv sync`
  is `--frozen`-compatible.
- **Dependency-group migration breaks `pip install -e .[dev]` muscle memory.**
  Mitigation: CONTRIBUTING and CLAUDE/AGENTS dev commands switch to
  `uv sync --all-extras --group dev`; the README Development section says the
  same. (`pip install -e .[scanner]` etc. for *runtime* extras still works.)
- **Coverage floor too tight.** Mitigation: floor set at 90% vs measured 94%.
- **Release pipeline regression.** Mitigation: only the build *step* changes to
  `uv build`; the publish job (Trusted Publishing) is byte-for-byte preserved
  and called out as a hard constraint.

## Verification

- `uv sync --all-extras --group dev` succeeds from a clean checkout.
- `make ci` is green: ruff check + ruff format --check + mypy strict + pytest
  with `--cov-fail-under=90`.
- `uv build` produces an sdist + wheel; `twine check dist/*` passes (local
  proxy for the release job).
- `mkdocs build --strict` is green.
- README renders (no broken links to the doc-site pages); badges resolve.
- `CLAUDE.md` and `AGENTS.md` carry identical Wardline developer guidance + the
  Audience banner, with the Filigree block intact below the markers in both.
- `wardline scan src/wardline` still runs clean (dogfood unaffected).
