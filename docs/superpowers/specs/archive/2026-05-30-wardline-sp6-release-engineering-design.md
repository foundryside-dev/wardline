# Wardline SP6 — Release Engineering Design

**Status:** Approved (design), pending spec review
**Date:** 2026-05-30
**Author:** John Morrissey (with Claude)
**Supersedes the predecessor's release apparatus:** `/home/john/wardline.old`

---

## 1. Goal

Make `foundryside-dev/wardline` a credibly **released, agent-installable**
package on PyPI with **green CI**, at the weight a 1–2-dev team can carry — not
enterprise weight.

This is the credibility floor beneath everything else on the roadmap. It
unblocks the PyPI install path that the docs site (SP7) and the MCP server
(SP8) will both assume.

## 2. North Star & Non-Goals

**Thesis (the filter for every decision):** *enterprise-class tools for teams
of 1–2 devs who want to enable their AI agents — without enterprise-class
weight.*

**Explicitly OUT of scope** — the machinery the reboot deliberately shed
(present in `wardline.old`, must NOT return):

- `benchmark.yml`, `corpus.yml`, `package-split.yml` workflows
- Multi-version test matrix (we pin 3.12, our only supported runtime)
- CodeQL scanning, Codecov upload (external accounts/tokens = weight)
- `docs/governance`, `docs/verification`, ADR apparatus, formal V&V
- Any signing / HMAC / counter-signature governance

**Also out (deferred to their own specs):** the full mkdocs docs *site* (SP7)
and the MCP server (SP8). SP6 touches docs only enough to make the README and
`pyproject` honest.

## 3. Template Source

Adapt from the on-disk archive `/home/john/wardline.old` (NOT the GC-able
dangling commit `a5bb789`). Files to mine and strip: `ci.yml`, `dependabot.yml`,
`LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, the issue
templates. Each is adapted to the dep-free lightweight build (3.12-only, no
`uv`-vs-pip dogma, no litellm/hypothesis, no governance sections).

## 4. Work Items

### 4.1 `pyproject.toml` reality fixes

- URLs `foundryside` → `foundryside-dev` (4 occurrences: Homepage, Repository,
  Issues, Changelog).
- Add classifier `"License :: OSI Approved :: MIT License"`.
- Keep PEP 639 `license = "MIT"`; add `license-files = ["LICENSE"]`.
- Leave `version` dynamic (sourced from `_version.py`); leave
  `Development Status :: 3 - Alpha` (honest for 0.1.0).

### 4.2 `LICENSE` file

MIT, copyright "John Morrissey", current year. Adapt from `wardline.old/LICENSE`
(verify it is the standard MIT text; replace only the copyright line if needed).

### 4.3 `jsonschema` config validation (retire the dead dep)

`jsonschema>=4.0` is declared in the `scanner` extra but unused. Wire it:

- Add `src/wardline/core/config_schema.py` exporting `WARDLINE_SCHEMA` (a Python
  dict / JSON Schema draft 2020-12) describing the full `wardline.yaml` surface:
  `source_roots` (array of str), `exclude` (array of str), `rules`
  (`{enable: array[str], severity: object[str→str]}`), `baseline` (object),
  `waivers` (array of objects), `judge`
  (`{model: str, context_lines: int≥0, max_findings: int≥1, policy_file: str,
  write_confidence_floor: number 0..1}`), `filigree` (object), `clarion`
  (object). `additionalProperties: false` at the top level — this is what turns
  the current *warning* on unknown keys into a hard error.
- In `config.load()`, replace the `_KNOWN_KEYS` warning loop with
  `jsonschema.validate(raw, WARDLINE_SCHEMA)`, wrapping
  `jsonschema.ValidationError` in `ConfigError` (fail-loud, consistent with the
  existing `ConfigError` for malformed YAML / non-mapping top level). The schema
  is the single source of truth and doubles as config documentation.
- `parse_judge_settings` keeps its own type checks (defence in depth; it runs on
  the already-validated `judge` sub-mapping). The schema and `parse_judge_settings`
  bounds must agree (context_lines ≥ 0, max_findings ≥ 1, floor 0..1).
- `jsonschema` moves from a silent dependency to a load-bearing one: it stays in
  the `scanner` extra (config loading already requires `pyyaml` from that extra).

### 4.4 CI — `.github/workflows/ci.yml`

Adapted and stripped from `wardline.old/ci.yml`. Triggers: `push` to `main`,
`pull_request`, and `schedule` (weekly cron for the network job).

- **Job `gate`** (the required check): checkout → setup Python 3.12 →
  `pip install -e ".[dev]"` → `ruff check src tests` → `mypy src` →
  `pytest -q` (network excluded by the existing `addopts = "-m 'not network'"`).
- **Job `self-hosting-scan`** (dogfood; `needs: gate`): run
  `wardline scan src/wardline -o results.sarif` and upload via
  `github/codeql-action/upload-sarif@v3` to the Security tab
  (`GITHUB_TOKEN` only — no external account). On-thesis: the tool demonstrates
  itself. `if: always()` so a finding doesn't fail the build.
- **Job `network`** (`if: github.event_name == 'schedule'`): runs
  `pytest -m network` with `WARDLINE_OPENROUTER_API_KEY` from repo secrets — the
  live judge e2e.
- No Codecov, no integration job (no `integration` marker exists in this build).
  Coverage may be printed (`--cov=wardline --cov-report=term-missing`) but is not
  gated or uploaded.

**Prerequisite (user action, documented in the plan):** add the
`WARDLINE_OPENROUTER_API_KEY` repo secret. Until then the scheduled network job
no-ops safely (skips on missing key is acceptable; document it).

### 4.5 `dependabot.yml`

Lean version: `pip` (the `dev`/`scanner`/`loom` extras) and `github-actions`,
weekly schedule, grouped minor/patch updates to reduce PR noise.

### 4.6 Release — `.github/workflows/release.yml`

Trigger on tag `v*`. Build with `python -m build` (sdist + wheel), then publish
via **PyPI Trusted Publishing (OIDC)** using
`pypa/gh-action-pypi-publish` with `permissions: id-token: write`. No stored
token. Gated: the release job `needs` the `gate` job (or runs only after CI is
green on that ref).

**Prerequisite (user action):** one-time PyPI Trusted Publisher config on
pypi.org (project name `wardline`, owner `foundryside-dev`, workflow
`release.yml`). Documented in the plan; cannot be automated.

### 4.7 Community-health files (lightweight scale)

- `SECURITY.md` — how to report a vulnerability (private contact), supported
  versions = latest.
- `CONTRIBUTING.md` — short: clone, `pip install -e ".[dev]"`, run the gate
  (`pytest -q && ruff check src tests && mypy src`), PR conventions. No CLA, no
  governance board.
- `CODE_OF_CONDUCT.md` — Contributor Covenant, contact = maintainer.
- `.github/ISSUE_TEMPLATE/bug_report.yml` + `feature_request.yml`, adapted lean.
- `AGENTS.md` + `CLAUDE.md` — **tracked**, lightweight, on-thesis (this is an
  agent-enablement tool; public agent-onboarding docs are a feature). Strip any
  references to the old heavy workflow; describe the rebuild's gate and layout.
  Note: the repo-root `CLAUDE.md` currently carries Filigree workflow
  instructions — the committed public version should be a *project* CLAUDE.md
  (what the tool is, how to work in it), not the Filigree operator playbook.

### 4.8 Inaugural release `0.1.0`

Bump `src/wardline/_version.py` from `0.1.0.dev0` → `0.1.0`. Update
`CHANGELOG.md` with the 0.1.0 entry. Publish **last**, by hand-cut annotated tag
`v0.1.0`, only after §4.1–4.7 are merged and CI is green. A version number is
never reusable — this step is deliberately the final, irreversible action.

### 4.9 Repo hygiene

- Delete the orphaned old-version remote branches: `1.0-v-and-v` and the
  ~9 `dependabot/*` branches (litellm/hypothesis/old-actions) via
  `gh api -X DELETE repos/foundryside-dev/wardline/git/refs/heads/<branch>`.
- Update the GitHub repo description + topics to match the rebuild
  (`gh repo edit`): description from the new `pyproject` summary; topics
  `static-analysis`, `taint-analysis`, `trust-boundaries`, `security`, `sarif`.

## 5. Sequencing

Strict order (each gate before the next):

1. **Local files & config** — §4.1, §4.2, §4.3, §4.7 (everything that's a
   committed file + the jsonschema code, with tests). Merge to `main`.
2. **CI** — §4.4, §4.5. Push; verify the `gate` job goes green on `main`.
3. **Release plumbing** — §4.6 (workflow file committed; user does the one-time
   PyPI Trusted Publisher config).
4. **Publish** — §4.8. The irreversible `0.1.0` tag, only after 1–3 are green.
5. **Cleanup** — §4.9.

## 6. Testing

- **§4.3 jsonschema** is the only production *code* change and gets real TDD:
  unit tests in `tests/unit/core/test_config.py` for (a) a valid full config
  passing, (b) an unknown top-level key now *raising* `ConfigError` (previously
  warned), (c) wrong-typed values (e.g. `context_lines: "x"`,
  `write_confidence_floor: 2.0`) raising `ConfigError`, (d) schema/`parse_judge_settings`
  bound agreement. The existing 725-test suite must stay green.
- **CI/workflows/community files** are config/text, not unit-tested in-repo;
  they are verified by the CI run itself going green on `main` (§5 step 2) and by
  a clean local `python -m build`.
- **Release** is verified by the `v0.1.0` tag producing a successful
  Trusted-Publishing run and the package appearing on PyPI.

## 7. Risks & Mitigations

- **Irreversible publish.** Mitigated by sequencing it last, behind green CI +
  clean build, at `0.1.0` (not the old `1.0.0`).
- **Trusted Publishing misconfig.** The one-time PyPI config is a documented
  user prerequisite; the workflow fails loudly (no silent token fallback) if it
  is absent.
- **Schema too strict breaks a valid config.** Mitigated by deriving the schema
  directly from the current `WardlineConfig`/`parse_judge_settings` surface and
  testing a known-good full config passes.
- **Re-importing weight.** Mitigated by the §2 non-goals list and the on-disk
  template-strip discipline (§3).

## 8. Deliverables

A merged `main` with: corrected `pyproject`, `LICENSE`, jsonschema-validated
config (+ tests), lean CI + dependabot + release workflows, lightweight
community-health files + tracked `AGENTS.md`/`CLAUDE.md`, a published `0.1.0` on
PyPI, and a cleaned-up remote.
