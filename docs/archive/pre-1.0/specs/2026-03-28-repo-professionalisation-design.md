# Repo Professionalisation

**Date:** 2026-03-28
**Status:** Approved
**Scope:** Public-facing repo surfaces, CI, metadata

## Context

Wardline is public on GitHub (johnm-dta/wardline) but the repo's public-facing
surfaces don't match the rigour of the codebase. This pass brings the repo to
publication quality.

**Audiences:**
1. Security engineers / compliance teams evaluating adoption
2. Python developers integrating boundary enforcement
3. Language-binding implementers using wardline as a reference implementation

**Canonical URL:** johnm-dta/wardline (tachyon-beep is a dev fork)
**Documentation site:** wardline.dev (not built in this pass)

## Deliverables

### 1. README.md rewrite

- Badge bar: CI status, coverage, PyPI version, Python version, license
- One-paragraph value proposition (not a sales pitch)
- `pip install wardline` + 10-line quickstart that runs
- Architecture table (subsystem, purpose, one line each)
- Rule summary table (PY-WL-001 through PY-WL-009)
- Links: spec docs, wardline.dev, contributing, license
- All URLs → johnm-dta/wardline

### 2. pyproject.toml metadata

```toml
[project.urls]
Homepage = "https://wardline.dev"
Repository = "https://github.com/johnm-dta/wardline"
Documentation = "https://wardline.dev"
Changelog = "https://github.com/johnm-dta/wardline/blob/main/CHANGELOG.md"
Issues = "https://github.com/johnm-dta/wardline/issues"
```

Add `keywords` field. Add `authors` field.

### 3. Missing files

| File | Content |
|------|---------|
| `src/wardline/py.typed` | Empty marker (PEP 561) |
| `.editorconfig` | root=true, utf-8, lf, 4-space indent, 140 line length (matches ruff) |
| `CODE_OF_CONDUCT.md` | Contributor Covenant v2.1 |

### 4. CI upgrade (.github/workflows/ci.yml)

**Coverage reporting:**
- Add `pytest-cov` to dev dependencies
- Run pytest with `--cov=wardline --cov-report=xml`
- Upload coverage XML to Codecov
- Badge in README

**Self-hosting scan:**
- New CI job: `wardline scan src/wardline --manifest wardline.yaml -o results.sarif`
- Upload SARIF to GitHub Security tab via `github/codeql-action/upload-sarif`
- Runs on push to main and PRs

**Dependabot:**
- `.github/dependabot.yml` for pip ecosystem and GitHub Actions

### 5. GitHub repo metadata (via gh CLI)

- Topics: `python`, `static-analysis`, `security`, `trust-boundaries`, `sarif`, `ast`
- Homepage: `https://wardline.dev`
- Description: already set, verify adequate

### 6. URL consistency fixes

All references to `tachyon-beep/wardline` → `johnm-dta/wardline`:
- CONTRIBUTING.md clone URL
- CHANGELOG.md release links
- README.md clone URL
- CODEOWNERS team references (if applicable)

## Out of Scope

Captured separately in `docs/superpowers/specs/2026-03-28-repo-professionalisation-future.md`.

## Constraints

- No new documentation content beyond README — deeper docs go on wardline.dev
- No PyPI publishing in this pass
- No branch protection configuration (requires admin access)
- Badge URLs should work even before Codecov/PyPI are wired — use shields.io with fallback
