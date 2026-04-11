# Repo Professionalisation — Future Work

**Date:** 2026-03-28
**Status:** Backlog
**Parent:** 2026-03-28-repo-professionalisation-design.md

Items identified during the professionalisation pass but out of scope for the
initial delivery. Each is an independent work item.

## Documentation Site (wardline.dev)

- Build system: GitHub Pages with MkDocs Material or similar
- Content structure:
  - Landing page with value prop and trust model diagram (narrative style)
  - Getting started tutorial (install → first scan → interpret results)
  - Spec docs (port from docs/spec/, rendered with cross-references)
  - Rule reference (PY-WL-001 through PY-WL-009 with examples)
  - Architecture overview with data flow diagrams
  - Language binding guide (how to implement wardline for other languages)
  - Severity matrix interactive explorer
- Custom domain: wardline.dev (DNS configuration)
- Auto-deploy from main branch

## PyPI Publishing

- Verify package builds cleanly: `uv build`
- Test install from built wheel
- Configure trusted publishing (GitHub Actions → PyPI OIDC)
- Add publish workflow triggered on GitHub Release
- Version management strategy (manual bump vs tool)

## Social Preview Image

- 1280x640 PNG for GitHub social preview
- Wardline logo / trust-tier diagram
- Set via GitHub repo settings

## Pre-commit Hooks

- `.pre-commit-config.yaml` with:
  - ruff (lint + format)
  - mypy
  - check-yaml
  - check-toml
  - trailing-whitespace
  - end-of-file-fixer

## Branch Protection

- Require PR reviews on main
- Require CI status checks to pass
- Require signed commits (if policy)
- Prevent force-push to main

## Release Automation

- GitHub Release workflow with changelog extraction
- Automated version bumping
- Release notes generation from conventional commits

## Additional CI

- Multi-Python-version testing matrix (3.12, 3.13)
- Performance benchmarks (weekly, track regressions)
- Corpus verification in CI (`wardline corpus verify`)
