# Wardline SP6 — Release Engineering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `foundryside-dev/wardline` a credibly released, agent-installable PyPI package with green CI, at 1–2-dev weight.

**Architecture:** Mostly additive files (LICENSE, community-health, GitHub workflows) adapted-and-stripped from the on-disk archive `/home/john/wardline.old`. One behavioral code change: `wardline.yaml` gains fail-loud JSON-Schema validation, retiring the dead `jsonschema` dependency. The irreversible PyPI publish is sequenced last, behind green CI.

**Tech Stack:** Python 3.12, hatchling, jsonschema (draft 2020-12), GitHub Actions, PyPI Trusted Publishing (OIDC), mkdocs deferred to SP7.

**⚠️ Git discipline for this repo:** Subagents MUST NEVER run any git command (no `add`/`commit`/`push`/`stash`/`checkout`/`restore`/`reset`/`branch`). The **controller** performs every `git`, `gh`, and tag/publish operation. Subagents create/modify files and run tests only; they report completion and the controller commits. The "Commit" steps below are **controller actions**.

**Gate (run before every commit):**
```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src
```

---

## File Structure

**Created:**
- `LICENSE` — MIT license text.
- `src/wardline/core/config_schema.py` — `WARDLINE_SCHEMA`, the single source of truth for `wardline.yaml` shape.
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` — lightweight community-health files.
- `AGENTS.md`, `CLAUDE.md` (project version) — tracked agent-onboarding docs.
- `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/dependabot.yml`
- `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`

**Modified:**
- `pyproject.toml` — URL org fix, OSI classifier, `license-files`.
- `src/wardline/core/config.py` — replace unknown-key warning with schema validation.
- `tests/unit/core/test_config.py` — replace the warns-test with a raises-test; add schema tests.
- `src/wardline/_version.py` — `0.1.0.dev0` → `0.1.0` (final task only).
- `CHANGELOG.md` — 0.1.0 release entry (final task only).

---

## Task 1: `pyproject.toml` reality fixes

**Files:**
- Modify: `pyproject.toml:15-19` (classifiers), `:38-42` (urls), `:5-13` (license-files)

- [ ] **Step 1: Fix the org in all four URLs**

In `pyproject.toml`, replace every `foundryside/wardline` with `foundryside-dev/wardline`:

```toml
[project.urls]
Homepage = "https://github.com/foundryside-dev/wardline"
Repository = "https://github.com/foundryside-dev/wardline"
Issues = "https://github.com/foundryside-dev/wardline/issues"
Changelog = "https://github.com/foundryside-dev/wardline/blob/main/CHANGELOG.md"
```

- [ ] **Step 2: Add OSI license classifier and `license-files`**

In the `[project]` table, add `license-files` directly under the `license` line:

```toml
license = "MIT"
license-files = ["LICENSE"]
```

In `classifiers`, add the OSI line (keep the existing three):

```toml
classifiers = [
    "Development Status :: 3 - Alpha",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.12",
    "Typing :: Typed",
]
```

- [ ] **Step 3: Verify the metadata parses**

Run: `.venv/bin/python -m build --sdist 2>&1 | tail -5`
Expected: a successful sdist build under `dist/` with no metadata errors. (Wheel build is exercised in Task 8; sdist is enough to validate metadata here.) Then `rm -rf dist/`.

- [ ] **Step 4: Commit** (controller)

```bash
git add pyproject.toml
git commit -m "build(sp6): fix repo org URLs, add OSI classifier + license-files"
```

---

## Task 2: `LICENSE` file

**Files:**
- Create: `LICENSE`

- [ ] **Step 1: Write the MIT license**

Create `LICENSE` with exactly this content:

```
MIT License

Copyright (c) 2026 John Morrissey

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Commit** (controller)

```bash
git add LICENSE
git commit -m "docs(sp6): add MIT LICENSE file"
```

---

## Task 3: `jsonschema` config validation (retire the dead dep)

**Files:**
- Create: `src/wardline/core/config_schema.py`
- Modify: `src/wardline/core/config.py:1-57`
- Test: `tests/unit/core/test_config.py`

- [ ] **Step 0: Add the type stubs dependency**

`jsonschema` 4.26 ships no `py.typed`, so mypy `--strict` errors with
`Library stubs not installed for "jsonschema"`. Add `types-jsonschema` to the
`dev` extra in `pyproject.toml` (alongside `types-PyYAML`):

```toml
    "types-PyYAML",
    "types-jsonschema",
```

Then install it: `.venv/bin/pip install types-jsonschema`.

- [ ] **Step 1: Write the schema module**

Create `src/wardline/core/config_schema.py`:

```python
"""JSON Schema (draft 2020-12) for ``wardline.yaml``.

Single source of truth for the config shape. ``additionalProperties: false`` at
the top level turns a typo'd key into a hard ``ConfigError`` (fail-loud), and the
schema doubles as config documentation. Bounds here MUST agree with
``parse_judge_settings`` (context_lines >= 0, max_findings >= 1, floor 0..1).
"""

from __future__ import annotations

from typing import Any

WARDLINE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "source_roots": {"type": "array", "items": {"type": "string"}},
        "exclude": {"type": "array", "items": {"type": "string"}},
        "rules": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "enable": {"type": "array", "items": {"type": "string"}},
                "severity": {"type": "object", "additionalProperties": {"type": "string"}},
            },
        },
        "baseline": {"type": "object"},
        "waivers": {"type": "array", "items": {"type": "object"}},
        "judge": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "model": {"type": "string"},
                "context_lines": {"type": "integer", "minimum": 0},
                "max_findings": {"type": "integer", "minimum": 1},
                "policy_file": {"type": "string"},
                "write_confidence_floor": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            },
        },
        "filigree": {"type": "object"},
        "clarion": {"type": "object"},
    },
}
```

- [ ] **Step 2: Replace the warns-test and add schema tests (write the failing tests)**

In `tests/unit/core/test_config.py`, **delete** `test_unknown_key_warns_not_raises` entirely and replace it with the following. Also add the new tests at the end of the file. (The `import warnings`-based behaviour is gone; `recwarn`-based `test_waivers_key_does_not_warn` still passes because no warnings are emitted.)

```python
def test_unknown_top_level_key_raises(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("bogus: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid"):
        load(p)


def test_full_valid_config_passes(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text(
        "source_roots: [src]\n"
        "exclude: ['**/x/**']\n"
        "rules:\n  enable: ['WLN-001']\n  severity: {WLN-001: WARN}\n"
        "baseline: {path: .wardline/baseline.yaml}\n"
        "waivers:\n  - fingerprint: " + ("a" * 64) + "\n    reason: ok\n"
        "judge:\n  model: anthropic/claude-opus-4-8\n  context_lines: 10\n"
        "  max_findings: 50\n  write_confidence_floor: 0.7\n"
        "filigree: {url: http://x}\n"
        "clarion: {db: .clarion/clarion.db}\n",
        encoding="utf-8",
    )
    cfg = load(p)
    assert cfg.source_roots == ("src",)
    assert cfg.judge == {
        "model": "anthropic/claude-opus-4-8", "context_lines": 10,
        "max_findings": 50, "write_confidence_floor": 0.7,
    }


def test_bad_judge_context_lines_type_raises(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("judge:\n  context_lines: lots\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(p)


def test_out_of_range_floor_raises(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("judge:\n  write_confidence_floor: 2.0\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(p)


def test_unknown_judge_key_raises(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("judge:\n  bogus_setting: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(p)
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/unit/core/test_config.py -q`
Expected: FAIL — `test_unknown_top_level_key_raises` fails (current code *warns*, doesn't raise), the judge-validation tests fail (current `load` does not validate the `judge` sub-block), and `config_schema` is imported by `config.py` only after Step 4 (so until then `load` has no schema). The four `parse_judge_settings` tests still pass.

- [ ] **Step 4: Wire schema validation into `config.load()`**

In `src/wardline/core/config.py`: remove `import warnings`, remove the `_KNOWN_KEYS` constant, add the new imports, and replace the unknown-key loop with schema validation.

Replace the top imports block (lines 1-17) so it reads:

```python
"""wardline.yaml loader. Uses the `scanner` extra (pyyaml + jsonschema)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from wardline.core.config_schema import WARDLINE_SCHEMA
from wardline.core.errors import ConfigError
```

Then inside `load()`, replace the unknown-key warning loop:

```python
    for key in raw:
        if key not in _KNOWN_KEYS:
            warnings.warn(f"unknown wardline.yaml key: {key!r}", stacklevel=2)
```

with schema validation:

```python
    try:
        jsonschema.validate(raw, WARDLINE_SCHEMA)
    except jsonschema.ValidationError as exc:
        raise ConfigError(f"invalid {path.name}: {exc.message}") from exc
```

- [ ] **Step 5: Run the full gate to verify green**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: all tests PASS (including the new config tests and the unchanged 725), ruff clean, mypy clean. The `types-jsonschema` stub added in Step 0 is what keeps mypy strict happy (verified: bare `import jsonschema` under `--strict` errors `import-untyped` without it).

- [ ] **Step 6: Commit** (controller)

```bash
git add src/wardline/core/config_schema.py src/wardline/core/config.py tests/unit/core/test_config.py pyproject.toml
git commit -m "feat(sp6): fail-loud jsonschema validation for wardline.yaml"
```

---

## Task 4: Community-health files + tracked agent docs

**Files:**
- Create: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `AGENTS.md`, `CLAUDE.md`
- Create: `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`

- [ ] **Step 1: `SECURITY.md`**

```markdown
# Security Policy

## Supported Versions

Only the latest released version of Wardline receives security fixes.

## Reporting a Vulnerability

Please report security issues privately to **john@wardline.dev** rather than
opening a public issue. Include a description, reproduction steps, and the
affected version. We aim to acknowledge reports within 7 days.
```

- [ ] **Step 2: `CONTRIBUTING.md`**

```markdown
# Contributing to Wardline

Wardline is a lightweight semantic-tainting static analyzer for Python, built
for small teams who want capable tooling without enterprise weight.

## Development setup

```bash
git clone https://github.com/foundryside-dev/wardline
cd wardline
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a PR

Run the full gate and make sure it is green:

```bash
pytest -q
ruff check src tests
mypy src
```

- Follow TDD: write the failing test first.
- Keep changes focused; one concern per PR.
- New behaviour needs tests. New `wardline.yaml` keys need a `config_schema.py` update.
```

- [ ] **Step 3: `CODE_OF_CONDUCT.md`**

```markdown
# Code of Conduct

This project adopts the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/),
version 2.1. Be respectful, assume good faith, and keep discussion focused on
the work.

Report unacceptable behaviour to **john@wardline.dev**.
```

- [ ] **Step 4: `AGENTS.md`**

```markdown
# Agents Guide

Wardline is designed to be driven by coding agents. This file orients an agent
working *in the Wardline repo itself*.

## What Wardline is

A generic, lightweight semantic-tainting static analyzer for Python. It tracks
untrusted-data flow across trust boundaries and emits structured findings
(JSONL, SARIF, or directly into Filigree). Part of the Loom suite alongside
Clarion (code intelligence) and Filigree (issue tracking).

## Layout

- `src/wardline/core/` — engine-agnostic contracts: findings, taint lattice,
  suppression, config, judge, emitters.
- `src/wardline/scanner/` — the Python AST analyzer.
- `src/wardline/decorators/` — the trust-vocabulary decorators.
- `src/wardline/cli/` — `wardline scan`, `wardline judge`, `wardline baseline`.
- `tests/` — `unit/`, `e2e/`, `conformance/`.

## The gate

Every change must pass: `pytest -q`, `ruff check src tests`, `mypy src`.
Network-marked tests (the live LLM judge e2e) are excluded by default and need
`WARDLINE_OPENROUTER_API_KEY`.
```

- [ ] **Step 5: project `CLAUDE.md`** (NOT the Filigree operator playbook currently at repo root in the dev environment)

```markdown
# Wardline — Project Guide for Claude

Wardline is a lightweight semantic-tainting static analyzer for Python, built
for 1–2-dev teams who want enterprise-class tooling without enterprise weight.

## Working in this repo

- Use TDD. Write the failing test, watch it fail, then implement.
- The gate is `pytest -q && ruff check src tests && mypy src`. It must be green
  before any commit.
- Keep the codebase dependency-light. The base package has zero runtime deps;
  optional features live behind extras (`scanner`, `loom`).
- New `wardline.yaml` configuration keys require a matching update to
  `src/wardline/core/config_schema.py` (the schema is fail-loud).

## Scope discipline

Wardline is deliberately Level 1–2 (lightweight), not a heavyweight Level-3
analyzer. Prefer precision and a small, well-justified rule set over breadth.
```

- [ ] **Step 6: Issue templates**

Create `.github/ISSUE_TEMPLATE/bug_report.yml`:

```yaml
name: Bug report
description: Report incorrect behaviour in Wardline
labels: [bug]
body:
  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
      description: What did you run, what did you expect, what did you get?
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: Wardline version
      placeholder: "0.1.0"
    validations:
      required: true
  - type: textarea
    id: repro
    attributes:
      label: Minimal reproduction
      description: A code snippet or config that triggers the issue.
```

Create `.github/ISSUE_TEMPLATE/feature_request.yml`:

```yaml
name: Feature request
description: Suggest an improvement
labels: [enhancement]
body:
  - type: textarea
    id: problem
    attributes:
      label: What problem are you trying to solve?
    validations:
      required: true
  - type: textarea
    id: proposal
    attributes:
      label: Proposed solution
```

- [ ] **Step 7: Commit** (controller)

```bash
git add SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md AGENTS.md CLAUDE.md .github/ISSUE_TEMPLATE
git commit -m "docs(sp6): lightweight community-health files + tracked agent docs"
```

---

## Task 5: CI + dependabot

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/dependabot.yml`

- [ ] **Step 1: `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 2 * * 0"

permissions:
  contents: read
  security-events: write

jobs:
  gate:
    name: Tests + Lint + Types
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install
        run: python -m pip install -e ".[dev]"
      - name: Ruff
        run: ruff check src tests
      - name: Mypy
        run: mypy src
      - name: Pytest
        run: pytest -q

  self-hosting-scan:
    name: Self-Hosting Scan (dogfood)
    runs-on: ubuntu-latest
    needs: gate
    if: github.event_name != 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install
        run: python -m pip install -e ".[dev]"
      - name: Scan self -> SARIF
        run: wardline scan src/wardline --format sarif --output results.sarif
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
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install
        run: python -m pip install -e ".[dev]"
      - name: Network tests
        run: pytest -m network -v
        env:
          WARDLINE_OPENROUTER_API_KEY: ${{ secrets.WARDLINE_OPENROUTER_API_KEY }}
```

> Invocation verified against `wardline scan --help`: SARIF requires explicit `--format sarif --output <path>` (there is no extension inference and no `-o` short flag).

- [ ] **Step 2: `.github/dependabot.yml`**

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    groups:
      python-minor-patch:
        update-types: ["minor", "patch"]
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    groups:
      actions-minor-patch:
        update-types: ["minor", "patch"]
```

- [ ] **Step 3: Validate YAML locally**

Run: `.venv/bin/python -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('.github/**/*.yml', recursive=True)]; print('yaml ok')"`
Expected: `yaml ok` (no parse errors). CI behaviour itself is verified after push in Task 7.

- [ ] **Step 4: Commit** (controller)

```bash
git add .github/workflows/ci.yml .github/dependabot.yml
git commit -m "ci(sp6): lean CI (3.12 gate + dogfood SARIF + weekly judge e2e) + dependabot"
```

---

## Task 6: Release workflow (Trusted Publishing)

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: read

jobs:
  build:
    name: Build distributions
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Build
        run: |
          python -m pip install build
          python -m build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  publish:
    name: Publish to PyPI
    runs-on: ubuntu-latest
    needs: build
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/
      - uses: pypa/gh-action-pypi-publish@release/v1
```

- [ ] **Step 2: Validate YAML locally**

Run: `.venv/bin/python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml')); print('yaml ok')"`
Expected: `yaml ok`

- [ ] **Step 3: Commit** (controller)

```bash
git add .github/workflows/release.yml
git commit -m "ci(sp6): tag-triggered release via PyPI Trusted Publishing (OIDC)"
```

> **Controller/user prerequisite (one-time, cannot be automated):** on pypi.org, add a Trusted Publisher for project `wardline` — owner `foundryside-dev`, repository `wardline`, workflow `release.yml`, environment `pypi`. Must be done before the Task 8 tag is pushed, otherwise `publish` fails loudly.

---

## Task 7: Merge to main + verify CI green (controller)

This task is controller-only (git + gh). No subagent.

- [ ] **Step 1: Run the full gate one final time**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: all green.

- [ ] **Step 2: Merge the SP6 branch to main (no-ff) and push**

```bash
git checkout main
git merge --no-ff sp6-release-engineering -m "merge(sp6): release engineering"
git push origin main
```

- [ ] **Step 3: Watch CI**

```bash
gh run watch $(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
```
Expected: the `gate` job passes; `self-hosting-scan` completes (SARIF uploaded; a finding does not fail the build). If `gate` is red, fix forward on a new branch — do NOT proceed to publish.

---

## Task 8: Inaugural `0.1.0` release (controller — IRREVERSIBLE)

Only after Task 7 shows green CI on `main` and the PyPI Trusted Publisher is configured (Task 6 prerequisite).

- [ ] **Step 1: Bump the version**

Modify `src/wardline/_version.py`:

```python
__version__ = "0.1.0"
```

- [ ] **Step 2: Update CHANGELOG**

In `CHANGELOG.md`, rename the `## [Unreleased]` section to `## [0.1.0] - 2026-05-30` (keep the existing entries) and add a fresh empty `## [Unreleased]` above it.

- [ ] **Step 3: Commit, tag, push (controller)**

```bash
git add src/wardline/_version.py CHANGELOG.md
git commit -m "release: 0.1.0"
git push origin main
git tag -a v0.1.0 -m "Wardline 0.1.0"
git push origin v0.1.0
```

- [ ] **Step 4: Watch the release run and verify PyPI**

```bash
gh run watch $(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```
Then: `curl -s -o /dev/null -w "%{http_code}\n" https://pypi.org/pypi/wardline/0.1.0/json`
Expected: release run green; the curl returns `200` (0.1.0 is live on PyPI).

---

## Task 9: Repo hygiene (controller)

- [ ] **Step 1: Delete orphaned old-version branches**

```bash
for b in 1.0-v-and-v \
  dependabot/github_actions/actions/checkout-6 \
  dependabot/github_actions/actions/setup-python-6 \
  dependabot/github_actions/actions/upload-artifact-7 \
  dependabot/github_actions/codecov/codecov-action-6 \
  dependabot/github_actions/github/codeql-action-4 \
  dependabot/pip/hypothesis-gte-6.151.12 \
  dependabot/pip/litellm-gte-1.83.4 \
  dependabot/pip/mkdocs-gte-1.6.1 \
  dependabot/pip/pymdown-extensions-gte-10.21.2; do
    gh api -X DELETE "repos/foundryside-dev/wardline/git/refs/heads/$b" && echo "deleted $b"
done
```
(Re-list first with `git ls-remote --heads origin` in case the set changed; delete exactly the stale old-version branches, not `main`.)

- [ ] **Step 2: Update repo description + topics**

```bash
gh repo edit foundryside-dev/wardline \
  --description "Generic semantic-tainting static analyzer for Python — enterprise-class trust-boundary analysis at small-team weight." \
  --add-topic static-analysis --add-topic taint-analysis \
  --add-topic trust-boundaries --add-topic security --add-topic sarif
```

---

## Self-Review

**Spec coverage:**
- §4.1 pyproject → Task 1 ✓
- §4.2 LICENSE → Task 2 ✓
- §4.3 jsonschema → Task 3 ✓
- §4.4 CI → Task 5 ✓
- §4.5 dependabot → Task 5 ✓
- §4.6 release → Task 6 ✓
- §4.7 community/agent files → Task 4 ✓
- §4.8 0.1.0 publish → Task 8 ✓
- §4.9 repo hygiene → Task 9 ✓
- §5 sequencing → Tasks ordered 1–4 (files), 5 (CI), 6 (release plumbing), 7 (merge+verify), 8 (publish last), 9 (cleanup) ✓
- §6 testing → Task 3 TDD; YAML validated locally in Tasks 5–6; CI verified in Task 7; publish verified in Task 8 ✓

**Type consistency:** `WARDLINE_SCHEMA` defined in Task 3 Step 1 and imported in Step 4 with matching name. `ConfigError` already exists (`errors.py:8`). Judge schema bounds (context_lines ≥ 0, max_findings ≥ 1, floor 0..1) match `parse_judge_settings`. Version string `"0.1.0"` consistent between Task 8 and the `v0.1.0` tag.

**Placeholder scan:** the two "verify before relying" notes (mypy jsonschema version in Task 3 Step 5; `wardline scan` SARIF invocation in Task 5 Step 1) are explicit verification instructions with concrete fallbacks, not deferred work.
