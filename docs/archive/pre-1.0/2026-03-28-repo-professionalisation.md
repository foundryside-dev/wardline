# Repo Professionalisation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the wardline repo's public-facing surfaces to publication quality across README, metadata, CI, and community files.

**Architecture:** Six independent deliverables (README, pyproject metadata, missing files, CI upgrade, GitHub metadata, URL fixes) with no inter-task dependencies. All changes are to repo config/docs — no source code changes.

**Tech Stack:** GitHub Actions, Codecov, shields.io badges, Contributor Covenant, PEP 561

---

### Task 1: URL Consistency Fixes

**Files:**
- Modify: `CONTRIBUTING.md:17` and `:76`
- Modify: `CHANGELOG.md:29-30`
- Modify: `README.md:37`
- Modify: `SECURITY.md:16`
- Modify: `.github/CODEOWNERS` (replace `@wardline/maintainers` with `@johnm-dta`)

- [ ] **Step 1: Fix CONTRIBUTING.md**

Replace two references:

```
Line 17: git clone https://github.com/tachyon-beep/wardline.git
→       git clone https://github.com/johnm-dta/wardline.git

Line 76: Please use [GitHub Issues](https://github.com/tachyon-beep/wardline/issues) and
→        Please use [GitHub Issues](https://github.com/johnm-dta/wardline/issues) and
```

- [ ] **Step 2: Fix CHANGELOG.md**

```
Line 29: [Unreleased]: https://github.com/tachyon-beep/wardline/compare/v0.1.0...HEAD
→        [Unreleased]: https://github.com/johnm-dta/wardline/compare/v0.1.0...HEAD

Line 30: [0.1.0]: https://github.com/tachyon-beep/wardline/releases/tag/v0.1.0
→        [0.1.0]: https://github.com/johnm-dta/wardline/releases/tag/v0.1.0
```

- [ ] **Step 3: Fix SECURITY.md**

```
Line 16: [private vulnerability reporting](https://github.com/tachyon-beep/wardline/security/advisories/new)
→        [private vulnerability reporting](https://github.com/johnm-dta/wardline/security/advisories/new)
```

- [ ] **Step 4: Fix CODEOWNERS**

Replace all `@wardline/maintainers` with `@johnm-dta` (GitHub teams require an org; personal accounts use the username directly).

- [ ] **Step 5: Verify no remaining tachyon-beep references**

Run: `grep -r 'tachyon-beep' --include='*.md' --include='*.yml' --include='*.yaml' .github/ *.md`
Expected: No matches

- [ ] **Step 6: Commit**

```bash
git add CONTRIBUTING.md CHANGELOG.md SECURITY.md .github/CODEOWNERS
git commit -m "fix: update all URLs from tachyon-beep to johnm-dta (canonical repo)"
```

---

### Task 2: Missing Files (py.typed, .editorconfig, CODE_OF_CONDUCT.md)

**Files:**
- Create: `src/wardline/py.typed`
- Create: `.editorconfig`
- Create: `CODE_OF_CONDUCT.md`

- [ ] **Step 1: Create py.typed marker**

Create an empty file at `src/wardline/py.typed`. This is the PEP 561 marker that tells type checkers this package ships inline types.

```bash
touch src/wardline/py.typed
```

- [ ] **Step 2: Create .editorconfig**

```ini
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.md]
trim_trailing_whitespace = false

[*.{yml,yaml}]
indent_size = 2

[*.{json,toml}]
indent_size = 2

[Makefile]
indent_style = tab
```

- [ ] **Step 3: Create CODE_OF_CONDUCT.md**

Use Contributor Covenant v2.1. Full text at https://www.contributor-covenant.org/version/2/1/code_of_conduct/

Contact method: link to GitHub discussions or maintainer email. Use:

```markdown
## Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported to the project maintainers via
[GitHub private reporting](https://github.com/johnm-dta/wardline/security/advisories/new).
```

- [ ] **Step 4: Verify py.typed is included in wheel**

Run: `uv run python3 -c "from pathlib import Path; p = Path('src/wardline/py.typed'); print('exists' if p.exists() else 'MISSING')"`
Expected: `exists`

- [ ] **Step 5: Commit**

```bash
git add src/wardline/py.typed .editorconfig CODE_OF_CONDUCT.md
git commit -m "chore: add py.typed marker, .editorconfig, CODE_OF_CONDUCT.md"
```

---

### Task 3: pyproject.toml Metadata

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add project.urls section**

Add after the `dependencies = []` line:

```toml
keywords = [
    "security",
    "static-analysis",
    "trust-boundaries",
    "taint-analysis",
    "sarif",
    "boundary-enforcement",
]
authors = [
    { name = "John M", email = "john@wardline.dev" },
]

[project.urls]
Homepage = "https://wardline.dev"
Repository = "https://github.com/johnm-dta/wardline"
Documentation = "https://wardline.dev"
Changelog = "https://github.com/johnm-dta/wardline/blob/main/CHANGELOG.md"
Issues = "https://github.com/johnm-dta/wardline/issues"
```

- [ ] **Step 2: Add pytest-cov to dev dependencies**

Add `"pytest-cov>=5.0"` to the `[project.optional-dependencies] dev` list.

- [ ] **Step 3: Verify pyproject.toml parses**

Run: `uv run python3 -c "import tomllib; tomllib.load(open('pyproject.toml', 'rb')); print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "chore: add project URLs, keywords, authors, pytest-cov dep"
```

---

### Task 4: CI Upgrade

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/dependabot.yml`

- [ ] **Step 1: Update ci.yml with coverage and self-hosting scan**

Replace the entire file with:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 2 * * 0"

permissions:
  contents: read
  security-events: write

jobs:
  test-unit:
    name: Unit Tests + Lint + Coverage
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install uv
        uses: astral-sh/setup-uv@v4
      - name: Set up Python
        run: uv python install 3.12
      - name: Install dependencies
        run: uv venv && uv pip install -e ".[dev]"
      - name: Ruff check
        run: uv run ruff check src/ tests/
      - name: Mypy
        run: uv run mypy src/
      - name: Unit tests with coverage
        run: uv run pytest -m "not integration" --tb=short --cov=wardline --cov-report=xml --cov-report=term-missing
      - name: Upload coverage to Codecov
        if: github.event_name != 'schedule'
        uses: codecov/codecov-action@v4
        with:
          files: coverage.xml
          fail_ci_if_error: false
        env:
          CODECOV_TOKEN: ${{ secrets.CODECOV_TOKEN }}

  test-integration:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: test-unit
    steps:
      - uses: actions/checkout@v4
      - name: Install uv
        uses: astral-sh/setup-uv@v4
      - name: Set up Python
        run: uv python install 3.12
      - name: Install dependencies
        run: uv venv && uv pip install -e ".[dev]"
      - name: Integration tests
        run: uv run pytest -m integration --tb=short

  self-hosting-scan:
    name: Self-Hosting Scan
    runs-on: ubuntu-latest
    needs: test-unit
    steps:
      - uses: actions/checkout@v4
      - name: Install uv
        uses: astral-sh/setup-uv@v4
      - name: Set up Python
        run: uv python install 3.12
      - name: Install dependencies
        run: uv venv && uv pip install -e ".[dev]"
      - name: Run wardline self-hosting scan
        run: uv run wardline scan src/wardline --manifest wardline.yaml -o results.sarif
      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: wardline-self-hosting

  test-network:
    name: Network Tests (Weekly)
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - name: Install uv
        uses: astral-sh/setup-uv@v4
      - name: Set up Python
        run: uv python install 3.12
      - name: Install dependencies
        run: uv venv && uv pip install -e ".[dev]"
      - name: Network tests
        run: uv run pytest -m network --tb=short -v
```

- [ ] **Step 2: Create .github/dependabot.yml**

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
```

- [ ] **Step 3: Verify YAML is valid**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); yaml.safe_load(open('.github/dependabot.yml')); print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml .github/dependabot.yml
git commit -m "ci: add coverage reporting, self-hosting scan, dependabot"
```

---

### Task 5: README.md Rewrite

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Write the new README**

Replace the entire file. The README must include (in order):

1. **Title + badges** (one line each):
   - CI status: `[![CI](https://github.com/johnm-dta/wardline/actions/workflows/ci.yml/badge.svg)](https://github.com/johnm-dta/wardline/actions/workflows/ci.yml)`
   - Coverage: `[![codecov](https://codecov.io/gh/johnm-dta/wardline/graph/badge.svg)](https://codecov.io/gh/johnm-dta/wardline)`
   - Python: `[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)`
   - License: `[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)`
   - Typed: `[![Typed](https://img.shields.io/badge/typed-strict-blue.svg)](https://mypy-lang.org/)`

2. **One-paragraph value prop** — what wardline does, who it's for, in 3 sentences max.

3. **Install** — `pip install wardline` (and dev setup with uv)

4. **Quickstart** — 10-line example: create minimal wardline.yaml, run scan, read output. Must actually work if someone copies it.

5. **Architecture table** — subsystem, one-line description:

| Subsystem | Description |
|-----------|-------------|
| `core/` | Trust tiers, taint lattice, severity matrix |
| `scanner/` | AST-based static analysis with taint propagation |
| `scanner/rules/` | Pluggable rule implementations (PY-WL-001 through PY-WL-009) |
| `scanner/taint/` | Three-phase taint assignment (variable, function, callgraph) |
| `manifest/` | YAML manifest loading, overlay merge, coherence validation |
| `decorators/` | `@audit`, `@authority`, `@validates_shape` and friends |
| `runtime/` | Descriptor-based boundary enforcement at execution time |
| `cli/` | Click-based CLI (`scan`, `explain`, `manifest`, `corpus`) |

6. **Rules** — table of PY-WL-001 through PY-WL-009:

| Rule | Detects |
|------|---------|
| PY-WL-001 | Dict key access with fallback default |
| PY-WL-002 | Attribute access with fallback default |
| PY-WL-003 | Existence-checking as structural gate |
| PY-WL-004 | Broad exception handlers |
| PY-WL-005 | Silent exception handlers |
| PY-WL-006 | Audit-critical writes in broad handlers |
| PY-WL-007 | Runtime type-checking on internal data |
| PY-WL-008 | Validation with no rejection path |
| PY-WL-009 | Semantic validation without shape validation |

7. **Development** — test/lint/typecheck commands (3 lines)

8. **Links** — Spec docs, wardline.dev, Contributing, Security, License

- [ ] **Step 2: Verify no tachyon-beep references remain**

Run: `grep -c 'tachyon-beep' README.md`
Expected: `0`

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README with badges, architecture, rule table"
```

---

### Task 6: GitHub Repo Metadata

**Files:** None (API calls only)

- [ ] **Step 1: Switch to johnm-dta account**

```bash
gh auth switch --user johnm-dta
```

- [ ] **Step 2: Set repository topics**

```bash
gh repo edit johnm-dta/wardline --add-topic python --add-topic static-analysis --add-topic security --add-topic trust-boundaries --add-topic sarif --add-topic ast --add-topic taint-analysis
```

- [ ] **Step 3: Set homepage URL**

```bash
gh repo edit johnm-dta/wardline --homepage "https://wardline.dev"
```

- [ ] **Step 4: Verify description is adequate**

```bash
gh repo view johnm-dta/wardline --json description
```

If the description needs updating:
```bash
gh repo edit johnm-dta/wardline --description "Semantic boundary enforcement framework for Python — static taint analysis with trust tiers"
```

- [ ] **Step 5: Switch back to tachyon-beep**

```bash
gh auth switch --user tachyon-beep
```

---

### Task 7: Final Verification

**Files:** None

- [ ] **Step 1: Run tests**

Run: `uv run pytest tests/ -q --tb=short`
Expected: All pass

- [ ] **Step 2: Verify README renders**

Check that the README has no broken markdown by inspecting with:
```bash
head -20 README.md
```
Verify badge URLs are syntactically correct image links.

- [ ] **Step 3: Verify no remaining tachyon-beep references**

Run: `grep -r 'tachyon-beep' --include='*.md' --include='*.yml' --include='*.yaml' --include='*.toml' . | grep -v '.venv/' | grep -v '.git/' | grep -v 'node_modules/'`
Expected: No matches (or only in git history references)

- [ ] **Step 4: Push changes**

```bash
gh auth switch --user johnm-dta
git push
gh auth switch --user tachyon-beep
```
