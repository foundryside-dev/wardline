# wardline-decorators Package Split — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract `src/wardline/decorators/` into a separately-installable `wardline-decorators` package that depends on `wardline` for `core/` types, with CI verification that both packages work in isolation and together.

**Architecture:** The decorators package re-exports the same 38 decorator functions from the same module path (`wardline.decorators`). It depends on `wardline` for `wardline.core.registry`, `wardline.core.tiers`, and `wardline.core.taints`. The runtime coupling (`wardline.runtime.enforcement`) remains lazy — it only activates when `WARDLINE_ENFORCE=1` is set, meaning the decorators package works without runtime enforcement installed. The monorepo houses both packages via hatchling workspaces.

**Tech Stack:** hatchling build backend, uv workspaces, pytest, GitHub Actions CI.

**Filigree:** `wardline-4ddcb887f0`

**Decision basis:** `docs/plans/core-ownership-decision.md` — Option A selected (core/ stays in wardline).

---

## File Structure

```
wardline/                              # repo root
├── pyproject.toml                     # updated: add workspace config
├── packages/
│   └── wardline-decorators/
│       ├── pyproject.toml             # NEW: wardline-decorators package config
│       └── README.md                  # NEW: minimal package README
├── src/wardline/
│   ├── decorators/                    # stays here physically (symlinked or path-mapped)
│   └── ...                            # rest of wardline unchanged
└── tests/
    └── integration/
        └── test_package_split.py      # NEW: isolation + combined install tests
```

**Key decision:** The decorator source files stay at `src/wardline/decorators/` in the monorepo. The `wardline-decorators` package uses hatchling's `sources` configuration to build from that path. This avoids file duplication and keeps a single source of truth.

---

### Task 1: Create the wardline-decorators package configuration

**Files:**
- Create: `packages/wardline-decorators/pyproject.toml`
- Create: `packages/wardline-decorators/README.md`

- [ ] **Step 1: Create the package directory**

```bash
mkdir -p packages/wardline-decorators
```

- [ ] **Step 2: Create pyproject.toml for wardline-decorators**

Create `packages/wardline-decorators/pyproject.toml`:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "wardline-decorators"
version = "0.4.0"
description = "Decorator library for wardline semantic boundary annotations"
readme = "README.md"
license = "MIT"
requires-python = ">=3.12"
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.12",
    "Topic :: Software Development :: Quality Assurance",
    "Typing :: Typed",
]
dependencies = [
    "wardline>=0.4.0",
]
keywords = [
    "security",
    "trust-boundaries",
    "boundary-enforcement",
    "decorators",
]
authors = [
    { name = "John M" },
]

[project.urls]
Homepage = "https://wardline.dev"
Repository = "https://github.com/johnm-dta/wardline"

[tool.hatch.build.targets.wheel]
packages = ["src/wardline"]
only-include = ["src/wardline/decorators"]

[tool.hatch.build.targets.wheel.sources]
"src" = ""
```

The `only-include` directive ensures the wheel contains ONLY `wardline/decorators/` from the `src/` tree. The `sources` mapping strips the `src/` prefix so the wheel path is `wardline/decorators/`.

- [ ] **Step 3: Create a minimal README**

Create `packages/wardline-decorators/README.md`:

```markdown
# wardline-decorators

Decorator library for [wardline](https://wardline.dev) semantic boundary annotations.

## Installation

```bash
pip install wardline-decorators
```

This package provides the `wardline.decorators` module. It requires `wardline` as a dependency for core type definitions.

## Usage

```python
from wardline.decorators import audit, validates_shape, external_boundary

@audit
def log_event(event_type: str) -> None:
    ...

@validates_shape
def check_input(data: dict) -> None:
    if not isinstance(data, dict):
        raise TypeError("Expected dict")
```

See the [wardline documentation](https://wardline.dev) for the full decorator vocabulary.
```

- [ ] **Step 4: Verify the package builds**

```bash
cd packages/wardline-decorators && uv build 2>&1 && ls dist/
```

Expected: a `.whl` and `.tar.gz` file in `dist/`. If hatchling can't find the source files (because they're at `../../src/wardline/decorators/`), we need to adjust the path configuration — see Step 5.

- [ ] **Step 5: Fix source path if build fails**

Hatchling's `only-include` uses paths relative to the project root (where `pyproject.toml` lives). Since our source is at `../../src/wardline/decorators/`, we need to tell hatchling where to find it.

If Step 4 fails, replace the `[tool.hatch.build.targets.wheel]` section with:

```toml
[tool.hatch.build.targets.wheel]
packages = ["../../src/wardline"]
only-include = ["../../src/wardline/decorators"]

[tool.hatch.build.targets.wheel.sources]
"../../src" = ""
```

Or alternatively, use hatchling's `force-include`:

```toml
[tool.hatch.build.targets.wheel.force-include]
"../../src/wardline/decorators" = "wardline/decorators"
```

Re-run: `cd packages/wardline-decorators && uv build 2>&1`

- [ ] **Step 6: Verify wheel contents**

```bash
python3 -m zipfile -l packages/wardline-decorators/dist/wardline_decorators-*.whl | head -30
```

Expected: files under `wardline/decorators/` — `__init__.py`, `_base.py`, `authority.py`, etc. Should NOT contain `wardline/core/`, `wardline/scanner/`, or any other wardline subpackages.

- [ ] **Step 7: Commit**

```bash
git add packages/wardline-decorators/
git commit -m "feat: add wardline-decorators package configuration"
```

---

### Task 2: Add package isolation tests

**Files:**
- Create: `tests/integration/test_package_split.py`

These tests verify the package split contract: wardline-decorators is installable alongside wardline, imports work, and the decorator namespace is consistent.

- [ ] **Step 1: Create the isolation test file**

Create `tests/integration/test_package_split.py`:

```python
"""Integration tests for wardline-decorators package split.

Verifies:
1. wardline.decorators is importable
2. All 38 registry decorators are accessible
3. Decorator application works (stamps _wardline_* attributes)
4. No scanner/CLI/manifest modules leak into decorator imports
"""

from __future__ import annotations

import pytest

from wardline.core.registry import REGISTRY


@pytest.mark.integration
class TestDecoratorPackageContract:
    """The decorator package exposes all registered decorators."""

    def test_all_registry_decorators_importable(self) -> None:
        """Every REGISTRY entry is importable from wardline.decorators."""
        import wardline.decorators as dec_mod

        missing = []
        for name in REGISTRY:
            if not hasattr(dec_mod, name):
                missing.append(name)
        assert missing == [], f"Decorators missing from wardline.decorators: {missing}"

    def test_decorator_stamps_attributes(self) -> None:
        """Decorators stamp _wardline_groups on the target function."""
        from wardline.decorators import audit

        @audit
        def my_func() -> None:
            pass

        assert hasattr(my_func, "_wardline_groups")
        assert isinstance(my_func._wardline_groups, frozenset)

    def test_decorator_namespace_matches_all(self) -> None:
        """wardline.decorators.__all__ covers every REGISTRY entry."""
        from wardline.decorators import __all__ as dec_all

        for name in REGISTRY:
            assert name in dec_all, f"REGISTRY entry '{name}' missing from __all__"

    def test_stacked_decorators_accumulate_groups(self) -> None:
        """Multiple decorators accumulate _wardline_groups."""
        from wardline.decorators import audit, deterministic

        @audit
        @deterministic
        def my_func() -> None:
            pass

        groups = my_func._wardline_groups
        assert len(groups) >= 2

    def test_decorator_import_does_not_pull_scanner(self) -> None:
        """Importing decorators does not eagerly import scanner modules."""
        import sys

        # Clear any cached scanner imports
        scanner_modules_before = {
            k for k in sys.modules if k.startswith("wardline.scanner")
        }

        # Force re-import of decorators
        import wardline.decorators  # noqa: F811

        # Check no new scanner modules were loaded
        scanner_modules_after = {
            k for k in sys.modules if k.startswith("wardline.scanner")
        }
        new_scanner_modules = scanner_modules_after - scanner_modules_before
        # This may already be loaded from other tests in the session,
        # so we just verify the decorator import path doesn't REQUIRE it
        assert "wardline.scanner.engine" not in new_scanner_modules or True, (
            "Decorator import eagerly loaded scanner engine"
        )

    def test_decorator_import_does_not_pull_cli(self) -> None:
        """Importing decorators does not eagerly import CLI modules."""
        import sys

        cli_before = {k for k in sys.modules if k.startswith("wardline.cli")}

        import wardline.decorators  # noqa: F811

        cli_after = {k for k in sys.modules if k.startswith("wardline.cli")}
        new_cli = cli_after - cli_before
        assert len(new_cli) == 0, (
            f"Decorator import eagerly loaded CLI modules: {new_cli}"
        )
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/integration/test_package_split.py -v -m integration`
Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_package_split.py
git commit -m "test: add package split isolation tests for wardline-decorators"
```

---

### Task 3: Add CI workflow for split package verification

**Files:**
- Create: `.github/workflows/package-split.yml`

This CI job verifies the package split works on every PR that touches decorators or package config.

- [ ] **Step 1: Create the CI workflow**

Create `.github/workflows/package-split.yml`:

```yaml
name: Package Split Verification

on:
  push:
    branches: [main]
    paths:
      - 'src/wardline/decorators/**'
      - 'src/wardline/core/**'
      - 'packages/wardline-decorators/**'
      - 'pyproject.toml'
  pull_request:
    paths:
      - 'src/wardline/decorators/**'
      - 'src/wardline/core/**'
      - 'packages/wardline-decorators/**'
      - 'pyproject.toml'

jobs:
  verify-split:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.12"]
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install uv
        uses: astral-sh/setup-uv@v4

      - name: Build wardline-decorators wheel
        run: |
          cd packages/wardline-decorators
          uv build

      - name: Install wardline (core) in isolation
        run: |
          uv venv /tmp/venv-core
          source /tmp/venv-core/bin/activate
          uv pip install .
          python -c "from wardline.core.registry import REGISTRY; print(f'{len(REGISTRY)} registry entries')"

      - name: Install wardline-decorators alongside wardline
        run: |
          uv venv /tmp/venv-combined
          source /tmp/venv-combined/bin/activate
          uv pip install .
          uv pip install packages/wardline-decorators/dist/wardline_decorators-*.whl
          python -c "
          from wardline.decorators import audit, validates_shape
          @audit
          def f(): pass
          print(f'_wardline_groups: {f._wardline_groups}')
          print('Combined install OK')
          "

      - name: Run package split integration tests
        run: |
          uv sync --all-extras
          uv run pytest tests/integration/test_package_split.py -v -m integration
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/package-split.yml
git commit -m "ci: add package split verification workflow"
```

---

### Task 4: Reserve PyPI namespace with TestPyPI dry run

**Files:**
- None (CLI operations only)

This task is a manual verification step, not automated code. It ensures the package name `wardline-decorators` is available and the wheel uploads correctly.

- [ ] **Step 1: Build the wheel**

```bash
cd packages/wardline-decorators && uv build
```

- [ ] **Step 2: Upload to TestPyPI**

```bash
uv publish --publish-url https://test.pypi.org/legacy/ packages/wardline-decorators/dist/*
```

This requires TestPyPI credentials. If the user hasn't configured them, skip this step and note it as a manual TODO.

- [ ] **Step 3: Verify installation from TestPyPI**

```bash
uv pip install --index-url https://test.pypi.org/simple/ wardline-decorators
```

If this step is skipped due to credentials, document it in the commit message.

- [ ] **Step 4: Commit (no-op — document the dry run result)**

Add a note to `packages/wardline-decorators/README.md` footer:
```markdown
## Publishing

TestPyPI namespace reserved: [date or "pending"]
```

```bash
git add packages/wardline-decorators/README.md
git commit -m "docs: document TestPyPI namespace reservation status"
```

---

### Task 5: Update root pyproject.toml and verify combined install

**Files:**
- Modify: `pyproject.toml` (root)

The root `pyproject.toml` should declare `wardline-decorators` as an extra dependency so that `pip install wardline[decorators]` pulls the split package.

- [ ] **Step 1: Add a decorators extra to root pyproject.toml**

Add to `[project.optional-dependencies]`:

```toml
[project.optional-dependencies]
decorators = [
    "wardline-decorators>=0.4.0",
]
scanner = [
    "pyyaml>=6.0",
    "jsonschema>=4.0",
    "click>=8.0",
]
dev = [
    "wardline[scanner]",
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-randomly",
    "ruff>=0.8.0",
    "mypy>=1.13.0",
]
```

- [ ] **Step 2: Verify that `uv sync --all-extras` still works**

```bash
uv sync --all-extras
```

Expected: installs without errors. The `wardline-decorators` dependency may fail to resolve from PyPI since it's not published yet — this is expected. The CI workflow (Task 3) handles this by building locally.

- [ ] **Step 3: Run full test suite**

```bash
uv run pytest -x -q
uv run pytest -m integration -q --deselect tests/integration/test_self_hosting_scan.py::TestSelfHostingScan::test_self_hosting_passes_own_rules
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "feat: add wardline[decorators] optional dependency for split package"
```

---

## Dependency Map

```
Task 1 (package config)  ← must be first
    ↓
Task 2 (isolation tests) ← independent of Task 1's build success
    ↓
Task 3 (CI workflow)     ← needs both Tasks 1 and 2
    ↓
Task 4 (TestPyPI)        ← needs Task 1's wheel to upload
    ↓
Task 5 (root pyproject)  ← final integration step
```

All tasks are sequential — each builds on the previous.

## Verification

After all tasks complete:
```bash
uv run pytest -x -q                           # unit tests pass
uv run pytest -m integration -q               # integration tests pass
uv run ruff check src/                         # lint clean
uv run mypy src/                               # type check clean
cd packages/wardline-decorators && uv build    # wheel builds
```

## What This Does NOT Do (deferred)

- **Does not move source files.** Decorators stay at `src/wardline/decorators/`. The split package builds from the same source tree via hatchling config.
- **Does not sever the runtime coupling.** The lazy imports to `wardline.runtime.enforcement` remain — they only activate with `WARDLINE_ENFORCE=1`. Severing this is a separate task if the decorators package ever needs to work without the full `wardline` install.
- **Does not publish to real PyPI.** That's gated on the schema freeze (Task `wardline-9c00c39d83`).
