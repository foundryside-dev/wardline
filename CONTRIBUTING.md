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
