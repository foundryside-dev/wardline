.DEFAULT_GOAL := help
.PHONY: help install lint format typecheck test test-cov scan-self docs build clean ci

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install all extras + dev tooling
	uv sync --all-extras --group dev

lint:  ## Run linter + format check + layering contracts
	uv run ruff check src tests
	uv run ruff format --check src tests
	uv run lint-imports

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
	@set -eu; \
	for path in dist build *.egg-info .mypy_cache .ruff_cache .pytest_cache; do \
		if [ ! -e "$$path" ] && [ ! -L "$$path" ]; then \
			continue; \
		fi; \
		if [ -L "$$path" ]; then \
			echo "refusing to remove symlink $$path" >&2; \
			exit 1; \
		fi; \
		rm -rf -- "$$path"; \
	done; \
	rm -f -- .coverage coverage.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

ci: lint typecheck test-cov  ## Run the full local CI gate
