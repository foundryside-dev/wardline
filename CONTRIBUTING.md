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
