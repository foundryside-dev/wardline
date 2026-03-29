# Wardline

[![CI](https://github.com/johnm-dta/wardline/actions/workflows/ci.yml/badge.svg)](https://github.com/johnm-dta/wardline/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/johnm-dta/wardline/graph/badge.svg)](https://codecov.io/gh/johnm-dta/wardline)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Typed](https://img.shields.io/badge/typed-strict-blue.svg)](https://mypy-lang.org/)

Wardline defines a four-tier trust hierarchy for Python codebases and statically verifies that data flows respect those boundaries. It catches trust-boundary violations — untrusted input reaching privileged code, missing validation at tier transitions — via AST analysis with taint propagation. Results are emitted as SARIF v2.1.0 for direct integration with GitHub Code Scanning and CI pipelines.

## Install

```bash
pip install wardline
```

Dev setup:

```bash
git clone https://github.com/johnm-dta/wardline.git
cd wardline
uv sync --all-extras
```

## Quickstart

Create `wardline.yaml` in your project root:

```yaml
$id: "https://wardline.dev/schemas/1.0/wardline.schema.json"

tiers:
  - id: "primary_db"
    tier: 1
  - id: "partner_api"
    tier: 4

module_tiers:
  - path: "src/myapp/core/"
    default_taint: "ASSURED"
  - path: "src/myapp/adapters/"
    default_taint: "EXTERNAL_RAW"

metadata:
  organisation: "My Company"
```

Annotate trust-critical functions:

```python
from wardline.decorators import integrity_critical, validates_shape

@integrity_critical
def write_audit_log(event: dict) -> None:
    ...

@validates_shape
def check_payload(data: dict) -> None:
    if not isinstance(data, dict):
        raise TypeError("Expected dict")
```

Run the scanner:

```bash
wardline scan src/
```

Violations are reported with rule IDs, file locations, and remediation guidance.

## Trust Hierarchy

| Tier | Taint State | Description |
|------|-------------|-------------|
| 1 | INTEGRAL | Audit-critical, highest trust (database writes, compliance logging) |
| 2 | ASSURED | Validated internal data (business logic on checked inputs) |
| 3 | GUARDED | Shape-validated but not semantically verified |
| 4 | EXTERNAL_RAW | Untrusted external input (API payloads, user input) |

Data flows downward freely. Upward flow requires explicit validation boundaries (`@validates_shape`, `@validates_semantic`).

## Rules

| Rule | Detects |
|------|---------|
| PY-WL-001 | Dict key access with fallback default |
| PY-WL-002 | Attribute access with fallback default |
| PY-WL-003 | Existence-checking as structural gate |
| PY-WL-004 | Broad exception handlers |
| PY-WL-005 | Silent exception handlers |
| PY-WL-006 | Audit-critical writes in broad handlers |
| PY-WL-007 | Runtime type-checking on internal data |
| PY-WL-008 | Validation boundary with no rejection path |
| PY-WL-009 | Semantic validation without prior shape validation |
| SCN-021 | Contradictory decorator combinations |
| SUP-001 | Decorator contract violations |

## Architecture

| Subsystem | Description |
|-----------|-------------|
| `core/` | Trust tiers, taint lattice, severity matrix, decorator registry |
| `scanner/` | AST-based static analysis with taint propagation |
| `scanner/rules/` | 11 pluggable rule implementations |
| `scanner/taint/` | Three-phase taint assignment (variable, function, callgraph) |
| `manifest/` | YAML manifest loading, overlay merge, coherence validation |
| `decorators/` | 38 semantic boundary annotations (`@integrity_critical`, `@validates_shape`, etc.) |
| `runtime/` | Descriptor-based boundary enforcement at execution time |
| `cli/` | 9 Click-based CLI commands |

## CLI Commands

| Command | Description |
|---------|-------------|
| `wardline scan` | Run the static analysis scanner |
| `wardline explain` | Explain a rule ID or finding |
| `wardline manifest` | Validate and inspect the manifest |
| `wardline coherence` | Cross-manifest consistency checks |
| `wardline corpus` | Manage and verify the test specimen corpus |
| `wardline exception` | Grant, review, and manage exception entries |
| `wardline fingerprint` | Track annotation changes via AST fingerprints |
| `wardline regime` | Assess and report governance posture |
| `wardline resolve` | Resolve tier assignments for a module path |

## Development

```bash
uv run pytest                    # Unit tests
uv run pytest -m integration     # Integration tests
uv run ruff check src/           # Lint
uv run mypy src/                 # Type-check (strict)
uv run wardline scan src/        # Self-hosting scan
```

## Links

[Documentation](https://wardline.dev) | [Specification](docs/spec/) | [Contributing](CONTRIBUTING.md) | [Security](SECURITY.md) | [License](LICENSE)
