# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Wardline

Wardline is a semantic boundary enforcement framework for Python. It defines a four-tier trust hierarchy (Tier 1 INTEGRAL → Tier 4 EXTERNAL_RAW) and statically verifies that data flows respect those boundaries. The scanner catches trust-boundary violations — untrusted input reaching privileged code, missing validation at tier transitions — via AST analysis with taint propagation.

## Build & Development Commands

```bash
# Install all dependencies (Python 3.12+, uses uv)
uv sync --all-extras

# Run unit tests (excludes integration and network tests by default)
uv run pytest

# Run a single test file
uv run pytest tests/unit/scanner/test_engine.py

# Run a single test by name
uv run pytest -k "test_name_substring"

# Run integration tests
uv run pytest -m integration

# Lint
uv run ruff check src/

# Type-check (strict mode)
uv run mypy src/

# Run the scanner against the project itself (self-hosting)
uv run wardline scan src/
```

## Architecture

### Core Domain (`src/wardline/core/`)

The trust model foundation. Key types:

- **`TaintState`** (8 variants in `taints.py`) — canonical taint tokens with a join lattice. `taint_join()` is commutative; `MIXED_RAW` is the absorbing element. Values are explicit uppercase strings (not `auto()`).
- **`AuthorityTier`** (`tiers.py`) — 4-level IntEnum. Lower numeric value = higher authority (Tier 1 > Tier 4). `TAINT_TO_TIER` maps every TaintState to a tier.
- **`RuleId`** (`severity.py`) — StrEnum of all rule IDs (canonical `PY-WL-*`, diagnostic `GOVERNANCE-*`, pseudo `TOOL-ERROR`, etc.). Member names use underscores; values use hyphens.
- **`registry.py`** — Frozen `REGISTRY` of all wardline decorators with expected `_wardline_*` attributes, grouped by function.

### Scanner (`src/wardline/scanner/`)

AST-based static analysis engine:

- **`engine.py`** (`ScanEngine`) — orchestrates file discovery → AST parse → taint assignment → rule execution. Resilient: parse errors skip file, rule crashes emit `TOOL-ERROR` finding.
- **`rules/`** — Each rule is a class inheriting `RuleBase` (`base.py`). `PY-WL-001` through `PY-WL-005` are implemented (MVP); `PY-WL-006` through `PY-WL-009` exist but are post-MVP. `SCN-021` and `SUP-001` are supplementary rules.
- **`taint/`** — Three-phase taint propagation: variable-level → function-level → callgraph propagation. `TaintProvenance` tracks how taints were assigned.
- **`sarif.py`** — SARIF v2.1.0 output for CI integration.
- **`context.py`** — `Finding` and `ScanContext` dataclasses that flow through the pipeline.

### Manifest (`src/wardline/manifest/`)

YAML manifest loading and validation:

- **`models.py`** — `WardlineManifest` and related dataclasses (tier assignments, boundaries, exceptions).
- **`loader.py`** / **`merge.py`** — Load `wardline.yaml` with overlay support for monorepos.
- **`coherence.py`** — Cross-manifest consistency checks (tier distribution, registry sync, exception governance).
- **`schemas/`** — JSON Schema files for manifest validation.

### Decorators (`src/wardline/decorators/`)

Library of decorators (`@audit`, `@authority`, `@external_boundary`, `@validates_shape`, etc.) that mark trust transitions in code. Each sets `_wardline_*` attributes that the scanner reads via `discover_annotations()`.

### Runtime (`src/wardline/runtime/`)

Descriptor-based boundary enforcement at execution time. `enforcement.py` checks tier transitions; `protocols.py` defines the runtime protocol interfaces.

### CLI (`src/wardline/cli/`)

Click-based CLI. Entry point: `wardline.cli.main:cli`. Subcommands: `scan`, `explain`, `manifest`, `corpus`, `coherence`, `fingerprint`, `resolve`, `regime`, `exception`, `preview`.

### Test Corpus (`corpus/`)

Specimens organized by rule ID (e.g., `corpus/specimens/PY-WL-001/`). Each specimen is a Python file with metadata tracking expected verdicts. `corpus_manifest.json` indexes all specimens. The `corpus verify` CLI command validates scanner output against expected verdicts.

## Key Configuration Files

- **`wardline.yaml`** — Self-hosting manifest with tier assignments for every `src/wardline/` sub-package.
- **`wardline.toml`** — Scanner configuration for self-hosting (target paths, excluded paths, thresholds).
- **`pyproject.toml`** — Build config (hatchling), test config (pytest markers: `integration`, `network`), ruff rules, mypy strict.

## Website & PDF Specification

The project website is served by Caddy at `wardline.dev` from `/var/www/wardline.dev/`.

- **Web root**: `/var/www/wardline.dev/` (static file server)
- **PDF spec**: `/var/www/wardline.dev/assets/wardline-specification.pdf`
- **Build pipeline**: `tools/pdf/build-spec.sh [--pdf]` — concatenates spec chapters, runs pandoc with a Typst template and Lua filter (`fix-tables.lua`), compiles to PDF
- **Deploy**: after rebuilding, copy `docs/assets/wardline-specification.pdf` to `/var/www/wardline.dev/assets/`

## Code Conventions

- **Zero runtime dependencies** — the core package has no deps. Scanner extras: `pyyaml`, `jsonschema`, `click`.
- **`MappingProxyType`** for deep immutability of registries and lookup tables.
- **Explicit `ValueError` over `assert`** — survives `python -O`.
- **`from __future__ import annotations`** everywhere for deferred evaluation.
- Ruff line length: 140. Target: Python 3.12+.
- mypy strict mode with `warn_return_any`.

## Task Tracking

This project uses Filigree for issue tracking. See AGENTS.md for full CLI/MCP reference. Quick workflow:

```bash
filigree ready          # Find available work
filigree show <id>      # Review issue details
filigree claim <id>     # Claim work
filigree close <id>     # Mark complete
```

<!-- filigree:instructions:v1.6.0:84820288 -->
## Filigree Issue Tracker

Use `filigree` for all task tracking in this project. Data lives in `.filigree/`.

### MCP Tools (Preferred)

When MCP is configured, prefer `mcp__filigree__*` tools over CLI commands — they're
faster and return structured data. Key tools:

- `get_ready` / `get_blocked` — find available work
- `get_issue` / `list_issues` / `search_issues` — read issues
- `create_issue` / `update_issue` / `close_issue` — manage issues
- `claim_issue` / `claim_next` — atomic claiming
- `add_comment` / `add_label` — metadata
- `list_labels` / `get_label_taxonomy` — discover labels and reserved namespaces
- `create_plan` / `get_plan` — milestone planning
- `get_stats` / `get_metrics` — project health
- `get_valid_transitions` — workflow navigation
- `observe` / `list_observations` / `dismiss_observation` / `promote_observation` — agent scratchpad
- `trigger_scan` / `trigger_scan_batch` / `get_scan_status` / `preview_scan` / `list_scanners` — automated code scanning
- `get_finding` / `list_findings` / `update_finding` / `batch_update_findings` — scan finding triage
- `promote_finding` / `dismiss_finding` — finding lifecycle (promote to issue or dismiss)

Observations are fire-and-forget notes that expire after 14 days. Use `list_issues --label=from-observation` to find promoted observations.

**Observations are ambient.** While doing other work, use `observe` whenever you
notice something worth noting — a code smell, a potential bug, a missing test, a
design concern. Don't stop what you're doing; just fire off the observation and
carry on. They're ideal for "I don't have time to investigate this right now, but
I want to come back to it." Include `file_path` and `line` when relevant so the
observation is anchored to code. At session end, skim `list_observations` and
either `dismiss_observation` (not worth tracking) or `promote_observation`
(deserves an issue) for anything that's accumulated.

Fall back to CLI (`filigree <command>`) when MCP is unavailable.

### CLI Quick Reference

```bash
# Finding work
filigree ready                              # Show issues ready to work (no blockers)
filigree list --status=open                 # All open issues
filigree list --status=in_progress          # Active work
filigree list --label=bug --label=P1        # Filter by multiple labels (AND)
filigree list --label-prefix=cluster:       # Filter by label namespace prefix
filigree list --not-label=wontfix           # Exclude issues with label
filigree show <id>                          # Detailed issue view

# Creating & updating
filigree create "Title" --type=task --priority=2          # New issue
filigree update <id> --status=in_progress                # Claim work
filigree close <id>                                      # Mark complete
filigree close <id> --reason="explanation"               # Close with reason

# Dependencies
filigree add-dep <issue> <depends-on>       # Add dependency
filigree remove-dep <issue> <depends-on>    # Remove dependency
filigree blocked                            # Show blocked issues

# Comments & labels
filigree add-comment <id> "text"            # Add comment
filigree get-comments <id>                  # List comments
filigree add-label <id> <label>             # Add label
filigree remove-label <id> <label>          # Remove label
filigree labels                             # List all labels by namespace
filigree taxonomy                           # Show reserved namespaces and vocabulary

# Workflow templates
filigree types                              # List registered types with state flows
filigree type-info <type>                   # Full workflow definition for a type
filigree transitions <id>                   # Valid next states for an issue
filigree packs                              # List enabled workflow packs
filigree validate <id>                      # Validate issue against template
filigree guide <pack>                       # Display workflow guide for a pack

# Atomic claiming
filigree claim <id> --assignee <name>            # Claim issue (optimistic lock)
filigree claim-next --assignee <name>            # Claim highest-priority ready issue

# Batch operations
filigree batch-update <ids...> --priority=0      # Update multiple issues
filigree batch-close <ids...>                    # Close multiple with error reporting

# Planning
filigree create-plan --file plan.json            # Create milestone/phase/step hierarchy

# Event history
filigree changes --since 2026-01-01T00:00:00    # Events since timestamp
filigree events <id>                             # Event history for issue
filigree explain-state <type> <state>            # Explain a workflow state

# All commands support --json and --actor flags
filigree --actor bot-1 create "Title"            # Specify actor identity
filigree list --json                             # Machine-readable output

# Project health
filigree stats                              # Project statistics
filigree search "query"                     # Search issues
filigree doctor                             # Health check
```

### File Records & Scan Findings (API)

The dashboard exposes REST endpoints for file tracking and scan result ingestion.
Use `GET /api/files/_schema` for available endpoints and valid field values.

Key endpoints:
- `GET /api/files/_schema` — Discovery: valid enums, endpoint catalog
- `POST /api/v1/scan-results` — Ingest scan results (SARIF-lite format)
- `GET /api/files` — List tracked files with filtering and sorting
- `GET /api/files/{file_id}` — File detail with associations and findings summary
- `GET /api/files/{file_id}/findings` — Findings for a specific file

### Workflow
1. `filigree ready` to find available work
2. `filigree show <id>` to review details
3. `filigree transitions <id>` to see valid state changes
4. `filigree update <id> --status=in_progress` to claim it
5. Do the work, commit code
6. `filigree close <id>` when done

### Session Start
When beginning a new session, run `filigree session-context` to load the project
snapshot (ready work, in-progress items, critical path). This provides the
context needed to pick up where the previous session left off.

### Priority Scale
- P0: Critical (drop everything)
- P1: High (do next)
- P2: Medium (default)
- P3: Low
- P4: Backlog
<!-- /filigree:instructions -->

Note that we are currently pushing to relase 1.0 - No deferrals will be approved. You should ask. YOU MUST NOT UNILATERALLY DEFER SCOPE.