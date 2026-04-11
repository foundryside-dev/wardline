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

---

## Wardline — Project Guide

Wardline is a semantic boundary enforcement framework for Python. It defines
trust tiers for a codebase and statically verifies that data flows respect those
boundaries — catching trust-boundary violations before they reach production.

### Spec Authority

For spec interpretation, audit reconciliation, and fix-code vs fix-spec decisions,
the authoritative source of truth is `docs/spec/wardline-0x-*` together with
`docs/specification.md`. If an older design note, implementation plan, audit
artifact, or test fixture conflicts with a `wardline-0x` document, follow the
`wardline-0x` document and treat the other artifact as stale unless the user
explicitly says otherwise.

### Development Setup

```bash
uv sync --all-extras          # Install all dependencies (including dev + scanner)
uv run pytest                 # Run unit tests (default: excludes integration/network)
uv run ruff check src/ tests/ # Lint
uv run mypy src/              # Type-check (strict mode)
```

### Project Structure

```
src/wardline/
├── core/          # Tier registry, severity levels, taint matrix
├── decorators/    # @audit, @authority, schema annotations
├── runtime/       # Descriptor-based boundary enforcement
├── manifest/      # YAML manifest loading, merging, coherence checks
│   └── schemas/   # JSON schemas for wardline.yaml validation
├── scanner/       # AST scanner engine
│   ├── rules/     # PY-WL-001 through PY-WL-005
│   └── taint/     # Function-level taint analysis
└── cli/           # Click-based CLI (scan, explain, manifest, corpus)

tests/
├── unit/          # Mirrors src/ structure (core/, scanner/, manifest/, etc.)
├── integration/   # End-to-end CLI tests, self-hosting scan, corpus verify
├── fixtures/      # Shared test fixtures (sample projects, configs)
└── conftest.py    # Shared fixtures

corpus/
└── specimens/     # Test specimens per rule (PY-WL-NNN/{scenario}/pos|neg/)
```

### Code Conventions

- **Python 3.12+** — use modern syntax (`type` statements, `|` unions, etc.)
- **Strict mypy** — all code must pass `mypy --strict`; type annotations required
- **Ruff** — enforces pycodestyle (E/W), pyflakes (F), isort (I), pyupgrade (UP),
  bugbear (B), simplify (SIM), type-checking (TCH)
- **Zero runtime dependencies** — the core library has no required dependencies;
  `pyyaml`, `jsonschema`, and `click` are optional extras under `[scanner]`

### Testing

Three pytest markers control which tests run:

| Marker | When it runs | Use for |
|--------|-------------|---------|
| *(none)* | Every PR, every push | Unit tests — fast, no I/O |
| `integration` | Push to `main` only | CLI end-to-end, self-hosting scan |
| `network` | Weekly (Sunday 02:00 UTC) | Tests requiring network access |

Mark tests appropriately:

```python
import pytest

@pytest.mark.integration
def test_full_scan_pipeline(): ...

@pytest.mark.network
def test_fetch_remote_schema(): ...
```

Default `pytest` invocation excludes `integration` and `network` markers
(configured in `pyproject.toml`).

### CI Pipeline

| Job | Trigger | Steps |
|-----|---------|-------|
| Unit Tests + Lint | Every push and PR | ruff → mypy → pytest (unit only) |
| Integration Tests | Push to `main` | pytest -m integration |
| Network Tests | Weekly schedule | pytest -m network |

All three must pass. Ensure `uv run ruff check src/ tests/` and `uv run mypy src/`
pass locally before pushing.

### Adding a Scanner Rule

1. Create `src/wardline/scanner/rules/py_wl_NNN.py` — subclass the base from `rules/base.py`
2. Register the rule in `rules/__init__.py`
3. Add corpus specimens to `corpus/specimens/PY-WL-NNN/{scenario}/{positive|negative}/`
4. Add unit tests in `tests/unit/scanner/test_py_wl_NNN.py`
5. Cover true positives, true negatives, and known false negatives (KFN)

### Security Considerations

These areas require extra care:

- **YAML deserialization** — always use `yaml.safe_load()`, never `yaml.load()`.
  Wardline manifests must not allow `!!python/object` or similar unsafe tags.
- **Path traversal** — file discovery and manifest loading must not follow symlinks
  or resolve paths outside the project root.
- **Corpus specimens** — contain deliberately malformed code. Never execute specimen
  content; only parse it via AST.

Report vulnerabilities via GitHub's
[private vulnerability reporting](https://github.com/johnm-dta/wardline/security/advisories/new),
not public issues.

### Pull Requests

A PR template exists at `.github/PULL_REQUEST_TEMPLATE.md`. PRs should include:

- Summary of what and why
- Notable changes (bullet list)
- Testing checklist (unit tests added, pytest passes, ruff + mypy pass)
- Related issue links

---

## Wardline Filing System

This project uses filigree's full type system. The live workflow is defined by
the tracker state plus the guidance below; older bootstrap filing-system
documents have been retired.

### Issue Hierarchy

```
Milestone: "Wardline Python MVP"
  └── Phase (Phase 0–6, sequence-ordered)
       └── Work Package (T-x.y tasks — the assignable unit, PR-sized)
            └── Step (created by implementing agent at execution time)

Requirements (spec invariants, linked to WPs)
  └── Acceptance Criteria (Given/When/Then)

Release: v0.1.0
  └── Release Items (one per Phase)
```

### How to Find and Do Work

1. `get_ready` — shows unblocked Work Packages sorted by priority
2. `get_issue <id>` — read acceptance criteria and description
3. `claim_issue <id>` — claim the WP (multi-agent safe)
4. `update_issue <id> --status=executing` — start work
5. Read the issue description, comments, linked requirements, and any cited
   normative docs under `docs/spec/` or `docs/requirements/spec-fitness/`
6. Create Steps within the WP for your sub-tasks as needed
7. Implement, test, commit
8. `close_issue <id> --reason="summary"` — delivers the WP
9. Check if any Requirements are now unblocked and can be verified

### Label System

| Namespace | Purpose | Examples |
|-----------|---------|----------|
| `phase:` | Phase number | `phase:0`, `phase:4` |
| `subsystem:` | Code area | `subsystem:core`, `subsystem:scanner`, `subsystem:manifest` |
| `effort:` | T-shirt size | `effort:xs`, `effort:s`, `effort:m`, `effort:l` |
| `spec:` | Spec section | `spec:taint-model`, `spec:governance` |

**Note:** `area:` is a reserved auto-tag namespace — use `subsystem:` instead.

### Dependency Directions

- **WP → WP:** Execution ordering. WP B `blocked_by` WP A means B can't start until A is delivered.
- **Requirement → WP:** Verification linkage. Requirement `blocked_by` WP means the requirement can't be verified until the WP delivers. The WP does NOT need the requirement to start.

### Reference Documents

| Document | Purpose |
|----------|---------|
| `docs/specification.md` | Specification landing page and chapter index |
| `docs/spec/` | Framework specification and language bindings |
| `docs/adr/` | Durable architecture and governance decisions that still constrain implementation |
| `docs/requirements/spec-fitness/` | Project-facing requirement baseline for assessing the Python implementation |
| Filigree issue descriptions and comments | Current task definitions, delivery notes, and handoff context |
