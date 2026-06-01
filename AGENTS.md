# AGENTS.md

This file provides guidance to coding agents (Claude Code, Codex, etc.) when working with code in this repository.

> The Filigree issue-tracker section below is auto-managed by `filigree init`
> (it lives between `<!-- filigree:instructions -->` markers and is regenerated
> in place). Keep Wardline-specific guidance *above* those markers so it
> survives a refresh. Its twin `AGENTS.md` carries the same Wardline developer guidance; the Filigree block below is auto-managed in each.

> **Audience — developing Wardline.** This file (and `AGENTS.md`) is for people
> and agents changing Wardline itself. End-user "how to *use* Wardline" guidance
> is NOT here — it lives in the `wardline install` instruction block, the
> `wardline-gate` skill (`src/wardline/skills/wardline-gate/SKILL.md`), and the
> docs site. Keep usage guidance out of this file.

## What Wardline is

Wardline is a **generic, lightweight semantic-tainting static analyzer for
Python**. It reads source statically (never runs it) and answers one question of
every trust-annotated function: *is the data this function works with as trusted
as it claims?* It is part of the **Loom** suite (Wardline analysis + Clarion code
intelligence + Filigree issue tracking).

Core design tenets — internalize these before changing behavior:

- **Zero-dependency base.** The installed package (`pip install wardline`) has
  **no runtime dependencies**. Third-party libs live behind optional extras:
  `scanner` (pyyaml/jsonschema/click — the CLI), `clarion` (blake3), `docs`
  (mkdocs). The LLM judge is dep-free (stdlib `urllib` → OpenRouter). Do not add
  an import of an extra's package outside its subpackage, and never make the base
  import-time depend on one.
- **Opt-in / fail-closed.** Undecorated code is the "developer-freedom zone":
  unknown-trust, no findings. Policy fires only where a developer has declared
  trust via decorators. When the engine *cannot prove* something, it records an
  honest `UNKNOWN_*` state and emits an observable `WLN-ENGINE-*` FACT rather
  than silently passing — a silent skip is a "false-green" and is treated as a
  bug.
- **CLI and MCP are identical by construction.** Both call the same
  `core/run.py` functions, so a scan via the CLI and via the MCP server produce
  the same findings/gate. Don't reintroduce logic into a command that belongs in
  `core/`.

## Dev commands

The repo uses [uv](https://docs.astral.sh/uv/). Set up with
`uv sync --all-extras --group dev`. A `Makefile` wraps the common flows
(`make help` lists them; `make ci` runs the full local gate).

```bash
# Tests (network + clarion_e2e are deselected by default via pyproject addopts)
uv run pytest                                 # full suite (~1000 tests)
uv run pytest tests/unit/scanner              # one directory
uv run pytest tests/unit/core/test_run.py     # one file
uv run pytest -k "py_wl_101"                  # by name substring
uv run pytest -m network                      # opt in: live OpenRouter judge e2e (SP5)
WARDLINE_CLARION_BIN=~/clarion/target/release/clarion \
  uv run pytest -m clarion_e2e                # opt in: real `clarion serve` round-trip (SP9)

# Lint / type-check / coverage (CI gates on all three; floor is 90%)
uv run ruff check src tests
uv run ruff format --check src tests          # CI enforces formatting
uv run mypy                                   # strict, src/wardline only (see pyproject)
make test-cov                                 # pytest with the 90% coverage floor

# Run the analyzer on a project
uv run wardline scan PATH --fail-on ERROR     # gate: exit 1 if active DEFECT >= ERROR
uv run wardline scan PATH --format sarif       # or jsonl (default)
uv run wardline vocab                          # emit the NG-25 trust-vocabulary descriptor
uv run wardline judge PATH --write             # opt-in LLM triage of active DEFECTs
uv run wardline baseline create PATH           # snapshot current findings as accepted
uv run wardline mcp                            # MCP-over-stdio server (JSON-RPC 2.0, no SDK)
uv run wardline install                        # wire Wardline into an agent project

# Docs
uv run mkdocs serve                            # local preview; CI builds --strict
```

Tests run under `pytest-randomly` (random order) — order-dependence is a real
failure, not flakiness.

## Architecture: the taint pipeline

A scan is a pure function of *(disk + config)*. The flow:

**`core/discovery.py`** finds analysable files → **`scanner/analyzer.py`
(`WardlineAnalyzer`)** orchestrates the layered taint engine → policy rules run
→ **`core/suppression.py`** classifies each finding (active / baselined / waived
/ judged) → **`core/emit.py`** / `sarif.py` / `filigree_emit.py` serialize.

The taint engine in `scanner/taint/` is layered (terms used throughout the code
and plans):

- **L1 — function-level seeding** (`function_level.py`): ask the
  `TaintSourceProvider` for each function's declared taint; fall back to
  `UNKNOWN_RAW`. The default provider is `DecoratorTaintSourceProvider`, which
  reads the three trust decorators from source.
- **L3 — project-scope fixed point** (`project_resolver.py` + `propagation.py`):
  build the inter-module call graph (`callgraph.py`), run Tarjan SCC
  decomposition, and iterate to a fixed point. A function is only as trusted as
  the least-trusted value it returns; trust flows transitively up the call graph
  across files. An optional `SummaryCache` memoizes per-module summaries (warm
  cache must produce byte-identical findings to cold — enforced by test).
- **L2 — per-variable taint within a body** (`variable_level.py`): walks a
  function AST tracking taint per variable through assignments, control-flow
  joins, match arms, and call sites. Combines with the **rank-meet
  `least_trusted` (weakest-link)** — a branch merge holds one alternative, not a
  mixture, so it is *not* `taint_join`'s provenance-clash `MIXED_RAW`. (Full L3
  subsumes the old `minimum_scope` one-hop refinement, which is off the pipeline.)

Everything is bounded fail-closed: a parse error, too-deep recursion, or missing
source root skips the unit and emits a `Severity.NONE` `WLN-ENGINE-*` FACT so the
under-scan is visible (`UNANALYZED_RULE_IDS` distinguishes genuine under-scans
from benign no-module skips).

### The trust model

Eight ordered taint states (`core/taints.py`), most→least trusted:
`INTEGRAL → ASSURED → GUARDED → UNKNOWN_ASSURED → UNKNOWN_GUARDED → EXTERNAL_RAW
→ UNKNOWN_RAW → MIXED_RAW`. Developers declare only four (`INTEGRAL`, `ASSURED`,
`GUARDED`, `EXTERNAL_RAW`) via three decorators in `decorators/trust.py`
(runtime no-op markers Wardline reads statically):
`@external_boundary` (source → `EXTERNAL_RAW`), `@trust_boundary(to_level=...)`
(validator that raises trust), `@trusted(level=...)` (trusted producer). The
`UNKNOWN_*` / `MIXED_RAW` states are engine-inferred and never written.

### The four policy rules (`scanner/rules/`)

| Rule | Flags | Gating |
|---|---|---|
| `PY-WL-101` | trusted producer returns data less trusted than declared | declaration-gated (always base severity) |
| `PY-WL-102` | trust boundary with no rejection path (can't say "no") | declaration-gated |
| `PY-WL-103` | broad exception handler in a trusted-tier function | tier-modulated severity |
| `PY-WL-104` | silently-swallowed exception in a trusted-tier function | tier-modulated severity |

Rules are toggled / re-severitied per project via `wardline.yaml`
(`rules.enable` / `rules.severity`).

## Package map (`src/wardline/`)

- **`core/`** — engine-agnostic orchestration and I/O. `run.py` (the shared
  `run_scan`/`gate_decision`), `config.py` + `config_schema.py` (jsonschema-validated
  `wardline.yaml`), `finding.py` (`Finding`/`Severity`/`Kind`), `taints.py` (the
  lattice + `least_trusted`/`taint_join`), `suppression.py`, `baseline.py`,
  `waivers.py`, `judged.py`, `judge.py`/`judge_run.py` (LLM triage), `descriptor.py`
  (the read-instead-of-import NG-25 vocabulary export), `explain.py`, emitters.
- **`scanner/`** — the AST engine: `analyzer.py`, `index.py` (entity discovery),
  `ast_primitives.py`, `taint/` (the L1/L2/L3 layers above), `rules/`.
- **`decorators/`** — the public trust decorators + their `REGISTRY`.
- **`cli/`** — `click` command group (`main.py` → `scan`, `judge`, `mcp`,
  `install`, `vocab`, `baseline`); thin wrappers over `core/`.
- **`mcp/`** — dep-free stdlib MCP-over-stdio server (`server.py` + `protocol.py`).
  Tools: scan / explain_taint / judge / baseline_create|update / waiver_add.
  Findings are NEVER exposed as a resource. MCP confines all paths under root
  (`confine_to_root=True`) where the CLI does not.
- **`clarion/`** — opt-in (`[clarion]`) write of per-entity `wardline-taint-1`
  facts to a Clarion taint store; HMAC-signed, blake3 freshness gate, fail-soft.
- **`install/`** — `wardline install`: injects a hash-fenced instruction block
  into `CLAUDE.md`/`AGENTS.md`, installs the `wardline-gate` skill, merges a
  `wardline` entry into `.mcp.json`, records Clarion/Filigree bindings.

### Error model

`WardlineError` subclasses (`core/errors.py`) carry tool-actionable failures.
Split by surface: **tool-execution** errors (bad config, missing judge key,
stale fingerprint) surface to the agent as a result payload / CLI exit 2;
**protocol** faults (unknown MCP tool/method/bad args) become JSON-RPC errors.

## Conventions

- **No back-compat shims for unreleased specs** — make clean changes.
- Wardline scans **its own source** as a dogfood gate; keep the tree finding-clean
  (or baselined) when you touch trust-annotated code.
- The shipped `vocabulary.yaml` is a *derived snapshot* of `descriptor.py`; a
  byte-identity test fails if they drift — regenerate, don't hand-edit.
- Findings carry repo-relative paths and stable SHA-256 fingerprints; changing a
  fingerprint input silently invalidates baselines/waivers — treat as breaking.
- Specs live in `docs/superpowers/specs/`, plans in `docs/superpowers/plans/`,
  prose docs in `docs/` (served via mkdocs). Concepts: `docs/concepts/{model,rules,taint-algebra}.md`.

<!-- filigree:instructions:v2.2.0:9dff6e6d -->
## Filigree Issue Tracker

`filigree` tracks tasks for this project. Data lives in `.filigree/`. Prefer
the MCP tools (`mcp__filigree__*`) when available; fall back to the `filigree`
CLI otherwise.

### Workflow

```bash
# At session start
filigree session-context                            # ready / in-progress / critical path

# Pick up the next startable issue (atomic claim + transition into its working status)
filigree start-next-work --assignee <name>
# ...or claim a specific issue
filigree start-work <id> --assignee <name>

# Do the work, commit, then
filigree close <id>
```

Use the atomic claim+transition verbs — `start_work` / `start_next_work`
(MCP) or `start-work` / `start-next-work` (CLI). Do **not** chain
`claim_issue` (MCP) or `filigree claim` (CLI) with a subsequent status
update — the two-step form races against other agents; the combined verb is
atomic.

**Ready ≠ startable.** The working status is type-specific (tasks →
`in_progress`, features → `building`). Bugs start at `triage`, which has no
single-hop transition into work (`triage → confirmed → fixing`), so a triage
bug is *ready* but not directly *startable*: `start_work` on one returns
`INVALID_TRANSITION` naming the next status, and `start_next_work` skips it.
`get_ready` items carry a `startable` flag (plus a `next_action` hint when
false). Pass `advance=true` (MCP) / `--advance` (CLI) to walk the soft
transitions to the nearest working status automatically.

### Observations: when (and when not) to use them

`observe` is a fire-and-forget scratchpad for *incidental* defects — things
you notice *outside the scope of your current task* (a code smell in a
neighbouring file, a stale TODO, a missing test for an edge case you happened
to spot). Notes expire after 14 days unless promoted. Include `file_path` and
`line` when relevant. At session end, skim `list_observations` and either
`dismiss_observation` or `promote_observation` for what has accumulated.

**You fix bugs in your currently defined scope. You do NOT use observations
to finish work prematurely.** If a defect, gap, or follow-up belongs to your
current task, you own it — handle it as part of that task: fix it now, expand
the task's scope, file a proper issue with a dependency, or surface it to the
user. Filing it as an observation and closing the task is *not* completing
the task; it is shipping known-broken work and hiding the debt in a 14-day
expiring scratchpad. The test is "would I have noticed this even if I weren't
working on this task?" If no, it's task scope, not an observation.

### Priority scale

- P0: Critical (drop everything)
- P1: High (do next)
- P2: Medium (default)
- P3: Low
- P4: Backlog

### Reaching for tools

MCP tool schemas describe each tool; `filigree --help` and `filigree <verb>
--help` are the authoritative CLI reference. You do not need to memorise
either catalogue. The verbs you will reach for most:

- **Find work:** `get_ready`, `get_blocked`, `list_issues`, `search_issues`
- **Claim work:** `start_work`, `start_next_work`
- **Update:** `add_comment`, `add_label`, `update_issue`, `close_issue`
- **Admin (irreversible):** `delete_issue` (MCP) / `delete-issue` (CLI) —
  hard-deletes a terminal issue and its rows; `undo_last` cannot reverse it.
- **Scratchpad:** `observe`, `list_observations`, `promote_observation`, `dismiss_observation`
- **Cross-product entity bindings (ADR-029):** `add_entity_association`,
  `remove_entity_association`, `list_entity_associations`,
  `list_associations_by_entity`. Used when a sibling tool (e.g.
  Clarion) needs to bind a Filigree issue to a function, class, or
  module identifier it owns. The `entity_id` is an opaque string
  from Filigree's perspective; the consumer (the sibling tool's read
  path) does drift detection against the stored
  `content_hash_at_attach`. `list_associations_by_entity` is the
  reverse-lookup surface — given a Clarion entity ID, return every
  Filigree issue bound to it (project isolation is by DB file). Also
  reachable over HTTP as
  `GET/POST /api/issue/{issue_id}/entity-associations`,
  `DELETE /api/issue/{issue_id}/entity-associations?entity_id=…`,
  and `GET /api/entity-associations?entity_id=…`.
- **Health:** `get_stats`, `get_metrics`, `get_mcp_status`

Pass `--actor <name>` (CLI) so events attribute to your agent identity. It
works in either position — before the verb (`filigree --actor X update …`) or
after it (`filigree update … --actor X`); the post-verb value overrides the
group-level one.

### Error handling

Errors return `{error: str, code: ErrorCode, details?: dict}`. Switch on
`code`, not on message text. Codes: `VALIDATION`, `NOT_FOUND`, `CONFLICT`,
`INVALID_TRANSITION`, `PERMISSION`, `NOT_INITIALIZED`, `IO`,
`INVALID_API_URL`, `FILE_REGISTRY_DISPLACED`, `REGISTRY_UNAVAILABLE`,
`CLARION_REGISTRY_VERSION_MISMATCH`, `BRIEFING_BLOCKED`, `STOP_FAILED`,
`SCHEMA_MISMATCH`, `INTERNAL`.

On `INVALID_TRANSITION`, call `get_valid_transitions` (MCP) or
`filigree transitions <id>` to see what the workflow allows from here.

Two failure modes deserve a specific response:

- **`SCHEMA_MISMATCH`** — the installed `filigree` is older than the project
  database. The error message contains upgrade guidance. Surface it to the
  user; do not retry.
- **`ForeignDatabaseError`** — filigree found a parent project's database
  but no local `.filigree.conf`. Run `filigree init` in the current
  directory. Do **not** `cd` upward to a different project unless that was
  the actual intent.
<!-- /filigree:instructions -->
