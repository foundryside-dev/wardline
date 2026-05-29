# SP0 — Wardline Product Skeleton (Design)

**Date:** 2026-05-29
**Status:** design — awaiting user review before implementation planning
**Sub-project:** SP0 of the generic-Wardline rebuild (see decomposition below)
**Companion:** [Wardline ↔ Loom integration brief](../../integration/2026-05-29-wardline-loom-integration-brief.md) (the cross-product contract this skeleton serializes to)

---

## 1. Context

Wardline is being rebuilt as a **generic, lightweight semantic-tainting static analyzer** for any Python project (language-pluggable later), fusing the rigorous taint engine of the prior reference implementation (`wardline.old`) with the elspeth judge subsystem's opt-in LLM adjudication — and deliberately shedding the heavy governance (HMAC signing, counter-signatures, BAR review bundles, IRAP/L3 conformance) that made the old build unusable for a one-to-two-person team. Governance is **light-touch**: a plain git-committed baseline. The guiding mantra is *enterprise functionality with single-person simplicity*.

Integration with the Loom siblings (Clarion, Filigree) is **native but additive** — Wardline boots, self-tests, and analyzes with both absent; sibling presence only enriches.

### The decomposition (agreed)

| # | Sub-project | Purpose |
|---|---|---|
| **SP0** | **Product skeleton** *(this doc)* | Runnable package: CLI shell, config, the `Finding` record, `findings.jsonl` writer, plugin Protocols. The frame everything plugs into. |
| SP1 | Analyzer core | Generalize `.old`'s scanner + taint engine (callgraph, SCC fixed-point, project resolver). |
| SP2 | Rules + trust vocabulary | Generic rules + `@trust_boundary` decorators + the registry / NG-25 descriptor. |
| SP3 | Light-touch governance | Git-committable baseline + human-readable waivers. |
| SP4 | Outputs + Loom integration | SARIF + native Filigree emitter (`/api/loom/scan-results`) + Clarion qualname reconciliation. |
| SP5 | LLM judge (opt-in) | Optional escalation layer for ambiguous findings. |

Build order: SP0 → SP1 → (SP2 ∥ SP3) → SP4 → SP5.

---

## 2. Goals & non-goals

### SP0 goals

A runnable, installable `wardline` package such that `wardline scan <path>`:
1. loads config (`wardline.yaml`) or sensible defaults,
2. discovers Python files under the configured source roots,
3. runs a **no-op analyzer** (returns no findings — real analysis is SP1),
4. writes a schema-valid (empty) `findings.jsonl`, exit 0.

The point of SP0 is to **lock the contracts and module boundaries** so SP1–SP5 are pure fill-in: the `Finding` record, the config schema, the `Analyzer` / `Rule` / `Sink` Protocols, the CLI surface, and the tooling baseline.

### Non-goals (YAGNI — explicitly deferred)

- Taint analysis, callgraph, fixed-point (SP1).
- Any rules or the decorator vocabulary (SP2).
- Baseline / waivers / drift detection (SP3).
- SARIF emission, Filigree/Clarion wiring (SP4) — the `Finding` is *designed* for them, but no network/serialization code ships in SP0 beyond `to_jsonl()`.
- The LLM judge (SP5).
- **Permanently out of scope:** HMAC signing, counter-signatures, BAR bundles, conformance-evidence machinery. These do not return.

---

## 3. Architecture

### Package layout (`src/wardline/`)

```
src/wardline/
  __init__.py          # version export
  _version.py          # __version__ = "0.1.0.dev0"
  py.typed
  cli/
    __init__.py
    main.py            # click group `cli`; entry point
    scan.py            # `wardline scan` subcommand (the only live one)
  core/
    __init__.py
    finding.py         # Finding record + Severity/Kind enums + WardlineMetadata
    config.py          # wardline.yaml loader + WardlineConfig schema + defaults
    discovery.py       # source-root walk → list[Path] of .py files (respects exclude)
    emit.py            # Sink Protocol + JsonlSink (findings.jsonl writer)
    protocols.py       # Analyzer / Rule Protocols (the SP1/SP2 plug points)
    errors.py          # WardlineError hierarchy
  scanner/
    __init__.py        # empty package; SP1 implements Analyzer here
  rules/
    __init__.py        # empty package; SP2 implements Rules here
tests/
  conftest.py
  unit/core/...
  fixtures/sample_project/...
```

**Boundary discipline:** `core` imports nothing from `scanner`/`rules`/`cli`. `cli` orchestrates `core` (+ later `scanner`). `scanner`/`rules` ship as empty packages exposing only the Protocols they will implement. This keeps each unit independently understandable and testable, and lets SP1/SP2 land without touching SP0 contracts.

### Data flow (SP0)

```
wardline scan PATH
  → config.load(PATH/--config)        # WardlineConfig (source_roots, exclude, rules, reserved blocks)
  → discovery.discover(config)        # → list[Path]
  → analyzer.analyze(files, config)   # NoOpAnalyzer → [] in SP0; SP1 replaces
  → sink.write(findings)              # JsonlSink → findings.jsonl
  → exit 0 (exit 1 reserved for "findings present & --fail-on" — wired but inert in SP0)
```

---

## 4. The `Finding` record — the central contract

A frozen dataclass, the single most important artifact in SP0. Designed as a **superset** of Filigree's `ScanFinding` intake (per the integration brief, Round 1) so SP4 emission is serialization, not translation. Wardline owns the *analysis fact*; it does **not** model finding lifecycle (`status`, `scan_run_id`, `seen_count`, `issue_id`, timestamps) — that is Filigree's authoritative domain.

```python
class Severity(StrEnum):       # internal vocabulary
    CRITICAL = "CRITICAL"
    ERROR    = "ERROR"
    WARN     = "WARN"
    INFO     = "INFO"
    NONE     = "NONE"          # facts / metrics carry no defect severity

class Kind(StrEnum):
    DEFECT         = "defect"
    FACT           = "fact"
    CLASSIFICATION = "classification"
    METRIC         = "metric"
    SUGGESTION     = "suggestion"

@dataclass(frozen=True, slots=True)
class Location:
    path: str                  # repo-relative POSIX path (Filigree file_path anchor)
    line_start: int | None = None
    line_end: int | None = None
    col_start: int | None = None   # retained for SARIF; Filigree ignores
    col_end: int | None = None

@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str               # namespaced WLN-*
    message: str
    severity: Severity
    kind: Kind
    location: Location
    fingerprint: str           # stable cross-run identity (see §4.1)
    suggestion: str | None = None          # fix text; capped ≤ 10_000 chars on emit
    qualname: str | None = None            # dotted module.qualified_name (Clarion key)
    confidence: float | None = None
    related_entities: tuple[str, ...] = ()
    properties: Mapping[str, Any] = field(default_factory=dict)  # per-rule extension

    def to_jsonl(self) -> str: ...          # SP0 ships this
    # to_filigree_dict() / to_sarif_result() deferred to SP4 (mechanical, given these fields)
```

### 4.1 `fingerprint` — composition requirement

The fingerprint is the cross-run identity Filigree will dedup on (top-level field, schema v17) and the spine of SP3's baseline. **Requirement carried from Filigree Round 1:** it must disambiguate findings that share `(file, rule_id, line)` but differ by **taint path** (two paths into one sink). SP0 defines the field and a *placeholder* deterministic hash over `(rule_id, path, line_start, message)`; **SP1 replaces the composition** to fold in taint-path identity. The placeholder is marked clearly so it is not mistaken for the final scheme.

### 4.2 Wire mapping (documented in SP0, implemented in SP4)

| `Finding` field | Filigree (`/api/loom/scan-results`) |
|---|---|
| `rule_id` | `rule_id` (byte-identical) |
| `message` / `suggestion` | `message` / `suggestion` (≤10k) |
| `severity` | mapped (see §4.3) |
| `location.path` / `line_start` / `line_end` | `file_path` (→`file_id`) / `line_start` / `line_end` |
| `fingerprint` | top-level `fingerprint` |
| `qualname` / `kind` / `confidence` / `related_entities` / `properties` | `metadata.wardline.*` |

`metadata` is preserved as a **semantic JSON object** (not byte-for-byte): Wardline must not rely on key order, whitespace, or duplicate keys.

### 4.3 Severity map (Wardline-owned)

| Wardline | Filigree | round-trip |
|---|---|---|
| `CRITICAL` | `critical` | `metadata.wardline.internal_severity` |
| `ERROR` | `high` | |
| `WARN` | `medium` | |
| `INFO` | `low` | |
| `NONE` | `info` | |

SP0 ships the enums and the mapping table as a pure function `severity_to_filigree(Severity) -> str` (used by SP4); no network code.

---

## 5. Config — `wardline.yaml`

```yaml
# wardline.yaml — minimal in SP0; reserved blocks are declared but inert.
source_roots: ["src"]          # default ["."] if omitted
exclude: ["**/.venv/**", "**/__pycache__/**"]   # glob excludes
rules:                          # SP2 honours; SP0 parses + validates shape only
  enable: ["*"]
  severity: {}                  # rule_id -> Severity override

# --- reserved (declared so the shape is visible; ignored in SP0) ---
baseline: {}                    # SP3
judge: {}                       # SP5
filigree: {}                    # SP4: {url, token, generation: loom}
clarion: {}                     # SP4
```

`config.load()` returns a typed `WardlineConfig`. Unknown top-level keys → warning, not error (forward-compat). Reserved blocks are accepted and ignored. Matches the `clarion.yaml` / `.filigree.conf` sibling convention.

---

## 6. CLI shell

`click` group (matches `.old`), entry point `wardline = "wardline.cli.main:cli"`.

| Command | SP0 behavior |
|---|---|
| `wardline scan [PATH] [--config FILE] [--format jsonl] [--output FILE] [--fail-on SEVERITY]` | Live. Discover → no-op analyze → write `findings.jsonl`. `--format sarif` and `--fail-on` parse but are inert/`NotImplemented`-guarded (SP3/SP4). |
| `wardline baseline ...` | Visible stub → exits 2 with "not yet implemented (SP3)". |
| `wardline judge ...` | Visible stub → exits 2 with "not yet implemented (SP5)". |
| `wardline --version` | Prints `_version.__version__`. |

The stubs exist so the eventual surface is legible from day one without implementing it.

---

## 7. Error handling

- `core/errors.py`: `WardlineError` base; `ConfigError` (malformed `wardline.yaml`), `DiscoveryError` (unreadable root). CLI catches `WardlineError` → stderr message + exit 2; unexpected exceptions propagate (no silent catches — a deliberate inversion of the old governance habit).
- Discovery is fault-tolerant per-file (an unreadable individual file warns and is skipped, never aborts the run) — mirrors `.old`'s I/O fault-tolerance posture.
- Config: fail-closed on malformed YAML (clear error + exit 2); fail-soft on unknown keys (warn, continue).

---

## 8. Testing & self-hosting seed

- `pytest` (+ `pytest-randomly`, `pytest-cov`). `addopts = -m 'not network'` (no network tests until SP4).
- **Smoke test:** `wardline scan tests/fixtures/sample_project` → exit 0, produces a `findings.jsonl` that is valid JSONL and empty (no analyzer yet).
- **Contract tests:** `Finding.to_jsonl()` round-trips; `severity_to_filigree` covers all 5 levels; config loader accepts the reserved-block skeleton and rejects malformed YAML.
- **ruff + mypy green** (`--strict` mypy on `src/wardline`).
- **Self-hosting seed:** a placeholder test marked `xfail(reason="no rules until SP2")` that will later run Wardline on its own source — establishing the discipline now so SP2 only flips the marker.

---

## 9. Tooling & packaging

- Build: `hatchling`, src-layout, `requires-python >= 3.12`.
- **`dependencies = []`** core posture (preserved from `.old`); optional extras:
  - `scanner` → `pyyaml`, `jsonschema`, `click`
  - `loom` → `httpx` (SP4 emitter)
  - `judge` → `litellm`, `anthropic` (SP5; replaces `.old`'s `bar` extra)
  - `dev` → `pytest`, `pytest-cov`, `pytest-randomly`, `ruff`, `mypy`
  - `docs` → mkdocs-material stack
- Entry point: `wardline = "wardline.cli.main:cli"`.
- `[project.urls]` → `github.com/foundryside/wardline` (Homepage / Repository / Issues / Changelog). **Org is `foundryside`, not `johnm-dta`.**
- `.gitignore`, `README.md` (one-paragraph product statement + the composition law pointer), `CHANGELOG.md` seeded.

---

## 10. Acceptance criteria (Definition of Done for SP0)

1. `pip install -e .[dev]` succeeds; `wardline --version` prints the version.
2. `wardline scan tests/fixtures/sample_project` exits 0 and writes valid, empty `findings.jsonl`.
3. `wardline baseline` / `wardline judge` exit 2 with clear "not yet implemented" messages.
4. `Finding`, `Severity`, `Kind`, `Location`, `WardlineConfig`, and the `Analyzer`/`Rule`/`Sink` Protocols exist with the fields/signatures in this doc.
5. `severity_to_filigree` and the `metadata.wardline.*` mapping are implemented as pure functions (no network).
6. ruff + mypy(strict) + pytest all green.
7. No HMAC, signing, baseline, SARIF, or network code present.

---

## 11. Open loops (tracked, do not block SP0)

- Qualname conformance corpus location (Clarion repo vs neutral suite location) — affects SP1/SP4, not SP0.
- Clarion NG-25 plugin-reader timeline — affects SP2.
- Filigree schema v17 (`fingerprint` column) ships independently — SP4 depends on it, SP0 does not.
