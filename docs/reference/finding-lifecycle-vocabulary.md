# Finding lifecycle & gate vocabulary

This is the single source of truth for the words Wardline uses to describe the
**state and lifecycle of a finding** — `new`, `active`, `suppression_state`,
`baselined`, `waived`, `judged` — and how each one maps onto the three surfaces
an agent reads: the **CLI summary line**, the **MCP / agent-summary JSON**, and
the **Filigree store**.

It is deliberately distinct from the [Trust vocabulary](vocabulary.md), which
documents the *trust-tier* markers (`trusted`, `trust_boundary`,
`external_boundary`) the engine reasons about. That page is about what data is
trusted; this page is about what happens to a finding once it is produced.

Every claim below cites a real `file:line` so the vocabulary stays anchored to
the code. The discipline test `tests/docs/test_glossary_vocabulary.py` fails if a
`SuppressionState` value is added without being documented here.

## The categories of a finding

Before lifecycle state, two orthogonal axes classify every finding:

| Axis | Values | Defined at |
| --- | --- | --- |
| `kind` | `defect`, `fact`, `classification`, `metric`, `suggestion` | `src/wardline/core/finding.py:68-73` (`Kind`) |
| `severity` | `CRITICAL`, `ERROR`, `WARN`, `INFO`, `NONE` | `src/wardline/core/finding.py:60-65` (`Severity`) |

Only `Kind.DEFECT` findings are ever suppressed or gated; facts and metrics
(`Severity.NONE`) never participate in the `--fail-on` gate
(`src/wardline/core/suppression.py:27-30`, `src/wardline/core/suppression.py:44-46`).

## The four suppression states

`SuppressionState` (`src/wardline/core/finding.py:76-80`) has exactly four
values. Every emitted `DEFECT` carries exactly one:

| State | Meaning | Set by |
| --- | --- | --- |
| `active` | Not suppressed — the default. A live defect. | default (`src/wardline/core/finding.py:77`, `src/wardline/core/finding.py:112`) |
| `baselined` | Matched a fingerprint in `.weft/wardline/baseline.yaml`. | `src/wardline/core/suppression.py:24` |
| `waived` | Matched an unexpired waiver in `.weft/wardline/waivers.yaml`. | `src/wardline/core/suppression.py:22` |
| `judged` | The LLM triage judge ruled it a false positive (`.weft/wardline/judged.yaml`). | `src/wardline/core/suppression.py:23` |

When more than one layer matches a finding, **precedence is
waiver > judged > baseline** — explicit human intent wins, then the LLM verdict
(so its rationale is the visible reason), then the silent baseline. The precedence
itself lives in the single JOIN predicate `resolve_identity`
(`src/wardline/core/finding_identity.py`); the suppression layer maps its verdict
onto the state (`src/wardline/core/suppression.py:72-77`).

### The per-finding key is `suppression_state` (not `suppressed`)

Each serialized finding carries its state under the key **`suppression_state`**
(`src/wardline/core/finding.py:145` in `to_jsonl`; `src/wardline/core/finding.py:305`
in the Filigree `metadata.wardline.*` subtree; the agent-summary entries and the
legis artifact use the same key). The key was renamed from `suppressed` →
`suppression_state` (weft-f506e5f845) so the per-finding **state** never reads as
the opposite of the summary's `active` **count**: `suppression_state: "active"`
clearly names a state, while `summary.active` is a count of unsuppressed defects.
The Filigree metadata only carries the key when the state is not `active`
(`src/wardline/core/finding.py:305`).

**"suppressed"** survives only as the umbrella *word* for "any state other than
`active`": `baselined` + `waived` + `judged`. The CLI prints this sum as the
`suppressed` count (`src/wardline/cli/scan.py:568`).

## `active` is the one word for "non-suppressed defect"

The canonical term for a live, non-suppressed defect is **`active`** —
consistently, on every surface:

| Surface | Where | Term |
| --- | --- | --- |
| Enum | `src/wardline/core/finding.py:72` | `SuppressionState.ACTIVE = "active"` |
| Summary field | `src/wardline/core/run.py:71`, built at `src/wardline/core/run.py:551` | `ScanSummary.active` |
| CLI summary line | `src/wardline/cli/scan.py:569` | `… {s.active} active` |
| MCP scan response | `src/wardline/mcp/server.py:928` | `summary.active` |
| Agent-summary JSON | `src/wardline/core/agent_summary.py:129` | `summary.active_defects` |
| `wardline:loop` prompt | `src/wardline/mcp/prompts.py:13` | "Read `summary.active`" |

The agent-summary key is `active_defects` rather than bare `active` — that is a
descriptive-suffix convention alongside `total_findings` / `suppressed_findings`
(`src/wardline/core/agent_summary.py:133-141`), not a different concept. It counts
the same population.

The discipline test `tests/cli/test_scan_summary_vocab.py` pins this: the CLI
line says `active` (never `new`), and the count matches the agent-summary and MCP
surfaces.

## The summary buckets partition the total

`ScanSummary` (`src/wardline/core/run.py:68-89`) counts split the whole scan into
buckets that **sum to `total`** exactly (weft-f506e5f845):

- the defect buckets partition the `DEFECT`s by state —
  `active` (`src/wardline/core/run.py:71`) + `baselined` (`src/wardline/core/run.py:73`)
  + `waived` (`src/wardline/core/run.py:74`) + `judged` (`src/wardline/core/run.py:75`);
- `informational` (`src/wardline/core/run.py:81`) is **every non-defect finding**
  (facts, metrics, classifications) — the rest of `total`.

So `active + baselined + waived + judged + informational == total`
(`src/wardline/core/run.py:70` for `total: int`). `unanalyzed`
(`src/wardline/core/run.py:89`) is an **overlay** — a subset of `informational`
that surfaces a silent under-scan — and is deliberately **not** a partition member.
The MCP `summary` block exposes `informational` (`src/wardline/mcp/server.py:936`)
and `unanalyzed` (`src/wardline/mcp/server.py:940`); the agent-summary block mirrors
both (`src/wardline/core/agent_summary.py:140`, `src/wardline/core/agent_summary.py:141`).

## Emitted-active vs the gate population

There are **two distinct populations** of defects in one scan, and they can
differ on purpose:

1. **Emitted-active** — `summary.active` counts `active` defects in the
   **emitted** (post-annotation) findings (built at `src/wardline/core/run.py:554`).
   Baseline / waiver / judged annotate these findings in place; a suppressed
   defect is still emitted, just not counted as `active`.

2. **Gate population** — the `--fail-on` gate evaluates a **separate**
   `ScanResult.gate_findings` list: the *unsuppressed* population
   (`src/wardline/core/run.py:489`). By default, repository-controlled
   baseline / waiver / judged entries **annotate** the emitted findings but do
   **not** clear the gate — so a malicious PR cannot green the gate by committing
   a suppression keyed to its own new defect. `gate_decision` evaluates
   `gate_findings` when present, else falls back to `findings` (the trusted
   `--trust-suppressions` / directly-constructed path), selected at
   `src/wardline/core/run.py:648` (`honors_suppressions`).

This is why **`summary.active: 0` can co-exist with `gate.tripped: true`**: every
defect was suppressed by a committed baseline (so emitted-active is 0), but those
suppressions do not clear the unsuppressed gate population. It is by design, not a
bug.

### The gate verdict is explicit (never a vacuous green)

`GateDecision` (`src/wardline/core/run.py:152`) carries `tripped` / `fail_on` /
`exit_class` **plus** an explicit `verdict` (`src/wardline/core/run.py:162`) and a
`would_trip_at`, alongside a human `reason` and the `evaluated` population it
judged. The `verdict` is one of:

- **`NOT_EVALUATED`** — neither gate knob (`--fail-on` / `--fail-on-unanalyzed`)
  was set, so the gate never judged. A bare scan is **not** a clean pass;
  `would_trip_at` names the highest severity that *would* trip so the agent's
  first call is not a false green (weft-b937e53854).
- **`PASSED`** — at least one knob ran and nothing tripped.
- **`FAILED`** — a knob ran and tripped.

The decision composes two independent sub-gates: the severity gate (`fail_on`)
and the opt-in unanalyzed gate (`fail_on_unanalyzed`, MCP-primary A4 —
trips when any file was discovered but never analysed; benign no-module skips
excluded). `severity_tripped` / `unanalyzed_tripped` attribute an overall
`tripped` to its sub-gate(s) so no consumer has to parse `reason`.

The MCP `scan` gate block exposes `gate.tripped` (`src/wardline/mcp/server.py:943`),
`gate.fail_on_unanalyzed`, `gate.verdict` (`src/wardline/mcp/server.py:947`),
`gate.severity_tripped`, `gate.unanalyzed_tripped`, `would_trip_at`, `reason`,
`evaluated`, and `migration_hint`, opened at `src/wardline/mcp/server.py:942`
(`"gate": {`); the agent-summary mirrors them at
`src/wardline/core/agent_summary.py:144` (`tripped`) and
`src/wardline/core/agent_summary.py:147` (`verdict`). The CLI prints
`gate: FAILED (<the tripping knob(s)>) — <reason>` then `gate: evaluated <…>`, or a
`gate: NOT_EVALUATED — …` line for a bare scan
(`src/wardline/cli/scan.py:621`).

`--new-since` scopes **both** populations identically: any `active` defect
outside the delta is re-marked `baselined` in both the emitted and gate lists
(`src/wardline/core/run.py:499`, `def apply_delta_scope`).

## The three meanings of "new"

"new" is overloaded across the suite. Wardline's own surfaces no longer use it
for the active count (that was a historical CLI mislabel, now `active`). The word
still legitimately means three different things depending on the surface:

| "new" on this surface | Means | Owner / anchor |
| --- | --- | --- |
| Filigree store | An **unseen fingerprint** — first time this finding identity is seen for a `(file, scan_source)`. | **Filigree-owned** lifecycle (`src/wardline/core/filigree_emit.py:68-76`) |
| `wardline scan --new-since <ref>` | **Delta-scope**: the gate fires only on defects in files/entities changed since a git ref; everything else is re-marked `baselined`. | `src/wardline/core/run.py:499`; help text `src/wardline/cli/scan.py` (`--new-since`) |
| (historical) CLI summary | Formerly relabelled the `active` count as "N new". **Corrected to "N active"**. | `src/wardline/cli/scan.py:568` |

The first-seen Filigree sense and the delta-scope `--new-since` sense are
genuinely distinct concepts; neither is "active".

## Cross-surface mapping table

How each concept appears on each surface:

| Concept | CLI summary text | `ScanSummary` field | MCP `summary` key | Agent-summary key | Filigree store |
| --- | --- | --- | --- | --- | --- |
| every finding | `N finding(s)` | `total` (`run.py:70`) | `total` (`server.py:927`) | `total_findings` (`agent_summary.py:128`) | one finding per wire entry |
| live defect | `N active` (`scan.py:569`) | `active` (`run.py:71,551`) | `active` (`server.py:928`) | `active_defects` (`agent_summary.py:129`) | no `suppression_state` key (`finding.py:295`) |
| suppressed (sum) | `N suppressed` (`scan.py:568`) | `baselined+waived+judged` | the three keys | `suppressed_findings` (`agent_summary.py:130`) | `metadata.wardline.suppression_state` (`finding.py:295`) |
| baselined | `N baseline` | `baselined` (`run.py:73`) | `baselined` (`server.py:929`) | `baselined` (`agent_summary.py:132`) | `suppression_state: "baselined"` |
| waived | `N waiver` | `waived` (`run.py:74`) | `waived` (`server.py:930`) | `waived` (`agent_summary.py:133`) | `suppression_state: "waived"` |
| judged | `N judged` | `judged` (`run.py:75`) | `judged` (`server.py:931`) | `judged` (`agent_summary.py:134`) | `suppression_state: "judged"` |
| informational (summary) | (the remainder of `total`) | `informational` (`run.py:81`) | `informational` (`server.py:936`) | `informational` (`agent_summary.py:140`) | facts/metrics |
| informational (display) | n/a | n/a | n/a | `informational` display array (`agent_summary.py:165`) — non-defect, non-engine-fact findings (metrics, classifications, suggestions, non-engine facts); excludes `engine_facts` which has its own display slot | facts/metrics |
| under-scan | `N file(s) could not be analyzed` | `unanalyzed` (`run.py:89`) | `unanalyzed` (`server.py:940`) | `unanalyzed` (`agent_summary.py:141`) | `WLN-ENGINE-*` facts |
| gate verdict | exit code + `--fail-on` | (`gate_findings`, `run.py:110`; `GateDecision`, `run.py:152`, `verdict` `run.py:162`) | `gate` (`server.py:942`), `gate.tripped` (`server.py:943`), `gate.verdict` (`server.py:947`) | `gate.tripped` (`agent_summary.py:144`), `gate.verdict` (`agent_summary.py:147`) | not emitted to Filigree |

The unsuppressed gate population is built from `Baseline(frozenset())`
(`src/wardline/core/run.py:489`).

## For the suite

This page is the **Wardline-anchored** glossary. Two pieces of the vocabulary are
owned by sibling tools and are recorded here as coordination context:

- **Filigree's "new" / `seen_count` lifecycle is Filigree-owned.** Filigree
  decides first-seen vs returning purely from fingerprint presence across scans
  (`mark_unseen`, `src/wardline/core/filigree_emit.py`). Wardline emits the
  fingerprint and `scanned_paths`; it does not rename Filigree's first-seen
  concept. If a scan contains under-analysis findings (`WLN-ENGINE-*` unanalyzed
  rule ids), Wardline disables `mark_unseen` for that batch so an absent fingerprint
  cannot be treated as fixed when the source was not actually analyzed.

- **legis receives the gate population, keyed by `suppression_state`.** The legis
  scan artifact projects the *whole scan*, mapping `baselined` / `judged` onto
  legis's own `suppressed` value while `active` stays `active`, so legis reproduces
  Wardline's gate population exactly (the "one judge" property). The per-finding key
  was renamed `suppressed` → `suppression_state` (weft-f506e5f845); legis adopts the
  same key on its side (tracked as a federation contract change). See the CHANGELOG
  legis handoff entry and [Signed scan handoff to legis](../guides/legis-handoff.md).

In short: **within Wardline, `active` is the single word for a non-suppressed
defect, and `suppression_state` is the single per-finding key for its state, on
every surface.** The remaining divergence is genuine cross-tool semantics
(Filigree's first-seen lifecycle, `--new-since` delta-scope) that this glossary
documents rather than collapses.
