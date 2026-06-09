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
| `kind` | `defect`, `fact`, `classification`, `metric`, `suggestion` | `src/wardline/core/finding.py:63-69` (`Kind`) |
| `severity` | `CRITICAL`, `ERROR`, `WARN`, `INFO`, `NONE` | `src/wardline/core/finding.py:55-60` (`Severity`) |

Only `Kind.DEFECT` findings are ever suppressed or gated; facts and metrics
(`Severity.NONE`) never participate in the `--fail-on` gate
(`src/wardline/core/suppression.py:27-30`, `src/wardline/core/suppression.py:44-46`).

## The four suppression states

`SuppressionState` (`src/wardline/core/finding.py:71-75`) has exactly four
values. Every emitted `DEFECT` carries exactly one:

| State | Meaning | Set by |
| --- | --- | --- |
| `active` | Not suppressed — the default. A live defect. | default (`src/wardline/core/finding.py:72`, `src/wardline/core/finding.py:107`) |
| `baselined` | Matched a fingerprint in `.weft/wardline/baseline.yaml`. | `src/wardline/core/suppression.py:24` |
| `waived` | Matched an unexpired waiver in `.weft/wardline/waivers.yaml`. | `src/wardline/core/suppression.py:22` |
| `judged` | The LLM triage judge ruled it a false positive (`.weft/wardline/judged.yaml`). | `src/wardline/core/suppression.py:23` |

When more than one layer matches a finding, **precedence is
waiver > judged > baseline** — explicit human intent wins, then the LLM verdict
(so its rationale is the visible reason), then the silent baseline. The precedence
itself lives in the single JOIN predicate `resolve_identity`
(`src/wardline/core/finding_identity.py`); the suppression layer maps its verdict
onto the state (`src/wardline/core/suppression.py:78-87`).

### The per-finding key is `suppression_state` (not `suppressed`)

Each serialized finding carries its state under the key **`suppression_state`**
(`src/wardline/core/finding.py:140` in `to_jsonl`; `src/wardline/core/finding.py:285`
in the Filigree `metadata.wardline.*` subtree; the agent-summary entries and the
legis artifact use the same key). The key was renamed from `suppressed` →
`suppression_state` (weft-f506e5f845) so the per-finding **state** never reads as
the opposite of the summary's `active` **count**: `suppression_state: "active"`
clearly names a state, while `summary.active` is a count of unsuppressed defects.
The Filigree metadata only carries the key when the state is not `active`
(`src/wardline/core/finding.py:285`).

**"suppressed"** survives only as the umbrella *word* for "any state other than
`active`": `baselined` + `waived` + `judged`. The CLI prints this sum as the
`suppressed` count (`src/wardline/cli/scan.py:403`).

## `active` is the one word for "non-suppressed defect"

The canonical term for a live, non-suppressed defect is **`active`** —
consistently, on every surface:

| Surface | Where | Term |
| --- | --- | --- |
| Enum | `src/wardline/core/finding.py:72` | `SuppressionState.ACTIVE = "active"` |
| Summary field | `src/wardline/core/run.py:50`, built at `src/wardline/core/run.py:335` | `ScanSummary.active` |
| CLI summary line | `src/wardline/cli/scan.py:404` | `… {s.active} active` |
| MCP scan response | `src/wardline/mcp/server.py:331` | `summary.active` |
| Agent-summary JSON | `src/wardline/core/agent_summary.py:135` | `summary.active_defects` |
| `wardline:loop` prompt | `src/wardline/mcp/prompts.py:13` | "Read `summary.active`" |

The agent-summary key is `active_defects` rather than bare `active` — that is a
descriptive-suffix convention alongside `total_findings` / `suppressed_findings`
(`src/wardline/core/agent_summary.py:134-147`), not a different concept. It counts
the same population.

The discipline test `tests/cli/test_scan_summary_vocab.py` pins this: the CLI
line says `active` (never `new`), and the count matches the agent-summary and MCP
surfaces.

## The summary buckets partition the total

`ScanSummary` (`src/wardline/core/run.py:47-68`) counts split the whole scan into
buckets that **sum to `total`** exactly (weft-f506e5f845):

- the defect buckets partition the `DEFECT`s by state —
  `active` (`src/wardline/core/run.py:50`) + `baselined` (`src/wardline/core/run.py:52`)
  + `waived` (`src/wardline/core/run.py:53`) + `judged` (`src/wardline/core/run.py:54`);
- `informational` (`src/wardline/core/run.py:60`) is **every non-defect finding**
  (facts, metrics, classifications) — the rest of `total`.

So `active + baselined + waived + judged + informational == total`
(`src/wardline/core/run.py:49` for `total: int`). `unanalyzed`
(`src/wardline/core/run.py:68`) is an **overlay** — a subset of `informational`
that surfaces a silent under-scan — and is deliberately **not** a partition member.
The MCP `summary` block exposes `informational` (`src/wardline/mcp/server.py:339`)
and `unanalyzed` (`src/wardline/mcp/server.py:343`); the agent-summary block mirrors
both (`src/wardline/core/agent_summary.py:146`, `src/wardline/core/agent_summary.py:147`).

## Emitted-active vs the gate population

There are **two distinct populations** of defects in one scan, and they can
differ on purpose:

1. **Emitted-active** — `summary.active` counts `active` defects in the
   **emitted** (post-annotation) findings (built at `src/wardline/core/run.py:335`).
   Baseline / waiver / judged annotate these findings in place; a suppressed
   defect is still emitted, just not counted as `active`.

2. **Gate population** — the `--fail-on` gate evaluates a **separate**
   `ScanResult.gate_findings` list: the *unsuppressed* population
   (`src/wardline/core/run.py:301`). By default, repository-controlled
   baseline / waiver / judged entries **annotate** the emitted findings but do
   **not** clear the gate — so a malicious PR cannot green the gate by committing
   a suppression keyed to its own new defect. `gate_decision` evaluates
   `gate_findings` when present, else falls back to `findings` (the trusted
   `--trust-suppressions` / directly-constructed path), selected at
   `src/wardline/core/run.py:386` (`honors_suppressions`).

This is why **`summary.active: 0` can co-exist with `gate.tripped: true`**: every
defect was suppressed by a committed baseline (so emitted-active is 0), but those
suppressions do not clear the unsuppressed gate population. It is by design, not a
bug.

### The gate verdict is explicit (never a vacuous green)

`GateDecision` (`src/wardline/core/run.py:97`) carries `tripped` / `fail_on` /
`exit_class` **plus** an explicit `verdict` (`src/wardline/core/run.py:106`) and a
`would_trip_at`, alongside a human `reason` and the `evaluated` population it
judged. The `verdict` is one of:

- **`NOT_EVALUATED`** — no `--fail-on` threshold was set, so the gate never judged.
  A bare scan is **not** a clean pass; `would_trip_at` names the highest severity
  that *would* trip so the agent's first call is not a false green (weft-b937e53854).
- **`PASSED`** — a threshold ran and nothing tripped.
- **`FAILED`** — a threshold ran and tripped.

The MCP `scan` gate block exposes `gate.tripped` (`src/wardline/mcp/server.py:346`),
`gate.verdict` (`src/wardline/mcp/server.py:349`), `would_trip_at`, `reason`,
`evaluated`, and `migration_hint`, opened at `src/wardline/mcp/server.py:345`
(`"gate": {`); the agent-summary mirrors them at
`src/wardline/core/agent_summary.py:150` (`tripped`) and
`src/wardline/core/agent_summary.py:153` (`verdict`). The CLI prints
`gate: FAILED (--fail-on …) — <reason>` then `gate: evaluated <…>`, or a
`gate: NOT_EVALUATED — …` line for a bare scan
(`src/wardline/cli/scan.py:438`).

`--new-since` scopes **both** populations identically: any `active` defect
outside the delta is re-marked `baselined` in both the emitted and gate lists
(`src/wardline/core/run.py:311`, `def apply_delta_scope`).

## The three meanings of "new"

"new" is overloaded across the suite. Wardline's own surfaces no longer use it
for the active count (that was a historical CLI mislabel, now `active`). The word
still legitimately means three different things depending on the surface:

| "new" on this surface | Means | Owner / anchor |
| --- | --- | --- |
| Filigree store | An **unseen fingerprint** — first time this finding identity is seen for a `(file, scan_source)`. | **Filigree-owned** lifecycle (`src/wardline/core/filigree_emit.py:68-76`) |
| `wardline scan --new-since <ref>` | **Delta-scope**: the gate fires only on defects in files/entities changed since a git ref; everything else is re-marked `baselined`. | `src/wardline/core/run.py:311`; help text `src/wardline/cli/scan.py` (`--new-since`) |
| (historical) CLI summary | Formerly relabelled the `active` count as "N new". **Corrected to "N active"**. | `src/wardline/cli/scan.py:403` |

The first-seen Filigree sense and the delta-scope `--new-since` sense are
genuinely distinct concepts; neither is "active".

## Cross-surface mapping table

How each concept appears on each surface:

| Concept | CLI summary text | `ScanSummary` field | MCP `summary` key | Agent-summary key | Filigree store |
| --- | --- | --- | --- | --- | --- |
| every finding | `N finding(s)` | `total` (`run.py:49`) | `total` (`server.py:330`) | `total_findings` (`agent_summary.py:134`) | one finding per wire entry |
| live defect | `N active` (`scan.py:404`) | `active` (`run.py:50,335`) | `active` (`server.py:331`) | `active_defects` (`agent_summary.py:135`) | no `suppression_state` key (`finding.py:285`) |
| suppressed (sum) | `N suppressed` (`scan.py:403`) | `baselined+waived+judged` | the three keys | `suppressed_findings` (`agent_summary.py:136`) | `metadata.wardline.suppression_state` (`finding.py:285`) |
| baselined | `N baseline` | `baselined` (`run.py:52`) | `baselined` (`server.py:332`) | `baselined` (`agent_summary.py:138`) | `suppression_state: "baselined"` |
| waived | `N waiver` | `waived` (`run.py:53`) | `waived` (`server.py:333`) | `waived` (`agent_summary.py:139`) | `suppression_state: "waived"` |
| judged | `N judged` | `judged` (`run.py:54`) | `judged` (`server.py:334`) | `judged` (`agent_summary.py:140`) | `suppression_state: "judged"` |
| informational (summary) | (the remainder of `total`) | `informational` (`run.py:60`) | `informational` (`server.py:339`) | `informational` (`agent_summary.py:146`) | facts/metrics |
| informational (display) | n/a | n/a | n/a | `informational` display array (`agent_summary.py:171`) — non-defect, non-engine-fact findings (metrics, classifications, suggestions, non-engine facts); excludes `engine_facts` which has its own display slot | facts/metrics |
| under-scan | `N file(s) could not be analyzed` | `unanalyzed` (`run.py:68`) | `unanalyzed` (`server.py:343`) | `unanalyzed` (`agent_summary.py:147`) | `WLN-ENGINE-*` facts |
| gate verdict | exit code + `--fail-on` | (`gate_findings`, `run.py:87`; `GateDecision`, `run.py:97`, `verdict` `run.py:106`) | `gate.tripped` (`server.py:346`), `gate.verdict` (`server.py:349`) | `gate.tripped` (`agent_summary.py:150`), `gate.verdict` (`agent_summary.py:153`) | not emitted to Filigree |

The unsuppressed gate population is built from `Baseline(frozenset())`
(`src/wardline/core/run.py:301`).

## For the suite

This page is the **Wardline-anchored** glossary. Two pieces of the vocabulary are
owned by sibling tools and are recorded here as coordination context:

- **Filigree's "new" / `seen_count` lifecycle is Filigree-owned.** Filigree
  decides first-seen vs returning purely from fingerprint presence across scans
  (`mark_unseen`, `src/wardline/core/filigree_emit.py:68-76`). Wardline emits the
  fingerprint and `scanned_paths`; it does not rename Filigree's first-seen concept.

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
