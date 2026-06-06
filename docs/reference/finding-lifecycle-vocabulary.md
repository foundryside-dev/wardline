# Finding lifecycle & gate vocabulary

This is the single source of truth for the words Wardline uses to describe the
**state and lifecycle of a finding** — `new`, `active`, `suppressed`,
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
| `kind` | `defect`, `fact`, `classification`, `metric`, `suggestion` | `src/wardline/core/finding.py:59-65` (`Kind`) |
| `severity` | `CRITICAL`, `ERROR`, `WARN`, `INFO`, `NONE` | `src/wardline/core/finding.py:51-56` (`Severity`) |

Only `Kind.DEFECT` findings are ever suppressed or gated; facts and metrics
(`Severity.NONE`) never participate in the `--fail-on` gate
(`src/wardline/core/suppression.py:20-22`, `src/wardline/core/suppression.py:37-39`).

## The four suppression states

`SuppressionState` (`src/wardline/core/finding.py:67-71`) has exactly four
values. Every emitted `DEFECT` carries exactly one:

| State | Meaning | Set by |
| --- | --- | --- |
| `active` | Not suppressed — the default. A live defect. | default (`src/wardline/core/finding.py:68`, `src/wardline/core/finding.py:103`) |
| `baselined` | Matched a fingerprint in `.wardline/baseline.yaml`. | `src/wardline/core/suppression.py:70` |
| `waived` | Matched an unexpired waiver in `wardline.yaml`. | `src/wardline/core/suppression.py:66` |
| `judged` | The LLM triage judge ruled it a false positive (`.wardline/judged.yaml`). | `src/wardline/core/suppression.py:68` |

When more than one layer matches a finding, **precedence is
waiver > judged > baseline** — explicit human intent wins, then the LLM verdict
(so its rationale is the visible reason), then the silent baseline
(`src/wardline/core/suppression.py:61-70`).

**"suppressed"** is the umbrella term for "any state other than `active`":
`baselined` + `waived` + `judged`. The CLI prints this sum as the `suppressed`
count (`src/wardline/cli/scan.py:366`), and `to_filigree_metadata` only writes a
`suppressed` key when the state is not `active`
(`src/wardline/core/finding.py:184-187`).

## `active` is the one word for "non-suppressed defect"

The canonical term for a live, non-suppressed defect is **`active`** —
consistently, on every surface:

| Surface | Where | Term |
| --- | --- | --- |
| Enum | `src/wardline/core/finding.py:68` | `SuppressionState.ACTIVE = "active"` |
| Summary field | `src/wardline/core/run.py:49`, built at `src/wardline/core/run.py:280` | `ScanSummary.active` |
| CLI summary line | `src/wardline/cli/scan.py:367` | `… {s.active} active` |
| MCP scan response | `src/wardline/mcp/server.py:314` | `summary.active` |
| Agent-summary JSON | `src/wardline/core/agent_summary.py:90` | `summary.active_defects` |
| `wardline:loop` prompt | `src/wardline/mcp/prompts.py:13` | "Read `summary.active`" |

The agent-summary key is `active_defects` rather than bare `active` — that is a
descriptive-suffix convention alongside `total_findings` / `suppressed_findings`
(`src/wardline/core/agent_summary.py:89-96`), not a different concept. It counts
the same population.

The discipline test `tests/cli/test_scan_summary_vocab.py` pins this: the CLI
line says `active` (never `new`), and the count matches the agent-summary and MCP
surfaces.

## The three meanings of "new"

"new" is overloaded across the suite. Wardline's own surfaces no longer use it
for the active count (that was a historical CLI mislabel, now `active`). The word
still legitimately means three different things depending on the surface:

| "new" on this surface | Means | Owner / anchor |
| --- | --- | --- |
| Filigree store | An **unseen fingerprint** — first time this finding identity is seen for a `(file, scan_source)`. Driven by `mark_unseen` / the absent-fingerprint sweep. | **Filigree-owned** lifecycle (`src/wardline/core/filigree_emit.py:68-76`) |
| `wardline scan --new-since <ref>` | **Delta-scope**: the gate fires only on defects in files/entities changed since a git ref; everything else is re-marked `baselined`. | `src/wardline/core/run.py:256-275`; help text `src/wardline/cli/scan.py` (`--new-since`, "new findings only") |
| (historical) CLI summary | Formerly relabelled the `active` count as "N new". **Corrected to "N active"** so the CLI matches every other surface. | `src/wardline/cli/scan.py:367` |

The first-seen Filigree sense and the delta-scope `--new-since` sense are
genuinely distinct concepts; neither is "active". An agent should read the CLI /
MCP `active` count as "live defects now", Filigree's first-seen status as "is this
identity new to the tracker", and `--new-since` as "only gate on what changed".

## Emitted-active vs the gate population

There are **two distinct populations** of defects in one scan, and they can
differ on purpose:

1. **Emitted-active** — `summary.active` counts `active` defects in the
   **emitted** (post-annotation) findings (`src/wardline/core/run.py:277-285`).
   Baseline / waiver / judged annotate these findings in place; a suppressed
   defect is still emitted, just not counted as `active`.

2. **Gate population** — the `--fail-on` gate evaluates a **separate**
   `ScanResult.gate_findings` list: the *unsuppressed* population
   (`src/wardline/core/run.py:242-246`). By default, repository-controlled
   baseline / waiver / judged entries **annotate** the emitted findings but do
   **not** clear the gate — so a malicious PR cannot green the gate by committing
   a suppression keyed to its own new defect. `gate_decision` evaluates
   `gate_findings` when present, else falls back to `findings` (the trusted
   `--trust-suppressions` / directly-constructed path)
   (`src/wardline/core/run.py:307-308`).

This is why **`summary.active: 0` can co-exist with `gate.tripped: true`**: every
defect was suppressed by a committed baseline (so emitted-active is 0), but those
suppressions do not clear the unsuppressed gate population. It is by design, not a
bug. The gate result is reported separately from `summary.active`: `GateDecision`
carries `tripped` / `fail_on` / `exit_class` **plus** a human `reason` and the
`evaluated` population it judged (`src/wardline/core/run.py:82-92`), so the
`0 active + tripped` case explains itself instead of reading as a defect. The MCP
`scan` block exposes `gate.tripped` / `gate.reason` / `gate.evaluated` /
`gate.migration_hint` (`src/wardline/mcp/server.py:333-339`); the CLI prints
`gate: FAILED (--fail-on …) — <reason>` then `gate: evaluated <…>` on stderr
(`src/wardline/cli/scan.py:381-382`).

`--new-since` scopes **both** populations identically: any `active` defect
outside the delta is re-marked `baselined` in both the emitted and gate lists
(`src/wardline/core/run.py:256-275`).

## Cross-surface mapping table

How each concept appears on each surface:

| Concept | CLI summary text | `ScanSummary` field | MCP `summary` key | Agent-summary key | Filigree store |
| --- | --- | --- | --- | --- | --- |
| every finding | `N finding(s)` | `total` (`run.py:48`) | `total` (`server.py:313`) | `total_findings` (`agent_summary.py:89`) | one finding per wire entry |
| live defect | `N active` (`scan.py:367`) | `active` (`run.py:49,280`) | `active` (`server.py:314`) | `active_defects` (`agent_summary.py:90`) | no `suppressed` key (`finding.py:184`) |
| suppressed (sum) | `N suppressed` (`scan.py:366`) | `baselined+waived+judged` | the three keys | `suppressed_findings` (`agent_summary.py:91`) | `metadata.wardline.suppressed` (`finding.py:184-187`) |
| baselined | `N baseline` | `baselined` (`run.py:51`) | `baselined` (`server.py:315`) | `baselined` (`agent_summary.py:93`) | `suppressed: "baselined"` |
| waived | `N waiver` | `waived` (`run.py:52`) | `waived` (`server.py:316`) | `waived` (`agent_summary.py:94`) | `suppressed: "waived"` |
| judged | `N judged` | `judged` (`run.py:53`) | `judged` (`server.py:317`) | `judged` (`agent_summary.py:95`) | `suppressed: "judged"` |
| under-scan | `N file(s) could not be analyzed` | `unanalyzed` (`run.py:59`) | `unanalyzed` (`server.py:321`) | `unanalyzed` (`agent_summary.py:96`) | `WLN-ENGINE-*` facts |
| gate verdict | exit code + `--fail-on` | (`gate_findings`, `run.py:78`) | `gate.tripped` (`server.py:334`) | `gate.tripped` (`agent_summary.py:99`) | not emitted to Filigree |

## For the suite

This page is the **Wardline-anchored** glossary. Two pieces of the vocabulary are
owned by sibling tools and are intentionally **not** renamed by Wardline — they
are recorded here as coordination context, not as a change Wardline executes:

- **Filigree's "new" / `seen_count` lifecycle is Filigree-owned.** Filigree
  decides first-seen vs returning purely from fingerprint presence across scans
  (`mark_unseen`, `src/wardline/core/filigree_emit.py:68-76`). Wardline emits the
  fingerprint and `scanned_paths`; it does not, and should not, rename Filigree's
  first-seen concept to match its own `active`. The two words mean different
  things and that distinction is correct.

- **legis receives the gate population as `active`.** The legis scan artifact
  projects the *whole scan*, mapping `baselined` / `judged` onto legis's own
  `suppressed` while `active` stays `active`, so legis reproduces Wardline's gate
  population exactly (the "one judge" property). This is a contract Wardline
  conforms to, not a rename of any other tool's fields (see the CHANGELOG legis
  handoff entry and [Signed scan handoff to legis](../guides/legis-handoff.md)).

In short: **within Wardline, `active` is the single word for a non-suppressed
defect, on every surface.** The remaining divergence is genuine cross-tool
semantics (Filigree's first-seen lifecycle, `--new-since` delta-scope) that this
glossary documents rather than collapses. No cross-repo rename is implied.
