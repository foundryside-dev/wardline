# Warpline delta scan — design spec

- **Date:** 2026-06-18
- **Status:** Approved (brainstorm), pre-plan
- **Tracker:** `wardline-4e08ab9ce6` (B, this spec) · `wardline-c0563eee74` (A, follow-on)
- **Baseline commit:** `4a24a032`
- **Label:** `warpline-delta-2026-06-18`

## 1. Background & topology correction

This spec emerged from a 2026-06-18 review (CI comparison vs `~/elspeth` →
federation-seam review → the warpline node) and the "next evolution" brainstorm.

**Warpline is the Weft federation's change-impact authority and is
advisory-only.** It does **not** ingest wardline findings. The data flow is:

```
wardline scan → findings → filigree (issues bound to loomweave SEIs)
warpline reads SEI + filigree → computes "changed + downstream" (call-graph
  closure, keyed by loomweave SEI) → reverify worklist → filigree
  warpline_worklist_ingest
```

So the in-grain wardline↔warpline edge runs the **opposite** direction from
"findings out": warpline says **what to re-verify**, and wardline is the
trust-gate that re-verifies it. Building "wardline findings → warpline worklist"
would be against the design.

## 2. Goal

Give wardline a **producer-agnostic "scan only these entities" capability** for
fast agent inner-loop feedback. Warpline's reverify worklist is the primary
producer, but **wardline never talks to warpline** — it consumes a scope set
that any producer (warpline, or an agent by hand) can supply.

The full scan remains the **gate of record** (CI). Delta scan is **speed, never
truth**: it never claims completeness, so there is no soundness regression to
engineer around.

## 3. Non-goals

- Delta is **not** a gate of record. CI keeps running the full scan.
- **No new sibling client.** wardline does not call warpline (HTTP/MCP/CLI).
- **No soundness claim** about cross-file taint flows outside the scope set —
  those are *declared out* in the result, never silently dropped.
- No change to the existing full-scan path's findings or fingerprints.

## 4. Decisions locked in the brainstorm

| Decision | Choice | Rationale |
|---|---|---|
| Edge | Delta scan from impact | The in-grain composition; warpline=impact, wardline=trust gate |
| Boundary | Producer-agnostic scope input | Decoupled, hermetically testable, no new client; the scope-set is the contract A pins |
| Authority | Advisory inner-loop | Full scan stays gate of record → no soundness regression |

## 5. Architecture

All new code lives under `src/wardline/core/`. The full-scan path is unchanged;
delta is a **scoping pre-filter on discovery** plus a **post-filter on
findings**.

### 5.1 Scope input — `delta_scope.py`

A new module that parses an **affected-entity scope** from one of two accepted
shapes:

1. A `warpline.reverify_worklist.v1` envelope (success envelope or its bare
   `data` payload), reading `items[].entity.{sei, locator}`.
2. A bare entity list: `[{ "sei"?: str, "locator"?: str }, ...]`.

Output: a normalized `AffectedScope` value — a frozen set of
`(sei | None, locator | None)` entries plus provenance (source kind, item
count). Empty or malformed input is **not** an error here; it is reported to the
caller, which applies the fail-closed rule (§5.4).

### 5.2 Entity → file resolution

Each affected entity must resolve to a file the scanner can analyze:

1. **SEI present** → resolve via loomweave (`SeiResolver`, already wired in
   `src/wardline/loomweave/`) to a file path. Authoritative.
2. **SEI absent or loomweave unavailable** → fall back to wardline's own
   parse-time **qualname index**: discovery already walks the tree and the
   engine resolves qualnames; we build a `qualname → file` map cheaply and match
   `locator` against it.
3. **Unresolvable entity** → contributes no file **and** trips the fail-closed
   rule (§5.4). Resolution outcomes (resolved / fell-back / unresolved) are
   recorded for the scope block.

### 5.3 Scan scoping & finding filter

- **Discovery still walks the whole tree** (cheap — a filesystem walk), so the
  `qualname → file` index is complete.
- The engine **only analyzes files that contain an affected entity.** Each such
  file is analyzed **in full** — whole-module context is preserved, so there is
  no *intra-file* soundness loss. **There IS inter-file soundness loss** (see
  §5.3a) and the design does not claim otherwise.
- After analysis, the **finding filter** keeps only findings whose
  `qualname`/`location` is in the affected set, **for the EMITTED/displayed
  findings only** (`findings`). The **gate population (`gate_findings`) is NEVER
  narrowed** in delta mode (INV-4 / §5.4). Findings on other entities in the
  same analyzed file are *context* in the displayed output, not silently dropped
  from the gate.

### 5.3a Soundness: the inter-file taint gap (honest accounting)

A taint **defect anchors at the SINK entity**, not the source. Because only
affected-entity files reach `analyzer.analyze`, cross-file taint that flows from
an out-of-scope **source** file into an in-scope **sink** is not computed: the
real finding can be **silently dropped (false negative)**, and an in-scope sink
whose source moved out of scope can read **clean**. This is the *dominant*
cross-function taint case, so the design must NOT claim "no soundness loss" — the
loss is inter-file and real. Two consequences for the plan:

1. **Closure-direction reconciliation.** Warpline computes "changed + DOWNSTREAM
   (callees)", but taint findings live **caller-side**; wardline's own
   `--new-since` path deliberately closes over **callers**
   (`core/delta.get_affected_entities`, reverse callee→caller BFS). Feeding
   warpline's downstream worklist straight into a caller-side analysis can
   scope-OUT the caller that actually carries the finding. The plan must, after
   resolving affected entities to files, **expand the analyzed file set once via
   the reverse-edge caller closure** (`get_affected_entities` over
   `last_context.project_edges`) so sinks downstream of a changed source are
   pulled in. This is a load-bearing correctness precondition, not a footnote.
2. **The boundary_caveat (above) states the stronger in-scope-correctness truth**
   so an agent does not over-trust "no findings on my change."

### 5.4 Fail-closed + honesty (load-bearing)

- If the scope is **empty or unresolvable** — or `--affected` was supplied but
  neither loomweave nor the qualname index can resolve any entity — wardline
  **falls back to a full scan**, and says so. A trust tool never narrows itself
  into a blind spot silently.
- Every delta result carries a **`scope` block**:
  - `mode`: `"delta"` | `"full-fallback"`
  - `gate_authority`: `"advisory"` (delta) | `"gate-of-record"` (full-fallback) —
    a **machine-readable** field an automated consumer can gate on, so a delta
    pass is type-distinguishable from a full pass without parsing prose.
  - `entities_requested`: N
  - `files_discovered`: D (the full discovery count)
  - `files_analyzed`: M (the scoped subset actually handed to `analyzer.analyze`;
    M == D only in `full-fallback`)
  - `in_scope_findings`: K
  - `fell_back_count`: number of entities resolved via the spoofable qualname
    locator path rather than authoritative SEI
  - `unresolved_entities`: list (locator/sei that did not resolve)
  - `boundary_caveat`: a fixed string — *"Delta scan analyzes only files
    containing the affected entities. Findings here may be incomplete OR absent:
    cross-file taint whose source lies outside the analyzed set is not computed,
    so an in-scope entity can read clean without being clean. Advisory
    inner-loop signal, not a verdict — the full scan is the gate of record."*
- This block is both the **honesty contract** for agents reading the result and
  the **seam that spec A pins** as a published contract. The caveat names the
  *in-scope-entity correctness* hazard (a finding ON an analyzed entity can be
  missing because its upstream taint source was out of scope), not just the
  omission of out-of-scope entities — because an agent acts on the findings that
  ARE present.
- **The honesty contract is enforceable, not just readable:** the severity gate
  in delta mode runs over the full unsuppressed population (INV-4), so the
  `gate_authority="advisory"` label and the full-population gate together make a
  forged green structurally impossible.

## 6. Surface

- **CLI:** `wardline scan --affected <file|->`. `-` reads the
  worklist/entity-list from stdin, so `warpline reverify | wardline scan
  --affected -` works with no glue.
- **MCP:** the `scan` tool gains an `affected` parameter (object/array or a path)
  — matching the MCP-primary direction. The `scope` block is emitted in
  structured content.
- **Deferred-optional convenience:** `--since <gitref>` resolves the affected set
  itself. It is built **on top of** the generic `--affected` input (it produces a
  scope, then the same path runs), keeping the core decoupled. Marked optional;
  may land in a later increment.

Output formats (`--format human|json|sarif`) all carry the `scope` block; SARIF
puts it in run-level `properties`.

## 7. Error handling summary

| Condition | Behavior |
|---|---|
| `--affected` not given | Normal full scan (unchanged path) |
| Malformed scope payload | Loud error (exit 2) — agent payload bug, not a degrade |
| Empty/zero-resolvable scope | Full-fallback scan, declared in scope block |
| loomweave absent | Qualname-index resolution; note in scope block |
| Some entities unresolved | Scan the resolved subset; list unresolved in scope block; if **none** resolved → full-fallback |
| Scope **surgically excludes** a sink-bearing file (malicious or stale worklist) | NOT a fail-closed condition (>0 files resolve → normal delta). Protection is INV-4: the severity gate runs over the FULL population, so the gate cannot green a real ERROR. Fail-closed-on-empty does **not** cover this case. |
| `--affected` + `--fail-on` composed | Allowed; the gate evaluates the full unsuppressed population (INV-4), `gate_authority="advisory"`. A delta scan can surface a trip as data but cannot emit an authoritative full-scan PASS. |
| `--affected` + `--new-since` composed | Mutually exclusive at CLI **and** MCP (loud `ScopeParseError`/`ToolError`). They scope different things (analysis vs gate) via different mechanisms; composing them is rejected, not silently double-scoped. |
| Oversized scope payload | `ScopeParseError` above a byte/`item_count` cap (DoS guard on the uncapped stdin/inline ingress). |

## 8. Testing

- **Hermetic golden (every PR, no sibling):** a fixed `warpline.reverify_worklist.v1`
  fixture + a small sample tree → assert the scoped file set, the filtered
  finding set, and the `scope` block (including the fallback path and the
  unresolved-entity path).
- **Unit:** `delta_scope.py` parsing (both input shapes, malformed, empty);
  entity→file resolution (SEI path, qualname fallback, unresolved); finding
  filter; fail-closed fallback.
- **New `warpline_e2e` marker** (fail-closed exactly like `loomweave_e2e` /
  `legis_e2e` / `filigree_e2e` — `WARDLINE_LIVE_ORACLE_REQUIRED=1` turns SKIP →
  FAIL): live `warpline reverify | wardline scan --affected -` round-trip,
  weekly/manual in CI only.

## 9. Reference contracts (from the 2026-06-18 mapping)

- **filigree `warpline_worklist_ingest`** — `~/filigree/src/filigree/mcp_tools/federation.py`
  + `~/filigree/src/filigree/warpline_consumer.py` (style reference only, not an
  import target — note it is at the package root, NOT under `mcp_tools/`).
  Worklist item shape:
  `{entity:{locator,sei}, priority, reason, depth, why[], suggested_verification[{kind,command}], enrichment{work,risk,governance,requirements}}`.
- **wardline emitter patterns to mirror for style/transport discipline** —
  `src/wardline/core/filigree_emit.py` (urllib + Bearer, fail-soft) and
  `src/wardline/core/legis.py` (HMAC, build-not-send). Delta scan has **no
  outbound transport**, but the fail-soft/loud discipline and config-via-`weft.toml`
  conventions carry over.
- **wardline Finding model** — `src/wardline/core/finding.py`
  (`rule_id`, `severity`, `kind`, `location`, `fingerprint`, `qualname`,
  `properties`, `suppression`). The finding filter keys on `qualname`/`location`.
- **loomweave SEI resolver** — `src/wardline/loomweave/` (`SeiResolver`,
  `identity.py`).

## 10. The A follow-on (separate spec)

`wardline-c0563eee74` turns this consumption into a **published, drift-checked
contract**: wardline consumes `warpline.reverify_worklist.v1` and emits a
`wardline.delta_scope.v1` provenance block; a golden vector pins it in CI against
the producer's *published* artifact — fixing the live gap that today's
conformance goldens are vendored stale copies whose drift check
(`test_sei_oracle.py::test_vendored_oracle_matches_loomweave_source`) skips
unless `LOOMWEAVE_REPO` is set, which CI never does. A is **out of scope for this
spec**; it gets its own spec → plan cycle.
