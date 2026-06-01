# Wardline — Loom entity dossier (design)

**Date:** 2026-06-01  
**Status:** Approved design (brainstormed; ready for implementation planning)  
**Scope:** Add a Wardline-assembled, cross-tool **entity dossier** — one
freshness-honest call that returns everything an agent needs to reason about a
function without reading its source — joining Wardline (trust), Clarion (code
intelligence), Filigree (work state), and git (history) on a single entity
identity.

> **Part of the Loom suite.** This spec describes Wardline's role as the
> *assembler*; Clarion and Filigree are read sources accessed through contracts
> they already (mostly) expose. It composes with the trust-declaration specs
> ([explicit `@trusted`](2026-06-01-wardline-explicit-trusted-body-return-design.md),
> [config-backed trust](2026-06-01-wardline-config-trust-declarations-design.md))
> but does not depend on them.

---

## 1. Goal

Give an agent **mastery of the codebase**: the ability to consider a function
and retrieve the facts it needs — trust posture, decorators, linkages, recent
history, and open work — in *one* structured, freshness-stamped call, instead of
reading a hundred lines across several files and several tools.

The human version of this dream is a **view**: assemble the facts and render them
for the eyes. The agent version is a **substrate + protocol**, and it differs in
four ways that drive the whole design:

| Human | Agent (this design) |
|---|---|
| Reads annotated source and interprets it | Wants the **derived property** already resolved ("`@trusted(INTEGRAL)` whose actual return is `ASSURED` → PY-WL-101 fires"). Source is a fallback, not the payload. |
| Eyeballs whether a fact looks stale | **Cannot** eyeball staleness — needs freshness as a typed contract on every fact, or it reasons on a lie. |
| Opens linkages one file at a time | Wants to **pivot cheaply** — traverse the entity graph and get the same shape at each hop in one call. |
| Starts from "this function" | Will also want to start from "**find every function matching this risk predicate**" (the inverse query — North Star, §10). |

This is the natural completion of a pattern Loom has already started: Wardline
already writes per-entity `wardline-taint-1` facts **into** Clarion (SP9), and
Filigree (ADR-029) already **binds issues to Clarion entity IDs** with
`content_hash_at_attach` drift detection. All three tools already agree on one
join key — the Clarion entity. The dossier is the read over that agreement.

---

## 2. Current capability review

Wardline can already do most of the plumbing:

1. `ClarionClient` already does `resolve(qualnames)` (qualname → entity),
   `write_taint_facts`, and `get_taint_fact` / `batch_get`, over a swappable
   `Transport` protocol (`src/wardline/clarion/client.py`). Entity resolution
   and per-entity fact read/write already exist.
2. The SP9 **never-serve-stale** blake3 freshness gate already exists for taint
   facts; this design generalises it to every section of the dossier
   (`docs/superpowers/specs/2026-05-31-wardline-sp9-clarion-taint-store-design.md`).
3. The MCP `explain_taint` tool already re-derives a fresh trust verdict and
   walks the N-hop taint chain via `core` functions; the dossier reuses that
   machinery rather than duplicating it.
4. The native Filigree emitter already speaks dep-free urllib to a Filigree HTTP
   server (`src/wardline/core/filigree_emit.py`); the dossier's Filigree read
   client follows the same pattern.
5. ADR-029 already exposes the reverse lookup the dossier needs:
   `GET /api/entity-associations?entity_id=…` (and the MCP/CLI
   `list_associations_by_entity`).

So this is an **assembly + contract** feature, not a new engine and not a new
trust model.

---

## 3. Fixed design decisions

Settled during brainstorming; not re-opened here:

1. **Wardline assembles.** A shared `core/dossier.py` orchestrates the join; the
   CLI (`wardline dossier`) and the MCP `dossier` tool both call it (CLI/MCP
   identical by construction). Clarion and Filigree are *read sources*, not
   owners.
2. **v1 verbs are `dossier` and bounded `traverse`.** Read-only. `find(predicate)`
   worklists and write-back are North Star, not v1 (§10).
3. **Freshness: re-derive cheap, flag dear.** Wardline's own facts are
   re-derived on demand (always FRESH); Clarion/Filigree facts are served with an
   explicit `STALE`/`DRIFT` verdict. Nothing stale is ever served unlabelled.
4. **History via `git log -L`** over the entity's line span (zero new deps,
   always available). Rename-following / temporal posture-diff is North Star.
5. **Fail-soft, standalone-preserving.** Wardline stays zero-dependency. With no
   Clarion or Filigree configured, the dossier still returns its Wardline-derived
   sections; absent sources are labelled `unavailable`, never fatal.

---

## 4. Architecture: the assembler and its four sources

`core/dossier.py` exposes one entry point used by both surfaces:

```python
def build_dossier(entity: str, *, root: Path, drill: Sequence[str] = (), ...) -> EntityDossier: ...
```

It fans out to four sources, joined on **entity identity** (Clarion `entity_id`
when available; otherwise qualname + content hash):

| Source | Provides | Mechanism | Freshness |
|---|---|---|---|
| **self** (Wardline engine) | trust verdict, declared/actual taint, active findings, taint chain | re-scan the entity's module via `core/run` + the `explain` internals | FRESH by construction |
| **Clarion** (opt-in `[clarion]`) | `resolve()` → `entity_id`; linkages (callers/callees/SCC); stored per-entity facts | existing `ClarionClient`, extended with a linkage read | hash-compared → FRESH/STALE |
| **Filigree** (opt-in) | bound + recent-touching tickets | new dep-free urllib client → `GET /api/entity-associations?entity_id=…` | `content_hash_at_attach` → DRIFT flag |
| **git** | last N commits touching the entity's line span | shell `git log -L <span>:<path>` | live |

New units, each one responsibility:

- `core/dossier.py` — the assembler + the `EntityDossier` envelope dataclass.
- `core/freshness.py` (or extend the SP9 helper) — the per-section freshness
  verdict (`FRESH` / `STALE` / `DRIFT` / `unavailable`) given an entity's current
  content hash.
- `clarion/client.py` — **extend** with a `linkages(entity_id)` read (new Clarion
  contract; see §9).
- `filigree/dossier_client.py` — **new**, small, dep-free; reads entity
  associations. (Wardline's Filigree integration is read-only here; it does not
  pull in any Filigree package.)
- `core/git_history.py` — **new**; a thin, fail-soft `git log -L` wrapper.
- `cli/main.py` — a `dossier` command; `mcp/server.py` — a `dossier` tool and a
  `traverse` tool.

The assembler owns the join and the envelope; each source module owns exactly one
fetch and knows nothing about the others.

---

## 5. The dossier envelope

A frozen dataclass, JSON-serialisable, token-bounded by default (summaries, not
source). Every non-`self` section carries a freshness verdict — this is the
"no false-green for agents" property made concrete.

```
EntityDossier(entity, drill=[...]) →
  identity   : entity_id?, qualname, kind, path, line_span, content_hash, freshness
  shape      : signature, decorators (trust semantics RESOLVED, not raw text)
  trust   ←self : declared FunctionTaint(body,returns), actual return,
                  gate verdict, active_findings[ {rule, severity, message} ],
                  taint_chain  (present only when drill=["chain"])          [FRESH]
  linkages←C  : callers[], callees[], scc_peers[]                  [FRESH|STALE|unavailable]
  history ←git: last N commits { sha, date, author, subject }     [live|unavailable]
  work    ←F  : tickets { id, status, priority, title, drift? }   [FRESH|DRIFT|unavailable]
  synthesis  : the actionable join — fix locus, responsible boundary, who's on it
  provenance : per-section { source, freshness, hash_checked_against }
```

### 5.1 `synthesis` — the leap from retrieval to mastery

`synthesis` is what makes this a dossier and not a fact dump. It joins Wardline's
*should-be* (trust policy) against Clarion's *is* (structure) against Filigree's
*who's-on-it* (work) and pre-computes the next move. Example:

> "Untrusted data reaches `build_record` (PY-WL-101). The boundary that should
> validate it is `validate_order`, 2 hops up the call graph; it is
> `@trust_boundary` with no rejection path (PY-WL-102). Filigree #123 is open on
> it (P1). Last touched 3 commits ago by `abc123`."

`synthesis` is best-effort and **degrades with its inputs**: with no Clarion it
omits the call-graph locus; with no Filigree it omits the ticket. It never
asserts a join it could not compute.

### 5.2 Token discipline

Default envelope is compact: counts and summaries, not bodies. `drill=[...]`
expands a named section (`"chain"` adds the N-hop taint chain; `"history"` adds
more commits; `"linkages"` adds full lists). The envelope is **elision-honest**:
when it truncates a list it reports the total and the count shown, so the agent
knows something was dropped. (See §10 for the budget-aware North Star form.)

---

## 6. Freshness contract

The contract extends SP9's never-serve-stale gate from taint facts to the whole
envelope.

**Granularity (v1):** freshness is checked against the SP9 **whole-file** blake3
hash, not a per-entity span hash. This is deliberately conservative — any edit
anywhere in the file marks the entity's Clarion/Filigree-sourced facts `STALE` /
`DRIFT`, even if the entity's own lines did not change. That over-flags rather
than under-flags, which is the safe direction (a spurious `STALE` costs a
re-derive; a missed one is a false-green). Entity-span hashing is a precision
refinement, not a v1 requirement.

Given the entity's current whole-file content hash:

- **self / trust** — computed *now* by re-scanning, so `FRESH` by construction.
  This is the deliberate "re-derive cheap" half: Wardline never serves a stale
  verdict because re-deriving one is cheap.
- **Clarion stored facts** — compare the fact's write-time content hash against
  the current hash → `FRESH` or `STALE`. A `STALE` fact is still returned (the
  agent may want it) but labelled, with the stale hash in `provenance`.
- **Filigree associations** — compare `content_hash_at_attach` (ADR-029) against
  current → `DRIFT`. A drifted association means the issue was bound to a
  prior version of the entity; surfaced, never silently trusted.
- **linkages** — `FRESH` when read live from a current Clarion index; `STALE` if
  Clarion reports its index predates the current hash.

**Invariant (tested):** no section is ever returned with stale data and a
missing-or-FRESH verdict. Staleness is always explicit.

---

## 7. Verbs

### 7.1 `dossier(entity, drill=[...])`

Returns one `EntityDossier`. `entity` is a qualname (resolved to an `entity_id`
via Clarion when available). `drill` expands named sections.

### 7.2 `traverse(entity, edge, depth, max_nodes)`

Pivots along one typed edge and returns a compact dossier per visited node:

- `edge ∈ {callers, callees, taint_contributors}` — `taint_contributors` walks
  the same N-hop chain `explain_taint` produces.
- Bounded by `depth` and `max_nodes`; **elision-honest** — when the frontier is
  truncated it returns a `truncated: {at, total_seen}` marker rather than
  silently stopping (silent caps read as "covered everything" when they did not).

Both verbs are read-only in v1.

---

## 8. Degradation and error model

### 8.1 Fail-soft degradation (a tenet, not a cut)

The dossier never fails wholesale because an optional source is down:

- **No Clarion configured / unreachable** → `linkages` and Clarion stored-fact
  sections return `unavailable` (with a reason); `identity.entity_id` is `None`
  and the join falls back to qualname-only. `trust`, `shape`, `history` still
  work.
- **No Filigree configured / unreachable** → `work: unavailable`.
- **Not a git repository** → `history: unavailable`.

This mirrors SP9's fail-soft MCP behaviour (`explain` survives a Clarion outage
by falling back). Each absent section is labelled; the agent always knows what it
got and what it did not.

### 8.2 Errors

Reuse Wardline's split error model:

- **Tool-execution** faults (entity not found in the scanned set, parse error on
  the entity's module) → a result payload the agent sees (`{isError, content}` /
  CLI exit 2).
- **Protocol** faults (bad args, unknown drill key) → JSON-RPC error.
- **Optional-source** faults (Clarion/Filigree unreachable, git absent) → soft;
  the corresponding section is `unavailable`, the call succeeds.

### 8.3 Relationship to `explain_taint`

`explain_taint` stays as the focused taint-chain tool. `dossier` is the superset
context call and reuses the same `core` explain functions for its `trust` /
`taint_chain` section — there is one implementation of taint explanation, called
from two surfaces.

---

## 9. Contracts required from Clarion and Filigree

This spec is buildable from the Wardline repo, but two sections depend on read
contracts from the sibling tools. Where a contract is missing, that section
simply degrades to `unavailable` (§8.1) until the sibling ships it.

- **Filigree (exists):** `GET /api/entity-associations?entity_id=…` (ADR-029)
  returns bound issues; association rows carry `content_hash_at_attach` for the
  DRIFT check. No Filigree change required for v1.
- **Clarion (partial):** entity resolution and stored-fact reads exist. The
  **linkages** read (callers/callees/SCC peers for an `entity_id`, with the
  index's current content hash for the freshness check) is the one new contract
  this design needs from Clarion. Until it lands, `linkages` is `unavailable`
  and the rest of the dossier is unaffected.

The implementation plan must record the Clarion-linkages contract as an external
dependency, not a Wardline task.

---

## 10. Best version (North Star)

v1 is a deliberate subset of a larger idea. The cuts below are scope decisions,
not the ceiling of the design — captured here so the vision survives the
tradeoff.

| Capability | Best version | v1 | Why cut |
|---|---|---|---|
| Read envelope | full `dossier` | ✅ full | — |
| Pivot | unbounded, budget-aware typed graph walk | ✅ bounded `traverse` | unbounded walking is a query-planning problem |
| History | Clarion **rename-following** history + **temporal posture-diff** ("trust flipped clean→PY-WL-101 at `abc123` when the `@trust_boundary` was deleted") | `git log -L` last-N | posture-diff needs derived facts at past commits (expensive) or Clarion fact-history |
| Worklists | `find(predicate)` across all three tools ("every `@trusted` producer with an open P1 and a non-FRESH taint fact and churn in the last 5 commits") | ✗ | needs a cross-tool predicate/query planner — its own spec |
| Write-back | entity-keyed `bind_ticket` / `waive` / `annotate`, so an agent's work leaves a durable typed trace the next dossier reflects | ✗ (read-only) | closing the loop is separable from reading it |
| Token discipline | `drill` becomes a **budget contract** — the agent states a token budget; the envelope ranks sections and fills to budget | ✅ drill + elision honesty | budget-ranking is an optimisation over the honest-elision base |
| Freshness | re-derive cheap, flag dear | ✅ full | — |

### 10.1 The North Star in one sentence

> The human dream is a window into a function; the Loom dossier is a queryable,
> freshness-honest, write-back-able model of the whole codebase's trust-and-work
> state, with the entity as the universal join key — read in one call, pivoted
> cheaply, and acted on without ever reading the source.

The two North Star verbs (`find`, write-back) each warrant their own spec; this
one ships the read substrate they will build on.

---

## 11. Testing strategy

- **Unit (assembler):** fake Clarion/Filigree/git sources via the existing
  `ClarionClient.Transport` seam and injected source callables. Pin the envelope
  shape, the `synthesis` join, and token/elision honesty.
- **Unit (freshness):** every verdict path — FRESH (re-derived), STALE (Clarion
  hash mismatch), DRIFT (Filigree attach-hash mismatch), unavailable. Assert the
  tested invariant from §6 (no stale-without-label).
- **Unit (degradation matrix):** each optional source absent in turn; assert the
  call succeeds and the right sections read `unavailable`.
- **Parity:** CLI `wardline dossier <qualname>` and the MCP `dossier` tool
  produce identical envelopes for the same input (the CLI/MCP tenet).
- **e2e:** a real `clarion serve` (route-capable build, as for `clarion_e2e`) +
  a git-repo fixture → a full dossier round-trip, including a live FRESH→STALE
  transition after an edit. Filigree associations against a live Filigree
  instance (the emitter is already live-verified).

---

## 12. Out of scope (v1)

- `find(predicate)` worklists (North Star §10 — own spec)
- write-back verbs (North Star §10 — own spec)
- temporal posture-diff and rename-following history (North Star §10)
- any change to the taint engine, lattice, rules, or trust vocabulary
- making Clarion or Filigree a hard dependency of Wardline (both stay opt-in)

---

## 13. Result

One verb gives an agent what previously took reading a hundred lines across
several files and three tools: a function's trust posture, its decorators, its
linkages, its recent history, and the open work that touches it — joined on a
single entity identity, every fact stamped with an explicit freshness verdict,
and the whole thing degrading gracefully to whatever sources are present. It is
the read substrate for codebase mastery; the worklist and write-back verbs that
turn reading into acting are specified separately and build on it.
