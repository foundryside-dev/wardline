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
   (`docs/superpowers/specs/archive/2026-05-31-wardline-sp9-clarion-taint-store-design.md`).
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
- `core/history.py` — **new**; a `HistoryProvider` seam plus the v1
  `GitLogHistoryProvider` (a thin, fail-soft `git log -L` wrapper). See §5.3.
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

### 5.3 The `history` source is a seam, not a hardwired git shell

The `history` section is read through a `HistoryProvider` interface, the same way
L1 seeding reads through `TaintSourceProvider` and the Clarion client reads
through `Transport`:

```python
class HistoryProvider(Protocol):
    def history(self, entity: EntityRef, *, limit: int) -> HistorySection | None: ...
```

v1 ships exactly one implementation, `GitLogHistoryProvider` (shells `git log -L`,
fail-soft to `unavailable`). The seam exists because history is the natural plug
point for the planned **opt-in governance plugin** (the fourth Loom tool): an
audit-grade `GovernanceHistoryProvider` could later supply sign-offs, control
mappings, freshness binding, and rename-following history **without re-opening
this spec**. This also makes the §10 "rich history / temporal posture-diff"
North Star a matter of supplying a richer provider, not reworking the dossier.

Defining the seam now costs ~nothing (it is the codebase's standard provider
pattern); committing to *build* a second provider is explicitly out of scope
(§12).

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

### 6.1 ORPHAN — the failure mode content-hashing cannot catch

Freshness above assumes the entity's **identity is stable** and only its
*content* changed. But Clarion's `entity_id` (`{plugin_id}:{kind}:{qualname}`)
is **not refactor-stable**: renaming or moving a function changes its ID. When
that happens, Wardline facts and Filigree associations keyed on the *old* ID are
not stale — they are **orphaned**: the old ID has facts but no live entity, and
the new entity has no facts. A content-hash check never fires, because the new
entity was never hashed against anything.

v1 cannot *fix* this (the fix is a stable identity in Clarion — §10, and it is
the single highest-leverage Loom investment). v1 must, however, be **honest about
it** rather than silently returning an empty `work`/facts section as if the
entity were clean:

- when `resolve(qualname)` yields an `entity_id` that has **no** stored facts and
  **no** associations, the dossier marks those sections `UNKNOWN` (not `FRESH`,
  not "clean") — "no facts found; this may be a fresh entity or an orphaned
  rename," consistent with the project's fail-closed, no-false-green ethos;
- `provenance` records the resolved ID so a caller (or a later stable-identity
  layer) can reconcile.

ORPHAN is called out here as a known, bounded limitation, not silently inherited.

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

All three tools share one author, so these are **internal, cross-repo roadmap
items we sequence ourselves** — not third-party dependencies we wait on. The
fail-soft degradation (§8.1) is the safety net for *ordering* (a section is
`unavailable` until its contract lands), not a permanent gap; the Loom roadmap
should land the Clarion-side read in step so `linkages` is not dark on day one.

- **Filigree (exists, frozen):** `GET /api/entity-associations?entity_id=…`
  (ADR-029) returns bound-issue rows `{issue_id, clarion_entity_id,
  content_hash_at_attach, attached_at, attached_by}`. Filigree is **done/frozen**
  (v2.3.0; contract changes need an ADR + 12-month deprecation) and
  **deliberately computes no drift** — the consumer does. So the dossier
  assembler **is** that consumer: it reads the row as-is and compares
  `content_hash_at_attach` against the current entity hash to set the `work`
  section's DRIFT verdict. No Filigree change required, and none is possible
  on this timescale — consume it exactly as served.
- **Clarion (the real gap — bigger than first written):** entity resolution
  (`resolve`) and stored taint-fact reads exist over HTTP. **Linkages do not.**
  Callers/callees/neighborhood exist in Clarion **only over MCP**
  (`callers_of` / `neighborhood` / `orientation_pack`); the HTTP read API
  (`http_read.rs`) serves only file-resolve, Wardline taint facts, and
  `_capabilities`. Wardline's `ClarionClient` is HTTP-only, so the dossier's
  `linkages` section is `unavailable` until **either** Clarion exposes
  linkages over HTTP **or** the assembler grows a Clarion-MCP client path. This
  is a real cross-repo build item, not a thin read.

The implementation plan must record the Clarion-linkages exposure as a cross-repo
Loom item (decide HTTP-route-vs-MCP-client up front), not silently assume it.
`linkages` (and `synthesis`'s call-graph locus) degrade to `unavailable` until it
lands; everything else ships without it.

---

## 10. Best version (North Star)

v1 is a deliberate subset of a larger idea. The cuts below are scope decisions,
not the ceiling of the design — captured here so the vision survives the
tradeoff.

| Capability | Best version | v1 | Why cut |
|---|---|---|---|
| Read envelope | full `dossier` | ✅ full | — |
| Pivot | unbounded, budget-aware typed graph walk | ✅ bounded `traverse` | unbounded walking is a query-planning problem |
| History | audit-grade `HistoryProvider` (governance plugin): rename-following, **temporal posture-diff** ("trust flipped clean→PY-WL-101 at `abc123` when the `@trust_boundary` was deleted"), sign-offs, control mappings | `GitLogHistoryProvider` (last-N via `git log -L`) | a provider swap behind the §5.3 seam, not a dossier rework; the richer provider is the governance plugin's job |
| Worklists | `find(predicate)` across all three tools ("every `@trusted` producer with an open P1 and a non-FRESH taint fact and churn in the last 5 commits") | ✗ | needs a cross-tool predicate/query planner — its own spec |
| Write-back | entity-keyed `bind_ticket` / `waive` / `annotate`, so an agent's work leaves a durable typed trace the next dossier reflects | ✗ (read-only) | closing the loop is separable from reading it |
| Token discipline | `drill` becomes a **budget contract** — the agent states a token budget; the envelope ranks sections and fills to budget | ✅ drill + elision honesty | budget-ranking is an optimisation over the honest-elision base |
| Freshness | re-derive cheap, flag dear | ✅ full (STALE/DRIFT) | ORPHAN labelled, not fixed (§6.1) |
| Entity identity | **refactor-stable** Clarion identity that survives rename/move, so facts/associations are never orphaned | qualname + whole-file hash (today's Clarion reality) | the keystone; its own Clarion work (§10.2) |

### 10.1 The North Star in one sentence

> The human dream is a window into a function; the Loom dossier is a queryable,
> freshness-honest, write-back-able model of the whole codebase's trust-and-work
> state, with the entity as the universal join key — read in one call, pivoted
> cheaply, and acted on without ever reading the source.

The two North Star verbs (`find`, write-back) each warrant their own spec; this
one ships the read substrate they will build on.

### 10.2 The keystone: a refactor-stable entity identity (and the salvage)

Every cross-tool binding in Loom hangs off entity identity — Wardline facts,
Filigree associations (ADR-029), and tomorrow's governance attestations. Today
that identity is **not refactor-stable** (Clarion derives it from name + module
path), so a rename silently orphans every binding (§6.1). This is the single
highest-leverage investment in the suite, and the dossier's ORPHAN handling is a
symptom-level mitigation, not the cure.

There is prior art to salvage, not reinvent. The suite once specified a richer
cross-tool standard — the **Loom URI** scheme (`loom://component/kind/id` +
`/api/loom/multi-fetch` + a federation registry) — which was **never implemented**
and was superseded by the simpler, shipped **ADR-029 entity-associations**. The
lesson is precise: the *registry / multi-fetch / URI-grammar apparatus* was
over-built and rightly dropped, but the **stable, content-addressed identity**
it was reaching for is exactly what is still missing. The right next step is the
*minimal* salvage — a refactor-stable identity primitive in Clarion (structural
fingerprint + rename tracking) plus the thin shared "fact envelope" all
producers already approximate — **not** a revival of the full URI/registry
machinery that killed the original effort by being too heavy to ship.

This is Clarion-side work and its own design; the dossier is specified to be
honest while it is missing (ORPHAN/UNKNOWN), and to get strictly better the day
it lands — with no change to this spec.

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
- any `HistoryProvider` beyond `GitLogHistoryProvider` — the seam is defined
  (§5.3) but the audit-grade provider is the governance plugin's scope, not this
  spec's (North Star §10)
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
