# Wardline → Clarion: Taint-Store Requirements (SP9)

**From:** Wardline maintainer (John, with Claude)
**To:** Clarion maintainers
**Date:** 2026-05-30
**Status:** Requirements / ask — awaiting Clarion confirmation before Wardline-side SP9 work begins
**Relates to:** Round-1 integration brief
(`docs/integration/2026-05-29-wardline-loom-integration-brief.md`), ADR-018
(identity reconciliation), ADR-029 (entity associations), the schema-reserved
Clarion `wardline_json` column.

---

## 1. What this document is

Wardline's SP8 shipped a native MCP server whose `explain_taint` tool answers
"where did the untrusted data at this sink come from?" Today it answers by
**re-running the (incremental, cached, deterministic) analysis** against current
disk and projecting the result — stateless by design, correct, but it pays the
analysis cost on every call.

SP9's goal is to make `explain_taint` (and two deferred features —
**overlay-scan** and the **full N-hop taint chain**) into **queries against a
persistent taint/provenance graph that Clarion stores**, keyed by Clarion
entity. Wardline computes the taint facts during `scan` and writes them to
Clarion; later reads become graph lookups instead of re-analysis.

This requires Clarion-side capability that **does not exist yet** (the brief
records the `wardline_json` column as schema-reserved and all-`None`, with the
reconciliation consumer deferred to Clarion v0.2). This document specifies
exactly what Wardline needs Clarion to provide. **Wardline-side SP9
implementation is blocked until these land**; once they do, Wardline writes its
own SP9 implementation spec + plan against this contract.

The deliverable here is a *contract*, not a Wardline design. Where a choice is
genuinely Clarion's to make, it is flagged **Decision requested**; Wardline
states its recommendation so Clarion can confirm or route back (the Round-1
pattern).

---

## 2. Reconciling the "ADR-029 seam" framing

The SP8 design penciled SP9 in as "persist the taint graph into Clarion *via the
ADR-029 entity-association seam*." On closer reading that seam is the wrong fit,
and we want to be explicit about why so the ask is clean:

- **ADR-029 binds a _Filigree issue_ to an opaque entity ID** with
  `content_hash_at_attach` drift detection. It is an issue↔entity reverse-lookup
  index owned by Filigree. It is not a per-symbol fact store and it does not live
  in Clarion.
- **What SP9 needs is a _Clarion-native, per-entity_ store** — a place to put a
  Wardline-owned `wardline_json` blob keyed by Clarion `EntityId`, readable back
  cheaply. That is the schema-reserved `wardline_json` column the brief already
  anticipated, plus an API around it.

So the ask below is for a **Clarion per-entity taint-fact store**, *not* an
ADR-029 binding. (ADR-029 remains relevant to a *different, adjacent* feature —
binding Filigree issues created from Wardline findings to Clarion entities — and
is explicitly out of scope here; see §9.)

---

## 3. The data Wardline owns and wants to persist

Wardline's analyzer produces, per function (the entity granularity — functions
and methods, keyed by the dotted `module.qualified_name` already agreed in
Round 1), a small set of taint facts. The load-bearing ones for `explain_taint`
and the chain are:

| Field | Meaning | Source in the engine |
|---|---|---|
| `declared_return` | trust tier the function declares it returns (anchored) | `project_return_taints` |
| `actual_return` | least-trusted tier actually returned | `function_return_taints` |
| `body_taint` | the function's body/anchored taint | `project_taints` |
| `source` | how the taint was determined: `anchored` / `module_default` / `minimum_scope` / `callgraph` / `fallback` | `TaintProvenance.source` |
| `contributing_callee_qualname` | the callee that introduced the least-trusted return — **the chain edge** | `function_return_callee` (SP8) |
| `resolved_call_count` / `unresolved_call_count` | call-resolution counts at this node | `TaintProvenance` |

Trust tiers are one of the eight `TaintState` values: `INTEGRAL`, `ASSURED`,
`GUARDED`, `UNKNOWN_ASSURED`, `UNKNOWN_GUARDED`, `EXTERNAL_RAW`, `UNKNOWN_RAW`,
`MIXED_RAW`.

**The chain is a single-successor walk.** Each function has exactly one
`contributing_callee_qualname` for its worst return path (or `null` at a
boundary/leaf). So the "full N-hop chain" is: from the sink entity, follow
`contributing_callee_qualname` → resolve that qualname to an entity → fetch its
fact → repeat until the field is `null` (the originating boundary). **Wardline
walks this client-side**; Clarion never has to understand or parse the chain.
This keeps `wardline_json` opaque to Clarion (the federation principle — exactly
as ADR-029's `entity_id` is opaque to Filigree).

---

## 4. Asks for Clarion (the API contract)

All five capabilities below are needed for the first cut. Each names a proposed
shape; treat the shapes as a starting point, the *capability* as the
requirement.

### A. Entity resolution — qualname → EntityId (batch)

Wardline speaks in dotted qualnames; Clarion owns `EntityId`s. Wardline needs to
resolve a batch of qualnames to entity IDs (to address writes and reads).

> **Proposed:** `POST /api/wardline/resolve` `{ "project": <id>, "qualnames": ["auth.tokens.TokenManager.issue", ...] }`
> → `{ "resolved": { "<qualname>": "<entity_id>" }, "unresolved": ["<qualname>", ...] }`

Round 1 already settled the reconciliation key (pre-composed dotted
`module.qualified_name`, byte-faithful to `module_dotted_name()` +
`__qualname__`, with the shared conformance corpus). This ask is just: **expose
that reconciliation as a callable resolve endpoint**, batch-friendly, returning
unresolved qualnames explicitly (so Wardline can fall back rather than guess).

**Decision requested:** is `EntityId`-addressing required for B/C below, or will
Clarion accept the qualname directly as the key (resolving internally)? Wardline
slightly prefers qualname-keyed writes/reads (one fewer round-trip), with resolve
available for the cases that need the stable ID.

### B. Per-entity taint-fact upsert (batch, scan-scoped, replace semantics)

A `wardline scan` produces a whole-program snapshot. Wardline needs to write the
batch and have it replace the prior snapshot consistently.

> **Proposed:** `POST /api/wardline/taint-facts`
> ```json
> {
>   "project": "<id>",
>   "scan_id": "<opaque run id Wardline supplies>",
>   "facts": [
>     { "qualname": "auth.tokens.read_raw",
>       "wardline_json": { ...Wardline-owned blob, see §5... } },
>     ...
>   ]
> }
> ```
> → `{ "written": <n>, "unresolved_qualnames": [...] }`

Requirements:
- **Upsert / replace per entity** (idempotent): re-writing the same entity
  overwrites; re-running an identical scan is a no-op-equivalent.
- **`wardline_json` is stored verbatim and treated as opaque** — Clarion must not
  parse, validate, or depend on its contents (Wardline versions it; §5).
- **Batch** — a project can have thousands of functions; per-entity HTTP calls
  won't scale.
- **Atomic-enough**: a partially-applied batch must not leave a fact set that
  mixes two scans for the *same* entity. Per-entity replace is sufficient;
  whole-batch transactionality is nice-to-have, not required.

**Decision requested:** does Clarion want a `scan_id` / generation marker stored
alongside each fact (so a later "prune everything not from scan N" is possible),
or is per-entity replace + the §E lifecycle rule enough? Wardline proposes
storing `scan_id` for observability but relying on §E for correctness.

### C. Per-entity taint-fact fetch (single + batch)

The read path that turns `explain_taint`/chain-walk into queries.

> **Proposed:**
> `GET /api/wardline/taint-facts?project=<id>&qualname=<q>` (single), and
> `POST /api/wardline/taint-facts/batch-get` `{ "project": <id>, "qualnames": [...] }`
> → per entity: `{ "qualname", "wardline_json", "current_content_hash", "exists": bool }`

The **batch-get is essential** for the chain walk: Wardline collects the chain's
qualnames and fetches them in one or few round-trips rather than N. The response
must include the entity's **current content hash** (see D) so Wardline can decide
freshness without reading any source.

### D. Freshness / staleness — the contract that makes this safe

This is the crux. A stored taint fact was computed against a specific source
state; the file may have changed since. SP8's `explain_taint` guarantees it
**never serves taint computed against drifted code**. The Clarion-backed path
must preserve that guarantee, cheaply.

Clarion already re-indexes code on change and (per ADR-029) tracks a content hash
per entity. The contract:

- Wardline stamps each fact with `content_hash_at_compute` *inside* `wardline_json`.
- On fetch (C), Clarion returns the entity's **`current_content_hash`** (computed
  by Clarion's indexer, by the agreed definition below).
- Wardline compares the two. Match → the fact is fresh, serve it. Mismatch (or
  entity absent) → **stale**: Wardline falls back to the SP8 re-run for that
  entity/scan and re-writes the fact. Clarion never serves a "fresh" verdict
  Wardline didn't earn.

The win: staleness becomes a metadata compare, **not** a disk read or
re-analysis — that is the entire point of SP9 over SP8.

> **Decision requested (the most important one):** the content-hash *definition*
> must be identical on both sides. Wardline proposes **sha256 of the entity's
> containing file** (whole-file), normalized to LF, hex-encoded — file-granular,
> simple, matches per-file indexing, conservatively re-stales all of a file's
> functions on any edit. Entity-AST-span hashing is more precise but requires both
> tools to agree on span boundaries (fragile); we propose deferring it. **Please
> confirm the hash algorithm + span, and that Clarion can return it per entity on
> fetch.** If Clarion already exposes a content hash with a different definition,
> tell us and Wardline will adopt yours as the single source of truth (as we did
> with `module_dotted_name()`).

### E. Lifecycle — deleted / renamed entities

When code is deleted or a function is renamed, its qualname disappears or
changes. The store must not keep serving facts for entities that no longer exist.

> **Proposed:** Clarion, which owns entity lifecycle (it indexes the code),
> **invalidates/removes a taint fact when its entity is deleted or its qualname
> changes** (cascade off the entity it's keyed to). A renamed function is a new
> qualname → a fetch returns `exists: false` → Wardline treats it as stale and
> recomputes.

**Decision requested:** can Clarion cascade taint-fact removal off entity
deletion/rename, or should Wardline prune explicitly on each scan (e.g. a
"delete facts not in scan N" call)? Wardline prefers Clarion-cascade (Clarion is
the authority on entity existence) but will implement scan-scoped pruning if
that's the cleaner Clarion-side contract.

### F. Transport

Wardline's core is **zero-dependency** and its existing Filigree emitter speaks
HTTP over the **standard library** (`urllib`, no SDK) — the same discipline as
the SP5 judge. SP9 will keep that.

> **Proposed:** the four endpoints above are plain HTTP+JSON, reachable the same
> way the Filigree emitter reaches Filigree (a `--clarion-url` analog), so
> Wardline can call them with stdlib `urllib`. No client SDK, no new dependency.

**Decision requested:** does Clarion expose (or will it expose) an HTTP+JSON API
surface for these, mirroring Filigree's `/api/loom/scan-results`? If Clarion is
local-library-only (in-process), say so and we'll design a thin adapter — but
HTTP keeps Wardline decoupled and dep-free, which we strongly prefer.

### G. Project isolation

Wardline is rooted at a project; SP8 hardened path/`source_roots` confinement to
that root. The store must be **per-project isolated** (a taint fact written for
project A is never served for project B). Round-1 noted Filigree isolates by DB
file; please confirm Clarion's store is similarly project-scoped and that the
`project` key above is the right handle.

---

## 5. The `wardline_json` schema (Wardline-owned, opaque to Clarion)

Wardline owns and versions this blob exactly as it owns its fingerprint and its
NG-25 descriptor. Clarion stores and returns it verbatim. **v1 proposed shape:**

```json
{
  "schema_version": "wardline-taint-1",
  "qualname": "auth.tokens.TokenManager.issue",
  "content_hash_at_compute": "<sha256-hex of the entity's file, LF-normalized>",
  "scan_id": "<opaque run id>",
  "computed_at": "<ISO-8601 UTC>",
  "taint": {
    "declared_return": "INTEGRAL",
    "actual_return": "EXTERNAL_RAW",
    "body_taint": "EXTERNAL_RAW",
    "source": "anchored",
    "contributing_callee_qualname": "auth.tokens.read_raw",
    "resolved_call_count": 3,
    "unresolved_call_count": 0
  },
  "findings": [
    { "rule_id": "PY-WL-101", "fingerprint": "<64-hex>", "line_start": 7 }
  ]
}
```

- `taint.*` is the per-entity slice `explain_taint` projects today.
- `taint.contributing_callee_qualname` is the chain edge Wardline follows
  (`null` at a boundary/leaf).
- `findings[]` is optional and lets a finding's fingerprint be looked up to its
  anchoring entity (supports `explain_taint(fingerprint)` without a scan).
- `schema_version` lets Wardline evolve the blob without a Clarion change.

**Contract:** Clarion treats this as an opaque string/JSON blob — no parsing, no
validation, no schema coupling. If a future Wardline emits `wardline-taint-2`,
Clarion needs no change.

---

## 6. What Wardline guarantees in return

- **Standalone degradation (Loom charter).** Wardline boots and runs without
  Clarion. Clarion-backed `explain_taint` is the *optimized* path; the SP8
  stateless re-run remains the fallback whenever Clarion is absent, unreachable,
  or returns stale. The integration is purely additive — no runtime dependency.
- **Opaque, versioned blob.** Wardline never asks Clarion to understand
  `wardline_json`; the schema is Wardline's to evolve behind `schema_version`.
- **Idempotent, batch-friendly writes.** Re-running an identical scan is
  effectively a no-op; writes are per-entity replace.
- **Qualname conformance already established.** Wardline emits the dotted
  `module.qualified_name` byte-faithfully (Round 1 + the shared conformance
  corpus); SP9 adds no new identity surface.
- **Wardline owns staleness.** Clarion supplies the current content hash;
  Wardline makes the fresh/stale decision and never serves drifted taint.

---

## 7. Decisions requested from Clarion (summary)

| # | Decision | Wardline's recommendation |
|---|---|---|
| 1 | Key writes/reads by `EntityId` or accept qualname directly? | Qualname-keyed (resolve available for when the stable ID is needed) |
| 2 | Store `scan_id`/generation per fact? | Yes, for observability; rely on §E lifecycle for correctness |
| 3 | **Content-hash definition (algorithm + span) and per-entity exposure on fetch** | sha256 of the entity's file, LF-normalized; adopt Clarion's if one already exists |
| 4 | Lifecycle: Clarion cascades fact removal on entity delete/rename, or Wardline prunes per scan? | Clarion-cascade (Clarion is the authority on entity existence) |
| 5 | HTTP+JSON API surface (mirroring Filigree's), or local-only? | HTTP+JSON, stdlib-`urllib`-callable, `--clarion-url` analog |
| 6 | Confirm per-project store isolation + the `project` handle | Per-project isolation, `project` key as shown |
| 7 | Timeline: when can the `wardline_json` consumer + these endpoints land? | — (drives Wardline SP9 scheduling) |

---

## 8. Dependency & sequencing

1. **This contract lands first** (Clarion confirms §7, implements A–G).
2. Then Wardline writes its **own SP9 implementation spec + plan** against the
   confirmed contract: the `wardline scan` write path, the `explain_taint`
   query path with SP8 re-run fallback, the chain walk, and (subsequently) the
   overlay-scan and full N-hop chain features the store unlocks.
3. The shared **qualname conformance corpus** (Round 1) is reused as-is; if
   Clarion ships the resolve endpoint (§A), a CI cross-check of corpus vs the
   live resolver is a cheap addition.

Wardline does **not** implement against an unconfirmed contract — this avoids the
release-timeline coupling the Loom charter warns about. Once Clarion confirms,
the Wardline side is a few well-scoped tasks (it already computes every fact in
§3; SP9 is plumbing them to/from Clarion plus the freshness compare).

---

## 9. Non-goals (this round)

- **ADR-029 issue↔entity bindings.** Binding Filigree *issues* created from
  Wardline findings to Clarion entities is a separate, adjacent feature; not part
  of the taint-store ask.
- **Overlay-scan and the full N-hop chain as shipped features.** The store is
  *designed to back* them cheaply, but they get their own Wardline specs once the
  store exists. This round only asks for the store + freshness contract.
- **Clarion parsing `wardline_json`.** Deliberately excluded — the blob stays
  opaque; all taint semantics (including the chain walk) stay Wardline-side.
- **Replacing the SP8 stateless re-run.** It remains the standalone fallback
  forever; SP9 is an optimization layered on top, never a hard dependency.

---

*Wardline will hold SP9 implementation until Clarion confirms §7 and the A–G
endpoints land. Route-backs welcome on any proposed shape — the capability is the
requirement, the shapes are a starting point.*
