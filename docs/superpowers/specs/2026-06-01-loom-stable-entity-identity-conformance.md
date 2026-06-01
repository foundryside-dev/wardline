# Loom — Stable Entity Identity (SEI) conformance standard (design)

**Date:** 2026-06-01  
**Status:** Canonical direction, **DRAFT — not yet locked.** SEI is the agreed
single track every subsystem converges on; its precise shape is **open for
per-subsystem requirements until lock** (see §0.3). Implementation that commits a
subsystem to a specific SEI shape waits for lock; shape-independent groundwork
(e.g. Clarion prior-index retention, §3.1) may start now.  
**Authority:** Suite-wide standard. Clarion is the identity **authority/implementer**;
Wardline, Filigree, and the planned `legis` subsystem are **consumers** that
conform. This document lives in the Wardline specs tree for now; propagate the
normative sections into `clarion/docs/federation/` and `filigree/docs/federation/`.

**SEI is the gold standard for the suite.** All four subsystems **must** conform
to it — **no matter how close any of them feels to it today.** Conformance is
**demonstrated** via the §8 oracle, never **assumed** from apparent
compatibility, and no subsystem is grandfathered (see §0.1).

**Scope:** Give Loom a **refactor-stable entity identity** so that a function's
cross-tool bindings (Wardline taint facts, Filigree issue associations, `legis`
governance attestations) survive renames and moves instead of being silently
orphaned. This is the keystone primitive the whole suite hangs off.

---

## 0. Why this exists

Verified against `clarion`/`filigree` source on 2026-06-01:

- Clarion's entity id is `{plugin_id}:{kind}:{canonical_qualified_name}`, **derived
  from the name + module path** and upserted on that key. A **rename or
  cross-module move changes the id** — and every Wardline fact and Filigree
  association keyed on the old id is **orphaned** (the old id has facts but no
  live entity; the new entity has none). There is no rename detection, no
  lineage, no surrogate id today (`clarion-storage/src/writer.rs` upsert
  `ON CONFLICT(id)`; ADR-003 explicitly **defers** an `EntityAlias` mechanism).
- Filigree (`done`/frozen, v2.3.0) stores the id as an **opaque string** and
  computes no drift — the consumer does.
- The suite once specified a richer cross-tool standard, the **Loom URI** scheme
  (`loom://…` + a registry + `/api/loom/multi-fetch`); it was **never implemented**
  and was superseded by the simpler ADR-029 entity-associations. Its registry /
  multi-fetch apparatus was over-built and never shipped — but the **stable
  identity** it reached for is exactly what is still missing. SEI is the
  deliberate, product-grade form of that idea, built forward on the suite's
  current robust baseline — learning from the Loom-URI's failure, not salvaging
  it.

The bug, precisely: Loom **conflates identity with address**. The qualname is a
fine *address* and a terrible *identity*, because the operations developers do
most — rename, move — change it. This standard separates the two.

## 0.1 Conformance is proven, not assumed (no grandfathering)

SEI is the suite's gold standard, and every subsystem is held to it **on the same
proven bar** — including ones that feel done (Filigree), the authority itself
(Clarion), and ones not yet built (`legis`). Two rules follow:

- **Demonstrated, not asserted.** A subsystem is conformant only when it **passes
  the §8 conformance oracle**, not because it "looks compatible."
- **Structural compatibility is necessary, not sufficient.** The clearest trap is
  Filigree: it stores an *opaque* id, so it needs no code change (§5) — but that
  makes it *able* to conform, not *conformant*. It is conformant only once it
  actually stores SEIs, the one-time locator→SEI backfill (§7) has run, and it
  passes the oracle. "Already stores an opaque string" is the start of the work,
  not the end of it.

Treat any binding still keyed on a locator as legacy to migrate, regardless of
which subsystem produced it.

## 0.2 Canonical status — this supersedes prior federation identity agreements

The subsystems are currently running on **divergent versions of "the federation
spec."** This document ends that on the identity question. SEI is the **single,
canonical, non-negotiable federation identity interface.** Where any prior
agreement — pairwise or documented — defines or assumes a different entity-identity
model, **this supersedes it**, regardless of what was previously agreed.

**Superseded (on identity only):**
- ADR-003's "the derived `{plugin}:{kind}:{qualname}` *is* the identity" — that
  string is now the **locator** (address), never the identity.
- ADR-018's qualname-reconciliation heuristics *as an identity mechanism* —
  subsumed by the §3 matcher + lineage.
- The abandoned **Loom-URI** addressing scheme — formally closed; SEI is the
  product-grade successor to the idea it reached for (not a revival of it).
- Any per-tool federation-contract clause that keys a cross-tool binding on a
  locator.

**Not superseded (these stand, but now carry an SEI):** the entity-association
API shape (ADR-029), the Wardline taint-fact store routes, and Filigree's frozen
surface keep their transports and payloads unchanged — only the **identity value**
they carry becomes an SEI.

**What is closed vs open:** the *track* is closed — that there is one canonical
identity interface, that it is SEI, and that it supersedes the divergent prior
specs above. The *precise shape* of SEI is **open until lock** (§0.3). "We already
agreed something different" is not grounds to stay on a divergent track; it *is*
legitimate input if it reflects a real, emerging requirement raised before lock.

## 0.3 Status: canonical direction, not yet locked

SEI is the agreed single track — every subsystem abandons its divergent
federation-identity version and converges here. But its **precise shape is not
yet locked.** Each of the four subsystems gets to influence it before lock,
because their requirements are **still emerging** — e.g. `legis`'s
governance/audit needs, Clarion's matcher constraints, Filigree's frozen-surface
limits, Wardline's dossier needs.

**Settled now (not in the input window):**
- that there is **one** canonical identity interface and it is **SEI** (the §0.2
  supersession holds today);
- the **conformance regime that takes effect at lock** — oracle-gated, no
  grandfathering (§0.1).

**Open until lock:** the interface details. The §1 decisions and the
wire/lineage/matcher specifics are the **proposed baseline**; a subsystem may
contest a detail by bringing a **concrete emerging requirement** — not by
re-litigating a settled trade-off or to stay on its old spec.

**Lock gate:** SEI locks when each of the four subsystems has signed off or
recorded its requirements against this spec, and the §8 conformance oracle
encodes them. After lock, §0.1 and §0.2 apply in full and changes need a
versioned revision. Until then, build only what is **true regardless of the final
shape** (Clarion prior-index retention, §3.1); defer anything that pins a
specific SEI shape.

---

## 0.4 What SEI unlocks — interoperability across the suite

§0 states the problem negatively (bindings orphan). The positive case is what
motivates the whole standard: **SEI is the connective tissue of Loom's
interoperability.** Loom's value is the *matrix* of its tools' combinations — not
their sum — and **every cell in that matrix is a cross-tool binding** that needs a
shared, durable identity to bind on:

| Combination | The binding it depends on | Without SEI |
|---|---|---|
| **Wardline + Clarion** (taint over a mapped codebase — the dossier) | taint facts keyed to the entity | facts orphan on rename/move |
| **Wardline + Filigree** (findings become tracked work) | issue ↔ entity association | association orphans |
| **Clarion + Filigree** (issues bound to live code) | association keyed to the entity | **orphans today** |
| **Wardline + legis** (agent-defined policy enforced at CI) | policy + attestation keyed to the entity | attestation orphans |
| **Clarion + legis** (attestations bound to code) | attestation ↔ entity | attestation orphans |
| **Filigree + legis** (governed issue lifecycle) | governed association | orphans |

The headline: **a combination is only as strong as its weakest binding.** A single
tool keying on a fragile (rename-mutable) locator silently orphans *every*
combination it participates in. SEI makes every binding survive the refactors
developers actually perform, so the matrix **composes** instead of quietly
decaying. This is also why conformance is neither optional nor grandfathered
(§0.1): one non-conformant binding is enough to break a combination for every tool
in it.

> The full operating-model context — agent-first "humans on the loop, not in the
> loop," zero-*human*-config, the agent-programmable extension plane, and `legis`'s
> graded enforcement — lives in `2026-06-01-loom-goal-state-case-study.md` §1.5.
> This section is that model viewed through the **identity** lens: interoperability
> is the payoff; SEI is the primitive that delivers it.

---

## 1. Fixed design decisions (proposed baseline — see §0.3)

Settled during brainstorming; not re-opened here:

1. **Surrogate identity.** Introduce a durable, opaque **SEI** (Stable Entity
   Identity) as the sole key for cross-tool bindings. The existing qualname id
   is demoted to a mutable, resolvable **locator**.
2. **Fail-closed re-binding.** When the matcher cannot *confidently* decide that
   a changed entity is the same one, it **mints a new SEI and records the old as
   orphaned** — it never silently carries an identity (and therefore never
   silently carries a governance attestation) across an unproven match.
3. **Deterministic matcher in v1.** SEI is carried only on high-certainty signals
   (unchanged locator; git-rename + identical body; identical body+signature at a
   new module). Edit-tolerant fuzzy matching is North Star (§8).
4. **Clarion is the authority.** Identity is minted, persisted, re-bound, and
   resolved in one place. Consumers never derive or parse it.
5. **No Loom-URI revival.** No registry, no multi-fetch, no URI grammar — those
   sank the first effort. Just identity.

---

## 2. The model: three separated concepts

| Concept | What it is | Mutability | Role |
|---|---|---|---|
| **SEI** | opaque durable token, e.g. `clarion:eid:<ulid>` | minted once, then **stable** across rename/move/edit | the **identity** — the only key cross-tool bindings use |
| **Locator** | `{plugin_id}:{kind}:{qualname}` (today's id) | **mutable** (changes on rename / module move) | the **address** — human-readable, resolvable to current SEI |
| **content_hash** | the per-entity content hash Clarion already computes (`entities.content_hash`, the entity body) | changes on edit | the **freshness** signal — unchanged role |

SEI is **opaque**: consumers MUST NOT parse it (same discipline as today's
entity id). Its internal form is Clarion's business; `<ulid>` is a suggestion.

> **Hash-granularity note (a pre-existing inconsistency, not introduced here):**
> Filigree's `content_hash_at_attach` snapshots `entities.content_hash` (the
> *entity body* hash — entity-granular), whereas Wardline's SP9 taint-fact
> freshness gate uses `current_file_hash` (the *whole-file* hash —
> file-granular). This standard's matcher (§3) uses the entity body hash for its
> "identical body" test, and the content axis (§2.1) means "the hash the binding
> stored." Harmonising the two freshness granularities suite-wide is adjacent
> work, out of scope here; flagged so it is not silently inherited.

### 2.1 Two orthogonal status axes

Separating identity from content gives every binding a clean two-axis status,
which **subsumes** the ad-hoc `STALE`/`DRIFT`/`ORPHAN` flags previously scattered
in the dossier spec:

| | content FRESH | content STALE |
|---|---|---|
| **SEI alive** | ✅ current | ⚠️ same entity, code changed — re-verify |
| **SEI orphaned** | 🔶 needs human re-bind | 🔶 needs human re-bind |

- *Identity axis* (SEI alive / orphaned) answers **"is this the same entity?"**
- *Content axis* (content_hash fresh / stale) answers **"has its code changed?"**

Both are always surfaced; neither is inferred from the other.

### 2.2 Lineage

Clarion keeps an **append-only lineage log** of SEI events: `born`,
`locator_changed`, `moved`, `orphaned`, `superseded`. Lineage lets a consumer
distinguish ORPHAN from STALE, lets a human reconcile an orphaned binding, and
gives `legis` a ready-made, tamper-evidence-able audit trail for free.

---

## 3. The re-binding matcher (Clarion, on re-index)

Deterministic and fail-closed. For each entity in a new scan, decide its SEI:

1. **Locator still present in the prior index** → carry the same SEI (today's
   trivial upsert case). If `content_hash` changed, emit nothing new for identity
   (the content axis carries the change).
2. **Locator vanished** → the entity may have been renamed/moved. Match it
   against *vanished* prior entities using **high-certainty signals only**:
   - a git-detected rename of the file/symbol **and** a byte-identical body hash
     → carry the SEI (`locator_changed`);
   - **identical body hash and identical signature** at a new module/locator
     → carry the SEI (`moved`).
3. **No confident match** → **fail closed**: mint a new SEI for the new entity
   (`born`), and mark the vanished prior entity `orphaned`. Bindings on the old
   SEI now read ORPHAN; they are never silently re-pointed.

### 3.1 Required Clarion capability: prior-index state

The matcher needs to diff against the previous index. Clarion today is
**wipe-and-rerun and retains no prior snapshot** (`clarion-mcp/src/index_diff.rs`).
So a load-bearing v1 obligation on Clarion is to **retain the prior
SEI↔locator + body-hash + signature map** across re-index runs. Without it,
every re-index would re-mint every SEI (catastrophic orphaning). This is the
single largest Clarion build item in the standard and must be sequenced first.

The signals the matcher needs already exist on the entity row (`content_hash`,
`source_byte_start/end`, `name`/`short_name`, `first_seen_commit`,
`properties`); v1 adds the retained prior map and the git-rename signal (which
may later be sourced from `legis` — see §6).

---

## 4. Wire contract (Clarion's conformance surface)

Identity resolution, exposed over the HTTP read API (consumers are HTTP clients):

- `resolve(locator)` → `{ sei, current_locator, content_hash, alive: true }`,
  or `{ alive: false }` if the locator resolves to nothing.
- `resolve_sei(sei)` → `{ current_locator, content_hash, alive: true }`, or
  `{ alive: false, lineage: [...] }` when the SEI is orphaned/superseded.
- `lineage(sei)` → the ordered event list.
- `_capabilities` advertises `sei: { supported: true, version: N }` so a consumer
  can detect a pre-SEI or non-conformant Clarion and **degrade** rather than
  guess.

SEI is opaque on the wire. Batch variants mirror the existing
`…:batch-get` shape. (Linkage exposure — callers/callees over HTTP — is a
*separate* gap tracked in the dossier spec; it is not part of this standard.)

---

## 5. Conformance obligations (set across the suite)

| Tool | Obligation |
|---|---|
| **Clarion** (authority) | mint + persist SEI; retain prior-index state (§3.1); run the deterministic matcher; fail-closed mint+lineage on ambiguity; serve `resolve` / `resolve_sei` / `lineage`; advertise the `sei` capability + version |
| **Wardline** | key taint facts (and dossier reads) on **SEI**, resolving locator→SEI via Clarion; treat SEI opaque; degrade gracefully when the `sei` capability is absent |
| **Filigree** (frozen) | **no code change, but not auto-conformant** (§0.1) — it already stores an opaque `clarion_entity_id`, so the standard only makes that stored value an SEI going forward, but conformance still requires the locator→SEI backfill (§7) to have run and the §8 oracle to pass. Its `content_hash_at_attach` drift check is unchanged and now cleanly means the **content axis** (STALE); the identity axis (ORPHAN) lives in Clarion's `resolve_sei` |
| **`legis`** (planned 4th subsystem) | governance attestations keyed on **SEI**; consume `lineage` as the audit trail; as the suite's git-interface owner, may *supply* the git-rename signal the matcher consumes (§6) |

The headline result: **Filigree conforms without being unfrozen.** Treating the
id as opaque — what looked like under-specification — is exactly what lets it
adopt a new identity model with zero API change. That property is *why* the
surrogate approach is safe to set across a suite with a frozen member.

---

## 6. Relationship to `legis` and the dossier

- **`legis`** (the planned governance + git-interface subsystem, loosely based on
  the `/home/john/elspeth` plugin/governance architecture) is both an SEI
  *consumer* (attestations key on SEI; lineage is its audit spine) and a
  potential *provider* of the git-rename/history signal the §3 matcher needs.
  v1 sources git-rename detection inside Clarion (shell/libgit2); if/when `legis`
  ships a git interface, that signal can move behind it with no change to the SEI
  model — the matcher consumes "a git-rename signal," not "Clarion's git code."
- **The dossier** (`2026-06-01-wardline-loom-entity-dossier-design.md`) should be
  updated, once this lands, to key its sections on SEI and to replace its §6.1
  ad-hoc ORPHAN handling with the §2.1 two-axis model. Until then the dossier's
  fail-closed UNKNOWN handling is the correct interim.

---

## 7. Migration (one-time)

When Clarion first runs SEI-aware, it mints an SEI for every current entity. A
backfill then resolves every existing Filigree association and Wardline fact from
its stored locator to the corresponding SEI and re-keys it. Locators that no
longer resolve (already-orphaned by a past rename) are **flagged ORPHAN for human
review — never silently dropped**, consistent with the suite's no-false-green
ethos.

---

## 8. Conformance oracle (shared test suite)

"Conformant" must be testable, not asserted. A shared, fixtures-based conformance
suite — mirroring Wardline's existing Clarion-producer conformance and Filigree's
federation §5 audit — that every tool runs against a reference Clarion:

- **identity round-trip + opacity:** mint → `resolve` both directions → consumer
  treats SEI opaque (a test that a consumer never parses it)
- **rename fixture:** rename a function with unchanged body → SEI carried,
  `current_locator` updated, `locator_changed` lineage event
- **move fixture:** move to a new module, body+sig unchanged → SEI carried,
  `moved` event
- **ambiguous fixture:** rename *with* a body edit → **fail closed**: new SEI,
  old `orphaned`, NOT carried
- **delete fixture:** entity removed → `orphaned`, `resolve_sei` returns
  `alive: false` + lineage
- **capability-absent fixture:** Clarion without the `sei` capability → consumers
  degrade (no crash, honest "identity unavailable")

---

## 9. Out of scope (v1) / North Star

| Capability | v1 | North Star |
|---|---|---|
| Identity | surrogate SEI, opaque, durable | — |
| Matcher | deterministic (locator / git-rename+identical-body / identical-body+sig move) | **edit-tolerant fuzzy** matching (carry SEI across rename *with* body edits) above a high similarity threshold, still fail-closed below it |
| Re-bind posture | fail-closed (mint + orphan on ambiguity) | — (posture is permanent) |
| Lineage | `born`/`locator_changed`/`moved`/`orphaned`/`superseded` | richer **split/merge** lineage (one entity → two; two → one) with provenance |
| Git signal | sourced in Clarion | sourced via `legis`'s git interface |

Explicitly **not** in scope, ever, as part of this standard: the Loom-URI scheme,
a federation registry, `/api/loom/multi-fetch`, or cross-language identity
unification. The standard is *identity*, kept minimal on purpose.

---

## 10. Result

Loom gets the primitive every cross-tool binding silently assumed but never had:
an identity that survives the refactors developers actually perform. Bindings
gain a clean two-axis truth (same-entity? / code-changed?), governance gets an
audit-grade lineage spine, and — because Filigree treats the id as opaque and
Clarion already named the `EntityAlias` seam — the standard is adoptable across
the whole suite, including a frozen member, without reviving the over-built
machinery that sank the first attempt.
