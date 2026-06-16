# Wardline → Loomweave: `ResolveRequest` plugin-hint — proposed contract shape

**From:** Wardline engineering
**To:** Loomweave maintainers (federation resolver, ADR-036)
**Date:** 2026-06-11
**Re:** §7 of the Amendments 6–9 changeset letter
(`loomweave docs/federation/2026-06-11-rust-qualname-amendment-6-9-changeset.md`):
the resolver is now plugin-aware (`clarion-69db8b2739`, ADR-036 amended
2026-06-11) and a qualname owned by more than one plugin resolves `Ambiguous`,
which the federation wire degrades to `unresolved`. The agreed disambiguator is
a **plugin-hint field on `ResolveRequest`**. Loomweave asked Wardline to agree
the shape in the same escalation-gated exchange as the 4–9 re-vendor; this is
that agreement, from the consumer side. Loomweave owns the normative resolver
semantics (ADR-036) — where this proposal and the implemented endpoint diverge,
the endpoint + its conformance fixtures are the contract.

## Why a hint, not inference

A Rust free-function locator (`crate.module.func`) is byte-ambiguous with a
Python qualname — no locator-dialect sniffing can attribute it. But Wardline
always knows which frontend minted a finding (`--lang` selects the analyzer;
findings carry `lang`), and both Wardline call sites of
`POST /api/wardline/resolve` — dossier source resolution and the
Filigree entity-association bridge — resolve qualnames taken from a finding.
The producer knows; the wire should carry it.

## Proposed shape

```json
POST /api/wardline/resolve
{
  "project": "…",
  "qualnames": ["demo.m.func", "…"],
  "plugin": "rust"
}
```

- **`plugin`** — OPTIONAL string; values are ADR-049 plugin ids exactly as they
  appear in entity ids (`python`, `rust`). **Batch-scoped** (one hint per
  request, not per qualname): every Wardline resolve batch is minted by exactly
  one frontend, so a per-row field would only invite mixed batches no producer
  sends. A consumer with mixed-language qualnames sends one request per plugin.
- **Semantics with the hint:** resolution is restricted to the named plugin's
  namespace. Unique match → resolved; no match in that plugin → `unresolved`
  (even if another plugin owns the qualname — the hint is a constraint, never a
  preference order); ambiguous *within* one plugin → `unresolved` (fail-closed;
  post-gold this is `duplicate_ids() = 0` territory, but the wire must not
  guess if it recurs).
- **Semantics without the hint:** exactly today's behavior — cross-plugin
  lookup, `Ambiguous` degrades to `unresolved`. Omission stays legal forever
  (a consumer that genuinely does not know the language must not be forced to
  fabricate a hint).
- **Unknown plugin value:** `unresolved` for the whole batch (or a 400 naming
  the field — Loomweave's call; Wardline only ever sends ids it produces).

## Rollout (deliberate, coordinated — `deny_unknown_fields` forces ordering)

1. **Loomweave first:** accept + honor `plugin` on `ResolveRequest` (the struct
   is `#[serde(deny_unknown_fields)]`, so Wardline cannot send a byte before
   this lands). Reject-with-a-message that NAMES the field if it ever 400s, for
   cross-version diagnosability.
2. **Wardline second (tracked, see ticket below):** thread the producing
   plugin from the finding's `lang` through `LoomweaveClient.resolve()` at both
   call sites, and treat a resolve 4xx as fail-soft `unresolved` (an old server
   must degrade the dossier/association, not crash it).
3. **Conformance:** three fixture rows ride the resolver's conformance surface
   and Wardline's vendored oracle when the field ships — hinted-hit,
   hinted-miss (qualname owned by the *other* plugin only), and
   unhinted-ambiguous → `unresolved`.

No `ontology_version` interaction; no change to `resolved`/`unresolved`
response shape; SEIs stay opaque to Wardline throughout.
