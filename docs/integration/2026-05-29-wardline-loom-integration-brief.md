# Wardline ↔ Loom Integration Brief

**Date:** 2026-05-29
**From:** Wardline (generic build, in flight)
**To:** Filigree and Clarion maintainers
**Status:** request-for-adaptation — sibling-side changes that let the generic Wardline emit findings natively into the suite
**Charter:** [`loom.md`](../../) §5 — integration is *additive, not load-bearing*. Every ask below is enrichment; Wardline boots, self-tests, and analyzes with both siblings absent.

---

## 1. Context

Wardline is being rebuilt as a **generic, lightweight semantic-tainting static analyzer** for any Python project (language-pluggable later), with light-touch, single-user-friendly governance (a plain git-committed baseline; no signing, no counter-signatures, no coverage gates). It fuses the rigorous taint engine of the prior reference impl with an opt-in LLM judge.

It needs to emit findings **natively** into the suite:

- **Filigree** — receive Wardline findings into its scan-results lifecycle (the authoritative home for finding *state*).
- **Clarion** — enrich those findings by reconciling Wardline's Python qualnames to Clarion entity IDs.

This brief states exactly what Wardline will emit and the small, bounded changes (mostly confirmations) it needs on each side. **Wardline deliberately does not ask either tool to grow new columns for Wardline-specific semantics** — those ride a namespaced `metadata` slot, per the charter.

---

## 2. The shared contract — Wardline's `Finding`

Wardline's internal `Finding` is a pure analysis fact. It is designed as a **superset** of Filigree's `ScanFinding` intake so emission is serialization, not translation. Wardline does **not** model finding lifecycle (`status`, `scan_run_id`, `seen_count`, `issue_id`, timestamps) — that is Filigree's authoritative domain.

| Wardline field | Wire destination |
|---|---|
| `rule_id` (`WLN-*`, namespaced) | Filigree `rule_id` — preserved byte-for-byte |
| `message` | Filigree `message` |
| `suggestion` | Filigree `suggestion` |
| `severity` (internal `INFO\|WARN\|ERROR\|CRITICAL`, `NONE` for facts) | Filigree `severity` (mapped, see §5) |
| `location.path` | Filigree `file_path` (→ `file_id` resolved server-side) |
| `location.line_start/end` | Filigree `line_start`/`line_end` |
| `fingerprint` (stable per-finding hash) | see §3 ask B |
| `qualname` (`module.qualified_name`, dotted) | `metadata.wardline.qualname` (see §4) |
| `kind` (`defect\|fact\|classification\|metric\|suggestion`) | `metadata.wardline.kind` |
| `confidence`, `related_entities` | `metadata.wardline.*` |
| `properties` (per-rule extension) | `metadata.wardline.properties.*` |

### The `metadata.wardline.*` namespace

All Wardline-specific richness lands under a single namespaced key, preserved verbatim by both siblings:

```jsonc
"metadata": {
  "wardline": {
    "fingerprint": "<64-hex stable hash>",
    "qualname": "auth.tokens.TokenManager.issue",
    "kind": "defect",
    "internal_severity": "ERROR",          // round-trips the 4-level original
    "confidence": 0.92,                      // optional
    "related_entities": [],                  // optional
    "properties": { "cwe": "CWE-200" }       // arbitrary per-rule extension
  }
}
```

---

## 3. Asks for Filigree

**A. (confirm) Batch scan-results ingest.** Confirm `POST /api/v1/scan-results` accepts `scan_source` plus a list of findings, each carrying `file_path, rule_id, message, severity, line_start, line_end, suggestion, metadata`, and preserves `metadata` verbatim. (Your `ScanIngestResponseLoom` implies this exists — just confirming the field set, especially `suggestion` and a free-form `metadata` on the *ingest* path, not only on the stored row.)

**B. (the one real change) Dedup on a Wardline-supplied `fingerprint`.** Wardline computes a stable per-finding fingerprint; it is the spine of Wardline's baseline/drift detection. **Request:** Filigree treats this fingerprint as the finding's cross-run identity for `seen_count`/lifecycle, rather than recomputing its own key — so Wardline's baseline and Filigree's lifecycle never disagree. Either:
- a top-level `fingerprint` field on the scan-results finding (preferred), or
- an agreed convention that Filigree dedups on `metadata.wardline.fingerprint` when `scan_source == "wardline"`.

Please call which you'd rather implement.

**C. (confirm) Standalone `file_path` → `file_id` resolution.** Confirm path-anchored ingest resolves `file_id` in **standalone Filigree** (no Clarion registry backend), so the (Wardline, Filigree) pair composes without Clarion present — pairwise composability per `loom.md` §4.

**D. (confirm) `scan_source = "wardline"`** and the `WLN-*` `rule_id` namespace are accepted and stored byte-for-byte (no normalization).

**Not asking for:** new columns for `qualname`/`kind`/`fingerprint`/`confidence`. They stay in `metadata.wardline.*`. The only schema touch requested is the dedup-key decision in (B).

---

## 4. Asks for Clarion

**A. (confirm) qualname → entity-ID reconciliation.** Wardline emits `metadata.wardline.qualname` as the **combined dotted `module.qualified_name`** (e.g. `auth.tokens.TokenManager.issue`) — deliberately matching Clarion's L7 form to resolve the [ADR-018](../../clarion/adr/ADR-018-identity-reconciliation.md) deferred clash in Clarion's favor. Confirm Clarion reconciles this to an `EntityId` at ingest/enrichment and that the dotted form is what you want (vs. the old `(module, qualified_name)` tuple).

**B. (decision) Transport role under "native" emission.** [ADR-015](../../clarion/adr/ADR-015-wardline-filigree-emission.md) scoped Wardline→Filigree through Clarion's `clarion sarif import` for v0.1, with a native Wardline emitter as the v0.2 retirement. Wardline now intends to ship the **native Filigree emitter directly** (it's the ~1-day path the ADR-015 spike already costed). Consequence: **Clarion is no longer on the transport path** for the (Wardline, Filigree) pair, and `loom.md` §5 asterisk 1 can retire. Clarion's role becomes pure **enrichment** (entity reconciliation), not a bridge. Please confirm you're happy to (a) keep the SARIF translator as a general-purpose path for *other* SARIF tools, and (b) treat Wardline as a native emitter. This likely warrants an ADR-015 "Revision 2".

**C. (optional, later) Entity associations.** If Wardline later binds findings to Clarion entities directly (beyond qualname reconciliation), it would use [ADR-029](../../clarion/adr/ADR-029-entity-associations-binding.md) `add_entity_association` with `content_hash_at_attach`. Not needed for the first cut — flagged so it's not a surprise.

---

## 5. Severity mapping

Wardline internal (4 levels + facts) → Filigree (5 levels). Original preserved in `metadata.wardline.internal_severity`.

| Wardline | Filigree |
|---|---|
| `CRITICAL` | `critical` |
| `ERROR` | `high` |
| `WARN` | `medium` |
| `INFO` | `low` |
| `NONE` (facts/metrics) | `info` |

---

## 6. Federation discipline (what Wardline will NOT do)

- Wardline has **no runtime dependency** on either sibling. `wardline scan` runs and writes `findings.jsonl` standalone; Filigree/Clarion emission is opt-in (`--filigree-url`, `--clarion-*`), absent → degrade silently.
- Wardline does **not** push its semantics into sibling schemas. Rich fields live in `metadata.wardline.*`.
- Wardline does **not** read finding *state* back as authoritative — Filigree owns lifecycle; Wardline owns the analysis fact and the local baseline.

---

## 7. Decisions requested back

1. **Filigree §3.B** — top-level `fingerprint` field, or dedup on `metadata.wardline.fingerprint`?
2. **Clarion §4.A** — confirm dotted `module.qualified_name` is the reconciliation key you want.
3. **Clarion §4.B** — agree Wardline ships as a native Filigree emitter and ADR-015 gets a Revision 2 (Clarion off the transport path, translator stays for other tools).

---

## Round 1 — Clarion response (2026-05-29) & Wardline reply

**Clarion decisions: §4.A ✅ (with a normalization contract), §4.B ✅ (asterisk 1 stays live until ship). Decision 1 is Filigree's.** Two route-backs to Wardline; both answered below.

### Reply to §4.A — qualname normalization contract (accepted)

- Wardline's emitter composes **only the module portion**, applying Clarion's exact `module_dotted_name()` rules (src/ strip, `.py` drop, `__init__.py` collapse, namespace + non-src layouts). **Please send that function**; Wardline vendors it as the single source of truth.
- Python `__qualname__` is preserved **byte-for-byte**: `<locals>` markers and dotted class chains pass through untouched, never re-dotted. Final key = `module_dotted_name(path) + "." + __qualname__`.
- **Proposal — shared qualname conformance corpus.** A committed JSON of `{layout, file, symbol} → expected_qualname` covering the landmines (src/namespace/non-src, `__init__` collapse, nested class, `<locals>`/closure, decorated/overloaded). Both tools run it in their own CI; federation-safe design-review artifact (nothing imports it). Wardline seeds it from Clarion's function. **Q back: where does it live — Clarion repo or a neutral suite location?** This converts byte-equality from assumption to test, on both sides.

### Reply to §4.B — transport / asterisk 1 (agreed in full)

Rev 2 rewrites the retirement *mechanism* (Wardline-side native emitter); asterisk 1 stays **live** in `loom.md` §5 under `release:1.1` until the emitter ships and is verified. No deletion on promise. Agreed.

### Reply to the REGISTRY route-back — asterisk 2 (the important one)

The rebuild **preserves the registry**: `wardline.core.registry.{REGISTRY, REGISTRY_VERSION, RegistryEntry}` + the decorator/annotation groups are core to Wardline (SP2), same package path. Wardline's commitment is **belt-and-suspenders**:

1. **Keep the `wardline.core.registry` import surface intact** in the rebuild → Clarion's plugin startup contract does **not** break (zero-day compat bridge).
2. **Additionally land the NG-25 descriptor** (versioned YAML/JSON vocabulary export carrying `REGISTRY_VERSION` + entries) so the plugin can *read* instead of *import* — the federation-clean retirement of asterisk 2.

Asterisk 2 retires when Clarion's plugin switches to the descriptor (same ship-not-promise discipline). **Q back: can the plugin consume an NG-25 descriptor, and on what timeline?** Until then the import keeps it running. (Descriptor-only-from-day-one is possible but couples our release timelines — plugin must switch before Wardline's first tag — so the compat bridge is recommended.)

### Accepted consequential ADR touches (Clarion-side)

- **ADR-018** gets its own dated entry: reconciliation entry point becomes "Wardline emits pre-composed `metadata.wardline.qualname`; Clarion matches via `find_entity`-by-qualname off the Filigree finding" — replacing the file-path composition rule.
- **ADR-017**'s Wardline severity-mapping role retires; the §5 table here is now the authority for the (direct) Wardline→Filigree mapping.
- **ADR-029** entity associations — acknowledged, not first-cut.

### New Wardline-side obligations captured from Round 1

- **SP1/SP2:** qualname emitter must replicate Clarion's `module_dotted_name()` byte-for-byte and preserve `__qualname__` verbatim.
- **Shared:** seed + maintain the qualname conformance corpus.
- **SP2:** preserve `wardline.core.registry` import surface **and** emit an NG-25 vocabulary descriptor.
- **SP4:** prefer a **top-level `fingerprint` field** for Filigree dedup (shared preference with Clarion).

---

## Round 1 — Filigree response (2026-05-29, schema v16) & Wardline reply

**Filigree: all four asks confirmed. §3.B accepted as the generic top-level `fingerprint` field (Wardline's preference). Two corrections + two questions back, answered below.**

### §3.B accepted — generic top-level `fingerprint` (Wardline confirms commitment)

Filigree will add an **optional, first-class `fingerprint`** column (not a Wardline metadata special-case): when non-empty it is the cross-run identity (keyed with `scan_source`); when absent, dedup falls back to `(file_id, scan_source, rule_id, coalesce(line_start,-1))`. Cost owned by Filigree: schema **v16→v17** (replace the non-partial UNIQUE dedup index with a partial one + add partial unique on `(scan_source, fingerprint)`), dedup-query change, wire/adapter/fixture update, and a behavioral fix (the update path must refresh `line_start`, not just `line_end`, since line can move while fingerprint holds).

**Wardline confirms it supplies a stable top-level `fingerprint`** — it is the spine of SP3's baseline/drift detection, so the migration is justified by a real consumer. Bonus that strengthens the case: Filigree's own line-based key is unstable (`_normalize_line_attribution_for_existing_files` clamps/clears `line_start`), which silently re-keys findings; a Wardline fingerprint pins identity through exactly that churn.

> **New constraint captured (SP1/SP3):** Filigree flags the plausible case of **two taint paths into one sink** — two findings at the same `file/rule/line` with different fingerprints. Wardline's fingerprint **must distinguish findings by taint path**, not just `(file, rule, line)`, or the two collapse. This is a fingerprint-composition requirement for the engine.

### §3.A confirmed — two corrections folded in

1. **`metadata` is preserved as a semantic JSON object, not byte-for-byte** (round-trips `json.dumps`/`loads`). Wardline will **not** rely on key order, whitespace, or duplicate keys in `metadata.wardline.*`. (`rule_id` *is* byte-identical — stored column, no transform. Brief §2/§3 wording corrected here.)
2. **`suggestion` is truncated at 10 000 chars** with a warning → Wardline caps/sizes fix text accordingly.

### §3.A — endpoint generation (question answered)

Filigree has two front doors sharing one request body: `POST /api/v1/scan-results` (classic) and `POST /api/loom/scan-results` (Loom vocab; `/api/scan-results` aliases Loom). **Wardline will emit into `/api/loom/scan-results`** — Wardline is a Loom-native citizen and wants the `ScanIngestResponseLoom` envelope. (SP4 emitter targets the Loom endpoint.)

### §3.C / §3.D / §5 — confirmed

Standalone `file_path`→`file_id` via the default `local` registry (composes with Clarion absent ✓); `scan_source="wardline"` + `WLN-*` stored as-is ✓; severity CHECK is exactly the 5-level set, our client-side map lands clean (fail-soft maps unknown→`info`, which we won't hit) ✓.

### §4.B federation note — agreed

When ADR-015 Rev 2 lands (Clarion off transport, Wardline native emitter), Filigree adds a one-line note that `scan-results` is a first-class external entry point for native emitters. No objection from Filigree's side; the endpoint doesn't care who calls it. Wardline agrees.

### New Wardline-side obligations from Filigree Round 1

- **SP1/SP3:** fingerprint composition must disambiguate same-`(file,rule,line)` findings by **taint path**.
- **SP4:** emit to `POST /api/loom/scan-results`; send top-level `fingerprint` (may mirror into `metadata.wardline.fingerprint`); cap `suggestion` ≤ 10 000 chars.
- **Contract hygiene:** treat `metadata` as semantic-JSON (no reliance on key order / dupes).

---

## Contract status (end of Round 1)

| Item | Status |
|---|---|
| Filigree top-level `fingerprint` dedup (v17) | ✅ agreed — Filigree implements |
| Loom scan-results endpoint as native entry point | ✅ Wardline emits to `/api/loom/scan-results` |
| Clarion qualname reconciliation (dotted, pre-composed) | ✅ agreed — pending `module_dotted_name()` handover + conformance corpus |
| Native emitter / ADR-015 Rev 2 / asterisk 1 live until ship | ✅ agreed |
| REGISTRY import preserved + NG-25 descriptor (asterisk 2) | ✅ Wardline commits both; pending Clarion plugin-reader timeline |
| Severity 4→5 map (Wardline-owned) | ✅ confirmed |
| Entity associations (ADR-029) | ⏸ deferred, not first-cut |

**Open loops (non-blocking for SP0):** qualname corpus location (Clarion repo vs neutral); Clarion NG-25 plugin-reader timeline.

---

## Round 2 — sibling implementations shipped & verified (2026-05-29)

Both siblings implemented their side; Wardline reviewed the code. Verified outcomes:

### Filigree (branch `docs/2.1.0-release-prep`) — COMPLIANT, with naming/version notes

- **Schema shipped as v19** (not v17 — two unrelated migrations landed between). SP4 must target schema **v19** (`db_schema.py:528`).
- **Top-level `fingerprint`** column `TEXT NOT NULL DEFAULT ''` (`db_schema.py:160`), generic (any scanner).
- **Dedup:** fingerprint non-empty → identity `(scan_source, fingerprint)`; empty → legacy `(file_id, scan_source, rule_id, coalesce(line_start,-1)) WHERE fingerprint=''` (`db_files.py:1063-1080`). Partial unique indexes per contract.
- **`line_start` refresh fix** present (`db_files.py:1189-1211`); test covers line-move under stable fingerprint.
- **`suggestion` truncated at 10 000 chars** with `"\n[truncated]"` (`db_files.py:1053-1061`).
- Standalone `path`→`file_id` via local registry works (Clarion absent) ✓.

**⚠️ SP4 wire gotchas (exact):**
- Endpoint **`POST /api/loom/scan-results`**. Per-finding path key is **`path`**, NOT `file_path` (sending `file_path` → 400).
- Per-finding keys: `path`(req), `rule_id`(req), `message`(req), `severity`(opt, 5-level lowercase), `line_start`/`line_end`(opt), `fingerprint`(opt top-level string; `null`≡omitted≡`""`), `suggestion`(opt), `metadata`(opt object), `language`(opt). Body also takes `scan_source`(req), `scan_run_id`, `mark_unseen`, `create_observations`, `complete_scan_run`.
- `metadata` preserved as semantic JSON (no key-order/dupes). Line clamping: a `line_start` beyond the on-disk file length is cleared to `null`.

### Clarion (Python plugin) — qualname PRODUCER contract fixed; CONSUMER not yet built

**Reconciliation read-path is NOT yet implemented** (schema-reserved `wardline_json` column, all `None`; `wardline_probe.py` only proves the import/version handshake; full join is ADR-018 / WP3 scope). So Wardline emitting the correct qualname now is what makes future reconciliation work. **The producer format is fixed and is the SP1 contract:**

**`module_dotted_name(rel_path)`** (`extractor.py:210-234`) — operate on the **project-relative POSIX path** (never absolute):
1. Strip exactly **one** leading `src/` component.
2. Drop the `.py` suffix; if the resulting stem is `__init__`, **remove that component** (collapse to parent).
3. Join remaining components with `.`.
- Examples: `demo.py`→`demo`; `src/demo.py`→`demo`; `pkg/__init__.py`→`pkg`; `src/pkg/sub/mod.py`→`pkg.sub.mod`; `src/src/pkg/mod.py`→`src.pkg.mod` (one level only).
- Top-level `__init__.py` → empty module → **emit no entity** (do not emit empty qualname).

**`reconstruct_qualname`** (`qualname.py:34-48`) — start with the symbol's bare name; walk ancestors innermost→outermost:
- `FunctionDef`/`AsyncFunctionDef` parent → prepend `"{name}.<locals>."`
- `ClassDef` parent → prepend `"{name}."`
- all other nodes (Module/If/With/…) → skipped.
- Final key: **`f"{dotted_module}.{qualname}"`**.
- Examples: `demo.Foo.bar`; `demo.Outer.Inner.method`; `demo.outer.<locals>.inner`; nested-class-in-closure → `demo.Foo.bar.<locals>.Local.meth`. The literal `<locals>` (with angle brackets) is a verbatim component, never re-dotted.

**Divergence gotchas SP1 must honor to keep reconciliation lossless:**
- `<locals>` comes from the **function** ancestor only (a class nested in a function gets one `<locals>` from the function, not from itself).
- `@overload` stubs (bare/`typing.overload`/`typing_extensions.overload`) are **dropped** before entity emission; aliased `overload as o` is not recognized.
- Duplicate qualnames (redefinition, `singledispatch def _`) → **first-wins**.
- `async def` ≡ `def` for qualname purposes.

> **SP1 obligation:** implement `module_dotted_name` + `reconstruct_qualname` to match the above byte-for-byte, and stand up the shared qualname conformance corpus (seeded from these examples + the edge cases) so both tools test it in CI.
