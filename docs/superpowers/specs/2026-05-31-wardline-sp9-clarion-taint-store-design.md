# Wardline SP9 — Clarion-backed taint store (design)

**Status:** Approved (brainstorm) — 2026-05-31. **Implementation BLOCKED** until
Clarion ships its side (ADR-036 + `/api/wardline/*` routes + `contracts.md`); see §2.
**Author:** John (with Claude)

## 1. Goal

Turn Wardline's `explain_taint` from a stateless re-analysis into a **cheap query
against a persistent taint store that Clarion owns**, and unlock the deferred
**full N-hop taint chain** on top of it. Wardline writes per-entity taint facts to
Clarion at scan time (opt-in); `explain_taint` reads them back at explain time and
falls back to the SP8 re-run whenever the store can't serve a fresh answer. Wardline
remains fully usable with no Clarion present — the integration is purely additive.

## 2. Dependency & status

This depends on Clarion-side capability that is **being built now** and is not yet
shipped/verified:

- Clarion plan: `~/clarion/docs/superpowers/plans/2026-05-31-clarion-wardline-taint-store.md`
- The ask it answers: `docs/integration/2026-05-30-wardline-clarion-taint-store-requirements.md`
- The wire contract will be pinned in Clarion's `docs/federation/contracts.md` (their W.5).

**Wardline implementation (writing-plans → code) must not start until Clarion's
routes land and `contracts.md` is published.** This spec is written against the
contract as designed; the one detail still to confirm from Clarion before the
client is built is the **exact HMAC canonicalization** (what string is signed) —
see §11. The spec stands; only that signing detail is pending.

## 3. Non-negotiable character (the thesis, carried forward)

- **Standalone first.** `wardline scan` and the SP8 MCP server work with no Clarion.
  Every Clarion interaction is opt-in (`--clarion-url` / MCP config) and **fail-soft**:
  Clarion absent, unreachable, write-disabled, or returning a stale/unknown answer →
  Wardline degrades to the SP8 stateless re-run. Clarion never becomes load-bearing.
- **Base stays zero-dependency.** The Clarion integration lives behind a new
  `wardline[clarion]` extra; the analyzer core and `scanner` install unchanged.
- **Never serve drifted taint.** SP8's `explain_taint` guarantee is preserved exactly:
  a stored fact is served only when it is provably fresh for the current code; otherwise
  Wardline recomputes. Freshness is decided **by Wardline**, from the content hash
  Clarion returns (Clarion never asserts freshness).
- **No new core dependency, opaque blob.** `wardline_json` is Wardline-owned and
  versioned; Clarion stores and returns it verbatim and never parses it.

## 4. Architecture

Four units, bottom-up. Each is independently testable; the transport is injectable so
no test touches the network.

### (a) `clarion/client.py` — the dep-light HTTP client

A small client speaking the four contract routes over HTTP+JSON, with an **injectable
transport** (the SP4/SP5 pattern) so handlers are unit-tested against a fake responder:

```python
class ClarionClient:
    def __init__(self, base_url: str, *, token: str, transport: Transport | None = None,
                 batch_max: int = 2000) -> None: ...
    def resolve(self, qualnames: list[str]) -> ResolveResult: ...           # POST /api/wardline/resolve
    def write_taint_facts(self, facts: list[TaintFactWrite]) -> WriteResult: ...  # POST /api/wardline/taint-facts (chunked)
    def get_taint_fact(self, qualname: str) -> TaintFactView | None: ...     # GET  /api/wardline/taint-facts?qualname=
    def batch_get(self, qualnames: list[str]) -> list[TaintFactView]: ...    # POST /api/wardline/taint-facts:batch-get (chunked)
    def capabilities(self) -> Capabilities: ...                              # GET  /api/v1/_capabilities (probe wardline_taint_store)
```

- **Auth:** every request carries the `X-Loom-Component: clarion:<hmac>` header
  (ADR-034). HMAC is computed with the **standard library** (`hmac` + `hashlib`),
  so auth adds no dependency. The canonicalization (what bytes are signed) matches
  Clarion's `require_hmac_identity` — confirmed from `contracts.md`/ADR-034 (§11).
- **Chunking:** `write_taint_facts` and `batch_get` split inputs to ≤ `batch_max`
  (Clarion's `WARDLINE_TAINT_BATCH_MAX`, 2000) and respect the 4 MiB body cap, exactly
  as Wardline's Filigree emitter splits against `BATCH_MAX_QUERIES`.
- **Status bands (reuse the SP4 Filigree discipline):** connection error / timeout /
  **5xx** → soft failure (the caller degrades to re-run; `wardline scan` warns and
  continues); **4xx** → loud `ClarionError` (Wardline sent a bad request — exit 2 on the
  CLI write path); **403 `WRITE_DISABLED`/`PROJECT_MISMATCH`** → soft, surfaced as a
  clear message (the write API is off, or wrong project) and the run continues without
  Clarion. `2xx` bodies parsed defensively (malformed → soft).

### (b) `clarion/facts.py` — build the per-entity taint facts

Pure function `build_taint_facts(result: ScanResult, root: Path) -> list[TaintFactWrite]`
that projects the engine's `AnalysisContext` into the `wardline-taint-1` blobs (§7),
one per function entity. It stamps each fact's `content_hash_at_compute` =
**blake3 of the entity's containing file** (raw bytes, hex — matching Clarion's
`file_content_hash`), memoizing the hash per file across the scan. This is the only
place `blake3` is used; it imports lazily so the base package never needs it.

### (c) Write path — `wardline scan` (+ MCP `scan`) persists facts

When a Clarion URL is configured **and** the write API is enabled (probed via
`capabilities()` → `wardline_taint_store`), a successful scan additionally:
`build_taint_facts` → `client.write_taint_facts` (chunked). Unresolved qualnames
(Clarion hasn't indexed them) are reported in the summary, never an error — the store
is allowed to be partial. The whole step is fail-soft (§3): a Clarion outage never
fails the scan or changes the gate. CLI: `wardline scan --clarion-url <url>`;
MCP: server config carries the URL/token so the `scan` tool writes as a side effect,
warming the store for subsequent `explain_taint` queries.

### (d) Read path — `explain_taint` as a query, with re-run fallback

`explain_finding` (core) and the MCP `explain_taint` tool gain a Clarion-backed mode
when a client is configured:

1. Resolve the sink's qualname (or the fingerprint → qualname via the blob's
   `findings[]`) and `batch_get` the fact.
2. **Freshness gate:** compare the fact's stamped `content_hash_at_compute` to the
   `current_content_hash` Clarion returned. Match → serve the explanation straight from
   the stored blob (no analysis). Mismatch, `exists: false`, or any soft Clarion failure
   → **fall back to the SP8 re-run** (and, on the CLI write path, opportunistically
   re-write the recomputed fact).
3. Standalone (no client configured) → SP8 re-run, exactly as today.

The result shape is unchanged from SP8 (`TaintExplanation`), so the MCP surface and the
split error model are untouched; SP9 only changes *where the answer comes from*.

## 5. The `clarion` extra + dependencies

- New optional extra `wardline[clarion] = ["blake3>=…"]`. `blake3` is the **only** new
  dependency, used solely to match Clarion's content-hash space; HMAC/JSON/HTTP are all
  stdlib. Base, `scanner`, and `docs` extras are unchanged and stay as they are.
- Importing `wardline.clarion.*` without the extra raises a clear, actionable error
  ("install `wardline[clarion]`"), the same fail-loud-on-missing-extra pattern the CLI
  already uses.

## 6. Configuration & credentials

- **Endpoint:** `--clarion-url` (CLI) / a `clarion.url` server-config field (MCP).
  Absent → the integration is simply off.
- **HMAC secret:** from the **environment / `.env` only, never from `wardline.yaml`** —
  the same discipline as the OpenRouter key. Proposed env var
  `WARDLINE_CLARION_TOKEN` (final name aligned to Clarion's `contracts.md`); `.env`
  fallback; env wins. The secret never appears in any output, finding, or stored blob.
- **No config-borne secret, no key in the blob.** (Carried from SP5's hard rule.)

## 7. The `wardline_json` schema (Wardline-owned, opaque to Clarion)

`wardline-taint-1`, per the requirements brief §5. Each written fact also carries
`scan_id` and `content_hash_at_compute` as **top-level** fields (Clarion's queryable
columns) in addition to the blob:

```json
{
  "schema_version": "wardline-taint-1",
  "qualname": "auth.tokens.TokenManager.issue",
  "content_hash_at_compute": "<blake3-hex of the entity's file>",
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
  "findings": [{ "rule_id": "PY-WL-101", "fingerprint": "<64-hex>", "line_start": 7 }]
}
```

`taint.contributing_callee_qualname` is the chain edge (`null` at a boundary/leaf).
`findings[]` lets `explain_taint(fingerprint)` find its anchoring entity without a scan.

## 8. Full N-hop taint chain (unlocked by the store)

With the store warm, `explain_taint` gains an optional `chain: true` (and a bounded
`max_hops`) that walks `contributing_callee_qualname` from the sink to the originating
boundary: collect the next qualname, `batch_get` the next hop's fact, repeat until the
field is `null` or a hop is `exists:false`/stale (→ that hop falls back to a re-run, or
the chain truncates with an explicit `truncated_at` marker — never a silent stop). The
walk is **entirely client-side**; Clarion never parses the blob. This is the deferred
SP8 feature; it ships here because the store makes each hop a cheap lookup instead of a
whole re-analysis. The single-hop boundary SP8 already returns remains the default;
`chain: true` is opt-in depth.

## 9. Error handling & degradation (summary)

| Condition | Behavior |
|---|---|
| No `--clarion-url` configured | SP8 re-run; Clarion code never invoked |
| Clarion unreachable / timeout / 5xx | Soft: warn + continue; reads fall back to re-run; scan write skipped |
| 403 `WRITE_DISABLED` / `PROJECT_MISMATCH` | Soft: clear message; run continues without Clarion |
| 4xx (bad request from Wardline) | Loud `ClarionError`; CLI write path exits 2 |
| Fact `exists:false` / unresolved qualname | Treated as a miss → re-run for that entity |
| `content_hash_at_compute ≠ current_content_hash` | **Stale** → re-run; never served |
| `wardline[clarion]` not installed but `--clarion-url` given | Loud: "install `wardline[clarion]`" |

## 10. Testing

- **Unit (no network):** injected fake transport for `resolve`/`write`/`get`/`batch_get`;
  chunking against the 2000 cap; HMAC header construction (a fixed-vector test against
  the confirmed canonicalization); status-band handling (conn/5xx soft, 4xx loud, 403
  soft); defensive 2xx parsing.
- **Fact builder:** `build_taint_facts` over the `_LEAKY` fixture → a PY-WL-101 fact with
  the right `taint.*` and a real blake3 stamp; per-file hash memoization.
- **Freshness:** fresh (match → served from store, analysis NOT invoked — assert via a
  spy), stale (mismatch → re-run), absent (`exists:false` → re-run).
- **Chain:** a 3-hop `_LEAKY` chain → ordered hops to the boundary; a stale mid-hop →
  `truncated_at`/re-run, never a silent stop.
- **Standalone:** no client configured → byte-identical to SP8 behavior (the existing
  SP8 explain tests must stay green).
- **Live e2e (the SP4 lesson — non-negotiable for a wire contract):** an ephemeral
  `clarion serve --… wardline_taint_write` over a tmp project, real HMAC, real
  blake3 — scan→write→explain→query round-trip; marked `clarion_e2e` (deselected by
  default like the judge `network` test). This is what catches a contract drift that
  hermetic fakes miss.

## 11. Open item to confirm from Clarion before building the client

The **exact HMAC canonicalization** — which bytes Clarion's `require_hmac_identity`
signs (raw body only, or method+path+body, plus any timestamp/nonce). Wardline's client
must reproduce it byte-for-byte. Source of truth: Clarion's `contracts.md` (their W.5) +
ADR-034. This is the single blocker for the client unit tests' fixed-vector; everything
else in this spec is pinned.

## 12. Non-goals (SP9 v1)

- **Overlay-scan (in-memory buffer scan).** Separate engine work; the store does not
  directly enable it. Stays deferred.
- **Relying on Clarion's heuristic resolution tier.** Only the exact qualname tier
  exists at Clarion 1.1 (their Flow B B.2 adds heuristic later); Wardline uses exact
  resolution and treats unresolved as a miss. No dependency on the heuristic tier.
- **Replacing the SP8 re-run.** It stays forever as the standalone path and the
  freshness/outage fallback. SP9 layers on top; it is never required.
- **Wardline parsing anything Clarion-internal, or Clarion parsing `wardline_json`.**
  The blob stays opaque both ways; all taint semantics (including the chain walk) stay
  Wardline-side.

## 13. Sequencing (shape of the eventual plan)

Once Clarion lands (§2) and the HMAC scheme is confirmed (§11), the Wardline plan is a
short, refactor-light sequence — the engine already computes every fact:

1. `wardline[clarion]` extra + `clarion/client.py` (HMAC, transport, status bands, chunking).
2. `clarion/facts.py` — `build_taint_facts` + blake3 stamping (lazy import).
3. Write path: `wardline scan --clarion-url` (+ MCP `scan` config), fail-soft.
4. Read path: `explain_finding`/`explain_taint` Clarion-backed mode + freshness gate +
   SP8 fallback.
5. Full N-hop chain (`chain: true`).
6. Live `clarion_e2e` round-trip; docs (`docs/agents.md` MCP section + a Loom-integration note).

Each step is independently testable behind the injected transport; the standalone SP8
behavior is the regression oracle throughout.
