# Wardline SP9 — Clarion-backed taint store (design)

**Status:** Approved (brainstorm) — 2026-05-31. **Implementation UNBLOCKED 2026-05-31:**
Clarion shipped its side (ADR-036 + `/api/wardline/*` routes + pinned `contracts.md`);
the spec has been reconciled against the delivered contract — see §2 and the
reconciliation deltas folded into §4/§6/§7/§9. The HMAC canonicalization (formerly the
§11 open item) is now pinned byte-exactly from Clarion source; §11 records it.
**Author:** John (with Claude)

## 1. Goal

Turn Wardline's `explain_taint` from a stateless re-analysis into a **cheap query
against a persistent taint store that Clarion owns**, and unlock the deferred
**full N-hop taint chain** on top of it. Wardline writes per-entity taint facts to
Clarion at scan time (opt-in); `explain_taint` reads them back at explain time and
falls back to the SP8 re-run whenever the store can't serve a fresh answer. Wardline
remains fully usable with no Clarion present — the integration is purely additive.

## 2. Dependency & status

This depended on Clarion-side capability that has now **shipped** (Clarion
release:1.1, landed 2026-05-31):

- Clarion ADR: `~/clarion/docs/clarion/adr/ADR-036-wardline-taint-fact-store.md`
- Pinned wire contract: `~/clarion/docs/federation/contracts.md` §"Wardline
  taint-fact store (SP9)" + §"Authentication" (HMAC) + §"Wardline qualname
  normalization".
- The ask it answers: `docs/integration/2026-05-30-wardline-clarion-taint-store-requirements.md`

The routes are live and verified by Clarion's W.1–W.4 tests. This spec has been
**reconciled against the delivered contract**; the deltas from the as-designed
draft are:

1. **No capabilities flag for the taint store.** `GET /api/v1/_capabilities`
   does **not** advertise the taint store or whether the write path is enabled.
   A client discovers the write API is off by receiving `403 WRITE_DISABLED`
   from the write route — *not* by probing. The client therefore has **no**
   `capabilities()`/`wardline_taint_store` probe; the write path is
   attempt-then-handle-403 (§4c).
2. **HMAC canonicalization pinned byte-exactly** (was the §11 open item; now §11
   records the resolved scheme, read from Clarion source).
3. **Read never returns `content_hash_at_compute`.** Freshness is decided by
   comparing the `content_hash_at_compute` Wardline stamped *inside* the opaque
   blob against the live `current_content_hash` Clarion returns (§4d, §7).
4. **`current_content_hash` can be field-absent even when `exists: true`** (the
   containing file was deleted/unreadable at request time) → treated as stale →
   re-run (§4d, §9).
5. **Qualname composition is already conformant.** Wardline's existing
   `core/qualname.py` (`module_dotted_name` + `reconstruct_qualname`) reproduces
   every vector in Clarion's normative fixture
   `wardline-qualname-normalization.json` — including the divergence traps. SP9
   reuses it; it does not reimplement composition (§4b, §10).

Implementation (writing-plans → code) may now proceed.

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
    def __init__(self, base_url: str, *, secret: str | None, project: str,
                 transport: Transport | None = None, batch_max: int = 2000) -> None: ...
    def resolve(self, qualnames: list[str]) -> ResolveResult: ...           # POST /api/wardline/resolve
    def write_taint_facts(self, facts: list[TaintFactWrite]) -> WriteResult: ...  # POST /api/wardline/taint-facts (chunked)
    def get_taint_fact(self, qualname: str) -> TaintFactView | None: ...     # GET  /api/wardline/taint-facts?project=&qualname=
    def batch_get(self, qualnames: list[str]) -> list[TaintFactView]: ...    # POST /api/wardline/taint-facts:batch-get (chunked)
```

There is **no** `capabilities()` method: the contract does not advertise the taint
store, so the write path is **attempt-then-handle-403** (§4c), not probe-then-write.

- **Auth (HMAC, stdlib, pinned byte-exactly — §11):** every request carries
  `X-Loom-Component: clarion:<hmac>`, where `<hmac>` is lowercase-hex HMAC-SHA256
  (RFC 2104, `hmac.new(secret, msg, hashlib.sha256).hexdigest()`) over the canonical
  message — three lines joined by `\n` with **no trailing newline**:

  ```text
  <METHOD>\n<PATH_AND_QUERY>\n<SHA256_HEX_OF_REQUEST_BODY>
  ```

  - `<METHOD>` is the uppercase HTTP verb (`POST`, `GET`).
  - `<PATH_AND_QUERY>` is the **raw** request-target string exactly as sent on the
    wire (path, plus `?query` when present) — the client must sign the byte-identical
    string it puts on the request line, including percent-encoding and param order.
  - `<SHA256_HEX_OF_REQUEST_BODY>` is `hashlib.sha256(body).hexdigest()`; for a
    bodyless GET this is `sha256(b"")` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
  - **Note the two different hashes:** the *body* hash inside the HMAC message is
    **SHA-256**; the *freshness* `current_content_hash` (§4d) is **blake3**. They are
    unrelated. Auth therefore needs no extra dependency — only the `clarion` extra's
    blake3 is new.
  - When the secret is unset, the client sends **no** auth header (works against a
    loopback-unauth Clarion). A `401 UNAUTHENTICATED` then means the server requires
    auth and the secret is missing/wrong → loud.
- **Project guard:** every request sends `project` = the scanned project's root
  directory name (Clarion's guard handle). Clarion accepts an empty `project` (no
  assertion) but a non-empty mismatch returns `403 PROJECT_MISMATCH`; sending the name
  catches "talking to the wrong Clarion" instead of silently writing to it.
- **Chunking:** `write_taint_facts` and `batch_get` split inputs to ≤ `batch_max`
  (Clarion's `WARDLINE_TAINT_BATCH_MAX`, 2000) and respect the 4 MiB body cap, exactly
  as Wardline's Filigree emitter splits against `BATCH_MAX_QUERIES`.
- **Status bands — switch on `code`, not status (reuse the SP4 Filigree discipline).**
  Clarion's error envelope is `{"error", "code"}` with a closed `code` enum, and the
  *same* `code` can carry different HTTP statuses by route, so the client routes on
  `code`. Connection error / timeout / **5xx** (`STORAGE_ERROR`/`INTERNAL`) → soft
  failure (caller degrades to re-run; `wardline scan` warns and continues). `403`
  `WRITE_DISABLED`/`PROJECT_MISMATCH` → soft, surfaced as a clear message (write API
  off, or wrong project) and the run continues without Clarion. Other `4xx`
  (`INVALID_PATH`, `UNAUTHENTICATED`, and the **`413 BATCH_TOO_LARGE`** with a JSON
  `code`, or a raw-body **`413` with no JSON `code`** meaning the client built a body
  over 4 MiB) → loud `ClarionError` (a Wardline bug — the client already chunks to
  2000, so a `413` signals a defect; exit 2 on the CLI write path). `2xx` bodies parsed
  defensively (malformed → soft).

### (b) `clarion/facts.py` — build the per-entity taint facts

Pure function `build_taint_facts(result: ScanResult, root: Path) -> list[TaintFactWrite]`
that projects the engine's `AnalysisContext` into the `wardline-taint-1` blobs (§7),
one per function entity.

- **Qualname (reuse, do not reimplement).** Each fact's `qualname` is the
  **pre-composed** dotted form `f"{module_dotted_name(rel_path)}.{__qualname__}"`,
  built with Wardline's existing `core/qualname.py` (`module_dotted_name` +
  `reconstruct_qualname`). That module is already documented as byte-for-byte with
  Clarion's `extractor.module_dotted_name`, and it reproduces every vector in
  Clarion's normative fixture `wardline-qualname-normalization.json` — including the
  divergence traps (`src/` stripped only at position 0 → `a.src.b`; `lib/`/`app/` not
  stripped; `<locals>` and nested-class chains verbatim; `__init__` collapse;
  top-level `__init__.py` → `None`, for which Wardline emits **no** fact). Clarion's
  `resolve`/write is **exact-only**, so a divergent spelling would land every fact in
  `unresolved` and silently no-op the store — reusing the conformant function is what
  prevents that.
- **Freshness stamp.** It stamps each fact's `content_hash_at_compute` =
  **blake3 of the entity's containing file**, computed over the **whole file, raw
  bytes (binary read — no text-mode LF translation), lowercase hex** (blake3-256 →
  64 hex chars). This must match Clarion's `current_content_hash`
  (`clarion_storage::current_file_hash`): it is **not** SHA-256, **not** LF-normalized,
  and **not** span-scoped to the entity's lines. The hash is memoized per file across
  the scan. This is the only place `blake3` is used; it imports lazily so the base
  package never needs it.

### (c) Write path — `wardline scan` (+ MCP `scan`) persists facts

When a Clarion URL is configured, a successful scan additionally **attempts** the
write — there is no capability to probe first (§2 delta 1): `build_taint_facts` →
`client.write_taint_facts` (chunked). If the write API is disabled, Clarion returns
`403 WRITE_DISABLED` **before parsing the body**; the client treats that as a soft
"store not accepting writes" message and the scan continues unaffected. Unresolved
qualnames (Clarion hasn't indexed them) come back in the write response's
`unresolved_qualnames` and are reported in the summary, never an error — the store is
allowed to be partial, and an exact-only write silently drops unresolved facts. The
whole step is fail-soft (§3): a Clarion outage, `WRITE_DISABLED`, or
`PROJECT_MISMATCH` never fails the scan or changes the gate. CLI:
`wardline scan --clarion-url <url>`; MCP: server config carries the URL/secret so the
`scan` tool writes as a side effect, warming the store for subsequent `explain_taint`
queries.

### (d) Read path — `explain_taint` as a query, with re-run fallback

`explain_finding` (core) and the MCP `explain_taint` tool gain a Clarion-backed mode
when a client is configured:

1. Resolve the sink's qualname (or the fingerprint → qualname via the blob's
   `findings[]`) and `batch_get` the fact.
2. **Freshness gate (Wardline decides; Clarion never asserts).** The read view never
   echoes the write-time `content_hash_at_compute` column — Wardline reads its own
   stamp from *inside* the returned opaque `wardline_json` blob (§7) and compares it to
   the live `current_content_hash` Clarion returns. **Match → fresh:** serve the
   explanation straight from the stored blob (no analysis). **Fall back to the SP8
   re-run** (and, on the CLI write path, opportunistically re-write the recomputed
   fact) on any of: hash **mismatch**; `exists: false`; `current_content_hash`
   **field-absent** (which happens even when `exists: true` if the containing file was
   deleted/unreadable when Clarion read it); or any soft Clarion failure.
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
  the same discipline as the OpenRouter key. Env var `WARDLINE_CLARION_TOKEN`; `.env`
  fallback; env wins. This holds the **shared secret string** the Clarion operator
  configured in the server's `serve.http.identity_token_env` (default
  `CLARION_LOOM_IDENTITY_SECRET`) — the two env-var *names* are independent; only the
  secret *value* must match. Unset → the client sends no auth header (loopback-unauth
  Clarion); a resulting `401` is loud. The secret never appears in any output, finding,
  or stored blob.
- **No config-borne secret, no key in the blob.** (Carried from SP5's hard rule.)

## 7. The `wardline_json` schema (Wardline-owned, opaque to Clarion)

`wardline-taint-1`, per the requirements brief §5. Each written fact carries
`scan_id` and `content_hash_at_compute` as **top-level** fields (Clarion's queryable
columns) **and** repeats `content_hash_at_compute` **inside** the blob. This
duplication is load-bearing: Clarion's read view **never returns** the top-level
column, so the freshness gate (§4d) reads the stamp from the blob it gets back. The
top-level copy is only for Clarion's own queryable storage.

```json
{
  "schema_version": "wardline-taint-1",
  "qualname": "auth.tokens.TokenManager.issue",
  "content_hash_at_compute": "<blake3-hex of the entity's file>",
  "computed_at": "<ISO-8601 UTC>",
  "taint": {
    "declared_return": "INTEGRAL",
    "actual_return": "EXTERNAL_RAW",
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
| `current_content_hash` field-absent (file deleted/unreadable, even if `exists:true`) | **Stale** → re-run; never served |
| Write returns `unresolved_qualnames` | Reported in summary; those facts silently dropped (exact-only) — not an error |
| `wardline[clarion]` not installed but `--clarion-url` given | Loud: "install `wardline[clarion]`" |

## 10. Testing

- **Unit (no network):** injected fake transport for `resolve`/`write`/`get`/`batch_get`;
  chunking against the 2000 cap; HMAC header construction as a **fixed-vector test**
  against the pinned canonicalization (§11) — including a bodyless-GET vector asserting
  the `sha256(b"")` body hash — cross-checked against Clarion's `component_hmac_hex`
  test vectors in `http_read.rs`; project-guard field set on every request; status-band
  handling routed on `code` (conn/5xx soft, `403 WRITE_DISABLED`/`PROJECT_MISMATCH`
  soft, other 4xx/`413` loud); defensive 2xx parsing (including `current_content_hash`
  field-absent and `wardline_json` field-absent on `exists:false`).
- **Qualname conformance:** assert Wardline's `f"{module_dotted_name}.{__qualname__}"`
  composition reproduces **every** vector in Clarion's
  `wardline-qualname-normalization.json` (vendored or referenced into
  `tests/conformance/`), traps included — the oracle that the exact-only `resolve`
  won't silently miss.
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

## 11. HMAC canonicalization (resolved — pinned from Clarion source)

The former open item is closed. Read from Clarion's `require_hmac_identity` /
`component_hmac_hex` / `canonical_hmac_message` in
`~/clarion/crates/clarion-cli/src/http_read.rs` and pinned in `contracts.md`
§"Authentication":

- **Header:** `X-Loom-Component: clarion:<hmac>` (value trimmed, `clarion:` prefix
  stripped, non-empty signature required).
- **`<hmac>`:** lowercase-hex **HMAC-SHA256** (RFC 2104) of the canonical message.
  Reproduced exactly by Python stdlib
  `hmac.new(secret_bytes, message_bytes, hashlib.sha256).hexdigest()` — including
  Clarion's >64-byte key handling (`key = sha256(secret)`), which is the standard
  HMAC block-key reduction stdlib already performs.
- **Canonical message** — three parts joined by `\n`, **no trailing newline**:

  ```text
  <METHOD>\n<PATH_AND_QUERY>\n<SHA256_HEX_OF_REQUEST_BODY>
  ```

  - `<METHOD>`: uppercase HTTP verb as sent.
  - `<PATH_AND_QUERY>`: the raw request-target (`uri.path_and_query()`) byte-identical
    to the wire — path, plus `?query` only when present. The client signs the exact
    string it sends (percent-encoding and param order included).
  - `<SHA256_HEX_OF_REQUEST_BODY>`: `hashlib.sha256(body).hexdigest()`; bodyless GET →
    `sha256(b"")` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

- **No timestamp, no nonce** in the signed message. This is *not* SHA-256-over-the-body
  as the secret material; it is HMAC-SHA256 over a message that *contains* the body's
  SHA-256. (Distinct again from the **blake3** freshness hash of §4d.)

The client unit test's fixed vector is now fully derivable; the live `clarion_e2e`
round-trip (§10) is the final proof that the byte-exact reproduction is correct against
a running Clarion.

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

Clarion has landed (§2) and the HMAC scheme is pinned (§11), so the Wardline plan is a
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
