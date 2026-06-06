# Wardline ← Loomweave ephemeral-port resolution (consumer half of ADR-044)

**Status:** Proposed — implementation handoff.
**Date:** 2026-06-06
**Conforms to:** Loomweave **ADR-044** (Read-API Ephemeral Port Publication) +
**ADR-034** (instance-ID guard). Tracking peer: **clarion-7f574bc34f** (comment 300
carries the contract for the loomweave half).
**Owner:** Wardline. This is the **consumer** side; Loomweave owns the file
contract, Wardline conforms.

## Problem

Wardline resolves the Loomweave taint-store / SEI endpoint by precedence
`explicit --loomweave-url flag > env (_LOOMWEAVE_URL_ENV) > wardline.yaml
loomweave.url` (`src/wardline/core/config.py::resolve_loomweave_url`). Every level
is a **static** URL. Loomweave's installer historically pinned `127.0.0.1:9111`
into every project, so a second project's Wardline reaches the *first* project's
serve. ADR-034's instance-ID guard correctly rejects the cross-project write
(`PROJECT_MISMATCH`, fail-soft) — observed live during the lacuna shakedown — but
federation is silently dead for the mis-targeted project.

ADR-044 fixes the publisher: Loomweave now writes its **live** bound port to
`<project>/.loomweave/ephemeral.port` (loopback-only, port-only, atomic,
present-only-while-serving). Wardline must **consume** that file instead of a
pinned URL. Wardline already does the identical thing for Filigree at *install*
time (`install/detect.py` reads `<root>/.filigree/ephemeral.port`); this is the
runtime twin for Loomweave.

## File contract (consumed, normative — owned by ADR-044)

Wardline implements its **own** reader against the file; it does **not** reuse
Loomweave's Rust resolver. The contract Wardline depends on:

- Path: `<project_root>/.loomweave/ephemeral.port`.
- Content: a single plain-ASCII integer, port only; optional trailing `\n`.
- Host + scheme implied: `http://127.0.0.1:<port>` (loopback-only — see below).
- Lifecycle: written atomically (temp + rename) on successful bind; removed on
  clean shutdown; **present only while serving**.
- **Read, never compute.** Wardline MUST NOT derive/guess the port from any band
  formula — it only reads the published value.
- Loopback invariant: a non-loopback bind (`allow_non_loopback`, ADR-034)
  publishes **no** file, so port-only can never under-specify the host. Absent
  file ⇒ fall back to configured URL.

## Decision

Add a Python published-port reader and insert it into `resolve_loomweave_url` at
one new precedence rung, keeping all other behaviour identical.

### New precedence (normative)

```
explicit --loomweave-url flag       # deliberate target — always wins
> env _LOOMWEAVE_URL_ENV             # deliberate target — always wins
> published .loomweave/ephemeral.port  # NEW: live port beats stale/default config (self-heal)
> wardline.yaml loomweave.url        # static config — last resort
> None                               # no loomweave configured → enrich-only no-op
```

The published file beats `wardline.yaml` (so a stale literal `:9111`/`:9112`
self-heals once a serve is live) but **never** overrides an explicit flag/env
(remote loomweave, debugging). This is exactly ADR-044's "Resolution semantics".

### Implementation

`src/wardline/core/config.py`:

```python
_LOOMWEAVE_PORT_FILE = ".loomweave/ephemeral.port"

def _loomweave_published_url(root: Path) -> str | None:
    """Read Loomweave's live read-API port from <root>/.loomweave/ephemeral.port,
    fail-soft. Returns http://127.0.0.1:<port> or None (missing / unreadable /
    malformed / out-of-range). Read, never compute — ADR-044."""
    port_file = root / ".loomweave" / "ephemeral.port"
    try:
        raw = port_file.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if not raw.isdigit():
        return None
    port = int(raw)
    if not (1 <= port <= 65535):
        return None
    return f"http://127.0.0.1:{port}"
```

Wire into `resolve_loomweave_url` between the env check and the config read:

```python
    if flag is not None:
        return flag
    env = os.environ.get(_LOOMWEAVE_URL_ENV)
    if env:
        return env
    published = _loomweave_published_url(root)   # NEW
    if published is not None:
        return published
    return _config_for(root, config_path, ...).loomweave_url
```

No consumer changes: `cli/scan.py`, `mcp/server.py`, and the dossier/explain
paths all call `resolve_loomweave_url(...)` and inherit the new rung. The
`LoomweaveClient` already fail-softs on a refused connection (`OSError` → soft
sentinel), and ADR-034's instance-ID guard is the correctness backstop if a
**stale** file points at another project's live serve (`PROJECT_MISMATCH` → soft).
So the reader can be simple, not perfect.

## Tests (twin of the filigree_url resolver tests)

Unit (`tests/unit/core/test_config.py` or a new `test_loomweave_port_resolution.py`):
1. published file present ⇒ `resolve_loomweave_url` returns `http://127.0.0.1:<port>`,
   **overriding** a different `wardline.yaml loomweave.url` (self-heal).
2. explicit `flag` and `env` each **win over** a present published file.
3. malformed content (`"abc"`, empty, `"99999"`, `"0"`, negative, trailing junk)
   ⇒ reader returns `None` ⇒ falls through to `wardline.yaml`.
4. missing file ⇒ falls through to config; missing file + no config ⇒ `None`.
5. unreadable file (permission/`OSError`) ⇒ `None`, no raise.

Integration (opt-in, `loomweave_e2e`): a `wardline scan` against a project whose
loomweave serve is bound to a **non-9111** port (publishing its file) resolves the
live port and writes taint successfully — **no `PROJECT_MISMATCH`**. (Reuses the
ephemeral-serve harness in `tests/e2e/test_loomweave_live.py`, which already writes
its own `loomweave.yaml`; extend it to assert resolution from the published file
rather than a hardcoded URL.)

## Migration (transparent)

Once the reader ships, any `wardline.yaml` pinning a literal `loomweave.url`
(`:9111`/`:9112`) is **superseded** by the published file whenever a serve is live
— no user edit required; degraded-but-not-broken when no serve is running.

**Lacuna cleanup (do with this change):** drop the `:9112` stopgap from lacuna's
`wardline.yaml`/`loomweave.yaml` (introduced during the port incident). With the
resolver in place the specimen must not ship a pinned port — the contract exists
to abolish exactly that.

## Related follow-up (separate change, flagged not bundled)

Wardline reads `.filigree/ephemeral.port` only at **install** time
(`install/detect.py`); at **scan** time it uses the static `filigree.url`. If the
federation standardises on consume-time live-port resolution, Wardline's Filigree
leg has the same latent staleness. Recommend a follow-up that gives
`resolve_filigree_url` the symmetric published-port rung (same precedence shape),
so both sibling legs resolve live ports identically. Out of scope for this doc;
do not bundle — it has its own test surface and its own peer (Filigree's
`.filigree/ephemeral.port` is already a published contract).

## Non-goals

- No band/formula knowledge in Wardline (read-never-compute).
- No change to the loud-vs-soft error model (4xx loud, absent/refused soft).
- No change to `LoomweaveClient` wire behaviour or the HMAC signer. The signer
  resync (canonical order + nonce) is a **Wardline↔Loomweave** concern
  (`loomweave/_hmac.py`, verified against loomweave's `auth.rs`) and a
  **Wardline↔Legis** concern (`core/legis.py`) — tracked separately. It is **not**
  a Filigree concern: the Wardline→Filigree intake (`core/filigree_emit.py` →
  `/api/weft/scan-results`) is bearer-only (ADR-018), no HMAC.
