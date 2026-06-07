# `wardline doctor` — filigree federation-token check + repair

**Date:** 2026-06-07
**Status:** Approved (design)
**Branch:** `rc4`

## Problem

When wardline emits scan findings to a Filigree daemon over the Weft federation
surface (`POST /api/weft/scan-results`), the request carries
`Authorization: Bearer <token>` where the token comes from
`load_filigree_token(root)` (env → `root/.env`, federation name then legacy
fallback). If that token is not the value the **running daemon** accepts, every
emit returns `401` and fails *soft and silent*: the scan still succeeds, findings
are written locally, and the only signal is a `filigree_emit` block the operator
must read. The Filigree tracker looks empty even though wardline holds active
defects.

### Root cause (observed in lacuna, 2026-06-07)

The failure is **not** a missing token or an unauthenticated POST. wardline reads
`root/.env` itself and *does* send a bearer token — just the wrong value. The
real cause is **two independently-minted federation-token stores that disagree**,
with no tier-1 env override to unify them:

- Filigree's federation token is auto-minted **per store-dir**
  (`filigree/federation_token.py`). A daemon launched with `--server-mode`
  resolves its token from `~/.config/filigree/federation_token`; a single-project
  resolution uses `<root>/.weft/filigree/federation_token`. These are minted
  independently and hold **different** secrets.
- In lacuna, the live daemon on `:8749` runs `--server-mode` with no
  `WEFT_FEDERATION_TOKEN` in its environment, so it accepts the
  `~/.config/filigree/` value (call it `W`). lacuna's `.env` carries
  `WARDLINE_FILIGREE_TOKEN` set to the *project-store* value (call it `D`).
- wardline emits `Bearer D`; the daemon only knows `W` → `401`. The Filigree
  MCP client's `.mcp.json` bearer happens to be `W`, so MCP reads work — masking
  the rotation. Empirically: probing the live daemon, `W → HTTP 400` (auth
  passed, sentinel body rejected), `D → HTTP 401` (auth rejected).

This is **not** a stale in-memory daemon and a restart does **not** fix it: the
daemon's token file is unchanged since boot; a restart re-reads `W` and still
rejects `D`. Git history shows recurring `fix(filigree): update authorization
token` commits — the churn of hand-pasting a rotated value with no single source
of truth.

`wardline doctor` should detect this mismatch and repair it.

## Goals

- Detect, from `wardline doctor`, that the token wardline **will emit** is not the
  token the configured Filigree daemon **accepts**.
- Under `--repair`, recover the correct token from local mints and pin it as
  `WEFT_FEDERATION_TOKEN` in `<root>/.env`, removing the stale legacy line.
- Emit a message that distinguishes *token absent* from *token present but
  rejected* — the existing `filigree_emit.py` 401 string ("set
  WEFT_FEDERATION_TOKEN") reads as "no token," which is what originally
  misdirected diagnosis.

## Non-goals (YAGNI)

- Reconciling the **Filigree MCP-client** bearer in `.mcp.json` — that is
  Filigree's client config, not wardline's emit path. doctor fixes only the token
  **wardline emits** (`.env`). A drifted MCP bearer is out of scope (noted, not
  touched).
- Re-minting or editing Filigree's store files (`federation_token`).
- Cross-host recovery: if the daemon authenticates against a `WEFT_FEDERATION_TOKEN`
  env override that no local file matches, doctor cannot recover the value — it
  reports the situation and the operator action, and writes nothing.

## Design

### New check: `filigree.auth`

A `DoctorCheck` added to `machine_readable_doctor`, alongside the existing
checks, and surfaced in the human `doctor` output.

#### Probe-URL resolution (precedence)

doctor must probe the **same daemon the emit path hits**. The emit URL in the
real (MCP) setup lives in `.mcp.json`, not in env/config, so a plain
`resolve_filigree_url(None, root)` returns `None` and would never probe. The
probe URL therefore resolves by:

1. `--filigree-url` flag (new, optional on `doctor`, mirrors `scan`)
2. `WARDLINE_FILIGREE_URL` env var
3. **`.mcp.json` → `mcpServers.wardline.args` → value after `--filigree-url`**
   (doctor already parses `.mcp.json` for `_check_project_mcp`)
4. published-port rung (`.weft/filigree/ephemeral.port`, legacy
   `.filigree/ephemeral.port`)

If none resolve → `ok`, message `"filigree not configured; nothing to verify"`.

#### Token

`load_filigree_token(root)` — exactly the value emit would send.

#### Detection (read-only; runs without `--repair`)

| Condition | Result |
|---|---|
| URL resolves, token is `None` | `error` — `"no federation token set; export WEFT_FEDERATION_TOKEN or add it to .env"` |
| Resolved URL is **non-loopback** | `ok` — `"non-loopback filigree; token not probed"` (never send a bearer off-box) |
| Probe → `401`/`403` | `error` — `"emit token rejected by filigree (<status>); the configured token is not what the daemon accepts"` |
| Probe → unreachable (conn refused / timeout) | `ok` — `"filigree daemon not reachable; token not verified"` |
| Probe → any other status (e.g. `400`, `2xx`) | `ok` |

**Probe mechanism:** `POST <url>` with a **sentinel body `{}`** and the bearer,
~2 s timeout. Filigree's auth middleware runs *before* body validation, so a good
token yields `400` (request rejected, **nothing recorded**) and a bad token
yields `401/403`. This is **not** `emit([])`, which would POST a valid
empty-findings body and could register an empty scan.

#### Repair (`--repair`; only when detection saw `401`/`403`)

1. Collect candidate tokens from locally-readable mints, in order:
   - `~/.config/filigree/federation_token` (server-mode store)
   - `<root>/.weft/filigree/federation_token` (project store)

   The already-rejected `.env`/env value is skipped.
2. Probe each candidate against the daemon (same sentinel POST). A daemon accepts
   exactly one token, so at most one **distinct** value can authenticate.
3. Outcome:
   - **Exactly one accepted** → surgically rewrite `<root>/.env`: set
     `WEFT_FEDERATION_TOKEN=<value>`, remove any stale `WARDLINE_FILIGREE_TOKEN=`
     line, preserve all other lines, `chmod 0600`. Mark `fixed`; re-probe to
     confirm `ok`.
   - **None accepted** → `error`, **no write**: `"no local federation_token matched
     the daemon — it likely uses a WEFT_FEDERATION_TOKEN env override; set that
     same value in .env"`.

### Code surface

- **`core/filigree_emit.py`** — add `FiligreeEmitter.verify_token() -> ProbeResult`
  (a small frozen dataclass: `accepted: bool`, `reachable: bool`,
  `status: int | None`). Reuses the existing auth-header construction and the
  injectable `Transport` seam. Sends the sentinel body. Does **not** reuse
  `emit()`.
- **`install/doctor.py`** — `_check_filigree_auth(root, *, repair: bool,
  filigree_url: str | None)` returning a `DoctorCheck`; helpers:
  - `_resolve_probe_url(root, flag)` (precedence above, incl. `.mcp.json` arg
    extraction)
  - `_filigree_token_candidates(root)` (the two store-dir files)
  - `_rewrite_env_token(env_path, value)` (surgical `.env` update + legacy-line
    removal + `0600`)

  Wire `_check_filigree_auth` into `machine_readable_doctor`. The repair path runs
  inside the existing `fix` flow.
- **`cli/doctor.py`** — add optional `--filigree-url` passthrough; thread it to
  `machine_readable_doctor` / `_check_filigree_auth`.

### Loopback discipline

The bearer is only sent to loopback origins. A non-loopback resolved URL skips the
probe entirely (reports `ok` / not-probed) rather than transmitting the token
off-box — mirroring the existing Loomweave token-origin discipline.

## Testing

Unit tests with an **injected prober / `Transport` stub** — no real network:

- Detection: rejected (`401`) → `error`; token `None` → absent-message `error`;
  unreachable → non-failing `ok`; non-loopback → skipped `ok`; URL unresolved →
  `ok`.
- Probe-URL resolution: flag > env > `.mcp.json` arg > published port; the
  `.mcp.json`-arg rung exercised explicitly (the lacuna shape).
- Repair: rejected + exactly-one-candidate-accepted → `.env` rewritten,
  `WEFT_FEDERATION_TOKEN` set, legacy `WARDLINE_FILIGREE_TOKEN` line removed,
  unrelated lines preserved, mode `0600`, re-probe `ok`/`fixed`.
- Repair: rejected + no-candidate-accepted → no write, guidance `error`.
- `verify_token()`: maps `401/403 → accepted=False`, `400/2xx → accepted=True`,
  transport error → `reachable=False`.

**Acceptance oracle (manual, already performed):** against the live lacuna daemon,
`W → HTTP 400`, `D → HTTP 401`, garbage `→ 401`. No real-network test enters the
default suite.

## Rollout

- Lands on `rc4` with the rest of the release-candidate work (single-RC-branch
  discipline).
- Pure addition: a new check + new emitter method + a new optional flag. No
  behavior change to existing checks, `scan`, or `emit`.
