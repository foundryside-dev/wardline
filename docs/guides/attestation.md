# Attestation

An attestation bundle is a **signed, reproducible evidence record**: "at commit X
(clean or dirty), with ruleset hash Y, the declared trust surface had this coverage
and these boundaries held — here is the signature."

Where the [assurance posture](assurance-posture.md) answers *how much* of the trust
surface the engine reached a verdict on today, `attest` **signs and freezes that
answer** so it can be carried forward, transported, and verified later — by a CI
system, a governance plugin like legis, or an agent making a deploy decision.

!!! warning "Threat model — read before trusting a bundle"
    The signature is **HMAC-SHA256 with a shared project key**. This is
    *tamper-evidence within a key-holding trust domain* — not public-key,
    asymmetric, non-repudiable proof of authorship. Verification **requires
    possessing the same secret used to sign**; anyone who holds the key can both
    produce and verify a valid bundle, so the signature does not bind the bundle
    to a specific signer. HMAC is **forced by Wardline's zero-dependency base**
    (Ed25519 / RSA would need a non-stdlib dependency) — not chosen as the
    preferred cryptographic primitive. Do not present a bundle as proof of *who*
    produced it; it proves only that *a holder of the project key* has not tampered
    with it since signing.

## Activation

`wardline install` mints a 64-hex signing key and appends it to `.env` at the
project root as `WARDLINE_ATTEST_KEY="<key>"`. It also ensures `.env` is listed
in `.gitignore` — the key must never be committed. This is the only setup step.
Pass `--no-attest-key` to `wardline install` if you want to skip minting.

The key lookup order at run time: environment variable `WARDLINE_ATTEST_KEY` →
`root/.env` line `WARDLINE_ATTEST_KEY=<value>`. An already-set environment value
always wins, so CI injects the key as a secret env var without touching `.env`.

!!! note "The key never goes in `.weft/wardline/`"
    `.weft/wardline/` holds committed state (baseline, waivers, judged). Writing a
    secret there would let anyone with repo read access forge bundles. `.env` is
    the correct home — it mirrors where `WARDLINE_LOOMWEAVE_TOKEN` lives.

## The bundle shape

A bundle is a JSON object with schema `"wardline-attest-1"`:

```json
{
  "schema": "wardline-attest-1",
  "payload": {
    "wardline_version": "1.0.0",
    "attested_at": "2026-06-03",
    "commit": "a1b2c3d4e5f6...",
    "dirty": false,
    "ruleset_hash": "sha256:deadbeef...",
    "posture": { ... },
    "boundaries": [
      {
        "qualname": "myapp.ingestion.parse_payload",
        "sei": "loomweave:eid:0123456789abcdef0123456789abcdef",
        "verdict": "clean",
        "tier": "ASSURED"
      }
    ],
    "sei_source": "loomweave"
  },
  "signature": {
    "alg": "HMAC-SHA256",
    "value": "7f3a...",
    "key_id": "9a1b2c3d"
  }
}
```

### Payload fields

| Field | Type | Meaning |
|---|---|---|
| `wardline_version` | string | Wardline version that produced the bundle |
| `attested_at` | string | ISO date (`YYYY-MM-DD`) the bundle was built — the bundle states its own date so `--reproduce` re-derives the date-sensitive posture (waiver `days_left`) against the *recorded* date, not the day verify happens to run |
| `commit` | string \| null | `git rev-parse HEAD` at scan time; `null` if not in a git repo or git is absent |
| `dirty` | bool | `true` if `git status --porcelain` was non-empty at scan time |
| `ruleset_hash` | string | `"sha256:<hex>"` over the enabled rules, severity overrides, and Wardline version — pinning the policy that produced the bundle |
| `posture` | object | The full [assurance posture](assurance-posture.md) object from `wardline assure` |
| `boundaries` | list | One entry per declared trust boundary, sorted by qualname |
| `sei_source` | string | `"loomweave"` if a Loomweave store resolved ≥1 SEI; `"unavailable"` otherwise |

### Boundary fields

| Field | Type | Meaning |
|---|---|---|
| `qualname` | string | Fully-qualified function name of the trust boundary |
| `sei` | string \| null | Loomweave SEI (stable, rename-resistant entity identifier) if resolved; `null` otherwise |
| `verdict` | string | `"clean"` / `"defect"` / `"unknown"` — the engine's three-valued verdict for this boundary |
| `tier` | string \| null | Declared trust tier (`"INTEGRAL"`, `"ASSURED"`, `"GUARDED"`, `"EXTERNAL_RAW"`) or `null` |

### Signature fields

| Field | Meaning |
|---|---|
| `alg` | Always `"HMAC-SHA256"` |
| `value` | HMAC-SHA256 hex digest over the canonical (compact, key-sorted) JSON bytes of `payload` |
| `key_id` | First 8 hex characters of `sha256(key)` — non-secret, lets bundles signed with different keys be distinguished |

## Dirty-tree honesty

A dirty working tree means the source files scanned do not exactly match the
recorded `commit`. The CLI and MCP **refuse a dirty tree by default** (CLI: exit
`2`; MCP: `isError` result) to preserve the invariant that a bundle's `commit`
truthfully pins its source.

Pass `--allow-dirty` (CLI) or `allow_dirty: true` (MCP) to override. When you do,
`dirty: true` is recorded in the payload honestly — the bundle is still signed, but
any consumer can see that the scan was not at a clean commit.

## Building a bundle

### MCP (agent-first)

The primary consumer is an agent using the MCP `attest` tool. The MCP server must
be started with `--loomweave-url` to enable SEI-keying (optional); otherwise all
`sei` fields are `null`.

```json
{
  "name": "attest",
  "arguments": {
    "path": "src/myapp"
  }
}
```

The tool returns the full bundle object directly. An `allow_dirty: true` argument
overrides the dirty-tree refusal. When no attest key is found, the tool returns an
`isError` result naming `WARDLINE_ATTEST_KEY`.

### CLI

```console
$ wardline attest src/myapp
{"schema": "wardline-attest-1", "payload": {...}, "signature": {...}}
```

Write to a file with `--out`:

```console
$ wardline attest src/myapp --out bundle.json
```

With SEI-keying:

```console
$ wardline attest src/myapp --loomweave-url http://localhost:9100 --out bundle.json
```

## Verifying a bundle

Verification is two separable checks:

1. **Signature check** — always performed, offline, requires the project key. No
   re-scan. Recomputes the HMAC over the *recorded* payload and compares in constant
   time. A wrong key or any tampered payload field yields `signature_valid: false`.
2. **Reproducibility check** (`--reproduce` / `reproduce: true`) — re-derives the
   payload at the *current* tree and compares canonical bytes. Equal → `reproduced:
   true`. A mismatch may mean the tree moved on since the bundle was produced — not
   necessarily tamper. The `note` field in the result says so explicitly.

The result object from both CLI and MCP `verify_attestation`:

```json
{
  "signature_valid": true,
  "reproduced": true,
  "mismatches": [],
  "note": "reproducibility holds against the RECORDED commit; a mismatch may mean the tree moved, not tamper."
}
```

`reproduced` is `null` when reproducibility was not requested.

### MCP

```json
{
  "name": "verify_attestation",
  "arguments": {
    "bundle": { ... },
    "reproduce": true
  }
}
```

The `bundle` argument is required (the parsed JSON object, not a path). `reproduce`
defaults to `false`. The tool returns the result object above.

CLI exit codes for `--verify`: `0` if `signature_valid`, `1` if not. The
reproducibility result does not affect the exit code.

### CLI

```console
$ wardline attest --verify bundle.json
{"signature_valid": true, "reproduced": null, "mismatches": [], "note": "..."}

$ wardline attest --verify bundle.json --reproduce
{"signature_valid": true, "reproduced": true, "mismatches": [], "note": "..."}
```

## SEI-keying (opt-in, fail-soft)

With a Loomweave store configured (`--loomweave-url` / the server's `--loomweave-url`
flag), each boundary's `sei` is resolved to a Loomweave SEI — an opaque,
rename-stable entity identifier. This makes boundaries resilient to function
renames: a verifier can locate the boundary in the current tree even if its
`qualname` has changed.

`sei_source` is `"loomweave"` only when a client was supplied **and** at least one
SEI resolved. If Loomweave is unreachable or returns no matches, every `sei` is
`null` and `sei_source` is `"unavailable"` — attestation never fails because
Loomweave is unreachable.

Reproducibility of a SEI-keyed bundle requires the same Loomweave store: without it,
`reproduce: true` re-derives with `sei: null` for every boundary and correctly
reports `reproduced: false` while leaving `signature_valid` unaffected.

See [Loomweave taint store](loomweave-taint-store.md) for store setup.

## Agent-first: CI workflow example

A typical pattern — an agent builds the bundle at CI time, stores it as an
artifact, and a verifier (legis, another agent, or a downstream job) checks it
before an action.

**Step 1 — produce a bundle in CI.**

The CI agent calls `attest` at the end of a clean build (tree is at a tagged
commit, no dirty changes):

```python
bundle = call_mcp("attest", {"path": "src/myapp"})
# bundle["payload"]["dirty"] is False — the key invariant
# bundle["payload"]["commit"] pins the scanned state
upload_artifact("attest-bundle.json", bundle)
```

**Step 2 — verify before deploying.**

A downstream agent or CI job retrieves the artifact and verifies:

```python
bundle = load_artifact("attest-bundle.json")
result = call_mcp("verify_attestation", {"bundle": bundle, "reproduce": True})

if not result["signature_valid"]:
    block_deploy(reason="attestation signature invalid — bundle may be tampered")

if result["reproduced"] is False:
    # Tree moved since attestation — expected if the bundle covers an earlier commit.
    # Decide whether to accept or re-attest.
    warn(f"payload mismatch on: {result['mismatches']}")
    warn(result["note"])

# Check the posture embedded in the bundle
posture = bundle["payload"]["posture"]
if posture["coverage_pct"] is not None and posture["coverage_pct"] < 80.0:
    block_deploy(reason=f"trust-surface coverage {posture['coverage_pct']}% below threshold")
```

**legis as a consumer.** The Weft governance plugin (legis) reads attestation
bundles as part of its policy pipeline — the bundle's `posture`, `boundaries`, and
`ruleset_hash` feed legis's trust-gate decisions without requiring legis to
re-scan.

## Determinism guarantee

The canonical bytes signed by HMAC are also the reproducibility target. Two builds
of the same unchanged tree produce byte-identical canonical payloads because:

- Every list in the payload is sorted on a stable key (boundaries by `qualname`;
  the posture sorts its own lists).
- The only date-sensitive field is the posture's `waiver_debt.days_left` — a
  waiver-free tree's payload is fully date-independent.
- `pytest-randomly` ordering in the test suite cannot perturb the bytes — the
  sorting is intrinsic to `_canonical_bytes`, not test-order-dependent.

## See also

- [Assurance posture](assurance-posture.md) — the `posture` embedded in every
  bundle; understand coverage and the honesty gap before reading attestation numbers.
- [Loomweave taint store](loomweave-taint-store.md) — enabling SEI-keyed boundaries.
- [Using Wardline with your coding agent](agents.md) — the full MCP tool surface.
