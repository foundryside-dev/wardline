# Signed scan handoff to legis

[legis](weft.md) is the Weft suite's governance plugin. An agent runs a Wardline
scan and hands the result to legis at `POST /wardline/scan-results`; legis
**governs** that scan — routes its active defects into the enforcement model — and
**never re-analyses**. Wardline is the one judge; legis carries the verdict.

This guide covers the **authenticated** handoff: how Wardline produces a *signed*
scan artifact so legis can be configured to require authenticated evidence and
reject unsigned or tampered bodies.

!!! note "Humans on the loop"
    The agent operates the hop end to end — Wardline emits the signed artifact, the
    agent posts it, legis governs. The shared secret is the one piece of operator
    setup; everything else is activation, not configuration.

## The wire

A scan posted to legis is a JSON object with provenance, the findings, and a
signature:

```json
{
  "scanner_identity": "wardline@1.0.0rc1",
  "rule_set_version": "sha256:9f86d0…",
  "commit_sha": "0a4a00e…",
  "tree_sha": "4b825dc…",
  "scan_scope": {
    "schema": "wardline-legis-scan-scope-1",
    "scan_root": ".",
    "is_git_root": true,
    "source_roots": ["."],
    "resolved_source_roots": ["."],
    "scanned_paths": ["src/service.py"]
  },
  "findings": [ … ],
  "artifact_signature": "hmac-sha256:v2:73eb9f0c…"
}
```

The agent posts it verbatim as the `scan` field:
`{"cell": "…", "agent_id": "…", "scan": <artifact>}`.

* **`scanner_identity`** — `wardline@<version>`.
* **`rule_set_version`** — the effective-policy hash (`sha256:…`), identical to the
  one [`attest`](attestation.md) signs. Two artifacts with the same value were
  produced under the same rules.
* **`commit_sha` / `tree_sha`** — the committed revision and its tree object SHA.
* **`scan_scope`** — the signed scope binding: scan root, whether that root is the
  git toplevel, configured and resolved `source_roots`, and the files actually
  scanned. A signed CI artifact must have `"is_git_root": true`.
* **`artifact_signature`** — `hmac-sha256:v2:<hex>` over the canonical JSON of every
  other field (see [Signing](#signing)).

## Producing the artifact

### From the CLI (CI pipelines)

```bash
wardline scan . --format legis --output /tmp/scan.legis.json
```

When the [shared secret](#provisioning-the-shared-secret) is provisioned the artifact
is signed; otherwise it is emitted with provenance but no signature (legis records it
as `unverified` — the trust-the-agent posture before a key is set).

!!! warning "Write the artifact outside the working tree when signing"
    Signing requires a **clean, committed** tree, and `git status` counts untracked
    files — so writing the artifact *into* the repo would dirty the tree and the next
    signed run would refuse. Write it to a temp path (as above) or add it to
    `.gitignore`. A dirty or non-git tree under signing fails loudly (exit 2): a
    `tree_sha` that does not match the scanned content is false provenance, so it is
    refused rather than emitted.

!!! warning "Signed artifacts are repository-root scans"
    When `WARDLINE_LEGIS_ARTIFACT_KEY` is provisioned, Wardline signs only when `PATH`
    is the containing git repository root. A subdirectory scan still emits an unsigned
    dev artifact when requested without a key, but it cannot be presented as verified
    evidence for the repository commit/tree.

!!! tip "Dev/tour loop on a dirty tree: `--allow-dirty`"
    Signing is clean-tree-only, but you do not need a commit to exercise the
    Wardline→legis handshake. Pass `--allow-dirty` (CLI) / `allow_dirty: true` (MCP
    `scan`) to emit an **unsigned**, clearly-marked artifact on a dirty tree:

    ```bash
    wardline scan . --format legis --allow-dirty --output /tmp/scan.legis.json
    ```

    The artifact carries `"dirty": true` and **no** `artifact_signature`; legis records
    it as `unverified`. The committed tree is never signed as if it described dirty
    working content. Use it for the dev loop and the tour — never to gate CI.

### From the MCP server (agents)

The `scan` tool attaches the artifact automatically once the secret is provisioned —
no extra argument:

```json
{
  "legis_artifact": { "scanner_identity": "wardline@…", "…": "…", "artifact_signature": "hmac-sha256:v2:…" },
  "legis_artifact_status": { "configured": true, "signed": true, "key_id": "121b69a8", "reason": null }
}
```

The agent posts `legis_artifact` verbatim. When no secret is set the block is absent
(default response unchanged); pass `legis_artifact: true` to emit an **unsigned**
artifact for legis's optional-verify posture. The block is **fail-soft** — a signing
refusal (dirty/non-repo tree) reports `signed: false` with a `reason` and omits the
postable artifact; it never fails the scan.

!!! note "Signing is a clean-checkout / CI operation"
    Because signing refuses a dirty tree (and `git status` counts untracked files), an
    interactive session with a work-in-progress tree will see `signed: false` nearly
    every time — that is expected, not a bug. The authenticated handoff is designed to
    run in CI on a clean checkout (or after committing); the unsigned `unverified`
    artifact is the right shape for the trust-the-agent posture during development.

## Provisioning the shared secret

legis reads its key from `LEGIS_WARDLINE_ARTIFACT_KEY`; Wardline reads the **same
secret** from `WARDLINE_LEGIS_ARTIFACT_KEY` (environment, or a
`WARDLINE_LEGIS_ARTIFACT_KEY=…` line in the project `.env`, which should be
gitignored). The two values must be byte-identical UTF-8 for the signature to verify.

```bash
# generate once, provision the SAME value on both sides
export WARDLINE_LEGIS_ARTIFACT_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
# … and on the legis deployment:
export LEGIS_WARDLINE_ARTIFACT_KEY="<same value>"
```

Until legis sets its key it stays in optional-verify mode: it accepts unsigned bodies
and records provenance as `unverified`. Once legis sets the key it **requires** a
valid signature and the four provenance fields — unsigned or tampered bodies are
rejected (HTTP 422). That flip is the deliberate breaking change; coordinate it with
whoever deploys legis.

### Rotation

The non-secret `key_id` (`legis_artifact_status.key_id`, the first 8 hex of
`sha256(key)`) lets both sides confirm they hold the same secret **without revealing
it**. To rotate: provision the new secret on both sides, confirm the `key_id` matches,
then retire the old value. The `hmac-sha256:v2:` prefix versions the scheme, so a
future canonicalisation change can be introduced without ambiguity.

## Signing

`artifact_signature = "hmac-sha256:v2:" + HMAC_SHA256(key, canonical_json(fields))`,
lowercase hex, where `fields` is the whole scan **minus** `artifact_signature`, and
`canonical_json` is sorted-key, tight-separator (`,`/`:`), non-ASCII-preserving,
NaN-rejecting JSON — byte-identical to legis's `canonical.py`. The signer is pinned by
a golden vector captured from the real legis signer and a hermetic conformance test
([`tests/conformance/test_legis_intake_contract.py`](https://github.com/foundryside-dev/wardline)).

!!! warning "Threat model"
    HMAC-SHA256 with a **shared secret** is tamper-evidence within a key-holding trust
    domain — not asymmetric, non-repudiable proof of authorship. Anyone holding the
    key can both produce and verify a valid signature, so it does not bind the
    artifact to a specific signer. HMAC is forced by Wardline's zero-dependency base.
    Treat the key like any deployment secret.

## What legis receives: the trust-tier projection

The signed artifact carries the **whole scan** — every finding, including engine
(`WLN-ENGINE-*`) facts — so legis's recorded `finding_count` stays honest and the
payload matches the original unsigned handshake. legis routes only the active defects;
non-defect kinds are carried and counted but not routed. Wardline does not cap the
list — legis enforces its own 500-finding limit, and a larger scan is rejected loudly
rather than silently truncated.

Each finding is projected onto legis's accepted vocabulary, because legis validates
the wire strictly where Wardline's rich finding shape is loose:

* **Properties carry trust tiers, verbatim.** legis carries Wardline's eight-tier
  trust vocabulary (`INTEGRAL`, `ASSURED`, `GUARDED`, `EXTERNAL_RAW`, `UNKNOWN_RAW`,
  `UNKNOWN_GUARDED`, `UNKNOWN_ASSURED`, `MIXED_RAW`) and rejects any property value
  that is not one of them. Wardline also stores analysis diagnostics in `properties`
  (`sink`, `callee`, `markers`, …); those are **not** part of the trust grammar and
  are dropped from the legis wire. The rich MCP / SARIF / Loomweave output keeps them.
* **Suppression proof travels in `properties`.** A non-active defect carries its
  `suppression_reason` (synthesised if absent) as a proof entry legis requires.
* **Suppression states are mapped.** Wardline's `baselined` and `judged` both ride
  legis's generic `suppressed` bucket; `waived` stays `waived`; `active` stays
  `active`. Because active stays active, legis's independently-derived gate population
  equals Wardline's `summary.active` exactly — the one-judge property, proven by the
  conformance test.

The trust **vocabulary** is identical on both sides and is asserted in CI; only the
non-grammar diagnostics are elided.
