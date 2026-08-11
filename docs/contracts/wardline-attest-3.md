# Contract: `wardline-attest-3` (producer: wardline · consumer: warpline)

## Status — DRAFT / non-normative S0 preview

**`wardline-attest-3` is a DRAFT.** Wardline does **not** emit it: the shipped builder
still writes `wardline-attest-2` (frozen by `tests/conformance/test_attest_contract_freeze.py`),
and `ATTEST_SCHEMA` is unchanged. What ships in S0 is the **consumer-first dual-read** — the
verifier *recognises* v3 before the builder *emits* it, so no consumer has to be updated in
the same release that changes the wire.

- Consumers **dual-read**: accept `wardline-attest-2` **and** `wardline-attest-3` today.
- Wardline emits v3 only after the **Rollout Fence**; `published_emission_ready` stays false
  until then.
- The payload fields below are a **DRAFT/S0 preview** drawn from declaration-surface-v2
  §11.2. S1 produces the first real serializer output, and that output must be **byte- and
  semantic-compared** against the shared vector before this document or the vector is
  treated as normative. Until then, do not build a consumer that *requires* any v3-only key.

## Envelope

Identical in shape to `wardline-attest-2`:

```json
{"schema": "wardline-attest-3", "payload": {...}, "signature": {...}}
```

- The signature is **HMAC-SHA256** over the compact, key-sorted JSON of the envelope
  `{"schema", "payload"}` — the outer schema tag is bound, so a schema relabel cannot
  verify against the wrong wire contract.
- `signature` is `{alg: "HMAC-SHA256", value: <hex>, key_id: <8 hex>}`, where `key_id` is
  the first 8 hex characters of `sha256(key)` — a non-secret short id that tells bundles
  signed under different keys apart without revealing either.
- **Shared-secret tamper-evidence within a key-holding domain, NOT non-repudiable proof of
  authorship.** Anyone holding the key can both produce and verify a bundle. Authorship
  lives in git, never in the HMAC.

## Payload

Everything `wardline-attest-2` carries — `wardline_version`, `attested_at`, `commit`,
`dirty`, `ruleset_hash`, `posture`, `boundaries[]` (`{qualname, sei, content_hash, verdict,
tier}`), `sei_source`, `sei_diagnostics[]` — with the same meanings and the same consumer
rules, **plus** the proposed declaration fields:

| Key | Type | Meaning (DRAFT) |
| --- | --- | --- |
| `declarations` | list | One entry per declaration in scope: `{declaration_id, kind, content_digest, verification_class, subject}`. `kind` ∈ the declaration-surface families; `verification_class` records whether the claim was machine-verified or is record-only. |
| `declaration_counts` | object | Per-family totals: `{contracts, facets, restoration, sensitivity, dependency_taint}`. |
| `declaration_debt` | object | Outstanding declaration debt: `{lapsed_expiries, stale_dependency_pins, record_only_claims}`. A non-zero count is **debt, not a verdict**. |
| `grants` | object | The trust grants the run was executed under: `{trusted_packs, trust_dependency_taint, strict_defaults}`. |
| `dependency_taint_digest` | string \| null | Digest of the dependency-taint input set, or `null` when dependency taint was not computed. |
| `authorship_note` | string | Fixed caveat restating that the HMAC attests domain-internal integrity, not third-party identity. |

Consumer rule (unchanged in spirit from v2): a declaration is **evidence about a claim**,
never a substitute for `boundaries[].verdict`. `record_only_claims > 0` does not upgrade
anything, and no consumer may derive a clean verdict from `declarations`.

## Shared vector

`tests/conformance/fixtures/wardline-attest-3.vector.json` is the **shared conformance
vector**. Warpline vendors it **byte-for-byte** and re-derives its HMAC as the cross-impl
pin (`tests/conformance/test_attest_dual_read.py` freezes the Wardline side; the Layer-2
byte-comparison arms when `WARPLINE_REPO` is set).

Its signing key is the **public, test-only** string:

```
wardline-attest-3-conformance-vector-key
```

That key is a conformance artifact and **never an operational secret**. It must not be used
to sign a real bundle, and a real key must never be used to regenerate the vector. The
vector's status is `DRAFT/S0 preview` — the HMAC pin makes any later edit loud, which is
the point: S1's first real serializer output gets compared against these exact bytes before
anything replaces them.

## Verification profiles

The two consumers of a bundle are **not** symmetric, and conflating them is the failure this
section exists to prevent.

**1. The Wardline verifier (key-holding domain).** Holds the shared key. Reports
`schema_recognized` alongside `signature_valid`, and HMAC-verifies **both** `wardline-attest-2`
and `wardline-attest-3`. `schema_recognized=False` names an unrecognised schema as the cause
and forces `signature_valid=False` — an unrecognised schema is *not* a validity verdict, and
it is distinguishable from a wrong key or a tampered payload even when the bundle was
correctly re-signed over its own unknown tag (the signer binds the recorded schema).

**2. The Warpline runtime (untrusted relay).** Receives a **pushed, untrusted** bundle,
holds **no** Wardline key, **never** verifies the HMAC, and therefore **always** reports
`signature_verified: false`. Its work is a mechanical commit / SEI / content-hash relay, not
cryptographic verification. A `false` there means *"not checked here"*, not *"checked and
failed"*.

The operational sequence is therefore:

1. In the key-holding domain, run `wardline attest . --verify bundle.json`.
2. Require **both** `schema_recognized` and `signature_valid` to be true.
3. Hand the **exact verified bytes** to Warpline.
4. Treat Warpline's result as a mechanical relay, never as a second cryptographic check.

## Migration

- **`wardline-attest-2` verifies unchanged.** It stays in `ACCEPTED_ATTEST_SCHEMAS`, keeps
  `schema_recognized=True`, and no v2 consumer breaks. The accepted set is written as string
  **literals** precisely so that bumping `ATTEST_SCHEMA` in S1 cannot silently drop v2.
- **`wardline-attest-1` remains rejected** — it is not in the accepted set, so it reports
  `schema_recognized=False` and `signature_valid=False`.
- A v3 bundle verified **before** S1 signature-verifies against its own recorded tag, but
  `--reproduce` re-derives the *current* builder's payload — so it honestly reports the
  v3-only keys as `mismatches` while `signature_valid` stays true. This is the
  `sei_diagnostics` precedent from v2, not a defect.

## Versioning

A change to the boundary key set, the `verdict` vocabulary, or the declaration field set is
a schema bump and must update this doc, `test_attest_contract_freeze.py`,
`test_attest_dual_read.py`, and warpline's consumer. Tracked under `wardline-c0563eee74`.
