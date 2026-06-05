# Weft integration

Wardline is a citizen of the Weft suite, but integration is **additive, never
load-bearing**: `wardline scan` boots, analyzes, writes findings, and gates with
both siblings absent. The three output paths below are enrichment you opt into.

This "additive, never load-bearing" rule is the federation's enrich-only axiom,
which is defined authoritatively in the Weft hub (`~/weft/doctrine.md` §5) — the
canonical source for the suite's roster and composition doctrine.

| Path | How | Consumer |
|---|---|---|
| **SARIF 2.1.0** | `--format sarif --output FILE` | any SARIF tool (GitHub code scanning, CI dashboards) |
| **Native Filigree emitter** | `--filigree-url URL` | Filigree's Weft scan-results lifecycle |
| **Loomweave producer conformance** | automatic in `metadata.wardline.qualname` | Loomweave entity reconciliation |

## Which path should agents use?

Use **native Filigree emission** (`wardline scan --filigree-url ...`) when the
goal is lifecycle work: deduplicating findings across scans, promoting a
fingerprint to a tracked Filigree issue, reconciling fixed/regressed findings,
or joining open work into a Weft dossier. Native emission sends Wardline's
top-level fingerprint and Wardline metadata directly to Filigree's Weft
scan-results endpoint, so Filigree can preserve the finding identity it uses for
promotion and lifecycle state.

Use **SARIF** when the goal is generic interchange: GitHub code scanning, CI
dashboards, archival evidence, or a tool that only speaks SARIF. SARIF can carry
Wardline identity, but downstream lifecycle behavior depends on the importer
preserving Wardline's fingerprint fields. If an importer drops or rewrites those
fingerprints, later promotion/dedup in Filigree will be weaker than native
emission.

## SARIF

SARIF 2.1.0 is a standard interchange format, so this path works with **any**
SARIF consumer. Treat it as interchange, not the preferred Filigree lifecycle
path.

```console
$ wardline scan src/wardline --format sarif --output results.sarif
```

With `--format sarif` and no `--output`, the default file is `findings.sarif` in
the scan path. The log carries one run with a `wardline` driver, minimal rule
descriptors (the distinct rule IDs seen), and one result per finding —
`ruleId` + `ruleIndex`, a `level` mapped from severity (`CRITICAL`/`ERROR` →
`error`, `WARN` → `warning`, `INFO` → `note`, `NONE` → `none`), a physical
location, and `partialFingerprints` carrying Wardline's stable fingerprint.
Suppressed findings (baseline / waiver / judged) emit a SARIF
`suppressions` entry (`kind: external`, `status: accepted`), with the waiver
reason as the justification.

Downstream importers should preserve
`partialFingerprints["wardlineFingerprint/v1"]` as the finding's lifecycle
identity. If that field arrives empty or is discarded, the imported finding may
still be visible as a generic SARIF result, but Filigree promotion,
deduplication, and close/reopen behavior cannot rely on the same stable identity
as native Wardline emission.

The `--fail-on` gate and suppression annotation run on the findings regardless of
output format, so SARIF output and CI gating compose.

!!! tip "Dogfooded in CI"
    Wardline's own CI scans the `wardline` source to SARIF and uploads it to
    GitHub code scanning:

    ```yaml
    - name: Scan self -> SARIF
      run: wardline scan src/wardline --format sarif --output results.sarif
    - name: Upload SARIF
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: results.sarif
        category: wardline-self-hosting
    ```

## Native Filigree emitter

`--filigree-url` POSTs findings into Filigree's Weft scan-results lifecycle —
Filigree owns finding *state* (status, seen-count, issue links); Wardline owns
the analysis fact and the local baseline. Pass the full endpoint URL:

```console
$ wardline scan . --filigree-url http://localhost:8377/api/weft/scan-results
```

This is layered on top of the normal local output — Wardline still writes
`findings.jsonl` (or your `--output`) and runs the gate; emission is additive.
The emitter is stdlib `urllib` only (no new dependency). Findings of **all**
kinds are sent; each goes on the wire with `path`, `rule_id`, `message`, mapped
lowercase `severity`, line range, a **top-level `fingerprint`** (Filigree's
cross-run identity key), and a `metadata.wardline.*` namespace carrying qualname,
kind, internal severity, and per-rule properties.

The outcome split is **load-bearing for the charter guarantee**:

- **Sibling absent / outage** — connection refused, timeout, or any 5xx: warn and
  continue. The scan proceeds to its gate; the exit code is unaffected. A Filigree
  outage must never make Wardline's gate load-bearing.
- **Client/protocol error** — a 4xx (or stray 3xx): loud failure. Wardline sent a
  request the server rejected — a payload/config bug — so the response body is
  echoed and the command exits `2`, even if findings are otherwise clean.
- **Success** — a one-line summary reports created/updated counts plus any
  server-side `warnings` (Filigree reports severity coercions and line clamps
  there) and partial-ingest failures.

The severity map (Wardline's 4 levels + facts → Filigree's 5) is:

| Wardline | Filigree |
|---|---|
| `CRITICAL` | `critical` |
| `ERROR` | `high` |
| `WARN` | `medium` |
| `INFO` | `low` |
| `NONE` (facts/metrics) | `info` |

## Loomweave producer conformance

Loomweave enriches findings by reconciling Wardline's Python qualnames to Loomweave
entity IDs. Wardline's only obligation is to **emit the right qualname** —
Loomweave is purely an enrichment consumer, never on the transport path between
Wardline and Filigree.

Wardline emits `metadata.wardline.qualname` as the combined dotted
`module.qualified_name` (e.g. `auth.tokens.TokenManager.issue`), composed with
Loomweave's exact module-normalization rules (strip one leading `src/`, drop `.py`,
collapse `__init__.py` to the parent) and the Python `__qualname__` preserved
byte-for-byte (`<locals>` markers and nested-class chains pass through untouched).

A vendored conformance corpus pins Wardline's producer against Loomweave's
normalization vectors in CI, converting byte-equality from an assumption into a
test. In Loomweave 1.0.0 the reconciliation *consumer* is not yet built, so this
is producer-pinning today; emitting the correct qualname now is what makes future
reconciliation lossless.

## Trust-vocabulary descriptor (the cross-product contract)

Wardline's trust-decorator vocabulary (`external_boundary` / `trust_boundary` /
`trusted`) is published as a **versioned, on-disk descriptor** — the canonical
*read-instead-of-import* contract for peers. It is generated from the in-process
`REGISTRY` and shipped in the wheel at `wardline/core/vocabulary.yaml` (emit it
with `wardline vocab`, or read `wardline://vocab` over MCP). The envelope carries
two version axes: `schema` (`wardline.vocabulary/v1`, the descriptor *format*)
and `version` (`wardline-generic-2`, the vocabulary *content*); a byte-identity
drift test keeps the committed file in lock-step with `REGISTRY`.

**Retirement note (Wardline side complete).** Loomweave historically imported
`wardline.core.registry.REGISTRY` in-process (Loomweave ADR-018). Because
`wardline.core` is becoming a **native (compiled) module**, no peer may import
it — the descriptor is the only supported external surface, and reading it needs
no Wardline import. The Wardline side of that retirement is **done**: the
descriptor is the contract, with a `schema` field, a documented location, and a
test proving the vocabulary is consumable from the file's bytes alone. The
remaining half — Loomweave switching its plugin from `import REGISTRY` to reading
the descriptor — is **Loomweave's** change (`loomweave-1f6241b329`; the reader
already exists in Loomweave's tree). See
[ADR: vocabulary descriptor cross-product contract](../decisions/2026-06-05-wardline-vocabulary-descriptor-cross-product-contract.md)
and the [Loomweave hand-off](../integration/2026-06-05-wardline-descriptor-loomweave-handoff.md).

The self-scan side of the native-module migration is handled by a declarative
allowlist, `_NATIVE_FIRST_PARTY_PREFIXES` in `scanner/diagnostics.py` — the
**seam the Rust migration extends** so a compiled `wardline.core` (no Python AST)
doesn't light up `WLN-ENGINE-UNKNOWN-IMPORT`. See
[ADR: native-module import resolution](../decisions/2026-06-05-wardline-native-module-import-resolution.md).

## See also

- [Configuration](configuration.md) — `wardline.yaml` keys.
- [Suppressing findings](suppression.md) — how suppression state flows into SARIF and Filigree emission.
