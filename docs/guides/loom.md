# Loom integration

Wardline is a citizen of the Loom suite, but integration is **additive, never
load-bearing**: `wardline scan` boots, analyzes, writes findings, and gates with
both siblings absent. The three output paths below are enrichment you opt into.

| Path | How | Consumer |
|---|---|---|
| **SARIF 2.1.0** | `--format sarif --output FILE` | any SARIF tool (GitHub code scanning, CI dashboards) |
| **Native Filigree emitter** | `--filigree-url URL` | Filigree's Loom scan-results lifecycle |
| **Clarion producer conformance** | automatic in `metadata.wardline.qualname` | Clarion entity reconciliation |

## SARIF

SARIF 2.1.0 is a standard interchange format, so this path works with **any**
SARIF consumer — it is not Filigree-specific.

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

`--filigree-url` POSTs findings into Filigree's Loom scan-results lifecycle —
Filigree owns finding *state* (status, seen-count, issue links); Wardline owns
the analysis fact and the local baseline. Pass the full endpoint URL:

```console
$ wardline scan . --filigree-url http://localhost:8377/api/loom/scan-results
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

## Clarion producer conformance

Clarion enriches findings by reconciling Wardline's Python qualnames to Clarion
entity IDs. Wardline's only obligation is to **emit the right qualname** —
Clarion is purely an enrichment consumer, never on the transport path between
Wardline and Filigree.

Wardline emits `metadata.wardline.qualname` as the combined dotted
`module.qualified_name` (e.g. `auth.tokens.TokenManager.issue`), composed with
Clarion's exact module-normalization rules (strip one leading `src/`, drop `.py`,
collapse `__init__.py` to the parent) and the Python `__qualname__` preserved
byte-for-byte (`<locals>` markers and nested-class chains pass through untouched).

A vendored conformance corpus pins Wardline's producer against Clarion's
normalization vectors in CI, converting byte-equality from an assumption into a
test. In Clarion 1.0.0 the reconciliation *consumer* is not yet built, so this
is producer-pinning today; emitting the correct qualname now is what makes future
reconciliation lossless.

## See also

- [Configuration](configuration.md) — `wardline.yaml` keys.
- [Suppressing findings](suppression.md) — how suppression state flows into SARIF and Filigree emission.
