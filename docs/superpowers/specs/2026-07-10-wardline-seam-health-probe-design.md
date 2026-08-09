# Wardline Seam-Health Probe Design

**Status:** approved design — ready for implementation planning
**Date:** 2026-07-10
**Product record:** PDR-0002 / PRD-0002 / `wardline-c66f62894b`

## Caveman summary

An empty answer can mean two different things:

- the seam is genuinely clean; or
- the seam is broken and Wardline cannot see the data.

Those must never look the same. Wardline will report a machine-readable reason
for every seam, then deliberately send a harmless probe through the real
consumer paths where that is possible. A peer that cannot participate is an
explicit amber result, never a clean result.

## Goal

Implement PRD-0002 criteria 1 and 2 without changing Wardline's analyzer
results, scan gate, base dependencies, or requiring a user to configure a new
feature. The finished surface answers two questions:

1. What can Wardline itself prove about each Wardline-owned seam?
2. For a seam Wardline consumes, can a real producer-to-consumer exchange be
   retrieved and checked rather than trusted because a peer reported a status?

The success condition remains G2-seam: no Wardline-owned seam may return an
empty, partial, stale, or unsupported result without a machine-readable reason.

## Scope and non-goals

This is Wardline residency, scope B.

- Wardline implements the self-check, the two consumer adapters, the CLI/MCP
  projections, and tests.
- Existing Loomweave identity-resolution and Warpline reverify-worklist wires
  are exercised through Wardline's real clients and parsers.
- A peer that lacks the required live probe behavior produces
  `peer_probe_unsupported`; Wardline records that honestly and does not add a
  peer endpoint or make the bet depend on a sibling release.
- This does not add the hub-owned Layer-3 federation roll-up, change peer
  protocol schemas, create analyzer rules, or make probes a scan gate.
- This does not bundle the wider CLI JSON-normalization program. It adds the
  read-only JSON form needed for the new doctor seam report only.

## User-facing surface

### CLI

`wardline doctor` keeps its existing behavior.

```text
wardline doctor --seams
wardline doctor --seams --probe
wardline doctor --seams --format json
wardline doctor --seams --probe --format json
```

- `--seams` runs Layer 1 only: Wardline's local, read-only seam checks.
- `--probe` is valid only with `--seams`; it additionally runs Layer 2 for
  Wardline's consumer seams.
- `--format json` emits the same structured seam report that MCP returns. It is
  read-only and independent of `--repair` / the legacy `--fix` repair path.
- A probe never runs as part of `wardline scan`, never writes a project artifact,
  and never changes a scan verdict.

Human output is a short row per seam containing the seam id, status, reason
code, and action. JSON is the contract for agents and tests.

### MCP

The existing `doctor` tool gains optional `seams: bool = false` and
`probe: bool = false` arguments. `probe: true` without `seams: true` is a typed
validation error. When `seams` is requested, the tool appends a `seams` report
to the existing doctor envelope; otherwise its current output is unchanged.

CLI and MCP call the same core report builder. Neither surface reimplements
reason selection, status aggregation, or redaction.

## Shared seam-health model

Create a small core model, independent of Click, MCP, and scan orchestration.
It owns the fixed Wardline seam inventory, probe dispatch, and JSON-safe report
construction.

```python
@dataclass(frozen=True)
class SeamReason:
    code: str
    message: str
    next_action: str | None = None

@dataclass(frozen=True)
class SeamLayerResult:
    status: Literal["ok", "amber", "error", "not_run"]
    reason: SeamReason
    key_id: str | None = None
    evidence: Mapping[str, str] = field(default_factory=dict)

@dataclass(frozen=True)
class SeamPosture:
    seam_id: str
    layer1: SeamLayerResult
    layer2: SeamLayerResult

@dataclass(frozen=True)
class SeamHealthReport:
    version: Literal["wardline.seam_health.v1"]
    probe_requested: bool
    seams: tuple[SeamPosture, ...]
```

Every layer result has a reason, including success (`reason.code == "ok"`) and
a probe intentionally not requested (`reason.code == "probe_not_requested"`).
No boolean-only or null-reason result is valid.

The initial bounded reason vocabulary is:

```text
ok
probe_not_requested
not_configured
dependency_missing
peer_unreachable
authentication_failed
key_missing
key_mismatch
schema_mismatch
scheme_mismatch
freshness_mismatch
malformed_response
partial_result
peer_probe_unsupported
local_check_failed
```

`key_id` is included only when the underlying seam already exposes a non-secret
key identifier. Secret values, token values, URLs with paths/query strings, and
raw peer response bodies are never placed in the report.

The report has a stable seam order and one fixed row for each Wardline-owned
surface:

1. `wardline.filigree_emit`
2. `wardline.legis_attest`
3. `wardline.loomweave_sei_read`
4. `wardline.warpline_worklist_read`
5. `wardline.delta_scope_artifact`
6. `wardline.sei_source_drift`

This list is derived from PRD-0002's closed surface set, not from a peer reply.
A missing adapter is therefore a local check failure, not an omitted row.

## Layer 1: self-check adapters

Layer 1 asks only questions Wardline can answer without trusting a peer's health
field. Each adapter returns a `SeamLayerResult`; it does not throw a soft
transport or configuration failure into a generic doctor exception.

| Seam | Local evidence | Success | Honest non-success |
| --- | --- | --- | --- |
| Filigree emit | effective scoped URL, authenticated probe posture, emit accounting capability | authenticated route and partial-result accounting available | `not_configured`, `peer_unreachable`, `authentication_failed`, or `partial_result` |
| Legis attest | configured artifact-key posture and derived non-secret key id | key present and key id available | `key_missing` or `key_mismatch` |
| Loomweave SEI read | resolved URL, optional-extra availability, Wardline client construction | client can make the configured identity-read request | `not_configured`, `dependency_missing`, `peer_unreachable`, or `authentication_failed` |
| Warpline worklist read | current parser and `warpline.reverify_worklist.v1` contract support | expected schema and parser are available | `schema_mismatch` or `local_check_failed` |
| Delta-scope artifact | live `wardline.delta_scope.v1` producer and consumer contract identifiers | declared artifact version is the version Wardline consumes | `schema_mismatch` |
| SEI source drift | required local conformance evidence and live-oracle marker registration | source-drift guard is present and recognized | `local_check_failed` |

Layer 1 must not send a scan-results payload, write a taint fact, mint an
attestation, alter a baseline, or repair configuration.

## Layer 2: consumer round-trip adapters

Layer 2 exists only for the two seams where Wardline consumes peer data:

- Loomweave SEI identity read
- Warpline reverify-worklist read

The common adapter contract is:

1. Obtain a producer-originated reserved-prefix probe value through the existing
   producer wire or its existing testable producer path.
2. Send it through Wardline's production client/parser — no duplicated decoder
   and no read of a self-reported health field.
3. Assert all three facts:
   - the expected value is retrievable under the stated identity scheme;
   - producer-emitted and consumer-accepted key sets agree for the contract
     portion Wardline relies on; and
   - the returned freshness anchor agrees with the live anchor available to the
     adapter (`content_hash` / current source identity for SEI, contract and
     generated-at/completeness evidence for the worklist).
4. Deliberately send a scheme-drifted sentinel. It must return
   `scheme_mismatch`, `schema_mismatch`, or another non-`ok` reason — never an
   empty successful hit.

Adapters use a narrowly injected transport/producer boundary so unit tests can
exercise every result without a sibling process. Live tests use the real HTTP
identity route or the real Warpline worklist artifact and are marked with the
existing live-oracle discipline.

If the configured peer cannot carry the reserved probe through its existing
surface, the adapter returns `amber / peer_probe_unsupported` with the peer and
capability named in redacted evidence. This is a real, inspectable health fact;
it never becomes `ok`, and it does not force a peer implementation change into
Wardline scope B.

## Aggregation and exit behavior

The structured report deliberately separates truth from command policy:

- `status: ok` means the requested check proved its stated condition.
- `status: amber` means Wardline learned an operational limitation or peer
  nonconformance and supplied an action; it is never silently folded into `ok`.
- `status: error` means Wardline could not perform a required local check or
  detected a local contract violation.
- `status: not_run` means Layer 2 was not requested and carries
  `probe_not_requested`.

`doctor --seams` exits nonzero only for an `error` Layer-1 result. `--probe`
adds its Layer-2 results to the report but does not modify scan behavior or
create durable state. Automation that needs stricter policy reads the structured
statuses; Wardline does not silently impose that policy on a scan.

## Error handling and security boundaries

- All configured peer URLs continue through the existing scheme, host, redirect,
  and credential-redaction guards. A probe never accepts a caller-supplied peer
  URL over MCP.
- The new core model receives resolved configuration from existing configuration
  resolution; it does not add another URL or token ladder.
- Secret material is absent from all model fields, human output, exceptions, and
  test fixtures.
- Probe request values use a reserved prefix and bounded, deterministic test
  payloads. They are read-only and may not be persisted by Wardline.
- Transport, parsing, and schema failures map to a specific reason code at the
  adapter boundary. They must not collapse to `[]`, `{}`, `None`, or `ok`.

## Verification

The implementation plan must include these tests before production code:

1. Core model tests prove all six rows are present in stable order and every
   Layer-1/Layer-2 result has a reason.
2. Per-adapter tests cover success plus missing key, authentication failure,
   unreachable peer, malformed payload, partial result, unsupported peer probe,
   and scheme drift as applicable.
3. CLI tests pin flag validation, human output, read-only JSON output, and exit
   policy.
4. MCP tests pin input validation, output schema, structured content, and exact
   CLI/MCP report parity.
5. Consumer-adapter tests prove a drifted sentinel cannot become a clean miss and
   prove producer/consumer key-set mismatch is visible.
6. A regression test proves `wardline scan` neither invokes a probe nor changes
   its active-finding population when seam health is enabled.
7. Existing full-suite, self-scan byte-identity, and dependency checks prove G1,
   G3, and G4 hold.

## Acceptance mapping

| PRD criterion | Design answer |
| --- | --- |
| 1 — Layer-1 self-check | shared six-row report, mandatory reason, non-secret `key_id`, CLI/MCP parity |
| 2 — Layer-2 consumer round-trip | two adapter probes through production clients/parsers, key-set and freshness checks, negative drift scenario |
| 3 — producer artifacts | already closed; this design only reports their local posture |
| 4 — no confident-empty | all outcomes have a reason; partial failures remain explicit |
| 5 — G1/G3/G4 | read-only, no scan-gate path, no new runtime dependency, exact regression coverage |
| 6 — Wardline scope B | unsupported peer is amber evidence, not a Wardline release dependency |

## Consequences

This design adds a small, stable diagnostic contract. It intentionally makes
some previously quiet federation limitations visible. That is success: agents
can now distinguish “clean” from “Wardline cannot prove clean.”

The next artifact is an implementation plan with exact files, tests, and commit
boundaries. It must preserve the shared-core boundary and use the current
doctor/CLI/MCP wrappers rather than creating another health-report projection.
