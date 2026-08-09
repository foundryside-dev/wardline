# MCP Scan `counts_by_kind` Design

**Status:** approved design
**Date:** 2026-07-12
**Implementation ticket:** `wardline-8ae1d6a995`
**Deferred qualification redesign:** `wardline-6114834aef`

## Goal

Add deterministic, whole-scan finding-kind counts to the MCP `scan` response so an
agent can distinguish defects, facts, classifications, metrics, and suggestions
without downloading or reconstructing the full finding population.

This is the deliberately narrow salvage from the abandoned
`codex/c16-scan-summary` prototype. It does not rebase that branch and does not carry
forward its `completeness`, `confidence`, or single-`advisory` fields.

## Contract

The MCP `scan` response gains one required member under its existing top-level
`summary` object:

```json
{
  "summary": {
    "total": 12,
    "active": 2,
    "baselined": 1,
    "waived": 0,
    "judged": 0,
    "informational": 9,
    "unanalyzed": 0,
    "counts_by_kind": {
      "defect": 3,
      "fact": 4,
      "classification": 2,
      "metric": 2,
      "suggestion": 1
    }
  }
}
```

`counts_by_kind` always contains exactly these five keys, in the canonical
`wardline.core.finding.Kind` order:

1. `defect`
2. `fact`
3. `classification`
4. `metric`
5. `suggestion`

Every value is a non-negative integer. Kinds absent from a scan are emitted with
value `0`; keys are never omitted. No `unknown` or caller-defined keys are permitted.
Wardline constructs every in-memory `Finding`, so a non-`Kind` value is an internal
contract violation rather than an output category to preserve.

The invariant is:

```text
sum(summary.counts_by_kind.values()) == summary.total
```

Counts include active and suppressed findings. Suppression state is orthogonal to
kind and remains represented by `active`, `baselined`, `waived`, and `judged`.

## Scope Semantics

The top-level MCP `summary` already describes the complete scan result. Therefore
`counts_by_kind` is computed from `result.findings`, before response-body filtering,
and is unaffected by:

- `where` selection;
- `offset` or `max_findings` pagination;
- `summary_only`;
- `include_suppressed`; or
- `explain` provenance limits.

For an affected/delta scan, it describes that scan result, consistently with the
other top-level summary counts. The existing `scope` block remains authoritative
about whether that result is advisory or gate-of-record.

## Architecture

Implement a small private pure helper beside the MCP scan response builder. It
initializes a dictionary from every canonical `Kind`, then increments one entry per
finding. `_scan` calls it once while constructing the top-level `summary`.

Keeping the helper in the MCP adapter is intentional: this feature changes only the
MCP response. It does not change `ScanSummary`, `AgentSummary`, or generic finding
serialization.

The MCP output schema defines `counts_by_kind` as an object with the five fixed,
required integer properties and `additionalProperties: false`. The committed schema
golden is regenerated from the live tool surface and its blob pin updated in the same
commit.

## Compatibility

The following surfaces remain byte-for-byte unchanged:

- `wardline-agent-summary-1`;
- CLI `--format agent-summary` output;
- scan-job agent-summary artifacts;
- the nested MCP `agent_summary` object; and
- JSONL, SARIF, and Legis finding payloads.

The top-level MCP `scan.summary` object gains a required additive field. This is a
deliberate output-schema change and is protected by the existing committed golden.
The `scan` tool name and all existing fields retain their current meanings.

## Error Handling

No new runtime failure mode or user-facing error is introduced. The helper consumes
Wardline-owned `Finding` instances whose `kind` is already a `Kind`. It does not
coerce arbitrary strings or silently create new categories.

Schema generation and conformance tests fail loudly if code, schema, or the committed
golden diverge.

## Testing

Implementation must add regression coverage for:

1. a mixed finding population with all five kinds;
2. zero-filled keys when kinds are absent;
3. the sum-to-`summary.total` invariant;
4. identical whole-scan counts under `where` filtering and pagination;
5. exact fixed-key MCP output-schema validation;
6. deliberate regeneration of the committed schema golden and blob pin; and
7. preservation of `wardline-agent-summary-1` and CLI/MCP agent-summary parity.

Verification includes focused tests, the full pytest suite, Ruff, mypy, changed-file
format checks, `git diff --check`, and Wardline's local-only ERROR gate because the
MCP scan path handles external input.

## Non-Goals

- No `completeness`, `confidence`, or `advisory` field.
- No reason-coded qualification list in this task.
- No agent-summary schema version change.
- No rebase or merge of commit `79eba408`.
- No configuration, CLI flag, environment variable, or pack override.

The broader versioned, multi-reason qualification contract is tracked separately by
`wardline-6114834aef` and must be designed fresh from current `main`.
