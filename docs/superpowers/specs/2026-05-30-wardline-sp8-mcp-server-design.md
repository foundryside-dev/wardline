# Wardline SP8 — MCP Server Design

**Status:** Approved (brainstorm) — 2026-05-30
**Author:** John Morrissey (with Claude)
**Supersedes the "Coming: an MCP server" teaser in `docs/agents.md`.**

## Goal

Expose Wardline to coding agents as a **first-class** native MCP server
(`mcp__wardline__*`) so an agent can run the analyzer as a set of structured
tools — scan, explain a taint finding, triage, and manage suppression — without
shelling out to the CLI and parsing stdout. Agents are a first-class customer of
Wardline, so the MCP surface ships *with the product*, not behind an opt-in
extra.

## Non-negotiable character (the thesis)

Wardline is deterministic, local, and dependency-free at the core. The MCP
server must not erode any of those:

- **Dependency-free transport.** The server speaks MCP-over-stdio (JSON-RPC 2.0)
  implemented on the standard library only — the same discipline that has the
  SP5 judge talk to OpenRouter over `urllib` instead of an SDK, and that drove
  the `httpx` removal. No MCP SDK dependency. (Decision: dep-free stdlib
  JSON-RPC, 2026-05-30.)
- **Deterministic + local by default.** Every tool is a pure function of (code
  on disk + config). The **only** exception is `judge`, whose network call is
  isolated and explicitly flagged.
- **No new core dependencies.** The server ships in the runnable product
  alongside the CLI; the analyzer core stays zero-dep.

## Architecture

Three layers, bottom-up.

### (a) `core/run.py` — the keystone (behavior-preserving refactor)

Today *all* scan orchestration lives inline inside the Click command
(`src/wardline/cli/scan.py:54-106`): discovery → `WardlineAnalyzer.analyze` →
load baseline/waivers/judged → `apply_suppressions` → summary counts → gate
decision. There is **no reusable core scan API**. The MCP server must not
re-implement this. SP8 therefore extracts it into a pure core orchestration
function that both the CLI and the MCP server call:

```python
def run_scan(root: Path, *, config_path: Path | None = None,
             cache_dir: Path | None = None) -> ScanResult: ...

@dataclass(frozen=True)
class ScanSummary:
    total: int
    active: int      # the gate population — post-suppression ACTIVE defects
    baselined: int
    waived: int
    judged: int

@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    summary: ScanSummary
    files_scanned: int

def gate_decision(result: ScanResult, fail_on: Severity | None) -> GateDecision:
    # {tripped: bool, fail_on: str | None, exit_class: 0 | 1 | 2}
    ...
```

The CLI `scan` command becomes a thin shell over `run_scan` that formats stdout,
writes SARIF/JSONL, performs Filigree emission, and translates the gate decision
into an exit code. **No behavior change.** The existing 730 tests are the
regression oracle that proves the extraction is behavior-preserving.

Because the MCP server calls the *same* `run_scan`, the CLI and the MCP surface
are behaviorally identical by construction — same findings, same `active` count,
same gate.

### (b) `mcp/protocol.py` — dep-free JSON-RPC 2.0 over stdio

Standard-library only. Reads framed JSON-RPC messages from stdin, dispatches to
registered method handlers, writes responses to stdout. Implements the MCP
*envelope*, not just raw JSON-RPC framing:

- the `initialize` / `initialized` handshake,
- `protocolVersion` negotiation,
- the `capabilities` object (advertising tools, resources, prompts),
- result wrapping — tool results are returned as
  `{content: [{type: "text", text: ...}]}` (or structured content), **not** bare
  JSON.

The envelope — not the framing — is the part that bites hand-rolled servers, so
it is conformance-tested against the published MCP schema and a real client
handshake (see Testing).

### (c) `mcp/server.py` — tools, resources, prompts

Thin handlers that marshal JSON args → core calls → JSON results. **Stateless:**
no server-side session, no held findings list; every call is a pure function of
(disk + config). The server is **rooted at its launch cwd** (overridable via an
`initialize` root parameter); `path` arguments default to that root, and
resources resolve their project against it.

Entry point: `wardline mcp` launches the stdio server.

## Tool surface (the "full loop")

The agent manages the full scan → triage → suppression lifecycle through MCP.
Suppression tools are deliberately *loud* (reason-required) so suppression is
never the frictionless path out of a red gate.

| Tool | Input | Output | Notes |
|---|---|---|---|
| `scan` | `{path?, fail_on?, config?}` | `{findings[], summary{total,active,baselined,waived,judged}, gate{tripped,fail_on,exit_class}}` | The spine. Whole-program, on-disk. `active` is the gate population. |
| `explain_taint` | `{fingerprint}` **or** `{path, line}` | `{source_boundary_qualname, immediate_tainted_callee, tier_in, tier_out}` **or** a no-match error | Re-runs analysis, projects the otherwise-discarded `TaintProvenance`. See "explain_taint mechanism". |
| `judge` | `{path?, confidence_floor?, write?}` | `[{fingerprint, label, confidence, rationale}]` | **`network: true`**, opt-in, never auto-invoked, never folded into `scan`. Requires `WARDLINE_OPENROUTER_API_KEY`; fails loud (JSON-RPC error) without it. `write` appends above-floor FALSE_POSITIVEs to `.wardline/judged.yaml`. |
| `baseline_create` | `{path?, reason}` | `{baselined_count, path}` | **`reason` required.** Refuses if a baseline already exists (mirrors CLI). Description steers toward fixing. |
| `baseline_update` | `{path?, reason}` | `{baselined_count, path}` | **`reason` required.** Re-derives and overwrites. |
| `waiver_add` | `{fingerprint, reason, expires}` | `{waiver}` | **`reason` and `expires` both required.** No permanent silent waivers. |

### Whole-program by default; no unsafe scoping knob

`scan` is always whole-program. The engine is incremental *under the hood*
(summary cache + `ReverseModuleIndex.transitive_callers` dirty-set expansion),
so whole-program correctness is delivered at changed-files speed. There is
**no** "changed-files-only" knob exposed to the agent: scoping a scan to the
files the agent named would silently miss a `PY-WL-101` that the edit just
created in an un-named dependent — a correctness foot-gun the agent would reach
for under time pressure.

## Resources & prompts

**Resources** are read-only context the host pulls in once; they must be stable
across the agent's edits. Findings change the instant code changes, so they are
**never** a resource — they come back only as a `scan` result.

| Resource URI | Content | Why a resource |
|---|---|---|
| `wardline://vocab` | Trust-vocabulary descriptor (decorators, lattice) | Stable; tells the agent whether to write `@trusted` vs `@external_boundary`. |
| `wardline://rules` | Rule catalog (id, description, severity model) | Stable per release. |
| `wardline://config` | Effective merged config | Stable per project. |
| `wardline://config-schema` | The config JSON Schema | Stable per release. |

**Prompts** — exactly one, by exception. The whole-program / no-overlay
semantics are non-obvious and easy to misuse, so a single discoverable prompt
documents the intended loop:

- `wardline:loop` — "scan → `explain_taint` each active defect → fix at the
  boundary, not the sink → rescan."

No other prompts. A templated "triage and fix this finding" prompt is the agent
narrating to itself and is omitted as overreach.

## explain_taint mechanism + staleness contract

**Engine change.** `TaintProvenance` is currently computed during cross-file SCC
propagation (`src/wardline/scanner/taint/propagation.py`) and then discarded —
only a single best-callee string survives, folded into the finding fingerprint
(`compute_finding_fingerprint`, `finding.py:102-113`). SP8 stops discarding it:
the engine carries the cheap projection — `via_callee` (the immediate upstream
tainted callee), the originating source-boundary qualname, and the trust tiers
in/out at the sink — so a finding can be explained on demand. The **full ordered
N-hop chain is out of scope** for v1 (the immediate hop + originating boundary
is the value knee; see Non-goals).

**Statelessness.** With no server state, `explain_taint(fingerprint)` re-runs
the (incremental, cached, deterministic) analysis against current disk and looks
up the requested fingerprint. This keeps `scan`'s default output lean while
depth is fetched on demand.

**Staleness contract (decided).** The fingerprint folds in `line_start`,
`qualname`, and a taint-path signature. Between the `scan` that produced
fingerprint *X* and a later `explain_taint(X)`, the agent may have edited the
file — so a re-run produces *different* fingerprints and *X* may no longer
exist. In that case `explain_taint` returns a clear error —

> "fingerprint not in current scan; your code changed since the scan that
> produced it — re-scan."

It **never** silently recomputes against drifted code. `explain_taint` is
documented as a call-after-scan-before-edit tool. This is the same staleness
discipline that keeps findings off the resource surface.

## Error handling & determinism

- **Tool errors** (bad config, unreadable path) → JSON-RPC error responses (the
  exit-2 equivalent). A **gate trip is data, not an error**: it is returned in
  `scan`'s result as `gate.tripped`, never raised.
- **`judge` with no API key** → a loud JSON-RPC error with remediation guidance,
  never a guess. `judge` is the one tool that may touch the network and is
  flagged `network: true`.
- **No code mutation** — the server never edits source. Fixing is the agent's
  job; a tool that edits source would make Wardline's output depend on
  Wardline's own edits.
- **No server-side session state** — every result is reproducible from
  (disk + config) across agents and runs.

## Testing

- **Refactor regression.** The existing 730 tests stay green across the
  `core/run.py` extraction — the oracle that proves it is behavior-preserving.
- **Handler unit tests.** Each tool and resource against fixtures (clean repo,
  tripped gate, suppressed finding, missing key for `judge`, stale fingerprint
  for `explain_taint`).
- **MCP conformance.** Validate the envelope against the published MCP schema
  *and* a real client handshake (`initialize` → `tools/list` → `tools/call` →
  result-wrapping → `resources/list` → `resources/read`). "Passes our handlers"
  is not "a client can connect" — the conformance test is the gate on the
  hand-rolled transport.

## Non-goals (v1) / future directions

Deferred to v2+ and pursued only if usage demands:

- **Overlay / buffer scan** (scan an uncommitted in-memory edit). The consumer
  acknowledged disk-first is consistent with how an agent already runs
  pytest/mypy/ruff; the v1 engine-surgery budget goes to `explain_taint`
  instead. An honest overlay must be whole-program (inject buffer content, rerun
  propagation against on-disk rest), never an isolated single-file scan.
- **Full ordered N-hop taint chain** in `explain_taint`. Add only if agents are
  observed asking to walk the chain to find a mid-stack choke point.
- **Session-relative deltas** ("new since my last scan"). Would require state;
  if ever added, must stay stateless (caller passes the prior fingerprint set).
- **SP9 — Clarion integration (penciled in as the next sub-project).** Persist
  the taint / provenance graph into Clarion (the Loom code-intelligence peer)
  keyed by symbol, via the ADR-029 entity-association seam. This turns
  `explain_taint` from a stateless re-run into a *query* against Clarion, and
  the same persistent store could later back overlay-scan and the full N-hop
  chain cheaply. v1 keeps Wardline self-contained — it owns the taint fact and
  recomputes deterministically — with Clarion-as-taint-store as the evolution
  that removes the re-run cost.

## Task sequencing

SP8 is **not** purely additive — it touches the shipping scan path — so the
refactor lands first, behind the regression oracle.

1. **Extract `core/run.py`** as a behavior-preserving refactor; CLI `scan`
   delegates to it; 730 tests stay green.
2. **Thread the `TaintProvenance` projection** onto findings (the `explain_taint`
   engine change).
3. **Dep-free JSON-RPC + MCP envelope layer** (`mcp/protocol.py`) with
   conformance tests against a real client handshake.
4. **Tools** (`scan`, `explain_taint`) → **resources** → **`judge`** →
   **suppression tools** (`baseline_*`, `waiver_add`) → the `wardline:loop`
   **prompt**.
5. **`wardline mcp` entry point** + docs: flip the `docs/agents.md` "Coming"
   teaser to a live integration page.
