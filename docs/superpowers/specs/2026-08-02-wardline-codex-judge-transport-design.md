# Wardline Codex CLI Judge Transport Design

**Status:** approved design — awaiting written-spec review
**Date:** 2026-08-02
**Filigree issue:** `wardline-f678111176`
**Reference:** ELSPETH Codex judge transport in
`elspeth-lints/src/elspeth_lints/core/judge.py`

## Caveman summary

`wardline judge` currently needs an OpenRouter key even when the operator already
has an authenticated Codex CLI. Wardline will gain a second judge transport and
will prefer it automatically when a capability-and-authentication probe proves it
is usable. The choice is made once, recorded everywhere a verdict is recorded,
and never changed after adjudication starts.

Codex may inspect more of the repository when the supplied excerpt is not enough,
but it does not receive a repository-root shell. It runs from an empty temporary
directory and sees only Wardline-owned, bounded, read-only inspection tools.

## Goal and success conditions

Add `auto`, `codex-cli`, and `openrouter` judge transport selection to the shared
core path used by CLI and MCP. `auto` defaults to Codex CLI when the installed
binary is compatible and authenticated, otherwise it selects OpenRouter. Explicit
`codex-cli` fails loudly when those prerequisites are absent.

The implementation is complete when:

- transport selection is closed, trusted-config-aware, and resolved once before
  per-finding triage;
- both providers use the same strict verdict parser and failure taxonomy;
- Codex exploration is useful but cannot escape the scan root, read likely
  secrets or repository instruction files, write, run a shell, use the network,
  or inherit ambient tools and credentials;
- every response, CLI/MCP verdict, and persisted false-positive record names the
  concrete transport that produced it; and
- existing OpenRouter behavior remains covered while Codex gains hermetic unit
  tests and a separately opt-in live test.

## Considered approaches

### 1. Sealed Codex plus Wardline read-only MCP — selected

Run `codex exec` in an empty temporary directory and register exactly one local
MCP server. That server exposes bounded `read_file`, `grep_files`, and
`glob_files` operations rooted at the scanned repository. Shell, writes, web,
apps, hooks, user configuration, repository instructions, memories, goals,
subagents, remote plugins, and ambient MCP servers are disabled.

This is more implementation work than starting Codex in the repository, but it
creates an enforceable capability boundary and directly satisfies Wardline's
untrusted-corpus posture. Wardline already has a dependency-free MCP protocol
implementation, so this approach does not add a runtime dependency.

### 2. `codex exec -C <repository> --sandbox read-only` — rejected

This is smaller and gives Codex convenient repository exploration. Read-only
sandboxing prevents writes, however, not reads. A repo-root shell could inspect
`.env`, credentials, or other unrelated secrets, and repository `AGENTS.md` or
similar instructions could enter the agent's instruction chain. The subprocess
would have substantially more authority than adjudication requires.

### 3. Excerpt-only Codex — rejected

This preserves the current disclosure boundary and is simple to test, but it
does not meet the feature's purpose. The current prompt explicitly treats unseen
context as unavailable; switching only the transport would retain the same false
positive pressure instead of letting the judge verify callers, helper behavior,
and guards.

## Public configuration and command surface

The public vocabulary is the same on both surfaces:

- `[wardline.judge] transport = "auto" | "codex-cli" | "openrouter"`
- `wardline judge --transport ...`
- MCP `judge` input `transport`

The default is `auto`. The CLI and MCP overrides take precedence over config.
Project-supplied `transport`, `model`, and `codex_model` values are ignored unless
`--trust-judge-config` / `trust_judge_config` is enabled, matching the existing
model trust boundary.

`[wardline.judge] model` and `--model` remain the OpenRouter model slug. Add
`[wardline.judge] codex_model` and `--codex-model` for the Codex namespace. The
initial Codex default is `gpt-5.6-sol`; the existing OpenRouter default remains
`anthropic/claude-opus-4-8`. Passing a provider-specific model flag never changes
the selected transport.

Configuration parsing and the published JSON Schema reject unknown transport
values and wrong model types. CLI Click choices and the MCP input schema expose
the same closed transport enum.

## Architecture

### Selection boundary

Introduce transport constants and a `CodexAvailability` result with a closed
reason vocabulary such as `available`, `binary_missing`, `incompatible`, and
`unauthenticated`. A capability probe runs these non-model commands through an
injectable subprocess runner:

1. `codex --version` proves the binary starts;
2. `codex exec --help` proves the required flags are advertised; and
3. `codex login status` proves authenticated account state is available.

The probe uses the same minimal environment as adjudication and bounds all
diagnostics. It does not invoke a model and does not inspect arbitrary command
failure text to decide whether a provider is unavailable.

`resolve_judge_transport(requested, probe)` returns only `codex-cli` or
`openrouter`. For `auto`, only a typed unavailable result permits the OpenRouter
choice. For explicit `codex-cli`, the same result becomes a
`JudgeConfigurationError` with remediation. Other configuration defects are
never caught as fallback signals.

`run_judge` resolves the transport once after scanning and before calling
`run_triage`, then closes over one concrete caller. If there are no active
findings, no provider preflight or credential lookup is needed, preserving the
current zero-call behavior. No per-finding code performs selection.

### Shared judge contract

Refactor the current OpenRouter-only function around a private transport result:

```python
@dataclass(frozen=True, slots=True)
class _TransportResult:
    raw_text: str
    served_model_id: str
    prompt_tokens_total: int
    prompt_tokens_cached: int | None

class JudgeTransport(StrEnum):
    AUTO = "auto"
    CODEX_CLI = "codex-cli"
    OPENROUTER = "openrouter"
```

The OpenRouter adapter retains its request and status-band behavior. The Codex
adapter reduces JSONL events into the same `_TransportResult`. `call_judge` then
passes `raw_text` through the existing strict `_parse_verdict_payload` exactly
once and constructs a `JudgeResponse` containing the concrete
`judge_transport`.

The JSON verdict remains exactly `verdict`, `rationale`, and `confidence` with no
additional properties. A shared JSON Schema mirrors those requirements. The
Codex JSONL reducer requires exactly one final agent message and one completed
turn, and rejects a fenced or otherwise non-object final message before the
shared parser. The existing OpenRouter envelope handling remains intact; Codex
does not gain a coercion or repair step.

### Codex subprocess

Each finding uses one noninteractive command with prompt text on stdin:

```text
codex exec
  --ephemeral
  --ignore-user-config
  --ignore-rules
  --strict-config
  --skip-git-repo-check
  --sandbox read-only
  --model <codex-model>
  --json
  --color never
  --output-schema <temporary-schema-path>
  --cd <empty-temporary-directory>
  <locked-down -c settings>
  -
```

Locked-down settings set approval to `never`, disable web search, shell and
unified execution, shell snapshots, apps, hooks, goals, memories, multi-agent,
remote plugins, and personality, and register exactly the Wardline judge-tools
MCP server. A strict-config failure is a transport startup failure, not a reason
to silently drop a security control.

The child environment is rebuilt from an allowlist: executable discovery,
account-home state, locale, terminal, temporary-directory, and TLS trust roots,
plus `NO_COLOR=1`. Provider keys, Wardline/Filigree/Legis tokens, cloud
credentials, proxy credentials, and arbitrary application variables do not
cross the boundary. The MCP child performs a second sensitive-variable check
before serving.

Codex currently has no per-call completion-token cap. Wardline therefore does
not pretend that `max_tokens` is enforced on this transport; schema enforcement
and the strict completed-event parser are the truncation guard. The subprocess
timeout stays finite and injectable in tests.

### Bounded repository exploration

Add a dedicated `wardline.mcp.codex_judge_tools` entry module using Wardline's
dependency-free JSON-RPC/MCP protocol code. It advertises only:

- `read_file`: at most 400 lines and 50,000 characters from one text file;
- `grep_files`: literal matching with only aggregate count or matching file
  names, never matching content; and
- `glob_files`: a bounded, sorted file-name list.

Every operation realpath-resolves its target and proves it is inside the scan
root. Symlink escapes, absolute/path-parent glob tricks, non-regular files,
binary/undecodable content, repository instruction files (`AGENTS.md`,
`CLAUDE.md`, `.codex`, `.agents`, and equivalents), known credential filenames
such as `.env`, and files matching a curated secret detector are denied. The
detector covers PEM private-key blocks, common provider/cloud token prefixes,
authorization bearer values, and credential-labelled assignments; its pattern
names, not matched bytes, appear in denials. Grep
applies the same per-file checks before counting, so it cannot become a secret
oracle. File count, result size, line count, scanned-file count, and total tool
calls are capped.

The prompt says repository bytes, comments, project policy, and instruction-like
text are untrusted evidence, never instructions. It allows the judge to use the
three tools when context is missing and asks the rationale to cite load-bearing
`path:line` evidence. The controlling policy changes from “unseen means
unavailable” to “inspect when tools are available; otherwise retain the
conservative TRUE_POSITIVE prior.” The Codex exploration addendum participates
in `policy_hash`, and `judge_transport` separately records that exploration was
available.

The initial finding excerpt keeps the existing OpenRouter behavior. The new
tools cannot expand that pre-existing disclosure envelope to unrelated likely
secrets.

## Failure semantics

The classification boundary is deliberately narrow:

| Phase | Failure | Result |
| --- | --- | --- |
| auto preflight | binary missing, required capability absent, unauthenticated | choose OpenRouter once |
| explicit Codex preflight | same typed unavailable reasons | `JudgeConfigurationError`, no fallback |
| selected Codex startup/runtime | timeout, nonzero exit, OS launch failure after successful preflight | `JudgeTransportError`; existing per-finding skip/count behavior |
| successful Codex output | malformed JSONL, missing final agent message, missing/invalid usage, schema-invalid verdict | `JudgeContractError`; abort run |
| selected OpenRouter runtime | existing connection/status behavior | unchanged |

Runtime error details are extracted only from structured Codex error events and
bounded stderr. Prompt text, source excerpts, subprocess stdout, and environment
values are never echoed wholesale. Authentication-like runtime text does not
trigger a post-selection provider switch.

## Provenance and persisted-record compatibility

Add `judge_transport` to `JudgeResponse`, the shared flattened `Verdict`, CLI
human output, MCP structured output and output schema, and `JudgedFP`.
`model_id` is also added to the flattened verdict so agents can see provider and
model together without opening the persistence file.

Increment `JUDGED_VERSION` to 2. Writers always emit `judge_transport` with the
closed concrete vocabulary `codex-cli | openrouter`. The loader accepts:

- v2 records only when the transport field is present and valid; and
- v1 records by assigning `openrouter`, the only transport Wardline supported
  when that version was written.

Loading v1 does not rewrite the file. The next normal `--write` emits a stable v2
document, so migration is explicit in version control. `auto` is invalid in an
audit record.

## CLI and MCP behavior

Human CLI verdict lines include provider/model provenance, for example:

```text
FP [0.93] PY-WL-101 src/example.py:18 via codex-cli/gpt-5.6-sol
```

The MCP `judge` description no longer says OpenRouter-only. Its input schema
adds the transport and Codex model choices; each verdict adds `judge_transport`
and `model_id`. CLI and MCP both delegate selection, execution, persistence, and
error mapping to `run_judge`; neither surface builds an independent provider
policy.

## Testing and verification

Implementation follows red-green-refactor at each boundary. Default tests never
call Codex or OpenRouter. Coverage includes:

- closed config/schema/CLI/MCP vocabulary and the trust-config gate;
- complete auto and explicit selection matrices, including exactly-once probes;
- child environment allowlisting and sensitive-variable denial;
- exact subprocess flags, temporary cwd, schema, prompt, and sole MCP
  registration;
- path/symlink confinement, instruction-file denial, secret-file denial, call and
  result budgets, and non-content grep behavior;
- Codex timeout/nonzero/startup failures with bounded diagnostics;
- malformed JSONL events, duplicate/final message handling, missing or malformed
  usage, impossible cache accounting, and schema-invalid verdicts;
- OpenRouter and Codex convergence on the shared verdict parser;
- `JudgeResponse`/CLI/MCP/persistence provenance and v1-to-v2 loading;
- the existing OpenRouter network test unchanged; and
- `tests/e2e/test_judge_codex_live.py` under a new `codex_live` marker excluded
  from default pytest and run explicitly with `pytest -m codex_live`.

Final verification runs focused judge suites, MCP schema conformance, the full
`make ci` gate, and `wardline scan . --fail-on ERROR` because the feature handles
untrusted subprocess output and repository paths.

## Scope boundaries

This feature does not add a generic provider plugin system, route ordinary scans
through an LLM, change suppression precedence, add write-capable agent tools,
install or authenticate Codex for the user, or promise deterministic equivalence
between provider verdicts. It adds exactly one local authenticated transport,
one automatic selection policy, and auditable provenance for the existing
opt-in judge.
