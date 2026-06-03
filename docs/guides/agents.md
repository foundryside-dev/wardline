# Using Wardline with your coding agent

Wardline is built for the one-to-two-developer team that has handed real work
to a coding agent and now wants a trust-boundary gate the agent can run *itself*
— and reason about — without standing up an enterprise security program.

## Why this fits an agent

An agent works best against a tool that is:

- **Deterministic** — the same code produces the same findings, so the agent can
  treat a verdict as ground truth rather than a roll of the dice.
- **Dependency-free at the core** — the analyzer is plain standard-library
  Python (the CLI adds only `click`, `pyyaml`, and `jsonschema`). Nothing to
  provision, no service to reach. The agent runs it the way it runs `pytest`.
- **Fast and local** — a scan is a process the agent spawns and reads, with a
  machine-readable exit code and a structured report.

That combination lets you wire Wardline into the loop the agent already runs: it
edits code, runs the gate, reads the result, and corrects itself before it ever
asks you to look.

If you have not installed Wardline yet, start with
[Getting Started](../getting-started.md).

## One-command setup: `wardline install`

`wardline install` wires wardline into a project's agent context in one step:

- injects a small, hash-fenced block into `CLAUDE.md` and `AGENTS.md` pointing
  the agent at the gate and the loop;
- installs the `wardline-gate` skill into `.claude/skills/` and `.agents/skills/`;
- merges a `wardline` entry into `.mcp.json` (preserving any existing servers);
- detects a Clarion taint store (`clarion` on `PATH` or `WARDLINE_CLARION_URL`)
  and a Filigree project (`.filigree.conf`), recording a `clarion:`/`filigree:`
  binding in `wardline.yaml` — live when a URL env var is set, otherwise a
  commented stanza for you to fill.

```console
$ wardline install
wardline install:
  CLAUDE.md: created
  AGENTS.md: created
  skill .claude/skills/wardline-gate: created
  skill .agents/skills/wardline-gate: created
  .mcp.json (wardline entry): created
  clarion: detected (commented)
  filigree: detected (commented)
```

It is idempotent (re-run to refresh after upgrading wardline) and non-interactive
(safe in CI). Opt out of any piece with `--no-claude-md`, `--no-agents-md`,
`--no-skill`, `--no-mcp`, or `--no-bindings`. There is no SessionStart hook —
freshness is enforced only when you re-run `wardline install`.

Once installed, the MCP server resolves the Clarion URL from `wardline.yaml`, so
the `.mcp.json` entry stays a bare `wardline mcp --root .` with no URL in its args.

## Gate the agent's work with `wardline scan`

Wardline marks trust boundaries with two decorators from `wardline.decorators`:
`@external_boundary` (data arriving from outside the trust boundary —
untrusted) and `@trusted` (a producer that is supposed to receive validated data
only). When untrusted data reaches a trusted producer, Wardline raises
`PY-WL-101` at `ERROR`.

Here is a self-contained example (`handlers.py`):

```python
from wardline.decorators import external_boundary, trusted


@external_boundary
def read_request_body(req):
    """Untrusted: data arriving from the network."""
    return req.body


@trusted
def store_record(req):
    """Trusted sink: this is supposed to receive validated data only."""
    payload = read_request_body(req)
    return payload
```

By default a scan reports but never fails — the gate is opt-in:

```console
$ wardline scan .
scanned 1 file(s); 3 finding(s) — 0 suppressed (0 baseline / 0 waiver / 0 judged), 1 new -> findings.jsonl
```

```console
$ echo $?
0
```

Add `--fail-on ERROR` and the same scan becomes a gate — a non-suppressed defect
at or above the threshold drives a non-zero exit:

```console
$ wardline scan . --fail-on ERROR
scanned 1 file(s); 3 finding(s) — 0 suppressed (0 baseline / 0 waiver / 0 judged), 1 new -> findings.jsonl
```

```console
$ echo $?
1
```

!!! note "Why the agent can self-correct"
    Exit `1` is the gate tripping; exit `2` is a Wardline error (bad config,
    unreadable path). The agent branches on the code. On a trip it reads the
    structured report it just wrote — the line `handlers.store_record declares
    return trust INTEGRAL but actually returns EXTERNAL_RAW (less trusted) —
    untrusted data reaches a trusted producer` names the function, the file, and
    the lines. That is enough for the agent to locate the leak and add a
    validating boundary before handing the change back to you.

### A pre-commit hook

To make the gate run on every commit, drop a `.git/hooks/pre-commit` script
(make it executable with `chmod +x`):

```bash
#!/usr/bin/env sh
# Block a commit if Wardline finds a new ERROR-or-worse defect.
# Write the findings file outside the working tree so the commit stays clean.
wardline scan . --fail-on ERROR --output /tmp/wardline-findings.jsonl
```

A `scan` always writes a findings file (default `findings.jsonl` in the scan
path), so point `--output` outside the tree — as above — or at a git-ignored
path; otherwise the hook litters every commit. The script's exit code becomes
the hook's exit code: a clean tree commits, a new defect aborts the commit with
the finding already on screen for the agent to act on.

## Let the agent triage with `wardline judge`

The taint engine is intentionally conservative and will sometimes over-report.
`wardline judge` is an **opt-in** LLM pass that labels each active defect
`TRUE_POSITIVE` or `FALSE_POSITIVE` with a calibrated confidence. It costs
nothing by default — `wardline scan` never calls a model, and `judge` runs only
when you invoke it.

It also fails loud rather than guessing, which keeps an agent honest: with no
API key configured it stops with remediation guidance and exit `2`, so the agent
never mistakes "couldn't triage" for "nothing to triage".

```console
$ wardline judge .
error: WARDLINE_OPENROUTER_API_KEY is not set. `wardline judge` calls OpenRouter to triage findings. Export the key (`export WARDLINE_OPENROUTER_API_KEY=sk-or-...`) or place it in a .env in the scan root, then re-run.
```

With a key, `judge` triages cold and prints one line per verdict. Pass `--write`
to append `FALSE_POSITIVE` verdicts to `.wardline/judged.yaml` — but only those
at or above the **confidence floor** (`judge.write_confidence_floor`, default
`0.5`); a low-confidence FP is reported and held back rather than silently
suppressed. A subsequent `wardline scan` reads `.wardline/judged.yaml` and treats
those fingerprints as suppressed, so the gate stops tripping on triaged
false positives while still flagging anything new.

For an agent this closes the loop: scan flags a defect, judge classifies it,
and an above-floor false positive is recorded as an audited suppression rather
than left to nag every run. See the [LLM triage judge guide](judge.md)
for the verdict format, the floor, and the `judged.yaml` record shape.

## Hand off via SARIF

For handing findings to another tool — GitHub code scanning, a CI dashboard, or
a sibling Loom tool — emit SARIF 2.1.0:

```console
$ wardline scan . --format sarif --output results.sarif --fail-on ERROR
scanned 1 file(s); 3 finding(s) — 0 suppressed (0 baseline / 0 waiver / 0 judged), 1 new -> results.sarif
```

The log is standard SARIF 2.1.0 with a `wardline` driver and one result per
finding (the defect alongside engine metric/fact entries), so it is not
Filigree-specific — any SARIF consumer can read it. `--fail-on` still gates while
the file is written, so the same command both publishes the report and blocks the
agent's change. See the [Loom integration guide](loom.md) for the full
output matrix, including the native Filigree emitter.

## Call Wardline as MCP tools

Wardline ships a native, dependency-free MCP server so an agent can call it as
tools instead of shelling out. Launch it over stdio:

```console
$ wardline mcp --root .
```

Tools: `scan` (structured findings + suppression summary + gate), `explain_taint`
(the tainted callee and originating boundary for one finding — call it right
after a scan and before editing), `fix` (mechanical autofixes for supported
findings), `judge` (opt-in, network), and the loud suppression tools
`baseline_create` / `baseline_update` / `waiver_add` (each requires a reason).
Resources expose the trust vocabulary, rule catalog, config, and config schema.
The `wardline:loop` prompt documents the intended
scan → explain → fix-at-the-boundary → rescan cycle.

With an opt-in Clarion taint store configured (`wardline mcp --clarion-url
<URL>`), `explain_taint` becomes a query when you pass the finding's `qualname`
as `sink_qualname`: a fresh fact is served from the store without re-scanning
the file. Pass `chain: true` (with an optional `max_hops`), again alongside
`sink_qualname`, to walk the full N-hop taint chain back to the originating
boundary. Without a store, or without
`sink_qualname`, `explain_taint` returns the single-hop SP8 explanation from a
local re-scan. Known cost: with a store configured, each `scan` additionally
builds taint facts (a blake3 hash per file) and POSTs them to Clarion — this is
fail-soft, but a real per-scan cost in the agent loop. See the
[Clarion taint store guide](clarion-taint-store.md) for the full
opt-in, auth, and fail-soft details.

The server is stateless — no session state is carried between calls; the
read-only tools (`scan`, `explain_taint`) are pure functions of your code on disk
and your config, and the analysis core stays zero-dependency. Only `judge`
touches the network; `fix`, the suppression tools (`baseline_create` /
`baseline_update` / `waiver_add`), and `judge` with `write` write to your project
files as requested.
