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
- writes a global Codex MCP entry in `~/.codex/config.toml`;
- **detects** a Loomweave taint store (`loomweave` on `PATH` or
  `WARDLINE_LOOMWEAVE_URL`) and a Filigree project (`.filigree.conf`) and reports
  what it found — it writes **no** binding and persists **no** URL. `weft.toml`
  stays operator-authored; live URLs come from the `--filigree-url` /
  `--loomweave-url` flag, the `WARDLINE_FILIGREE_URL` / `WARDLINE_LOOMWEAVE_URL`
  env var, or the published `.weft/<sibling>/ephemeral.port` rung (legacy
  `.<sibling>/ephemeral.port` tolerated).

```console
$ wardline install
wardline install:
  CLAUDE.md: created
  AGENTS.md: created
  skill .claude/skills/wardline-gate: created
  skill .agents/skills/wardline-gate: created
  .mcp.json (wardline entry): created
  Codex MCP (wardline entry): created
  loomweave: detected (no URL — rely on flag/env/published port)
  filigree: detected (no URL — rely on flag/env/published port)
  runtime markers: install `weft-markers` and import from `weft_markers`
```

It is idempotent (re-run to refresh after upgrading wardline) and
non-interactive, but it writes project-local agent and MCP files. Run it only
on a trusted checkout or as an operator-controlled bootstrap step. For
untrusted pull-request CI, use `wardline scan ... --fail-on ERROR`; do not run
`wardline install` against attacker-controlled working-tree contents. Opt out
of any piece with `--no-claude-md`, `--no-agents-md`, `--no-skill`, `--no-mcp`,
or `--no-bindings`. There is no SessionStart hook — freshness is enforced only
when you re-run `wardline install`.

Once installed, the MCP server resolves a Loomweave/Filigree URL at runtime from
the flag, env var, or published `.weft/<sibling>/ephemeral.port` rung — not from
config — so the `.mcp.json` entry stays a stdio `wardline mcp --root .` command
with no URL in its args.
The Codex entry is global, so it runs `wardline mcp` without `--root` and lets
Codex launch it from the active workspace.

Check the wiring later with:

```console
$ wardline doctor
```

Use `wardline doctor --repair` after moving binaries, starting a Filigree
dashboard, or changing sibling tool config. It refreshes the instruction blocks,
skills, and MCP entries, and re-detects siblings using the same discovery rules
as `wardline install` — it never writes `weft.toml` or a sibling binding.

Over MCP, the `doctor` tool returns the same machine-readable envelope
(read-only by default; pass `repair: true` for the write-gated repair) **plus
the running server's self-identification**: package version, pid, start time,
and a source-freshness verdict. If `server.fresh` is `false`, the long-lived
MCP server process predates the on-disk wardline code — every result it serves
is stale; restart the server. Call it whenever federation writes fail or after
upgrading/editing wardline itself.

## Gate the agent's work with `wardline scan`

Wardline marks trust boundaries with marker decorators from `weft_markers`:
`@external_boundary` (data arriving from outside the trust boundary —
untrusted) and `@trusted` (a producer that is supposed to receive validated data
only). When untrusted data reaches a trusted producer, Wardline raises
`PY-WL-101` at `ERROR`.

Here is a self-contained example (`handlers.py`):

```python
from weft_markers import external_boundary, trusted


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
scanned 1 file(s); 3 finding(s) — 0 suppressed (0 baseline / 0 waiver / 0 judged), 1 active -> findings.jsonl
```

```console
$ echo $?
0
```

Add `--fail-on ERROR` and the same scan becomes a gate — a non-suppressed defect
at or above the threshold drives a non-zero exit:

```console
$ wardline scan . --fail-on ERROR
scanned 1 file(s); 3 finding(s) — 0 suppressed (0 baseline / 0 waiver / 0 judged), 1 active -> findings.jsonl
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
# Use mktemp for the findings file; never write to a predictable shared /tmp path.
out="$(mktemp "${TMPDIR:-/tmp}/wardline-findings.XXXXXX.jsonl")" || exit 2
trap 'rm -f "$out"' EXIT
wardline scan . --fail-on ERROR --output "$out"
```

A `scan` always writes a findings file (default `findings.jsonl` in the scan
path), so point `--output` at a per-run temporary file — as above — or at a
git-ignored path inside the repository; otherwise the hook litters every commit.
Avoid predictable filenames in shared directories such as `/tmp`. The script's
exit code becomes the hook's exit code: a clean tree commits, a new defect
aborts the commit with the finding already on screen for the agent to act on.

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
to append `FALSE_POSITIVE` verdicts to `.weft/wardline/judged.yaml` — but only those
at or above the **confidence floor** (`judge.write_confidence_floor`, default
`0.5`); a low-confidence FP is reported and held back rather than silently
suppressed. A subsequent `wardline scan` reads `.weft/wardline/judged.yaml` and treats
those fingerprints as suppressed, so the gate stops tripping on triaged
false positives while still flagging anything new.

For an agent this closes the loop: scan flags a defect, judge classifies it,
and an above-floor false positive is recorded as an audited suppression rather
than left to nag every run. See the [LLM triage judge guide](judge.md)
for the verdict format, the floor, and the `judged.yaml` record shape.

## Hand off via SARIF

For handing findings to another tool — GitHub code scanning, a CI dashboard, or
a sibling Weft tool — emit SARIF 2.1.0:

```console
$ wardline scan . --format sarif --output results.sarif --fail-on ERROR
scanned 1 file(s); 3 finding(s) — 0 suppressed (0 baseline / 0 waiver / 0 judged), 1 active -> results.sarif
```

The log is standard SARIF 2.1.0 with a `wardline` driver and one result per
finding (the defect alongside engine metric/fact entries), so it is not
Filigree-specific — any SARIF consumer can read it. `--fail-on` still gates while
the file is written, so the same command both publishes the report and blocks the
agent's change. See the [Weft integration guide](weft.md) for the full
output matrix, including the native Filigree emitter.

## Call Wardline as MCP tools

Wardline ships a native, dependency-free MCP server so an agent can call it as
tools instead of shelling out. Launch it over stdio:

```console
$ wardline mcp --root .
```

Tools: `scan` (structured findings + suppression summary + gate, including the
stable `agent_summary` block for compact handoff), `explain_taint`
(the tainted callee and originating boundary for one finding — call it right
after a scan and before editing), `decorator_coverage` (stable JSON inventory of
every trust-decorated entity with declared/actual tiers, verdicts, SEI/content
status, and linked work when configured), `file_finding` (promote one emitted
finding to a Filigree issue), `scan_file_findings` (one-shot scan, explain,
emit, promote, and identity-attach workflow), `fix` (mechanical autofixes for
supported findings), `judge` (opt-in, network), and the loud suppression tools
`baseline` / `waiver_add` (each requires a reason; `baseline` defaults to
no-clobber and accepts `overwrite: true` to re-derive).
Resources expose the trust vocabulary, rule catalog, config, and config schema.
The `wardline:loop` prompt documents the intended
scan → explain → fix-at-the-boundary → rescan cycle.

`scan` payload controls (the `summary`/`gate` blocks always describe the whole
project — these only bound the returned finding bodies):

- `where` — a conjunctive read-lens (keys: `rule_id`, `qualname`, `severity`,
  `suppression`, `kind`, `path_glob`, `sink`, `tier`) that filters **both** the
  `findings` list and the `agent_summary` arrays.
- `summary_only: true` — counts + gate only, no finding bodies. The smallest
  "did the gate pass?" payload.
- `include_suppressed: false` — drop suppressed (baselined/waived/judged) bodies;
  the suppression counts stay in `summary`.
- `max_findings: N` — cap the returned bodies (and inlined explanations).
- `explain: true` — inline each active defect's provenance; capped at 10 by
  default (raise/lower with `max_findings`).

Every cut is reported in the response `truncation` block (`findings_total`,
`findings_returned`, `findings_truncated`, `explanations_truncated`) so a bounded
payload never reads as "covered everything."

With an opt-in Loomweave taint store configured (`wardline mcp --loomweave-url
<URL>`), `explain_taint` becomes a query when you pass the finding's `qualname`
as `sink_qualname`: a fresh fact is served from the store without re-scanning
the file. Pass `chain: true` (with an optional `max_hops`), again alongside
`sink_qualname`, to walk the full N-hop taint chain back to the originating
boundary. Without a store, or without
`sink_qualname`, `explain_taint` returns the single-hop SP8 explanation from a
local re-scan. Known cost: with a store configured, each `scan` additionally
builds taint facts (a blake3 hash per file) and POSTs them to Loomweave — this is
fail-soft, but a real per-scan cost in the agent loop. See the
[Loomweave taint store guide](loomweave-taint-store.md) for the full
opt-in, auth, and fail-soft details.

`file_finding` can also opt into Loomweave identity attachment with
`attach_loomweave_identity: true`. Wardline promotes the finding first, then
re-runs the scan to find the fingerprint's qualname, resolves that qualname
through Loomweave, and attaches a Filigree entity association when it has both an
entity id and a current content hash. The returned `identity_attach` block
reports `attempted`, `attached`, `entity_id`, `content_hash`, `binding_kind`, and
`reason`. If only a legacy locator is available and no current hash can be read,
the tool says so and leaves the promoted issue intact rather than fabricating a
binding.

For the usual agent loop, prefer `scan_file_findings`: it defaults to a dry-run
summary of active defects, including explanation summaries, then promotes only
when you pass explicit `fingerprints` or `all_active: true`. Filigree emission,
per-finding promotion, unknown fingerprints, and Loomweave identity attachment are
reported as separate status blocks so partial failure is not hidden.

The server is stateless — no session state is carried between calls; the
read-only tools (`scan`, `explain_taint`) are pure functions of your code on disk
and your config, and the analysis core stays zero-dependency. Only `judge`
touches the network; `fix`, the suppression tools (`baseline` / `waiver_add`),
and `judge` with `write` write to your project files as requested.

For shell workflows, `wardline scan --format agent-summary` writes the same
versioned handoff shape (`wardline-agent-summary-1`) to disk: active defects
first with fingerprints and next tool calls, plus suppressed findings, engine
facts, and Loomweave/Filigree write status when configured.

## Scanning Rust

For a Rust codebase, add `--lang rust` (install the `wardline[rust]` extra first);
over MCP, pass `lang: "rust"` to the `scan` tool — the two surfaces share the
engine and return identical findings.
It sweeps `*.rs` and flags command-injection defects (`RS-WL-108` program
injection / `RS-WL-112` shell injection) through the same gate, formats, and
emission paths as the Python frontend. Rust finding identity is frozen and
crate-prefixed, so RS-WL-* findings are **baseline-eligible** — baseline, waivers,
and judged verdicts apply exactly as for Python findings. Read the result at the
right scope: rule coverage is the command-injection slice, and `weft.toml`
severity overrides do not yet apply. Declare a function's trust tier
with a `/// @trusted(level=ASSURED|GUARDED)` doc-comment marker so the
default-clean analysis knows which functions are part of your trust surface. See
the [Rust support guide](rust-preview.md) for the boundary sources, the trust
marker, and the documented false-negative families.
