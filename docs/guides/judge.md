# LLM triage judge

The judge is an **opt-in** escalation pass. It reads each active DEFECT finding
and labels it `TRUE_POSITIVE` or `FALSE_POSITIVE` with calibrated confidence and
a short rationale. It never runs as part of `wardline scan`, and it writes no
suppression unless you pass `--write`.

Wardline adds no runtime dependency for judging. It either invokes an installed
Codex CLI or sends a standard-library `urllib` request to OpenRouter; it does not
install an LLM SDK.

## Choose a transport

The default transport is `auto`:

1. Wardline checks whether a compatible Codex CLI is installed, authenticated,
   and safe to run through Wardline's isolated auth projection.
2. If that narrow preflight succeeds, Wardline selects `codex-cli`.
3. If Codex is missing, incompatible, unauthenticated, or its authentication
   cannot be projected safely, Wardline selects `openrouter`.

Selection happens once before per-finding triage. After Wardline selects a
provider, it **does not switch** providers because of a timeout, non-zero exit,
provider error, or malformed response. This prevents one run from silently
mixing adjudication contracts.

Select a provider explicitly when fallback would hide an operator error:

```bash
wardline judge . --transport codex-cli
wardline judge . --transport openrouter
```

An explicit `codex-cli` selection fails with exit `2` when preflight cannot
prove availability; it never falls back. An explicit `openrouter` selection
does not probe Codex.

## Authentication

### Codex CLI

Authenticate the local CLI with ChatGPT before running Wardline:

```bash
codex login
codex login status
wardline judge . --transport codex-cli
```

Wardline does not copy the ChatGPT refresh token into the judge process. It
projects only a still-valid access identity into a temporary Codex home and
uses an inert refresh value. The access token must remain valid for the bounded
judge timeout plus a safety margin. Authentication that Wardline cannot project
safely is unavailable to `auto`; explicit Codex fails loudly. File-backed
ChatGPT projection currently requires POSIX private-file permissions, so select
OpenRouter on platforms where that guarantee is unavailable.

### OpenRouter

Set `WARDLINE_OPENROUTER_API_KEY` in the environment:

```bash
export WARDLINE_OPENROUTER_API_KEY=fake_openrouter_key_for_docs_only
wardline judge . --transport openrouter
```

Replace the obviously fake value with your operator key and never commit the
real key. As a CLI convenience, `wardline judge` can read one
`WARDLINE_OPENROUTER_API_KEY=...` entry from `.env` in the scan root when the
environment variable is unset. An existing environment value always wins.
Wardline never reads an OpenRouter key from `weft.toml`.

No OpenRouter key is required when Codex is selected.

## Codex execution boundary

Wardline launches `codex exec` in an **empty temporary working directory** with
ephemeral state, read-only sandboxing, strict configuration, an output schema,
and a minimal allowlisted environment. It ignores operator config and project
execution rules. Ambient web access, apps, hooks, memory, goals, subagents,
remote plugins, arbitrary MCP servers, and write tools are not available to the
judge.

The scanned repository is not the Codex working directory. Wardline exposes
only three bounded, read-only tools through a private MCP server:

- `read_file` reads a bounded source excerpt.
- `grep_files` returns bounded file names or counts for literal matches.
- `glob_files` returns a bounded set of repository-relative paths.

The tools confine paths to the scan root, reject symlink escapes, instruction
files, credential files, binaries, invalid UTF-8, oversized input, and common
secret patterns. Repository source, comments, policy, and instruction-like text
remain untrusted evidence. If a read is denied or cannot establish the missing
context, the judge must keep the conservative true-positive prior.

## Usage

```text
Usage: wardline judge [OPTIONS] [PATH]

Options:
  --config FILE
  --transport [auto|codex-cli|openrouter]
                                  Judge transport: auto, codex-cli, or
                                  openrouter (default auto).
  --model TEXT                    OpenRouter model slug (overrides config).
  --codex-model TEXT              Codex CLI model id (overrides config).
  --context-lines INTEGER         Excerpt radius (default 30).
  --max-findings INTEGER          Cap findings triaged this run.
  --write                         Append FALSE_POSITIVE verdicts to
                                  .weft/wardline/judged.yaml (default: dry-
                                  run).
  --trust-judge-policy            Load judge.policy_file as untrusted context.
  --trust-judge-config            Allow project config to select transport,
                                  both models, context, cap, and write floor.
  --trust-pack TEXT
  --allow-custom-packs
  --strict-defaults
  --help
```

Flags override `[wardline.judge]` configuration. Without
`--trust-judge-config`, repository configuration cannot choose a transport,
model, context radius, cap, or write confidence floor. `policy_file` has its
separate `--trust-judge-policy` gate and remains untrusted model context.

The OpenRouter default is `anthropic/claude-opus-4-8`. The Codex default is
`gpt-5.6-sol`, with reasoning effort pinned to `high`. These settings are
separate because an OpenRouter routing slug is not a Codex model identifier.
Codex JSONL does not attest the backend model that served the request, so its
recorded `model_id` is the requested Codex model. OpenRouter records the served
model when the provider supplies it, otherwise the requested model.

The judge applies existing baseline, waiver, and judged suppressions, then
selects one transport and triages only the remaining active DEFECT findings.
When no active defects remain, it does not probe or call a provider:

```console
$ wardline judge .
triaged 0 defect(s): 0 true / 0 false
```

## Dry run, persistence, and provenance

By default the command is a dry run. Each CLI verdict includes the concrete
transport and model as `via <judge_transport>/<model_id>`. The MCP `judge` tool
returns the same `judge_transport` and `model_id` fields in every flattened
verdict. `judge_transport` is always `codex-cli` or `openrouter`, never `auto`.

`--write` persists eligible false positives to
`.weft/wardline/judged.yaml`. Wardline writes only verdicts at or above
`judge.write_confidence_floor` (default `0.5`); it reports lower-confidence
false positives but holds them back.

Each version 2 judged record contains the model's verbatim rationale plus
`model_id`, `judge_transport`, `confidence`, `recorded_at`, and `policy_hash`.
Re-judging the same fingerprint replaces that record rather than duplicating
it. See [Suppressing findings](suppression.md#judged-false-positives) for the
schema and legacy version 1 compatibility.

## Failure contract

Malformed JSONL, missing usage or final output, a schema-invalid verdict, or
truncated output raises `JudgeContractError` and aborts the run. Wardline never
coerces malformed model output and never falls back after it.

A selected provider's timeout or transport failure uses the existing
skip-and-count behavior. For Codex, Wardline stops launching more subprocesses
after the first transport failure and counts the remaining findings as skipped;
it does not send them to OpenRouter. Configuration and authentication failures
remain loud exit-`2` errors.

## Optional live verification

The default test suite makes no provider calls. To verify the installed,
authenticated Codex CLI explicitly:

```bash
WARDLINE_CODEX_LIVE=1 uv run pytest -m codex_live -v tests/e2e/test_judge_codex_live.py
```

The live test checks both a normal verdict and a completed bounded repository
read. OpenRouter retains its separate opt-in `network` live test.

## See also

- [Configuration](configuration.md#wardlinejudge)
- [Suppressing findings](suppression.md)
- [CLI reference](../reference/cli.md#wardline-judge)
- [MCP reference](../reference/mcp.md#judge)
