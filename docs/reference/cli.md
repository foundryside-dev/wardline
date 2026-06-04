# CLI reference

Complete reference for the `wardline` command-line interface, version `0.2.0`.
Every `--help` block below is the verbatim output of the installed CLI; every
example is a realistic invocation.

## Installation and extras

The CLI is a [Click](https://click.palletsprojects.com/) application. Most
commands depend on the `scanner` extra; one (`judge`) is dependency-free beyond
the base CLI.

| Command | Requires | Why |
| --- | --- | --- |
| `scan` | `wardline[scanner]` | Runs the analyzer engine; needs `pyyaml`, `jsonschema`, `click`. |
| `baseline create` / `baseline update` | `wardline[scanner]` | Re-derives findings from a scan, so it pulls in the full scanner stack. |
| `vocab` | `wardline[scanner]` | Ships with the CLI (`click`), which arrives via the `scanner` extra. |
| `judge` | no extra | The SP5 LLM triage judge talks to OpenRouter over stdlib `urllib`; no third-party dependency is needed beyond the base CLI. |

Install the scanner stack with:

```text
pip install 'wardline[scanner]'
```

The `scanner` extra resolves to `pyyaml>=6.0`, `jsonschema>=4.0`, and
`click>=8.0`. After that, every command on this page is available.

## `wardline` (top level)

**Purpose:** the root command group. On its own it prints usage and the command
list; the only top-level option that does work is `--version`.

```text
Usage: wardline [OPTIONS] COMMAND [ARGS]...

  Wardline — generic semantic-tainting static analyzer.

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  baseline  Manage the finding baseline (.wardline/baseline.yaml).
  file-finding
            File the finding identified by FINGERPRINT into a tracked...
  judge     Triage active DEFECTs with the opt-in LLM judge.
  scan      Scan PATH for findings.
  vocab     Emit the NG-25 trust-vocabulary descriptor as YAML...
```

Check the installed version:

```text
$ wardline --version
wardline, version 0.2.0
```

Use `--version` in CI before a scan to pin the toolchain in your build log; the
conformance fixtures and SARIF output are stable per version.

## `wardline scan`

**Purpose:** analyze a directory for trust-boundary findings and emit them as
JSONL or SARIF. Requires the `scanner` extra.

```text
Usage: wardline scan [OPTIONS] [PATH]

  Scan PATH for findings.

Options:
  --config PATH
  --format [jsonl|sarif]
  --output PATH
  --fail-on [CRITICAL|ERROR|WARN|INFO]
  --cache-dir PATH                Persist L3 summary cache here for faster
                                  incremental scans.
  --filigree-url TEXT             POST findings to this Filigree Loom scan-
                                  results URL (opt-in).
  --help                          Show this message and exit.
```

`PATH` is a **directory** (defaults to the current directory if omitted). Point
it at a package root, not a single file.

| Option | Effect |
| --- | --- |
| `--config PATH` | Path to a `wardline.yaml` config file; controls rule enable/severity and judge settings (defaults to `wardline.yaml` in the scan path). |
| `--format [jsonl\|sarif]` | Output shape. `jsonl` is one finding per line; `sarif` is SARIF 2.1.0 for GitHub code-scanning and other generic SARIF consumers. SARIF carries Wardline identity in `partialFingerprints["wardlineFingerprint/v1"]`; downstream Filigree lifecycle quality depends on importers preserving that field. |
| `--output PATH` | Write findings to a file instead of stdout. |
| `--fail-on [CRITICAL\|ERROR\|WARN\|INFO]` | Exit non-zero when any finding at or above this severity survives the baseline. Use this as your CI gate. |
| `--cache-dir PATH` | Persist the L3 inter-procedural summary cache here so the next scan reuses unchanged summaries. |
| `--filigree-url TEXT` | Opt-in: POST findings to a Filigree Loom scan-results endpoint as well as emitting them locally. Prefer this native path when agents need Filigree promotion, deduplication, or close/reopen lifecycle state. |

Realistic invocation — scan the source tree, emit SARIF to a file, and fail the
build on any `ERROR`-or-worse finding:

```text
$ wardline scan src/ --format sarif --output wardline.sarif --fail-on ERROR
```

Incremental local run reusing a warm cache:

```text
$ wardline scan src/ --cache-dir .wardline/cache
```

See the [getting-started guide](../getting-started.md) for a first end-to-end
scan and how to read the findings.

## `wardline file-finding`

**Purpose:** promote one already-emitted finding, keyed by fingerprint, into a
tracked Filigree issue. Requires a Filigree Loom scan-results URL.

```text
Usage: wardline file-finding [OPTIONS] FINGERPRINT [PATH]

  File the finding identified by FINGERPRINT into a tracked Filigree issue.

Options:
  --config FILE
  --filigree-url TEXT        Filigree Loom URL (else env/wardline.yaml).
  --clarion-url TEXT         Clarion URL used with --attach-clarion-identity.
  --attach-clarion-identity  After filing, resolve the finding qualname
                             through Clarion and attach a Filigree entity
                             association.
  --priority TEXT            Filigree priority, e.g. P2.
  --label TEXT               Label to attach (repeatable).
  --help                     Show this message and exit.
```

Without `--attach-clarion-identity`, the JSON result is the promotion result:
`reachable`, `issue_id`, `created`, `not_found`, `fingerprint`, and
`disabled_reason`.

With `--attach-clarion-identity`, Wardline re-runs the scan locally to find the
matching finding qualname, resolves it through Clarion, and attempts a Filigree
entity association only after promotion returns an `issue_id`. The response adds
an `identity_attach` block with `attempted`, `attached`, `entity_id`,
`content_hash`, `binding_kind`, and `reason`. SEI bindings are preferred. If
Clarion can only resolve a legacy locator and no current content hash is
available, Wardline reports that explicitly and does not attach a false hash;
the promoted issue is still returned.

## `wardline judge`

**Purpose:** run the opt-in LLM triage judge over the *active* DEFECT findings
(those not already suppressed by the baseline) and classify each as a true
positive or a false positive. Dependency-free — it reaches OpenRouter over
stdlib `urllib`, so no extra is required.

```text
Usage: wardline judge [OPTIONS] [PATH]

  Triage active DEFECTs with the opt-in LLM judge.

Options:
  --config PATH
  --model TEXT             OpenRouter model slug (overrides config).
  --context-lines INTEGER  Excerpt radius (default 30).
  --max-findings INTEGER   Cap findings triaged this run.
  --write                  Append FALSE_POSITIVE verdicts to
                           .wardline/judged.yaml (default: dry-run).
  --help                   Show this message and exit.
```

| Option | Effect |
| --- | --- |
| `--config PATH` | Path to a `wardline.yaml` config; supplies the default model slug and other judge settings. The API key is **never** read from config — it comes only from the `WARDLINE_OPENROUTER_API_KEY` environment variable or a `.env` in the scan root. |
| `--model TEXT` | OpenRouter model slug, overriding whatever the config sets for this one run. |
| `--context-lines INTEGER` | How many source lines on each side of a finding to include in the excerpt sent to the model. Default is `30`. |
| `--max-findings INTEGER` | Hard cap on how many findings to triage this run — useful to bound token spend. |
| `--write` | Persist `FALSE_POSITIVE` verdicts to `.wardline/judged.yaml`. **Without `--write` the command is a dry run** that prints verdicts but changes nothing. |

By default `judge` is a dry run: it prints what it *would* suppress. Add
`--write` only once you trust the verdicts.

Dry-run triage of at most 20 findings with an explicit model:

```text
$ wardline judge src/ --model anthropic/claude-opus-4-8 --max-findings 20
```

Commit the suppressions once satisfied:

```text
$ wardline judge src/ --write
```

The judge is opt-in and the safe default is dry-run; see the
[judge guide](../guides/judge.md) for credentials, the `.wardline/judged.yaml`
format, and the false-positive workflow.

## `wardline vocab`

**Purpose:** print the NG-25 trust-vocabulary descriptor as YAML so a consumer
can *read* the canonical decorator names instead of importing Wardline. Ships
with the CLI.

```text
Usage: wardline vocab [OPTIONS]

  Emit the NG-25 trust-vocabulary descriptor as YAML (read-instead-of-import).

Options:
  --help  Show this message and exit.
```

It takes no arguments. The output is the canonical descriptor:

```text
$ wardline vocab
version: wardline-generic-2
entries:
- canonical_name: external_boundary
  group: 1
  attrs: {}
- canonical_name: trust_boundary
  group: 1
  attrs:
    _wardline_to_level: TaintState
- canonical_name: trusted
  group: 1
  attrs:
    _wardline_level: TaintState
```

Each entry names a decorator, its group (`1`), and the marker attribute it
stamps (`trust_boundary` carries `_wardline_to_level`, `trusted` carries
`_wardline_level`, and `external_boundary` carries none). Tooling that wants to
recognise Wardline decorations without taking a dependency on Wardline can parse
this YAML. Application code that needs runtime imports should depend on the tiny
`loom-markers` package and import `loom_markers.*`; Wardline recognizes that
namespace and the backward-compatible `wardline.decorators.*` namespace. For
what the three decorators actually declare, see the
[trust vocabulary reference](vocabulary.md).

## `wardline baseline`

**Purpose:** the baseline command group. The baseline (`.wardline/baseline.yaml`)
records the set of findings you have accepted, so future scans report only
*new* findings. Requires the `scanner` extra.

```text
Usage: wardline baseline [OPTIONS] COMMAND [ARGS]...

  Manage the finding baseline (.wardline/baseline.yaml).

Options:
  --help  Show this message and exit.

Commands:
  create  Write a new baseline from current findings (refuses if one...
  update  Re-derive and overwrite the baseline from current findings.
```

The group has two subcommands. `create` is for first-time setup and refuses to
clobber an existing baseline; `update` deliberately overwrites.

### `wardline baseline create`

**Purpose:** write a fresh baseline from the current findings. **Refuses if a
baseline already exists** — this is the safe, first-time command.

```text
Usage: wardline baseline create [OPTIONS] [PATH]

  Write a new baseline from current findings (refuses if one exists).

Options:
  --config PATH
  --help         Show this message and exit.
```

`PATH` is the directory to scan (current directory if omitted). `--config`
points at a `.wardline` config so the baseline lands where the config expects.

Establish a baseline for an existing project so a noisy first scan does not
break the build:

```text
$ wardline baseline create src/
```

If a baseline already exists this command will refuse rather than overwrite — to
replace it, use `baseline update` below.

### `wardline baseline update`

**Purpose:** re-derive the baseline from current findings and **overwrite** the
existing one. Use this after you have genuinely resolved or accepted changes and
want the baseline to reflect the new reality.

```text
Usage: wardline baseline update [OPTIONS] [PATH]

  Re-derive and overwrite the baseline from current findings.

Options:
  --config PATH
  --help         Show this message and exit.
```

Unlike `create`, `update` expects a baseline to exist and replaces it
unconditionally — so run it deliberately, never as a reflex to silence a scan.

Refresh the baseline after a round of fixes:

```text
$ wardline baseline update src/
```

!!! warning
    `baseline update` overwrites whatever is there. Any finding present in the
    current scan becomes part of the accepted set, including genuinely new
    defects. Review the scan output *before* updating.

For the full baseline-and-waiver workflow — when to baseline vs. waive, and how
the baseline interacts with the judge — see the
[suppression guide](../guides/suppression.md).
