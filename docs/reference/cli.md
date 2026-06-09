# CLI reference

Complete reference for the `wardline` command-line interface, version `1.0.0rc4`.
Every `--help` block below is the verbatim output of the installed CLI; every
example is a realistic invocation.

## Installation and extras

The CLI is a [Click](https://click.palletsprojects.com/) application. Most
commands depend on the `scanner` extra; one (`judge`) is dependency-free beyond
the base CLI.

| Command | Requires | Why |
| --- | --- | --- |
| `scan` | `wardline[scanner]` | Runs the analyzer engine; needs `pyyaml`, `jsonschema`, `click`. |
| `decorator-coverage` | `wardline[scanner]` | Re-derives trust-decorator coverage rows from the analyzer context. |
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
  baseline  Manage the finding baseline (.weft/wardline/baseline.yaml).
  decorator-coverage
            List every Wardline trust-decorated entity under PATH.
  file-finding
            File the finding identified by FINGERPRINT into a tracked...
  judge     Triage active DEFECTs with the opt-in LLM judge.
  scan      Scan PATH for findings.
  vocab     Emit the NG-25 trust-vocabulary descriptor as YAML...
```

Check the installed version:

```text
$ wardline --version
wardline, version 1.0.0rc4
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
  --config FILE                   Path to a weft.toml whose [wardline] table
                                  supplies configuration overrides (weft.toml).
  --format [jsonl|sarif|agent-summary|legis]
  --lang [python|rust]            Language frontend. 'rust' (PREVIEW) scans
                                  .rs files for command-injection findings.
  --output PATH
  --fail-on [CRITICAL|ERROR|WARN|INFO]
  --cache-dir PATH                Persist L3 summary cache here for faster
                                  incremental scans.
  --filigree-url TEXT             POST findings to this Filigree Weft scan-
                                  results URL (opt-in).
  --help                          Show this message and exit.
```

`PATH` is a **directory** (defaults to the current directory if omitted). Point
it at a package root, not a single file.

| Option | Effect |
| --- | --- |
| `--config FILE` | Path to a `weft.toml` config file; Wardline reads its `[wardline]` table for rule enable/severity and judge settings (defaults to `weft.toml` in the scan path). |
| `--format [jsonl\|sarif\|agent-summary\|legis]` | Output shape. `jsonl` is one finding per line; `sarif` is SARIF 2.1.0 for GitHub code-scanning and other generic SARIF consumers; `agent-summary` is stable versioned JSON for agents (`schema: wardline-agent-summary-1`) with active defects first, suppressed findings, engine facts, integration status, and suggested next tool calls; `legis` is the signed, verbatim-postable `scan` for legis's `POST /wardline/scan-results` (signed when `WARDLINE_LEGIS_ARTIFACT_KEY` is provisioned — write it **outside** the working tree, see the [legis handoff guide](../guides/legis-handoff.md)). SARIF carries Wardline identity in `partialFingerprints["wardlineFingerprint/v2"]`; downstream Filigree lifecycle quality depends on importers preserving that field. |
| `--lang [python\|rust]` | Language frontend (default `python`). `rust` is a **preview** that sweeps `*.rs` for command-injection findings (`RS-WL-108`/`RS-WL-112`); needs the `wardline[rust]` extra. Findings carry provisional identity (baseline-ineligible) and config severity overrides do not apply — see the [Rust support guide](../guides/rust-preview.md). |
| `--output PATH` | Write findings to a file instead of stdout. |
| `--fail-on [CRITICAL\|ERROR\|WARN\|INFO]` | Exit non-zero when any finding at or above this severity survives the baseline. Use this as your CI gate. |
| `--cache-dir PATH` | Persist the L3 inter-procedural summary cache here so the next scan reuses unchanged summaries. |
| `--filigree-url TEXT` | Opt-in: POST findings to a Filigree Weft scan-results endpoint as well as emitting them locally. Prefer this native path when agents need Filigree promotion, deduplication, or close/reopen lifecycle state. |

Realistic invocation — scan the source tree, emit SARIF to a file, and fail the
build on any `ERROR`-or-worse finding:

```text
$ wardline scan src/ --format sarif --output wardline.sarif --fail-on ERROR
```

Incremental local run reusing a warm cache:

```text
$ wardline scan src/ --cache-dir .weft/wardline/cache
```

Agent handoff summary:

```text
$ wardline scan src/ --format agent-summary --output findings.agent-summary.json
```

See the [getting-started guide](../getting-started.md) for a first end-to-end
scan and how to read the findings.

## `wardline file-finding`

**Purpose:** promote one already-emitted finding, keyed by fingerprint, into a
tracked Filigree issue. Requires a Filigree Weft scan-results URL.

```text
Usage: wardline file-finding [OPTIONS] FINGERPRINT [PATH]

  File the finding identified by FINGERPRINT into a tracked Filigree issue.

Options:
  --config FILE
  --filigree-url TEXT        Filigree Weft URL (else flag/env).
  --loomweave-url TEXT         Loomweave URL used with --attach-loomweave-identity.
  --attach-loomweave-identity  After filing, resolve the finding qualname
                             through Loomweave and attach a Filigree entity
                             association.
  --priority TEXT            Filigree priority, e.g. P2.
  --label TEXT               Label to attach (repeatable).
  --help                     Show this message and exit.
```

Without `--attach-loomweave-identity`, the JSON result is the promotion result:
`reachable`, `issue_id`, `created`, `not_found`, `fingerprint`, and
`disabled_reason`.

With `--attach-loomweave-identity`, Wardline re-runs the scan locally to find the
matching finding qualname, resolves it through Loomweave, and attempts a Filigree
entity association only after promotion returns an `issue_id`. The response adds
an `identity_attach` block with `attempted`, `attached`, `entity_id`,
`content_hash`, `binding_kind`, and `reason`. SEI bindings are preferred. If
Loomweave can only resolve a legacy locator and no current content hash is
available, Wardline reports that explicitly and does not attach a false hash;
the promoted issue is still returned.

## `wardline decorator-coverage`

**Purpose:** list every Wardline trust-decorated entity with declared tier,
actual tier, gate verdict, active/suppressed finding fingerprints, optional
Loomweave SEI/content status, and optional Filigree linked-work status.

```text
Usage: wardline decorator-coverage [OPTIONS] [PATH]

  List every Wardline trust-decorated entity under PATH.

Options:
  --config FILE
  --loomweave-url TEXT       Loomweave URL for optional SEI/content status.
  --filigree-url TEXT      Filigree URL for optional linked issue/open-work
                           status.
  --format [json|human]    Output format: json (default) or human-readable
                           table.
  --help                   Show this message and exit.
```

JSON output is stable for agents: `summary` plus `rows`. Each row includes
`qualname`, `path`, `line`, `decorators`, `declared_tier`, `actual_tier`,
`verdict`, `finding_state`, `active_finding_fingerprints`,
`suppressed_finding_fingerprints`, `identity`, and `work`. Optional integrations
degrade explicitly: no Loomweave reports `identity.available=false`; no Filigree
reports `work.available=false`. A configured Filigree with zero linked tickets
reports `work.available=true` and an empty `tickets` list.

## `wardline scan-file-findings`

**Purpose:** run the common agent workflow in one call: scan, list active defects
with explanation summaries, optionally emit to Filigree, promote selected
findings, and attach Loomweave identity when available.

```text
Usage: wardline scan-file-findings [OPTIONS] [PATH]

  Run the agent workflow from scan to optionally filed Filigree issues.

Options:
  --config FILE
  --fail-on [CRITICAL|ERROR|WARN|INFO]
  --cache-dir PATH
  --filigree-url TEXT             Filigree Weft URL (else flag/env).
  --loomweave-url TEXT              Loomweave URL for optional identity
                                  attachment.
  --fingerprint TEXT              Active finding fingerprint to promote.
  --all-active                    Promote every active defect from this scan.
  --dry-run                       Only summarize active defects; do not emit
                                  or promote.
  --priority TEXT                 Filigree priority for promoted findings,
                                  e.g. P2.
  --label TEXT                    Label to attach to promoted findings.
  --trust-pack TEXT
  --allow-custom-packs
  --strict-defaults
  --help                          Show this message and exit.
```

With no selection flags, the command is a dry run. It returns `active_defects`
first; each entry includes fingerprint, rule, qualname, path/line, an
`explanation` summary, `promotion` status, and `identity_attach` status. Use
`--fingerprint` to promote specific active findings, or `--all-active` for the
whole active set. Partial failures stay visible in the JSON: Filigree emission,
per-finding promotion, unknown fingerprints, and Loomweave identity attachment are
reported independently.

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
                           .weft/wardline/judged.yaml (default: dry-run).
  --help                   Show this message and exit.
```

| Option | Effect |
| --- | --- |
| `--config PATH` | Path to a `weft.toml` config; its `[wardline]` table supplies the default model slug and other judge settings. The API key is **never** read from config — it comes only from the `WARDLINE_OPENROUTER_API_KEY` environment variable or a `.env` in the scan root. |
| `--model TEXT` | OpenRouter model slug, overriding whatever the config sets for this one run. |
| `--context-lines INTEGER` | How many source lines on each side of a finding to include in the excerpt sent to the model. Default is `30`. |
| `--max-findings INTEGER` | Hard cap on how many findings to triage this run — useful to bound token spend. |
| `--write` | Persist `FALSE_POSITIVE` verdicts to `.weft/wardline/judged.yaml`. **Without `--write` the command is a dry run** that prints verdicts but changes nothing. |

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
[judge guide](../guides/judge.md) for credentials, the `.weft/wardline/judged.yaml`
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
`weft-markers` package and import `weft_markers.*`; Wardline recognizes that
namespace and the backward-compatible `wardline.decorators.*` namespace. For
what the three decorators actually declare, see the
[trust vocabulary reference](vocabulary.md).

## `wardline baseline`

**Purpose:** the baseline command group. The baseline (`.weft/wardline/baseline.yaml`)
records the set of findings you have accepted, so future scans report only
*new* findings. Requires the `scanner` extra.

```text
Usage: wardline baseline [OPTIONS] COMMAND [ARGS]...

  Manage the finding baseline (.weft/wardline/baseline.yaml).

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
points at a `weft.toml` whose `[wardline]` table the baseline reads.

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
