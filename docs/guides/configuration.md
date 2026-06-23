# Configuration

Wardline reads its settings from the `[wardline]` table of a shared,
operator-authored **`weft.toml`** at the scan root (or a TOML file passed with
`--config`). Every command — `scan`, `judge`, `baseline`, `assure`, `attest` —
loads the same table. `weft.toml` is the federation's shared operator file;
Wardline only ever **reads** its own `[wardline]` table and never writes it.

With no `weft.toml` (or no `[wardline]` table), Wardline boots on built-in
defaults: it scans `.` with all rules enabled.

!!! info "Missing or malformed `weft.toml` is a silent fallback, never a hard error"
    If `weft.toml` is **absent**, is **unreadable**, or **fails to parse as
    TOML**, Wardline silently falls back to its built-in defaults — it never
    hard-fails on a missing or malformed file. A `weft.toml` with no `[wardline]`
    table behaves the same way.

!!! warning "But unknown keys and out-of-range values in a *present* `[wardline]` table are hard errors"
    Once a `[wardline]` table parses, it is validated against a JSON Schema
    (draft 2020-12). The table, the `[wardline.rules]` block, the
    `[wardline.judge]` block, the `[wardline.artifacts]` block, and the
    `[wardline.autofix]` block all set `additionalProperties: false`, so a
    typo'd key or an out-of-range value **fails loud** — Wardline exits `2`
    rather than silently ignoring it.

    ```console
    $ wardline scan .
    error: invalid weft.toml (after merging packs): Additional properties are not allowed ('bogus_key' was unexpected)
    ```

    ```console
    $ wardline scan .
    error: invalid weft.toml (after merging packs): -5 is less than the minimum of 0
    ```

## Keys under `[wardline]`

Everything nests under the `[wardline]` table.

| Key | Type | Purpose |
|---|---|---|
| `source_roots` | array of strings | Roots to discover Python under (default `["."]`). |
| `exclude` | array of strings | Path patterns to skip during discovery. |
| `store_dir` | string | Operator override for Wardline's machine-state subtree (default `.weft/wardline`). A relative path resolves under the scan root. |
| `packs` | array of strings | Trust-grammar packs to load. Operator-authored only (packs import and execute code). |
| `rules` | table | Enable/disable rules and override severities. |
| `judge` | table | Settings for the opt-in LLM triage judge. |
| `artifacts` | table | Default scan artifact directory and retention. |
| `autofix` | table | Settings for the interactive autofix (`wardline fix`). |

!!! note "Sibling URLs are not config keys"
    There is **no** `[wardline.filigree].url` or `[wardline.loomweave].url`
    config key. Sibling endpoint URLs resolve only via the `--filigree-url` /
    `--loomweave-url` flag, the `WARDLINE_FILIGREE_URL` / `WARDLINE_LOOMWEAVE_URL`
    environment variable, or the published `<root>/.weft/<sibling>/ephemeral.port`
    rung (legacy `<root>/.<sibling>/ephemeral.port` is tolerated). See
    [Weft integration](weft.md).

!!! note "Waivers are not config keys"
    Waivers are fingerprint-keyed, machine/CLI-written suppression state — not
    operator config. They live in `.weft/wardline/waivers.yaml`, not in
    `weft.toml`. See [Suppressing findings](suppression.md#waivers).

### `source_roots` / `exclude`

```toml
[wardline]
source_roots = ["src", "lib"]
exclude = ["**/migrations/**", "tests"]
```

When `source_roots` is omitted it defaults to `["."]` (the scan path).

### `store_dir`

Wardline writes its machine state — `baseline.yaml`, `judged.yaml`, and
`waivers.yaml` — under `.weft/wardline/` at the scan root by default. An operator
may relocate that subtree:

```toml
[wardline]
store_dir = ".weft/wardline"   # the default; set to a path of your choosing
```

A relative `store_dir` resolves under the scan root. The attest signing key is
**not** part of this subtree — it lives in `.env` (see [Attestation](attestation.md)).

### `[wardline.artifacts]`

Scan outputs are written under `.wardline/` by default using timestamped names
such as `20260620T153012Z-findings.jsonl`. Wardline prunes older artifacts for
the same output format after each default-output scan:

```toml
[wardline.artifacts]
dir = ".wardline"  # the default; relative paths resolve under the scan root
retain = 20        # keep the newest 20 artifacts per format
```

Use `--output PATH` when a workflow needs an exact file path; explicit output
paths bypass artifact timestamping and retention.

### `packs`

Trust-grammar packs extend Wardline's vocabulary. Because a pack imports and
executes code, packs are **operator-authored** — `wardline install <pack>` only
*emits guidance* to add the pack here; it never writes `weft.toml` on your
behalf.

```toml
[wardline]
packs = ["myorg.trustpack"]
```

Then assert the pack at scan/judge time with `--trust-pack myorg.trustpack`.

### `[wardline.rules]`

Two sub-keys, both optional (`additionalProperties: false` — a typo here is a
hard error):

- `enable` — array of strings. Rule IDs (or `"*"`) to run. Defaults to `["*"]`
  (all rules).
- `severity` — table mapping a rule ID to a severity string, overriding the
  rule's built-in severity.

```toml
[wardline.rules]
enable = ["*"]
severity = { "PY-WL-103" = "WARN", "PY-WL-104" = "INFO" }
```

### `[wardline.judge]`

Settings for the opt-in LLM triage judge (`additionalProperties: false`). All
keys are optional; the defaults are shown.

| Key | Type | Default | Constraint |
|---|---|---|---|
| `model` | string | `anthropic/claude-opus-4-8` | OpenRouter model slug. |
| `context_lines` | integer | `30` | `>= 0`. Excerpt radius around a finding. |
| `max_findings` | integer | unset (all) | `>= 1`. Cap findings triaged per run. |
| `policy_file` | string | unset | Path (under the scan root) to an extra project policy appended to the built-in prompt. |
| `write_confidence_floor` | number | `0.5` | `0.0`–`1.0`. FALSE_POSITIVE verdicts below this are reported but not written under `--write`. |

```toml
[wardline.judge]
model = "anthropic/claude-opus-4-8"
context_lines = 30
write_confidence_floor = 0.5
```

Out-of-range values fail loud:

```console
$ wardline judge .
error: judge.write_confidence_floor must be 0.0..1.0, got 2.0
```

See [LLM triage judge](judge.md) for what each setting does.

### `[wardline.autofix]`

Settings for the interactive autofix (`wardline fix`).

| Key | Type | Purpose |
|---|---|---|
| `boundary_exception` | string | Dotted exception name the autofix may insert at a trust boundary (e.g. `ValueError`). |

```toml
[wardline.autofix]
boundary_exception = "ValueError"
```

## A complete `weft.toml`

```toml
[wardline]
source_roots = ["src"]
exclude = ["build/**"]
packs = ["myorg.trustpack"]

[wardline.rules]
enable = ["PY-WL-101"]
severity = { "PY-WL-101" = "ERROR" }

[wardline.judge]
model = "anthropic/claude-opus-4-8"
context_lines = 30

[wardline.autofix]
boundary_exception = "ValueError"
```

## See also

- [Suppressing findings](suppression.md) — baseline, waivers, judged FPs (machine state under `.weft/wardline/`).
- [LLM triage judge](judge.md) — the `[wardline.judge]` section in depth.
- [Weft integration](weft.md) — emitting findings to SARIF / Filigree and how sibling URLs resolve.
