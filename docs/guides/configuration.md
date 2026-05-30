# Configuration

Wardline reads an optional `wardline.yaml` from the scan root (or a path passed
with `--config`). Every command — `scan`, `judge`, `baseline` — loads the same
file. With no config, Wardline scans `.` with all rules enabled.

!!! warning "Unknown or mistyped keys are hard errors"
    `wardline.yaml` is validated against a JSON Schema (draft 2020-12) on load.
    The top level, the `rules` block, and the `judge` block all set
    `additionalProperties: false`, so a typo'd key or an out-of-range value
    **fails loud** — Wardline exits `2` rather than silently ignoring it.

    ```console
    $ wardline scan .
    error: invalid wardline.yaml: Additional properties are not allowed ('bogus_key' was unexpected)
    ```

    ```console
    $ wardline scan .
    error: invalid wardline.yaml: -5 is less than the minimum of 0
    ```

## Top-level keys

| Key | Type | Purpose |
|---|---|---|
| `source_roots` | array of strings | Roots to discover Python under (default `["."]`). |
| `exclude` | array of strings | Path patterns to skip during discovery. |
| `rules` | object | Enable/disable rules and override severities. |
| `baseline` | object | Reserved; inert. See note below. |
| `waivers` | array of objects | Fingerprint-keyed suppressions with optional expiry. |
| `judge` | object | Settings for the opt-in LLM triage judge. |
| `filigree` | object | Reserved; inert. |
| `clarion` | object | Reserved; inert. |

### `source_roots` / `exclude`

```yaml
source_roots:
  - src
  - lib
exclude:
  - "**/migrations/**"
  - tests
```

When `source_roots` is omitted it defaults to `["."]` (the scan path).

### `rules`

Two sub-keys, both optional (`additionalProperties: false` — a typo here is a
hard error):

- `enable` — array of strings. Rule IDs (or `"*"`) to run. Defaults to `["*"]`
  (all rules).
- `severity` — object mapping a rule ID to a severity string, overriding the
  rule's built-in severity.

```yaml
rules:
  enable:
    - "*"
  severity:
    PY-WL-103: WARN
    PY-WL-104: INFO
```

### `waivers`

An array of objects, each keyed on a finding's full `fingerprint`. A waiver
needs a `reason` and may carry an ISO `expires` date. Covered in detail under
[Suppressing findings](suppression.md#waivers).

```yaml
waivers:
  - fingerprint: 7bd0099a6e87d1a7e5994d175da5dd5d5de422747b189e4223273ea8eaa9980d
    reason: "validated downstream by the gateway; engine cannot see the guard"
    expires: 2026-12-31
```

### `judge`

Settings for the opt-in LLM triage judge (`additionalProperties: false`). All
keys are optional; the defaults are shown.

| Key | Type | Default | Constraint |
|---|---|---|---|
| `model` | string | `anthropic/claude-opus-4-8` | OpenRouter model slug. |
| `context_lines` | integer | `30` | `>= 0`. Excerpt radius around a finding. |
| `max_findings` | integer | unset (all) | `>= 1`. Cap findings triaged per run. |
| `policy_file` | string | unset | Path (under the scan root) to an extra project policy appended to the built-in prompt. |
| `write_confidence_floor` | number | `0.5` | `0.0`–`1.0`. FALSE_POSITIVE verdicts below this are reported but not written under `--write`. |

```yaml
judge:
  model: anthropic/claude-opus-4-8
  context_lines: 30
  write_confidence_floor: 0.5
```

Out-of-range values fail loud:

```console
$ wardline judge .
error: invalid wardline.yaml: 2.0 is greater than the maximum of 1.0
```

See [LLM triage judge](judge.md) for what each setting does.

### Reserved keys: `baseline`, `filigree`, `clarion`

These three keys are accepted as objects but are **reserved and currently
inert**. They do not validate their internal shape, so do not add sub-keys
expecting behavior.

!!! note "The `baseline:` config key is not the baseline file"
    The committed finding baseline lives in `.wardline/baseline.yaml`, managed
    by `wardline baseline create|update` — **not** under the `baseline:` config
    key. See [Suppressing findings](suppression.md#baseline).

## A complete `wardline.yaml`

```yaml
source_roots:
  - src
exclude:
  - "**/migrations/**"

rules:
  enable:
    - "*"
  severity:
    PY-WL-103: WARN

waivers:
  - fingerprint: 7bd0099a6e87d1a7e5994d175da5dd5d5de422747b189e4223273ea8eaa9980d
    reason: "validated downstream by the gateway; engine cannot see the guard"
    expires: 2026-12-31

judge:
  model: anthropic/claude-opus-4-8
  context_lines: 30
  write_confidence_floor: 0.5
```

## See also

- [Suppressing findings](suppression.md) — baseline, waivers, judged FPs.
- [LLM triage judge](judge.md) — the `judge:` section in depth.
- [Loom integration](loom.md) — emitting findings to SARIF / Filigree.
