# Assurance posture

A defect report answers "what is wrong?". The assurance posture answers the
prior question a fail-closed tool must own: **how much of the declared trust
surface did the engine reach a definite verdict on, and how much is honestly
unknown?**

This is the "prove your coverage" answer an IRAP or SOC 2 assessor will ask
that a small team otherwise cannot give — and no tool lacking explicit
`UNKNOWN_*` states can replicate it, because a tool without an honesty gap has
already silently promoted every undecided case to "clean".

## The trust surface

Wardline's trust surface is the set of functions that have *declared* a trust
level via one of the three trust decorators:

| Decorator | What it marks |
|---|---|
| `@external_boundary` | Data source — declares `EXTERNAL_RAW` trust |
| `@trust_boundary(to_level=…)` | Validator — raises trust when it rejects bad input |
| `@trusted(level=…)` | Trusted producer — must only receive data at its declared tier |

Undecorated code is the **developer-freedom zone**: unknown trust, no policy
fires, and it never enters the coverage denominator. `assure` is not about
*all* code — it is about every entity where a developer made a commitment.

## Coverage: definite verdict vs. the honesty gap

```
coverage_pct = 100 × (boundaries_total − unknown_count) / boundaries_total
```

A **definite verdict** is either:

- **proven** — the engine confirmed the entity's return taint matches its
  declaration (no active defect).
- **defect** — the engine found a policy violation (an active defect counts as
  *covered*: a definite negative verdict is still a verdict).

The **honesty gap** is `unknown` — entities whose trust the engine could not
determine. Wardline records these explicitly rather than silently passing them.

When `boundaries_total == 0` (no trust annotations in the scanned path) the
result is a vacuous `100.0`: there is nothing to be unknown about.

## The structured posture object

Both the CLI (`wardline assure PATH --format json`) and the MCP `assure` tool
return the same object (identical by construction — both call the same
`build_posture` function):

```json
{
  "boundaries_total": 12,
  "proven": 9,
  "defect_total": 1,
  "unknown": [
    {
      "qualname": "myapp.ingestion.parse_payload",
      "tier": "ASSURED",
      "location": {"path": "src/myapp/ingestion.py", "line": 47},
      "reason": null
    },
    {
      "qualname": "myapp.io.fetch_record",
      "tier": null,
      "location": {"path": "src/myapp/io.py", "line": 103},
      "reason": "WLN-ENGINE-PARSE-ERROR: syntax error at line 103"
    }
  ],
  "engine_limited": 1,
  "coverage_pct": 83.3,
  "unanalyzed_rule_ids": ["WLN-ENGINE-PARSE-ERROR"],
  "waiver_debt": [
    {
      "fingerprint": "sha256:a1b2c3...",
      "expires": "2026-09-01",
      "days_left": 90,
      "reason": "Accepted FP: external validator upstream, mitigated by network policy"
    }
  ],
  "baselined_total": 1,
  "judged_total": 0
}
```

### Field reference

| Field | Type | Meaning |
|---|---|---|
| `boundaries_total` | int | Count of anchored (trust-declared) entities — the denominator |
| `proven` | int | Entities with a clean verdict (no active defect) |
| `defect_total` | int | Entities with an active defect (covered — a definite negative verdict) |
| `unknown` | list | Entities with no definite verdict — the honesty gap |
| `engine_limited` | int | Subset of `unknown` caused by engine under-scan (parse/recursion skip → `WLN-ENGINE-*` FACT) |
| `coverage_pct` | float | `100 × (boundaries_total − unknown_count) / boundaries_total`; `100.0` when denominator is 0 |
| `unanalyzed_rule_ids` | list[str] | Distinct `WLN-ENGINE-*` rule ids seen in findings — indicates *why* engine-limited unknowns occurred |
| `waiver_debt` | list | Every configured waiver from `wardline.yaml`, with days-to-expiry |
| `baselined_total` | int | Findings suppressed via the accepted baseline |
| `judged_total` | int | Findings suppressed as LLM-judged false positives |

#### `unknown[]` entry

| Field | Meaning |
|---|---|
| `qualname` | Fully-qualified function name |
| `tier` | Declared trust tier, or `null` if undeclared |
| `location.path` | Repo-relative source path |
| `location.line` | Line where the entity is declared |
| `reason` | The `WLN-ENGINE-*` FACT message if engine-limited, else `null` |

A `null` reason means the entity's trust simply could not be proven from the
code — the engine reached the entity but could not compute a definite verdict.
A non-null reason means the engine skipped the body entirely (parse error,
recursion depth) and the entity was never analysed.

#### `waiver_debt[]` entry

| Field | Meaning |
|---|---|
| `fingerprint` | Finding fingerprint the waiver covers |
| `expires` | ISO-8601 expiry date, or `null` for no-expiry waivers |
| `days_left` | `(expires − today).days`; negative for lapsed waivers; `null` for no-expiry |
| `reason` | Required human reason recorded when the waiver was accepted |

Lapsed waivers (`days_left < 0`) are surfaced, not dropped — accepted debt
that has outlived its acceptance window stays visible so it cannot hide
indefinitely behind a waiver entry.

!!! note "Waiver debt is always reported"
    `waiver_debt` is populated even when `boundaries_total == 0` (nothing
    analysable). Waivers are a config-level rollup independent of whether the
    engine found anything to cover — suppressing them on an empty scan would
    hide accepted debt behind an empty result (a false green).

## Empty trust surface

When the scanned path contains no trust-annotated functions:

```json
{
  "boundaries_total": 0,
  "proven": 0,
  "defect_total": 0,
  "unknown": [],
  "engine_limited": 0,
  "coverage_pct": 100.0,
  "unanalyzed_rule_ids": [],
  "waiver_debt": [],
  "baselined_total": 0,
  "judged_total": 0
}
```

The human format prints: `No trust surface declared (0 trust-annotated
boundaries) — nothing to assure.` This is the expected result for a path that
has not yet declared any trust — it is not a health signal either way.

## Agent-first: calling `assure` via MCP

The primary consumer of `assure` is an agent using the MCP tool — the
structured object is designed to be read and acted on programmatically, not
piped through jq.

**Scenario:** before the agent merges a PR that touches `myapp.ingestion`, it
calls `assure` to decide whether the module is trustworthy enough to merge.

Tool call:

```json
{
  "name": "assure",
  "arguments": {
    "path": "src/myapp"
  }
}
```

The agent reads the result and branches:

```python
posture = call_mcp("assure", {"path": "src/myapp"})

if posture["coverage_pct"] < 80.0:
    # Too many unknowns — flag for human review before merge.
    block_merge(reason=f"Coverage {posture['coverage_pct']}% below threshold")

if posture["unknown"]:
    engine_limited = [u for u in posture["unknown"] if u["reason"] is not None]
    unprovable     = [u for u in posture["unknown"] if u["reason"] is None]
    if engine_limited:
        # Engine could not parse these bodies — surface them.
        report_parse_failures(engine_limited, posture["unanalyzed_rule_ids"])
    if unprovable:
        # Engine reached these but trust is undeclared or unprovable.
        # May be a missing decorator or a complex data-flow pattern.
        report_unprovable_boundaries(unprovable)

lapsed = [w for w in posture["waiver_debt"] if w["days_left"] is not None and w["days_left"] < 0]
if lapsed:
    # Accepted-debt waivers have expired — require re-review before merge.
    block_merge(reason=f"{len(lapsed)} lapsed waiver(s) need re-review")
```

The agent does not need to inspect every finding — it reads the coverage ratio
and the honesty gap directly, and acts on what it finds.

### MCP tool schema

```json
{
  "name": "assure",
  "description": "Trust-surface COVERAGE posture: how many declared trust boundaries the engine reached a definite verdict on vs. how many are honestly unknown, plus waiver-debt. Consult before deciding to trust a module.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": {"type": "string"},
      "config": {"type": "string"}
    }
  }
}
```

Both `path` and `config` are optional. When omitted, `path` defaults to the
server root and `config` resolves to `wardline.yaml` at the scan root. Paths
are confined under the server root (the same guarantee as `scan`).

## CLI quick reference

```console
$ wardline assure src/myproject --format human
Trust-surface coverage: 91.7% (11/12 boundaries reached a definite verdict)
  proven:   9
  defect:   1
  unknown:  1  (1 engine-limited)
  Unknown boundaries:
    myapp.io.fetch_record  src/myapp/io.py:103  [WLN-ENGINE-PARSE-ERROR: ...]
  1 waiver(s); 90 day(s) until earliest expiry
```

```console
$ wardline assure src/myproject --format json
{"boundaries_total": 12, "proven": 9, ...}
```

The default format is `json`. Pass `--config path/to/wardline.yaml` to point
at a config file in a non-standard location.

## Zero setup

`assure` is zero-config: no new configuration is required. It reads what every
scan already computes and applies the same config (`wardline.yaml`) and waivers
that govern `scan`. Run it on a path that already has trust annotations and you
immediately know your coverage.

## See also

- [Using Wardline with your coding agent](agents.md) — the full MCP tool
  surface including `scan`, `explain_taint`, and `judge`.
- [Suppressing findings](suppression.md) — baselines, waivers, and the
  `judged.yaml` record (all three suppression counts appear in `assure`).
- [Configuration](configuration.md) — `wardline.yaml` keys including the
  `waivers:` block that feeds `waiver_debt`.
- [Rules](../concepts/rules.md) — the `WLN-ENGINE-*` rule ids that appear in
  `unanalyzed_rule_ids`.
