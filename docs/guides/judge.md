# LLM triage judge

The judge is an **opt-in** escalation pass. It reads each *active* DEFECT
finding cold — no human rationale — and labels it `TRUE_POSITIVE` or
`FALSE_POSITIVE` with a calibrated confidence and a short, verbatim rationale.
Its practical job for a solo team is a false-positive filter over the taint
engine's known, documented over-approximations.

!!! info "Never required"
    There is **no LLM cost by default**. `wardline scan` never calls a model.
    The judge runs only when you invoke `wardline judge`, and even then it only
    *writes* suppressions when you pass `--write`. The whole feature is additive:
    Wardline boots, scans, and gates without it.

## Dependency-free by design

The judge ships in core with **no new runtime dependency**. Transport is a plain
standard-library `urllib` POST to OpenRouter's chat-completions endpoint
(`https://openrouter.ai/api/v1/chat/completions`), at `temperature=0` for
reproducible verdicts. There is no SDK, no `litellm`, no `anthropic` package — a
dep-free judge that works out of the box fits "lightweight, opt-in, no cost by
default".

## The API key

The judge authenticates with an OpenRouter key in
`WARDLINE_OPENROUTER_API_KEY` (note the `WARDLINE_` prefix). The core reads it
from the environment only — it never touches the filesystem for the key.

As a CLI convenience, if the variable is unset the `judge` command reads a single
`WARDLINE_OPENROUTER_API_KEY=...` line from a `.env` file in the scan root. An
already-set environment value always wins; the `.env` read never silently
overrides it.

If no key can be found and there are active defects to triage, the judge fails
loud with remediation guidance:

```console
$ wardline judge .
error: WARDLINE_OPENROUTER_API_KEY is not set. `wardline judge` calls OpenRouter to triage findings. Export the key (`export WARDLINE_OPENROUTER_API_KEY=sk-or-...`) or place it in a .env in the scan root, then re-run.
```

## Usage

```
wardline judge [OPTIONS] [PATH]

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

The judge loads config, scans, applies the existing baseline / waiver / judged
suppressions, and triages only the DEFECTs still active after that. So baselines
and waivers already shrink the set the judge pays for. With nothing active to
triage, it is a no-op and never calls a model:

```console
$ wardline judge .
triaged 0 defect(s): 0 true / 0 false
```

Flags override config (see the [`judge:` config section](configuration.md#judge)).
The default model is `anthropic/claude-opus-4-8`; the default excerpt radius is
30 lines.

## Dry-run vs. `--write`

By default `judge` is a **dry-run**: it prints a verdict per finding and writes
nothing. Each line shows a `TP`/`FP` tag, confidence, rule ID, location, and the
rationale. Low-confidence FP verdicts are tagged `FP?` and noted as held back.

`--write` appends the FALSE_POSITIVE verdicts to `.wardline/judged.yaml`, which a
later scan or judge run reads as suppressions
([judged FPs](suppression.md#judged-false-positives)).

### The confidence floor

`--write` is conservative: it writes a FALSE_POSITIVE only when its confidence is
**at or above** `judge.write_confidence_floor` (default `0.5`). The prior is
deliberate — never suppress a possibly-real defect on a low-confidence guess.
Below-floor FPs are reported but held back, and the held-back count is surfaced in
the summary in both modes. Set the floor to `0.0` to write every FP, or raise it
to demand more confidence.

## What gets written

Each written record carries the model's verbatim `rationale` (the audit
primitive) plus `model_id`, `confidence`, `recorded_at`, and a `policy_hash`. A
re-judge of the same fingerprint updates its record rather than duplicating it.
The verdict is advisory: the rationale is recorded so a human can audit it and
revert by deleting the entry. The judge never edits or deletes code. See
[Suppressing findings](suppression.md#judged-false-positives) for the file shape.

A malformed model response is **never coerced** — it crashes with a contract
error (exit `2`), because a corrupted audit record is worse than none. A bad key,
model, or request (a 4xx) is likewise loud (exit `2`); a transient server outage
(5xx / connection failure) is treated as a skip-and-warn, since the judge is not
a load-bearing stage.

## See also

- [Configuration](configuration.md#judge) — the `judge:` settings.
- [Suppressing findings](suppression.md) — where judged FPs sit among baseline and waivers.
