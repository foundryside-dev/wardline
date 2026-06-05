# Suppressing findings

Wardline has three suppression layers, each for a different situation. All three
key on a finding's full `fingerprint` — a stable 64-character hex hash — so a
suppression survives across runs but is re-keyed if the finding's line moves
(see the note at the bottom).

| Layer | Where it lives | Authored by | Use it when |
|---|---|---|---|
| **Baseline** | `.wardline/baseline.yaml` | `wardline baseline create/update` | Adopting Wardline on an existing codebase: accept today's findings wholesale and gate only on new ones. |
| **Waiver** | `wardline.yaml` (`waivers:`) | a human | One specific finding is a known false positive or accepted risk; you want a recorded reason and (optionally) an expiry. |
| **Judged FP** | `.wardline/judged.yaml` | the LLM judge (`wardline judge --write`) | The opt-in judge ruled a finding a false positive and you accept that verdict. |

When more than one layer matches a finding, **precedence is waiver > judged >
baseline** — explicit human intent wins, and an LLM verdict wins over a silent
baseline so its rationale is the visible reason. A scan summary reports the
breakdown:

```console
$ wardline scan .
scanned 2 file(s); 4 finding(s) — 1 suppressed (1 baseline / 0 waiver / 0 judged), 0 new -> findings.jsonl
```

## Suppressions and the `--fail-on` gate (read this first)

All three layers — baseline, waiver, judged — live in **committed repository
content** (`.wardline/baseline.yaml`, `wardline.yaml`, `.wardline/judged.yaml`).
That makes them attacker-controllable in an untrusted pull request: a PR can add a
suppression entry keyed to its own new defect's fingerprint.

So, **by default the `--fail-on` gate evaluates the *unsuppressed* population.**
Baseline / waiver / judged still **annotate** every emitted finding (you see
`suppressed: baselined | waived | judged` in the output) — they just do **not**
clear the gate. A self-suppressing PR therefore still goes red.

Two ways to scope or relax the gate, depending on trust:

- **`--new-since <merge-base>` — the secure CI ratchet.** The git ref is supplied
  by the operator (the pipeline), not by repository content, so it is unforgeable.
  It scopes **both** the emitted findings and the gate to findings new since the
  ref: a pre-existing defect outside the delta does not trip; a new one inside it
  does, and no committed suppression can clear it. This is the recommended adopt-an-
  existing-codebase pattern in CI.
- **`--trust-suppressions` — trusted local checkouts only.** Restores the old
  behaviour: baseline / waiver / judged clear the gate. Use it when you are running
  Wardline on a checkout you trust (your own working tree, the judge DX loop). **Do
  not** enable it in CI on untrusted PR content.

The MCP `scan` tool mirrors this exactly: `new_since` and a `trust_suppressions`
boolean (default false).

## Baseline

A baseline is a git-committable snapshot of findings you accept as-is. It is the
fast on-ramp for an existing project: capture everything once so they are
annotated as `baselined` in scan output.

Note (changed): a baseline **annotates** but no longer clears the `--fail-on`
gate by default — see [Suppressions and the `--fail-on` gate](#suppressions-and-the-fail-on-gate-read-this-first)
above. To make the gate "fire only on findings that appear after the snapshot",
use the unforgeable `--new-since <merge-base>` ratchet in CI, or
`--trust-suppressions` on a trusted local checkout.

```
wardline baseline [OPTIONS] COMMAND [ARGS]...

  Manage the finding baseline (.wardline/baseline.yaml).

Commands:
  create  Write a new baseline from current findings (refuses if one exists).
  update  Re-derive and overwrite the baseline from current findings.
```

```
wardline baseline create [OPTIONS] [PATH]

  Write a new baseline from current findings (refuses if one exists).

Options:
  --config PATH
  --help         Show this message and exit.
```

`create` writes `.wardline/baseline.yaml` and refuses to clobber an existing one;
`update` re-derives and overwrites. Only DEFECT findings are baselined, and any
finding with an active waiver is excluded (so its waiver expiry still resurfaces
it later).

```console
$ wardline baseline create .
baselined 1 finding(s) -> .wardline/baseline.yaml: 1 ERROR
```

```console
$ wardline baseline create .
.wardline/baseline.yaml already exists; use `wardline baseline update` to overwrite.
```

The file carries `rule_id` / `path` / `message` per entry purely for human
auditability in a git diff; only the `fingerprint` is loaded into the match set.

```yaml
version: 1
entries:
- fingerprint: 7bd0099a6e87d1a7e5994d175da5dd5d5de422747b189e4223273ea8eaa9980d
  rule_id: PY-WL-101
  path: svc.py
  message: svc.leaky declares return trust INTEGRAL but actually returns EXTERNAL_RAW
    (less trusted) — untrusted data reaches a trusted producer
```

Commit `.wardline/baseline.yaml`. Re-run `wardline baseline update` whenever you
intentionally accept a new batch of findings, then commit the diff.

## Waivers

A waiver suppresses one finding by fingerprint, with a **required reason** and an
**optional ISO expiry**. Waivers are hand-authored inline in `wardline.yaml`:

```yaml
waivers:
  - fingerprint: 7bd0099a6e87d1a7e5994d175da5dd5d5de422747b189e4223273ea8eaa9980d
    reason: "validated downstream by the gateway; engine cannot see the guard"
    expires: 2026-12-31
```

Copy the `fingerprint` from a scan's JSONL output. The `reason` must be a
non-empty string; a duplicate fingerprint or a non-ISO `expires` is a hard error.

```console
$ wardline scan .
scanned 2 file(s); 4 finding(s) — 1 suppressed (0 baseline / 1 waiver / 0 judged), 0 new -> findings.jsonl
```

Expiry is **inclusive**: a waiver is active through its `expires` day and lapses
only strictly after it (`today > expires`). When it lapses the finding resurfaces
as active — an expiry is a built-in review reminder, not a permanent mute. Omit
`expires` for a waiver that never lapses.

Reach for a waiver (not the baseline) when you have a *specific, explained*
acceptance for *one* finding. The baseline is the bulk accept-everything tool;
waivers are surgical and self-documenting.

## Judged false positives

When you run the opt-in [LLM triage judge](judge.md) with `--write`, its
FALSE_POSITIVE verdicts (at or above the configured confidence floor) are
appended to `.wardline/judged.yaml`. This is the same machine-vs-human split as
the baseline: hand-authored waivers stay clean in `wardline.yaml`, while
machine-judged FPs live in their own file with full provenance.

Each record carries the model's verbatim `rationale` — the audit primitive — plus
`model_id`, `confidence`, `recorded_at`, and a `policy_hash` so a re-run under a
changed prompt is a visible audit signal.

```yaml
version: 1
findings:
- fingerprint: <64-hex>
  rule_id: PY-WL-101
  path: svc.py
  message: <finding message>
  verdict: FALSE_POSITIVE
  rationale: <verbatim model reasoning — the audit record>
  confidence: 0.9
  model_id: anthropic/claude-opus-4-8
  recorded_at: 2026-05-30T00:00:00+00:00
  policy_hash: sha256:<...>
```

Commit `.wardline/judged.yaml` like the baseline. A judged suppression is
advisory — the rationale is recorded precisely so a human can audit it and revert
by deleting the entry. Like the other layers it **annotates** but does not clear
the `--fail-on` gate by default (see [the gate section](#suppressions-and-the-fail-on-gate-read-this-first));
the `judge` workflow itself always consults judged records. Each record must carry
`verdict: FALSE_POSITIVE` — a record without it, or with any other verdict, is
rejected on load so a hand-edited entry cannot become a silent suppression. See the
[LLM triage judge](judge.md) guide for how verdicts are produced and the `--write`
confidence floor.

## A note on line sensitivity

All three layers key on the full fingerprint, which includes the finding's start
line (a deliberate strict-matching dial). A cosmetic edit that shifts a line —
adding an import or a docstring — re-keys the finding: a previously
baselined/waived/judged defect resurfaces as active. After a refactor that moves
lines, regenerate the baseline (`wardline baseline update`) and re-copy any
affected waiver fingerprints.
