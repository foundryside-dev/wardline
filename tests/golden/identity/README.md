# Identity parity oracle

A byte-exact golden corpus of Wardline's externally-observable **identity** —
the cross-engine contract that gates the future Rust-core cutover. The Rust
engine must reproduce this corpus byte-for-byte before any cutover; **"parity
corpus green" is a hard gate** (see the ADR
`docs/decisions/2026-06-05-wardline-finding-identity-frozen-contract.md`).

## What it covers

Captured per input root by `_capture.py`, for the **identity-bearing** surface
only (`PY-WL-* ∧ Kind.DEFECT`) plus the peer-consumed payloads:

- **findings** — the real wire format (`Finding.to_jsonl()`): fingerprint,
  rule_id, qualname, location spans, properties, suppression, …
- **entity_spans** — qualname + full span (`line_start`/`line_end`/`col_start`/
  `col_end`) of **every** analyzed entity, so the parser's span rendering is
  frozen even for constructs that produce no finding (the brief's #1 risk).
- **taint facts** — `build_taint_facts(result, root)`, the exact Clarion payload
  (sorted by `qualname`; inner findings sorted).
- **SARIF** — `build_sarif(...)` with the mutable `driver.version` normalised to
  `<normalized>` and `ruleIndex` dropped (recoverable from `ruleId`); `codeFlows`
  causal sequences preserved.
- **assure posture** — `build_posture(root).to_dict()` (`corpus/assure.json`).
- **explain** — `explanation_from_context(...)` for the first identity-bearing
  finding per input.

Engine diagnostics (`WLN-ENGINE-*` / `WLN-L3-*` / `Kind.METRIC` / `Kind.FACT`)
are deliberately **excluded** — a different engine may legitimately differ on
them and they are not what downstream associations key on.

## Inputs

- `fixtures/sampleapp/` — vendored realistic app (fires `PY-WL-101`; 54 facts).
- `fixtures/stress/identity_stress.py` — purpose-built identity-edge fixture
  (decorated/nested/async/overloaded/methods/lambdas/comprehensions/unicode;
  fires `PY-WL-101` + `PY-WL-111`).

Fixtures carry **no** `.wardline/` or `wardline.yaml` (a baseline/waiver would
date-poison the corpus via `date.today()`); `.gitattributes` pins them to LF so
`blake3` content hashes stay reproducible.

## Determinism (verified before freezing)

In-process stable · path-independent · cross-process (`PYTHONHASHSEED` 0/1) ·
cross-interpreter (CPython 3.12 freeze ↔ 3.13 reproduce, byte-identical). So the
gate runs on every CI interpreter with no skip.

## Regenerating (intentional rekey ONLY)

The corpus changes only via a deliberate, reviewed rekey — never to silence an
accidental drift (that is a real regression; the failure dumps
`/tmp/corpus_actual_<name>.json` + a unified diff). **Enforcement is this parity
test in CI** — it fails any PR that changes `corpus/*` without a matching
production change. The `--reason` flag is the accountability record stamped into
`corpus/META.json`. *Recommended complement* (not yet wired): a `.github/CODEOWNERS`
entry `tests/golden/identity/corpus/ @<maintainer>` so a rekey also requires
maintainer review.

```bash
cd tests && PYTHONPATH=. python -m golden.identity.regen --reason "<why>"
```
