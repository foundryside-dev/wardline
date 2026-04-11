# 2026-04-12 Adversarial Panel Adjudication

## Purpose

This note preserves the external adversarial review of the rewritten
conformance chapter and records the result of a branch-level, first-principles
check against the current repository. It exists so the review is not lost while
the compliance model is reworked.

## Verdict

The adversarial report surfaced several real release-blocking defects, but it
also mixed those with policy-extension requests and a small number of incorrect
claims. The net result is:

- valid: the report found real conformance-model defects that must be tracked
- partial: several claims are directionally right but technically overstated
- incorrect: a few claims do not match the current branch

## High-Confidence Valid Findings

| Finding | Result | Evidence | Tracker |
|---|---|---|---|
| §15 worked examples claim passing rows contradicted by live branch evidence | Valid | `wardline.conformance.json` reports `corpus_verdict: FAIL` with 17 cells below floor while `docs/spec/wardline-01-15-conformance.md` shows worked-example `pass` rows | `wardline-9243d037e7` |
| Conformance floors and specimen schema have drifted across §11, §15, live schema, and verifier behavior | Valid | `docs/spec/wardline-01-11-verification-properties.md`, `docs/spec/wardline-01-15-conformance.md`, `src/wardline/manifest/schemas/corpus-specimen.schema.json`, `src/wardline/cli/corpus_cmds.py` disagree on fields and threshold semantics | `wardline-735e7f15fe` |
| L3 taint propagation uses trust ordering rather than the normative `taint_join` algebra | Valid | `src/wardline/core/taints.py` defines the normative join; `src/wardline/scanner/taint/callgraph.py` and `callgraph_propagation.py` use `TRUST_RANK` and `max()` | `wardline-cf49edcde8` |
| Criterion 4 and the analysis-level contract are ambiguous relative to the current implementation | Valid | `docs/spec/wardline-01-15-conformance.md` and `docs/spec/wardline-02-A-python-binding.md` promise minimum two-hop scope at level 1, but general callgraph taint propagation only runs at level 3 | `wardline-dac6c4195a` |
| Self-hosting pass/fail semantics are underdefined in the chapter and too weak in the current report | Valid | `src/wardline/cli/corpus_cmds.py` treats self-hosting as pass when there are zero unexcepted `error` findings, even when warnings and suppressed findings remain | `wardline-625c233fde` |

## Partial Findings

| Finding | Result | Notes |
|---|---|---|
| No cryptographic binding of sign-off to artefact state | Partial | The SARIF and conformance artefacts already carry hashes and input identity fields, but §15 does not require sign-off records to bind to them. |
| Corpus oracle is only a smoke test | Partial | The live verifier does compare line, text, and function for structured true-positive specimens, but true negatives and severity/exceptionability checks are weaker than §11 implies. |
| Exception register is an ungated escape hatch | Partial | The register is large and Lite governance is permissive, but the strongest attack-tree language is rhetoric rather than a direct contradiction. |
| Determinism claim is unsound | Partial | File discovery is unsorted in the engine, but SARIF results are sorted before emission. This is a real risk surface, not yet proof that verification-mode output is unstable. |

## Incorrect or Overstated Findings

| Finding | Result | Notes |
|---|---|---|
| The integration-marked corpus-oracle test is excluded by default | Incorrect | `pyproject.toml` excludes only `network` by default on this branch. The marker description is stale, but the test is not deselected by config. |
| Part I to Part II rule mapping is only advisory | Overstated | The Python binding includes an explicit rule-mapping table in `docs/spec/wardline-02-A-python-binding.md`. |
| External control-catalog alignment and signed attestations are direct chapter contradictions | Overstated | These are strong governance-hardening requests, but they are not already promised elsewhere in the current spec set. |

## Action

The review has been preserved in tracker form before further work:

- `wardline-9243d037e7` — fix §15 worked examples
- `wardline-735e7f15fe` — reconcile §11, §15, and corpus schema/floors
- `wardline-cf49edcde8` — align taint propagation with `taint_join`
- `wardline-dac6c4195a` — define criterion 4 / analysis levels clearly
- `wardline-625c233fde` — define self-hosting semantics in SARIF terms
- `wardline-fae28f1be3` — replace the release-only conformance model with the obligation-ledger compliance model

This adjudication is an input to the new compliance ledger, not a substitute for
it.
