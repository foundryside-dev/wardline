# P2 — collision finalizer guard (the tripwire)

> Phase 2 of the fingerprint rekey. See `…-00-index.md` for the spine.
> Run after P1, **strictly before P3**. **none** rekey-impact.
> Closes `wardline-8fb773a7af`.

> **✅ SHIPPED — `0a551c4` (guard) + `4928fbd` (real-chokepoint proof + member-list
> fix), rc4. `wardline-8fb773a7af` closed.** This file is reconciled post-hoc to the
> implementation that landed. The original draft proposed a non-gating
> `Kind.METRIC`/`Severity.NONE` diagnostic built by a singular `build_collision_finding`,
> with a separate `detect_fingerprint_collisions` detector scoped by hand to the
> `is_identity_bearing` population. The shipped design is **stronger and simpler** — a
> single gating-DEFECT builder over the full emitted set — see **What landed** below.

- **id:** `finalizer-guard`
- **goal:** Land the no-collision runtime guard so that when P3 removes `line_start`, any discriminator bug (incl. the latent broad/silent collision `wardline-6102d4c833`) fires LOUD instead of collapsing silently in `baseline.py` `setdefault`.
- **depends-on:** P1 (soft — operates on the bare in-memory hex, untouched by the scheme stamp). **Strictly BEFORE P3.**
- **rekey-impact:** **none.** The diagnostic carries a `WLN-ENGINE-*` rule_id; the identity corpus population is `PY-WL-* ∧ Kind.DEFECT` (ADR §2), so it is excluded **by prefix** — no rekey, frozen contract untouched. (Excluded by prefix, *not* by the draft's `Kind.METRIC`/`Severity.NONE` — the shipped diagnostic is a DEFECT and is still correctly absent from the corpus.)

**BLOCKER answered (record this):** duplicate-fp emission is NEVER legitimate between two findings a consumer would treat as DISTINCT. Every fingerprint consumer joins on `Finding.fingerprint` as a UNIQUE key — `baseline.generate_baseline` collapses same-fp with `setdefault` keep-first (`baseline.py:49`), `judged` is last-write-wins, the baseline/waiver/judged YAML loaders REJECT a duplicate outright, SARIF (`partialFingerprints`) and Filigree dedup downstream — so a distinct-pair collision silently masks one finding on all four joins (a real trust-boundary false-negative). The ONLY benign same-fp case is two **byte-identical** findings (collapsing loses nothing). `baseline.py:49`'s `setdefault` was silent insurance against a rule-suite bug; the guard makes it LOUD.

## What landed

The whole guard is one function — `build_collision_findings(findings)` in
`src/wardline/scanner/diagnostics.py` — wired as the last step of
`WardlineAnalyzer._analyze_inner` (`src/wardline/scanner/analyzer.py:661`; the public
`analyze` delegates through it), after `findings.extend(registry.run(context))` and
before `return findings`:

```python
findings.extend(build_collision_findings(findings))
```

- **One builder, not detector + builder.** The draft split detection
  (`detect_fingerprint_collisions`) from construction (`build_collision_finding`,
  singular). The shipped `build_collision_findings` (plural) does both: group the full
  emitted set by bare fingerprint, then emit one diagnostic per ≥2-member colliding group.
- **Posture: gating `Kind.DEFECT` / `Severity.ERROR` at `ENGINE_PATH`** — the same
  engine-soundness posture as `WLN-L3-MONOTONICITY-VIOLATION`, NOT the draft's
  non-gating `Kind.METRIC`/`Severity.NONE`. A lineless DEFECT at `ENGINE_PATH` is NOT
  downgraded to a non-gating FACT (`suppression.py` only downgrades lineless DEFECTs
  *off* `ENGINE_PATH`), so the diagnostic ITSELF trips `--fail-on ERROR` — a silent
  false-negative becomes a loud, gate-tripping signal. The guard is **additive**: it
  drops neither colliding finding, it appends one DEFECT per colliding fingerprint.
- **Distinctness oracle: `Finding.to_jsonl()`** (deterministic, `sort_keys`) — the full
  consumer-visible surface. A same-fp group whose members differ in `to_jsonl()` is a
  lossy collision; byte-identical members are a benign duplicate and do NOT fire. Both
  the count and the listed members derive from this single key, so a collision differing
  only in `properties`/`severity` is still counted AND listed (the `4928fbd` member-list fix).
- **Scope: the full emitted finding set — which SUBSUMES the draft's hand-scoping, it
  did not regress it.** The draft excluded `WLN-ENGINE-*`/`WLN-L3-*` engine diagnostics
  from the population by hand. Under `to_jsonl` distinctness that exclusion is
  unnecessary: an engine diagnostic's fingerprint is `_fingerprint(rule_id, message)`,
  so two engine diagnostics share a fingerprint only if they share rule_id AND message —
  i.e. they are byte-identical — i.e. benign and silent. Two *distinct* engine
  diagnostics cannot collide by construction. So **both `PY-WL-*` AND `RS-WL-*` are
  guarded**, engine diagnostics never false-positive, and the guard's OWN output cannot
  collide (each diagnostic's fingerprint is keyed on the colliding fp, distinct per group).

## Tests (shipped)

- `tests/unit/scanner/test_diagnostics.py`:
  - `test_collision_guard_flags_distinct_findings_sharing_a_fingerprint`
  - `test_collision_guard_ignores_byte_identical_duplicates`
  - `test_collision_guard_clean_set_emits_nothing`
  - `test_collision_guard_distinguishes_on_any_consumer_visible_field`
  - `test_collision_guard_is_deterministic_and_per_group`
- `tests/unit/scanner/test_analyzer.py::test_analyze_emits_collision_diagnostic_through_the_real_chokepoint`
  — a stub registry returning two same-fp/different-message findings through the REAL
  `WardlineAnalyzer.analyze` proves the assembled whole fires (the prior tests forged
  findings; a guard against a silent failure that is itself inertly wired fails silently).
- `tests/unit/core/test_suppression.py::test_collision_diagnostic_survives_suppression_and_trips_gate`
  — end-to-end: the diagnostic survives `apply_suppressions` as an ACTIVE DEFECT and trips
  the gate at `--fail-on ERROR`.
- `tests/golden/identity/test_identity_parity.py::test_corpus_fingerprints_are_collision_free`
  stays byte-green on 3.12 and 3.13 — the corpus generator already excludes engine
  diagnostics, so no new capture carries the rule_id and the frozen contract is untouched.

## Acceptance (met)
Guard wired at `analyzer.py:661`; forged DEFECT collision → exactly one gating diagnostic,
drops nothing; engine diagnostics never false-positive (byte-identical ⇒ benign); `PY-WL-*`
AND `RS-WL-*` in scope; oracle byte-green both legs; `WLN-ENGINE-FINGERPRINT-COLLISION`
never in the corpus. Full suite 2704 green; dogfood `wardline scan src` 0 collisions;
ruff + mypy clean.

→ Next: `…-03-drop-linestart-discriminator.md` (P3, THE value-rekey — this tripwire must be green first).
