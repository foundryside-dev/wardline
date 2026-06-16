# P1 — scheme-infra (the loud-fail safety primitive)

> Phase 1 of the fingerprint rekey. See `…-00-index.md` for the spine. Run FIRST.
> **format-only** rekey-impact: every fingerprint VALUE stays byte-identical.

- **id:** `scheme-infra`
- **goal:** Make the fingerprint self-describing and make all four stores loud-fail on a scheme mismatch, **without touching the hash**. The SARIF key rename + new META field are the only corpus deltas.
- **depends-on:** nothing (this is the floor).
- **rekey-impact:** **format-only.**
- **blast radius:** `finding.py`, `errors.py`, `baseline.py`, `judged.py`, `waivers.py`, `suppression.py`, `filigree_emit.py`, `sarif.py`, `legis.py`, new `finding_identity.py`, the identity oracle. Cross-tool: Filigree gets a prefixed wire value + envelope scheme; SARIF consumers must key on `wardlineFingerprint/v2`; legis artifact gains an envelope scheme. `facts.py` (Loomweave blob) is **deliberately exempt** (decision D1). Pre-1.0, no compat shim.

## TDD steps (failing test first → impl)

- [ ] **S1 — `FINGERPRINT_SCHEME = "wlfp1"` + `format_fingerprint`/`parse_fingerprint` helpers; hash untouched.**
  - Test: `tests/unit/core/test_fingerprint_scheme.py` — `FINGERPRINT_SCHEME == "wlfp1"`; `format_fingerprint("wlfp1", "ab"*32) == "wlfp1:"+"ab"*32`; `parse_fingerprint(format_fingerprint(s,h)) == (s,h)`; `parse_fingerprint` rejects no-colon / wrong-len / uppercase → `ValueError`; `compute_finding_fingerprint(...)` returns bare 64-hex (no colon).
  - Impl: add the constant + helpers to `src/wardline/core/finding.py`. `compute_finding_fingerprint` UNCHANGED (still hashes `line_start`). In-memory stays bare hex; the prefix is applied only at the wire/store boundary. `parse_fingerprint` ships now (round-trip test) for the Filigree-wire reader + P4.

- [ ] **S2 — `SchemeMismatchError(ConfigError)`** carrying `store_name`/`found`/`expected` + `run wardline rekey`.
  - Test: `tests/unit/core/test_errors.py::test_scheme_mismatch_error` — `issubclass(SchemeMismatchError, ConfigError)`; `str(...)` names the file, the expected scheme, and `run wardline rekey`.
  - Impl: add to `src/wardline/core/errors.py`. Subclass `ConfigError` so existing `except ConfigError` / CLI exit mapping stays intact.

- [ ] **S3 — `baseline.py`: write `fingerprint_scheme` header; assert on load; NO version bump.**
  - Test: `tests/unit/core/test_baseline.py` — `build_baseline_document([f])["fingerprint_scheme"] == "wlfp1"`; a doc with no `fingerprint_scheme` → `SchemeMismatchError` (NOT a version-mismatch `ConfigError`); wrong scheme → `SchemeMismatchError`; **missing/empty file → `Baseline(frozenset())` (no error)**; roundtrip; entry value stays bare 64-hex.
  - **Edit existing tests** in this file: lines **34, 83, 90, 98** construct docs with `version` but no `fingerprint_scheme` — add `"fingerprint_scheme": "wlfp1"` to each (line 98 still expects the duplicate-fp `ConfigError` AFTER the scheme check passes).
  - Impl: add `"fingerprint_scheme": FINGERPRINT_SCHEME` to `build_baseline_document`. **Do NOT bump `BASELINE_VERSION`** (a version bump makes old files hit the version-mismatch branch first → hintless error). **Loader order is load-bearing:** empty-guard FIRST → scheme check → version check → entries.

- [ ] **S4 — `judged.py`: write header; assert on load; NO version bump; provenance preserved.**
  - Test: `tests/unit/core/test_judged.py` — `build_judged_document[...]["fingerprint_scheme"] == "wlfp1"`; no-scheme → `SchemeMismatchError` (not the version-mismatch at `judged.py:98`); wrong scheme → error; absent/empty → empty `JudgedSet`; roundtrip preserves `rationale`/`model_id`/`policy_hash`/`confidence`/`recorded_at` verbatim.
  - **Edit existing tests:** lines **47, 52, 59, 77, 88, 101, 115** build `version`-only docs — add the scheme header to each.
  - Impl: add the header to `build_judged_document`; **do NOT bump `JUDGED_VERSION`**; loader order empty-guard → scheme → version.

- [ ] **S5 — `waivers.py`: CREATE the writer (`WAIVERS_VERSION` + `build_waivers_document`) + header + empty-guard before the scheme check.**
  - **This is a symbol-creation step** — `build_waivers_document` and `WAIVERS_VERSION` **do not exist today** (verified). `add_waiver` is the only writer (inline hand-rolled YAML). P4's `carry_waivers_forward` consumes the new writer, so it must exist here.
  - Test: `tests/unit/core/test_waivers.py` — `add_waiver` writes top-level `fingerprint_scheme: "wlfp1"`; missing scheme → `SchemeMismatchError` naming `waivers.yaml`; wrong scheme → error; roundtrip preserves `reason`+`expires`, entry fp bare 64-hex; second `add` keeps the header; **present-but-empty `{}` waivers.yaml → empty, no error** (empty-guard); absent file → empty.
  - **Edit existing tests:** lines **15, 73** load header-less waivers — add the scheme header.
  - Impl: add `WAIVERS_VERSION = 1` + `build_waivers_document(waivers) -> dict` (so P4 can write through it). `add_waiver` writes `{fingerprint_scheme, version, waivers:[...]}` (create on first write, preserve on append). `load_project_waivers`: **empty-guard FIRST** (return `()` for absent/empty), THEN scheme check, THEN delegate to `parse_waivers` (pure, unchanged).

- [ ] **S6 — Filigree wire: scheme in the envelope + prefixed value.**
  - Test: `tests/unit/core/test_filigree_emit.py` — `build_scan_results_body([f])["fingerprint_scheme"] == "wlfp1"`; `_finding_to_wire(f)["fingerprint"] == "wlfp1:"+f.fingerprint`; `to_filigree_metadata(f)["wardline"]["fingerprint"] == "wlfp1:"+f.fingerprint`.
  - **Edit existing test:** `test_filigree_emit.py:67` asserts bare `"a"*64` for the wire value — change to expect the prefixed value.
  - Impl: `build_scan_results_body` adds top-level `fingerprint_scheme`. `_finding_to_wire` (`filigree_emit.py:51`) and `to_filigree_metadata` (`finding.py:186`) emit `format_fingerprint(FINGERPRINT_SCHEME, finding.fingerprint)`.
  - **Runtime-consumer audit before landing:** `mcp/server.py:317` (`by_fp.get(entry["fingerprint"])`) must join on the in-memory BARE fingerprint, not the prefixed wire value — verify it does.

- [ ] **S6b — legis envelope scheme (the cross-artifact consistency fix).**
  - Decision D2: legis's per-finding `fingerprint` stays **bare** (it reads `wire["fingerprint"]` from `to_jsonl`, bare-by-design like SARIF's value — confirmed `legis.py:169`). Add a top-level `fingerprint_scheme` to the legis ARTIFACT ENVELOPE so it carries the scheme signal like SARIF's key-version and Filigree's envelope.
  - Test: `tests/unit/core/test_legis.py` — `build_legis_artifact(...)["fingerprint_scheme"] == "wlfp1"`; per-finding value stays bare.
  - Impl: add the envelope field in `src/wardline/core/legis.py`.

- [ ] **S7 — SARIF key `wardlineFingerprint/v1` → `/v2` (value stays bare).**
  - Test: `tests/unit/core/test_sarif.py::test_partial_fingerprint_key_is_v2` — `partialFingerprints` has `wardlineFingerprint/v2` and NOT `/v1`; value is bare (no colon).
  - **Edit existing test:** `test_sarif.py:66` asserts `{"wardlineFingerprint/v1": "a"*64}` — move to `/v2`.
  - Impl: change the literal at `sarif.py:110`. Value unchanged.

- [ ] **S8 — `resolve_identity()`: single JOIN predicate the suppression layer calls.**
  - Test: `tests/unit/core/test_finding_identity.py` — waiver wins over judged/baseline; judged when no waiver; baseline when neither; no-match → `matched=False, matched_on=None`; `reason` = waiver.reason → rationale → None; `drifted_from` is None this phase. Behavior-lock `tests/unit/core/test_suppression.py::test_apply_suppressions_unchanged_via_resolver` — identical `SuppressionState` + `suppression_reason`.
  - **Behavior-lock MUST also cover the three pre-join early-exit branches:** (a) non-DEFECT passthrough; (b) ENGINE_PATH passthrough; (c) **lineless-DEFECT → `WLN-ENGINE-LINELESS-DEFECT` FACT substitution** (`suppression.py:40-60`, which runs BEFORE any match — assert the FACT is still emitted and the original DEFECT dropped).
  - Impl: new `src/wardline/core/finding_identity.py` with `resolve_identity(fingerprint, *, baseline, waivers, judged, today) -> IdentityResolution(matched, matched_on, drifted_from, reason)`. It invokes the stores' existing membership APIs (single predicate, not a fourth store). Refactor `apply_suppressions` to call it, preserving waiver>judged>baseline precedence and the lineless-DEFECT branch unchanged. `drifted_from` stays None (no second scheme yet); the field exists so P4 populates it without a signature change.

- [ ] **S9 + S10 — META scheme + corpus regen (KEEP ATOMIC — do not commit between).**
  - S9 test: `tests/golden/identity/test_identity_parity.py::test_corpus_meta_has_engine_scheme` — `META.json["fingerprint_scheme"] == FINGERPRINT_SCHEME`. (Red until S10 regen runs — that's why they're one unit.)
  - S10: the existing `test_identity_corpus_is_byte_identical` goes RED after S7 (captured SARIF now `/v2`); `_capture.py:111` reads the literal `wardlineFingerprint/v1` as a sort key and would `KeyError` — that's the signal.
  - Impl: (a) `_capture.py:111` sort key → `wardlineFingerprint/v2`; (b) `regen.py` imports `FINGERPRINT_SCHEME`, writes it into META, bumps `CORPUS_VERSION` 2→3; (c) run:
    ```
    cd tests && PYTHONPATH=. python -m golden.identity.regen \
      --reason 'scheme-infra: SARIF key /v1->/v2 + META fingerprint_scheme=wlfp1 (hash unchanged)'
    ```
  - (d) **Verify the ONLY corpus diff is the SARIF key rename + META gaining `fingerprint_scheme` (+ `corpus_version` 2→3); every finding `fingerprint` VALUE is byte-identical** — proves the hash was untouched.

## Acceptance
- S1–S8 unit tests green on BOTH 3.12 and 3.13.
- A store file with no `fingerprint_scheme` (one each: baseline/judged/waivers) → `SchemeMismatchError` naming the file + `run wardline rekey` (NOT a version-mismatch error).
- Absent/empty store on a fresh checkout → empty store, no error (empty-guard precedes scheme check) — incl. empty `{}` waivers.yaml.
- `build_baseline_document`/`build_judged_document`/`build_waivers_document` carry top-level `fingerprint_scheme == "wlfp1"`; per-entry fps bare 64-hex.
- Filigree wire + metadata emit `wlfp1:<hex>`; envelope carries the scheme. SARIF uses `/v2` with bare value. legis envelope carries the scheme; legis per-finding value bare.
- `apply_suppressions` routes through `resolve_identity` with byte-identical output (behavior-lock green, incl. lineless-DEFECT branch).
- Identity oracle byte-green; only corpus delta = SARIF `/v1`→`/v2` + META scheme (+ version 2→3); every fingerprint VALUE byte-identical.
- Full suite green; ruff + mypy clean.

→ Next: `…-02-collision-finalizer.md` (P2, the tripwire — must land before P3).
