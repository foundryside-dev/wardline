# P3 — rules-discriminator (THE value-rekey)

> Phase 3 of the fingerprint rekey. See `…-00-index.md` for the spine.
> Run after P2 (the tripwire must be green). **value-rekey** rekey-impact.
> Closes `wardline-8654423823`; folds in the `wardline-6102d4c833` broad/silent fix.

- **id:** `rules-discriminator`
- **goal:** Make the fingerprint invariant to comment-insertion / vertical moves: drop `line_start` from the hashed parts; migrate every rule to the move-stable `taint_path` convention; broad/silent_exception gain the span (also the fix for `wardline-6102d4c833`); regen the corpus once.
- **depends-on:** P1 (scheme + loaders), **P2 (guard must exist first).**
- **rekey-impact:** **value-rekey.** Every `PY-WL-*` (and `RS-WL-*` via `run_scan`) fingerprint VALUE changes.
- **blast radius:** every store + SARIF carry new values (carried forward by P4). Engine `WLN-ENGINE-*` fps (separate local `_fp` helpers) UNAFFECTED. Corpus regenerated (corpus_version 3→4). RS-WL-* values shift but are firewalled from the three local stores by `provisional_identity=True`.

**Scheme label (must-fix):** P3 stamps **`wlfp2`** — distinct from P1's `wlfp1`, so a store written between P1 and P3 loud-fails `SCHEME_MISMATCH`. Set `FINGERPRINT_SCHEME = "wlfp2"` in `finding.py` as part of this phase.

**Corpus version (must-fix):** P1 already bumped 2→3, so P3 bumps **3→4**.

## Per-rule discriminator checklist

| Rule(s) | Class | Old taint_path | New taint_path | Edit site |
|---|---|---|---|---|
| PY-WL-101/102/109/110/111/113/119 | singleton (def-anchored) | `None` | `None` (drop `line_start` arg only) | assert_only_boundary:80/83, boundary_without_rejection:72/75, contradictory_trust:129/132, degenerate_boundary:90/93, failopen_boundary:119/122, none_leak:250/253, untrusted_reaches_trusted:114/117 |
| PY-WL-103 (broad) / PY-WL-104 (silent) | handler-anchored | `None` | `f"{rel}:{h.col_offset}:{h.end_col_offset}:except"` where `rel = h.lineno - entity.location.line_start` (anchor is `handler.lineno`, NOT def line — confirmed) | broad_exception:52/63, silent_exception:55/63 |
| PY-WL-106/107/108/112/115/116/117 | call-site family | `f"{sink}@{col}:{end_col}"` (NO line term) | prepend `rel_line` → `f"{rel}:{col}:{end_col}:{callee}"` | **single edit at `_sink_helpers.py` base `_fp` (call ~:271, taint_path ~:282)** |
| PY-WL-118 (sql_injection) | call-site | `f"{sink}@{col}:{end_col}"` | prepend `rel_line` | sql_injection.py `_fp` ~:154, taint_path ~:165, line_start ~:157 |
| PY-WL-105 (untrusted_to_trusted_callee) | call-site | span | prepend `rel_line` | untrusted_to_trusted_callee.py `_fp` ~:167 |
| PY-WL-120 **return site** (stored_taint) | singleton-like | `None` | `f"{rel}:{col}:{end_col}:return"` (`:return` token DISTINCT from call-arg callee token) | stored_taint.py ~:155 |
| PY-WL-120 **call-arg site** (stored_taint) | call-site | span | prepend `rel_line`, callee token | stored_taint.py ~:222 |
| PY-WL-114 (invalid_decorator_level) | ordinal — **KEEP** | `f"{name}:{token}#{ordinal}"` | unchanged; **only drop the `line_start` arg** (at ~:172, NOT :190) | invalid_decorator_level.py |
| `_PolicyConfigRule` | — | — | drop `line_start=None` | rules/__init__.py |

**Reality correction:** there are **23 `line_start=` args across 15 rule files** (not "~12 / 9 files"). Dropping the parameter forces editing all of them; a miss is a `TypeError` at import (loud), not silent — but the file list must be complete.

## TDD steps

- [ ] **S1 — comment-insertion stability test (driver) — NON-corpus dir.**
  - Test: `tests/golden/identity/test_rekey_mutation_pairs.py::test_comment_above_entity_keeps_fingerprint` — scan `before.py`/`after.py` (byte-identical except a benign comment above a finding-bearing entity); match findings ACROSS scans by `(rule_id, qualname, sorted(properties))` (NOT by fingerprint — circular); assert matched findings have IDENTICAL fingerprint. Fails today.
  - **Constrain the multi-emit fixture to exactly ONE finding per `(rule, qualname)`** (else the non-fp match key is ambiguous and the test flakes). Fixtures live in `tests/golden/identity/fixtures/rekey_mutation/` (NON-corpus — does not staleness the frozen corpus).

- [ ] **S2 — collision-pair gate (driver) — NON-corpus.**
  - Test: `tests/golden/identity/test_rekey_collision_pairs.py::test_multiemit_pairs_stay_distinct` — for each `(rule_id, qualname)` group with >1 finding assert `len(set(fingerprints)) == count`. Plant: (a) two same-sink calls at the **SAME column on DIFFERENT lines with SAME-LENGTH call text** (`cur.execute(qa)` / `cur.execute(qb)` — so `rel_line` is the SOLE distinguisher; differing-length text would make `end_col` differ and the gate vacuous); (b) two broad `except` handlers (PY-WL-103); (c) two silent handlers (PY-WL-104) — the `wardline-6102d4c833` case with no fixture today.
  - **Put these fixtures in a dedicated NON-corpus dir** (mirror S1), OR if kept in the corpus confirm `test_corpus_fingerprints_are_collision_free` now covers them. (Editing `tests/golden/identity/fixtures/sinks/wardline_sinks.py` stalenesses `sinks.json` immediately — prefer non-corpus.)

- [ ] **S3 — construction-shape lint (source-AST) + `RuleMetadata.multi_emit`.**
  - Test: `tests/unit/scanner/rules/test_discriminator_shape.py::test_every_multiemit_rule_carries_a_span_or_ordinal` — `ast.parse` each `scanner/rules/*.py`, find each `_fp`/`compute_finding_fingerprint` call, read its `taint_path` kwarg; for `metadata.multi_emit` rules assert it references `col_offset`/`end_col_offset` OR contains `#`+ordinal; for singletons assert it's the `None` literal.
  - **Special-case the `TaintedSinkRule` base** for the 7 sink subclasses (106/107/108/112/115/116/117) — they have NO per-module `_fp` call (the single call is in `_sink_helpers.py:271`, which carries no rule_id). Assert ITS taint_path carries a span; treat subclasses as covered.
  - Impl: add `RuleMetadata.multi_emit: bool` (`metadata.py`) as the non-circular source of truth (`taint_path` is a hash input, never persisted, so a runtime/corpus reader can't see it — the lint must be source-AST).

- [ ] **S4 — ATOMIC engine edit:** drop `line_start` from `compute_finding_fingerprint` signature/body (`parts = (rule_id, path, qualname or "", taint_path or "")`); set `FINGERPRINT_SCHEME = "wlfp2"`; migrate ALL 23 call sites per the table. `line_start` stays on `Location`.
  - **Cross-WP contract for P4 (must expose):** P4's migration needs the v0 `taint_path` STRING for call-site rules (not reconstructible from a post-change Finding). **Surface it** — e.g. stash the pre-change taint_path on `finding.properties["taint_path_v0"]` — and **preserve `handler.lineno` on `Location.line_start` for PY-WL-103/104** (NOT the def line) so P4 can derive the handler old_fp. (If you choose NOT to expose `taint_path_v0`, P4 falls back to a two-engine scan — flag it.)
  - The S1–S3 tests are the drivers and go green here. Confirm full suite green EXCEPT the byte-parity gate (red until S5).

- [ ] **S5 — TERMINAL re-green (corpus regen).**
  - Test: `tests/golden/identity/test_identity_parity.py::test_identity_corpus_is_byte_identical` — red until regen, then green on both legs.
  - Impl: `regen.py` adds `--new-scheme-version`, bumps `CORPUS_VERSION` 3→4, writes `fingerprint_scheme=wlfp2` into META. Run:
    ```
    cd tests && PYTHONPATH=. python -m golden.identity.regen \
      --reason 'rekey: drop line_start + move-stable discriminators' --new-scheme-version wlfp2
    ```

## Acceptance
- `compute_finding_fingerprint` no longer accepts/hashes `line_start`; `parts == (rule_id, path, qualname or "", taint_path or "")`; `FINGERPRINT_SCHEME == "wlfp2"`.
- Comment above any finding-bearing entity → byte-identical fingerprint (matched by non-fp key).
- No two distinct ACTIVE findings share a fp: collision-pair gate green for SAME-LENGTH cross-line call pairs AND two-broad-handler AND two-silent-handler functions (`wardline-6102d4c833` verified, not just documented).
- Every multi-emit rule's taint_path carries a span or PY-WL-114's ordinal; every singleton's is `None` — enforced by the shape lint × `RuleMetadata.multi_emit`.
- `taint_path_v0` exposed for call-site rules; `Location.line_start` for PY-WL-103/104 is the handler line (P4 contract).
- Corpus regenerated, corpus_version 4, `fingerprint_scheme=wlfp2` in META; byte-parity green on 3.12 and 3.13.
- Full suite green; `line_start` still on `Finding.location`; ruff + mypy clean.

→ Next: `…-04-scan-driven-migration.md` (P4, `wardline rekey` — carries verdicts across this rekey).
