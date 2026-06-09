# P4 — migration (`wardline rekey`)

> Phase 4 of the fingerprint rekey. See `…-00-index.md` for the spine.
> Run after P1 + P3 land. **value-rekey** (operator-run, never automatic).
> Realizes migration `weft-e618c4118a` (WL-1) as a scan-driven one-shot remap.

- **id:** `migration`
- **goal:** Carry every baseline/judged/waiver verdict (+ best-effort Filigree) across the value-rekey in ONE migration scan, computing `old_fp` (frozen wlfp1 formula, incl. `line_start`) and `new_fp` (new engine) from the SAME source, journalled, resumable, with snapshot rollback.
- **depends-on:** **P1** (scheme headers + `SchemeMismatchError` + `build_waivers_document`), **P3** (defines `new_fp` + the v0 discriminator component `taint_path_v0`). Both must land first.
- **rekey-impact:** **value-rekey** (operator-run; never automatic).
- **blast radius:** additive migration-only: `core/rekey.py`, `core/fingerprint_v0.py`, `cli/rekey.py`, one `cli/main.py` registration, `RekeyCollisionError` in `errors.py`, `migration_journal_path` in `paths.py`. Reads the stores + the `build_*_document` writers. Does NOT touch the production hash, suppression, analyzer, or rules. Each project's `.weft/wardline/` is mutated only by explicit `wardline rekey`; snapshot makes the YAML legs reversible.

## Two corrected fundamentals (these were data-loss bugs in the draft)

- **D-PROVENANCE — the journal/snapshot is the SOLE provenance source; NEVER re-read the live store on resume.** Crash-after-write-before-flag would otherwise resume, re-read the already-rewritten (new_fp) store, match zero against the journal's old_fp, and write an EMPTY store — shredding every verdict. **Fix:** carry full provenance from the immutable pre-flight snapshot (judged `rationale`/`model_id`/`policy_hash`/`recorded_at`/`confidence`; waiver `reason`/`expires`). Either embed full carried docs in the journal, or pin the snapshot as the sole provenance source. **Add a crash-after-write test asserting post-resume CONTENT equals the snapshot-derived expectation** (the double-invoke idempotency test alone passes while emptying the store).

- **D-INJECTIVITY — per-collision orphan-and-report, NOT whole-run abort.** The new scheme is by construction lower-cardinality (it dropped `line_start`). Two findings differing only by `line_start` collapse → distinct `old_fp` → identical `new_fp`. A whole-run abort would brick a real project permanently. **But P2/P3 guarantee no two CURRENT findings share a `new_fp`**, so a collision here means a discriminator bug. **Posture:** report it LOUD (record both old_fps + the shared new_fp), orphan that pair, continue the migration. `RekeyCollisionError` becomes a per-pair report, not a fatal raise.

**v0 scheme reconciliation:** the frozen module computes the **wlfp1** hash (the OLD line_start-in formula that P1 stamped). `from=wlfp1`, `to=wlfp2`.

## TDD steps

- [ ] **S1 — freeze `compute_finding_fingerprint_v0` (the wlfp1 formula).**
  - Test: `tests/unit/core/test_fingerprint_v0.py::test_v0_matches_pre_change_hash` — pin `compute_finding_fingerprint_v0(rule_id=..., path=..., line_start=42, qualname=..., taint_path=...)` to a hardcoded 64-hex literal **sourced from the pre-change git tip / an independent hand-rolled sha256, NEVER by running the frozen copy** (circular); also assert changing `line_start` changes the digest.
  - Impl: new `src/wardline/core/fingerprint_v0.py` — byte-exact copy of the pre-P3 `finding.py:154-165` body (line_start IN). Migration-only consumer; never edited again; never called by production scan (own module so the oracle stays byte-green).

- [ ] **S2 — dual-fingerprint contract from one scan.**
  - Test: `tests/unit/core/test_rekey_dual_fp.py::test_dual_fingerprint_for_every_rule_class` — over a fixture exercising **singleton (PY-WL-102), handler (PY-WL-103), ordinal (PY-WL-114), call-site (PY-WL-118), AND BOTH PY-WL-120 sites** (return → singleton-like, call-arg → call-site), assert `compute_old_new_fingerprints(scan_result)` returns per finding `(old_fp, new_fp)` where `old_fp == compute_finding_fingerprint_v0(...)` matches the v0 golden and `new_fp == finding.fingerprint`. (Do NOT assert `old_fp != new_fp` partially — `line_start` drops for ALL rules so they ALL differ; the load-bearing property is that `old_fp` MATCHES the stored fp.)
  - **Cross-WP contract (verify P3's committed interface FIRST):** `old_fp` for call-site rules needs the v0 `taint_path` STRING via `finding.properties["taint_path_v0"]` (P3 surfaces it). For singletons/handler/PY-WL-114, `old_fp` derives from the Finding (`None` / `handler.lineno`-on-Location / unchanged ordinal). **Verify P3 preserves `handler.lineno` on `Location.line_start` for PY-WL-103/104.** If P3 froze WITHOUT `taint_path_v0`, fall back to a two-engine scan (changes the scan shape — resolve before writing impl).
  - Impl: `src/wardline/core/rekey.py` with `compute_old_new_fingerprints(result) -> list[FingerprintRemap]` (`FingerprintRemap`: old_fp, new_fp, rule_id, path, qualname). Derive v0 taint_path per the per-finding (not per-rule — PY-WL-120 spans two classes) rule. Raise loudly if a call-site finding lacks the expected v0 component.

- [ ] **S3 — new_fp injectivity → per-collision orphan-and-report (NOT abort).** See D-INJECTIVITY.
  - Test: `tests/unit/core/test_rekey_injective.py::test_collapsing_remap_reports_and_continues` — two distinct old_fp + identical new_fp → the pair is recorded in a collisions list (naming both old_fps + the shared new_fp), neither verdict carried, the rest of the map proceeds; happy path returns the full map.
  - Impl: add `RekeyCollisionError`/`RekeyCollision` to `errors.py`/`rekey.py`; build `new_fp -> old_fp` dict; on a second distinct old_fp record the collision and exclude both. Share the invariant text with P2's `WLN-ENGINE-FINGERPRINT-COLLISION`.

- [ ] **S4 — pre-flight snapshot (the provenance source).**
  - Test: `tests/unit/core/test_rekey_snapshot.py::test_snapshot_copies_existing_stores_only` — baseline+waivers present, judged absent → `snapshot_stores(root)` writes `.weft/wardline/.rekey_snapshot/{baseline,waivers}.yaml` byte-identical, no judged snapshot; second call idempotent (refuses to clobber the safe copy).
  - Impl: `snapshot_stores(root)` in `rekey.py` using `paths.*_path` + `safe_paths.safe_project_file` confined under root. Copy only existing files; guard against overwrite.

- [ ] **S5 — carry verdicts from the SNAPSHOT, preserving ALL provenance; flag orphans.** See D-PROVENANCE.
  - Test: `tests/unit/core/test_rekey_carry.py::test_carry_preserves_provenance_and_flags_orphans` — seed baseline/judged/waiver with three stored old_fp (two in remap, one absent); assert `carry_*_forward` emit docs whose entries use new_fp, byte-preserve every non-fingerprint field for matched, and report the third as orphan. **Read old verdicts from the snapshot, not the live store.**
  - Impl: `carry_baseline_forward`/`carry_judged_forward`/`carry_waivers_forward` in `rekey.py`, each returning `(new_document, carried_old_fps, orphaned_old_fps)`. Build docs via `build_baseline_document`/`build_judged_document`/`build_waivers_document` (the last CREATED in P1/S5) with the `wlfp2` header. New entries via `dataclasses.replace(entry, fingerprint=new_fp)`.

- [ ] **S6 — journal (provenance-complete).**
  - Test: `tests/unit/core/test_rekey_journal.py::test_journal_roundtrip_and_resume_skips_done` — `write_journal`/`load_journal` roundtrip; mark `baseline` done → `next_pending_leg == "judged"`; all-done → complete; resume reads the persisted remap WITHOUT `run_scan` (inject a spy that fails if called).
  - Impl: `migration_journal_path(root)` in `paths.py`. `Journal` dataclass (`schema_version`, `fingerprint_scheme_from="wlfp1"`, `fingerprint_scheme_to="wlfp2"`, remap, orphans, collisions, legs `[{name, done, carried, orphaned}]`). **Embed full carried docs OR confirm snapshot is the provenance source** (D-PROVENANCE — the remap alone lacks rationale/reason). YAML via `require_yaml`, confined write.

- [ ] **S7 — per-leg-atomic idempotent application; YAML legs 1-3 first, gate green after leg 1.**
  - Test: `tests/unit/core/test_rekey_legs.py::test_legs_idempotent_and_gate_green_after_yaml` — run `apply_pending_legs(root, journal)` twice; each YAML store written once (mtime stable on 2nd run), all YAML done-flags set; rekeyed files load under wlfp2 with no `SCHEME_MISMATCH` while the pre-snapshot copies still fail.
  - **Crash-safety test (must-fix):** `tests/unit/core/test_rekey_legs.py::test_crash_after_write_before_flag_preserves_content` — simulate process death after store write, before done-flag; resume; assert post-resume content equals the snapshot-derived expectation (NOT an empty store).
  - Impl: `apply_pending_legs(root, journal, *, filigree=None)` — for each not-done YAML leg: carry from snapshot → write → persist done-flag (crash-safe). Source provenance from snapshot/journal, NEVER the live store.

- [ ] **S8 — Filigree leg (last, reconciliation debt, soft-fail).**
  - Test: `tests/unit/core/test_rekey_filigree.py::test_filigree_leg_soft_fails_after_yaml_done` — all YAML legs done + injected emitter returning a connection error → filigree leg `done=False` with recorded debt, overall YAML migration still success, YAML stores untouched; a 2xx marks it done.
  - Impl: build the leg on `filigree_emit.build_scan_results_body` over carried findings (new_fp wire) via the injected `FiligreeEmitter.emit`; the mark_unseen sweep fires by default for a non-empty set (closing old_fps — note `build_scan_results_body` computes `mark_unseen` internally; it is NOT a settable param). Honest: NO remap endpoint exists; old associations may orphan. Record debt; never raise on soft-fail.

- [ ] **S9 — `--probe` (read-only cross-check).**
  - Test: `tests/unit/core/test_rekey_probe.py::test_probe_reports_unmatched_and_collisions_without_writing` — seeded tree with one orphan; `probe(root)` returns `ProbeReport(matched=N, orphaned=[...], collisions=[...])`; NO file under `.weft/wardline/` changes (mtimes stable, no journal).
  - Impl: `probe(root, *, config_path, ...) -> ProbeReport` — scan, dual-fp, load stores, compute match/orphan/collision, assert dry-run carry docs load clean. Pure.

- [ ] **S10 — forward-only rollback.**
  - Test: `tests/unit/core/test_rekey_rollback.py::test_rollback_restores_yaml_byte_identical` — after a full rekey, `rollback(root)` restores the three YAML stores byte-identical to snapshot, removes the journal, issues reverse Filigree calls (injected emitter); no-op-safe with a clear error if no snapshot exists.
  - Impl: `rollback(root, *, filigree=None)` — require snapshot (else `WardlineError`); copy snapshot back; replay remap in reverse against the emitter (best-effort, soft-fail); delete journal+snapshot on success. **YAML rollback clean+complete; Filigree rollback best-effort (may orphan).**

- [ ] **S11 — CLI wiring.**
  - Test: `tests/unit/cli/test_rekey_cli.py::test_rekey_end_to_end_dry_run_on_copy` — over a COPIED `.weft/wardline/` tree: `rekey PATH` → exit 0, stores `SCHEME_MISMATCH`-clean + journal complete; `--probe` → exit 0, writes nothing; `--resume` after deleting the judged done-flag re-applies only judged without re-scanning; `--rollback` restores snapshot.
  - Impl: `src/wardline/cli/rekey.py` (`@click.command "rekey"`) delegating to `core/rekey.py`; register via `cli.add_command(rekey)` in `src/wardline/cli/main.py`. Honor `--config`/`--cache-dir`/`--trust-pack`/`--allow-custom-packs`/`--strict-defaults`; `--filigree-url`/`--filigree-token` opt-in. **Map exceptions mirroring `_generate_baseline` at `cli/main.py:66-93`** (`WardlineError`→exit 2; clean→0; drift-on-probe→nonzero). There is no `cli/baseline.py`.

- [ ] **S12 — loud-missed-leg integration (the safety contract).**
  - Test: `tests/integration/test_rekey_loud_miss.py::test_unrekeyed_store_fails_scheme_mismatch` — rekey baseline+judged, simulate the waivers leg never running (old-scheme waivers.yaml left in place); assert `run_scan`/`load_project_waivers` raises `SchemeMismatchError` naming `waivers.yaml` + `run wardline rekey`; after the waivers leg completes the scan is clean.
  - Impl: no new production code — consumes P1's load-time assertion. If it fails, the bug is a missing scheme header on the carried doc (fix in `carry_*_forward`/`build_*_document`).

## Acceptance
- `wardline rekey PATH` does exactly ONE `run_scan`, writes a complete `migration_journal.yaml`, applies legs `[baseline, judged, waivers, filigree]`.
- After leg 1 the local gate is green under wlfp2; all three YAML stores load `SCHEME_MISMATCH`-clean.
- `old_fp` via frozen `compute_finding_fingerprint_v0` (wlfp1), `new_fp` via the new engine; call-site old_fp uses P3's `taint_path_v0`.
- Every carried entry byte-preserves all non-fingerprint provenance **sourced from the snapshot**; orphans reported, never dropped.
- **Crash-after-write-before-flag preserves content** (not an empty store).
- Two old_fp → one new_fp is reported per-pair and the migration continues (NOT a whole-run abort).
- `--resume` applies only not-done legs WITHOUT re-scanning (spy proves it); re-running a done leg is a no-op.
- `--probe` writes nothing; reports match-rate/orphans/collisions.
- `--rollback` restores YAML byte-identical + removes journal; Filigree reversal best-effort with recorded debt.
- Filigree leg last, soft-fails on absent/5xx/401 (records debt, never aborts the completed YAML migration).
- Integration: un-rekeyed store fails `SCHEME_MISMATCH` naming the file + `run wardline rekey`.
- Full suite green; oracle byte-green both legs (`compute_finding_fingerprint_v0` never called by production); ruff + mypy clean.

## Operator runbook

```
# 0. Pre-1.0; no compat shim. After P1–P3 land, EVERY existing project's stores
#    are old-scheme (wlfp1) and will SCHEME_MISMATCH on the next scan. Run rekey.

# 1. DRY-RUN FIRST — read-only, writes nothing.
wardline rekey PATH --probe
#    Reports matched=N, orphaned=[old_fp...], collisions=[...].
#    Investigate orphans (source moved/deleted → verdict won't carry) and any
#    collision (a discriminator bug — should be EMPTY given P2/P3).

# 2. REKEY — one scan, snapshot, journal, legs [baseline, judged, waivers, filigree].
wardline rekey PATH
#    - Snapshots the three YAML stores to .weft/wardline/.rekey_snapshot/ (provenance source).
#    - Writes .weft/wardline/migration_journal.yaml (from=wlfp1, to=wlfp2, remap, orphans, collisions, per-leg done-flags).
#    - Leg 1 (baseline) → gate green under wlfp2. Legs 2-3 (judged, waivers) → all YAML stores wlfp2-clean.
#    - Leg 4 (Filigree, LAST) → re-emit carried findings under new_fp + mark_unseen sweep.
#      Soft-fails on sibling-absent/5xx/401 → recorded debt, does NOT abort the (complete) YAML migration.

# 3. RESUME (if interrupted) — reads the journal, applies only not-done legs, NEVER re-scans.
wardline rekey PATH --resume
#    DO NOT edit source between leg runs — old_fp/new_fp are pinned from the single scan; a re-scan would drift.

# 4. ROLLBACK (forward-only) — restores YAML byte-identical from snapshot + removes journal.
wardline rekey PATH --rollback
#    YAML rollback is clean+complete. Filigree reversal is best-effort (re-emit old_fp / close new_fp); old associations may orphan.
```

**Leg order rationale:** YAML first (gate-critical — leg 1 restores the local `--fail-on` gate); Filigree last (reconciliation debt, no remap endpoint). **Safety contract:** a missed leg is impossible to ignore — the un-rekeyed store `SCHEME_MISMATCH`es on the next scan and steers the operator to `wardline rekey`.

**Documented debt (decision D1):** the Loomweave `wardline-taint-1` blob (`facts.py:70`) carries a bare fingerprint VALUE that also rekeys, but is **exempt from a migration leg** — Loomweave independently recomputes the whole-file blake3 and never cross-joins the fingerprint with Filigree. The next `wardline scan --loomweave-url` re-emits the blob with the new value. No leg; recorded as debt.

→ Next: `…-05-rust-worktree-reconciliation.md` (P5, the rebase runbook — runs when the worktree rebases, not part of rc4).
