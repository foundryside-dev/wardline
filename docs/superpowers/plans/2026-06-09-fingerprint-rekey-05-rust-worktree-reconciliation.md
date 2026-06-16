# P5 — rust worktree reconciliation (NOT rc4 code)

> Phase 5 of the fingerprint rekey. See `…-00-index.md` for the spine.
> This is a **rebase runbook + worktree-only changes** for `.worktrees/rust-plugin`
> (branch `feat/rust-plugin`), executed when the worktree rebases onto rc4 AFTER
> P1–P4 land. **No rc4 source edit here.**

**Deliverable:** `docs/superpowers/specs/2026-06-09-rust-plugin-rebase-runbook.md` (a worktree doc — author it in the worktree, not rc4).

## Rebase recipe — hot-file conflict resolution

For `finding.py`, `baseline.py`, `suppression.py`: **TAKE rc4's tightened version**
(scheme stamp `wlfp2`, `line_start` dropped from the hash, scheme-mismatch loaders,
dropped `line_start` param), then **re-apply the worktree-only additions.**

**The worktree-only additions are exactly THREE** (reality-corrected — the draft's
"WLN-ENGINE-LINELESS-DEFECT guard" is FALSE: that guard is ALREADY on rc4 at
`suppression.py:40-60`, diff-proven; the rebaser TAKES it from base, no action):

1. `finding.py`: `UNANALYZED_RULE_IDS += "WLN-ENGINE-FILE-FAILED"`.
2. `baseline.py` `build_baseline_document`: the `if f.properties.get("provisional_identity") is True: continue` skip.
3. `suppression.py` `apply_suppressions`: the same provisional skip (lines 61-70 in the worktree — the ONLY diff from rc4).

(2)/(3) are not textual conflicts (different code sections) but ARE a required semantic re-application onto rc4's rewritten hot files.

**Rebase acceptance:** the worktree's existing firewall tests pass against the rc4-merged hot files — `build_baseline_document` excludes `provisional_identity` findings; `apply_suppressions` keeps them ACTIVE/never-matched.

## Provisional firewall + scheme inheritance

- RS-WL-* findings carry `provisional_identity=True` → firewalled from the THREE local stores (`baseline.py` write-exclude, `suppression.py` ACTIVE/never-matched) but DO flow to SARIF/Filigree. They **inherit `wlfp2` + the `/v2` SARIF key** on rebase — the worktree must carry the identical `FINGERPRINT_SCHEME` + helpers.
- **Collision-guard scope (decision D3):** P2's detector scopes to `Kind.DEFECT AND not engine-prefix`, so **RS-WL-* DEFECTs ARE guarded** (they have the riskiest resolved-tier fingerprints). Confirm the rebase does not narrow the scope to `PY-WL-*` only.

## RS-WL-* discriminator + §8 doctrine (worktree change, SP2-gated)

- **Drop the EXTERNAL_RAW-in-taint_path violation** (source-derived-only invariant): `rust/rules.py` `_program_finding` (RS-WL-108, folds `program_taint.value` ~:95) AND `_shell_finding` (RS-WL-112, folds `worst.value` ~:107) currently put a RESOLVED `TaintState` in `taint_path`. Replace with `f"{rel_line}:{col}:{end_col}:{token}"` (NodeId `@node{trigger_node_id}` suffix retained as collision-completeness fallback). The clean human form stays in `properties["taint_path"]`.
- **Plumb byte offsets:** `CommandTrigger` (`dataflow.py:44-49`) carries only `trigger_node_id`/`trigger_line`/`constructor_line` today — add `col_start`/`col_end` from `rust/index.py` tree-sitter byte points.
- **§8 byte-offset doctrine (decision D4):** tree-sitter `(row, byte-in-line)` is byte-compatible with CPython `ast` `col_offset` (both UTF-8 bytes), so the `rel_line:col:end_col` convention is uniform across frontends. **Multi-line subtlety:** CPython `end_col_offset` is the byte column on the END line; take `end_col` from the trigger node's END-row `end_point[1]`, NOT a naive `start_point[1]/end_point[1]` copy (wrong when the call spans lines).
- **Test (worktree):** `tests/unit/rust/test_rules.py::test_rs_wl_taint_path_is_source_derived_and_move_stable` — fingerprinted taint_path contains NO `TaintState` value (no `EXTERNAL_RAW`/`.value`); a benign line above the enclosing fn leaves the fingerprint unchanged; two distinct commands on one line stay distinct. **Exercise BOTH `_program_finding` (RS-WL-108) and `_shell_finding` (RS-WL-112)** or one violation survives.
- **Gating:** this change AND un-provisioning are **SP2-gated** — `provisional_identity=True` MUST persist across the rebase (un-provisioning is a later slice). Worktree test `test_rs_wl_still_provisional_post_rebase` confirms RS-WL-* stay provisional and absent from any written baseline post-rebase.

## Why the blast radius is low
A Python rekey (P1–P4) has near-zero incremental blast radius on the `.rs` plugin: provisional findings never enter the three local stores. The SARIF/Filigree axis rekeys with the shared function, but RS-WL-* identity is already contractually unstable (the provisional banner) — no NEW orphan risk. The real cost is this rebase coordination on the four hot files, which is bounded and scripted above.
