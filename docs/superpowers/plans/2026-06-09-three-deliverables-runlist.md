# Three-deliverable runlist — state + executable sequence (2026-06-09)

> Ground-truthed against rc4 @ local tip (3 commits ahead of origin/rc4), the
> `feat/rust-plugin` worktree, and the Filigree tracker. **`✅ done · ⏳ in
> flight · ❌ not started · 🔒 gated`.** The detailed per-step instructions live
> in the `2026-06-09-fingerprint-rekey-0X-*.md` plan files; this is the index
> above them — what's done, what's next, which file to open.

## The shape

- **#2 Fingerprint rekey is the critical path** and a hard **1.0 prereq**. Nothing in #1 ships until it lands.
- **#3 Rust plugin is effectively built** (WP1–WP7 on its branch); its only remaining work is *integration* (the P5 rebase, after #2 lands) — so it's genuinely "downtime / no rush."
- **#1 1.0 is release-cut mechanics** gated on #2: version is already `1.0.0rc4`, dogfood PRs (#30, #34) merged, **no open dogfood/lacuna or P0/P1 tickets**.

Master order: **rekey spine (P1→P2-finish→P3→P4) → rebase rust (P5) → lacuna re-dogfood → cut 1.0.**

---

## Deliverable #2 — Fingerprint rekey (1.0 PREREQ · critical path)

The single source serialization point is the **identity corpus** (`tests/golden/identity/corpus/*`): P1 and P3 each regen it. **No two corpus-touching phases run in parallel.**

| Phase | State | Evidence |
|---|---|---|
| **P1 scheme-infra** | ❌ **not started** | no `FINGERPRINT_SCHEME`/`wlfp1` in src; `finding_identity.py`, `build_waivers_document`, `SchemeMismatchError` all ABSENT |
| **P2 collision guard** | ✅ **DONE · committed · ticket closed** | `build_collision_findings` @ `diagnostics.py:111`, wired `analyzer.py:661`; tests committed (`0a551c4` + `4928fbd`); plan `…-02` reconciled to shipped reality; `wardline-8fb773a7af` `closed` |
| **P3 drop line_start** | ❌ core change not done · ✅ groundwork landed | `compute_finding_fingerprint` STILL hashes `str(line_start)` (`finding.py`). Done already: PY-WL-114 ordinal (`e3e1e7a`), call-site spans (`705acfe`), broad-except precondition test (`1797fa6`) |
| **P4 migration (`wardline rekey`)** | ❌ **not started** | `core/rekey.py`, `core/fingerprint_v0.py`, `cli/rekey.py` ABSENT |
| **P5 rust reconciliation** | 🔒 gated on P1–P4 + rebase | (also = #3 integration) |

### Executable steps

- [x] **2.1 — Finish P2 (do NOT rebuild it).** ✅ **DONE.** The shipped impl was the keeper and *diverged from its plan file* (it chose `Kind.DEFECT`/`Severity.ERROR` fail-loud, one `build_collision_findings(findings)`, `to_jsonl()` distinctness — the draft said METRIC/NONE + singular fn). Resolution:
  - [x] Tests were already committed (`0a551c4` shipped the 5 unit + 1 e2e suppression/gate tests; `4928fbd` added the real-chokepoint proof + member-list consistency fix). No uncommitted `test_diagnostics.py` edit remained. Suite 2704 green.
  - [x] **Reconciled `…-02-collision-finalizer.md`** to shipped reality (DEFECT/ERROR, single `build_collision_findings` over the full set, `to_jsonl` oracle) — reframed as a shipped-record. **`…-03` and `…-04` were re-verified and needed NO edit:** they reference P2 only design-agnostically ("the tripwire / the guard must exist first", the real rule_id `WLN-ENGINE-FINGERPRINT-COLLISION`, "P2/P3 guarantee no two current findings share a new_fp"). The earlier "dangling cross-refs in 03/04" note was a planning-time guess that ground-truth grep disproved — no `detect_fingerprint_collisions` / singular fn / "non-fatal" string exists in either. Likewise `…-00-index` (P2 = "finalizer / tripwire / rekey-impact none") is still accurate.
  - [x] Closed `wardline-8fb773a7af`.

- [ ] **2.2 — P1 scheme-infra (the floor).** Open `…-01-scheme-stamp-infra.md`. Start: `tests/unit/core/test_fingerprint_scheme.py` (create) + `FINGERPRINT_SCHEME = "wlfp1"` + `format_/parse_fingerprint` in `finding.py`, **hash untouched**. Format-only, byte-safe. Ends with corpus regen 2→3 (only delta = SARIF `/v1`→`/v2` + META scheme).

- [ ] **2.3 — P3 drop line_start (THE value-rekey).** Open `…-03-drop-linestart-discriminator.md`. **Narrowed by groundwork:** the call-site family + PY-WL-114 are already discriminator-ready; the *remaining* rule work is (a) give **PY-WL-103/104** the handler span (this is also the `wardline-6102d4c833` fix — its precondition test `1797fa6` goes RED here, intended), (b) drop `line_start` from the hash, (c) stamp **`wlfp2`**, (d) expose `taint_path_v0` + keep handler.lineno on Location (P4 contract), (e) regen corpus 3→4. Close `wardline-8654423823` + `wardline-6102d4c833`.

- [ ] **2.4 — P4 migration `wardline rekey`.** Open `…-04-scan-driven-migration.md`. New `core/rekey.py` + `core/fingerprint_v0.py` (frozen wlfp1) + `cli/rekey.py`. Mind the two folded data-loss fixes (D-PROVENANCE: never re-read live store on resume; D-INJECTIVITY: per-collision orphan-and-report, not whole-run abort). Close `weft-e618c4118a` if tracked.

- [ ] **2.5 — Verify after EACH phase:** full suite (~2625) green · identity oracle byte-green on **3.12 AND 3.13** · `ruff` + `mypy` clean.

---

## Deliverable #3 — Rust plugin (nice-to-have · NOT 1.0-required · downtime)

**Status: feature-complete on `feat/rust-plugin` (worktree clean).** WP1–WP7 all landed:
WP1 discovery `63dabbc` · WP2 parse+qualname `09b015f` · WP3 vocab `4cf7ccf` · WP4 dataflow `5752807` · WP5 rules+RustAnalyzer `17776ee` · WP6 wire into `run_scan`+CLI `--lang rust` `4c2a2dd`/`b344aea`/`8c8dc94` · WP7 docs `ed49189` · qualname corpus re-vendor `c124f0c`. Memory said "WP3 done, WP4 next" — **stale; it's all done.**

### Executable steps (all 🔒 until #2 lands)

- [ ] **3.1 — P5 rebase onto rc4** (open `…-05-rust-worktree-reconciliation.md`). Take rc4's tightened `finding.py`/`baseline.py`/`suppression.py` (wlfp2, line_start dropped), re-apply the **3 worktree-only additions** (the doc lists them), inherit `wlfp2` + `/v2`.
- [ ] **3.2 — RS-WL-* discriminator fix** (SP2-gated): drop the `EXTERNAL_RAW`-in-`taint_path` violation in `rust/rules.py`, plumb byte offsets from tree-sitter. `provisional_identity=True` must persist.
- [ ] **3.3 — Decide merge:** rust → rc4 before 1.0 (in) or hold for 1.1 (out). Default per your framing: **out of 1.0**, merge when convenient.

---

## Deliverable #1 — 1.0 release + lacuna dogfood (gated on #2)

**Status: substantially done.** Version `1.0.0rc4`; dogfood PRs #30/#34 merged to main; **zero open dogfood/lacuna tickets**; no P0/P1 blockers. What remains is the release cut + a final validation pass — all **after #2 lands**.

### Executable steps

- [ ] **1.1 🔒 — Gate: fingerprint rekey (#2 P1–P4) merged to rc4.** Hard prereq.
- [ ] **1.2 — lacuna re-dogfood (acceptance).** Once rekey lands: run `wardline rekey` on the lacuna `.weft/wardline/` tree (`--probe` first), then `wardline scan . --fail-on ERROR` against lacuna → confirm clean + no orphaned baseline/waivers. This proves the rekey carries verdicts on a real project.
- [ ] **1.3 — Expansion backlog: in or out of 1.0?** 9× `expansion` P3 sink-family tasks + `wardline-718048a518` (boundary de-confliction) + `wardline-d6af917bde` (lambda zero-trip FN) + `wardline-e159060db7` (test hardening). These are the *separate agent-attributed expansion backlog*, not defect blockers. **Decision needed** — recommend post-1.0 unless you want broader sink coverage in the 1.0 cut.
- [ ] **1.4 — Release cut:** finalize CHANGELOG `[Unreleased]`→`1.0.0`, bump `_version.py` rc4→`1.0.0`, tag, PyPI publish (Trusted Publishing), push rc4 + open/merge the final `rc4→main` PR. (Prior rc PRs #31–#34 are the template.)
- [ ] **1.5 — Post-release:** delete superseded branches; update memory.

---

## The one decision that's blocking nothing but worth making now — ✅ RESOLVED
The committed P2 (`build_collision_findings`, DEFECT/ERROR) **superseded its plan file**, and the **fail-loud design is kept** (it's stronger — the diagnostic itself trips the gate). `…-02` is reconciled to that reality; 2.1 was pure cleanup and is done. Downstream P3/P4 already key off the real design (they reference the rule_id and the no-collision guarantee, not the superseded fn name/posture).
