# S0 — Hardening + Consumer-First Cross-Product Prep — Implementation Plan (rev 3.9)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Git discipline (non-negotiable):** subagents NEVER run git — no `git add/commit/stash/checkout/restore/reset/diff/status`, nothing. Every "Commit" step is executed by the orchestrator. Cross-repo tasks (17–21) touch fixed targets only. The target must be clean before its task starts; before commit, intended edits are expected, but every changed path must be in that task's explicit file list. The orchestrator runs `git diff --check`, inspects `git diff --stat`, stages explicit paths only (never `-A`), and inspects `git diff --cached --name-status`. Any unexpected path is a hard stop. `/home/john/loomweave/.worktrees/integrate-review-fixes/` and every `.claude/worktrees/*` checkout are non-targets.
>
> **Rev 3 custody decision** (post adversarial core/QE/consumer scrub of rev 2): rescue this plan in place so the ticket link remains canonical. Builtin call grammar now includes bare-vs-called form; literal `**{...}` values share the PY-WL-114/provider reader; dynamic `**mapping` is described truthfully as statically unverifiable; custom packs remain untouched; mixed-root shadows are filtered per marker; S0 bumps the resolver cache epoch; P11 is split honestly; the complete per-kind QE floor is specified; custom-grammar hashing is collision-resistant; and consumer readiness is separated into local coordinated and published-release gates. Preview vectors are non-normative and pinned to the design-spec blob until real S1 serializers replace them.
>
> **Rev 3.1 (pre-execution resolutions):** the Task 1 spec correction was pre-landed as the then-current spec rev 3 (`1244f627`); the Legis clean-target stop was resolved by committing the untracked plainweave plan on legis `main` (`a117a21`); the preflight claim uses the executing session's actor; and the shared `read_level`'s declared-sibling widening is now a named, pinned contract (Task 2). With the 1.5.0→main merge, wardline's fixed target branch is **`release/2.0.0`** (the wardline-2 program residency — this plan and its spec ARE wardline 2); loomweave remains `release/1.5.0`.
>
> **Rev 3.2 (spec reconciliation):** spec revision 4 is committed at `ae968b540470467258be5989d451991252f7f8dd` with blob `b43aab4bab1f93f419c189e26fd533afdcc6d387`. It owns the complete S0 engine/QE/consumer contract, corrects P11b's generic `TokenSetArg` gate to S2 with an Evidence-domain repeat in S3, and makes the per-kind clean-sentinel and low-sample receipt floors explicit. This plan now pins that revision and supplies the corresponding executable steps. Superseded by rev 3.4, again by rev 3.5, again by rev 3.6, and again by rev 3.7: the governing spec is now **revision 9**. Blob `f4ba87c488778f2c315de1944818db12707d981f` at commit `aa10dd3d` is **revision 10**'s — the governing revision — and is the pinned preflight constant, with no re-pin owed — see the Rev 3.7 record for that residue and its standing prohibitions. Blob `9624f8925a006a80677c12eaa0951933d631920f` (rev 5) and blob `b43aab4bab1f93f419c189e26fd533afdcc6d387` (rev 4) are review provenance only.
>
> **Rev 3.3 (bug re-scope, 2026-08-09):** the go/no-go review of rev 3.2 found that closing `wardline-4928b75782` after Task 6 would bank a half-fix: two members of the same false-green class, in the same fail-open direction, survive S0. The ticket was therefore **re-scoped to the Python builtin marker CALL SHAPE**, which Tasks 2–6 do close, and the residue was split out — `wardline-b857b50b54` (Rust: a non-canonical `/// @trusted(...)` shape silently fails to match; verified zero golden blast radius) and `wardline-2b2a6cddfa` (a statically-unreadable level VALUE such as `@trusted(level=_SVC_LEVEL)` drops the seed with no diagnostic on any channel; reproduced at exit 0). Only the Filigree discipline changes here — no task's engineering content moves.
>
> **Rev 3.4 (review-condition amendments, 2026-08-09):** the rev-3.2 go/no-go review's six pre-merge conditions are now folded in, and the governing spec moved to **revision 5**. Engine side (Tasks 1–6): the Task 1 tripwire covers both builtin roots as spec §4.2 requires; Task 4's shape validator drops a malformed builtin's seed and PY-WL-130 (ERROR) is the loud channel. A proposed demotion of that seed to `UNKNOWN_RAW` whenever a provable sibling exists was **evaluated and REJECTED on measurement**: `UNKNOWN_RAW` is in `RAW_ZONE`, `modulate()` returns `Severity.NONE` there, and PY-WL-101 skips a declared tier in `RAW_ZONE`, so demoting silences the very rules the change exists to preserve. Dropping the malformed marker and letting a provable sibling stand is strictly louder than today — the motivating stack (`@trusted(level='ASSURED')` over a malformed `@external_boundary(...)`) seeds `EXTERNAL_RAW` today and fires ZERO ERROR+ defects, and after the change seeds `ASSURED` and fires PY-WL-101 + PY-WL-112 on top of PY-WL-130. Task 6 Step 4.2 keeps its plain `taint_for` instruction, which Task 4 does not touch; PY-WL-130's diagnostics claim runtime-invalidity only where a `TypeError` is proved from the shipped signatures; and PY-WL-130's `examples_clean` no longer freezes the `wardline-2b2a6cddfa` silence into a shipped contract. Consumer side: Task 17 now genuinely READS a generic-3 descriptor — spec rev 5 defines schema acceptance as the obligation to parse every section the schema defines, so `facets:` is parsed and attributed rather than silently ignored. The reason vocabulary of spec §4.2 is deliberately **unchanged** (eight values); the two dual-form reasons are split by offender token instead. Superseded in part by rev 3.5, rev 3.6 and rev 3.7: the governing spec is now **revision 9**, and this note's "settled — do not re-open" disposition of `wardline-2b2a6cddfa` is **reversed by PDR-0018**. The measured `RAW_ZONE` demotion rejection recorded above is unaffected and still governs the provider task's seed handling (Task 4 in this note's rev-3.4 numbering; **Task 5** at rev 3.5). This note's "Task 6 Step 4.2 keeps its plain `taint_for` instruction, which Task 4 does not touch" is **superseded by rev 3.5**, and the two tasks it names are **Task 7** and **Task 5** at rev 3.5: the provider task now threads the per-module census and `reference_site=entity.node` into `_match` and discards the widened verdict's third element, while Task 7 Step 4.2 remains the sole place `taint_for`'s branch arms and its two `SeedResult(...)` constructions change — disjoint statements of the same function, so neither task is "the sole place `taint_for` changes".
>
> **Rev 3.5 (spec rev 6 + PDR-0018 + the owner scope split, 2026-08-10):** the go/no-go on rev 3.4 (`docs/superpowers/plans/2026-08-10-s0-rev6-go-no-go.md`) returned **NO-GO on the plan**. Revision 6 had been drafted under an edit-only-the-spec discipline, so its engineering was not stale here — it was **absent**: a whole-plan grep returned zero occurrences of "form 5", "reference site", `WLN-ENGINE-UNREADABLE-MARKER-VALUE`, `SeedContext` or any Rust frontend file. Three triggers each sufficed. Task 2's frozen `level_token` / `read_level` signatures made **P9 — Task 2's own named QE deliverable — unprovable**, so an implementer would ship a green agreement receipt over a reader that does not implement the grammar. The drop-coverage matrix's `Kind.DEFECT` filter plus its pure-absence branch built a false green into the guard whose entire purpose is proving there are none. And the unknown-marker task's three-arm `taint_for` branch, with "Nothing else in `taint_for` changes", left the residual population structurally unreachable. Rev 3.5 folds the review's 25 conditions in.
>
> **Rev 3.6 (delegation defects closed, 2026-08-10):** the go/no-go on rev 3.5 returned **NO-GO on the plan** for a single coherent defect class — *tasks delegating obligations to other tasks whose Files lists forbid executing them*. Rev 3.5 had supplied revision 6/7's engineering, which is what rev 3.4 lacked; what it had not done is amend the Files lists to match the obligations its two new tasks hand outward, so **five separate obligations were handed between tasks that the per-task path gate (the per-task path gate at Global Constraints :5 — "every changed path must be in that task's explicit file list") each forbade from carrying them out**. Rev 3.6 closes all six blocking defects and the review's thirty conditions. Every hand-off now names an owning task whose Files list carries the path AND whose steps carry the instruction: PY-WL-114's census rewire is **Task 3 Step 4(c)** (B1); form 5's normative **lexical-precedence** fifth conjunct is stated in the reader's contract, its docstring and both case tables (B2); `test_form5_agreement` — P9's receipt, and a §12 S0 shipping prerequisite that rev 3.5 left unownable — is **Task 8 Step 7**, read back at the S0 close as `wardline-5a795253f1` condition (v) (B3); the `test_provider_loop.py` amendment is **split across Task 5 Step 1 and Task 7 Step 4.6**, because `SeedResult.unreadable_level_values` does not exist until Task 7 and the single-task fix `AttributeError`s (B4); the absent-census raise is ruled **builtin-only**, with the unconditional reading rejected in terms and the `builtin=False` cell pinned by name (B5); and Task 5's false "no `_seed` case presents a bare `Name`" claim is replaced by the named case and its `run_scan` rewrite (B6). Alongside them: the all-rules `examples_clean` guard lands at **Task 8 Step 8**, and PRD-0003 criterion 1's two exit-code repros acquire owning steps with commit steps at **Task 6 Step 7** and **Task 8 Step 9** — Final verification reads those artifacts and has no commit step of its own. Global Constraints' mandatory **value census** is discharged in place, at its stated scope. **The governing spec is revision 9** *(as of rev 3.6; superseded at rev 3.7 — it is now **revision 9**, see the residue correction later in this note and the Rev 3.7 record)*. Revisions 6 and 7 remain the correct credit for form 5, the residual FACT and the go/no-go closures; revision 8 carries the spec-side conditions this plan-only pass cannot make — §4.4's closure condition 4 split (a marker COUNT over a tree with zero stacked markers is structurally blind to the first-recognised-wins behaviour it must guard), §4.2.1's `detail` precedence rule and catch-all family, §4.2.1's stale criterion-1 enumeration and discharge clause, and the two §4.2.1 corrections this plan already applies on its own side: the absent-census raise's **`builtin` qualifier** (spec :157 states the trigger unconditionally and now diverges from the plan's builtin-only ruling) and its **provider-side disposition** (spec :157 says the raise propagates out of the parse pass past a SyntaxError/UnicodeDecodeError/OSError guard; verified in source, `pipeline.py:221`'s bare `except Exception` catches it and emits `WLN-ENGINE-FILE-FAILED` with the file dropped from the analysed set — the safety conclusion survives, only the mechanism was wrong). **The residue rev 3.6 recorded here was stated on a false premise, and rev 3.7 corrects it:** blob `f4ba87c488778f2c315de1944818db12707d981f` **at commit `aa10dd3d`** IS **revision 8** — the spec's own revision header at that commit records it — so revision 8 was never an obligation without a commit to pin, and every literal blob and commit pin in this plan named it correctly. Rev 3.6 recorded the opposite in good faith. **What rev 3.7 does not do is pretend the residue is gone:** the governing spec is now **revision 9**, which is not the blob those pins name, so the same obligation returns one revision along. Re-pin the Global Constraints preview-vector pin and the preflight `git hash-object` check from **revision 9's commit** the moment it exists; until then they name revision 8's blob and say so. The standing prohibitions are unchanged and are the reason this is a re-pin and never a re-derivation: those pins must **not** be re-derived from a working-tree file (Global Constraints forbids it by name, because a working-tree-derived constant pins a blob reachable from no commit), and any drift the preflight check reports is the STOP-and-re-review it is designed to be — that check gates Tasks 19, 20 and 22 only, so nothing in Tasks 1–18 is blocked on it. Task numbering is **unchanged at 23**; only Task 6's and Task 8's internal step ordinals move, and every cross-reference to them was re-cut in the same pass.
>
> **Rev 3.7 (the positional-guard fail-open closed, 2026-08-10):** the go/no-go on rev 3.6 returned **NO-GO on the plan** over **one** surviving blocking defect, on a trend of 11 → 6 → 1. Task 2's frozen `read_level` silently dropped the **released positional-argument guard** (`decorator_provider.py:165-166`, `if deco.args: return None`). Because registry call-form validation and `PY-WL-130` are **builtin-only by design** (spec §4.2.1; Global Constraints' hard custom-pack gate), the custom side would have had **no positional guard anywhere** from Task 5's commit onward: a pack declaring a **defaulted** `LevelArg` on `@mypack.sanitized('GUARDED')` or `@mypack.sanitized(*ARGS)` would take `_defaulted()` and seed **TRUSTED** with no diagnostic on any channel — the exact false-green class this programme exists to close, and it would have shipped with **zero in-tree test reds**, because every custom `LevelArg` in the tree passes `default=None` while wardline's OWN builtins (`boundary_types.py:108`, `:125`) use the defaulted shape a pack author copies. Zero reds is the mechanism, not the reassurance. The guard is restored in the frozen block **between** the `isinstance(deco, ast.Call)` check and `extract_keywords` — position is the whole point, since after `extract_keywords` it closes nothing — the reader's docstring now leads its custom-side enumeration with positional arguments, two `builtin=False` reader rows against a **non-None** `default` pin it at Task 2 Step 5, and **Task 14**'s asymmetry module gains `test_custom_positional_argument_never_takes_a_defaulted_level`, the one custom-side cell the builtin-only drop-coverage matrix cannot reach. **Three execution defects go with it, each of which would have stopped an implementer typing the pinned text verbatim:** Task 2 Step 2's `_read_level` re-cut named `shadowed_roots` and `bt.builtin`, neither in that module-level function's scope — two `NameError`s where the snippet is placed — so the provider-private reader's **own** signature now takes both as required, undefaulted, keyword-only parameters with its sole call site (`:405`, inside `_match`) re-cut, and the "not a signature change" clause is narrowed so it no longer steers toward the two wrong repairs the next paragraph forbids; Task 2 Step 1's PY-WL-130 `offence_ordinal` fingerprint pin could not execute at a task whose Files list carries no PY-WL-130 path, so it is **split** — the reader-level offence tuple stays here, the fingerprint half lands at **Task 6 Step 1** — with the canonical phase order stated as the loop actually runs it (call form, positional, **extraction offences**, keyword classification, missing names), which is the ordering an implementer reconstructing the tuple from the call text gets backwards; and Task 2 Step 3's pinned import block omitted `ModuleCensus`, which the same step's prescribed call constructs. Alongside them, `test_form5_agreement`'s **custom-`BoundaryType` row** was unexecutable through the mandated driver — `run_scan` accepts no grammar — and is carved out at all four sites onto `build_analyzer` + `analyzer.last_context`, with the three assertion substitutions named and the disposition recorded in the same directive so no implementer escalates a harness choice as a P9 cross-reader disagreement. **The review's twenty-six conditions are folded in:** the dead `:1186-1193` pointer at five sites and nine further self-pins are re-cut to **named anchors rather than corrected coordinates**, because this document has moved its own line numbers across four consecutive revisions; the two divergent exhaustive close-gate enumerations collapse to one authoritative list; Task 9's title, expected failure, Step 5 instruction and commit message stop describing a one-key change in a task that ships two; Task 3 Step 5 gains the multiple-target-assignment row spec §4.2.1 makes normative and no bullet exercised; Task 20 Step 7 stops describing an edit to a path its own Files list forbids; the Rollout Fence's Loomweave probe becomes a **behavioural** read against the installed package rather than the accept-only half spec §4.3 names as the fail-open; and Global Constraints' unqualified green-suite condition now names its **two** deliberate cross-task carried reds and forbids weakening either. **The governing spec is revision 9** — five textual conditions against revision 8, none of which changes what gets built; the plan's short-circuit justification moves with it from P13's repository-scoped ceiling to the shipped secure default. **The honest residue moves one revision along rather than closing:** rev 3.6 recorded that revision 8 "has no commit to pin", which was false. **Corrected at rev 3.7 and later, after measurement:** blob `f4ba87c488778f2c315de1944818db12707d981f` at commit `aa10dd3d` **is revision 10's** — the governing revision — so **no re-pin is owed** and the preflight's static check PASSES as written. Rev 3.7's own claim that "all eight pin sites were re-cut" was a false self-audit: the digest sites were, the surrounding prose was not, and eight further sites went on asserting an owed re-pin until they were corrected here. The lesson the rev-3.4 record already states is what defeated it again — grep the **premise** ("owed", "re-pin", "does not yet carry"), not only the digest and the revision word. It must never be re-derived from a working-tree file, drift is the STOP-and-re-review it is designed to be, and it gates Tasks 19, 20 and 22 only. Task numbering is **unchanged at 23** and no task's internal step ordinals move.

> **Rev 3.8 (the unexecutable receipts closed, 2026-08-11):** the go/no-go on rev 3.7 returned **GO-WITH-CONDITIONS on both artifacts** — **0 blocking**, on a trend of 11 → 6 → 1 → 0 — against a closed list of fifteen. An engineer could already have started Task 1 safely; what this revision buys is a plan that is shippable end to end, and every condition it closes is of one kind: **a step, a script or a receipt that reads as executable and is not**. Four clusters, each reproduced live rather than argued. (1) **Both sanctioned MCP-golden re-freezes died before writing a byte.** `_live_output_schemas()` asserts `"error" not in resp`, but the handshake opt-out lives **only** in `test_mcp_output_schema_golden.py`'s autouse fixture `_handshake_preopened` (`:48-61`), which never runs outside pytest — `protocol.py:37` defaults `require_handshake` to `True` and `:103-104` answers every non-`initialize` method with `-32600`. Task 9 Step 4's script now mirrors that fixture before importing the module, and is verified end to end with the write suppressed: 18 tool schemas, digest `b6b95b929f53cbb65467c1dd55146cec03baad23`, byte-identical to the committed golden — ***rev-3.9 correction:*** *that digest is the **pre-Task-9** baseline and is stale as a live constant. Task 9's sanctioned re-freeze has since landed, so the live golden and `test_mcp_output_schema_golden.py`'s `VENDORED_BLOB_SHA` (`:69`) both moved off it. ***Rev-3.10 correction:*** *this clause then quoted `a3247bdaa78b9214a2f7bc2393dd095de82f4cf6`, which Task 20's re-freeze has since made stale in turn — the second staleness of the same sentence. No digest is quoted here any more; `:69` is the single source. See the same correction at Task 9 Step 4.* The mechanism claim this sentence makes — that the patched script runs to completion and reproduces the committed bytes — is unaffected; only the constant moved. Task 20 Step 5.3 quotes no SHA and needs no edit.* Task 20 Step 3 points at the patched block **by name and with the reason**, so a reader who regenerates from the module's header procedure instead cannot silently drop the opt-out; both sites now carry the standing prohibition on hand-editing the golden, which is the nearest wrong repair and which that module forbids by name, and both record that the Global Constraint's **exactly two** leaves no third attempt budget. (2) **The S0 close gate had a conjunct with no executable content.** Close condition (iv) turned on "the same four frozen-oracle suites", the over-approximation probe's "exactly two symbols" and "the blinded negative control" — a whole-repo grep found no definition of any of the three, so the likely receipt was the very no-op the bullet's own text warns against. Final verification's blast-radius bullet is now the measurement's **single definition** and says plainly that it **constitutes** rather than recovers: the four suites are enumerated by exact invocation and mapped one-to-one onto the no-regeneration list, with `tests/corpus/rust/**` named honestly as a count-and-label gate rather than a byte oracle; the probe's two `_level_token` symbols are named; and the control is defined as the perturbed symbol **plus the delta that must appear** — both measured live on the pre-Task-1 tree, the widened probe at zero delta and the control at a 32-line diff (22 DEFECT lines lost across PY-WL-101/102/105/106/107/108/109, `taint_source_counts.anchored` 43 → 18), which is what proves it discriminates semantically. Condition (iv) is re-cut to **point** at that enumeration rather than restate it, because two lists both claiming exhaustiveness is how a condition goes missing. The control is pinned as an in-process scratch perturbation and never a committed edit. (3) **Two justifications spec revision 9 withdrew in terms were still standing — in shipping text and in source.** The P13 waiver-ceiling rationale for the shape-gate short-circuit survived at three sites, including the `call_shape_offences` docstring typed into `src/` at Task 2 and the canonical ruled-ordering paragraph that tells every other step to "write it that way"; all three now carry the shipped **secure default** instead, and the canonical site additionally states the residual risk §4.2.1 obliges be stated rather than argued away. The "no waiver or baseline row can even be *written*" over-claim survived at five, two of which escape the repo — a `CHANGELOG.md` paste and a Filigree scope note — telling users of a security tool that a suppression is rejected when in fact it is accepted and inert; all five now state the true narrower claim (never *generated*, `build_baseline_document` filtering through `_is_baselineable_finding`; a hand-authored row or waiver **is** writable and simply does nothing), and the guard test is renamed `test_residual_fact_is_never_generated_into_a_baseline_document` so the name no longer denies what its own sibling deliberately constructs. Both test bodies are unchanged. (4) **The two reproduced reds inside pinned code, plus eight the review did not look for.** Task 5's `_match` body was a mypy-strict `[assignment]` error (`LevelRead.level` is `TaintState | None` and mypy performs no correlated narrowing from `verdict`), fixed with `assert read.level is not None` keeping `LevelVerdict.RESOLVED` as the semantic gate; Task 2's pinned test header was `I001`, fixed by ordering `registry` before `run`. Running the **full** `E,F,I,UP,B,SIM` set over those two fences — which no prior pass had done — found eight further `E501` rows in `SHAPE_CASES` and `CLAUSE_CASES`, all wrapped in each table's own existing continuation style with no tuple content changed. Alongside them: `wardline-2b2a6cddfa` finally acquires the **owning action** its close gate presumed — **Task 8 Step 14**, after the commit that anchors it, with the matching Filigree-discipline bullet and the Final-verification bullet re-cut from "both are genuinely still open" to the by-owner conditional form the discipline already mandated; Task 2 Step 3 stops asserting `PY-WL-130` owns malformed markers four tasks before the rule exists, announces the intra-plan window explicitly, and Task 6 gains `test_shape_offence_with_invalid_token_is_pywl130_only` — the **discriminating** hand-off, and the only shape in which the gate's ordering is observable, which no test anywhere pinned; the `examples_violation` fence recovers the lead-in naming its destination and its APPEND action; the one surviving dead line coordinate becomes a named anchor; the "provider's only `except ValueError`" claim is narrowed to the path it is true of; and Task 9 Step 3.3's false statement of JSON Schema semantics is replaced by the true reason `required` is load-bearing. **Task numbering is unchanged at 23**, no existing step ordinal moves, and Task 8 gains one appended step. **The governing spec moves to revision 10** in this same round — §4.2.1's blast-radius paragraph is re-cut spec-side to carry the enumeration above, so the plan and the spec select the same measurement rather than leaving a spec reader alone with the empty gate. **Rev-3.8 amendment on the pin, recorded rather than quietly carried:** the preflight constant and the Global Constraints preview-vector pin name blob `f4ba87c488778f2c315de1944818db12707d981f` at commit `aa10dd3d`, ~~which **is revision 9's** — correct as those sites stand, and no re-pin was owed at rev 3.7. With the spec at revision 10 the same obligation returns one revision along: **re-pin both from revision 10's commit the moment it exists**, and until then they name revision 9's blob and this record says so.~~ — ***rev-3.9 correction, struck because it manufactures a false STOP:*** *both halves of the struck clause are wrong. That blob at `aa10dd3d` **is revision 10's** — the spec's own revision header at that commit reads `**Status:** DESIGN, revision 10`, the governing revision — so **no re-pin is owed** and the execution preflight's static check **passes as written**. The numbering line at `:11` and Global Constraints' preview-vector pin already say exactly this; the struck clause was the only site that contradicted them, and an implementer reading it before Tasks 19/20/22 would have halted on a re-pin obligation that does not exist. `:11` is correct and is deliberately left untouched.* The standing prohibitions are unchanged and are why this is a re-pin and never a re-derivation — never from a working-tree file, drift is the STOP-and-re-review it is designed to be, and the check gates Tasks 19, 20 and 22 only. No pin text was touched in this pass; closing that hand-off is the orchestrator's.

> **Rev 3.9 (the cross-repo anchors re-cut before dispatch, 2026-08-12):** Tasks 1–18 are complete and committed; Tasks 19–23 reach into loomweave, warpline and legis and have never been executed. An **eleven-agent readiness audit** verified every anchor those five tasks cite **by execution rather than inspection** — running the scripts, importing the symbols, measuring the deltas — and returned **Tasks 19–23 as 5/5 GO** subject to eleven corrections owed first. All eleven are applied here; every premise was independently re-confirmed against the live trees in this pass before its edit was made, and no source, test or golden changed. The corrections were made **before** dispatch rather than during for one reason: this plan converts an unexpected red into a STOP-and-re-review, four of these items were independent mid-task halts, and a stall inside *someone else's repository* is the expensive failure. **One item was the blocker and the rest are not close to it.** The S0 close gate's condition (iv) — the blinded negative control that makes the whole blast-radius measurement non-vacuous — instructed a perturbation of `wardline.scanner.taint.decorator_provider._level_token`, a function **Task 2 deleted**; measured, `hasattr` is `False`, so the gate had no executable target at the one moment it is read. Post-Task-2 there is exactly **one** such reader, `wardline.scanner.marker_reader.level_token`, and the control is re-addressed there. That is recorded as a **prescribed symbol swap, not an invitation to improvise**, because improvised re-addressings measurably do not reproduce the gate's own numbers: a `LevelRead` wrapper bypasses `read_level`'s `allowed`-set gate and yields an engine-unreachable control (green where it must red), and rebinding the two **import-time-bound aliases** (`invalid_decorator_level._level_token`, `module_census.level_token`) alongside the module attribute widens the delta to 23 lost / 28 gained with 25 spurious PY-WL-114 rows. Patching the **module attribute alone** reproduces the recorded delta exactly — 22 DEFECT lines lost across PY-WL-101/102/105/106/107/108/109, 2 PY-WL-102 gained, `taint_source_counts.anchored` 43 → 18 — and reds `tests/grammar/test_golden_oracle.py::test_builtin_findings_match_golden`, all re-measured live on the post-Task-18 tree on 2026-08-12. The **historical** pre-Task-1 probe paragraph is deliberately **not** re-addressed: it is a dated measurement of two symbols that existed then, it is not part of the Pass condition, and rewriting it onto one symbol would make the record a lie about what was measured — an addressing note is appended instead. The other ten: a rev-3.8 clause asserting the pinned spec blob "is revision 9's" and owing a re-pin is **struck** as a manufactured STOP (it is revision 10's, `:11` and the Global Constraints pin already said so, and the preflight check passes as written); `docs/reference/mcp.md` joins Task 20's Files list **with a Step 7 instruction**, being the one path a step already edits, the per-task path gate already forbids, and no test pins — the only place executing rev 3.8 verbatim would have shipped a false statement to users; a stale `b6b95b92…` golden digest is corrected to the live `a3247bda…` at both sites; Task 20's MCP anchors, ~18 lines stale and in one case straddling two unrelated tests, are re-cut **by symbol and quoted text rather than by corrected line numbers**, since line coordinates are what rotted; Task 19 Step 7 names the single self-test fixture the new `accepted_descriptors` key reds (`aligned`, which transitively fixes both hook assertions) and the post-pin-check placement that leaves the other five negative fixtures untouched, and states rather than silently carries the capability guard its replacement hook drops; Task 21 Step 4.2's pasted block loses two authored **E501** rows against warpline's clean baseline; Task 21 gains an explicit repo-relative-paths rule because `CHANGELOG.md` is a warpline `PUBLIC_DOC_ROOTS` entry and `tests/test_public_docs_hygiene.py` is off that task's Files list; Task 20's "warpline consumer NOT YET wired" justification is replaced by the true one (the path gate) since warpline has shipped `_attest.py` since 1.3.0, with the row's own stale clause handed to its owning task; Task 23 gains the `attest.py:62` → `:63` evidence-path fix; and an **undocumented cross-task dependency** is written down at both ends — Task 23's `_has_shared_vector_pin` greps **Task 20's** authored test source for `GOLDEN_KEY`, a literal `sign_artifact(` call and a `*_FIELD` constant, which the alias `from wardline.core.attest import _sign as sign_artifact` is the only reason exists, so a Task 20 implementer "cleaning up" the pinned block would red a gate three tasks later for a cause invisible from that task's text. **Task numbering is unchanged at 23, no step ordinal moves, and exactly one Files-list entry was added** (item 3's `docs/reference/mcp.md`, on Task 20). One coordinate in the audit brief itself did not survive re-checking and is recorded rather than propagated: `marker_reader.level_token` is at `marker_reader.py:260`, not `:213`, and the surviving import alias is at `invalid_decorator_level.py:29`, not `:30` — the substantive premises (one post-Task-2 reader, that symbol, that delta) all hold and were verified by execution.

**Numbering, because rev 3.5 moves it.** Rev 3.5 inserts two engine tasks — the per-module binding census as **Task 3** and the residual-FACT task as **Task 8** — so the plan now carries **23** tasks and every task from rev 3.4's Task 3 onward shifts (+1 up to rev-3.4's Task 6, +2 from rev-3.4's Task 7 on). Every task ordinal in the body, the dependency order, the Filigree discipline, the Rollout Fence, Final verification and the coverage map is **live rev-3.5 numbering**. The one deliberate exception is the dated revision records — the **Rev 3.1 / 3.3 / 3.4 blockquotes above and the "Rev 3.4 amendments" entry in Self-review notes** — whose ordinals are **frozen at the numbering of the revision that wrote them**, because renumbering a dated record makes it a lie about what that revision contained. Read a task number inside those four notes as rev-3.4 numbering; read it as live everywhere else. The three triggers named in the previous paragraph are stated by role for exactly this reason: at rev 3.5 they live in Task 2, **Task 14** and **Task 7**. **The governing spec is revision 9.** Blob `f4ba87c488778f2c315de1944818db12707d981f` at commit `aa10dd3d` is **revision 10**'s — the governing revision — and is the constant the execution preflight pins; no re-pin is owed. Never re-derive it from a working-tree hash (Rev 3.7 record, Global Constraints' preview-vector pin). Revision 7 closed the six conditions the 2026-08-10 go/no-go raised against revision 6; revision 9 closes the five textual conditions the rev-3.6 review raised, **none of which changes what gets built** (§4.2.1 conditions 3 and 4 cut back to what source supports, the short-circuit's asymmetry re-justified on the shipped secure default rather than on P13, §4.4's `unparseable_args` catch-all re-scoped to a *rejected* argument list with the accept predicate stated positively, and every dead `plan line N` coordinate re-cut to cite by owning task and role); and revision 8 closes the five the rev-3.5 review raised — including two §4.2.1 statements that were **false in source**: the absent-census raise is **builtin-only**, and its provider-side disposition is a gate-eligible `WLN-ENGINE-FILE-FAILED` ERROR DEFECT via the parse loop's broad per-file guard, not an escape from the parse pass. Revision 6 is where form 5 and the residual FACT were admitted, so statements crediting revision 6 with that engineering remain accurate. It admits **P3 form 5** — a same-file, single-binding, one-hop module-level value reference in a **builtin** marker's LEVEL slot, on a **module-top-level `def` / `async def`** — and pairs it with the residual **`WLN-ENGINE-UNREADABLE-MARKER-VALUE`** FACT (`Severity.NONE`, `Kind.FACT`, builtin-only) under five normative soundness conditions, so a DRY refactor to a module constant no longer silently disarms the gate and what stays unreadable stays observable (§P3, §4.2.1). Both halves ship; neither substitutes for the other. **Scope, ruled by the owner on 2026-08-10:** `wardline-2b2a6cddfa` (the statically unreadable level VALUE) is **inside S0** — forced, not preferred, because revision 6 places form 5 inside Task 2's frozen produced interface and its P9 receipt, so the fix re-cuts S0's own engine core and cannot be additive work alongside a green S0. `wardline-b857b50b54` (the Rust non-canonical marker shape) is **outside S0**, as its own thread owned by spec §4.4, closing **before G2 is read** — a different frontend, zero golden blast radius, no coupling to Task 2's reader. **S0's close therefore does not close PRD-0003 criterion 6**, and the plan says so where S0 closes rather than leaving the criterion ownerless. Two rulings made within the orchestrator's authority are written **into** the tasks rather than left implicit. The **shape gate short-circuits**: `call_shape_offences` is the single call-shape verdict and Task 5 already runs it before the levels loop, so a marker that is both shape-malformed and value-unreadable takes `PY-WL-130` **only** and emits no residual FACT. That is an ordering, not a dominance claim — `PY-WL-130` is a `Kind.DEFECT` and therefore suppressible, so a waived `PY-WL-130` leaves that site with **no** signal at all; the justification is noise-avoidance plus the shipped **secure default** — at `trust_suppressions=False` the gate population is rebuilt with an empty baseline and waiver set, so a waived `PY-WL-130` still trips `--fail-on` (spec rev 9 §4.2.1, which replaces rev 8's repository-scoped P13 clause). And the `decorator_coverage` count is a **seventh sibling summary key**, landed inside Task 9's already-sanctioned re-freeze — not a second one, which Global Constraints' exactly-two rule forbids. The G2 narrowing (spec §4.2.1's unratified proposal) is **explicitly deferred**: it changes only PRD-0003 criterion 2's verdict, blocks no engineering, and **nothing in this plan may depend on it**.

**Goal:** Ship stage S0 of the declaration-surface-v2 program against governing spec **revision 10** — *rev-3.8 amendment: this read "revision 9" through rev 3.7 and moves with the spec's rev-10 round, which re-cuts §4.2.1's blast-radius paragraph to carry Final verification's enumeration; nothing S0 builds changes. The preflight blob pin and the Global Constraints preview-vector pin still name **revision 9's** blob `f4ba87c488778f2c315de1944818db12707d981f` at commit `aa10dd3d`, correctly and with no re-pin owed as those sites stand — re-pin both from revision 10's commit the moment it exists, never from a working-tree file.* Concretely: fix the live false green `wardline-4928b75782` (PY-WL-130 + `WLN-ENGINE-UNKNOWN-MARKER`), land the §4.2 registry-owned argument and call-form grammar, land **P3 form 5** — a same-file, single-binding, one-hop module-level value reference in a builtin marker's LEVEL slot on a module-top-level `def` / `async def` — with its **per-module census** (the qualifying module-scope bindings *and* the set of form-5-eligible reference sites, spec §4.2.1) and the residual **`WLN-ENGINE-UNREADABLE-MARKER-VALUE`** FACT under all five of its soundness conditions, closing `wardline-2b2a6cddfa`, close QE prerequisites P1–P10 and P12–P14 — **P9 is closed only when the shared reader's agreement receipt is exercised over all eight of revision 6's form-5 cases on the analyser's real construction path (spec §4.2.1), never over the pre-rev-6 CASES table** — close P11a (forward vocabulary skew), defer P11b's generic `TokenSetArg` gate to S2 and its Evidence-domain integration repeat to S3, and stage consumer-first cross-product prep — all before any new marker vocabulary exists. “Stage” means merged, commit-anchored consumer support plus an isolated local-install proof; it does not mean a public consumer release has shipped. **S0 does not close PRD-0003 criterion 6.** The Rust non-canonical marker shape (`wardline-b857b50b54`) was ruled outside S0 by the owner on 2026-08-10 and is owned by spec §4.4's separately-owned thread, which must close **before G2 is read**. That thread is criterion 6's owner; this plan is not.

**Custody verdict:** **The rev-3.4 GO does not carry over.** The 2026-08-10 go/no-go returned NO-GO on rev 3.4, and revision 6 re-cuts S0's **engine core** — Task 2's frozen produced interface and its P9 receipt — rather than its residue, so the prior three-panel green was given over a different artifact. **Rev 3.5 is not cleared for execution until it is re-reviewed**; that NO-GO stands until the re-review returns. **NO-GO for published generic-3 or attest-3 emission** is unchanged and stands until the Published-release gate is satisfied. The former unrelated Legis clean-target blocker was resolved on Legis `main` at `a117a21`; execution additionally requires the live clean-target preflight **and** the spec blob check to pass at the moment of execution. The blob check needs no re-pin: the pinned constant is revision 10's, measured against the governing spec.

**Architecture:** Builtin marker calls use one registry-owned grammar: `RegistryEntry.call_form`, `kwargs`, and `arg_kinds`. The L1 provider and PY-WL-130 share `call_shape_offences`; the provider and PY-WL-114 share literal-keyword extraction and level-token reading; PY-WL-110 applies the same exact-export and per-root shadow rules. This validation is builtin-only. Custom `BoundaryType` packs retain their released contract: `level_args` declares values Wardline reads, and a custom type with `level_args=()` may carry foreign metadata kwargs Wardline ignores. Dynamic `**mapping` is runtime-ambiguous but outside Wardline's statically readable declaration grammar, so the seed drops and PY-WL-130 explains the analyzer limitation. The unknown-marker FACT rides the `SeedResult → FunctionSeed → pipeline` channel exactly like `WLN-ENGINE-UNPROVABLE-BOUNDARY`, and the residual `WLN-ENGINE-UNREADABLE-MARKER-VALUE` FACT rides a **second, distinct** field on that same channel — distinct because the provider documents that builtin boundary types never appear in `unprovable_boundaries`, and that exclusion is what preserves the byte-identity oracle (spec §4.2.1). The new carrier is **unserialised**, so `SUMMARY_SCHEMA_VERSION` does not move. The **per-module census** that P3 form 5 reads — the qualifying module-scope bindings with their lines, a module-level `poisoned` flag set by an unresolved star import, and the set of form-5-eligible reference sites held **by node identity** — is built once per module in the `pipeline.py` parse loop, where the tree is already in hand, and travels to both readers without being rebuilt: directly on `SeedContext` for the provider side, and as a module-path→census mapping on `AnalysisContext` for the rule side, following the shipped `module_bindings` precedent. Neither the census nor the reference site may carry a default on either reader entry point. Wardline still emits `wardline-generic-2` and `wardline-attest-2` after S0.

**Tech Stack:** Python 3.12, pytest via `uv run pytest`, ruff, mypy, import-linter; Rust/cargo only to re-verify the loomweave manifest parse. Spec: `docs/superpowers/specs/2026-08-09-declaration-surface-v2-design.md`. Tickets: `wardline-5a795253f1` (S0), `wardline-4928b75782` (bug; the call-shape half is closed by Tasks 2–7).

## Global Constraints

- **Zero scan-golden drift.** After every wardline task the full default suite is green — with **exactly two deliberate cross-task carried reds**, each announced by its own task's Expected line and each clearing at a named later task: Task 5's `test_malformed_sibling_never_reduces_the_error_population` (clears at Task 6's green, when PY-WL-130 exists) and Task 6's `test_unreadable_value_is_not_a_shape_offence` `WLN-ENGINE-UNREADABLE-MARKER-VALUE` assertion (clears at Task 8's green, when the emission loop lands). Neither may be weakened, xfailed or deleted to make its own task green, and neither is an Unexpected-red STOP. There are no others — with NO regeneration of: `tests/grammar/golden/builtin_findings.jsonl` (byte oracle over `tests/corpus/fixtures`), `tests/golden/identity/corpus/*.json`, `tests/corpus/rust/**`, `tests/golden/identity/rust/corpus/*.json`, `tests/golden/identity/rust/fixtures/**`, `tests/conformance/fixtures/wardline-vocabulary-descriptor.golden.yaml` (+ its `UPSTREAM_BLOB_SHA`), `src/wardline/core/vocabulary.yaml`. The three Rust trees are named explicitly because `tests/golden/identity/corpus/*.json` does **not** glob them and they carry 21 canonical `/// @trusted(level=ASSURED)` markers of their own. The `to_level` census (2026-08-09) covers marker call **shape** only; its conclusion — that no corpus or golden fixture carries a malformed marker call — holds, so the shape behaviour changes in Tasks 5–7 fire on no frozen fixture. **That census is not evidence for revision 6.** Form 5 and the residual FACT emit over a **disjoint** population — level *values*, not call shapes — so a **separate value census** over every builtin `level=` / `to_level=` value in the frozen trees above was required. **It is DISCHARGED HERE, in place, at plan rev 3.6** — no task owns it and none should, because it is an up-front inventory of the frozen trees rather than a build step, and its whole purpose is to tell the implementer *before* Task 2 whether form 5 can move a golden at all. Measured 2026-08-10 over exactly the population named above: across `tests/corpus/fixtures` and `tests/golden/identity/**`, every Python builtin LEVEL value is a `str` literal — 60 occurrences, being 44 `level="ASSURED"`, 10 `to_level="ASSURED"`, 3 `level="INTEGRAL"`, 2 `level="BOGUS"` and 1 `to_level="GUARDED"` — and **ZERO** are a bare `ast.Name`; and all **21** markers under `tests/corpus/rust/**` and `tests/golden/identity/rust/fixtures/**` are the canonical `/// @trusted(level=ASSURED)`. The inventory is exhaustive over this constraint's own list because the remaining named artefacts hold no marker call site to census: `tests/golden/identity/corpus/*.json` and `tests/golden/identity/rust/corpus/*.json` are scanner OUTPUTS, and the vocabulary descriptor golden plus `src/wardline/core/vocabulary.yaml` are declaration metadata. **Conclusion: form 5 moves no frozen golden.** The two `level="BOGUS"` values are the one non-trivial datum and they change nothing either — a token that is READ and then fails the `allowed` check is PY-WL-114's DEFECT on spec §4.2.1's *READS, then rejects* row, which the residual FACT excludes by name. Read this discharge at its stated scope and no wider: the **repo-wide** census is spec §14's, and it is read at Final verification's self-scan gate, not here. **The sibling obligation in this sentence is NOT discharged and stays owned:** spec §4.2.1's blast-radius measurement is **re-run once the form-5 plumbing shape is fixed**, against the same four frozen-oracle suites with the blinded negative control re-confirmed **live in the same session** — owned by Final verification's blast-radius bullet and by `wardline-5a795253f1` close condition (iv), neither of which this discharge touches; a delta is PRD-0003 criterion 4's reject branch. Every task carrying revision 6 is inside this constraint, not only Tasks 5–7. **Repro placement, both frontends (spec §4.2.1):** each rev-6 exit-code repro lives in a `tmp_path` unit or integration test and in **none** of the trees named above — a specimen committed into a fixture tree is silently absorbed, converting criterion 4's guard into a re-freeze. If a scan-golden test goes red, the change is wrong — stop and fix the change, never the golden.
- **Exactly two sanctioned golden re-freezes**, both of `tests/conformance/mcp_output_schemas.golden.json` (an API-surface golden, not a scan golden): Task 9 (decorator_coverage summary keys) and Task 20 (verify_attestation `schema_recognized`). Each follows the module's RE-FREEZE PROCEDURE and bumps `VENDORED_BLOB_SHA` in the same commit.
- **`REGISTRY_VERSION` stays `"wardline-generic-2"`** (`src/wardline/core/registry.py:24` — *rev-3.9 correction: this read `:22`, which was never right rather than drift; `ATTEST_SCHEMA`'s `:63` beside it is correct and unchanged*) and **`ATTEST_SCHEMA` stays `"wardline-attest-2"`** (`src/wardline/core/attest.py:63`) throughout S0. The `generic-3`/`attest-3` bumps are S1, gated by the Rollout Fence section.
- **`_RESOLVER_VERSION` bumps `"sp1g"` → `"sp1h"` in Task 5.** Builtin seeding semantics change even though descriptor bytes and the builtin provider fingerprint do not; old warm summaries must miss.
- **`src/wardline/core/descriptor.py` output is untouched** — new `RegistryEntry` fields are NOT serialised into the vocabulary descriptor in S0.
- **The three shipped markers' runtime signatures are frozen** — no edits to `src/wardline/decorators/` or `packages/weft-markers/`. `@external_boundary` is bare-only, `@trust_boundary` call-only, and `@trusted` bare-or-called; Task 1 records those forms without changing runtime code.
- **Custom-pack compatibility is a hard gate.** Tasks 1–9 must keep `tests/grammar/test_thirdparty_pack_bridge.py` green and preserve its two recognised boundaries. PY-WL-130 never validates custom marker kwargs.
- **Truthful diagnostics.** PY-WL-130 may call a shape runtime-invalid only for a proved runtime-invalid reason. `unreadable_splat` says Wardline cannot statically prove the mapping; it never promises Python raises `TypeError`.
- **P11 is split by lifetime.** P11a (new marker on old Wardline) lands in Task 7. P11b's generic unknown-`TokenSetArg` contract is an S2 release gate proved with an unknown `Sensitivity` token; S3 repeats the integration gate with an unknown `Evidence` token. A LEVEL-token proxy satisfies neither obligation.
- **Preview-vector source pin.** The pinned blob is `f4ba87c488778f2c315de1944818db12707d981f` **at commit `aa10dd3d`**, which is spec **rev 10** — the governing revision. The rev-3.7 record's "owed a re-pin" residue is **discharged, and the discharge is verified rather than asserted**: the pinned constant is revision 10's blob as read from revision 10's commit, never from a working-tree hash. Do not restate a site count here — rev 3.7 claimed "all eight pin sites" and was wrong, because the digest moved and the prose did not. The pin is **derived from the commit**, never from a `git hash-object` reading of the working-tree file: a working-tree-derived constant would make the check below pass while pinning a blob reachable from no commit, voiding the provenance the pin exists for. Blob `9624f8925a006a80677c12eaa0951933d631920f` (rev 5) is demoted to review provenance and joins `b43aab4bab1f93f419c189e26fd533afdcc6d387` (rev 4, commit `ae968b540470467258be5989d451991252f7f8dd`), `4956ba3b33ad3c594f0ad47db98ee6d636ad3051` at `1244f627` and `0f04eeb172e4479c330a806b37ff9b2132917f20` at `ed7bfe860d836f4bbab891eddfbada90330db825` as review provenance only. Tasks 19, 20, and 22 verify the pinned blob via the execution preflight's static check against the **rev-10** constant; any later spec drift is STOP-and-re-review. Reach, stated honestly: that executable check gates Tasks 19, 20 and 22 only — it does **not** gate Tasks 1–18, so revision 6's engine content in those tasks is protected by review, not by this check. S1's first serializer gate replaces every non-normative preview with real producer output and compares it before emission.
- New rule id is exactly **`PY-WL-130`**; new FACT ids are exactly **`WLN-ENGINE-UNKNOWN-MARKER`** and **`WLN-ENGINE-UNREADABLE-MARKER-VALUE`** — both `Severity.NONE` + `Kind.FACT`, both reserved by the spec, the second added at rev 6 (§4.2.1). The second is **builtin-only** and never co-emits on the same site with either neighbour. Not with `WLN-ENGINE-UNPROVABLE-BOUNDARY`: a custom `BoundaryType`'s unreadable level value keeps its released channel and an `UNKNOWN_RAW` seed, so no unreadable value is reported twice or counted twice in `decorator_coverage`. And not with `PY-WL-130`: `call_shape_offences` is the single call-shape verdict and runs **before** the levels loop, so a shape-rejected marker's value is never read and never becomes a question. That second one is an **ordering**, not a claim that one channel dominates — `PY-WL-130` is a `Kind.DEFECT` and therefore suppressible, so a waived `PY-WL-130` leaves that site with no signal at all, whereas the FACT is unsuppressible but never gates. FACT ids are not numbered; the next free **numeric** rule id after this plan is 131.
- Conventions: FACTs are `Severity.NONE` + `Kind.FACT`; PY-WL-130 is `Severity.ERROR` + `Kind.DEFECT`, `maturity=Maturity.STABLE` (default), `multi_emit=True`.
- Test commands run from `/home/john/wardline` unless a task names another repo. Full suite = `uv run pytest -q`.
- Commit messages follow `feat(scope):` / `fix(scope):` / `test(scope):` / `docs(scope):`. Fixed targets are Wardline `release/2.0.0`, Loomweave `release/1.5.0`, Warpline and Legis `main`; "current branch" is never accepted as a substitute.
- **No consumer version bumps in S0.** Loomweave's plugin version is CI-lockstepped to the Rust workspace version (`scripts/check-workspace-version-lockstep.py`); the rollout floor is recorded as commits, not version strings (see Rollout Fence).
- **Unexpected-red discipline.** A red in a file the current task does not name is STOP-and-report, not permission to broaden scope. On an honest corpus-budget STOP, leave the worktree dirty and wait; never relabel findings, regenerate scan goldens, or stash shared-tree work to force green.

## Execution preflight and target checkouts

Before Task 1, the orchestrator performs these read-only checks, then atomically claims `wardline-4928b75782`. Do not claim the blocked S0 ticket first.

```bash
cd /home/john/wardline
git status --short --branch
git rev-parse HEAD
git worktree list --porcelain
filigree session-context
filigree start-work wardline-4928b75782 --assignee claude  # use the executing session's actor
```

Before Tasks 19–23, run this exact clean-target preflight. Any output from `status --porcelain` is a hard stop: do not stash, delete, absorb, or commit unrelated files.

```bash
(
set -euo pipefail
while IFS='|' read -r S0_REPO_PATH S0_TARGET_BRANCH; do
  test "$(git -C "$S0_REPO_PATH" rev-parse --show-toplevel)" = "$S0_REPO_PATH"
  test "$(git -C "$S0_REPO_PATH" branch --show-current)" = "$S0_TARGET_BRANCH"
  S0_DIRTY_STATE="$(git -C "$S0_REPO_PATH" status --porcelain=v1 --untracked-files=all)"
  if test -n "$S0_DIRTY_STATE"; then
    printf 'STOP: dirty target checkout %s\n%s\n' "$S0_REPO_PATH" "$S0_DIRTY_STATE" >&2
    exit 1
  fi
  git -C "$S0_REPO_PATH" rev-parse HEAD
  git -C "$S0_REPO_PATH" worktree list --porcelain
done <<'EOF'
/home/john/wardline|release/2.0.0
/home/john/loomweave|release/1.5.0
/home/john/warpline|main
/home/john/legis|main
EOF
)
```

Immediately before each cross-repository commit, recheck the branch, then require the dirty path set to be a subset of that task's named files; intended task edits are not a cleanliness failure. Run `git diff --check`, inspect `git diff --stat`, stage named paths, and inspect `git diff --cached --name-status`. The reviewed target checkouts are:

| Repo | Required target checkout | Required target branch | Other worktrees observed during rev 3 review |
|---|---|---|---|
| wardline | `/home/john/wardline` | `release/2.0.0` | `codex-c16-scan-summary`, `release-prep` |
| loomweave | `/home/john/loomweave` | `release/1.5.0` | agent worktree, `integrate-review-fixes`, `reconcile` |
| warpline | `/home/john/warpline` | `main` | `codex-c17-overflow-contract`, `c20` |
| legis | `/home/john/legis` | `main` | `c20`, `seam-debt`, `plainweave-doctor-binding` |

For every non-target worktree, inspect `git status --short --branch` and check the owning agent/session. If a live or dirty worktree overlaps a named file, STOP and coordinate. Clean status alone is not a liveness proof. Cross-repo tasks edit the primary targets above only, stage explicit paths only, and verify the resulting commit is an ancestor of the named target branch. (The formerly untracked Legis file `docs/superpowers/plans/2026-07-14-plainweave-preflight-v2-conformance.md` was preserved byte-for-byte and committed on legis `main` as `a117a21` — that preflight stop is resolved; the check above still guards against any NEW dirt.)

Recheck the committed spec pin before consumer work. The constant below is the blob **at commit `aa10dd3d`**, which is spec **rev 10** — the governing revision — and is read from that commit, never from a hash of whatever the working tree happens to hold. The check PASSES against the governing spec as shipped. If it ever fails, that is the drift case: STOP and re-review, and never repair it by re-deriving the constant from the working tree. If the check fails, that is its designed behaviour on a drifted spec and it is a STOP-and-re-review; it is never a licence to re-derive the constant from the working-tree file, which would pin a blob reachable from no commit.

```bash
test "$(git hash-object docs/superpowers/specs/2026-08-09-declaration-surface-v2-design.md)" = \
  "f4ba87c488778f2c315de1944818db12707d981f"
```

This check gates Tasks 19, 20 and 22 only (see Task dependency order). Tasks 1–18 carry revision 6's engine content and are **not** gated by it.

## Task dependency order

T1 → T2 → T3 → T4 → T5 → T6 → T7 → T8 → T9; T10–T18 depend only on earlier Wardline tasks where stated (T14 needs T5–T8 — its matrix asserts the residual FACT channel T8 emits and the form-5 resolution T5 lands). **Revision 6 inserted the two engine tasks that lengthened that chain, and both now carry real ordinals:** **T3** is the per-module binding census (its type's builder, both context carriers), placed after T2 because T2's re-cut reader takes the census as a required parameter and before T5 because T5 is its first live caller; **T8** is the residual `WLN-ENGINE-UNREADABLE-MARKER-VALUE` FACT (emission loop, fingerprint, and its five soundness conditions), placed after T7 because T7 owns the `taint_for` arm that populates the carrier and before T9 because T9 counts the resulting FACT in `decorator_coverage`. T8 additionally depends on T5, which is where `_match` first mints the residual pair. Cross-repo: **T19, T20, and T22 require the committed spec **rev 10** pin (preflight blob check; the shipped constant is revision 9's and passes), independent of T1; T20 precedes T21; T23 requires T20+T21 and runs after T22 so both consumer receipts exist.** Recommended execution order is numeric.

## Filigree discipline

- Before T1: `work_start` on `wardline-4928b75782` (atomic claim). The S0 ticket `wardline-5a795253f1` is dependency-blocked by the bug — do NOT claim it yet.
- After T7's final green (the call-shape fix is Tasks 2–7): close `wardline-4928b75782` with commit refs and the before/after repro from Final Verification, THEN `work_start` on `wardline-5a795253f1` for the remainder. **The ticket is re-scoped (rev 3.3) to the Python builtin call SHAPE — close it as "the call-shape half is fixed", never as "the false green is fixed".** Name both siblings in the close comment, stated **by owning task** rather than by status at that instant: `wardline-2b2a6cddfa` (the statically unreadable level VALUE) is **in S0 scope** at rev 3.5, per spec §13.2's S0 row, and closes when the form-5 reader **and** the residual `WLN-ENGINE-UNREADABLE-MARKER-VALUE` FACT have both landed — neither substitutes for the other (PDR-0018); `wardline-b857b50b54` (the Rust non-canonical marker shape) is **outside S0** by owner ruling of 2026-08-10, owned by spec §4.4's separately-owned thread, and must close **before G2 is read**. Whether either is already closed at T7's green depends on task placement — do not assert a status the tracker can contradict.
- **`wardline-5a795253f1` closes only when all five conditions (i)–(v) in Final verification's `wardline-5a795253f1` close bullet hold**, each recorded in the close comment with its evidence. **That bullet is the single authoritative enumeration and is deliberately NOT restated here** — two lists both claiming exhaustiveness is how a condition goes missing, and the four-item list this pointer replaces omitted two of the five: (i) Task 23's integrated Wardline commit plus the four-repo local-install receipt, and (v) P9's `test_form5_agreement`. Global Constraints and the Rev 3.6 record both key to the roman numbering for the same reason. **S0's close does NOT close PRD-0003 criterion 6.** State that in the close comment and name `wardline-b857b50b54` and spec §4.4's thread as the criterion's owner, so it does not go ownerless the day S0 goes green — which is precisely the failure the scope split was made to avoid.
- **Re-opened by PDR-0018 / spec rev 6 §4.2.1:** `wardline-2b2a6cddfa` is **re-opened by owner decision** and closes **inside S0**, by P3 form 5 plus the residual `WLN-ENGINE-UNREADABLE-MARKER-VALUE` FACT. Rev 3.4's "settled — do not re-open" disposition is withdrawn in full, and with it that note's two-gap scoping of the drop-coverage matrix comment (T12 in rev-3.4 numbering, **T14** at rev 3.5): under rev 6 the matrix is channel-name-driven and a statically unreadable builtin LEVEL value is **never** silent. **The one clause that stands, unchanged and reinforced: an unreadable level value must never appear in any rule's `examples_clean`.** The `@trusted(level=cfg.LEVEL)` snippet is **already removed** from **T6**'s `METADATA` (PY-WL-130) and must not be re-added, and PY-WL-114's own shipped `examples_clean` entry for it is **deleted, not re-annotated** — a `Severity.NONE` FACT does not convert a fail-open construct into a legitimate clean exemplar. Do **not** rely on `tests/unit/scanner/rules/test_rule_examples_meta.py` to enforce that clause: it filters to `Kind.DEFECT`, so the residual FACT reds nothing there and neither deletion is forced by a failing test — the enforcing assertion has to be written. (Rev 3.4's measured rejection of demoting a malformed builtin's seed to `UNKNOWN_RAW` is unaffected and is recorded in the rev-3.4 note above: it governs **T5**'s seed handling, not this ticket's status.)
- **After T8's commit — `wardline-2b2a6cddfa`'s owning action is T8 Step 14: CLOSE it.** Named explicitly at rev 3.8 because rev 3.7 named no owner: the bullet above said the ticket "closes inside S0" and the only command touching it anywhere in this plan was an `add-comment` at T8 Step 10, while `wardline-5a795253f1`'s close condition (ii) requires it **CLOSED**. The close is the orchestrator's, carries T8's commit sha and the committed exit-code repro `tests/unit/cli/test_false_green_exit_code_repros.py::test_hole3_unreadable_level_value_trips_the_gate`, and lands **after** the commit rather than beside the comment so it never anchors a sha that does not yet exist. This is the plan's rev-3.6 defect class — the unowned hand-off — caught one level down.
- During T15: verify the two already-filed engine ticket IDs listed there; do not file duplicates.

---

### Task 1: Complete registry grammar — `ArgKind`, call form, and immutable kwargs (P14)

**Files:**
- Modify: `src/wardline/core/registry.py`
- Modify: `src/wardline/scanner/boundary_types.py:133-141` (tripwire extension)
- Modify: `src/wardline/scanner/diagnostics.py:36-38` (native/compiled import allowlist)
- Test: `tests/unit/core/test_registry.py`
- Test: `tests/unit/scanner/test_diagnostics.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `ArgKind` (`LEVEL`, `TOKEN_SET`, `REF`); `MarkerCallForm` (`BARE_ONLY`, `CALL_ONLY`, `BARE_OR_CALL`); `RegistryEntry.kwargs`, `arg_kinds`, and `call_form`. There is no ignored-kwarg concept. `__post_init__` copies every caller-owned mutable and requires `arg_kinds.keys() == kwargs`. The load-time tripwire covers both builtin roots and guarantees each builtin `BoundaryType.level_args` agrees with the registry's kwargs and `LEVEL` kinds.

- [ ] **Step 1: Write the failing tests** — append to `tests/unit/core/test_registry.py`:

```python
from wardline.core.registry import REGISTRY, ArgKind, MarkerCallForm, RegistryEntry


def test_registry_declares_marker_kwargs() -> None:
    # The declared keyword set per marker — spec §4.2. This is the DECLARATION
    # contract, not a transcription of the runtime signature
    # (src/wardline/decorators/trust.py): trust_boundary declares only to_level and
    # trusted only level, while external_boundary declares none because it is
    # BARE_ONLY — call form is decided first, so kwargs are never consulted for it.
    # (Its `fn` parameter is positional-or-keyword, so `external_boundary(fn=...)`
    # is legal Python; it still declares nothing on the decorated function, which is
    # exactly why the empty set is the right contract rather than `{"fn"}`.)
    assert REGISTRY["external_boundary"].kwargs == frozenset()
    assert REGISTRY["trust_boundary"].kwargs == frozenset({"to_level"})
    assert REGISTRY["trusted"].kwargs == frozenset({"level"})


def test_registry_arg_kinds_cover_the_level_args() -> None:
    assert dict(REGISTRY["trusted"].arg_kinds) == {"level": ArgKind.LEVEL}
    assert dict(REGISTRY["trust_boundary"].arg_kinds) == {"to_level": ArgKind.LEVEL}
    assert dict(REGISTRY["external_boundary"].arg_kinds) == {}


def test_registry_kwarg_invariants() -> None:
    for entry in REGISTRY.values():
        assert set(entry.arg_kinds) == entry.kwargs, entry.canonical_name


def test_shipped_call_forms_are_exact() -> None:
    assert REGISTRY["external_boundary"].call_form is MarkerCallForm.BARE_ONLY
    assert REGISTRY["trust_boundary"].call_form is MarkerCallForm.CALL_ONLY
    assert REGISTRY["trusted"].call_form is MarkerCallForm.BARE_OR_CALL


def test_registry_arg_kinds_are_immutable() -> None:
    import pytest

    with pytest.raises(TypeError):
        REGISTRY["trusted"].arg_kinds["level"] = ArgKind.REF  # type: ignore[index]


def test_registry_entry_deep_freezes_caller_inputs() -> None:
    kwargs = {"level"}
    kinds = {"level": ArgKind.LEVEL}
    entry = RegistryEntry(
        "x", 1, {}, kwargs=kwargs, arg_kinds=kinds,
        call_form=MarkerCallForm.BARE_OR_CALL,
    )
    kwargs.add("audit")
    kinds["level"] = ArgKind.REF
    assert entry.kwargs == frozenset({"level"})
    assert dict(entry.arg_kinds) == {"level": ArgKind.LEVEL}


def test_registry_rejects_untyped_declared_keyword() -> None:
    import pytest

    with pytest.raises(ValueError, match="arg_kinds keys must equal kwargs"):
        RegistryEntry("x", 1, {}, kwargs={"level"}, arg_kinds={})


def test_registry_kwargs_match_boundary_type_level_args() -> None:
    # One source of truth: the tripwire in boundary_types enforces this at import,
    # this test makes the fusion a named contract.
    from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES

    for bt in BUILTIN_BOUNDARY_TYPES:
        assert REGISTRY[bt.canonical_name].kwargs == frozenset(
            la.arg_name for la in bt.level_args
        ), bt.canonical_name


def test_tripwire_covers_both_builtin_roots() -> None:
    # Spec §4.2: the load-time tripwire covers BOTH builtin roots. Pin that the
    # weft_markers rows are genuinely checked, not skipped, by asserting they carry
    # exactly the registry contract the loop enforces.
    from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES

    roots = {bt.module_prefix.split(".")[0] for bt in BUILTIN_BOUNDARY_TYPES}
    assert roots == {"wardline", "weft_markers"}
    for bt in BUILTIN_BOUNDARY_TYPES:
        entry = REGISTRY[bt.canonical_name]
        assert entry.group == bt.group, bt.module_prefix
        assert entry.kwargs == frozenset(la.arg_name for la in bt.level_args), bt.module_prefix
        assert dict(entry.arg_kinds) == {
            la.arg_name: ArgKind.LEVEL for la in bt.level_args
        }, bt.module_prefix


def test_tripwire_leaves_no_module_scope_temporaries() -> None:
    # The trailing `del` must name every leaked temporary and nothing more — a
    # stale `del _la` would NameError at import and take the whole package down.
    import wardline.scanner.boundary_types as bt_mod

    assert not [
        n for n in vars(bt_mod)
        if n in {"_bt", "_entry", "_expected_kwargs", "_expected_kinds", "_la"}
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/core/test_registry.py -v`
Expected: FAIL — `ImportError: cannot import name 'ArgKind'`.

- [ ] **Step 3: Implement in `src/wardline/core/registry.py`.** Add `from enum import StrEnum` and extend the dataclass import with `field`. Insert after `REGISTRY_VERSION`:

```python
class ArgKind(StrEnum):
    """The marker-argument grammar (declaration-surface-v2 §4.2, P14).

    Declares how the engine READS each keyword argument of a registered marker.
    S0 ships only ``LEVEL`` consumers. ``TOKEN_SET`` (tuples of value tokens,
    e.g. ``marks=``/``evidence=``) and ``REF`` (module-level declaration
    references, e.g. ``contract=``) get their generic readers with their first
    S2 consumers; S3 reuses TOKEN_SET for the Evidence domain. Every kind is
    fail-closed on any deviation from its form. There is no ignored/compat
    keyword concept: a keyword outside ``kwargs`` is PY-WL-130's DEFECT and the
    seed drops (the runtime signatures reject it too).
    """

    LEVEL = "level"
    TOKEN_SET = "token_set"
    REF = "ref"


class MarkerCallForm(StrEnum):
    """Whether a shipped marker is legal bare, called, or in either form."""

    BARE_ONLY = "bare_only"
    CALL_ONLY = "call_only"
    BARE_OR_CALL = "bare_or_call"
```

Replace `RegistryEntry` with:

```python
@dataclass(frozen=True)
class RegistryEntry:
    """A registered trust decorator and its expected ``_wardline_*`` attributes.

    ``attrs`` maps each stamped attribute name to its expected value *type*.
    ``kwargs`` is the declared keyword set the marker's call form accepts —
    exactly the runtime signature's keyword parameters, fused to the boundary
    types' ``level_args`` by the load-time tripwire in ``boundary_types``.
    ``arg_kinds`` maps declared keywords to their :class:`ArgKind` reading
    discipline. Mappings are wrapped in ``MappingProxyType`` at construction.
    """

    canonical_name: str
    group: int
    attrs: Mapping[str, type]
    kwargs: frozenset[str] = field(default_factory=frozenset)
    arg_kinds: Mapping[str, ArgKind] = field(default_factory=dict)
    call_form: MarkerCallForm = MarkerCallForm.BARE_OR_CALL

    def __post_init__(self) -> None:
        frozen_kwargs = frozenset(self.kwargs)
        frozen_arg_kinds = MappingProxyType(
            {name: ArgKind(kind) for name, kind in self.arg_kinds.items()}
        )
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))
        object.__setattr__(self, "kwargs", frozen_kwargs)
        object.__setattr__(self, "arg_kinds", frozen_arg_kinds)
        object.__setattr__(self, "call_form", MarkerCallForm(self.call_form))
        if set(frozen_arg_kinds) != frozen_kwargs:
            raise ValueError(f"{self.canonical_name}: arg_kinds keys must equal kwargs")
```

Update `_ENTRIES`:

```python
_ENTRIES: dict[str, RegistryEntry] = {
    "external_boundary": RegistryEntry(
        canonical_name="external_boundary",
        group=1,
        attrs={},
        call_form=MarkerCallForm.BARE_ONLY,
    ),
    "trust_boundary": RegistryEntry(
        canonical_name="trust_boundary",
        group=1,
        attrs={"_wardline_to_level": TaintState},
        kwargs=frozenset({"to_level"}),
        arg_kinds={"to_level": ArgKind.LEVEL},
        call_form=MarkerCallForm.CALL_ONLY,
    ),
    "trusted": RegistryEntry(
        canonical_name="trusted",
        group=1,
        attrs={"_wardline_level": TaintState},
        kwargs=frozenset({"level"}),
        arg_kinds={"level": ArgKind.LEVEL},
        call_form=MarkerCallForm.BARE_OR_CALL,
    ),
}
```

- [ ] **Step 4: Extend the load-time tripwire.** In `src/wardline/scanner/boundary_types.py`, the tripwire loop at `:133-141` currently checks name + group. Replace its body check with:

```python
# Consistency tripwire: builtin names/group/kwargs/arg-kinds must mirror the released
# REGISTRY so the two views (REGISTRY = declaration contract; grammar = + seed
# semantics) cannot drift. BOTH builtin roots are covered (spec §4.2): the
# ``weft_markers`` rows share the same canonical REGISTRY rows as their
# ``wardline.decorators`` twins — verified identical on group, level_args and seed —
# so the loop simply revisits each canonical name once per root. The three redundant
# lookups are intentional: they are what proves a future per-root edit cannot desync
# one root while the other stays green.
for _bt in BUILTIN_BOUNDARY_TYPES:
    _entry = REGISTRY.get(_bt.canonical_name)
    if _entry is None or _entry.group != _bt.group:  # pragma: no cover
        # Load-time tripwire: unreachable unless a future edit desyncs the builtin
        # boundary types from the frozen REGISTRY. Fail CLOSED-LOUD at import.
        raise ValueError(f"builtin BoundaryType {_bt.canonical_name!r} drifted from REGISTRY")
    _expected_kwargs = frozenset(_la.arg_name for _la in _bt.level_args)
    _expected_kinds = {_la.arg_name: ArgKind.LEVEL for _la in _bt.level_args}
    if _entry.kwargs != _expected_kwargs:  # pragma: no cover
        # The registry's declared keyword set IS the level-arg schema; PY-WL-130
        # and seeding both derive tolerance from one place. Fail CLOSED-LOUD.
        raise ValueError(f"builtin BoundaryType {_bt.canonical_name!r} kwargs drifted from REGISTRY")
    if dict(_entry.arg_kinds) != _expected_kinds:  # pragma: no cover
        raise ValueError(f"builtin BoundaryType {_bt.canonical_name!r} arg kinds drifted from REGISTRY")
del _bt, _entry, _expected_kwargs, _expected_kinds
```

(Import `ArgKind` beside `REGISTRY` at the top of `boundary_types.py`. The current `weft_markers` skip is **removed**: both builtin roots share the same canonical registry rows and both must trip on drift — verified 2026-08-09 that the three `weft_markers` entries carry identical `group`, `level_args` and `seed` to their `wardline.decorators` twins, so removing the skip trips nothing at import; the loop now runs six iterations with three redundant-but-passing lookups, which is the point. `_WEFT_MARKERS_PREFIX` remains referenced by the `BUILTIN_BOUNDARY_TYPES` tuple construction, so it does not become dead. The trailing `del` lists exactly the four module-scope temporaries — `_la` is a comprehension variable and never binds at module scope, so deleting it would `NameError` at import.)

- [ ] **Step 5: Pin the compiled/native public import surface.** Add `"ArgKind"` and `"MarkerCallForm"` to `_NATIVE_FIRST_PARTY_IMPORTS["wardline.core.registry"]`, update `registry.py`'s public-surface docstring to list all five public names, and add a diagnostic test that imports both enums with `project_modules=frozenset()` and expects no unknown-import finding.

- [ ] **Step 6: Run tests to verify they pass, and prove zero drift**

Run: `uv run pytest tests/unit/core/test_registry.py tests/unit/scanner/test_diagnostics.py tests/unit/core/test_descriptor.py tests/grammar/test_grammar_model.py tests/conformance/test_vocabulary_descriptor_wire_golden.py -q`
Expected: all PASS. `test_committed_vocabulary_yaml_matches_registry` proves the descriptor bytes did not move.

- [ ] **Step 7: Commit** — `feat(registry): record immutable marker kwargs, arg kinds, and call forms (S0 P14)`. Record the commit SHA in the implementation receipt.

---

### Task 2: Shared marker-reader engine-floor module + call-shape validator (P9)

**Files:**
- Create: `src/wardline/scanner/marker_reader.py`
- Modify: `src/wardline/scanner/taint/decorator_provider.py` (delete moved functions, import instead)
- Modify: `src/wardline/scanner/rules/invalid_decorator_level.py` (drop the loose local readers; import shared)
- Modify: `src/wardline/scanner/rules/contradictory_trust.py` (drop the local resolver + provider-private import; import shared)
- Modify: `tests/unit/scanner/taint/test_decorator_provider.py` (reverse the ghost `weft_markers.trust` export pin)
- Modify: `tests/unit/scanner/rules/test_contradictory_trust.py` (per-root shadow directions)
- Modify: `tests/unit/scanner/rules/test_invalid_decorator_level.py` (Step 3's unconditional foreign-receiver silence assertion; Step 3's re-label of the `@trusted(level=cfg.LEVEL)` `clean_dynamic` case at `:93`; any OLD-textual-behaviour pin Step 3's sweep turns up)
- Modify: `tests/unit/scanner/rules/test_invalid_decorator_level_recognizer.py` (Step 3's OLD-textual-behaviour sweep only — measured 2026-08-10, `grep -n "TaintState" tests/unit/scanner/rules/test_invalid_decorator_level*.py` returns NO hits in either file, so this path may legitimately end the task with an **empty diff**. It is listed because the sweep is instructed and execution-time drift could surface a pin; an empty diff on a LISTED path is never a stop, whereas an unlisted changed path is.)
- Test: `tests/unit/scanner/test_marker_reader_agreement.py` (new)

**Interfaces:**
- Consumes: `TaintState` plus Task 1's `MarkerCallForm` and registry grammar.
- Produces (all public, exact signatures — Tasks 3 and 5–7 import these):
  - `dotted_name(node: ast.expr) -> str | None`
  - `resolve_dotted_fqn(node: ast.expr, alias_map: Mapping[str, str]) -> str | None`
  - `resolve_decorator_fqn(deco: ast.expr, alias_map: Mapping[str, str]) -> str | None`
  - `alias_map_for_qualname(qualname: str, alias_maps: Mapping[str, Mapping[str, str]]) -> Mapping[str, str]` — one longest-owning-module lookup for all rules.
  - `ModuleCensus(values: Mapping[str, CensusBinding], poisoned: bool, reference_sites: frozenset[ast.stmt])` — spec rev 6 §4.2.1's per-module census, with its three components: `values` is the binding census keyed by module-scope name; `poisoned` is the module-wide flag an unresolved star import sets; `reference_sites` holds the `def` / `async def` statements that are direct elements of `Module.body`, **by node identity** — sound because module source is parsed exactly once and both readers receive the same node objects, and load-bearing because a conditionally-defined module-level `def` has the same qualname as an unconditional one, so no qualname or column-offset proxy can answer the reference-site restriction. The type is defined HERE, in the engine floor, because Task 2's own callers must type-check against it and the census task (**Task 3**) lands after Task 2; that task owns the parse-loop BUILDER and the two context carriers and creates no second type. This is the ONE census name — nothing downstream may introduce a synonym.
  - `CensusBinding(token: str | None, unreadable_reason: str | None, line: int)` — exactly one of `token` / `unreadable_reason` is set; `line` is the binding's line, which is what makes lexical precedence decidable. `unreadable_reason` is diagnostic message text and is **never** fingerprint input (spec §4.2.1 condition 4 keys the fingerprint on the unparsed value node, which needs no census entry at all).
  - `level_token(value: ast.expr, alias_map: Mapping[str, str], *, census: ModuleCensus | None, reference_site: ast.stmt | None, shadowed_roots: frozenset[str], builtin: bool) -> str | None` (STRICT: alias-resolved `wardline.core.taints.TaintState` receiver or str literal — the semantics spec §4.2.1 keeps and explicitly does NOT supersede). **All four new keywords are REQUIRED and carry NO default**; spec §4.2.1 forbids a defaulted-empty census by name, because a defaulted one ships the one-sided widening that mints a fresh silent false green. A bare `ast.Name` resolves under P3 form 5 and under nothing else — **five** required conditions, and the fifth is not optional: `builtin` is True, `census` is not `None` and not `poisoned`, `reference_site` is in `census.reference_sites`, `census.values` holds an entry for that name whose `token` is set, **and that entry's `line` is strictly less than `reference_site.lineno`**. That fifth conjunct is spec §4.2.1's **lexical-precedence** clause — normative at spec :42, :111 and :113, with its own case-table row at spec :133 ("the binding must precede the decorated `def` / `async def` in source order"; verdict UNREADABLE + FACT otherwise) — and it is stated here because the census only **carries** the binding line: the comparison is the reader's, and no other task performs it. **The anchor is named so no implementer substitutes another node:** it is the `reference_site` statement's OWN `lineno`, which for a decorated `FunctionDef` / `AsyncFunctionDef` is the **`def` line, decorators excluded** (measured at CPython 3.13.1; the AST has behaved this way since 3.8). A qualifying module-scope binding that precedes the `def` also precedes its decorators, so the choice between the two anchors moves no verdict; the comparison is **strict** (`<`) because no module-scope binding can share the `def`'s own line. Build the reader without this conjunct and it RESOLVES a binding placed *after* the decorated `def` — a minted seed where the specification requires UNREADABLE, which is the seed-minting direction and the dangerous one. Every other bare `Name` is unreadable. **Absent and empty are different inputs**: a census that is present but holds no qualifying entry — or a `reference_site` outside `census.reference_sites`, or an entry that does not lexically precede it — is an ordinary unreadable and returns `None`, whereas being handed a bare `ast.Name` in a LEVEL slot on a **builtin** marker with `census=None` (no census built for that module at all) is a plumbing defect and the reader **raises `ValueError`**. **The raise is BUILTIN-ONLY, and the unconditional reading is rejected here rather than left implicit:** on a custom `BoundaryType` a bare `Name` is an ordinary unreadable and returns `None`, because form 5 cannot resolve there at all (spec :119 — "Form 5 is builtin-only") and no census could change that verdict, so a raise would buy nothing while breaking the released `WLN-ENGINE-UNPROVABLE-BOUNDARY` + `UNKNOWN_RAW` contract the Global Constraints pin as a hard gate. Corroboration, not the basis: the builtin-only ruling leaves the three shipped custom-boundary cases in `tests/grammar/test_provider_loop.py` (`:48`, `:57`, `:72` — each passing a bare `ast.Name` in a **custom** `BoundaryType`'s LEVEL slot through a census-less `SeedContext`: `to_level=CFG` at `:51` and `:64`, `to_level=A` / `to_level=B` at `:85-86`; only the first goes through the `_ctx()` helper, the other two construct `SeedContext(...)` inline at `:67` and `:88`) untouched, where the unconditional reading would red all three. The reader tests only what it was handed, never whether some other component ran, so a non-`Name` value with `census=None` still reads normally, and so does a bare `Name` with `builtin=False`. `shadowed_roots` closes the pre-existing gap for a form-2 value written DIRECTLY in the LEVEL slot; form 5's own right-hand-side shadowed-root refusal is applied at the census build (spec §4.2.1) and must never be re-derived here, where the form-2 receiver is already gone. `reference_site` is `| None` for one stated reason only — verified in source, the provider's `_match` receives no entity node today, so the Task 2 provider path cannot present a site; Task 5 threads `entity.node` down into `_match` (its own re-cut). `None` is not a permanent option and never suppresses the raise.
  - `KeywordExtraction(items: tuple[tuple[str, ast.expr], ...], offences: tuple[tuple[str, str], ...])`
  - `extract_keywords(deco: ast.expr) -> KeywordExtraction` — direct and literal-splat keywords in Python's evaluation order.
  - `LevelVerdict` ∈ {`RESOLVED`, `REJECTED`, `UNREADABLE`} and `LevelRead(verdict: LevelVerdict, level: TaintState | None, unreadable_value: tuple[str, str] | None)` — the discriminated result that replaces the old bare `TaintState | None`. `RESOLVED` carries the level. `REJECTED` means a token was **READ** and then failed `TaintState(...)` or the `allowed` check: that is PY-WL-114's DEFECT and it **never** carries a residual pair and **never** emits `WLN-ENGINE-UNREADABLE-MARKER-VALUE` (spec §4.2.1's *READS, then rejects* row). `UNREADABLE` means no token was read at all. `unreadable_value` is the `(argument name, ast.unparse(value node))` pair the residual FACT is built from, and is populated **only** when `verdict` is `UNREADABLE` **and** `builtin` is True — that is the mechanism keeping form 5 and the residual channel builtin-only, in place of a caller-side gate. The text is RAW `ast.unparse` — un-normalised and untruncated — and it stays raw all the way to the emission site: NFC normalisation and the 200-character truncation belong to the emission site (spec §4.2.1 condition 4), never here. That site derives **one** key from this raw text and renders the fingerprint's fourth part, the diagnostic message and `properties["value"]` from that same key — **one text, not two**. This interface therefore does **not** promise that the message keeps the full text; the earlier wording to that effect is withdrawn as contradicting the emission Task 8 pins.
  - **On the custom side the two non-resolving verdicts collapse, deliberately.** A custom `BoundaryType` takes the released `(None, canonical_name)` unprovable path on `REJECTED` **and** on `UNREADABLE` alike — only the builtin arm distinguishes them. The enum is a new discrimination for builtins, not licence to split the custom side: splitting it would stop a custom `level='ASURED'` emitting `WLN-ENGINE-UNPROVABLE-BOUNDARY`, breaking the released contract Global Constraints pin as a hard gate.
  - `read_level(deco: ast.expr, arg: str, *, declared: frozenset[str], allowed: frozenset[TaintState], default: TaintState | None, alias_map: Mapping[str, str], census: ModuleCensus | None, reference_site: ast.stmt | None, shadowed_roots: frozenset[str], builtin: bool) -> LevelRead` (uses `extract_keywords`; no ignored-arg path). The four new keywords are REQUIRED with NO default and are forwarded verbatim to `level_token`, so the raise disposition above reaches this entry point unchanged. Declared-sibling semantics are a deliberate, pinned widening over the old provider-private reader (which failed closed on ANY keyword other than the one being read): a keyword that is DECLARED but is not the arg being read is legal. Observable only for multi-level-arg custom markers; none ship in the builtin grammar.
  - `call_shape_offences(deco: ast.expr, *, call_form: MarkerCallForm, declared: frozenset[str], required: frozenset[str]) -> tuple[tuple[str, str], ...]` — the ONE call-shape verdict.
  - `is_builtin_decorator_fqn(fqn: str, canonical_name: str, module_prefix: str) -> bool`
  - `shadowed_builtin_roots(project_modules: frozenset[str]) -> frozenset[str]`
  - Constants `VOCAB_PREFIX = "wardline.decorators"`, `WEFT_MARKERS_PREFIX = "weft_markers"`, `BUILTIN_MARKER_ROOTS`

- [ ] **Step 1: Create `src/wardline/scanner/marker_reader.py`.** Import `dataclass` and move the common resolver/recognizer bodies from `decorator_provider.py`: `_dotted_name`, `_resolve_dotted_fqn`, `_resolve_decorator_fqn`, `_level_token`, `_is_builtin_decorator_fqn`, `_shadowed_builtin_roots`, and their constants (public names as specified above). Create the new shared `read_level` from the old reader minus `ignored_args`, backed by `extract_keywords`. For this intermediate commit only, leave the old provider-private `_read_level` (and its legacy ignored branches) in `decorator_provider.py`; Task 5 deletes it atomically with the seeding/cache change.

```python
# src/wardline/scanner/marker_reader.py
"""The ONE marker-reading grammar (engine floor, declaration-surface-v2 P9).

Every consumer of a trust-marker AST — the L1 seeding provider AND every
validation rule (PY-WL-110, PY-WL-114, PY-WL-130, the S2+ declaration
validators) — reads through these primitives, so a rule can never recognise or
read a marker differently than seeding does (the recogniser-agreement property,
wardline-09c09f14df). Fail-closed everywhere: a value this module cannot read is
``None``, never a guess.

Reading a LEVEL value has exactly three outcomes and each names its channel once
(design spec rev 6 §4.2.1). A bare ``Name`` satisfying P3 form 5 — a BUILTIN
marker, a reference site that is a ``def``/``async def`` DIRECTLY in the module
body, exactly one qualifying same-file module-scope binding, and that binding
LEXICALLY PRECEDING the decorated ``def`` in source order — RESOLVES; it is
an ordinary DRY refactor to a module constant, not a hole. A value that stays
unreadable is NEVER silence: on a builtin it takes the
``WLN-ENGINE-UNREADABLE-MARKER-VALUE`` FACT (``Severity.NONE``), and on a custom
``BoundaryType`` it keeps the released ``WLN-ENGINE-UNPROVABLE-BOUNDARY`` channel
with an ``UNKNOWN_RAW`` seed — one unreadable value takes exactly one channel,
never both. A token that is READ and then rejected by the ``allowed`` check stays
PY-WL-114's DEFECT and takes NO FACT.

Being asked to resolve a bare ``Name`` in a BUILTIN marker's LEVEL slot with NO
census present for the module at all is a PLUMBING DEFECT, not an input
condition: this module RAISES rather than returning a quiet ``None``. The raise
is BUILTIN-ONLY — form 5 is builtin-only, so on a custom ``BoundaryType`` a bare
``Name`` is an ordinary unreadable and no census could change that verdict. An
absent census and an empty one are different inputs — an empty census is an
ordinary unreadable.

``call_shape_offences`` is the single authority on "this marker call's SHAPE is
malformed": the provider drops the seed exactly when it returns offences, and
PY-WL-130 emits exactly one DEFECT per offence — agreement by construction.

Imports only ``core`` (acyclic floor): the provider and the rules both import
THIS; neither reaches into the other.
"""
```

Then add the immutable `ModuleCensus` / `CensusBinding` census types, the `LevelVerdict` / `LevelRead` verdict types (import `Enum` alongside `dataclass`), `KeywordExtraction`, `extract_keywords`, and the validator. Extend `level_token` with P3 form 5 exactly as the Produces list specifies — a bare `ast.Name` resolves only for a builtin marker, only when the handed reference site is in `census.reference_sites`, only from an unpoisoned census holding a single qualifying binding with a token, **and only when that binding's `line` is strictly less than `reference_site.lineno`** (spec §4.2.1's lexical-precedence clause; the anchor is the reference-site statement's own `lineno` — the `def` line, decorators excluded), and it **raises** on `census=None` **only when the marker is builtin**; on a custom `BoundaryType` a bare `Name` is an ordinary unreadable `None`, per the Produces list. `level_token`'s **own docstring must state all five conjuncts**, name the lexical-precedence anchor, and state the builtin-only raise, so the contract ships in source rather than living only in this plan. **`shadowed_roots`' mechanism is stated here rather than left to be inferred, because "moved body-identically" would drop it:** the shipped `_level_token` (`decorator_provider.py:128-143`) consults no shadow set at all, so in the re-cut reader's `ast.Attribute` branch, after `resolve_dotted_fqn(value.value, alias_map)` succeeds, **return `None` when the resolved FQN's first dotted component is in `shadowed_roots`** — the same `fqn.split(".")[0] in shadowed_roots` test this plan writes for the vocabulary recogniser. Without that check Task 3 Step 5's `test_shadowed_root_refusal_is_applied_at_the_census_build` cannot go green, and Task 3's Files list declares `marker_reader.py` NOT modified, so it could not be repaired from there. Everything else about `level_token` is moved body-identically, including the STRICT alias-resolved receiver rule. The extraction contract is exact: direct keywords append; `**KW` is `unreadable_splat`; a literal dict with a non-string **constant** key is `invalid_splat_key`; a key that is not a constant at all (computed, f-string, or a `Name`) is `unreadable_splat`, because it is frequently valid at runtime and Wardline simply cannot read it; nested `**` inside a dict is unreadable; repeated keys *within one literal dict* use the last value and are not duplicates (Python dict construction semantics); a direct/literal-splat collision is `duplicate_kwarg`.

```python
def alias_map_for_qualname(
    qualname: str,
    alias_maps: Mapping[str, Mapping[str, str]],
) -> Mapping[str, str]:
    """Alias map for the longest module prefix that owns *qualname*."""
    module = next(
        (
            name
            for name in sorted(alias_maps, key=len, reverse=True)
            if qualname == name or qualname.startswith(name + ".")
        ),
        None,
    )
    return alias_maps.get(module, {}) if module is not None else {}


@dataclass(frozen=True, slots=True)
class KeywordExtraction:
    """Static keyword values plus extraction defects, in deterministic order."""

    items: tuple[tuple[str, ast.expr], ...]
    offences: tuple[tuple[str, str], ...]


def extract_keywords(deco: ast.expr) -> KeywordExtraction:
    """Extract direct and literal-``**`` keywords without executing target code.

    One literal dict is normalized with Python's insertion-order/last-value
    semantics before its items are appended. A dynamic or nested expansion is
    wholly unreadable; non-string literal keys are invalid but do not cause the
    reader to guess at runtime coercion.
    """
    if not isinstance(deco, ast.Call):
        return KeywordExtraction((), ())
    items: list[tuple[str, ast.expr]] = []
    offences: list[tuple[str, str]] = []
    for kw in deco.keywords:
        if kw.arg is not None:
            items.append((kw.arg, kw.value))
            continue
        if not isinstance(kw.value, ast.Dict) or any(key is None for key in kw.value.keys):
            offences.append(("<**splat>", "unreadable_splat"))
            continue
        order: list[str] = []
        final_values: dict[str, ast.expr] = {}
        for key, value in zip(kw.value.keys, kw.value.values, strict=True):
            if not isinstance(key, ast.Constant):
                # A COMPUTED key ('lev' + 'el', an f-string, a Name) is not a literal
                # key and is frequently valid at runtime — verified 2026-08-09:
                # trusted(**{'lev' + 'el': 'ASSURED'}) executes cleanly. Wardline
                # simply cannot READ it, so it belongs to the analyzer-limitation
                # channel, never the proved-runtime-invalid one. Routing it here also
                # makes it suppress missing_kwarg for free (the guard below keys on
                # unreadable_splat) — a computed key MAY supply the required name.
                offences.append(("<**splat>", "unreadable_splat"))
                continue
            if not isinstance(key.value, str):
                # A non-string CONSTANT key is a PROVED failure — verified 2026-08-09:
                # trusted(**{1: 'ASSURED'}) raises TypeError: keywords must be strings.
                offences.append(("<**splat>", "invalid_splat_key"))
                continue
            if key.value not in final_values:
                order.append(key.value)
            final_values[key.value] = value
        items.extend((name, final_values[name]) for name in order)
    return KeywordExtraction(tuple(items), tuple(offences))


@dataclass(frozen=True, slots=True)
class CensusBinding:
    """One module-scope name's census entry: a token, or why it is unreadable.

    Exactly one of ``token`` / ``unreadable_reason`` is set. ``line`` is the
    binding's line, which is what makes form 5's lexical-precedence clause
    decidable. ``unreadable_reason`` is diagnostic message text and is NEVER
    fingerprint input.
    """

    token: str | None
    unreadable_reason: str | None
    line: int


@dataclass(frozen=True, slots=True)
class ModuleCensus:
    """One module's form-5 census: bindings, star poison, eligible reference sites.

    ``reference_sites`` holds the ``def`` / ``async def`` statements that are
    DIRECT elements of ``Module.body``, by NODE IDENTITY — module source is
    parsed exactly once and both readers receive the same node objects, and no
    qualname or column-offset proxy can answer this test (a conditionally-defined
    module-level ``def`` has the same qualname as an unconditional one). Built
    once per module in the parse loop; never rebuilt, and no rule computes one.
    """

    values: Mapping[str, CensusBinding]
    poisoned: bool
    reference_sites: frozenset[ast.stmt]


class LevelVerdict(Enum):
    """How ONE declared LEVEL argument read. Each verdict names its channel once."""

    RESOLVED = "resolved"  # a token was read and passed the ``allowed`` check
    REJECTED = "rejected"  # a token was READ, then rejected — PY-WL-114's DEFECT, never a FACT
    UNREADABLE = "unreadable"  # nothing was read — the residual channel


@dataclass(frozen=True, slots=True)
class LevelRead:
    """The discriminated result the old bare ``TaintState | None`` collapsed.

    ``unreadable_value`` is the ``(argument name, ast.unparse(value))`` pair the
    residual FACT is built from. It is set ONLY when ``verdict`` is
    ``UNREADABLE`` AND the marker is builtin — that is the mechanism that keeps
    the residual channel builtin-only. The text this carrier holds is RAW —
    un-normalised and untruncated. NFC normalisation and the 200-character
    truncation belong to the EMISSION site, which derives ONE key from this raw
    text and renders the fingerprint's fourth part, the diagnostic message and
    ``properties["value"]`` from that same key: one text, not two. This reader
    makes no promise about the message keeping the full text.
    """

    verdict: LevelVerdict
    level: TaintState | None
    unreadable_value: tuple[str, str] | None


def read_level(
    deco: ast.expr,
    arg: str,
    *,
    declared: frozenset[str],
    allowed: frozenset[TaintState],
    default: TaintState | None,
    alias_map: Mapping[str, str],
    census: ModuleCensus | None,
    reference_site: ast.stmt | None,
    shadowed_roots: frozenset[str],
    builtin: bool,
) -> LevelRead:
    """Read one declared level; malformed/unreadable values fail closed.

    SHAPE IS DECIDED FIRST AND SHORT-CIRCUITS: builtins have already passed
    ``call_shape_offences``, so a shape-malformed marker drops its seed there and
    its LEVEL value is never read — such a site takes PY-WL-130 and never also
    the residual FACT. Custom level-bearing packs retain the released reader
    contract: POSITIONAL ARGUMENTS, undeclared metadata, extraction defects, or
    duplicate values make the declaration unreadable — the positional guard is
    the CUSTOM side's alone, because ``call_shape_offences`` is builtin-only and
    a custom pack reaches no shape gate — and on the custom side ``REJECTED`` and
    ``UNREADABLE`` alike take the released unprovable path. A zero-level custom
    marker never calls this reader and therefore may retain metadata.
    """
    if arg not in declared:
        raise ValueError(f"level argument {arg!r} is not declared")

    def _unreadable(value: ast.expr | None) -> LevelRead:
        # The residual pair is builtin-only, and an ABSENT argument has no value
        # node to unparse — so neither ever reaches the FACT.
        pair = (arg, ast.unparse(value)) if (builtin and value is not None) else None
        return LevelRead(LevelVerdict.UNREADABLE, None, pair)

    def _defaulted() -> LevelRead:
        # ``default is None`` means the argument is REQUIRED (LevelArg's released
        # contract): absent-and-required is unreadable, exactly as today.
        return LevelRead(LevelVerdict.RESOLVED, default, None) if default is not None else _unreadable(None)

    if not isinstance(deco, ast.Call):
        return _defaulted()
    if deco.args:
        # The RELEASED contract, preserved verbatim (decorator_provider.py:165-166):
        # a positional argument makes the declaration unreadable. Builtins take
        # PY-WL-130 at the shape gate and never reach here, but registry call-form
        # validation is BUILTIN-ONLY by design (spec :105; Global Constraints' hard
        # custom-pack gate), so for a custom ``BoundaryType`` this line IS the whole
        # positional guard — delete it and a pack declaring a DEFAULTED ``LevelArg``
        # takes ``_defaulted()`` and seeds TRUSTED with no diagnostic on any channel.
        # Payload is None: positional is a SHAPE problem and never mints a residual
        # pair. Covers ``*ARGS`` too — ``deco.args`` holds the ``Starred`` node.
        return _unreadable(None)
    extracted = extract_keywords(deco)
    if extracted.offences:
        return _unreadable(None)
    if any(name not in declared for name, _value in extracted.items):
        return _unreadable(None)
    values = [value for name, value in extracted.items if name == arg]
    if not values:
        return _defaulted()
    if len(values) != 1:
        return _unreadable(values[0])
    token = level_token(
        values[0],
        alias_map,
        census=census,
        reference_site=reference_site,
        shadowed_roots=shadowed_roots,
        builtin=builtin,
    )
    if token is None:
        return _unreadable(values[0])
    try:
        level = TaintState(token)
    except ValueError:
        # READ, then rejected: PY-WL-114's DEFECT owns this. No residual pair.
        return LevelRead(LevelVerdict.REJECTED, None, None)
    if level not in allowed:
        return LevelRead(LevelVerdict.REJECTED, None, None)
    return LevelRead(LevelVerdict.RESOLVED, level, None)


def call_shape_offences(
    deco: ast.expr,
    *,
    call_form: MarkerCallForm,
    declared: frozenset[str],
    required: frozenset[str],
) -> tuple[tuple[str, str], ...]:
    """Every statically-provable malformation of one marker call's SHAPE.

    Returns ``(offender, reason)`` pairs in a pinned canonical phase order:
    call-form, positional, extraction offences (source order), keyword
    classification/duplicate events (source order), then missing names (sorted).
    Reasons are
    ``call_not_allowed`` | ``call_required`` | ``positional_args`` |
    ``undeclared_kwarg`` | ``invalid_splat_key`` | ``unreadable_splat`` |
    ``duplicate_kwarg`` | ``missing_kwarg``. The vocabulary is exactly the eight
    reasons of spec §4.2 — unchanged. Two of them cover a PROVED-invalid and an
    UNPROVABLE form under one name, split by OFFENDER token:
    ``positional_args`` is ``<positional>`` (a plain positional argument) or
    ``<*args>`` (a ``*`` expansion, which may bind zero arguments), and
    ``unreadable_splat`` covers both a dynamic/nested ``**`` and a literal dict
    with a COMPUTED (non-``ast.Constant``) key. ``invalid_splat_key`` is
    narrowed to a non-string ``ast.Constant`` key — the only splat-key form that
    proves ``TypeError: keywords must be strings``. Value problems are NOT shape
    problems: this validator looks at no value at all, so ``level=CFG``,
    ``level=get_level()`` and ``level='ASURED'`` alike return no offence here.
    Under design spec rev 6 those three then route DIFFERENTLY from one another —
    ``level=CFG`` RESOLVES when P3 form 5 is satisfied in full, a value that stays
    unreadable takes the ``WLN-ENGINE-UNREADABLE-MARKER-VALUE`` FACT rather than
    silence, and a readable-but-invalid token stays PY-WL-114's DEFECT — but none
    of the three is a shape offence.

    SHAPE IS DECIDED FIRST AND SHORT-CIRCUITS. The provider runs this validator
    BEFORE the levels loop, so a marker whose call shape is malformed drops its
    seed here and its LEVEL value is never read: such a site takes PY-WL-130 and
    NEVER also the residual FACT. That is not an exception carved out of "every
    unreadable builtin LEVEL value takes the FACT" — the value was never a
    question, the marker having been rejected on shape. Do NOT describe this
    ordering as strictly louder or as losing nothing: PY-WL-130 is a
    ``Kind.DEFECT`` and therefore IS suppressible, so a waived PY-WL-130 leaves
    that site with no signal at all, no FACT having been emitted. The ordering is
    justified on noise avoidance plus the shipped SECURE DEFAULT — not on either
    channel dominating the other. Under ``trust_suppressions=False``, ``run_scan``
    rebuilds ``gate_population_findings`` with an empty ``Baseline``, an empty
    ``WaiverSet`` and ``judged=None``, so a waived or baselined PY-WL-130 still
    trips ``--fail-on``; the site loses its signal only under an explicit
    ``--trust-suppressions`` operator decision (spec rev 9 §4.2.1).

    The drop-coverage matrix (tests/grammar/test_drop_coverage_matrix.py) pins
    the full partition.
    """
    if not isinstance(deco, ast.Call):
        if call_form is MarkerCallForm.CALL_ONLY:
            return (("<bare>", "call_required"),)
        return ()
    if call_form is MarkerCallForm.BARE_ONLY:
        # Return before inspecting args so @external_boundary() and
        # @external_boundary(**{}) are rejected for the same root reason.
        return (("<call>", "call_not_allowed"),)
    out: list[tuple[str, str]] = []
    # Phase 2 (positional). Split by offender so the two forms are distinguishable in
    # properties and fingerprints while the pinned REASON vocabulary is untouched.
    if any(not isinstance(a, ast.Starred) for a in deco.args):
        out.append(("<positional>", "positional_args"))
    if any(isinstance(a, ast.Starred) for a in deco.args):
        # ``*ARGS`` may bind ZERO arguments — verified 2026-08-09: trusted(*()) executes
        # cleanly and returns the decorator. So this is NOT a proved runtime failure;
        # the argument list is simply outside the keyword-only declaration grammar and
        # Wardline cannot prove what it supplies. Emitted AFTER the plain-positional
        # offence so the canonical phase order stays deterministic.
        out.append(("<*args>", "positional_args"))
    extracted = extract_keywords(deco)
    out.extend(extracted.offences)
    supplied: set[str] = set()
    for name, _value in extracted.items:
        if name not in declared:
            out.append((name, "undeclared_kwarg"))
            continue
        if name in supplied:
            # Emit at the second occurrence; later repeats emit again in source
            # order and receive distinct offence ordinals.
            out.append((name, "duplicate_kwarg"))
        else:
            supplied.add(name)
    # Suppression must cover EVERY unreadable-splat-class offence: a dynamic mapping
    # OR a computed literal key may be exactly the required name. Both are
    # ``unreadable_splat`` by construction (see extract_keywords) — keep it that way.
    if not any(reason == "unreadable_splat" for _name, reason in out):
        for arg in sorted(required - supplied):
            out.append((arg, "missing_kwarg"))
    return tuple(out)
```

The implementation of `extract_keywords` must preserve AST/source order, normalize one literal dict to its final key/value pairs before appending them, and never evaluate Python. A nested dict expansion has `key is None` and therefore yields `unreadable_splat`. A literal dict with a computed key yields `unreadable_splat` for the same reason: `@trusted(**{'lev' + 'el': 'ASSURED'})` runs cleanly, and only `invalid_splat_key`'s non-string constant proves a `TypeError`. Its output is passed both to the validator and the level reader so `@trusted(**{"level": "ASURED"})` reaches PY-WL-114, not PY-WL-130.

Add a **multi-phase offence test** to the new `tests/unit/scanner/test_marker_reader_agreement.py` — written at **Step 5**, which is where that file is created — pinning the COMPLETE offence tuple for one call carrying a positional argument, an unreadable splat AND an undeclared direct keyword: `@trusted('ASSURED', audit=True, **KW)` read with `call_form=MarkerCallForm.BARE_OR_CALL`, `declared=frozenset({"level"})`, `required=frozenset()`. The expected tuple is exactly

```python
(
    ("<positional>", "positional_args"),
    ("<**splat>", "unreadable_splat"),
    ("audit", "undeclared_kwarg"),
)
```

**Read that order off the phase list in the docstring above, never off the source order of the call.** Extraction offences are emitted by `out.extend(extracted.offences)` BEFORE the keyword-classification loop, so the splat lands at index 1 and the undeclared keyword at index 2 even though `audit=True` is written first — the one ordering an implementer reconstructing the tuple from the call text will get backwards. `SHAPE_CASES` varies one phase at a time and carries no multi-phase row, which is why this pin is separate. It makes the canonical phase order a compatibility contract rather than an incidental loop order.

**The matching PY-WL-130 `offence_ordinal` fingerprint pin is NOT owed at this task and must not be attempted here** — the rule does not exist until Task 6 (`grep -rhoE "PY-WL-1[0-9]{2}" src/` tops out at PY-WL-126) and this task's Files list carries no PY-WL-130 rule or test path, so the per-task path gate forbids it. It lands as `test_multi_offence_call_pins_the_canonical_phase_order` at **Task 6 Step 1**, over this same call.

Do not move `is_builtin_decorator_fqn` body-identically: use this root-specific export table:

```python
def is_builtin_decorator_fqn(fqn: str, canonical_name: str, module_prefix: str) -> bool:
    exports = {f"{module_prefix}.{canonical_name}"}
    if module_prefix == VOCAB_PREFIX:
        exports.add(f"{module_prefix}.trust.{canonical_name}")
    return fqn in exports
```

`wardline.decorators` therefore accepts its real implementation export; `weft_markers` accepts only its direct export. Reverse the existing `test_builtin_decorator_accepts_weft_markers_implementation_module_export` to assert `weft_markers.trust.<name>` does not seed, and add corresponding PY-WL-110/114 silence pins.

- [ ] **Step 2: Rewire `decorator_provider.py`.** Delete the moved definitions; add:

```python
from wardline.scanner.marker_reader import (
    VOCAB_PREFIX as _VOCAB_PREFIX,
    WEFT_MARKERS_PREFIX as _WEFT_MARKERS_PREFIX,
    is_builtin_decorator_fqn as _is_builtin_decorator_fqn,
    level_token as _level_token,
    resolve_decorator_fqn as _resolve_decorator_fqn,
    shadowed_builtin_roots as _shadowed_builtin_roots,
)
```

Keep `vocabulary_star_exports`, the fingerprint/identity helpers, the existing private `_read_level`, and the provider class in place. Task 4 removes incidental legacy fixture noise and Task 5 imports the shared `read_level` and deletes the private reader atomically; no intermediate commit may change seeding without the Task 5 cache/version gate.

**Resolving the retained `_read_level` against the re-cut `level_token` — three constraints held simultaneously, decided here rather than left to the implementer.** The surviving private `_read_level` calls `_level_token(values[0], alias_map)` two-positionally and therefore does NOT compile against the re-cut signature; form-5 resolution must stay INERT until Task 5's cache/version gate, since this step's own final clause forbids changing seeding in an intermediate commit; and no default may be added to the new parameters to make the legacy caller compile, which spec rev 6 §4.2.1 forbids by name. **The resolution is an explicitly-passed inert census — not a change to the SHARED reader's signature, and not a deletion moved forward** (moving the deletion here would drag the `"sp1g"` → `"sp1h"` `_RESOLVER_VERSION` bump out of Task 5, where the Global Constraints place it). **The provider-private `_read_level` is a different function and its OWN signature must change; this is stated rather than left to be discovered as two `NameError`s.** Verified in source: `_read_level` is a MODULE-LEVEL function (`decorator_provider.py:146-154`) whose keyword-only parameters are `allowed`, `default`, `alias_map`, `ignored_args` — neither `shadowed_roots` nor `bt` is in its scope. `shadowed_roots` is a parameter of the METHOD `_match` (`:363-367`, sourced from `taint_for`), and `bt` is `_match`'s loop variable (`:390`). So **extend `_read_level`'s keyword-only parameter list with `shadowed_roots: frozenset[str]` and `builtin: bool`, both REQUIRED and carrying NO default, placed BEFORE the existing defaulted `ignored_args`**, and re-cut its **sole** call site — `:405`, inside `_match` — to pass `shadowed_roots=shadowed_roots, builtin=bt.builtin` from that method's scope. Both edits land in `decorator_provider.py`, already on this task's Files list, and Task 5 Step 3 deletes the whole function, so the two parameters are short-lived by construction. Do **not** default them to avoid touching the call site: that is the defaulted-empty affordance spec §4.2.1 forbids, in the same paragraph that forbids the two wrong repairs named below. The rule-side twin in Step 3 needs no equivalent change — `shadowed_roots` (`invalid_decorator_level.py:136`) and `entity.node` (`:145`) are both already in `check`'s scope. Re-cut the call inside `_read_level` to:

```python
        token = _level_token(
            values[0],
            alias_map,
            # PRESENT but empty: no bindings, not poisoned, no eligible reference
            # sites — so form 5 resolves nothing and seeding is byte-identical to
            # today, while the reader still raises on a genuine plumbing defect.
            # Constructed INLINE, deliberately: the engine floor ships no inert
            # census constant, because a public one is the defaulted-empty
            # affordance spec rev 6 §4.2.1 forbids. Replaced by the real
            # per-module census when the census task lands; this call site and
            # PY-WL-114's in Step 3 are the ONLY two, and both are rewritten there.
            census=ModuleCensus(values={}, poisoned=False, reference_sites=frozenset()),
            # ``_match`` holds no entity node today (verified in source), so the
            # provider path cannot present a reference site until Task 5 threads
            # ``entity.node`` down. Not a permanent option.
            reference_site=None,
            # BOTH of these are ``_read_level``'s OWN new parameters, forwarded —
            # not names captured from an enclosing scope. ``bt`` never enters this
            # function; it is the ``:405`` CALL SITE, inside ``_match``, that reads
            # ``bt.builtin`` and passes it in.
            shadowed_roots=shadowed_roots,
            builtin=builtin,
        )
```

Passing the real `bt.builtin` in at the `:405` call site is not cosmetic: hardcoding `True` would put custom packs on the builtin arm and break the released custom contract this task must keep green. `shadowed_roots` is already computed in `taint_for` and threaded into `_match`; thread it **one hop further** — into `_read_level` via the required parameter added above — rather than recomputing it or substituting `frozenset()`. Both names in the snippet above are `_read_level`'s own parameters; neither is captured from an enclosing scope, and `bt` never enters that function. Add `ModuleCensus` to the Step 2 import block: it is a CLASS, so ruff's isort (`order-by-type`, the default) sorts it ahead of every lowercase function name — it goes after `WEFT_MARKERS_PREFIX as _WEFT_MARKERS_PREFIX` and before `is_builtin_decorator_fqn as _is_builtin_decorator_fqn`, not alphabetically among the functions.

- [ ] **Step 3: Unify PY-WL-114 onto the shared reader.** In `src/wardline/scanner/rules/invalid_decorator_level.py`: delete the local `_dotted_name` (:63-70), `_level_token` (:73-81), `_resolve_decorator_fqn` (:84-94). Replace the provider-private import at `:20` with:

```python
from wardline.scanner.marker_reader import (
    # ``ModuleCensus`` FIRST, not in alphabetical position among the functions:
    # ruff's isort runs with ``order-by-type`` and sorts classes ahead of lowercase
    # names. It is imported because this step's own ``level_token`` call below
    # constructs one; without it that call is a NameError on the first level read.
    ModuleCensus,
    alias_map_for_qualname,
    call_shape_offences,
    extract_keywords,
    is_builtin_decorator_fqn as _is_builtin_decorator_fqn,
    level_token as _level_token,
    resolve_decorator_fqn as _resolve_decorator_fqn,
    shadowed_builtin_roots as _shadowed_builtin_roots,
)
```

Import `REGISTRY` from `wardline.core.registry`. Replace the hand-written keyword loop with `extract_keywords`, then call the shared `level_token` — with all four new keywords supplied explicitly: `reference_site=entity.node` (the rule already iterates `entity.node.decorator_list`, so it holds the decorated statement and can PRESENT a site even though it cannot CLASSIFY one), `shadowed_roots=shadowed_roots` (already computed in `check`), `builtin=True` (PY-WL-114 polices builtin level-bearing markers only), and `census=ModuleCensus(values={}, poisoned=False, reference_sites=frozenset())` — the same explicitly-passed inert census as Step 2, with the same comment, for the same reason: the rule side holds neither the module AST nor the star-export map and therefore literally cannot build one, and this call is replaced by **Task 3 Step 4(c)**, which swaps it for `context.module_censuses.get(mod_name)` — addressed by the longest owning module `check` already computes at `invalid_decorator_level.py:140-143` — with `src/wardline/scanner/rules/invalid_decorator_level.py` on that task's Files list. Step 2's inert census, the ONLY other one, is **not** Task 3's: it dies with the provider-private `_read_level` that **Task 5 Step 3** deletes, on that task's own Files list. Two placeholders, two named owning steps, both staged; neither is left to "the census task". Perform registry-owned call-shape validation first: if a marker is malformed, PY-WL-114 goes silent on it from this commit onward — the shape verdict is decided before any level is read. **The rule that will own that shape does not exist yet, and this step does not assert a channel it cannot see:** `PY-WL-130` is created by **Task 6** (`grep -rhoE "PY-WL-1[0-9]{2}" src/` tops out at PY-WL-126 at this commit, as Task 2's own PY-WL-130 fingerprint split already records). Announce the consequence here rather than let it be discovered: **between this task and Task 6's green, a builtin marker that is BOTH shape-malformed AND carries a readable-but-invalid token — `@trusted(level='ASURED', audit=True)`, the discriminating shape, on which shipped PY-WL-114 fires today — has no rule-side channel at all.** The window is intra-plan and pre-release, the released reader already drops that seed (`decorator_provider.py:165-186`), and Task 6 closes it with `test_shape_offence_with_invalid_token_is_pywl130_only`, which pins the hand-off in both directions. It is **not** a third deliberate carried red — no test goes red inside it — so Global Constraints' "exactly two" stands unamended. **Behaviour delta (deliberate, three directions, all pinned in Step 5):** (a) an aliased genuine `TaintState` typo now fires; (b) a foreign `*.TaintState` receiver is now silent; (c) a readable typo inside a literal splat, such as `@trusted(**{"level": "ASURED"})`, now fires PY-WL-114.

**APPEND one entry to `METADATA.examples_violation`** in `src/wardline/scanner/rules/invalid_decorator_level.py` — the delta-(a) case, and the receiver-side sibling of that tuple's existing third entry at `invalid_decorator_level.py:45-51`, which aliases the DECORATOR (`trusted as t`) where this one aliases the `TaintState` RECEIVER:

```python
        # An aliased genuine TaintState with a typo: the provider reads it (alias-
        # resolved) and drops the seed, so the rule must fire (shared reader, P9).
        "from wardline.core.taints import TaintState as T\n@trusted(level=T.ASURED)\ndef f(p):\n    return p",
```

and `METADATA.examples_clean` — **two edits, both in this step, both in `src/wardline/scanner/rules/invalid_decorator_level.py`** (already on this task's Files list, and both must appear in the task's explicit staged-path list):

**(a) DELETE the existing third entry outright.** It is live at `invalid_decorator_level.py:55` as `"@trusted(level=cfg.LEVEL)\ndef h(p):\n    return p"`. Delete it — do not re-annotate it, do not replace it. `cfg.LEVEL` is a dotted `Attribute`, held out of form 5 by design, so under spec rev 6 it is an unreadable builtin LEVEL value that takes `WLN-ENGINE-UNREADABLE-MARKER-VALUE`. A `Severity.NONE` FACT does not convert a fail-open construct into a legitimate clean exemplar; the rule's own gate stays green either way, and what must not survive is a SHIPPED exemplar teaching that an unreadable level value is exemplary. This is the same trap this plan removed one rule over, and it must not re-form here.

**(b) APPEND NOTHING.** In particular do NOT add a `myconfig.TaintState.ASURED` clean entry: its receiver does not alias-resolve to the exact known export, so it is likewise an unreadable builtin LEVEL value on the residual FACT channel, and shipping it as a clean exemplar re-forms the trap (a) removes. Pin the foreign-receiver silence property as a UNIT ASSERTION in `tests/unit/scanner/rules/test_invalid_decorator_level.py` instead — `import myconfig` with `@trusted(level=myconfig.TaintState.ASURED)` emits no PY-WL-114 — which proves the same behaviour without shipping an exemplar.

Neither deletion is forced by a failing test: `tests/unit/scanner/rules/test_rule_examples_meta.py` filters to `Kind.DEFECT`, so a `Severity.NONE` FACT reds nothing there. The obligation to add an all-rules assertion that no `examples_clean` snippet emits `WLN-ENGINE-UNREADABLE-MARKER-VALUE` belongs to the task that ships that FACT — **Task 8, Step 8**, whose Files list carries `tests/unit/scanner/rules/test_rule_examples_meta.py` for exactly this — and is recorded there, not here.

Check `tests/unit/scanner/rules/test_invalid_decorator_level.py` and `tests/unit/scanner/rules/test_invalid_decorator_level_recognizer.py` for pins of the OLD textual behaviour (`grep -n "TaintState" tests/unit/scanner/rules/test_invalid_decorator_level*.py`); update any case asserting a fire on a foreign `*.TaintState` receiver to assert silence, and any case asserting silence on an aliased genuine `TaintState` typo to assert a fire. Measured 2026-08-10, that `grep` returns **no hits in either file**, so an empty diff on the recognizer file is the expected outcome and not a missed step; run the sweep anyway, because the pins are what execution-time drift would surface. **In the same sweep, re-label — do NOT delete — the `@trusted(level=cfg.LEVEL)` `clean_dynamic` case at `tests/unit/scanner/rules/test_invalid_decorator_level.py:93`.** It is the test-side twin of the shipped exemplar (a) deletes, and it does **not** red: `cfg` never alias-resolves to the exact known `TaintState` export, so PY-WL-114 is correctly silent there at this commit and after Task 8. That is precisely why it needs a deliberate edit rather than a failing test to force one — left inside a fixture whose functions are named `clean_*`, it goes on teaching that an unreadable builtin LEVEL value is *clean*, which is the trap (a) removes. Keep the case and its zero-findings assertion, rename the fixture's `clean_dynamic` function to `unreadable_dynamic`, and comment that PY-WL-114's silence there is **correct** — the value is unreadable, not clean — and that `WLN-ENGINE-UNREADABLE-MARKER-VALUE` (Task 8) is the channel that speaks for it.

- [ ] **Step 4: Unify PY-WL-110 onto the shared module.** In `src/wardline/scanner/rules/contradictory_trust.py`: delete the local `_dotted_name` (:59-65) and `_resolve_decorator_fqn` (:68-75); replace the provider-private import at `:30` with:

```python
from wardline.scanner.marker_reader import (
    alias_map_for_qualname,
    is_builtin_decorator_fqn as _is_builtin_decorator_fqn,
    resolve_decorator_fqn as _resolve_decorator_fqn,
    shadowed_builtin_roots,
)
```

`_marker_canonical_name` keeps its exact-export logic, now calling the shared helpers. Move the repeated longest-owning-module alias lookup used by PY-WL-110/PY-WL-114 into `alias_map_for_qualname`, and use it in both rules and PY-WL-130. PY-WL-110 must receive `shadowed_builtin_roots(project_modules)` and filter each candidate by that marker's own import root. Do not use a global "any shadow disables all roots" switch: a project module named `wardline` must not suppress a genuine `weft_markers` import, and a project module named `weft_markers` must not suppress a genuine `wardline.decorators` import. Put both direction tests in `tests/unit/scanner/rules/test_contradictory_trust.py`. Exact accepted exports are direct imports from `wardline.decorators`, `wardline.decorators.trust`, and direct `weft_markers`; there is no `weft_markers.trust` export.

- [ ] **Step 5: Write the agreement tests** — `tests/unit/scanner/test_marker_reader_agreement.py`:

```python
"""P9 — one marker-reading grammar: the rule-side reader IS the provider-side reader."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from wardline.core.registry import MarkerCallForm
from wardline.core.run import run_scan
from wardline.core.taints import TaintState
from wardline.scanner.marker_reader import (
    CensusBinding,
    LevelVerdict,
    ModuleCensus,
    alias_map_for_qualname,
    call_shape_offences,
    level_token,
    read_level,
)

# A PRESENT but EMPTY census: no bindings, not poisoned, no eligible reference
# sites. Test-local on purpose — the engine floor ships no such constant, because a
# public inert census is the defaulted-empty affordance spec rev 6 §4.2.1 forbids.
_EMPTY_CENSUS = ModuleCensus(values={}, poisoned=False, reference_sites=frozenset())

CASES = [
    ("'ASSURED'", {}, "ASSURED"),
    ("TaintState.ASSURED", {"TaintState": "wardline.core.taints.TaintState"}, "ASSURED"),
    ("taints.TaintState.ASSURED", {"taints": "wardline.core.taints"}, "ASSURED"),
    ("T.ASSURED", {"T": "wardline.core.taints.TaintState"}, "ASSURED"),  # aliased import
    # Foreign/re-exported TaintState: NOT the exact known export — unreadable.
    ("shim.TaintState.ASSURED", {"shim": "myapp.shim"}, None),
    ("myconfig.TaintState.ASURED", {"myconfig": "myconfig"}, None),
    # A bare Name against an EMPTY census is form 5's UNBOUND case — NOT a blanket
    # refusal of bare names. Rev 6 admits form 5; FORM5_CASES below pins it.
    ("LEVEL", {}, None),
    ("get_level()", {}, None),
    ("f'{x}'", {}, None),
    ("cfg.ASSURED", {"cfg": "myapp.cfg"}, None),
]


@pytest.mark.parametrize(("expr", "alias_map", "expected"), CASES)
def test_level_token_is_the_single_reader(expr: str, alias_map: dict, expected: str | None) -> None:
    value = ast.parse(expr, mode="eval").body
    assert level_token(
        value,
        alias_map,
        census=_EMPTY_CENSUS,
        reference_site=None,
        shadowed_roots=frozenset(),
        builtin=True,
    ) == expected


# --- P3 form 5: the value-reference verdicts, at reader level ----------------------
# SUPPLEMENTARY UNIT CHECK ONLY. The census here is HAND-BUILT, which spec rev 6
# §4.2.1 refuses as evidence for P9 — P9's property is that both callers agree when
# driven through the analyser's OWN construction path. See the P9 note after this
# step for where that half lands. What this table pins is the READER's verdict per
# case, so a one-sided implementation of any single case is caught at unit level.


def _decorated_def(tree: ast.Module) -> ast.stmt:
    """The def/async def carrying the marker, wherever in the module it sits."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.decorator_list:
            return node
    raise AssertionError("fixture has no decorated def")


def _level_value(tree: ast.Module) -> ast.expr:
    # BOTH builtin LEVEL keywords, not just ``level=``. The mechanism is argument-name-
    # agnostic (``level_token`` never sees the argument name), so ``to_level=`` must be
    # exercised POSITIVELY or a later narrowing of form 5 to ``@trusted`` ships green —
    # spec :83's "so no second frozen marker is left behind".
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in {"level", "to_level"}:
            return node.value
    raise AssertionError("fixture has no level=/to_level= keyword")


_BOUND = CensusBinding(token="ASSURED", unreadable_reason=None, line=1)
_TWICE = CensusBinding(token=None, unreadable_reason="bound more than once in module scope", line=1)
_GLOBAL = CensusBinding(token=None, unreadable_reason="declared global in this module", line=1)
# The LEXICAL-PRECEDENCE counterexample: a qualifying, perfectly resolvable binding whose
# LINE falls AFTER the decorated ``def``'s. Everything else about it reads — only form 5's
# fifth conjunct refuses it (spec §4.2.1: "the binding must precede the decorated ``def``/
# ``async def`` in source order"). Line 4 is _AFTER's REAL binding line; its ``def`` is at
# line 2 (measured, CPython 3.13.1: a decorated FunctionDef's ``lineno`` is the ``def``
# line, decorators excluded).
_LATE = CensusBinding(token="ASSURED", unreadable_reason=None, line=4)

_TOP = "_SVC_LEVEL = 'ASSURED'\n@trusted(level=_SVC_LEVEL)\ndef f(p):\n    return p\n"
# The OTHER builtin LEVEL keyword. ``level_token`` never sees the argument name, so this
# fixture is a RECEIPT that form 5 is argument-name-agnostic, not a second mechanism —
# without it a later narrowing of form 5 to ``@trusted`` ships green (spec :83).
_TOP_TB = "_SVC_LEVEL = 'ASSURED'\n@trust_boundary(to_level=_SVC_LEVEL)\ndef f(p):\n    return p\n"
# Binding placed AFTER the decorated ``def``: the ``def`` is at line 2, the binding line 4.
_AFTER = "@trusted(level=_SVC_LEVEL)\ndef f(p):\n    return p\n_SVC_LEVEL = 'ASSURED'\n"
_METHOD = (
    "_SVC_LEVEL = 'ASSURED'\nclass C:\n    @trusted(level=_SVC_LEVEL)\n"
    "    def f(self, p):\n        return p\n"
)
_COND = (
    "_SVC_LEVEL = 'ASSURED'\nif TYPE_CHECKING:\n    @trusted(level=_SVC_LEVEL)\n"
    "    def f(p):\n        return p\n"
)

# (label, module source, census values, poisoned, reference site eligible, builtin,
#  expected token). Spec rev 6 §4.2.1's EIGHT mandated cases FIRST, in its own order,
#  FOLLOWED BY the rows this plan adds. The eight are a spec MINIMUM, never a maximum:
#  append any further row BELOW the added block rather than re-cutting either group.
FORM5_CASES = [
    ("bound", _TOP, {"_SVC_LEVEL": _BOUND}, False, True, True, "ASSURED"),
    ("unbound", _TOP, {}, False, True, True, None),
    ("method reference site", _METHOD, {"_SVC_LEVEL": _BOUND}, False, False, True, None),
    ("conditional def reference site", _COND, {"_SVC_LEVEL": _BOUND}, False, False, True, None),
    ("two-occurrence census", _TOP, {"_SVC_LEVEL": _TWICE}, False, True, True, None),
    ("global-declared name", _TOP, {"_SVC_LEVEL": _GLOBAL}, False, True, True, None),
    ("star-import poisoned module", _TOP, {"_SVC_LEVEL": _BOUND}, True, True, True, None),
    ("custom BoundaryType LEVEL arg", _TOP, {"_SVC_LEVEL": _BOUND}, False, True, False, None),
    # --- rows this plan ADDS beyond spec §4.2.1's eight ------------------------------
    # LEXICAL PRECEDENCE. The census entry resolves and the reference site IS eligible;
    # the only thing refusing this row is ``_LATE.line`` (4) failing to be strictly less
    # than the decorated ``def``'s ``lineno`` (2). A reader built without the fifth
    # conjunct returns "ASSURED" here — a MINTED SEED where spec :133 requires
    # UNREADABLE + FACT, which is the seed-minting direction and the dangerous one.
    ("binding after the def", _AFTER, {"_SVC_LEVEL": _LATE}, False, True, True, None),
    # POSITIVE ``to_level=``: form 5 RESOLVES on @trust_boundary exactly as on @trusted.
    ("to_level resolving", _TOP_TB, {"_SVC_LEVEL": _BOUND}, False, True, True, "ASSURED"),
]


@pytest.mark.parametrize(
    ("label", "src", "values", "poisoned", "eligible", "builtin", "expected"),
    FORM5_CASES,
    ids=[case[0] for case in FORM5_CASES],
)
def test_level_token_form5_verdicts(label, src, values, poisoned, eligible, builtin, expected) -> None:
    # The reference-site set is what decides the method and conditional-def rows —
    # NOT the census's value entries, which resolve perfectly well in both. The
    # census task pins that the BUILDER actually produces this set (a def nested in a
    # module-level ``if`` is ABSENT from it); without that pin this table would beg
    # its own question.
    tree = ast.parse(src)
    site = _decorated_def(tree)
    census = ModuleCensus(
        values=values,
        poisoned=poisoned,
        reference_sites=frozenset({site}) if eligible else frozenset(),
    )
    assert level_token(
        _level_value(tree),
        {},
        census=census,
        reference_site=site,
        shadowed_roots=frozenset(),
        builtin=builtin,
    ) == expected


def test_absent_census_on_a_bare_name_is_a_plumbing_defect() -> None:
    # An ABSENT census and an EMPTY one are DIFFERENT inputs (spec rev 6 §4.2.1).
    # Empty is an ordinary unreadable; absent means no census was built for this
    # module at all — a plumbing defect, which must never be a quiet None. Rule side
    # lands on per-rule isolation as a WLN-ENGINE-RULE-FAILED ERROR DEFECT. On the
    # PROVIDER side the raise does NOT propagate out of the parse pass: verified in
    # source, the parse loop's bare ``except Exception`` per-file isolation handler
    # (pipeline.py:221) catches it, emits a WLN-ENGINE-FILE-FAILED ERROR DEFECT naming
    # the file, and continues with that file dropped from the analysed set — the
    # SyntaxError/UnicodeDecodeError/OSError guard at pipeline.py:182 is a DIFFERENT
    # handler and never sees it. Either way the plumbing defect lands as a gate-eligible
    # ERROR on the unsuppressed population, so a baseline row or waiver ANNOTATES it
    # without clearing the secure gate absent ``--trust-suppressions``. A scan that
    # reports the failure loudly is acceptable here; a scan that returns green is the
    # failure this contract exists to forbid.
    tree = ast.parse(_TOP)
    with pytest.raises(ValueError):
        level_token(
            _level_value(tree),
            {},
            census=None,
            reference_site=_decorated_def(tree),
            shadowed_roots=frozenset(),
            builtin=True,
        )


def test_absent_census_is_harmless_for_a_non_name_value() -> None:
    # The raise triggers on what the reader was HANDED — a bare Name in a LEVEL slot —
    # never on whether some other component ran. A str literal reads with no census,
    # which is what makes a direct construction or a test that never presents a bare
    # Name safe.
    tree = ast.parse("@trusted(level='ASSURED')\ndef f(p):\n    return p\n")
    assert level_token(
        _level_value(tree),
        {},
        census=None,
        reference_site=_decorated_def(tree),
        shadowed_roots=frozenset(),
        builtin=True,
    ) == "ASSURED"


def test_absent_census_on_a_custom_marker_bare_name_does_not_raise() -> None:
    # The raise is BUILTIN-ONLY, and this row pins the cell the unconditional reading
    # gets wrong. Form 5 is builtin-only (spec :119), so on a custom ``BoundaryType`` no
    # census could change the verdict: a bare ``Name`` is an ordinary unreadable ``None``
    # and the released WLN-ENGINE-UNPROVABLE-BOUNDARY + UNKNOWN_RAW contract is untouched.
    # Reading the raise unconditionally instead reds three shipped custom-boundary cases
    # in tests/grammar/test_provider_loop.py (:48, :57, :72) at Task 5's commit.
    tree = ast.parse(_TOP)
    assert (
        level_token(
            _level_value(tree),
            {},
            census=None,
            reference_site=_decorated_def(tree),
            shadowed_roots=frozenset(),
            builtin=False,
        )
        is None
    )


def test_shadowed_root_refuses_a_direct_form2_level_value() -> None:
    # ``shadowed_roots`` must reach the ATTRIBUTE branch of the reader. Every other row
    # in this module passes ``frozenset()``, so without this one the parameter ships
    # UNREAD and Task 3 Step 5's test_shadowed_root_refusal_is_applied_at_the_census_build
    # has nothing to stand on — and Task 3 declares marker_reader.py NOT modified, so it
    # could not repair the reader from there. This is form 2 written DIRECTLY in the LEVEL
    # slot (spec §4.2.1's pre-existing gap), NOT form 5: form 5's own right-hand-side
    # shadowed-root refusal is applied at the census build and never re-derived here.
    tree = ast.parse("@trusted(level=TaintState.ASSURED)\ndef f(p):\n    return p\n")
    alias_map = {"TaintState": "wardline.core.taints.TaintState"}
    assert (
        level_token(
            _level_value(tree),
            alias_map,
            census=_EMPTY_CENSUS,
            reference_site=_decorated_def(tree),
            shadowed_roots=frozenset({"wardline"}),
            builtin=True,
        )
        is None
    )
    # The SAME value with no shadow reads normally, so this row pins the SHADOW and not
    # the value shape.
    assert (
        level_token(
            _level_value(tree),
            alias_map,
            census=_EMPTY_CENSUS,
            reference_site=_decorated_def(tree),
            shadowed_roots=frozenset(),
            builtin=True,
        )
        == "ASSURED"
    )


_DECLARED = frozenset({"level"})
_REQUIRED_NONE: frozenset[str] = frozenset()
_TB_DECLARED = frozenset({"to_level"})
_TB_REQUIRED = frozenset({"to_level"})

SHAPE_CASES = [
    ("trusted(level='ASSURED')", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, ()),
    ("trusted", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, ()),
    ("external_boundary()", MarkerCallForm.BARE_ONLY, frozenset(), frozenset(), (("<call>", "call_not_allowed"),)),
    ("external_boundary(**{})", MarkerCallForm.BARE_ONLY, frozenset(), frozenset(), (("<call>", "call_not_allowed"),)),
    ("trust_boundary", MarkerCallForm.CALL_ONLY, _TB_DECLARED, _TB_REQUIRED, (("<bare>", "call_required"),)),
    ("trusted('ASSURED')", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE,
     (("<positional>", "positional_args"),)),
    ("trusted(level='ASSURED', audit=True)", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE,
     (("audit", "undeclared_kwarg"),)),
    ("trusted(**KW)", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, (("<**splat>", "unreadable_splat"),)),
    ("trusted(**{1: 'ASSURED'})", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE,
     (("<**splat>", "invalid_splat_key"),)),
    (
        "trusted(level='A', **{'level': 'B'})",
        MarkerCallForm.BARE_OR_CALL,
        _DECLARED,
        _REQUIRED_NONE,
        (("level", "duplicate_kwarg"),),
    ),
    # Within one literal dict, Python constructs the dict last-value-wins.
    ("trusted(**{'level': 'A', 'level': 'B'})", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, ()),
    ("trust_boundary()", MarkerCallForm.CALL_ONLY, _TB_DECLARED, _TB_REQUIRED, (("to_level", "missing_kwarg"),)),
    ("trust_boundary(to_level='ASSURED')", MarkerCallForm.CALL_ONLY, _TB_DECLARED, _TB_REQUIRED, ()),
    ("trusted(audit_fn)", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE,
     (("<positional>", "positional_args"),)),
    ("trusted(*ARGS)", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, (("<*args>", "positional_args"),)),
    ("trusted(x, *ARGS)", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE,
     (("<positional>", "positional_args"), ("<*args>", "positional_args"))),
    ("trusted(**{'lev' + 'el': 'ASSURED'})", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE,
     (("<**splat>", "unreadable_splat"),)),
    # A computed key may BE the required name — missing_kwarg must stay suppressed.
    ("trust_boundary(**{'to_' + 'level': 'ASSURED'})", MarkerCallForm.CALL_ONLY, _TB_DECLARED, _TB_REQUIRED,
     (("<**splat>", "unreadable_splat"),)),
    # A VALUE is never a shape offence, whichever way it later reads: this validator
    # looks at no value at all. Under rev 6 ``CFG`` RESOLVES when P3 form 5 is
    # satisfied in full, while ``get_level()`` stays unreadable and takes the
    # residual FACT — and BOTH return the empty offence tuple here.
    ("trusted(level=CFG)", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, ()),
    ("trusted(level=get_level())", MarkerCallForm.BARE_OR_CALL, _DECLARED, _REQUIRED_NONE, ()),
]


@pytest.mark.parametrize(("src", "call_form", "declared", "required", "expected"), SHAPE_CASES)
def test_call_shape_offences_table(src: str, call_form, declared, required, expected) -> None:
    deco = ast.parse(f"@{src}\ndef f(): ...").body[0].decorator_list[0]
    assert call_shape_offences(
        deco, call_form=call_form, declared=declared, required=required
    ) == expected


def test_rule_and_provider_agree_on_reexported_taintstate(tmp_path: Path) -> None:
    # A typo'd level behind a re-export: the provider cannot read it (no seed) and
    # PY-WL-114 must not claim to have read it either — consistent silence, pinned.
    src = (
        "from myapp.shim import TaintState\n"
        "from wardline.decorators import trusted\n"
        "@trusted(level=TaintState.ASURED)\n"
        "def f(p):\n"
        "    return p\n"
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    result = run_scan(proj)
    assert not [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames  # provider dropped the seed too


def test_rule_and_provider_agree_on_aliased_taintstate_typo(tmp_path: Path) -> None:
    # The FN direction closed: an aliased GENUINE TaintState with a typo is read
    # by the provider (seed drops) — the rule now reads it identically and fires.
    src = (
        "from wardline.core.taints import TaintState as T\n"
        "from wardline.decorators import trusted\n"
        "@trusted(level=T.ASURED)\n"
        "def f(p):\n"
        "    return p\n"
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    result = run_scan(proj)
    assert [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_no_rule_imports_provider_privates() -> None:
    # P9's structural half: rules read markers ONLY through marker_reader.
    import pathlib

    rules_dir = pathlib.Path("src/wardline/scanner/rules")
    offenders = [
        p.name
        for p in rules_dir.glob("*.py")
        if "taint.decorator_provider import" in p.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_alias_map_for_qualname_uses_longest_owner() -> None:
    maps = {"pkg": {"x": "pkg.x"}, "pkg.mod": {"x": "pkg.mod.x"}}
    assert alias_map_for_qualname("pkg.mod.C.method", maps) == maps["pkg.mod"]


def test_alias_map_for_qualname_without_owner_is_empty() -> None:
    assert alias_map_for_qualname("other.f", {"pkg": {"x": "pkg.x"}}) == {}


def test_read_level_accepts_sibling_declared_keywords() -> None:
    # Deliberate widening vs the old provider-private reader (None on ANY
    # keyword other than the one being read): a DECLARED sibling keyword is
    # legal while reading one arg. Observable only for multi-level-arg
    # custom markers; none ship in the builtin grammar. BOTH values here are
    # ``str`` literals, so form 5 never engages — this exercises the sibling
    # rule and NOT the custom form-5 path.
    deco = ast.parse("@m(a='ASSURED', b='ASSURED')\ndef f(): ...").body[0].decorator_list[0]
    read = read_level(
        deco,
        "a",
        declared=frozenset({"a", "b"}),
        allowed=frozenset(TaintState),
        default=None,
        alias_map={},
        census=_EMPTY_CENSUS,
        reference_site=None,
        shadowed_roots=frozenset(),
        builtin=False,
    )
    assert read.verdict is LevelVerdict.RESOLVED
    assert read.level is TaintState.ASSURED
    assert read.unreadable_value is None


def _read(src: str, *, builtin: bool = True):
    deco = ast.parse(f"@{src}\ndef f(): ...").body[0].decorator_list[0]
    return read_level(
        deco,
        "level",
        declared=frozenset({"level"}),
        allowed=frozenset({TaintState.INTEGRAL, TaintState.ASSURED}),
        default=TaintState.INTEGRAL,
        alias_map={},
        census=_EMPTY_CENSUS,
        reference_site=None,
        shadowed_roots=frozenset(),
        builtin=builtin,
    )


def test_read_level_discriminates_rejected_from_unreadable() -> None:
    # spec rev 6 §4.2.1: READS-then-rejects and UNREADABLE must NOT collapse into one
    # bare None. A token READ and then rejected by the allowed check is PY-WL-114's
    # DEFECT and carries NO residual pair, so it never reaches the FACT; a value never
    # read carries the (argument name, ast.unparse(value)) pair the FACT is built from.
    rejected = _read("trusted(level='ASURED')")
    assert rejected.verdict is LevelVerdict.REJECTED
    assert rejected.unreadable_value is None

    unreadable = _read("trusted(level=get_level())")
    assert unreadable.verdict is LevelVerdict.UNREADABLE
    assert unreadable.unreadable_value == ("level", "get_level()")


def test_read_level_never_carries_a_residual_pair_for_a_custom_marker() -> None:
    # The residual channel is BUILTIN-ONLY. A custom BoundaryType's unreadable level
    # keeps WLN-ENGINE-UNPROVABLE-BOUNDARY and an UNKNOWN_RAW seed, and never also the
    # residual FACT — one unreadable value takes exactly one channel. Note also that on
    # the custom side REJECTED and UNREADABLE both take that released path: only the
    # builtin arm distinguishes them.
    custom = _read("sanitized(level=get_level())", builtin=False)
    assert custom.verdict is LevelVerdict.UNREADABLE
    assert custom.unreadable_value is None


@pytest.mark.parametrize("src", ["sanitized('ASSURED')", "sanitized(*ARGS)"])
def test_read_level_refuses_a_positional_argument_on_a_custom_marker(src: str) -> None:
    # The CUSTOM side's only positional guard, and the reason ``read_level`` keeps the
    # released ``deco.args`` check (decorator_provider.py:165-166) rather than delegating
    # to the shape gate. ``call_shape_offences`` is builtin-only by design (spec :105;
    # custom-pack compatibility is a hard gate), so nothing else in the pipeline ever
    # inspects ``deco.args`` for a custom ``BoundaryType``.
    #
    # ``_read`` supplies a NON-None ``default`` (TaintState.INTEGRAL), and that is what
    # makes these two rows discriminate: without the guard both fall through to
    # ``_defaulted()`` and return RESOLVED/INTEGRAL — a trusted seed, minted from a
    # declaration Wardline never read, with no diagnostic on any channel. Every custom
    # ``LevelArg`` in this tree happens to pass ``default=None`` (measured 2026-08-10),
    # and the one file Global Constraints names as a HARD GATE,
    # tests/grammar/test_thirdparty_pack_bridge.py, binds a pack whose BoundaryType
    # declares ``level_args=()`` and therefore never calls this reader at all — so the
    # restored guard moves no in-tree verdict and reds no gate. No shipped test reds if
    # the guard is DROPPED either; wardline's OWN builtins use the
    # defaulted shape (boundary_types.py:108, :125), which is the idiom a pack author
    # copies. Zero reds is the mechanism by which that regression would ship, not
    # evidence that it is hypothetical.
    read = _read(src, builtin=False)
    assert read.verdict is LevelVerdict.UNREADABLE
    assert read.level is None
    assert read.unreadable_value is None
```

**P9 is NOT closed by this task, and this plan does not let it be claimed here.** Everything above is a reader-level unit check over a HAND-BUILT census, which spec rev 6 §4.2.1 explicitly refuses as evidence for P9: the property P9 pins is that BOTH callers agree when driven through the analyser's own construction path, never a hand-built context. That path needs two things this task does not build — the per-module census, built once per module in the parse loop and carried on `SeedContext` / `AnalysisContext`, and `WLN-ENGINE-UNREADABLE-MARKER-VALUE` itself. The agreement half is therefore **specified here and executed by exactly one task — Task 8, at its Step 7** — extending THIS module rather than creating another. Task 8 is the first commit at which BOTH halves the receipt asserts over exist: Task 3's per-module census and `WLN-ENGINE-UNREADABLE-MARKER-VALUE` itself, which the unreadable rows assert the presence of. `tests/unit/scanner/test_marker_reader_agreement.py` is on Task 8's Files list for that reason; Task 3 Step 7 runs the module read-only and writes nothing in it, and no other task may claim a row. **This list is the specification site and is authoritative over the executing step**: if a condition adds a row here, Task 8 Step 7 carries it, and the row count is not frozen in that step's prose.

- `tests/unit/scanner/test_marker_reader_agreement.py::test_form5_agreement` — one `run_scan(tmp_path)` per case over spec §4.2.1's eight **plus the rows this plan adds beyond them**, with the ids of `FORM5_CASES` above (the eight are a spec minimum, never a maximum — extend the list, never re-cut it to keep a count true): **bound** (`_SVC_LEVEL = 'ASSURED'` at module top level, `@trusted(level=_SVC_LEVEL)` on a `def` that is a direct element of the module body); **unbound**; **method / nested-`def` reference site**; **conditionally-defined module-level `def` reference site** (inside `if TYPE_CHECKING:`); **two-occurrence census** (a qualifying top-level binding PLUS a conditional module-scope rebinding); **binding placed AFTER the decorated `def`** (*added beyond the eight* — spec :133's case-table row; the qualifying single binding sits below the `def`, so lexical precedence refuses it and the qualname must be ABSENT from `declared_qualnames` with the residual FACT present. This is the row that reds if the reader's fifth conjunct is missing, and it fails in the seed-minting direction, so it is not optional); a **resolving `to_level=`** case (*added beyond the eight* — `@trust_boundary(to_level=_SVC_LEVEL)` over a qualifying lexically-preceding binding on a module-body `def`, asserting the qualname ENTERS `declared_qualnames` with no FACT and no `PY-WL-114`. The mechanism is argument-name-agnostic, so without a positive `to_level=` row a later narrowing of form 5 to `@trusted` ships green — spec :83); **`global`-declared name**; **star-import-poisoned module**; and a **custom `BoundaryType` LEVEL argument** (the ONE row that is **not** driven by `run_scan` — see the driver carve-out bullet below; it is a mandated row of this list like any other and may not be dropped on the strength of the carve-out).
- Every case asserts on BOTH sides of the same scan, so a one-sided plumbing gap reds rather than passing quietly: the rule-side finding set (`PY-WL-114` and `WLN-ENGINE-UNREADABLE-MARKER-VALUE`, each present or absent) AND `result.context.declared_qualnames` (the provider-side seed). The bound case asserts the qualname IS in `declared_qualnames` with no FACT and no PY-WL-114; every unreadable case asserts it is NOT and the residual FACT IS present; the custom case asserts `WLN-ENGINE-UNPROVABLE-BOUNDARY` with an `UNKNOWN_RAW` seed and the residual FACT **absent** — read off `analyzer.last_context`, not `result.context`, per the driver carve-out immediately below.
- **Driver carve-out — it applies to exactly ONE row, the custom `BoundaryType` LEVEL argument, and that row is still owed.** `run_scan` takes no grammar: its signature (`src/wardline/core/run.py:301-317`) is root, `config_path`, `cache_dir`, `source_root_confinement`, `new_since`, `affected`, `sei_resolver`, `trust_local_packs`, `trusted_packs`, `strict_defaults`, `trust_suppressions`, `skip_suppression`, `lang`, `progress_callback` — and nothing else. The only other route to a custom `BoundaryType` is a config-declared pack, which needs `trust_local_packs=True` **and** an importable pack module, flatly incompatible with "each row its own project whose only source is that row's module". Driven through `run_scan` regardless, `@myproj.trust.sanitized(to_level=...)` matches no loaded `BoundaryType`, so there is no `WLN-ENGINE-UNPROVABLE-BOUNDARY` finding and no `UNKNOWN_RAW` seed to assert against — the row would pass by asserting nothing, which is the green-by-absence failure P9 exists to catch. **Drive this row through `build_analyzer(grammar=default_grammar().extend(boundary_types=(custom,)))` and `analyzer.analyze([f], WardlineConfig(), root=tmp_path)`** — the shipped idiom at `tests/grammar/test_unprovable_boundary.py:35`, and the one Task 8's own `test_custom_boundary_unreadable_level_never_takes_the_residual_fact` already uses ~190 lines before its Step 7. **Three assertion substitutions, named so a verbatim implementer does not write `result.context` against an object that has no `.context`:** the finding set is the list `analyzer.analyze(...)` **returns**, not `result.findings`; the provider-side seed set is `analyzer.last_context.declared_qualnames` (`src/wardline/scanner/analyzer.py:257`, non-`None` after `analyze`), not `result.context.declared_qualnames`; and the `UNKNOWN_RAW` seed is `analyzer.last_context.project_taints[<qualname>]`, the `tests/grammar/test_unprovable_boundary.py:46` idiom. Every other row keeps `run_scan(tmp_path)`, and **a test is never a reason to widen `run_scan`'s signature**. Recorded here so the executing step need not re-derive it: **switching test drivers is NOT the "repair a reader" the executing step's STOP clause forbids.** There is no cross-reader disagreement on this row — both readers agree the custom side is not form 5 — so the carve-out is a harness choice and must not be escalated as a P9 red.
- The last two cases are not optional extras. A star-import poison predicate evaluated in one reader and not the other, and a builtin/custom split drawn differently on each side, both produce a channel that fires once or not at all with nothing to compare against — silent cross-reader disagreement, which is exactly what P9 exists to catch and exactly what a wrong-but-visible answer is not.
- **THE INVALID-TOKEN ROW, beyond spec §4.2.1's eight and beyond the two rows this plan already adds, because none of them can detect the defect P9 exists to catch.** Name it by function, never by ordinal — `FORM5_CASES` above already carries ten, and its own preamble comment — the one declaring the eight "a spec MINIMUM, never a maximum", immediately above the `FORM5_CASES = [` line — keeps the list open-ended, so any ordinal here rots the moment a condition appends. Add `invalid token resolved via form 5`: `_SVC_LEVEL = 'ASURED'` bound once, unconditionally, at module top level, with `@trusted(level=_SVC_LEVEL)` on a `def` that is a direct element of the module body — the **bound** row's shape with an INVALID token in it. One `run_scan(tmp_path)` asserts three things, and **only the first discriminates**, stated here so a later editor cannot "simplify" the row down to the two that pass trivially: (i) **PY-WL-114 FIRES** — the rule-side assertion, and the whole point of the row; (ii) **no** `WLN-ENGINE-UNREADABLE-MARKER-VALUE` is emitted (spec §4.2.1's *READS, then rejects* row); (iii) `svc.f` is **ABSENT** from `result.context.declared_qualnames`, because `TaintState('ASURED')` fails and the seed drops. (ii) and (iii) are provider-side and read identically whatever the rule side does. **Why an INVALID token is the only shape that surfaces a one-sided reader:** on a VALID token the rule side is silent whether it resolved the name or could not read it, so both readers yield the same finding set and nothing reds; only when the resolved token is then REJECTED does resolving-versus-not change the rule's verdict. That is the pair spec §4.2.1 names. Without this row the suite is structurally blind — every one of the eight above passes over a rule side reading an EMPTY census: the **bound** row because an inert reader reads nothing and the row asserts the ABSENCE of a rule-side finding, every unreadable row because it is driven provider-side, and the custom row because it is provider-side too.
- The census task additionally pins that the BUILDER produces the reference-site set `FORM5_CASES` assumes — a `def` nested in a module-level `if` is ABSENT from `census.reference_sites` (spec §4.2.1's newest and least obvious rule). Without that pin the hand-built table begs its own question.

Until those rows are green, **no receipt may record P9 as closed**. This task's `(P9)` title means it establishes the ONE grammar P9 is about — it does not prove the agreement, and the plan's coverage map must carry that distinction rather than mapping P9 to this task alone.

- [ ] **Step 6: Run the affected suites**

Run: `uv run pytest tests/unit/scanner/test_marker_reader_agreement.py tests/unit/scanner/rules/test_invalid_decorator_level.py tests/unit/scanner/rules/test_invalid_decorator_level_recognizer.py tests/unit/scanner/rules/test_contradictory_trust.py tests/unit/scanner/taint/test_decorator_provider.py tests/grammar -q && uv run lint-imports`
Expected: PASS (fix any test that imported the moved privates from `decorator_provider` by pointing it at `marker_reader` — `grep -rn "from wardline.scanner.taint.decorator_provider import" tests/ src/` and update each hit). `lint-imports` proves the layering contracts still hold.

- [ ] **Step 7: Run the full suite** — `uv run pytest -q`. Expected: PASS, zero scan-golden drift.

- [ ] **Step 8: Commit** — `refactor(scanner): shared marker_reader module + call_shape_offences; PY-WL-110/114 unified onto it (S0, P9)`

---

### Task 3: Per-module binding census — type, parse-loop builder, and both context carriers (form 5's single evaluation point)

**Files:**
- Create: `src/wardline/scanner/module_census.py`
- **NOT modified: `src/wardline/scanner/marker_reader.py`.** This task imports from it and changes nothing in it. `ModuleCensus` / `CensusBinding` are Task 2's types and are not re-declared, moved, or renamed, and no second reader primitive is added — see Interfaces.
- Modify: `src/wardline/scanner/pipeline.py` (`ParsedFile` gains the census; one build per module in the parse loop)
- Modify: `src/wardline/scanner/taint/provider.py` (`SeedContext` gains the per-file census)
- Modify: `src/wardline/scanner/context.py` (`AnalysisContext` gains the module→census mapping)
- Modify: `src/wardline/scanner/analyzer.py:631-644` (gather the censuses beside `module_sink_bindings`) and `:1139-1162` (pass them to `AnalysisContext`)
- Modify: `src/wardline/scanner/rules/invalid_decorator_level.py` (**Step 4(c)** — PY-WL-114's `level_token` call stops passing Task 2 Step 3's inert census and reads `context.module_censuses` instead). Staged HERE deliberately: this is the only task whose Files list can carry the path *and* whose commit has a census to read, and the per-task path gate (Global Constraints, :5) makes every other placement unexecutable.
- Modify: `tests/unit/scanner/rules/test_invalid_decorator_level.py` (**Step 4(c)** — the one rule verdict that moves)
- Test: `tests/unit/scanner/test_module_census.py` (new — sibling of the shipped `tests/unit/scanner/test_module_bindings.py`)
- Modify: `tests/unit/scanner/test_pipeline.py` (the census reaches `ParsedFile` and `SeedContext`, built once)
- Modify: `tests/unit/scanner/test_context.py` (the new field's read-only-view pin)
- Modify: `tests/unit/scanner/taint/test_provider_seedcontext.py` (the absent sentinel)

**Interfaces:**
- Consumes: Task 2's `marker_reader` — `ModuleCensus`, `CensusBinding`, `shadowed_builtin_roots`, and the public `level_token`.
- **This task mints no new reader and places no new obligation on Task 2's produced-interface list.** The census build reads right-hand sides through Task 2's public `level_token`, called with an **inline empty census** — the same idiom as Task 2's own two retained call sites. That is not a convenience: it is what makes form 5's **one hop only** rule structural rather than a discipline (spec §4.2.1 — "the right-hand side is another bare name → UNREADABLE"). An empty census resolves no bare `Name`, so a right-hand side that is itself a bare name is refused by construction and no second hop is reachable, whereas a census that called the widened reader with the real census would be a two-hop walk. There is therefore no second base-read primitive to name and **none may be minted**.
- **Direction of the runtime import edge, stated because it is the one thing that could invert a layer.** `marker_reader` DEFINES `ModuleCensus` / `CensusBinding` (Task 2's produced-interface list) and this module defines only the BUILDER, so the runtime edge is one-way — `module_census` → `marker_reader`, never back. Any annotation `marker_reader` ever needs of this module's own names rides `from __future__ import annotations` plus a `TYPE_CHECKING` import: the shape `pyproject.toml`'s import-linter commentary blesses for exactly this direction, and `tests/conformance/test_import_layering.py` excludes `TYPE_CHECKING` edges from its cycle check by design.
- Produces: `build_module_census(...)`; `SeedContext.census`; `AnalysisContext.module_censuses`; `ParsedFile.census`. The census — **not either reader** — owns the star-import poison predicate and the reference-site predicate, so each is evaluated once per module, in one place, and cannot drift between callers (spec §4.2.1). It **carries** the binding line rather than evaluating lexical precedence, because precedence is a fact about the *pair* (binding, reference site) and not a per-module fact; the reader evaluates it.
- **The rule side addresses the census by the longest owning module, not by a naive qualname split.** `AnalysisContext.module_censuses` is keyed by module path, and `qualname.rsplit(".", 1)[0]` yields `svc.C` for the method `svc.C.method` — a **miss**, and a miss is the absent sentinel, so the reader raises `WLN-ENGINE-RULE-FAILED` on legitimate code where correct keying gives census-present → ineligible reference site → `None` → unreadable. That is fail-loud-and-wrong on precisely the method shape spec §4.2.1 spends a paragraph refusing. Task 2 already produces the shipped answer to this identical problem for `alias_maps` — `alias_map_for_qualname` ("one longest-owning-module lookup for all rules") — and the census lookup uses that same longest-owning-module resolution. The **rule-side call site belongs to this task, at Step 4(c)** — the carrier is this task's, the rule already computes the longest-owning-module `mod_name` at `invalid_decorator_level.py:140-143`, and doing the lookup in the commit that keys the carrier is what makes the two impossible to drift apart. The **provider-side** call site is **Task 5 Step 3's**, and it performs no qualname lookup whatsoever: the provider takes its census directly off `SeedContext.census`, which the parse loop filled per file. **Task 2 owns neither call site** — its two inline inert censuses are placeholders, replaced by Step 4(c) here and by Task 5 Step 3 there.
- **This task changes no seeding, and exactly one rule verdict.** It builds and transports the census, and Step 4(c) wires the one reader that exists onto it; nothing consumes it for *seeding* until Task 5's cache/version gate. The single verdict that moves does so in the fail-loud direction: a builtin LEVEL slot holding a bare `Name` that form 5 resolves to an **invalid** token — `_SVC_LEVEL = 'ASURED'` bound once at module top level, read on a module-body `def` — was silently skipped by the inert census and now **fires PY-WL-114**. Measured inert (Global Constraints' value census: zero bare-`Name` level values in the repository or any frozen tree), so it moves no golden and trips no self-scan; what it closes is the rule half of the one-sided widening spec §4.2.1 names as a silent false green. No `_RESOLVER_VERSION` move here (the Global Constraints and spec §4.3 keep that in Task 5), no golden drift, no `SUMMARY_SCHEMA_VERSION` bump.
- **Why this task can follow Task 2 rather than precede it, and the one residual that leaves.** The re-cut reader raises only when asked to resolve a **bare `Name` in a builtin LEVEL slot with no census present at all** (spec §4.2.1's absent-vs-empty split). Spec §4.2.1's measurement records **zero bare-`Name` level values anywhere in the repository**, so at Task 2's own commit that raise is reachable from nothing but the `pytest.raises` row in Task 2 Step 5 — Task 2 is green with the census absent everywhere. From this commit the absence is closed. The residual is that PY-WL-114, wired onto the real census by **Step 4(c) of this task** (at Task 2 it was handed an inert one and could resolve nothing), can resolve form 5 two commits before the provider does; it is **inert by that same measurement**, the window closes at Task 5. Step 7 re-runs the agreement module here, and its reach is stated honestly rather than as a detector: at this commit that module holds only Task 2 Step 5's reader-level rows over **hand-built** censuses, so it reds on a regression in the reader and **not** on a rule side left reading an inert census. `test_form5_agreement` does not exist until the task that owns it — **Task 8**, the first commit at which both the census and `WLN-ENGINE-UNREADABLE-MARKER-VALUE` exist — and the row that actually discriminates a one-sided widening is its **invalid-token row** (specified in Task 2 Step 5's list). Nothing in this task's own suite reds if the rule-side census is never plumbed, so the rule-side rewire must be carried by an owning step rather than by that receipt. Task 2 Step 2's retained private `_read_level` is consistent with this: it passes an explicitly-constructed **inert** census, so the census is **absent-in-effect at Task 2 and live from this task on**.
- **Supersession this task needs in its own right.** Spec §4.2.1 supersedes Task 5's *"no `pipeline.py` change"* clause for the residual-FACT emission loop; that supersession **extends to the per-module census build**, which is the second thing `pipeline.py` gains and which spec §4.2.1 places in the parse loop by name. Without this extension an implementer meets a standing prohibition in Task 5 and stops under the Global Constraints' no-scope-broadening discipline. The *"and therefore no `SUMMARY_SCHEMA_VERSION` bump"* clause and its restatement are **not** superseded and hold here unchanged — this task serialises nothing.

- [ ] **Step 1: Create `src/wardline/scanner/module_census.py`** — the builder and its richer entry view in one module, so the three predicates have exactly one home.

```python
# src/wardline/scanner/module_census.py
"""The per-module binding census — form 5's ONE evaluation point (spec §4.2.1).

Built exactly ONCE per module, in the parse loop, where the tree is already in
hand, and handed to both readers: the provider directly (``SeedContext``), the
rule side as the value under its module key (``AnalysisContext``). It is never
rebuilt, and no rule computes one — the rule side holds neither the module AST
nor the star-export map, and that inability is precisely the pressure that would
otherwise produce the defaulted-empty census the specification forbids.

Three components, and the census — not either reader — owns all three:

* ``values`` — every name bound at module scope, resolved to a level token ONLY
  when exactly one occurrence satisfies the direct-top-level, unconditional,
  single-``Name``-target discipline and no other module-scope occurrence of any
  kind exists anywhere in the module;
* ``poisoned`` — an unresolved top-level star import makes every name in the
  module unreadable, because ``build_import_alias_map`` skipped that import and
  the star may silently override the visible assignment;
* ``reference_sites`` — the ``def`` / ``async def`` statements that are DIRECT
  elements of ``Module.body``, held by node identity.

Last-binding-wins is refused outright. Decorator expressions are evaluated at
``def`` time, not in module source order, so picking the last binding in a VALUE
position is a trust escalation: any second occurrence — at any statement depth,
of any kind — makes the name unreadable rather than resolving to one of the pair.
"""
```

Import `ast`, `Mapping`, `MappingProxyType`, and from `wardline.scanner.marker_reader` exactly three names — the census types `ModuleCensus` / `CensusBinding` and the public `level_token`. Nothing else, so the module stays on the engine floor and the `marker_reader` edge stays one-way; `shadowed_builtin_roots` is deliberately NOT imported here, because the shadow set is loop-invariant and is hoisted once in `pipeline.py` (Step 3) and passed in. `ModuleCensus` and `CensusBinding` are **Task 2's** types and are not redefined here; this module adds only the builder and the local alias below.

`CensusEntry` is this module's name for `marker_reader.CensusBinding` — one type, two spellings is exactly the synonym Task 2 forbids, so **alias it rather than declaring it**:

```python
CensusEntry = CensusBinding
"""Task 2's ``CensusBinding``, re-exported under the builder's local name.

Exactly one of ``token`` / ``unreadable_reason`` is set. ``line`` is the
binding's line, which is what makes form 5's lexical-precedence clause
decidable. ``unreadable_reason`` is DIAGNOSTIC MESSAGE TEXT, not a pinned
vocabulary and not fingerprint input — the residual FACT keys on the unparsed
value node, which needs no census entry at all. No test asserts on these strings
and no fingerprint consumes them; do not mint a reason vocabulary here.
"""
```

`ModuleCensus.reference_sites` is Task 2's `frozenset[ast.stmt]` — membership is by **node identity**, which is sound because module source is parsed exactly once: the parse loop parses the module and discovers its entities from that one tree, so the provider and the rule side compare against identical objects rather than equal-looking copies. Pinned by `test_reference_site_membership_is_the_entity_node_object`, and the reason no qualname or column-offset proxy can answer the test (a conditionally-defined module-level `def` has the same qualname as an unconditional one). Liveness is not this module's problem: `ParsedFile.tree` and `AnalysisContext.entities` both retain the nodes for the whole scan.

- [ ] **Step 2: Write the builder — two walks with deliberately different descent rules.** The asymmetry is load-bearing and must be commented at the site: the **binding walk stops at nested scopes**, because class and function bodies are separate scopes and do not enter the census; the **`global` scan descends everywhere**, because spec §4.2.1 poisons a name for the whole module when a `global <name>` statement appears *anywhere* in it, and that cheap fail-closed rule is what makes the first walk's omission sound.

```python
def _enclosing_scope_exprs(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
) -> tuple[ast.expr, ...]:
    """Child expressions Python evaluates in the ENCLOSING scope, not the body.

    A ``def``'s decorators, argument defaults and annotations, and a ``class``'s
    bases and keywords, are evaluated where the statement appears — so a binding
    occurrence inside one of them IS a module-scope occurrence. The body is a
    separate scope and never enters the census. Descending into exactly these and
    stopping at the body is what keeps the walk fail-closed in both directions.
    """
    if isinstance(node, ast.ClassDef):
        return (*node.decorator_list, *node.bases, *(kw.value for kw in node.keywords))
    args = node.args
    annotations = tuple(
        a.annotation
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)
        if a.annotation is not None
    )
    return (
        *node.decorator_list,
        *args.defaults,
        *(d for d in args.kw_defaults if d is not None),
        *annotations,
        *((node.returns,) if node.returns is not None else ()),
    )


def build_module_census(
    tree: ast.Module,
    *,
    alias_map: Mapping[str, str],
    shadowed_roots: frozenset[str],
    star_exports: Mapping[str, Mapping[str, str]],
) -> ModuleCensus:
    """Build one module's census. Called ONCE per module, from the parse loop."""
    # POISON. This is build_import_alias_map's OWN expansion test, inverted: it
    # materialises a star import only when the import is ABSOLUTE and the target
    # module is in star_exports. Everything else it silently skips, so the star
    # may supply a name the census cannot see. Pinned against the shipped
    # function by test_census_poison_agrees_with_build_import_alias_map.
    poisoned = any(
        isinstance(stmt, ast.ImportFrom)
        and any(alias.name == "*" for alias in stmt.names)
        and not (
            (stmt.level or 0) == 0
            and stmt.module is not None
            and stmt.module in star_exports
        )
        for stmt in tree.body
    )

    occurrences: dict[str, list[int]] = {}
    declared_global: set[str] = set()

    def occurrence(name: str, line: int) -> None:
        occurrences.setdefault(name, []).append(line)

    def visit(child: ast.AST) -> None:
        line = getattr(child, "lineno", 0)
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # The def/class statement BINDS its own name — omitting it runs
            # fail-open: form 5 would resolve a token the code has since replaced
            # with a function or a class.
            occurrence(child.name, line)
            for sub in _enclosing_scope_exprs(child):
                visit(sub)
            return  # separate scope — the body never enters the census
        if isinstance(child, (ast.Import, ast.ImportFrom)):
            # An import IS a binding occurrence; the value it binds lives in
            # another module, so the name is unreadable for form 5.
            for alias in child.names:
                if alias.name == "*":
                    continue
                occurrence(alias.asname or alias.name.split(".")[0], line)
            return
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            # One test covers Assign, AnnAssign, AugAssign, walrus, for/with/
            # comprehension targets, tuple and starred unpacking, and `del`.
            occurrence(child.id, line)
        elif isinstance(child, ast.ExceptHandler) and child.name is not None:
            occurrence(child.name, line)
        elif isinstance(child, (ast.MatchAs, ast.MatchStar)) and child.name is not None:
            occurrence(child.name, line)
        elif isinstance(child, ast.MatchMapping) and child.rest is not None:
            occurrence(child.rest, line)
        for grandchild in ast.iter_child_nodes(child):
            visit(grandchild)

    for stmt in tree.body:
        visit(stmt)

    # WALK 2 — deliberately unlike walk 1: `global` counts ANYWHERE in the module,
    # nested scopes included. It is the fail-closed substitute for interprocedural
    # reasoning about writes back into module scope, and it is what makes walk 1's
    # refusal to descend into function bodies sound.
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            declared_global.update(node.names)

    # The one shape that may resolve: a DIRECT element of Module.body, single
    # `Name` target, unconditional. An `AnnAssign` qualifies when it has a value —
    # the annotation is not read, only the right-hand side, because `X: Final = ...`
    # is the idiomatic DRY spelling and refusing it re-opens the ticket for the
    # most likely real form. A name with two qualifying statements also has two
    # occurrences and is rejected below, so the last-wins write here is unreachable.
    qualifying: dict[str, tuple[ast.expr, int]] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            qualifying[stmt.targets[0].id] = (stmt.value, stmt.lineno)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            qualifying[stmt.target.id] = (stmt.value, stmt.lineno)

    values: dict[str, CensusEntry] = {}
    for name, lines in occurrences.items():
        if name in declared_global:
            values[name] = CensusEntry(None, "declared `global` in this module", lines[0])
            continue
        if len(lines) != 1 or name not in qualifying:
            values[name] = CensusEntry(
                None,
                "bound more than once in module scope, or not a direct top-level "
                "unconditional single-name assignment",
                lines[0],
            )
            continue
        value_node, line = qualifying[name]
        # The RIGHT-HAND-SIDE ALLOWLIST is Task 2's public `level_token`, called
        # with an inline EMPTY census — which is what makes form 5's one-hop rule
        # STRUCTURAL rather than a discipline: an empty census resolves no bare
        # `Name`, so a right-hand side that is itself a bare name is refused by
        # construction and the walk cannot take a second hop. What survives is
        # exactly P3 form 1 (a `str` constant) and P3 form 2. No second reader and
        # no new identifier: this is the same inline-census idiom as Task 2's two
        # call sites, for the same reason — the engine floor ships no inert census
        # constant, because a public one is the defaulted-empty affordance spec
        # rev 6 §4.2.1 forbids. `shadowed_roots` is threaded so the form-2
        # shadowed-root refusal is applied HERE, where the form-2 receiver is still
        # in view, and nowhere else (spec §4.2.1). `builtin=True` is inert on this
        # call — form 5 cannot fire against an empty census — so it does not give
        # the census a builtin/custom opinion; the census stays marker-agnostic.
        token = level_token(
            value_node,
            alias_map,
            census=ModuleCensus(values={}, poisoned=False, reference_sites=frozenset()),
            reference_site=None,
            shadowed_roots=shadowed_roots,
            builtin=True,
        )
        values[name] = (
            CensusEntry(token, None, line)
            if token is not None
            else CensusEntry(None, "right-hand side is outside form 1 / form 2", line)
        )

    return ModuleCensus(
        # Proxied HERE, not in AnalysisContext.__post_init__: `_freeze_value` returns a
        # non-Mapping/non-set value unchanged, so a ModuleCensus passes through the
        # context's freeze opaque and its inner dict would stay mutable — against that
        # class's "genuinely read-only view" guarantee. Wrapping in the builder also
        # covers the SeedContext path, which __post_init__ never touches.
        values=MappingProxyType(values),
        poisoned=poisoned,
        reference_sites=frozenset(
            stmt
            for stmt in tree.body
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
        ),
    )
```

Two over-approximations are deliberate and both fail **closed**, so neither is special-cased: a comprehension's own iteration target is a separate scope but is counted as a module-scope occurrence, and a walrus inside a nested comprehension is counted twice. Over-counting can only make a name unreadable; it can never resolve one. Record this in the module docstring so a later reader does not "fix" it into a fail-open.

- [ ] **Step 3: Build the census once per module in the parse loop.** In `src/wardline/scanner/pipeline.py`, add the imports beside the existing `build_import_alias_map` import at `:17`:

```python
from wardline.scanner.marker_reader import ModuleCensus, shadowed_builtin_roots
from wardline.scanner.module_census import build_module_census
```

Hoist the loop-invariant shadow set beside `provider_fingerprint` (`:113`), then build between `build_import_alias_map` (`:159-164`) and the `SeedContext(...)` construction (`:167`) — the only place in the engine where the tree, the alias map and the star-export map are all in hand at once:

```python
    shadowed_roots = shadowed_builtin_roots(project_modules)  # loop-invariant
```

```python
            census = build_module_census(
                tree,
                alias_map=alias_map,
                shadowed_roots=shadowed_roots,
                star_exports=stage_input.star_exports,
            )
            seeds = seed_function_taints(
                entities,
                ctx=SeedContext(
                    module=module,
                    alias_map=alias_map,
                    project_modules=project_modules,
                    census=census,
                ),
                provider=stage_input.provider,
            )
```

Add `census: ModuleCensus` to `ParsedFile` (`:39-47`) and pass the **same object** at `:250-259`. This is the single build: `SeedContext` and `ParsedFile` receive one census per module, not two.

- [ ] **Step 4: Both carriers, the rule side that reads one of them, and the required-parameter discipline stated at the boundary that actually has it.** Spec §4.2.1 forbids a defaulted census because a default ships the one-sided false green — and a signature-level `no default` on the reader does **not** by itself deliver that, because the census reaches the reader through a context object and the forbidden default would live there. Three mechanisms, stated together:

**(a) The carrier's default is the ABSENT SENTINEL, never an empty `ModuleCensus`.** An absent census and an empty one are different inputs and get different verdicts, on a predicate the reader can evaluate from what it holds. In `src/wardline/scanner/taint/provider.py`, `SeedContext` gains:

```python
    # The module's form-5 binding census, or None when this construction does not
    # seed from decorators (the trivial default provider's tests). None is the
    # ABSENT sentinel and is NOT an empty census: asked to resolve a bare `Name` in
    # a builtin LEVEL slot with no census at all, the shared reader RAISES, because
    # that is a plumbing defect rather than an input condition — and the raise is
    # BUILTIN-ONLY: on a custom `BoundaryType` a bare `Name` is an ordinary unreadable
    # `None`, because form 5 cannot resolve there and no census could change that.
    # On the provider side there is no per-rule isolation to land on; verified in
    # source, the raise is caught by the parse loop's bare `except Exception` per-file
    # isolation handler (pipeline.py:221 — the SyntaxError/UnicodeDecodeError/OSError
    # guard at pipeline.py:182 is a different handler and never sees it), which emits a
    # WLN-ENGINE-FILE-FAILED ERROR DEFECT and drops the file from the analysed set. That
    # is gate-eligible on the unsuppressed population, so a baseline row or waiver
    # annotates it without clearing the secure gate — the plumbing hole cannot be read
    # green. A defaulted EMPTY census would instead convert that plumbing hole into an
    # ordinary unreadable — silently, on every module.
    census: ModuleCensus | None = None
```

In `src/wardline/scanner/context.py`, `AnalysisContext` gains a field that follows `module_bindings`' shape and default-factory exactly (`TYPE_CHECKING` import beside `SinkBindings`), placed immediately after it:

```python
    # Per-module form-5 binding censuses: ``{module: ModuleCensus}``. Built ONCE in
    # the parse loop and only GATHERED here — never rebuilt, and no rule computes
    # one. Shape and default mirror ``module_bindings`` so direct constructions
    # (tests) need not supply it; a MISSING KEY is the absent sentinel and makes the
    # shared reader raise, landing on the shipped per-rule isolation as a
    # gate-eligible WLN-ENGINE-RULE-FAILED ERROR DEFECT — loud, and impossible to
    # confuse with a clean scan.
    module_censuses: Mapping[str, ModuleCensus] = field(default_factory=dict)
```

and the matching line at the end of `__post_init__` (`:176`), beside `module_bindings`' — the class freezes every mapping field and an unfrozen one is a hole in the read-only-view guarantee:

```python
        # ModuleCensus is a frozen dataclass whose own `values` map is already
        # proxied by the builder — only the outer map needs the proxy here.
        object.__setattr__(self, "module_censuses", _freeze_mapping(self.module_censuses))
```

`module_bindings` is a **shape** precedent, not a build-site one: `module_sink_bindings` is computed in the analyzer at `:634` from `parsed.tree`, whereas the census must not be. In `src/wardline/scanner/analyzer.py`, gather inside the existing `for parsed in file_meta:` loop at `:633` — no new loop, no rebuild:

```python
        module_censuses: dict[str, ModuleCensus] = {}
        for parsed in file_meta:
            module_censuses[parsed.module] = parsed.census  # GATHER only — no rebuild
            module_sink_bindings[parsed.module] = collect_sink_bindings(...)
```

and pass `module_censuses=module_censuses,` in the `AnalysisContext(...)` construction at `:1139-1162`, beside `module_bindings`.

**(b) P9 exercises both callers through the analyser's real construction path**, never a hand-built context (Task 2 Step 5's specified agreement suite, `test_form5_agreement`, executed by the task that owns it — **Task 8**, the first commit at which both the census and the residual FACT exist), so an unplumbed rule side reds the agreement test before it can ship. Mechanism (a) makes the plumbing hole loud; mechanism (b) is what proves the plumbing exists — **but only through that suite's **invalid-token row**, and the claim is false without it**: spec §4.2.1's own eight rows all pass over a rule side reading an inert census, so a suite limited to them proves nothing about rule-side plumbing. Neither mechanism alone is sufficient and the plan must carry both; note also that (b) is not carried **at all** until `test_form5_agreement` lands with that ninth row in Task 8, so at THIS task's commit (a) is the only live mechanism.

**(c) The rule side actually READS the carrier — and this is where PY-WL-114 stops being form-5-blind.** Mechanisms (a) and (b) build the carrier and prove it is plumbed; neither wires the one consumer that exists at this commit. In `src/wardline/scanner/rules/invalid_decorator_level.py`, replace Task 2 Step 3's explicitly-passed inert census — `census=ModuleCensus(values={}, poisoned=False, reference_sites=frozenset())` — with the real one, then pass `census=census` at the `level_token` call:

```python
            census = context.module_censuses.get(mod_name) if mod_name is not None else None
```

**Reuse `mod_name`; do not re-derive it.** `check` already computes the longest-owning-module key at `invalid_decorator_level.py:140-143` for its `alias_map` lookup, and `AnalysisContext.module_censuses` is keyed the same way (see the keying bullet in Interfaces), so one resolution serves both and the two cannot drift — which is the whole point of that bullet. A miss yields `None`, the ABSENT sentinel, exactly as (a) intends. Drop `ModuleCensus` from the rule's import list if nothing else in the module still uses it.

**Why this is not deferrable.** Task 2's Files list holds the rule module, but at Task 2 no census exists to read; Task 5 is provider-side and holds no qualname lookup; Task 8 declares its staged-path list exact. This task is the only one whose Files list can carry the path AND whose commit has a census to read. Left unowned, the rule side ships **permanently** form-5-blind while Task 5 widens the provider — one reader resolving `_SVC_LEVEL = 'ASURED'` and the other not — which is the one-sided widening spec §4.2.1 names **by name** as a silent false green, and which Task 8's `test_readable_but_invalid_token_is_py_wl_114_and_takes_no_fact` would then red six tasks downstream, in a task forbidden from repairing it.

**The one verdict that moves, and its receipt.** Append to `tests/unit/scanner/rules/test_invalid_decorator_level.py` a case named `test_form5_resolvable_invalid_token_now_fires`, written with that module's own `_analyze(tmp_path, src)` helper — which runs the real `WardlineAnalyzer.analyze`, so `context.module_censuses` is populated on the analyser's own construction path — over `_SVC_LEVEL = 'ASURED'` bound once, unconditionally, at module top level and lexically before a module-body `@trusted(level=_SVC_LEVEL)` on `def f(p): return p`, asserting `[(f.rule_id, f.qualname) for f in InvalidDecoratorLevel().check(ctx)] == [("PY-WL-114", "m.f")]`. Assert the **rule side only**: the provider does not resolve form 5 until Task 5, so a `declared_qualnames` assertion written at this commit would be a stale cross-reader claim. Both readers are asserted together, on one scan, by `test_form5_agreement`'s invalid-token row (**Task 8 Step 7**) — the row that exists precisely because this wiring could otherwise have gone missing. **No golden moves:** Global Constraints' value census records every builtin `level=`/`to_level=` value in the frozen trees as a `str` literal and zero bare-`Name` level values anywhere in the repository, so this widening fires on no frozen fixture and on no repo source.

- [ ] **Step 5: Write the census tests** — `tests/unit/scanner/test_module_census.py`. Build against a parsed module, never a hand-written `ModuleCensus`, so every test exercises the real predicates.

- **Resolution and the right-hand-side allowlist.** `X = "ASSURED"` resolves; `X: Final = TaintState.ASSURED` resolves (the annotation is not read); `X: Final` with no value is unreadable **and still counts as an occurrence**. A parametrised refusal table covering a call, an f-string, a subscript, a conditional expression, a tuple, `os.environ[...]`, a non-`str` Constant (`3`, `True`, `None`), and **another bare name** — the last pinning one-hop-only, which is the row that proves the census did not re-enter the widened reader.
- **`test_multi_target_assignment_is_not_a_qualifying_binding`** — parametrised over `X, Y = "ASSURED", "INTEGRAL"`, `X = Y = "ASSURED"` and `(X,) = ("ASSURED",)`, each asserting `census.values["X"].token is None` with exactly **one** recorded occurrence, so spec §4.2.1's tuple/starred/multiple-target row — "form 4's *single-`Name` target*, verbatim" — is pinned by the **target** conjunct alone rather than incidentally by the two-occurrence rule. The bullet above varies only the right-hand side and the bullet below needs two occurrences, so without this row a single-occurrence multi-target binding is exercised by neither, and Step 2's builder comment claiming coverage of "tuple and starred unpacking" has no test behind it. Relaxing the builder's `len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)` conjunct would RESOLVE a binding the spec requires to be UNREADABLE — the seed-minting direction, and the only direction that ships a false green.
- **`test_second_occurrence_at_any_depth_makes_the_name_unreadable`** — parametrised over a conditional rebind inside `if` / `try` / `with` / `if TYPE_CHECKING:`, a `for` target, a `with … as` target, an `except … as` target, a walrus, an augmented assignment, an `import` and a `from … import`, a `def <name>`, a `class <name>`, a `del <name>`, and a `match` capture. Include the realistic escalation shape by name — `X = "INTEGRAL"` then `if sys.platform == "win32": X = "ASSURED"` — asserting **unreadable**, not resolution to the top-level one.
- **`test_global_anywhere_poisons_the_name`** — with the `global <name>` inside a function body, so it passes only if walk 2 descends where walk 1 does not.
- **`test_class_and_function_body_bindings_do_not_enter_the_census`** — a qualifying module-scope binding still resolves when the same name is assigned inside a function or class body. Comment that this row is sound **only** in combination with the reference-site restriction and the `global` poison, and that neither may be relaxed without re-deriving it.
- **`test_unresolved_star_import_poisons_the_module`** plus the anti-drift pin **`test_census_poison_agrees_with_build_import_alias_map`**: for a relative star import, an unknown-module star import and a `wardline.decorators` star import, assert the census's `poisoned` flag is the exact complement of whether `build_import_alias_map` materialised that import's names. This is the guard against the two predicates drifting apart.
- **`test_reference_sites_hold_only_direct_module_body_defs`** — and, called out separately because spec §4.2.1 names it the newest and least obvious of the reference-site rules, **`test_conditionally_defined_module_level_def_is_not_a_reference_site`**: a `def` nested in a module-level `if` (a `sys.version_info` fork, or `if TYPE_CHECKING:`) is **absent** from the set. Cover a method, a nested `def`, and a module-top-level `async def` (present) in the same module.
- **`test_reference_site_membership_is_the_entity_node_object`** — parse one module, run `discover_file_entities` over the same tree, and assert `entity.node in census.reference_sites` **and** `entity.node is tree.body[i]` for the module-top-level entity. If `discover_file_entities` ever stops handing back the same object, form 5 silently stops resolving everywhere — a total, fail-closed feature outage with nothing red. This `is` assertion is the whole soundness argument for holding reference sites by node identity.
- **`test_shadowed_root_refusal_is_applied_at_the_census_build`** — a form-2 right-hand side (`X = TaintState.ASSURED`) in a project that shadows the vocabulary root records an **unreadable** entry. Pair it with a comment stating the alternative that was refused: applied at the value's *use site* instead, the reader sees a bare `Name` whose token has already been resolved, the receiver is gone, and the same code reads as ordinary and resolves.
- **`test_the_census_is_marker_agnostic`** — the census records the same entry regardless of which marker later reads the name, because it holds no builtin/custom discriminator at all. This pins that the builtin-only gate lives in exactly one place (the reader and its caller), so a second, divergent split cannot form here — the builtin/custom half of spec §4.2.1's two silent-cross-reader-disagreement cases. The other half, the star-import poison, is covered by the next step's cross-reader assertion; the full eight-case agreement table is Task 2 Step 5's.

- [ ] **Step 6: Write the transport tests.** In `tests/unit/scanner/test_pipeline.py`: `test_parse_loop_builds_one_census_per_module` asserting `parsed_file.census is` the object handed to the provider's `SeedContext` (capture it with a recording provider), so a second build cannot creep in; and a `run_scan(tmp_path)` test asserting `result.context.entities["svc.f"].node in result.context.module_censuses["svc"].reference_sites` — the end-to-end proof that the object the parse loop built is the object a rule receives, on the analyser's real construction path. In `tests/unit/scanner/test_context.py`: extend the existing read-only-view coverage to the new field — a source dict mutated after construction does not change `context.module_censuses`, and `context.module_censuses[m].values` refuses assignment. In `tests/unit/scanner/taint/test_provider_seedcontext.py`: `test_seed_context_census_defaults_to_the_absent_sentinel`, asserting the default is `None` and **not** an empty `ModuleCensus`. Add the cross-reader poison assertion here as a `run_scan` test: on a star-import-poisoned module, both sides agree — the qualname is absent from `result.context.declared_qualnames` **and** the census both sides hold reports `poisoned`, so neither reader re-derived the predicate.

- [ ] **Step 7: Run the affected suites**

Run: `uv run pytest tests/unit/scanner/test_module_census.py tests/unit/scanner/test_pipeline.py tests/unit/scanner/test_context.py tests/unit/scanner/taint/test_provider_seedcontext.py tests/unit/scanner/rules/test_invalid_decorator_level.py tests/unit/scanner/test_marker_reader_agreement.py tests/unit/scanner/test_module_bindings.py -q && uv run lint-imports`

`tests/unit/scanner/rules/test_invalid_decorator_level.py` is in the list because Step 4(c) edits both it and the rule beside it. Note also what `test_marker_reader_agreement.py` holds at this commit — Task 2's reader-level rows over a HAND-BUILT census, and nothing else. `test_form5_agreement`, the both-sides receipt P9 turns on, does not exist until **Task 8 Step 7**, so a green run here is not a P9 receipt and must not be recorded as one.
Expected: all PASS. `test_marker_reader_agreement.py` is in the list deliberately, but for a **narrower** reason than the one-sided-widening detector it was previously called: at this commit the module holds only Task 2 Step 5's reader-level rows over hand-built censuses, so it reds on a regression in the reader, not on a rule side left reading an inert census. The detector is `test_form5_agreement`, and specifically its **invalid-token row** — the only shape on which the two readers can disagree — which lands with the task that owns it, **Task 8**. Running the module here is a no-regression check, not the P9 receipt. `test_module_bindings.py` is run-only, not modified: it is the nearest neighbour of the analyzer loop this task edits, so a mis-placed gather reds there first. `lint-imports` proves the new engine-tier module did not invert a layer; the `module_census` → `marker_reader` runtime edge is one-way and the reverse edge is `TYPE_CHECKING` only.

- [ ] **Step 8: Run the full suite** — `uv run pytest -q`. Expected: PASS, **zero scan-golden drift** — this commit transports a census and changes no seeding, so any golden movement means something is already consuming it and the change is wrong.

- [ ] **Step 9: Commit** — `feat(scanner): per-module binding census — parse-loop build, SeedContext + AnalysisContext carriers (S0, spec §4.2.1 form 5)`. Record the commit SHA in the implementation receipt.

---

### Task 4: Migrate the 9 incidental legacy `to_level` fixture sites (behaviour-neutral)

**Files (all test-fixture edits, no assertions change):**
- Modify: `tests/unit/scanner/rules/test_untrusted_reaches_trusted.py:71`
- Modify: `tests/unit/scanner/taint/test_review_fixups_engine.py:177,193,209,225,283,333,351,385`

The 2026-08-09 census found EXACTLY 10 occurrences of the invalid legacy shape `@trusted(level=..., to_level=...)`. Nine are incidental fixture noise (the `to_level=` asserts nothing); the tenth is the deliberate tolerance pin `test_trusted_level_tolerates_legacy_to_level_keyword` (`tests/unit/scanner/taint/test_decorator_provider.py:164-171`), which Task 5 REWRITES — do not touch it here.

- [ ] **Step 1: Edit the nine sites.** In each listed line, change `@trusted(level='ASSURED', to_level='ASSURED')` → `@trusted(level='ASSURED')` (match the exact quoting each site uses). These are decorator strings inside test source fixtures; the enclosing tests assert rebinding/precision behaviour, not the decorator shape.

- [ ] **Step 2: Verify the census is exhausted.** Run:

```bash
rg -n --pcre2 '@trusted\((?=[^)]*\blevel\s*=)(?=[^)]*\bto_level\s*=)[^)]*\)' \
  tests --glob '*.py'
```

Expected: exactly one hit — the deliberate provider tolerance test rewritten next task. This pattern does not miscount adjacent decorators or custom `to_level` calls embedded in the same fixture string.

- [ ] **Step 3: Run the two touched suites** — `uv run pytest tests/unit/scanner/rules/test_untrusted_reaches_trusted.py tests/unit/scanner/taint/test_review_fixups_engine.py -q`. Expected: PASS (behaviour-neutral — the tolerance still exists this commit, and `level=` alone seeds identically).

- [ ] **Step 4: Commit** — `test(scanner): migrate 9 incidental legacy to_level fixture sites to the lawful @trusted(level=...) form (S0)`

---

### Task 5: Provider — call-shape validator wired into `_match`; the `to_level` tolerance dies

**Files:**
- Modify: `src/wardline/scanner/taint/decorator_provider.py` (`_match` :363-420 — signature AND verdict both widen; `taint_for` — plumbing only: it threads the per-module census and `reference_site=entity.node` down into `_match` and discards the new third verdict element, which Task 7 Step 4.2 then consumes; delete `_read_level`)
- Modify: `src/wardline/scanner/taint/project_resolver.py:54` (`_RESOLVER_VERSION` `sp1g` → `sp1h`)
- Modify: `tests/unit/scanner/taint/test_decorator_provider.py:164-171` **and `:201-204`** (rewrite the tolerance test; rewrite `test_trusted_dynamic_level_is_no_opinion` at `:201-204` — verified in source as the ONE existing `_seed` case presenting a bare `Name`, which raises at this task's commit — into the `run_scan`-based `test_module_constant_level_now_resolves_under_form5`; and add the P3 form-5 posture sibling beside `test_malformed_marker_alone_still_takes_no_opinion`, which is `run_scan`-based for the reason stated under Step 1)
- Modify: `tests/unit/scanner/taint/test_summary.py` (epoch pin)
- Modify: `tests/unit/scanner/taint/test_summary_cache.py` (cold/warm malformed-builtin equivalence)
- Modify: `tests/grammar/test_provider_loop.py:111-120` (`test_unprovable_builtin_does_not_signal` — Step 1 gives it a census-carrying `SeedContext`. **The Task 5 half of a two-task amendment**; Task 7 Step 4.6 owns the other half and the path is on that task's Files list too, because the field it asserts on does not exist until Task 7)

**Interfaces:**
- Consumes: Task 2's `call_shape_offences`, `read_level`, `LevelRead`/`LevelVerdict`; Task 3's per-module census on `SeedContext`.
- Produces: builtin-only registry validation. A malformed builtin call never seeds and stays silent in the provider (PY-WL-130 is the loud channel, Task 6, and it is an ERROR). The dropped seed is deliberately **not** demoted to `UNKNOWN_RAW` when a provable sibling marker exists: measured at `release/2.0.0`, `UNKNOWN_RAW` is in `RAW_ZONE`, `modulate()` returns `Severity.NONE` there and PY-WL-101 skips a declared tier in `RAW_ZONE`, so demoting would silence every tier-gated rule on the function — whereas dropping the malformed marker and letting the provable one stand seeds `ASSURED` and fires PY-WL-101 + PY-WL-112 on the very stack that fires nothing today. `_match`'s verdict WIDENS to three elements: the existing seed and unprovable-custom-name pair, plus `unreadable_level_values: tuple[tuple[str, str], ...]` carrying the `(argument name, ast.unparse(value))` pairs a BUILTIN marker's unreadable `ArgKind.LEVEL` value produces (spec §4.2.1). **The reader mints the pair; `_match` only collects and forwards it.** Task 2's `read_level` holds both the argument name and the value node and returns the pair on `LevelRead.unreadable_value`, populated only on verdict `UNREADABLE` and only for a builtin — so `_match` never re-reads a value to derive it, and never duplicates the builtin gate at the call site where it could drift from the reader's. `_match` also gains the per-module census and the reference site as REQUIRED, non-defaulted keyword parameters, so P3 form 5 resolves in the provider. Custom `BoundaryType` packs do **not** pass through the builtin validator; their released `level_args` contract and `WLN-ENGINE-UNPROVABLE-BOUNDARY` channel are unchanged, and a custom type's unreadable level value keeps the released `(None, canonical_name)` verdict with an EMPTY residual tuple — it never enters the new channel and is never counted twice (spec §4.2's compatibility boundary). `@external_boundary()` and `@external_boundary(**{})` now drop because the registry declares the marker bare-only. `_RESOLVER_VERSION="sp1h"` invalidates every cached pre-S0 seed result.

- [ ] **Step 1: Write the failing tests.** REWRITE `test_trusted_level_tolerates_legacy_to_level_keyword` (`tests/unit/scanner/taint/test_decorator_provider.py:164-171`) into its opposite, and add the external_boundary pin next to it. **This step makes THREE rewrites to this file, not two** — the third is `test_trusted_dynamic_level_is_no_opinion` (`:201-204`), the one existing `_seed` case that presents a bare `Name` in a builtin LEVEL slot and therefore **raises** at this task's commit; it is converted to `run_scan`/`tmp_path` in the block below, beside `test_form5_module_constant_level_seeds_and_declares`, and the enumeration after the block states why.

```python
def test_legacy_to_level_on_trusted_now_drops_the_seed() -> None:
    # REVERSAL (S0, spec §4.2): the analyzer-only tolerance for the runtime-
    # invalid `@trusted(level=..., to_level=...)` shape is gone. The runtime
    # raises TypeError on this call; the analyzer now agrees — undeclared
    # keyword => shape offence => no seed (and PY-WL-130 fires, rule suite).
    out = _seed(
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', to_level='ASSURED')\n"
        "def f():\n"
        "    return 1\n"
    )
    assert out["m.f"] is None


def test_called_external_boundary_drops_the_seed() -> None:
    # external_boundary's runtime signature takes NO call arguments; the provider
    # previously never inspected them (level_args=()) and seeded anyway. The
    # shape validator closes that: a runtime-TypeError declaration never seeds.
    for call in ("external_boundary()", "external_boundary(**{})", "external_boundary(source='http')", "external_boundary('http')", "external_boundary(**KW)"):
        out = _seed(
            "from wardline.decorators import external_boundary\n"
            "KW = {}\n"
            f"@{call}\n"
            "def f():\n"
            "    return 1\n"
        )
        assert out["m.f"] is None, call


def test_bare_external_boundary_still_seeds() -> None:
    out = _seed(
        "from wardline.decorators import external_boundary\n"
        "@external_boundary\n"
        "def f():\n"
        "    return 1\n"
    )
    assert out["m.f"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_malformed_sibling_never_reduces_the_error_population(tmp_path) -> None:
    # The property that matters, and the one a seed-value assertion cannot express:
    # dropping a malformed marker must never make a scan QUIETER than leaving it.
    # Measured at release/2.0.0: the pre-Task-5 engine seeds this stack EXTERNAL_RAW
    # and fires ZERO ERROR+ defects, because EXTERNAL_RAW is in RAW_ZONE and modulate()
    # returns Severity.NONE. After Task 5 the malformed marker drops, @trusted stands
    # alone, the tier is ASSURED, and PY-WL-101 + PY-WL-112 fire. Demoting the seed to
    # UNKNOWN_RAW "for safety" would return it to silence — declaring trust is what
    # SUBJECTS a function to the leak rules.
    from wardline.core.finding import Kind, Severity
    from wardline.core.run import run_scan

    src = (
        "import subprocess\n"
        "from wardline.decorators import trusted, external_boundary\n"
        "@external_boundary\n"
        "def raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\n"
        "@external_boundary(source='http')\n"
        "def f(p):\n"
        "    cmd = raw(p)\n"
        "    subprocess.run(cmd, shell=True)\n"
        "    return cmd\n"
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    result = run_scan(proj)
    assert result.context is not None
    assert result.context.project_taints["svc.f"] == T.ASSURED
    errors = {
        f.rule_id for f in result.findings
        if f.kind is Kind.DEFECT and f.severity in (Severity.ERROR, Severity.CRITICAL)
    }
    assert {"PY-WL-101", "PY-WL-112", "PY-WL-130"} <= errors


def test_malformed_marker_alone_still_takes_no_opinion() -> None:
    # The contribute-only-alongside-a-candidate rule, SPLIT by rev 6 (spec §4.2.1):
    # a lone marker with a malformed SHAPE must NOT enter declared_qualnames
    # (posture denominator stability) — a shape offence is not a value problem, so
    # this half is unchanged. A lone marker whose LEVEL RESOLVES — including via
    # P3 form 5 — DOES enter declared_qualnames and DOES count in the anchored
    # posture bucket (spec §4.2.1, §11.4). The sibling below pins that half.
    out = _seed(
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', audit=True)\n"
        "def f():\n"
        "    return 1\n"
    )
    assert out["m.f"] is None


def test_form5_module_constant_level_seeds_and_declares(tmp_path) -> None:
    # The other half of the split above, and the posture consequence spec §4.2.1
    # states rather than leaving to the implementer. `_SVC_LEVEL` is a single,
    # unconditional, direct-top-level `str` binding lexically preceding a `def`
    # that is a direct element of Module.body, read in a BUILTIN marker's LEVEL
    # slot — P3 form 5 in full. It RESOLVES, so this function IS a recognised
    # boundary: it seeds, it enters declared_qualnames, and it takes NO residual
    # FACT (the FACT is for what stays unreadable, never for what resolves).
    #
    # run_scan/tmp_path, NOT _seed: _seed builds its own SeedContext and supplies
    # no per-module census, and a bare Name in a LEVEL slot with no census present
    # is a PLUMBING DEFECT the shared reader RAISES on (spec §4.2.1). Only the
    # parse loop builds the census, so only an end-to-end scan can exercise form 5.
    from wardline.core.run import run_scan

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\n"
        "_SVC_LEVEL = 'ASSURED'\n"
        "@trusted(level=_SVC_LEVEL)\n"
        "def f(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert result.context is not None
    # Primary assertion: the posture denominator moves, correctly.
    assert "svc.f" in result.context.declared_qualnames
    assert result.context.project_taints["svc.f"] == T.ASSURED
    assert not [
        f
        for f in result.findings
        if f.rule_id == "WLN-ENGINE-UNREADABLE-MARKER-VALUE"
    ]


def test_module_constant_level_now_resolves_under_form5(tmp_path) -> None:
    # REWRITE of `test_trusted_dynamic_level_is_no_opinion` (:201-204), whose
    # premise spec §4.2.1 retires. That test read `LV = 'ASSURED'` /
    # `@trusted(level=LV)` through `_seed` and asserted no-opinion — "a non-literal
    # level (a Name) cannot be read statically -> fail-closed". Under P3 form 5
    # that exact source RESOLVES (one unconditional direct-top-level `str`
    # binding, lexically preceding a `def` that is a direct element of
    # Module.body, in a BUILTIN LEVEL slot), so BOTH the name and the assertion
    # invert.
    #
    # It also cannot stay on `_seed`: `_seed` constructs its own SeedContext with
    # no census, and from this task's commit the shared reader RAISES on a bare
    # `Name` in a builtin LEVEL slot with `census=None`. Left alone it would ERROR
    # here, not merely fail. Kept as its own row rather than folded into the test
    # above, so the reversal stays visible where the old fail-closed pin stood.
    from wardline.core.run import run_scan

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\n"
        "LV = 'ASSURED'\n"
        "@trusted(level=LV)\n"
        "def f():\n"
        "    return 1\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert result.context is not None
    assert result.context.project_taints["svc.f"] == T.ASSURED
    assert "svc.f" in result.context.declared_qualnames
```

The custom zero-level metadata case is implemented with the real `BoundaryType`/`build_analyzer` construction in Task 14; Task 5's bridge gate must already remain at exactly two recognised boundaries.

(`_seed`, `FunctionTaint`, `T` are this file's existing helpers/imports — match the surrounding tests' exact usage. `test_malformed_sibling_never_reduces_the_error_population` is deliberately the exception: it is end-to-end via `run_scan`/`tmp_path`, because the property it pins — the scan must not get quieter — is not expressible as a seed value. `test_form5_module_constant_level_seeds_and_declares` is the second exception, for a different and harder reason: `_seed` constructs its own `SeedContext` and supplies **no per-module census**, and spec §4.2.1 makes a bare `Name` in a LEVEL slot with **no census present for that module at all** a PLUMBING DEFECT the shared reader **raises** on — not an input condition it answers `None` to. A `_seed`-based form-5 case would therefore raise rather than resolve. **That invariant is exactly one existing case away from true, and the case is named here rather than left to be met as an unexplained red.** Verified in source at `release/2.0.0`: `test_trusted_dynamic_level_is_no_opinion` (`tests/unit/scanner/taint/test_decorator_provider.py:201-204`) is the ONE existing `_seed` case in this file that presents a bare `Name` in a builtin LEVEL slot — its source is `LV = 'ASSURED'` / `@trusted(level=LV)` — so at this task's commit it **raises `ValueError`** rather than returning `None`. Every other `_seed` case is a `str` literal or a dotted `Attribute`: `grep -n "level=" tests/unit/scanner/taint/test_decorator_provider.py` returns exactly two other non-literal values, `TaintState.GUARDED` (`:135`) and `cfg.GUARDED` (`:258`), neither of them a bare `Name`. Step 1's third rewrite is that case, converted above to the `run_scan`/`tmp_path` `test_module_constant_level_now_resolves_under_form5`, in which both its name and its assertion invert. **With that rewrite landed the invariant holds, and it is the rewrite that establishes it**: no `_seed` case in this file presents a bare `Name`, which is the whole reason the census-less `_seed` helper (`:16-30`) stays safe once this task threads `SeedContext.census` — `None` for every `_seed` construction — into the shared reader. Preserving it is the next sentence's job: any future form-5 case must go through `run_scan`, which builds the census in the parse loop, or construct a census explicitly. Adding a default to the census parameter to make `_seed` compile is forbidden — it ships the one-sided false green spec §4.2.1 describes.)

**Also in this step, and not optional: amend `tests/grammar/test_provider_loop.py::test_unprovable_builtin_does_not_signal` (`:111-120`).** The shipped test calls `provider.taint_for(ent, SeedContext(module="m", alias_map=alias_map))` over `@trust_boundary(to_level=CFG)` — a bare `Name` in a **builtin** LEVEL slot with **no census** — which Step 3's re-cut `_match` hands to the shared reader as spec §4.2.1's plumbing-defect **raise**. Verified in source: **no** `except ValueError` wraps the reader call on `taint_for`'s path. There are two in that file and neither catches it — `decorator_provider.py:196`, inside `_read_level`, is the only one ON that path and it wraps the `TaintState(token)` conversion rather than the reader call; the other, `:234` inside `_closure_identity`, is on the provider-fingerprint path. So the raise escapes `taint_for` and the test ERRORs at this task's commit unless it is amended here. Construct its `SeedContext` with an explicit per-module census built by Task 3's `build_module_census` over the same parsed tree, pass it as `census=`, and keep both existing assertions **verbatim** — `res.taint is None` and `res.unprovable_boundaries == ()`, both still true and both required by §4.2's compatibility boundary (a builtin's unreadable LEVEL value never takes the custom channel).

**This amendment PREVENTS a red rather than creating one**, which is why it is not in Step 1's failing-test list: it passes at Step 2 (the provider still uses the retained private `_read_level` with Task 2 Step 2's inline inert census) and it passes again at Step 4 (the census is present, `CFG` is unbound, so the value is an ordinary unreadable). **Do NOT add the `res.unreadable_level_values` assertion here.** `SeedResult.unreadable_level_values` is declared in **Task 7** — on its Files list, in its *Produces (rev 6)* entry, and in its **Step 4** sub-items 1 (`provider.py`) and 3 (`function_level.py`) — so that assertion would raise `AttributeError` at this commit — it is **Task 7 Step 4.6's** half, and `tests/grammar/test_provider_loop.py` is on both tasks' Files lists for exactly that reason.

- [ ] **Step 2: Run to verify the rewritten test fails** — `uv run pytest tests/unit/scanner/taint/test_decorator_provider.py -v`. Expected: the two new drop tests FAIL (tolerance still seeds; external_boundary still seeds), and so does `test_malformed_sibling_never_reduces_the_error_population` — PY-WL-130 does not exist yet, and the malformed `@external_boundary(source='http')` still seeds, so the tier is `EXTERNAL_RAW` rather than `ASSURED` and none of the three expected ERRORs fire. `test_malformed_marker_alone_still_takes_no_opinion` already PASSES — it is a no-regression pin on behaviour this task must NOT change. `test_form5_module_constant_level_seeds_and_declares` also FAILS: P3 form 5 does not reach the provider until this task's re-cut `_read_level` call passes the census and the reference site, so `_SVC_LEVEL` is still an unreadable bare `Name`, the seed drops and `svc.f` is absent from `declared_qualnames`. **`test_module_constant_level_now_resolves_under_form5` — Step 1's third rewrite, of `test_trusted_dynamic_level_is_no_opinion` (`:201-204`) — also FAILS, for the same reason and on the same assertion**: at this commit the provider still reads through Task 2's retained private `_read_level` and its inline INERT census, so `LV` is an unreadable bare `Name`, the seed drops, `svc.f` is absent from `declared_qualnames` and `project_taints["svc.f"]` is `UNKNOWN_RAW` rather than `ASSURED`. It FAILS rather than ERRORs precisely because Step 1 already moved it off `_seed`; left on `_seed` it would raise `ValueError` from Step 3 onward. Everything else PASS.

- [ ] **Step 3: Implement.** In `_match` (:363-420) there are FOUR changes — the frozen-at-two framing rev 3.4 carried here is superseded by spec rev 6 §4.2.1, which places P3 form 5 inside this task's reader call. (1) Delete the `ignored = frozenset({"to_level"}) ...` comment+line block (**:400-404** — the four-line legacy-tolerance comment at `:400-403` plus the `ignored = ...` assignment at `:404`). **Not `:399`**, which is the `for la in bt.level_args:` loop header the replacement snippet below retains: deleting it strips the header and leaves an indented body — a `SyntaxError`. (2) Insert the validator gate right after a boundary type matches, **before** the `levels` loop. (3) Widen the signature with `census` and `reference_site` as REQUIRED keyword parameters carrying NO default, so the shared reader can evaluate form 5's binding census and its reference-site restriction. (4) Widen the verdict from `(FunctionTaint | None, str | None)` to `(FunctionTaint | None, str | None, tuple[tuple[str, str], ...])`, whose third element carries the residual `(argument name, unparsed value text)` pairs. Every one of `_match`'s existing return sites is re-cut to the wider verdict: a new verdict channel **is** added, and it is the only carrier for the pair spec §4.2.1 condition 4 fingerprints on. The ordering in (2) is load-bearing and unchanged — the shape gate runs before any level is read, so a marker that is BOTH shape-malformed and value-unreadable is rejected on shape before its value is a question; it takes `PY-WL-130` alone and never also `WLN-ENGINE-UNREADABLE-MARKER-VALUE` (spec §4.2.1). Do not describe that trade as strictly louder or as losing nothing: `PY-WL-130` is a `Kind.DEFECT` and therefore suppressible, so a waived `PY-WL-130` leaves that site with no signal at all, no FACT having been emitted. The justification is noise-avoidance plus the shipped **secure default** — under `trust_suppressions=False`, `run_scan` rebuilds `gate_population_findings` with an empty `Baseline`, an empty `WaiverSet` and `judged=None`, so a waived or baselined `PY-WL-130` still trips `--fail-on`, and the site loses its signal only under an explicit `--trust-suppressions` operator decision (spec rev 9 §4.2.1, which replaces rev 8's P13 clause; P13 is a **repository-scoped** ceiling and never bore that weight) — not dominance. This is the same justification `call_shape_offences`' docstring carries (Task 2) and the same one Task 8's canonical ruled-ordering paragraph states; the three must not diverge.

```python
        fqn = _resolve_decorator_fqn(deco, alias_map)
        if fqn is None:
            return None, None, ()
        ...
            if bt.builtin:
                entry = REGISTRY[bt.canonical_name]
                required = frozenset(
                    la.arg_name for la in bt.level_args if la.default is None
                )
                if call_shape_offences(
                    deco,
                    call_form=entry.call_form,
                    declared=entry.kwargs,
                    required=required,
                ):
                    # Malformed builtin shape: the seed drops and the provider stays
                    # SILENT. PY-WL-130 is the loud channel (Task 6), and it is an
                    # ERROR, so a malformed marker cannot ship green.
                    #
                    # Deliberately NOT demoted to UNKNOWN_RAW when a provable sibling
                    # marker exists. Measured at release/2.0.0: UNKNOWN_RAW is in
                    # RAW_ZONE, modulate() returns Severity.NONE for it, and PY-WL-101
                    # skips a declared tier in RAW_ZONE — so demoting SILENCES every
                    # tier-gated rule on the function. Dropping the malformed marker and
                    # letting the provable one stand is strictly louder: the motivating
                    # stack (@trusted(level='ASSURED') over @external_boundary(source=…))
                    # seeds EXTERNAL_RAW today and fires ZERO ERROR+ defects, whereas
                    # after this change it seeds ASSURED and fires PY-WL-101 +
                    # PY-WL-112 — because declaring trust is what SUBJECTS a function to
                    # the leak rules.
                    #
                    # This return is ALSO the short-circuit that keeps a malformed
                    # marker off the residual channel: the shape verdict is decided
                    # here, BEFORE any level is read, so a marker that is both
                    # shape-malformed and value-unreadable never reaches the reader
                    # and never also takes WLN-ENGINE-UNREADABLE-MARKER-VALUE
                    # (spec §4.2.1). The residual tuple is empty for that reason.
                    return None, None, ()
            # The `(argument name, unparsed value text)` pair spec §4.2.1 condition 4
            # fingerprints on arrives on `LevelRead.unreadable_value` — Task 2's
            # discriminated return type, which is THE mechanism this plan names for
            # reaching it. The old bare `TaintState | None` answered `None` for BOTH
            # an unreadable value and a token that WAS read and then rejected by the
            # `allowed` check, and only the FIRST takes the residual FACT; the second
            # is PY-WL-114's DEFECT (spec §4.2.1's READS-then-rejects row) and must
            # never also emit a FACT. `LevelRead` is what keeps them apart, and the
            # provider does NOT re-read the value to work it out.
            levels: dict[str, TaintState] = {}
            unreadable = False
            unreadable_level_values: list[tuple[str, str]] = []
            for la in bt.level_args:
                read = _read_level(
                    deco,
                    la.arg_name,
                    declared=(REGISTRY[bt.canonical_name].kwargs if bt.builtin else frozenset(
                        item.arg_name for item in bt.level_args
                    )),
                    allowed=la.allowed,
                    default=la.default,
                    alias_map=alias_map,
                    census=census,
                    reference_site=reference_site,
                    shadowed_roots=shadowed_roots,
                    builtin=bt.builtin,
                )
                if read.verdict is not LevelVerdict.RESOLVED:
                    unreadable = True
                    if read.unreadable_value is not None:
                        # `unreadable_value` is populated ONLY on verdict UNREADABLE
                        # AND builtin — the reader's own gate, so no caller-side
                        # builtin test is needed or wanted here. A CUSTOM
                        # BoundaryType therefore never contributes a pair: form 5 and
                        # the residual FACT are both builtin-only (spec §4.2's
                        # compatibility boundary, §4.2.1), so a custom type keeps
                        # `(None, canonical_name)` below with an EMPTY residual tuple,
                        # keeps WLN-ENGINE-UNPROVABLE-BOUNDARY and an UNKNOWN_RAW
                        # seed, and is never counted on two channels. A REJECTED
                        # verdict likewise carries no pair, on either side.
                        #
                        # Stored RAW. NFC normalisation and the 200-character
                        # truncation of spec §4.2.1 condition 4 apply to the
                        # VALUE-TEXT part only and are applied at the FACT emission
                        # site, never here.
                        unreadable_level_values.append(read.unreadable_value)
                    break
                # `LevelVerdict.RESOLVED` stays the semantic gate; this is the TYPE
                # obligation, not a second decision. Task 2's `LevelRead` contract is
                # that RESOLVED carries the level, but mypy performs no correlated
                # narrowing from `verdict` onto `level`, and `[assignment]` is
                # disabled for `tests` only, never for `src/`.
                assert read.level is not None
                levels[la.arg_name] = read.level
            if unreadable:
                return (
                    None,
                    (None if bt.builtin else bt.canonical_name),
                    tuple(unreadable_level_values),
                )
            return bt.seed(levels), None, ()
        return None, None, ()
```

Import `call_shape_offences`, `LevelVerdict` and `read_level as _read_level` from `marker_reader`; delete the old provider-private reader and its `ignored_args` branches. The **provider-private** `_level_token` goes with it — the shared `level_token` replaces it, and the shared reader is now the only reader on both sides. `_match`'s signature widens in the same edit to `_match(self, deco, alias_map, shadowed_roots, *, census, reference_site) -> tuple[FunctionTaint | None, str | None, tuple[tuple[str, str], ...]]`; **neither `census` nor `reference_site` carries a default**, exactly as Task 2's re-cut entry points forbid one — a defaulted-empty census ships the one-sided false green spec §4.2.1 names. `_match`'s docstring gains two lines: "Shape offences (``call_shape_offences``) drop the seed before any level is read — so a marker that is BOTH shape-malformed and value-unreadable takes ``PY-WL-130`` alone and never also ``WLN-ENGINE-UNREADABLE-MARKER-VALUE``." and "``(None, None, pairs)`` — a BUILTIN marker whose ``ArgKind.LEVEL`` value stays unreadable; ``pairs`` carries ``(argument name, ast.unparse(value))`` RAW, for the residual FACT to normalise and truncate at emission."

**One mechanism, named once, and this is the reconciliation of the two candidates the review left open.** Reaching the residual pair, and separating an unreadable value from a token that was read and then rejected, is done by Task 2's **discriminated `LevelRead` return type** — `verdict` plus a `unreadable_value` that the reader populates only on `UNREADABLE` **and** builtin. The rejected alternative, composing `extract_keywords` with a second `level_token` call here in `_match` to re-derive what the reader already knew, is **not** taken: it reads every unreadable value twice, duplicates the builtin gate at the call site where it can drift from the reader's, and leaves `read_level`'s collapsed `None` in place — which is NO-GO trigger 1. Exactly one of the two may be named anywhere in this plan, or Tasks 2 and 5 build different readers; the named one is `LevelRead`, and Task 2's produced-interface list carries it.

`taint_for` **is** touched by this task, but as PLUMBING only, and the change is disjoint from Task 7's. Task 5 threads the two new required arguments down into `_match`: the per-module census, which reaches the provider on the `SeedContext` Task 3 added, and `reference_site=entity.node` — the decorated `def` / `async def` statement `taint_for` already holds for every entity it seeds, passed directly rather than on a context object. Task 5 does **not** consume `_match`'s new third element: the residual pairs are received and discarded here, and **Task 7 Step 4.2 remains the sole place `taint_for`'s branch arms and its two `SeedResult(...)` constructions change**, where the fourth arm collects them. Splitting it this way keeps Task 5's commit behaviour-neutral for the residual channel while making the pair reachable at all; it also means Task 5 and Task 7 never claim the same edit.

The shape gate still returns the plain "no match" verdict — now three-wide, with an empty residual tuple — so a malformed builtin contributes nothing to the candidate list and the existing unprovable-CUSTOM-boundary meet is unchanged. A function whose ONLY decorator is a malformed builtin therefore keeps today's behaviour exactly — no seed, absent from `declared_qualnames`, `UNKNOWN_RAW` by the L1 fallback, PY-WL-130 as the diagnostic — so **every existing planned assertion of the form `"svc.f" not in result.context.declared_qualnames` still holds verbatim FOR A MALFORMED SHAPE; do not weaken any of those** (Task 6's PY-WL-130 suite and Task 14's matrix depend on it). That instruction is scoped to malformed-SHAPE assertions and to nothing else. It does **not** bar the form-5 additions rev 6 requires, in which a marker whose level RESOLVES through a qualifying module constant DOES enter `declared_qualnames` and DOES move the anchored posture bucket (spec §4.2.1, §11.4). Task 14's matrix carries a row that must INVERT on exactly that distinction; inverting it is the fix, not a weakening.

There is no new **serialised** state — and that is now the whole of this line's claim. Spec §4.2.1 supersedes this line's former *no-`SeedResult` field*, *no-`FunctionSeed` field* and *no-`pipeline.py`-change* clauses **by name**: the residual FACT's carrier IS a new, **unserialised** field on both `SeedResult` and `FunctionSeed`, distinct from `unprovable_boundaries` (reusing that tuple would breach the builtin-exclusion invariant the byte-identity oracle rests on), and `pipeline.py` DOES change — it gains the per-module census build and the residual-FACT emission loop. **Neither of those edits happens in this task**: the census build is owned by Task 3 and the emission loop by Task 8, and `pipeline.py` is deliberately absent from Task 5's Files list, so a `pipeline.py` diff appearing under this task is a hard stop under the per-task path gate.

**Standing, explicitly NOT superseded: no `SUMMARY_SCHEMA_VERSION` bump.** `SUMMARY_SCHEMA_VERSION` guards `FunctionSummary`'s structural shape, the summary cache stores tuples of `FunctionSummary` and nothing else — never a `FunctionSeed`, never a `SeedResult` — and PY-WL-130 re-derives the malformed-shape verdict from the AST. The new seed-plane field is dropped at the summariser boundary exactly as `unprovable_boundaries` already is, so there is nothing for a bump to guard, and the parse pass re-derives the residual on every scan, warm or cold.

The `sp1g` → `sp1h` `_RESOLVER_VERSION` bump below covers the changed seeding semantics for **both** halves — the shape gate and P3 form 5 — and no additional epoch is needed. That is a fact about this plan's own sequencing rather than an appeal to the spec: Task 2 deliberately leaves the provider-private `_read_level` in place, and this task deletes it, imports the shared reader and bumps the epoch **in one atomic commit**, so form-5 resolution first becomes observable in the same commit that invalidates every warm summary. A second epoch becomes mandatory only if `"sp1h"` is ever published before form 5 lands.

In the same implementation step bump `_RESOLVER_VERSION` from `sp1g` to `sp1h`. In `test_summary.py`, replace the old epoch pin with `assert _RESOLVER_VERSION == "sp1h"` and `assert _key(resolver_version="sp1h") != _key(resolver_version="sp1g")`. In `test_summary_cache.py`, follow `test_warm_cache_honours_untrusted_sources_policy_change`: create one source with malformed `@trusted(level='ASSURED', audit=True)`, one `SummaryCache`, and one `WardlineAnalyzer`; analyze twice. On both runs assert `last_context.project_taints["example.f"] is T.UNKNOWN_RAW` and `"example.f" not in last_context.declared_qualnames`; compare non-METRIC finding projections for equality. After the second run assert `cache.hits > 0` and the second `WLN-ENGINE-METRICS` finding has `cache_hit_rate > 0.0`. Do not bump `SUMMARY_SCHEMA_VERSION`: the serialized summary shape is unchanged.

- [ ] **Step 4: Run to verify pass + hunt stragglers**

Run: `uv run pytest tests/unit/scanner/taint/test_decorator_provider.py tests/grammar tests/corpus tests/golden tests/grammar/test_thirdparty_pack_bridge.py -q`
Expected: PASS **except `test_malformed_sibling_never_reduces_the_error_population`, which stays RED until Task 6** — its tier assertion (`svc.f == T.ASSURED`) is satisfied by this task's gate, but its `PY-WL-130 ∈ errors` membership cannot hold before Task 6 creates the rule. It is the one deliberately cross-task test in this suite; do not weaken it to make Task 5 green, and do not mark it xfail. Everything else PASS; the third-party bridge still reports exactly two recognised boundaries. `tests/grammar/test_provider_loop.py::test_unprovable_builtin_does_not_signal` is **green here and is NOT a carried red** — Step 1 repaired it in-task with a census-carrying `SeedContext`. If it is red or errors, the Step 1 amendment was skipped; it is not deferrable to a later task, and its second half (Task 7 Step 4.6) does not substitute for it. Then run `rg -n 'external_boundary\(' tests src/wardline` and classify every called form; no test may expect it to seed. Step 1's third rewrite, **`test_module_constant_level_now_resolves_under_form5`, PASSES here and is repaired IN-TASK rather than carried**: the source it scans (`LV = 'ASSURED'` / `@trusted(level=LV)`) resolves under form 5 the moment this task threads the census and the reference site into the reader. Had Step 1 left it as the shipped `_seed`-based `test_trusted_dynamic_level_is_no_opinion` (`:201-204`) it would ERROR here with `ValueError` — a bare `Name` in a builtin LEVEL slot against `SeedContext.census is None` — and under the Unexpected-red discipline (Global Constraints) that error reads as an implementation bug in this task's `_match` rather than as the stale test premise it actually is. That is the hunt this enumeration exists to prevent.

- [ ] **Step 5: Full suite** — `uv run pytest -q`. Expected: PASS, with the single carried-forward red above (`test_malformed_sibling_never_reduces_the_error_population`, awaiting Task 6's PY-WL-130). Task 6's final green is where it first passes; verify it there before closing Task 6. `tests/grammar/test_provider_loop.py::test_unprovable_builtin_does_not_signal` is **not** on that carried list — Step 1 repaired it inside this task, and it is green from this commit on.

- [ ] **Step 6: Commit** — `fix(provider)!: call-shape validator gates seeding; remove the runtime-invalid to_level-on-@trusted tolerance (S0, wardline-4928b75782 seed half)`

---

### Task 6: PY-WL-130 — malformed builtin-marker call (the false-green fix, rule half) + the four inventory pins

**Files:**
- Create: `src/wardline/scanner/rules/malformed_marker_call.py`
- Modify: `src/wardline/scanner/rules/__init__.py` (import; append to `_ALL_RULE_CLASSES` LAST)
- Modify: `tests/grammar/test_grammar_model.py:38-65` (ordered id list)
- Modify: `tests/grammar/test_analyzer_wiring.py:15-42` (`_BUILTIN_IDS`)
- Modify: `tests/unit/scanner/rules/test_default_registry.py:41-68` (id set)
- Modify: `tests/unit/scanner/rules/test_vocabulary_shape_pin.py:54-81` (metadata table)
- Modify: `docs/concepts/rules.md` (count 27; range text `101–126 plus 130`; rule row, detail section, declaration list)
- Test: `tests/unit/scanner/rules/test_malformed_marker_call.py` (new)
- Test: `tests/unit/cli/test_false_green_exit_code_repros.py` (new — **Step 7's** hole-1 exit-code repro. Task 8 Step 9 appends hole 3's to this same module, and that path is on Task 8's Files list too; one home for both PRD-0003 criterion-1 repros, never two)

**Interfaces:**
- Consumes: `call_shape_offences`, `resolve_decorator_fqn`, `is_builtin_decorator_fqn`, `shadowed_builtin_roots` (Task 2); `BUILTIN_BOUNDARY_TYPES`; `RuleMetadata`; `compute_finding_fingerprint`.
- Sequencing: form 5 is already live (Task 5), so the two rev-6 tests in this task's suite read against a reader that resolves module constants. The residual FACT is Task 8's; see Step 6 for the one assertion that carries red if Task 8 is sequenced after this task.
- Produces: rule class `MalformedMarkerCall`, `rule_id="PY-WL-130"`, `Severity.ERROR`, `Kind.DEFECT`, `Maturity.STABLE`, `multi_emit=True`. Its charter is a **malformed or statically unverifiable builtin-marker call**. Findings carry `properties={"decorator", "offender", "reason"}` with `reason ∈ {call_not_allowed, call_required, positional_args, undeclared_kwarg, invalid_splat_key, unreadable_splat, duplicate_kwarg, missing_kwarg}` and fingerprint discriminator `taint_path=f"{name}:{offender}#{deco_ordinal}.{offence_ordinal}"`. Offender tokens discriminate the two dual-form reasons: `positional_args` is `<positional>` or `<*args>`; `unreadable_splat` is `<**splat>` from either a dynamic mapping or a computed literal key.

- [ ] **Step 1: Write the failing tests** — `tests/unit/scanner/rules/test_malformed_marker_call.py`:

```python
"""PY-WL-130 — a malformed builtin-marker call must be a loud ERROR DEFECT.

The engine drops the seed for these shapes (wardline-4928b75782): the function
falls out of declared_qualnames and every tier-modulated rule goes quiet — the
scan gets GREENER on a typo. This suite pins the rule that makes the shape red,
its agreement with seeding (fires exactly where call_shape_offences drops the
seed), and where it stays silent (well-formed calls, unreadable VALUES,
foreign/custom/shadowed markers)."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan


def _scan(tmp_path: Path, src: str):
    # Accepts a directory that may not exist yet, so a parametrized case can pass
    # `tmp_path / case` and keep each case's project tree distinct.
    proj = tmp_path / "proj"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "svc.py").write_text(src, encoding="utf-8")
    return run_scan(proj)


def _hits(result, rule_id: str = "PY-WL-130"):
    return [f for f in result.findings if f.rule_id == rule_id]


def test_undeclared_kwarg_on_trusted_fires_error(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.severity is Severity.ERROR
    assert hit.kind is Kind.DEFECT
    assert hit.properties == {"decorator": "trusted", "offender": "audit", "reason": "undeclared_kwarg"}
    # Agreement: the seed dropped (rule observes, never repairs).
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_shape_offence_with_invalid_token_is_pywl130_only(tmp_path: Path) -> None:
    # THE DISCRIMINATING HAND-OFF, and the only shape in which the gate's ordering is
    # observable: this marker is BOTH shape-malformed AND carries a readable-but-INVALID
    # token. Shipped PY-WL-114 fires on `level='ASURED'` whatever its siblings are, so
    # without Task 2 Step 3's shape gate this one site would take BOTH channels. The
    # sibling above uses a VALID token, where PY-WL-114 is silent gate or no gate.
    # The residual-FACT assertion is a FORWARD pin, trivially true until Task 8 and
    # required to stay true after it — a READS-then-rejects token never takes the FACT.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASURED', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trusted", "offender": "audit", "reason": "undeclared_kwarg"}
    assert not _hits(result, "PY-WL-114")
    assert not _hits(result, "WLN-ENGINE-UNREADABLE-MARKER-VALUE")
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_legacy_to_level_on_trusted_fires(tmp_path: Path) -> None:
    # The runtime rejects this call; the tolerance is gone (Task 5) — loud DEFECT.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', to_level='ASSURED')\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trusted", "offender": "to_level", "reason": "undeclared_kwarg"}
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_positional_arg_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n@trusted('INTEGRAL')\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties["reason"] == "positional_args"


def test_called_external_boundary_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import external_boundary\n"
        "@external_boundary()\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "external_boundary", "offender": "<call>", "reason": "call_not_allowed"}
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames  # Task 5: no more seeding through it


def test_bare_trust_boundary_fires_call_required(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trust_boundary\n@trust_boundary\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trust_boundary", "offender": "<bare>", "reason": "call_required"}


def test_zero_arg_trust_boundary_fires_missing_kwarg(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trust_boundary\n@trust_boundary()\ndef f(p):\n    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties["reason"] == "missing_kwarg"


def test_duplicate_level_via_splat_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED', **{'level': 'ASSURED'})\n"
        "def f(p):\n"
        "    return p\n",
    )
    (hit,) = _hits(result)
    assert hit.properties == {"decorator": "trusted", "offender": "level", "reason": "duplicate_kwarg"}


def test_duplicate_inside_one_literal_dict_uses_last_value(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(**{'level': 'ASURED', 'level': 'ASSURED'})\n"
        "def f(p):\n    return p\n",
    )
    assert not _hits(result)
    assert not [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames


def test_duplicate_inside_one_literal_dict_last_typo_is_pywl114(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(**{'level': 'ASSURED', 'level': 'ASURED'})\n"
        "def f(p):\n    return p\n",
    )
    assert not _hits(result)
    assert [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_literal_non_string_splat_key_is_shape_defect_only(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(**{1: 'ASSURED'})\n"
        "def f(p):\n    return p\n",
    )
    assert [f for f in result.findings if f.rule_id == "PY-WL-130"]
    assert not [f for f in result.findings if f.rule_id == "PY-WL-114"]


def test_unreadable_value_is_not_a_shape_offence(tmp_path: Path) -> None:
    # The PROPERTY survives rev 6 unchanged — a value problem is never a SHAPE
    # offence. The FIXTURE does not: `CFG = 'ASSURED'` now satisfies P3 form 5 in
    # full and RESOLVES (see the companion below), which would leave this test
    # green while exercising nothing. Re-expressed over a binding form 5
    # explicitly REFUSES — a call right-hand side (spec §4.2.1). `level=DYN` is a
    # runtime-VALID call whose value stays statically unreadable, so PY-WL-130 is
    # silent AND the residual FACT fires: unreadable is never silent.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "def get_level():\n    return 'ASSURED'\n"
        "DYN = get_level()\n"
        "@trusted(level=DYN)\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert not _hits(result)
    assert [
        f
        for f in result.findings
        if f.rule_id == "WLN-ENGINE-UNREADABLE-MARKER-VALUE"
    ]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames


def test_form5_module_constant_resolves_and_is_not_a_shape_offence(
    tmp_path: Path,
) -> None:
    # The companion, and the inversion rev 6 introduces. `CFG` is a single,
    # unconditional, direct-top-level `str` binding lexically preceding a `def`
    # that is a direct element of Module.body, read in a BUILTIN marker's LEVEL
    # slot — P3 form 5 in full. It RESOLVES: no shape offence (this rule stays
    # silent for the same reason as ever), no residual FACT (nothing stayed
    # unreadable), and the qualname ENTERS declared_qualnames (spec §4.2.1).
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\nCFG = 'ASSURED'\n@trusted(level=CFG)\ndef f(p):\n    return p\n",
    )
    assert not _hits(result)
    assert not [
        f
        for f in result.findings
        if f.rule_id == "WLN-ENGINE-UNREADABLE-MARKER-VALUE"
    ]
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames


def test_aliased_builtin_fires(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted as t\n@t(level='INTEGRAL', audit=True)\ndef f(p):\n    return p\n",
    )
    assert len(_hits(result)) == 1


def test_foreign_and_custom_markers_are_not_this_rules_concern(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import other_pkg\n@other_pkg.trusted(level='X', extra=1)\ndef f(p):\n    return p\n",
    )
    assert not _hits(result)


def test_shadowed_root_stays_silent(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / "wardline" / "decorators").mkdir(parents=True)
    (proj / "wardline" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "wardline" / "decorators" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert not _hits(result)


def test_stacked_malformed_markers_get_distinct_fingerprints(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted, external_boundary\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "@external_boundary(source='http')\n"
        "def f(p):\n"
        "    return p\n",
    )
    hits = _hits(result)
    assert len(hits) == 2
    assert len({h.fingerprint for h in hits}) == 2


def test_multi_offence_call_pins_the_canonical_phase_order(tmp_path: Path) -> None:
    # The FINGERPRINT half of the phase-order contract Task 2 Step 5 pins at reader
    # level. ``offence_ordinal`` is the ``.N`` component of ``taint_path``, so the
    # canonical order of ``call_shape_offences`` (call-form, positional, extraction
    # offences, keyword classification, missing names) is a compatibility contract:
    # reorder those phases and every multi-offence fingerprint silently reshuffles.
    # The sibling above discriminates ``deco_ordinal`` across STACKED decorators and
    # is blind to this — it is the ``.N`` on ONE call that is unpinned without this row.
    #
    # Note the order: ``audit=True`` is written BEFORE ``**KW`` in the source, but
    # extraction offences precede keyword classification, so the splat takes ordinal 1
    # and the undeclared keyword ordinal 2.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "KW = {'level': 'ASSURED'}\n"
        "@trusted('ASSURED', audit=True, **KW)\n"
        "def f(p):\n"
        "    return p\n",
    )
    hits = _hits(result)
    assert len(hits) == 3
    assert {h.properties["reason"]: h.taint_path_v0 for h in hits} == {
        "positional_args": "trusted:<positional>#0.0",
        "unreadable_splat": "trusted:<**splat>#0.1",
        "undeclared_kwarg": "trusted:audit#0.2",
    }
    assert len({h.fingerprint for h in hits}) == 3


_RUNTIME_INVALID = "invalid for the shipped runtime signature"

# (case id, source, expected reason, must the runtime-invalid clause appear?)
CLAUSE_CASES = [
    ("call_required",     "@trust_boundary\ndef f(p):\n    return p\n",                      "call_required",     True),
    ("undeclared_kwarg",  "@trusted(level='ASSURED', audit=True)\ndef f(p):\n    return p\n","undeclared_kwarg",  True),
    ("duplicate_kwarg",   "@trusted(level='A', **{'level': 'B'})\ndef f(p):\n    return p\n","duplicate_kwarg",   True),
    ("missing_kwarg",     "@trust_boundary()\ndef f(p):\n    return p\n",                    "missing_kwarg",     True),
    ("invalid_splat_key", "@trusted(**{1: 'ASSURED'})\ndef f(p):\n    return p\n",           "invalid_splat_key", True),
    # --- the four cases that must NOT carry the claim (all REPL-verified runtime-VALID) ---
    ("call_not_allowed_callable",
     "def audit(x):\n    return x\n@external_boundary(audit)\ndef f(p):\n    return p\n", "call_not_allowed", False),
    ("positional_callable",
     "def audit(x):\n    return x\n@trusted(audit)\ndef f(p):\n    return p\n",           "positional_args",  False),
    ("star_args",
     "ARGS = ()\n@trusted(*ARGS)\ndef f(p):\n    return p\n",                             "positional_args",  False),
    ("computed_splat_key",
     "@trusted(**{'lev' + 'el': 'ASSURED'})\ndef f(p):\n    return p\n",                  "unreadable_splat", False),
]


@pytest.mark.parametrize(
    ("case", "body", "reason", "claims_runtime_invalid"),
    CLAUSE_CASES, ids=[c[0] for c in CLAUSE_CASES],
)
def test_message_claims_runtime_invalidity_only_when_proved(
    tmp_path: Path, case: str, body: str, reason: str, claims_runtime_invalid: bool
) -> None:
    # Plan Global Constraints / spec §4.2: PY-WL-130 may call a shape
    # runtime-invalid ONLY for a proved runtime-invalid reason. Each False row
    # below was executed against the real decorators and did NOT raise.
    result = _scan(
        tmp_path / case,
        "from wardline.decorators import external_boundary, trust_boundary, trusted\n" + body,
    )
    hits = [h for h in _hits(result) if h.properties["reason"] == reason]
    assert hits, f"{case}: expected reason {reason}, got {[h.properties for h in _hits(result)]}"
    assert all((_RUNTIME_INVALID in h.message) is claims_runtime_invalid for h in hits), case


def test_star_args_and_computed_key_keep_the_pinned_reason_vocabulary(tmp_path: Path) -> None:
    # No new reason strings: the eight of spec §4.2 are the whole vocabulary.
    for body, reason, offender in (
        ("ARGS = ()\n@trusted(*ARGS)\ndef f(p):\n    return p\n", "positional_args", "<*args>"),
        ("@trusted(**{'lev' + 'el': 'X'})\ndef f(p):\n    return p\n", "unreadable_splat", "<**splat>"),
    ):
        result = _scan(tmp_path / reason, "from wardline.decorators import trusted\n" + body)
        (hit,) = _hits(result)
        assert hit.properties["reason"] == reason
        assert hit.properties["offender"] == offender


def test_computed_splat_key_suppresses_missing_kwarg(tmp_path: Path) -> None:
    # A computed key MAY be the required name; Wardline must not claim it is missing.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trust_boundary\n"
        "@trust_boundary(**{'to_' + 'level': 'ASSURED'})\ndef f(p):\n    return p\n",
    )
    reasons = {h.properties["reason"] for h in _hits(result)}
    assert reasons == {"unreadable_splat"}
```

- [ ] **Step 2: Run tests to verify they fail** — `uv run pytest tests/unit/scanner/rules/test_malformed_marker_call.py -v`. Expected: FAIL — no `PY-WL-130` findings. Two rev-6 tests in this file do not depend on PY-WL-130 and have their own expectations: `test_form5_module_constant_resolves_and_is_not_a_shape_offence` already PASSES here (form 5 went live in Task 5), and `test_unreadable_value_is_not_a_shape_offence` passes its shape half but its `WLN-ENGINE-UNREADABLE-MARKER-VALUE` assertion is red until Task 8's emission loop lands — see Step 6.

- [ ] **Step 3: Implement `src/wardline/scanner/rules/malformed_marker_call.py`:**

```python
# src/wardline/scanner/rules/malformed_marker_call.py
"""PY-WL-130 — builtin trust marker called with a malformed argument shape.

A builtin marker call that violates its registered bare/called form, carries a
positional argument, an undeclared or duplicated keyword, an invalid literal
** key, an unreadable ** splat, or misses a required keyword is
silently UN-DECLARED by the engine: ``call_shape_offences`` drops the seed, the
function falls out of ``declared_qualnames``, and every tier-modulated rule
goes quiet (wardline-4928b75782). This rule makes the shape a loud ERROR
DEFECT, using the SAME validator seeding uses. The diagnostic is truthful per
offence: it claims a runtime ``TypeError`` only where the shipped signatures
prove one (``call_required``, ``undeclared_kwarg``, ``duplicate_kwarg``,
``missing_kwarg``, ``invalid_splat_key``). ``unreadable_splat`` says only that
Wardline cannot statically read the mapping; ``call_not_allowed`` and
``positional_args`` state a Wardline declaration-grammar rule, because
``@external_boundary(some_callable)`` and ``@trusted(audit_fn)`` are runtime-valid
calls that are nonetheless not declarations Wardline will honour.

Deliberately NOT silenced by the builtin-stays-quiet convention: that
convention preserves the byte-identity oracle, and a NEW rule id appears in no
frozen golden. Value problems are out of scope for THIS rule, and none of them
is silence (spec §4.2.1): a bare ``Name`` satisfying P3 form 5 RESOLVES and
seeds; a readable-but-invalid token is ``PY-WL-114``'s DEFECT and takes no FACT;
and a value that stays unreadable takes the ``WLN-ENGINE-UNREADABLE-MARKER-VALUE``
FACT (``Severity.NONE``, builtin-only), never silence. SHAPE is decided first, so
a marker that is both shape-malformed and value-unreadable is rejected on shape
before its value is a question: it takes this rule alone and never also that FACT
(the drop-coverage matrix pins the partition).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.registry import REGISTRY
from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES, BoundaryType
from wardline.scanner.marker_reader import (
    alias_map_for_qualname,
    call_shape_offences,
    is_builtin_decorator_fqn,
    resolve_decorator_fqn,
    shadowed_builtin_roots,
)
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-130",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    multi_emit=True,
    description=(
        "A builtin trust marker (@external_boundary/@trust_boundary/@trusted) is "
        "used with an illegal call form, a positional argument, an undeclared "
        "or duplicated keyword, an invalid/unreadable ** splat, or without a "
        "required keyword; the engine "
        "silently drops the declaration, disabling every tier-modulated rule on "
        "the function."
    ),
    examples_violation=(
        "@trusted(level='INTEGRAL', audit=True)\ndef f(p):\n    return p",
        "@trusted('INTEGRAL')\ndef g(p):\n    return p",
        "@trusted(level='ASSURED', to_level='ASSURED')\ndef legacy(p):\n    return p",
        "@external_boundary(source='http')\ndef r(p):\n    return p",
        "@trust_boundary\ndef b(p):\n    if not p: raise ValueError\n    return p",
    ),
    examples_clean=(
        "@trusted(level='INTEGRAL')\ndef f(p):\n    return p",
        "@trusted\ndef g(p):\n    return p",
        "@trust_boundary(to_level='ASSURED')\ndef b(p):\n    if not p: raise ValueError\n    return p",
        # A foreign decorator merely spelled like a marker is not the builtin.
        "import other_pkg\n@other_pkg.trusted(level='X', extra=1)\ndef f2(p):\n    return p",
    ),
)


def _builtin_marker(
    deco: ast.expr, alias_map: Mapping[str, str], shadowed_roots: frozenset[str]
) -> BoundaryType | None:
    """The matched builtin BoundaryType iff *deco* resolves to a builtin marker
    seeding would honour (exact known export, root not shadowed)."""
    fqn = resolve_decorator_fqn(deco, alias_map)
    if fqn is None:
        return None
    for bt in BUILTIN_BOUNDARY_TYPES:
        if not bt.builtin:
            continue
        if bt.module_prefix.split(".")[0] in shadowed_roots:
            continue
        if is_builtin_decorator_fqn(fqn, bt.canonical_name, bt.module_prefix):
            return bt
    return None


class MalformedMarkerCall:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        shadowed = shadowed_builtin_roots(frozenset(context.alias_maps))
        for qualname, entity in context.entities.items():
            alias_map = alias_map_for_qualname(qualname, context.alias_maps)
            for deco_ordinal, deco in enumerate(entity.node.decorator_list):
                bt = _builtin_marker(deco, alias_map, shadowed)
                if bt is None:
                    continue
                entry = REGISTRY[bt.canonical_name]
                declared = entry.kwargs
                required = frozenset(la.arg_name for la in bt.level_args if la.default is None)
                offences = call_shape_offences(
                    deco, call_form=entry.call_form,
                    declared=declared, required=required,
                )
                for offence_ordinal, (offender, reason) in enumerate(offences):
                    # (predicate, clause). The clause is TRUTHFUL BY CONSTRUCTION: the
                    # runtime-invalid claim is asserted ONLY where a TypeError is proved
                    # from the shipped signatures in src/wardline/decorators/trust.py
                    # (each proved case verified at the REPL 2026-08-09). Plan Global
                    # Constraints + spec §4.2: "PY-WL-130 may call a shape runtime-invalid
                    # only for a proved runtime-invalid reason."
                    #
                    # NOT proved, and therefore NOT claimed:
                    #   call_not_allowed  — external_boundary(some_callable) is a VALID
                    #                       call (signature external_boundary(fn)); it is
                    #                       simply not a decorator-factory form.
                    #   positional_args   — trusted(audit_fn) is a VALID call (fn=None, /)
                    #                       and trusted(*()) binds zero arguments.
                    #   unreadable_splat  — trusted(**{'lev' + 'el': 'ASSURED'}) is VALID;
                    #                       Wardline just cannot read the mapping.
                    predicate, clause = {
                        "call_not_allowed": (
                            "is written as a call",
                            "; this marker has no decorator-factory form, so either the "
                            "call raises TypeError or the marker attaches to its argument "
                            "and this function is left with no _wardline_* attributes — "
                            "either way nothing is declared here. Write it bare",
                        ),
                        "call_required": (
                            "is written bare",
                            "; this call is invalid for the shipped runtime signature",
                        ),
                        "positional_args": (
                            "is called with a positional argument or ``*`` expansion",
                            "; a positional argument makes the marker attach to that "
                            "argument instead of to this function, leaving it with no "
                            "_wardline_* attributes (or raising TypeError if the argument "
                            "is not callable) — either way nothing is declared here. "
                            "Wardline's declaration grammar accepts keyword arguments "
                            "only (spec §4.2)",
                        ),
                        "undeclared_kwarg": (
                            f"is called with the undeclared keyword {offender!r}",
                            "; this call is invalid for the shipped runtime signature",
                        ),
                        "invalid_splat_key": (
                            "is called with a non-string constant ``**`` key",
                            "; this call is invalid for the shipped runtime signature",
                        ),
                        "unreadable_splat": (
                            "is called with a ``**`` mapping Wardline cannot statically read",
                            "; Wardline cannot statically prove this mapping satisfies the "
                            "marker grammar",
                        ),
                        "duplicate_kwarg": (
                            f"is called with keyword {offender!r} more than once",
                            "; this call is invalid for the shipped runtime signature",
                        ),
                        "missing_kwarg": (
                            f"is called without a statically-readable required "
                            f"{offender!r} argument",
                            "; this call is invalid for the shipped runtime signature",
                        ),
                    }[reason]
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            message=(
                                f"{qualname}: builtin marker @{bt.canonical_name} "
                                f"{predicate} — the engine drops this declaration "
                                f"(no seed; every tier-modulated rule is disabled on "
                                f"this function){clause}"
                            ),
                            severity=self.base_severity,
                            kind=Kind.DEFECT,
                            location=entity.location,
                            fingerprint=_fp(
                                rule_id=self.rule_id,
                                path=entity.location.path,
                                qualname=qualname,
                                # PY-WL-114's move-stable ordinal discipline (wardline-377b896a87):
                                # within-def ordinals only; offence_ordinal splits co-located offences.
                                taint_path=f"{bt.canonical_name}:{offender}#{deco_ordinal}.{offence_ordinal}",
                            ),
                            taint_path_v0=f"{bt.canonical_name}:{offender}#{deco_ordinal}.{offence_ordinal}",
                            qualname=qualname,
                            properties={"decorator": bt.canonical_name, "offender": offender, "reason": reason},
                        )
                    )
        return findings
```

`examples_clean` deliberately does NOT contain a statically-unreadable level value such as `@trusted(level=cfg.LEVEL)`. The **instruction is unchanged and reinforced** by spec rev 6 §4.2.1; only its premise has moved, and the new premise makes the exclusion matter more rather than less. Under rev 6, `@trusted(level=_SVC_LEVEL)` with a qualifying module-top-level binding now **RESOLVES** (P3 form 5), while `cfg.LEVEL` is a dotted `Attribute` deliberately held out of form 5 and is now **observable** on the `Severity.NONE` `WLN-ENGINE-UNREADABLE-MARKER-VALUE` FACT rather than silent. Observable is not exemplary: the seed still drops and every tier-modulated rule still goes quiet, so such a snippet is a fail-open construct wearing a clean label. And nothing would catch it — `tests/unit/scanner/rules/test_rule_examples_meta.py` filters to `Kind.DEFECT`, so it asserts every clean example fires zero DEFECTS of any rule and would not see the FACT at all; the exemplar would ship green with no test red. `wardline-2b2a6cddfa` is **closed in this stage** — by form 5 plus the residual FACT together, neither substituting for the other — so keeping the value out of `examples_clean` protects a fix that lands here, rather than deferring one.

- [ ] **Step 4: Register the rule.** In `src/wardline/scanner/rules/__init__.py`: add `from wardline.scanner.rules.malformed_marker_call import MalformedMarkerCall` alongside the sibling imports, and append `MalformedMarkerCall,` as the LAST entry of `_ALL_RULE_CLASSES` (:52-80) — registration order = emission order; appending preserves every frozen ordering.

Add a structural comment beside registration: this is the only rule allowed to call the builtin shape validator directly; future declaration rules must reuse this chokepoint instead of rebuilding keyword grammar.

- [ ] **Step 5: Edit the four inventory pins** (each reds until edited — run `uv run pytest tests/grammar/test_grammar_model.py tests/grammar/test_analyzer_wiring.py tests/unit/scanner/rules/test_default_registry.py tests/unit/scanner/rules/test_vocabulary_shape_pin.py -q` first to see all four fail):
  1. `tests/grammar/test_grammar_model.py:38-65` — append `"PY-WL-130",` after `"PY-WL-126",` in the ordered list.
  2. `tests/grammar/test_analyzer_wiring.py:15-42` — append `"PY-WL-130",` to `_BUILTIN_IDS` (one edit, two assertions go green).
  3. `tests/unit/scanner/rules/test_default_registry.py:41-68` — add `"PY-WL-130",` to the id set.
  4. `tests/unit/scanner/rules/test_vocabulary_shape_pin.py:54-81` — add `"PY-WL-130": (Severity.ERROR, Kind.DEFECT, Maturity.STABLE),` to `_EXPECTED_RULE_SHAPE`.

Update `docs/concepts/rules.md` in the same commit: Wardline has 27 Python rules, numbered `PY-WL-101` through `PY-WL-126` plus `PY-WL-130`; add the summary row, full rule section, and the declaration-rule inventory entry. Do not imply IDs 127–129 already ship. The new PY-WL-130 rule section must describe the **three** clause channels the rule emits — a proved runtime-invalid call, an analyzer limitation (`unreadable_splat`), and a Wardline declaration-grammar rule (`call_not_allowed`, `positional_args`) — rather than implying every malformed call is a runtime error.

- [ ] **Step 6: Run the whole gate battery for a new rule**

Run: `uv run pytest tests/unit/scanner/rules/test_malformed_marker_call.py tests/grammar tests/unit/scanner/rules/test_rule_examples_meta.py tests/unit/scanner/rules/test_discriminator_shape.py tests/unit/mcp/test_server_resources.py tests/corpus tests/golden tests/test_self_hosting.py -q`
Expected: PASS. Named criteria: every `examples_violation` fires PY-WL-130 and every `examples_clean` fires ZERO defects of ANY rule (test_rule_examples_meta); the ordinal `taint_path` satisfies the multi_emit discriminator lint; the MCP rules resource sees a non-empty description; no corpus/golden/self-host fixture fires it (census-verified).

One exception, and it is a SEQUENCING fact rather than a defect: `test_unreadable_value_is_not_a_shape_offence` asserts `WLN-ENGINE-UNREADABLE-MARKER-VALUE` is PRESENT, which cannot hold before Task 8's emission loop lands. Under the recommended numeric execution order Task 8 runs AFTER this task, so that ONE assertion is a deliberate carried red — the same cross-task discipline as `test_malformed_sibling_never_reduces_the_error_population` in Task 5, and it first passes at Task 8's green. Do not weaken it, do not mark it xfail, and do not delete it to make Task 6 green; the assertion is the only thing pinning that an unreadable value is never silent.

- [ ] **Step 7: Write PRD-0003 criterion 1's hole-1 exit-code repro — the committed artifact this task owns.** Final verification's **hole 1** end-to-end repro bullet (`wardline-4928b75782`, the ticket's scenario) READS this artifact; it does not author it, and Final verification carries no commit step, so a test produced there would never be committed. It is written HERE because this is the commit at which the exit code first moves: Task 5 dropped the malformed marker's seed and this task's `PY-WL-130` (`Severity.ERROR`) is what trips the gate. Create `tests/unit/cli/test_false_green_exit_code_repros.py`, following the shipped `tests/unit/cli/test_cli.py` idiom exactly — `from click.testing import CliRunner`, `from wardline.cli.main import cli`, one `tmp_path` project per repro. **Task 8 Step 9 appends hole 3's repro to this same module**; do not create a second one.

```python
def test_hole1_malformed_marker_call_trips_the_gate(tmp_path: Path) -> None:
    # wardline-4928b75782, the ticket's own scenario: an undeclared kwarg on a builtin
    # marker used to drop the seed SILENTLY — the function left declared_qualnames,
    # every tier-modulated rule went quiet, and the gate exited 0 on a real leak.
    # PY-WL-130 is Severity.ERROR, so the gate now trips. The assertion is on the
    # literal PROCESS EXIT CODE, which is what PRD-0003 criterion 1 reads; the mere
    # presence of a finding is a different and weaker claim.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        '@trusted(level="INTEGRAL", audit=True)\ndef leaky(p):\n    return read_raw(p)\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["scan", str(proj), "--fail-on", "ERROR"])
    assert result.exit_code == 1, result.output
```

Run: `uv run pytest tests/unit/cli/test_false_green_exit_code_repros.py -q`. Expected: **PASS**. This is a receipt rather than a TDD driver — Step 2 already recorded this task's red, and no rule-level test in Step 1 asserts a process exit code, which is the gap. **Placement rule (spec §4.2.1), non-negotiable:** the specimen lives in `tmp_path` and in **none** of `tests/corpus/fixtures` or `tests/golden/identity/corpus/*.json`, both of which auto-absorb a stray `.py` file and would convert PRD-0003 criterion 4's guard into a re-freeze. Record the before state (exit 0) from the ticket's reproduction — that is the before/after Final verification's hole-1 bullet asks the close comment to carry.

- [ ] **Step 8: Full suite** — `uv run pytest -q`. Expected: PASS, subject only to the single carried red named in Step 6, which clears at Task 8.

- [ ] **Step 9: Commit** — `feat(rules): PY-WL-130 malformed builtin-marker call is a loud ERROR, sharing seeding's shape validator (wardline-4928b75782 rule half)`

---

### Task 7: `WLN-ENGINE-UNKNOWN-MARKER` FACT + pipeline override preservation (observability half; P11a)

**Files:**
- Modify: `src/wardline/scanner/marker_reader.py` (add `unknown_vocabulary_marker`)
- Modify: `src/wardline/scanner/taint/provider.py` (`SeedResult.unknown_markers` **and** `SeedResult.unreadable_level_values`)
- Modify: `src/wardline/scanner/taint/decorator_provider.py` (`taint_for` :306-335 collects unknowns **and** unreadable builtin LEVEL values)
- Modify: `src/wardline/scanner/taint/function_level.py` (`FunctionSeed.unknown_markers` **and** `FunctionSeed.unreadable_level_values` + threading)
- Modify: `src/wardline/scanner/pipeline.py` (FACT emission after :280; override fix at :165-181)
- Test: `tests/grammar/test_unknown_marker.py` (new); `tests/unit/scanner/test_pipeline.py` (append the **three** override-preservation tests Step 4.4 writes — `test_config_source_override_preserves_unknown_markers`, `test_config_source_override_preserves_unprovable_boundaries` and `test_config_source_override_preserves_unreadable_level_values`; the second pins the pre-existing bug Step 4.4 fixes and Task 8's condition-1 ownership entry requires the third "beside its two siblings")
- Modify: `tests/grammar/test_provider_loop.py:111-120` (**Step 4.6** — the `res.unreadable_level_values` assertion and the test's now-false header comment. **The Task 7 half of the amendment Task 5 Step 1 begins**, split because the field it reads is declared in *this* task: written at Task 5 it would `AttributeError`)

**Interfaces:**
- Consumes: Task 2's `resolve_decorator_fqn`/`is_builtin_decorator_fqn`; `REGISTRY`.
- Produces: `marker_reader.unknown_vocabulary_marker(deco, alias_map, shadowed_roots) -> str | None`; `SeedResult.unknown_markers: tuple[str, ...] = ()`; `FunctionSeed.unknown_markers: tuple[str, ...] = ()`; findings `rule_id="WLN-ENGINE-UNKNOWN-MARKER"`, `Severity.NONE`, `Kind.FACT`, `properties={"marker": <fqn>, "reason": "unrecognised_vocabulary"}`. Task 9 counts these by rule_id.
- Produces (rev 6): the residual carrier `SeedResult.unreadable_level_values: tuple[tuple[str, str], ...] = ()` and the identical `FunctionSeed.unreadable_level_values: tuple[tuple[str, str], ...] = ()`, both **unserialised**, each entry an `(argument name, ast.unparse(value node))` pair. **This task DECLARES the field pair and populates it; Task 8 owns only the `pipeline.py` emission loop, the fingerprint preimage and the five soundness tests.** The split is deliberate: Step 4.2 constructs `SeedResult(..., unreadable_level_values=...)`, so the field must exist by the time Task 7 commits, one task before Task 8. `SUMMARY_SCHEMA_VERSION` still does not move — nothing here is serialised and `FunctionSummary`'s structural shape is untouched (spec §4.3).
- The pipeline's configured-source override now PRESERVES all THREE observability channels — `unprovable_boundaries`, `unknown_markers` and `unreadable_level_values` (it silently voided the FACT for config-declared sources, and the reconstruction is wholesale, so an unnamed field is erased). This is spec §4.2.1's soundness condition 1, "not voided by configuration".

- [ ] **Step 1: Write the failing tests** — `tests/grammar/test_unknown_marker.py`:

```python
"""WLN-ENGINE-UNKNOWN-MARKER — forward vocabulary skew (P11a).

When a new marker reaches an older Wardline, a decorator rooted in the vocabulary
(``wardline.decorators`` / ``weft_markers``) that THIS engine does not recognise
takes no opinion (fail-closed), never crashes, and leaves a FACT.

This is P11a only. P11b's generic TokenSetArg contract is an S2 release gate;
S3 repeats it for the Evidence domain. A LEVEL typo represents neither gate.
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan

FACT_ID = "WLN-ENGINE-UNKNOWN-MARKER"


def _scan(tmp_path: Path, src: str):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    return run_scan(proj)


def _facts(result):
    return [f for f in result.findings if f.rule_id == FACT_ID]


def test_unknown_marker_is_no_opinion_never_a_crash(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import weft_markers\n@weft_markers.audit_record\ndef write_event(e):\n    return e\n",
    )
    (fact,) = _facts(result)
    assert fact.severity is Severity.NONE
    assert fact.kind is Kind.FACT
    assert fact.properties == {"marker": "weft_markers.audit_record", "reason": "unrecognised_vocabulary"}
    assert result.context is not None
    assert "svc.write_event" not in result.context.declared_qualnames
    assert not [f for f in result.findings if f.kind is Kind.DEFECT]


def test_from_import_form_is_detected(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from weft_markers import audit_record\n@audit_record\ndef write_event(e):\n    return e\n",
    )
    (fact,) = _facts(result)
    assert fact.properties["marker"] == "weft_markers.audit_record"


def test_nested_vocabulary_path_is_observable(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import wardline.decorators.evil\n"
        "@wardline.decorators.evil.trusted(level='INTEGRAL')\n"
        "def f(p):\n"
        "    return p\n",
    )
    (fact,) = _facts(result)
    assert fact.properties["marker"] == "wardline.decorators.evil.trusted"


def test_known_marker_malformed_call_is_not_unknown(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert not _facts(result)
    assert [f for f in result.findings if f.rule_id == "PY-WL-130"]


def test_invalid_level_remains_the_separate_py_wl_114_channel(tmp_path: Path) -> None:
    # This pins channel separation; it is NOT evidence for P11b.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n"
        "@trusted(level='CONFIDENTIAL')\n"
        "def f(p):\n"
        "    return p\n",
    )
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames
    assert [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert not _facts(result)  # a KNOWN marker is never "unknown vocabulary"


def test_valid_builtin_seed_survives_beside_unknown_marker(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import weft_markers\n"
        "from wardline.decorators import trusted\n"
        "@weft_markers.audit_record\n"
        "@trusted(level='ASSURED')\n"
        "def f(p):\n    return p\n",
    )
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames
    assert len(_facts(result)) == 1


def test_shadowed_root_emits_no_fact(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / "weft_markers").mkdir(parents=True)
    (proj / "weft_markers" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "svc.py").write_text(
        "import weft_markers\n@weft_markers.audit_record\ndef f(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert not _facts(result)


def test_foreign_decorator_emits_no_fact(tmp_path: Path) -> None:
    result = _scan(tmp_path, "import functools\n@functools.cache\ndef f(p):\n    return p\n")
    assert not _facts(result)


```

Additionally, append the override-preservation tests to `tests/unit/scanner/test_pipeline.py` (it already imports `run_parse_project_stage`, `ParseProjectInput`, `WardlineConfig`, `DecoratorTaintSourceProvider`, `vocabulary_star_exports`, `T` — the `:143-161` config-source test is the idiom being extended):

```python
def test_config_source_override_preserves_unknown_markers(tmp_path) -> None:
    # The configured-source override (the FunctionSeed reconstruction below the
    # seeding call) must PRESERVE the observability channels, not void them.
    path = tmp_path / "m.py"
    path.write_text(
        "import weft_markers\n@weft_markers.audit_record\ndef feed(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(untrusted_sources=("m.feed",)),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.feed"]
    assert seed.body_taint == T.EXTERNAL_RAW  # the directive took effect...
    assert seed.unknown_markers == ("weft_markers.audit_record",)  # ...channel intact


def test_config_source_override_preserves_unprovable_boundaries(tmp_path) -> None:
    # Pre-existing bug closed by the same edit: the reconstruction hardcoded
    # unprovable_boundaries=() — a config-declared source that ALSO carried an
    # unprovable CUSTOM boundary lost its WLN-ENGINE-UNPROVABLE-BOUNDARY FACT.
    from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES, BoundaryType, LevelArg
    from wardline.scanner.taint.provider import FunctionTaint

    custom = BoundaryType(
        "sanitized",
        "myproj.trust",
        1,
        (LevelArg("to_level", frozenset({T.GUARDED, T.ASSURED}), None),),
        lambda lv: FunctionTaint(T.EXTERNAL_RAW, lv["to_level"]),
    )
    path = tmp_path / "m.py"
    path.write_text(
        "import myproj.trust\n@myproj.trust.sanitized(to_level=CFG)\ndef feed(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(boundary_types=BUILTIN_BOUNDARY_TYPES + (custom,)),
            config=WardlineConfig(untrusted_sources=("m.feed",)),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.feed"]
    assert seed.body_taint == T.EXTERNAL_RAW
    assert seed.unprovable_boundaries == ("sanitized",)


def test_config_source_override_preserves_unreadable_level_values(tmp_path) -> None:
    # Spec §4.2.1 soundness condition 1: the residual FACT must NOT be voided by
    # configuration. The override block is a wholesale FunctionSeed reconstruction,
    # so without this test the third channel can be dropped from it and nothing reds.
    # DYN has a CALL right-hand side, which form 5 explicitly refuses, so the value
    # stays unreadable; the recorded value text is ast.unparse of the LEVEL slot's
    # own node ('DYN'), never the binding's right-hand side.
    path = tmp_path / "m.py"
    path.write_text(
        "from wardline.decorators import trusted\n"
        "def get_level():\n    return 'ASSURED'\n"
        "DYN = get_level()\n"
        "@trusted(level=DYN)\ndef feed(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_parse_project_stage(
        ParseProjectInput(
            files=(path,),
            root=tmp_path,
            provider=DecoratorTaintSourceProvider(),
            config=WardlineConfig(untrusted_sources=("m.feed",)),
            star_exports=vocabulary_star_exports(),
        )
    )
    seed = result.modules[0].seeds["m.feed"]
    assert seed.body_taint == T.EXTERNAL_RAW  # the directive took effect...
    assert seed.unreadable_level_values == (("level", "DYN"),)  # ...channel intact
```

Add an inertness regression with at least five ordinary functions and one unknown marker. After the scan, assert `compute_resolution_posture(result.findings).inert is True`: a NONE/FACT observability record must not make an otherwise inert project active.

- [ ] **Step 2: Run tests to verify they fail** — `uv run pytest tests/grammar/test_unknown_marker.py -v`. Expected: FAIL — no FACT emitted.

- [ ] **Step 3: Add the detector to `marker_reader.py`:**

```python
_VOCAB_PREFIXES: tuple[str, ...] = (VOCAB_PREFIX, WEFT_MARKERS_PREFIX)


def unknown_vocabulary_marker(
    deco: ast.expr,
    alias_map: Mapping[str, str],
    shadowed_roots: frozenset[str],
) -> str | None:
    """The resolved FQN iff *deco* is vocabulary-rooted but not a recognised export.

    Vocabulary-rooted = the FQN sits strictly under ``wardline.decorators`` or
    ``weft_markers``. Exact known exports (the REGISTRY names) are excluded —
    those are recognised markers whose malformed CALLS are PY-WL-130's concern.
    Shadow-rejected roots are excluded (builtin matching is off wholesale under
    a shadow). This is the new-markers-old-wardline observability hook:
    ``@weft_markers.audit_record`` on a wardline that predates facets resolves
    here instead of vanishing. Known FN, by design: a name arriving via
    ``from weft_markers import *`` that is NOT a current REGISTRY key stays
    unresolved in the alias map (``vocabulary_star_exports`` maps only known
    names) and cannot be attributed to the vocabulary.
    """
    fqn = resolve_decorator_fqn(deco, alias_map)
    if fqn is None:
        return None
    if fqn.split(".")[0] in shadowed_roots:
        return None
    if not any(fqn.startswith(prefix + ".") for prefix in _VOCAB_PREFIXES):
        return None
    for name in REGISTRY:
        for prefix in _VOCAB_PREFIXES:
            if is_builtin_decorator_fqn(fqn, name, prefix):
                return None
    return fqn
```

(Add `from wardline.core.registry import REGISTRY` to `marker_reader.py` imports.)

- [ ] **Step 4: Thread the channel.**
  1. `provider.py` — add BOTH fields to `SeedResult` after `unprovable_boundaries` (and extend its docstring: "``unknown_markers`` carries the resolved FQNs of vocabulary-rooted decorators this engine does not recognise — surfaced as ``WLN-ENGINE-UNKNOWN-MARKER`` FACTs. Builtin malformed-CALL loudness lives in PY-WL-130 (a rule), so builtins still never appear in ``unprovable_boundaries``. ``unreadable_level_values`` carries ``(argument name, ast.unparse(value node))`` for every BUILTIN ``ArgKind.LEVEL`` value the shared reader could not read after P3 form 5 — surfaced as ``WLN-ENGINE-UNREADABLE-MARKER-VALUE`` FACTs. It is builtin-only: a CUSTOM boundary's unreadable level value stays in ``unprovable_boundaries``, so no site is reported on two channels. Neither field is serialised — the summary cache stores ``FunctionSummary`` tuples only."):

```python
    unknown_markers: tuple[str, ...] = ()
    unreadable_level_values: tuple[tuple[str, str], ...] = ()
```

  2. `decorator_provider.py` `taint_for` (:306-335) — add the `unknown` list AND the `unreadable_levels` list, collect both in the decorator loop, and add `unknown_markers=tuple(unknown)` **and** `unreadable_level_values=tuple(unreadable_levels)` to BOTH `SeedResult(...)` constructions (:320 and :335). Import `unknown_vocabulary_marker` from `marker_reader`. **The rev-3.4 pin "nothing else in `taint_for` changes — Task 4 does not touch this function" is withdrawn** (spec rev 6 §4.2.1; that pin's "Task 4" is **Task 5** at rev 3.5): Task 5 Step 3 also re-cuts this function, threading `entity.node` (the form-5 reference site) and the per-module census down into `_match` and widening `_match`'s verdict to three elements. The two tasks touch **disjoint statements** of the same function — Task 5 owns the `self._match(...)` call and its argument list, this step owns the collecting arms and the two `SeedResult(...)` constructions — so neither is "the sole place `taint_for` changes".

```python
        unknown: list[str] = []
        unreadable_levels: list[tuple[str, str]] = []
        shadowed_roots = _shadowed_builtin_roots(ctx.project_modules)
        for deco in entity.node.decorator_list:
            # ``_match``'s argument list and its THREE-element verdict are Task 5
            # Step 3's; that step governs the exact spelling. This step changes only
            # the unpacking and adds the fourth arm below.
            ft, unprov, unreadable = self._match(
                deco, ctx.alias_map, shadowed_roots, census=ctx.census, reference_site=entity.node
            )
            if ft is not None:
                candidates.append(ft)
            elif unprov is not None:
                # A CUSTOM BoundaryType's unreadable level value stays HERE: it keeps
                # WLN-ENGINE-UNPROVABLE-BOUNDARY and its UNKNOWN_RAW seed and NEVER
                # enters the residual list. One unreadable value takes exactly one
                # channel, which is what keeps decorator_coverage from counting the
                # same site twice (spec §4.2.1, soundness condition 5).
                unprovable.append(unprov)
            else:
                marker = unknown_vocabulary_marker(deco, ctx.alias_map, shadowed_roots)
                if marker is not None:
                    unknown.append(marker)
                elif unreadable:
                    # FOURTH ARM — a BUILTIN marker whose ArgKind.LEVEL value the shared
                    # reader could not read after P3 form 5. Mutually exclusive with the
                    # unknown probe by construction, not by precedence: the marker
                    # resolved to an exact REGISTRY export, so unknown_vocabulary_marker
                    # returned None for it. The population is what SURVIVES the shape
                    # gate — Task 5 runs call_shape_offences BEFORE the levels loop, so a
                    # shape-malformed marker drops its seed with no level read and takes
                    # PY-WL-130, never this arm.
                    unreadable_levels.extend(unreadable)
```

  3. `function_level.py` — add `unknown_markers: tuple[str, ...] = ()` **and** `unreadable_level_values: tuple[tuple[str, str], ...] = ()` to `FunctionSeed` (docstring: the same two sentences as SeedResult) and `unknown_markers=res.unknown_markers,` **plus** `unreadable_level_values=res.unreadable_level_values,` to both `FunctionSeed(...)` constructions in `seed_function_taints` (:61, :69).
  4. `pipeline.py` — FIX the configured-source override (:165-181): the wholesale reconstruction dropped `unprovable_boundaries` (voiding the UNPROVABLE FACT for config-declared sources) and would drop `unknown_markers` and `unreadable_level_values` the same way — which is precisely how spec §4.2.1's soundness condition 1 ("not voided by configuration") fails, on the population under the most explicit operator scrutiny. Replace the `seeds[ent.qualname] = FunctionSeed(...)` block with:

```python
                    original = seeds[ent.qualname]
                    seeds[ent.qualname] = FunctionSeed(
                        qualname=ent.qualname,
                        body_taint=TaintState.EXTERNAL_RAW,
                        return_taint=TaintState.EXTERNAL_RAW,
                        source="provider",
                        # The directive overrides the TAINT, never the observability
                        # channels. ALL THREE survive it — an unprovable custom boundary,
                        # an unknown marker, and an unreadable BUILTIN LEVEL value on a
                        # config-declared source each still surface their FACT. This is a
                        # WHOLESALE reconstruction: any field NOT named here is erased, so
                        # a fourth channel added later must be added here in the same
                        # change (spec §4.2.1, soundness condition 1).
                        unprovable_boundaries=original.unprovable_boundaries,
                        unknown_markers=original.unknown_markers,
                        unreadable_level_values=original.unreadable_level_values,
                    )
```

  5. `pipeline.py` — directly after the `unprovable_boundaries` FACT loop (after :280), same indent:

```python
            for marker in fn_seed.unknown_markers:
                parse_findings.append(
                    Finding(
                        rule_id="WLN-ENGINE-UNKNOWN-MARKER",
                        message=(
                            f"{ent.qualname}: decorator @{marker} is Wardline vocabulary this "
                            f"engine does not recognise — no opinion taken (newer weft-markers "
                            f"than wardline?)"
                        ),
                        severity=Severity.NONE,
                        kind=Kind.FACT,
                        location=ent.location,
                        fingerprint=_fp("WLN-ENGINE-UNKNOWN-MARKER", ent.qualname, marker),
                        qualname=ent.qualname,
                        properties={"marker": marker, "reason": "unrecognised_vocabulary"},
                    )
                )
```

(`_fp` here is pipeline.py's own positional NUL-join sha256 helper at `:32` — NOT `compute_finding_fingerprint`; this matches the sibling FACT's style exactly.)

  6. `tests/grammar/test_provider_loop.py` — the **Task 7 half** of the two-task amendment named in Task 8's **Sequencing note**. **Task 5 Step 1** already re-cut `test_unprovable_builtin_does_not_signal` (`:111-120`) to construct a census-carrying `SeedContext` and kept its two existing assertions; this sub-item appends the third, which could not compile before now because `SeedResult.unreadable_level_values` is declared in sub-item 1 above:

```python
    assert res.unreadable_level_values == (("to_level", "CFG"),)
```

  In the same edit correct the test's now-false header comment at `:112` — "an unreadable BUILTIN level stays silent (no signal)" — to say that the builtin channel is `WLN-ENGINE-UNREADABLE-MARKER-VALUE` and that what stays silent is only the *unprovable-boundary* channel, which §4.2's compatibility boundary requires. **Rename nothing**: the test's subject is still that channel. This mirrors what Task 8 Step 6 does for the sibling `test_unprovable_boundary.py` test, and it belongs here rather than in Task 5 because the comment only becomes false when this assertion lands. No new run path is needed — Step 6's `tests/grammar` already covers this module.

- [ ] **Step 5: Record both deferred P11b lifetimes on their owning tickets.** Run:

```bash
filigree --actor codex add-comment wardline-1c0524c578 \
  "P11b generic release gate (S2): before @sensitive(marks=...) emits, an unknown Sensitivity token must make the whole declaration unreadable. The generic TokenSetArg reader lands here; a LEVEL-token test is not a proxy. S0 Task 7 closes P11a only."
filigree --actor codex add-comment wardline-b9d70c6a3a \
  "P11b Evidence integration repeat (S3): before @restoration_boundary(evidence=...) emits, an unknown Evidence token must make the whole declaration unreadable through the existing TokenSetArg reader. A LEVEL-token test is not a proxy."
```

- [ ] **Step 6: Run tests to verify they pass** — `uv run pytest tests/grammar/test_unknown_marker.py tests/unit/scanner/test_pipeline.py tests/grammar tests/unit/scanner/taint -q`. Expected: PASS (no fixture carries an unknown marker; FACTs are maturity-STABLE but the identity corpus excludes FACTs by construction — the byte oracle is a stream over corpus fixtures which contain none of these shapes).

- [ ] **Step 7: Full suite** — `uv run pytest -q`. Expected: PASS, **with the single carried-forward red inherited from Task 6** — `test_unreadable_value_is_not_a_shape_offence`'s `WLN-ENGINE-UNREADABLE-MARKER-VALUE` assertion, in `tests/unit/scanner/rules/test_malformed_marker_call.py`, a file this task does not name and must not touch. It awaits Task 8's emission loop and first passes at Task 8's own full-suite green (**Step 12** after this revision's renumber; Task 6 Step 6 records the same sequencing fact). Do not weaken, xfail or delete it, and do not treat it as an Unexpected-red STOP: it is announced here for exactly that reason.

- [ ] **Step 8: Commit** — `feat(engine): preserve unknown-marker observability and close P11a (wardline-4928b75782)`

---

### Task 8: `WLN-ENGINE-UNREADABLE-MARKER-VALUE` — residual-FACT emission, fingerprint, and the five soundness conditions (§4.2.1)

**Files:**
- Modify: `src/wardline/scanner/pipeline.py` (second FACT emission loop directly after Task 7's unknown-marker loop; add `import unicodedata`)
- Test: `tests/grammar/test_unreadable_marker_value.py` (new)
- Test: `tests/unit/core/test_suppression.py` (append the condition-3 guard; add `Waiver` to the existing `wardline.core.waivers` import and `build_baseline_document` to the `wardline.core.baseline` import)
- Test: `tests/unit/scanner/taint/test_summary_cache.py` (append the warm-cache re-derivation pin, following `test_warm_cache_honours_untrusted_sources_policy_change` at `:170`)
- Test: `tests/grammar/test_unprovable_boundary.py` (additive amendment to `test_unprovable_builtin_emits_no_fact` at `:72`)
- Test: `tests/unit/scanner/test_marker_reader_agreement.py` (**Step 7** — APPEND `test_form5_agreement`, P9's both-sides receipt. Task 2's module is EXTENDED, never duplicated; this task is its sole executor because it is the first commit at which both the census and the FACT exist)
- Test: `tests/unit/scanner/rules/test_rule_examples_meta.py` (**Step 8** — the all-rules `examples_clean` guard **Task 2 Step 3** delegates to "the task that ships that FACT")
- Test: `tests/unit/cli/test_false_green_exit_code_repros.py` (**Step 9** — APPEND hole 3's exit-code repro to the module Task 6 Step 7 creates; one home for both PRD-0003 criterion-1 repros, never two)

**Deliberately NOT modified, so the staged-path list above is exact (the per-task path gate makes any other changed path a hard stop):** `src/wardline/scanner/taint/provider.py` and `src/wardline/scanner/taint/function_level.py` — the carrier fields are declared *and* populated in Task 7, because Task 7's fourth `taint_for` arm writes them and its commit must compile with them present. `src/wardline/scanner/taint/module_summariser.py` — its summariser builds each `FunctionSummary` from that dataclass's seven named fields (`:60-73`) and therefore drops every other seed field *implicitly*, `unprovable_boundaries` included; there is no dropping code to add for the new field, and adding any would be the wrong fix. Step 5's warm-cache pin is what forbids the wrong fix; a "did the constant move" assertion would not catch it.

**Interfaces:**
- Consumes: Task 7's `SeedResult.unreadable_level_values: tuple[tuple[str, str], ...] = ()` and the identical `FunctionSeed` field, populated by Task 7's fourth `taint_for` arm out of Task 5's widened `_match` verdict. Each element is `(argument name, ast.unparse(value node))` and the value text arrives **raw** — un-normalised, untruncated. Task 3's per-module census is consumed only transitively: it is what makes the reader's RESOLVES-versus-`None` split well-defined, and therefore what makes this population well-defined.
- Produces: findings `rule_id="WLN-ENGINE-UNREADABLE-MARKER-VALUE"`, `Severity.NONE`, `Kind.FACT`, `location=ent.location`, `qualname=ent.qualname`, `properties={"argument": <arg name>, "value": <value key>, "reason": "unreadable_level_value"}`, and `fingerprint=_fp("WLN-ENGINE-UNREADABLE-MARKER-VALUE", ent.qualname, <arg name>, <value key>)`, where `<value key>` is the NFC-normalised, first-200-character truncation of the carrier's raw value text. **One text, not two**: the same `<value key>` appears in the message, in `properties["value"]` and as the fingerprint's fourth part, so what a reader sees *is* the preimage's fourth part and there is no second rendering to reconcile. Task 9 counts these by `rule_id`.
- Produces, equally: **the carrier's contract**, which is this task's to pin even though Task 7 declares the fields — the field is unserialised, never reaches `FunctionSummary`, and `SUMMARY_SCHEMA_VERSION` does not move (§4.3). Task 5's re-cut of the no-serialised-state paragraph preserves the no-bump clause verbatim; this task is where that clause acquires a test.

**Sequencing note — the second of the two grammar-test amendments is not this task's, and must not be.** `tests/grammar/test_unprovable_boundary.py::test_unprovable_builtin_emits_no_fact` runs through `analyzer.analyze`, so its census is built by the real parse loop and its one assertion (no `WLN-ENGINE-UNPROVABLE-BOUNDARY` on a builtin) stays true forever; it never reds, it merely acquires a false comment and a missing assertion, so the additive amendment belongs here. `tests/grammar/test_provider_loop.py::test_unprovable_builtin_does_not_signal` (`:111`) is different in kind: it calls `provider.taint_for(ent, SeedContext(module="m", alias_map=alias_map))` over `@trust_boundary(to_level=CFG)` — a bare `Name` in a LEVEL slot with **no census present**, which is §4.2.1's plumbing-defect **raise**, not an ordinary unreadable. That test therefore goes RED at **Task 5's** commit, the commit that makes the census a required reader input — and its amendment is **split across two tasks, because a single-task fix does not execute**. **Task 5 Step 1** constructs a `SeedContext` carrying an explicit per-module census built with Task 3's `build_module_census`, and keeps `res.taint is None` and `res.unprovable_boundaries == ()` — both still true and both required by §4.2's compatibility boundary; that half must land in Task 5 or Task 5 commits red. **Task 7 Step 4.6** appends `res.unreadable_level_values == (("to_level", "CFG"),)`, which cannot be written any earlier: `SeedResult.unreadable_level_values` is declared in Task 7 — on its Files list, in its *Produces (rev 6)* entry, and in its **Step 4** sub-items 1 (`provider.py`) and 3 (`function_level.py`) — so at Task 5 the assertion would raise `AttributeError` rather than pass. `tests/grammar/test_provider_loop.py` is on **both** tasks' Files lists for that reason, and neither task may carry the other's half — this task carries neither.

**The five soundness conditions, each with its owner and its named test.** None of the five is discharged by prose; §4.2.1 makes them normative because a fact-only residual is unsound without all five.
1. **Not voided by configuration** — owner **Task 7**, Step 4.4: the `untrusted_sources` override reconstructs `FunctionSeed` wholesale (`pipeline.py:170-181`) and erases any field it does not name, so the third channel joins the reconstruction and its frozen comment, pinned by `test_config_source_override_preserves_unreadable_level_values` beside its two siblings.
2. **Not inertness-clearing** — owner **this task**, `test_residual_fact_does_not_de_inert_a_scan` (Step 1).
3. **Not suppressible** — owner **this task**, three named guards (Step 4). Read Step 4's preamble before writing a line of code: there is **no implementation** here.
4. **Distinct fingerprint** — owner **this task**, three tests in Step 1: `test_two_unreadable_arguments_on_one_function_are_distinct`, `test_fingerprint_preimage_is_nfc_normalised_and_truncated` (which recomputes the preimage through the shipped `_fp` rather than asserting a frozen hex string), and `test_two_spellings_of_one_value_text_share_one_fingerprint`.
5. **Counted in `decorator_coverage`** — owner **Task 9**, as a seventh sibling summary key beside the six, landed inside Task 9's single already-sanctioned `mcp_output_schemas.golden.json` re-freeze. It must not become a second re-freeze — the Global Constraints permit exactly two in all of S0, and §12's per-kind rekey/re-freeze allowance is untouched because revision 6 introduces no declaration kind. The key's name is fixed by §4.2.1 condition 5's derivation (named from the rule id by the same rule that names the unknown-marker key from `WLN-ENGINE-UNKNOWN-MARKER`, with a report field mirroring `unknown_marker_count`, and one name across all four surfaces); this task does not mint it, and Task 9's schema block is `additionalProperties: False`, so it goes into both `properties` and `required`.

**The ruled ordering, stated once here so no step has to infer it.** Task 5 inserts `call_shape_offences` **before** the levels loop, so a builtin marker whose call shape is malformed never reaches the value reader: the site takes `PY-WL-130` and takes **no** residual FACT. This is not an exception carved out of §4.2.1's verdict vocabulary — it is a case that never enters it, the marker having been rejected on shape before its value was a question. Write it that way. **Do not describe the ordering as "strictly louder" or as "losing nothing"**, and do not let the rev-3.4 note's use of "strictly louder" — which is about a different change, the malformed-marker seed drop — migrate here. `PY-WL-130` is a `Kind.DEFECT` and is therefore suppressible; a waived `PY-WL-130` leaves that site with **no signal at all**, because no FACT was ever emitted. The justification is noise-avoidance plus the shipped **secure default** — under `trust_suppressions=False`, `run_scan` rebuilds `gate_population_findings` with an empty `Baseline`, an empty `WaiverSet` and `judged=None`, so a waived or baselined `PY-WL-130` still trips `--fail-on`, and the site loses its signal only under an explicit `--trust-suppressions` operator decision — not dominance. **Do not justify it on §12's P13 waiver ceiling**; spec rev 9 §4.2.1 replaces rev 8's clause that did. P13 is a **repository-scoped** bound on how many suppressions a repository may hold, which says nothing about whether this particular one was reviewed, and it must not be asked to carry this concession alone. **And state the residual risk rather than arguing it away**, which §4.2.1 makes an obligation on the text and not a nicety: with `--trust-suppressions` in force and `PY-WL-130` waived, the site retains only a *waived, non-gating* DEFECT — `apply_suppressions` annotates rather than removes, so `suppressed=WAIVED` stays visible in output — and it therefore has **no gate-eligible signal and no unsuppressible one**, the FACT having been short-circuited before it could be emitted. That is the price of the ordering; it is bounded to an explicit operator opt-in over an explicitly waived ERROR, and it is recorded rather than covered over.

- [ ] **Step 1: Write the failing tests** — `tests/grammar/test_unreadable_marker_value.py`:

```python
"""WLN-ENGINE-UNREADABLE-MARKER-VALUE — the residual channel for a builtin
marker's statically unreadable LEVEL value (spec §4.2.1).

P3 form 5 resolves a same-file, module-level, one-hop value reference in a
BUILTIN marker's LEVEL slot on a module-top-level ``def``/``async def``.
Everything form 5 refuses stays unreadable — and becomes OBSERVABLE rather than
silent. Both halves ship; neither substitutes for the other.

Channel discipline pinned here:
  * unreadable builtin LEVEL value   -> this FACT (Severity.NONE, never gates)
  * readable-but-invalid token       -> PY-WL-114 DEFECT, and NO fact
  * malformed CALL SHAPE             -> PY-WL-130, and NO fact (the shape gate
                                        short-circuits before any level is read)
  * unreadable CUSTOM level value    -> WLN-ENGINE-UNPROVABLE-BOUNDARY, unchanged
                                        by revision 6, and NEVER also this FACT
One unreadable value takes exactly one channel, which is what keeps the
decorator_coverage count (Task 9) from double-counting a site.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

from wardline.core.finding import Kind, Severity
from wardline.core.resolution_posture import compute_resolution_posture
from wardline.core.run import run_scan
from wardline.scanner.pipeline import _fp

FACT_ID = "WLN-ENGINE-UNREADABLE-MARKER-VALUE"
_IMPORT = "from wardline.decorators import trusted\n"


def _scan(tmp_path: Path, src: str):
    proj = tmp_path / "proj"
    proj.mkdir(parents=True)
    (proj / "svc.py").write_text(src, encoding="utf-8")
    return run_scan(proj)


def _facts(result):
    return [f for f in result.findings if f.rule_id == FACT_ID]


# Every shape form 5 refuses, from the §4.2.1 case table. Each row must produce
# exactly ONE fact, and — audit gap, pinned deliberately — that fact must carry a
# SOURCE LINE. tests/grammar/test_output_determinism.py filters to Kind.DEFECT
# today, so a ``line_start is None`` here would be invisible; this is the pin that
# makes widening that filter safe rather than a surprise.
_UNREADABLE = [
    pytest.param(
        _IMPORT + "def get_level():\n    return 'ASSURED'\n"
        "@trusted(level=get_level())\ndef f(p):\n    return p\n",
        "svc.f", "level", "get_level()", id="call",
    ),
    pytest.param(
        _IMPORT + "X = 'ASS'\n@trusted(level=f'{X}URED')\ndef f(p):\n    return p\n",
        "svc.f", "level", "f'{X}URED'", id="fstring",
    ),
    pytest.param(
        _IMPORT + "import os\n@trusted(level=os.environ['LVL'])\ndef f(p):\n    return p\n",
        "svc.f", "level", "os.environ['LVL']", id="subscript",
    ),
    pytest.param(
        _IMPORT + "A = 'ASSURED'\nB = A\n@trusted(level=B)\ndef f(p):\n    return p\n",
        "svc.f", "level", "B", id="two_hop",
    ),
    pytest.param(
        _IMPORT + "N = 3\n@trusted(level=N)\ndef f(p):\n    return p\n",
        "svc.f", "level", "N", id="non_str_constant",
    ),
    pytest.param(
        _IMPORT + "@trusted(level=LATE)\ndef f(p):\n    return p\nLATE = 'ASSURED'\n",
        "svc.f", "level", "LATE", id="binding_after_the_def",
    ),
    pytest.param(
        _IMPORT + "import sys\nX = 'INTEGRAL'\nif sys.platform == 'win32':\n    X = 'ASSURED'\n"
        "@trusted(level=X)\ndef f(p):\n    return p\n",
        "svc.f", "level", "X", id="two_occurrences",
    ),
    pytest.param(
        _IMPORT + "X = 'ASSURED'\ndef g():\n    global X\n@trusted(level=X)\ndef f(p):\n    return p\n",
        "svc.f", "level", "X", id="global_poisons_the_name",
    ),
    pytest.param(
        _IMPORT + "X = 'ASSURED'\nclass C:\n    @trusted(level=X)\n    def m(self, p):\n        return p\n",
        "svc.C.m", "level", "X", id="method_reference_site",
    ),
    pytest.param(
        _IMPORT + "import sys\nX = 'ASSURED'\nif sys.version_info >= (3, 12):\n"
        "    @trusted(level=X)\n    def f(p):\n        return p\n",
        "svc.f", "level", "X", id="conditionally_defined_def",
    ),
    # Pins §4.2.1's `X: Final` (AnnAssign, no value) case-table row, and it is the one
    # row COUPLED to Task 3: it is UNREADABLE-and-FACT either way, but only if Task 3's
    # builder counts a valueless AnnAssign as a census OCCURRENCE is it unreadable for
    # the stated reason rather than merely unbound. If Task 3 skips such nodes, fix
    # Task 3 — do not delete this row.
    pytest.param(
        _IMPORT + "from typing import Final\nX: Final\n@trusted(level=X)\ndef f(p):\n    return p\n",
        "svc.f", "level", "X", id="annassign_without_a_value",
    ),
    pytest.param(
        _IMPORT + "from unknownpkg import *\nX = 'ASSURED'\n@trusted(level=X)\ndef f(p):\n    return p\n",
        "svc.f", "level", "X", id="star_import_poisons_the_module",
    ),
    pytest.param(
        "from wardline.decorators import trust_boundary\n@trust_boundary(to_level=CFG)\n"
        "def f(p):\n    return p\n",
        "svc.f", "to_level", "CFG", id="unbound_name_on_to_level",
    ),
]


@pytest.mark.parametrize(("src", "qualname", "arg", "value"), _UNREADABLE)
def test_every_unreadable_shape_is_observable_and_carries_a_source_line(
    tmp_path: Path, src: str, qualname: str, arg: str, value: str
) -> None:
    result = _scan(tmp_path, src)
    (fact,) = _facts(result)
    assert fact.severity is Severity.NONE
    assert fact.kind is Kind.FACT
    assert fact.qualname == qualname
    assert fact.properties == {"argument": arg, "value": value, "reason": "unreadable_level_value"}
    assert fact.location.line_start is not None  # never a lineless FACT
    # The seed dropped, so the function is NOT in the declared set — the FACT is
    # the honest record of that, not a substitute for it.
    assert result.context is not None
    assert qualname not in result.context.declared_qualnames


def test_form_5_resolution_emits_no_fact_and_enters_the_declared_set(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        _IMPORT + "_SVC_LEVEL = 'ASSURED'\n@trusted(level=_SVC_LEVEL)\ndef f(p):\n    return p\n",
    )
    assert not _facts(result)
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames


def test_readable_but_invalid_token_is_py_wl_114_and_takes_no_fact(tmp_path: Path) -> None:
    # READS, then rejects: the name->token hop succeeded and the allow-check failed,
    # so the louder DEFECT is the channel. The residual FACT must NOT stack on it.
    result = _scan(
        tmp_path,
        _IMPORT + "_SVC_LEVEL = 'ASURED'\n@trusted(level=_SVC_LEVEL)\ndef f(p):\n    return p\n",
    )
    assert [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert not _facts(result)


def test_shape_offence_short_circuits_the_value_reader(tmp_path: Path) -> None:
    # THE ORDERING PIN. call_shape_offences runs before the levels loop (Task 5), so
    # a marker that is BOTH shape-malformed AND value-unreadable never reaches the
    # reader: PY-WL-130 fires and no FACT is emitted. This is the only assertion in
    # the area that is positive AND negative, and it is the one that pins the
    # short-circuit. Note honestly what the ordering costs: PY-WL-130 is a DEFECT and
    # is therefore suppressible, so a waived PY-WL-130 leaves this site with no signal
    # at all. Neither channel dominates the other.
    result = _scan(
        tmp_path,
        _IMPORT + "def get_level():\n    return 'ASSURED'\n"
        "@trusted(level=get_level(), audit=True)\ndef f(p):\n    return p\n",
    )
    assert [f for f in result.findings if f.rule_id == "PY-WL-130"]
    assert not _facts(result)


def test_custom_boundary_unreadable_level_never_takes_the_residual_fact(tmp_path: Path) -> None:
    # §4.2's compatibility boundary: revision 6 changes nothing on the custom side.
    # The released channel stands and the residual FACT is builtin-only, so no site
    # is reported twice or counted twice in decorator_coverage. Built through
    # build_analyzer/default_grammar().extend(...) — the idiom in
    # tests/grammar/test_unprovable_boundary.py:35 — because run_scan takes no
    # grammar, and a test is never a reason to widen run_scan's signature.
    from wardline.core.config import WardlineConfig
    from wardline.core.taints import TaintState as T
    from wardline.scanner.analyzer import build_analyzer
    from wardline.scanner.grammar import BoundaryType, LevelArg, default_grammar
    from wardline.scanner.taint.provider import FunctionTaint

    custom = BoundaryType(
        canonical_name="sanitized",
        module_prefix="myproj.trust",
        group=1,
        level_args=(LevelArg("to_level", frozenset({T.GUARDED, T.ASSURED}), None),),
        seed=lambda lv: FunctionTaint(T.EXTERNAL_RAW, lv["to_level"]),
        builtin=False,
    )
    f = tmp_path / "m.py"
    f.write_text(
        "import myproj.trust\n@myproj.trust.sanitized(to_level=get())\n"
        "def g(p):\n    return p\n",
        encoding="utf-8",
    )
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(custom,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    assert [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]
    assert not [x for x in findings if x.rule_id == FACT_ID]


def test_two_unreadable_arguments_on_one_function_are_distinct(tmp_path: Path) -> None:
    # §4.2.1 condition 4's distinctness claim, stated to match the preimage exactly:
    # the registry's two LEVEL keywords give the cross-marker case for free.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted, trust_boundary\n"
        "def a():\n    return 'ASSURED'\n"
        "@trusted(level=a())\n@trust_boundary(to_level=a())\ndef f(p):\n    return p\n",
    )
    facts = _facts(result)
    assert len(facts) == 2
    assert len({f.fingerprint for f in facts}) == 2
    assert {f.properties["argument"] for f in facts} == {"level", "to_level"}


def test_fingerprint_preimage_is_nfc_normalised_and_truncated(tmp_path: Path) -> None:
    # The preimage is the SHIPPED pipeline._fp over four ordered parts —
    # (rule id, qualname, argument name, value key) — mirroring the sibling FACT's
    # part shape widened by one, with NO relpath part. NFC and the 200-character
    # truncation apply to the FOURTH PART ONLY, before it becomes a part, never to
    # the joined preimage. No new helper exists or is wanted.
    long_expr = "get('" + "z" * 400 + "')"
    result = _scan(
        tmp_path,
        _IMPORT + "def get(k):\n    return k\n"
        f"@trusted(level={long_expr})\ndef f(p):\n    return p\n",
    )
    (fact,) = _facts(result)
    key = unicodedata.normalize("NFC", long_expr)[:200]
    assert len(fact.properties["value"]) == 200
    assert fact.properties["value"] == key
    assert fact.fingerprint == _fp(FACT_ID, "svc.f", "level", key)


def test_two_spellings_of_one_value_text_share_one_fingerprint(tmp_path: Path) -> None:
    # NFC, per §4.2.1 condition 4, following §11.1's declarations-digest encoding:
    # two spellings of one text must not mint two fingerprints. The variation has to
    # ride a STRING LITERAL inside the value expression, NOT an identifier — CPython
    # NFKC-normalises identifiers at parse time, so an identifier pair would pass
    # without our normalisation ever running, which is a test that proves nothing.
    composed = "\u00c5"        # LATIN CAPITAL LETTER A WITH RING ABOVE
    decomposed = "A\u030a"     # LATIN CAPITAL LETTER A + COMBINING RING ABOVE
    fps = set()
    for i, spelling in enumerate((composed, decomposed)):
        result = _scan(
            tmp_path / f"v{i}",
            _IMPORT + "def get(k):\n    return k\n"
            f"@trusted(level=get('{spelling}'))\ndef f(p):\n    return p\n",
        )
        (fact,) = _facts(result)
        fps.add(fact.fingerprint)
    assert len(fps) == 1


def test_residual_fact_does_not_de_inert_a_scan(tmp_path: Path) -> None:
    # §4.2.1 condition 2. A residual entity is not a provider-seeded row, does not
    # move the posture denominator, and must not arm an otherwise inert project —
    # mirroring §4.3's unknown-marker contract. Only successful resolution moves it.
    body = "".join(f"def q{i}(p):\n    return p\n" for i in range(5))
    result = _scan(
        tmp_path,
        _IMPORT + body + "def get_level():\n    return 'ASSURED'\n"
        "@trusted(level=get_level())\ndef f(p):\n    return p\n",
    )
    assert len(_facts(result)) == 1
    assert compute_resolution_posture(result.findings).inert is True
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames
```

(`from wardline.scanner.pipeline import _fp` is deliberate: the fingerprint test recomputes the preimage through the **shipped** helper rather than freezing a hex string, so the test states the preimage rather than memorising an output. It is the only private import in the module.)

- [ ] **Step 2: Run to verify they fail** — `uv run pytest tests/grammar/test_unreadable_marker_value.py -v`. Expected: every parametrised row FAILS on `ValueError: not enough values to unpack` (no FACT emitted), and so do `test_two_unreadable_arguments_on_one_function_are_distinct`, `test_fingerprint_preimage_is_nfc_normalised_and_truncated`, `test_two_spellings_of_one_value_text_share_one_fingerprint` and `test_residual_fact_does_not_de_inert_a_scan`, all for the same reason. Four already PASS — `test_form_5_resolution_emits_no_fact_and_enters_the_declared_set`, `test_readable_but_invalid_token_is_py_wl_114_and_takes_no_fact`, `test_shape_offence_short_circuits_the_value_reader` and `test_custom_boundary_unreadable_level_never_takes_the_residual_fact`. Those four are no-regression pins on behaviour Tasks 3–7 already landed, and each passes today only because no FACT exists at all; **they are not evidence and must be re-read after Step 3**, when their negative assertions first have something to exclude.

- [ ] **Step 3: Implement the emission loop.** Add `import unicodedata` beside `import hashlib` in `pipeline.py`, then insert directly after Task 7's `unknown_markers` loop, same indent, inside the same `for ent in entities:` block:

```python
            for arg_name, value_text in fn_seed.unreadable_level_values:
                # NFC + 200-char truncation apply to the VALUE TEXT ONLY, before it
                # becomes a part — never to the joined preimage. The same key is the
                # message text, the property and the fingerprint's fourth part, so
                # output and identity cannot drift apart.
                value_key = unicodedata.normalize("NFC", value_text)[:200]
                parse_findings.append(
                    Finding(
                        rule_id="WLN-ENGINE-UNREADABLE-MARKER-VALUE",
                        message=(
                            f"{ent.qualname}: builtin marker argument {arg_name}={value_key} "
                            f"is not statically readable — no seed taken, so this function is "
                            f"NOT in the declared set (P3 form 5 does not reach this shape)"
                        ),
                        severity=Severity.NONE,
                        kind=Kind.FACT,
                        location=ent.location,
                        fingerprint=_fp(
                            "WLN-ENGINE-UNREADABLE-MARKER-VALUE",
                            ent.qualname,
                            arg_name,
                            value_key,
                        ),
                        qualname=ent.qualname,
                        properties={
                            "argument": arg_name,
                            "value": value_key,
                            "reason": "unreadable_level_value",
                        },
                    )
                )
```

`_fp` is `pipeline.py`'s own positional NUL-join sha256 at `:32`, exactly as both sibling FACTs use it — **no new helper module and no test for one**. §4.2.1 condition 4 relaxes to this helper deliberately: `_fp` is a join-and-digest primitive, not a preimage policy, and the condition specifies preimage *components*. The four parts mirror `WLN-ENGINE-UNPROVABLE-BOUNDARY`'s three (`pipeline.py:276`) widened by one, and like it carry **no relpath part** — do not add one. The join stays injective because `ast.unparse` escapes a raw NUL rather than emitting it (`ast.unparse(ast.Constant("\x00"))` yields `'\x00'`), so no value text can forge a part boundary. The admitted cost, already accepted in §4.2.1 condition 4 and not a defect to be fixed here: two distinct values sharing a 200-character prefix collide into one fingerprint, and two *stacked identical* decorators — same keyword, same value text — share one too, merging two adjacent diagnostics on a channel that never gates.

`location=ent.location` is deliberate and is the second reason Step 1 parametrises over every refused shape. The entity's own location always carries a `line_start`, whereas a per-value location derived from the value node would have to be defended shape by shape — and a lineless FACT would be **invisible today**: `tests/grammar/test_output_determinism.py:57` filters to `Kind.DEFECT`, so nothing would red, and it would surface only if that filter were ever widened. Do not widen that filter in this task; the parametrised `line_start is not None` assertion is what makes widening it later a non-event rather than a surprise.

- [ ] **Step 4: Pin soundness condition 3 — three guards, and NO implementation.** Read this before writing anything: **non-suppressibility is already true, structurally, and costs zero lines of production code.** `apply_suppressions` short-circuits on `if f.kind is not Kind.DEFECT` (`suppression.py:98-101`) *before* `resolve_identity` — the single waiver/judged/baseline JOIN — so no waiver, judged entry or baseline row can suppress this FACT; `_is_baselineable_finding` is literally `return finding.kind is Kind.DEFECT` (`baseline.py:212-217`), so `build_baseline_document` never *generates* a row for it; and `SEVERITY_ORDER` omits `Severity.NONE` by design (`suppression.py:27-29`), so it never gates. **State that claim exactly that wide and no wider (spec rev 9 §4.2.1 condition 3): a waiver — or a hand-authored baseline row — naming this FACT's fingerprint *can* be written, and is simply INERT.** An earlier drafting said none could even be written; that was an over-claim against the shipped machinery and is **withdrawn**. Verified in source: `add_waiver` (`waivers.py:157`) validates fingerprint format, reason and expiry and never sees a `Finding` at all, and a loaded baseline is a bare set of fingerprints (`_build_baseline`, `baseline.py:270-294`, which kind-checks nothing), so both rows are accepted and `apply_suppressions` then steps straight over them at the `Kind.DEFECT` short-circuit. That is precisely why the first guard below constructs **both**, and why deleting it on a none-can-be-written premise would delete the only thing that pins the property. Two wrong implementations are forbidden **by name**, because an implementer reading "non-suppressible, carrying the baseline posture" will reach for one of them: (a) do **not** wire the FACT into any baseline-document section — spec revision 6's §11.2 borrow asserted a property the shipped code does not provide and has been **withdrawn**; a `Kind.FACT` is not compared-and-reported in a baseline document, it never enters one; (b) do **not** touch `_LINELESS_DEFECT_FACT_ALLOWLIST` (`suppression.py:34`), which is intentionally empty and is not this mechanism. **The deliverable is a regression, not a feature**: it reds only if a future refactor removes the `Kind.DEFECT` short-circuit, which is exactly the silent breakage the condition exists to prevent. Append to `tests/unit/core/test_suppression.py` (extend its existing imports with `Waiver` from `wardline.core.waivers` and `build_baseline_document` from `wardline.core.baseline`):

```python
def _residual_fact(fp: str) -> Finding:
    return Finding(
        rule_id="WLN-ENGINE-UNREADABLE-MARKER-VALUE",
        message="m",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=Location(path="src/m.py", line_start=2),
        fingerprint=fp,
    )


def test_residual_fact_survives_a_baseline_and_a_waiver_on_its_own_fingerprint() -> None:
    # Soundness condition 3 (spec §4.2.1). A GUARD, not a feature: the property is
    # already met by the Kind.DEFECT short-circuit above resolve_identity. This test
    # is what reds if that short-circuit is ever refactored away.
    fact = _residual_fact(_FP_A)
    baseline = Baseline(frozenset({_FP_A}))
    waivers = WaiverSet([Waiver(fingerprint=_FP_A, reason="attempt to silence the fact")])
    (out,) = apply_suppressions([fact], baseline, waivers, today=_TODAY)
    assert out is fact  # passed through untouched — not even a `replace` copy
    assert out.suppressed is SuppressionState.ACTIVE
    assert out.severity is Severity.NONE and out.kind is Kind.FACT


def test_residual_fact_is_never_generated_into_a_baseline_document() -> None:
    # The other half of condition 3, and the correction to the withdrawn §11.2 borrow:
    # a Kind.FACT is not "compared and reported" in a baseline document — it is ABSENT
    # from it, because build_baseline_document filters through _is_baselineable_finding,
    # which admits only Kind.DEFECT. The claim is GENERATION, not authorship: a
    # hand-authored row naming this fingerprint loads fine and is inert, which is what
    # the sibling test above pins. Pinning the shipped mechanism here stops anyone
    # "fixing" condition 3 by adding a section the code structurally forbids.
    assert build_baseline_document([_residual_fact(_FP_A)])["entries"] == []


def test_residual_fact_never_participates_in_the_gate() -> None:
    assert Severity.NONE not in SEVERITY_ORDER
    assert gate_trips([_residual_fact(_FP_A)], Severity.INFO) is False
```

(Import `SEVERITY_ORDER` from `wardline.core.suppression` alongside the module's existing `apply_suppressions`/`gate_trips` import.) Record the sibling precedent in the same commit's ticket comment (Step 10): `PY-WL-130` was filed as repo-disableable (`wardline-c32e5d1420`) while its sibling observability FACTs are not, and that asymmetry is deliberate — a gating DEFECT needs an escape hatch, an unsuppressible non-gating FACT is the escape hatch's honest counterweight.

- [ ] **Step 5: Pin the warm/cold re-derivation.** The residual FACT is re-derived by the parse pass's unconditional seeding on every scan, warm or cold, exactly as `WLN-ENGINE-UNPROVABLE-BOUNDARY` is: `parse_project`'s loop runs `seed_function_taints` for every discovered module and consults the summary cache only to populate `dirty_modules`, and the emission loop iterates an **unserialised** `FunctionSeed` field inside that same loop. A "the constant did not move" assertion does not protect this — it would not catch someone serialising the field to "fix" a cache bug they imagined. Append to `tests/unit/scanner/taint/test_summary_cache.py`, following `test_warm_cache_honours_untrusted_sources_policy_change` (`:170`) exactly: write one source whose only marker is `@trusted(level=get_level())`, build **one** `WardlineAnalyzer(summary_cache=SummaryCache())`, analyze twice, and assert on **both** runs that exactly one `WLN-ENGINE-UNREADABLE-MARKER-VALUE` finding is present with an identical fingerprint; after the second run assert `cache.hits > 0` so the test proves the second run really was warm. In the same test add the two structural assertions that make the no-bump clause checkable rather than asserted: `SUMMARY_SCHEMA_VERSION` is unchanged, and `set(FunctionSummary.__dataclass_fields__)` still equals exactly `{"fqn", "body_taint", "return_taint", "taint_source", "unresolved_calls", "schema_version", "cache_key"}`. The second is the one that reds if someone serialises the carrier; a version-constant assertion alone would not.

- [ ] **Step 6: Amend `tests/grammar/test_unprovable_boundary.py` additively.** `test_unprovable_builtin_emits_no_fact` (`:72`) uses `@trust_boundary(to_level=CFG)` with no binding for `CFG`. Its existing assertion — no `WLN-ENGINE-UNPROVABLE-BOUNDARY` on a builtin — is not merely still true, it is something revision 6 **requires** (§4.2's compatibility boundary: a builtin unreadable LEVEL value never takes the custom channel), so **keep it verbatim**. What is now false is the comment "an unreadable BUILTIN level stays silent (no FACT)": correct it to say the builtin channel is the residual FACT, and add the positive assertion that exactly one `WLN-ENGINE-UNREADABLE-MARKER-VALUE` finding fires with `properties["argument"] == "to_level"`. Rename nothing — the test's name is about the *unprovable-boundary* channel and stays accurate. The companion amendment to `tests/grammar/test_provider_loop.py::test_unprovable_builtin_does_not_signal` is **not** in this task; see the Sequencing note above.

- [ ] **Step 7: Write `test_form5_agreement` — P9's receipt, owned HERE and nowhere else.** Task 2 Step 5's `test_form5_agreement` bullet list — the one immediately after its **P9 is NOT closed by this task** paragraph — SPECIFIES this suite and cannot execute it: its Steps 6-7 demand unqualified PASS, and the rows cannot pass before the census and the FACT exist. Task 3 runs the module read-only. This is the first commit at which both exist. **Append** to `tests/unit/scanner/test_marker_reader_agreement.py` — extend Task 2's module, never create a second agreement module:

  - **One `run_scan(tmp_path)` per row of the agreement list Task 2 Step 5 specifies** — its `test_form5_agreement` bullet list, immediately after the **P9 is NOT closed by this task** paragraph, which is the authoritative specification site — **with the single driver carve-out that list names, restated at the end of this bullet**; each row its own project whose only source is that row's module, and each asserting **both sides of the same scan**: the rule-side finding set (`PY-WL-114` and `WLN-ENGINE-UNREADABLE-MARKER-VALUE`, each present or absent) **and** `result.context.declared_qualnames`. The bound row asserts the qualname IS in `declared_qualnames` with no FACT and no PY-WL-114; every unreadable row asserts it is NOT and the residual FACT IS present; the custom row asserts `WLN-ENGINE-UNPROVABLE-BOUNDARY` with an `UNKNOWN_RAW` seed and the residual FACT **absent**. **The custom row alone takes the specification site's driver carve-out.** `run_scan` accepts no grammar (`src/wardline/core/run.py:301-317`), so that one row is built with `build_analyzer(grammar=default_grammar().extend(boundary_types=(custom,)))` and `analyzer.analyze([f], WardlineConfig(), root=tmp_path)` — the idiom this very task already uses in `test_custom_boundary_unreadable_level_never_takes_the_residual_fact` — and its assertions read the **returned** finding list, `analyzer.last_context.declared_qualnames` and `analyzer.last_context.project_taints[<qualname>]`, never `result.context`, which that object does not have. Every other row stays on `run_scan(tmp_path)`; `run_scan`'s signature is not widened for a test. **That driver switch is not the "repair a reader" this step's STOP clause below forbids** — there is no cross-reader disagreement on the custom row, both readers agreeing that the custom side is not form 5 — so do not escalate it.
  - **The row count is NOT frozen in this step.** Reproduce whatever rows that bullet list carries at execution time — that list is the specification site and this step is its executor. Among them is the **invalid-token row**: `_SVC_LEVEL = 'ASURED'` bound once, unconditionally, at module top level and read on a module-body `def`, asserting that PY-WL-114 **fires**, that **no** residual FACT is emitted (a token READ and then rejected is a DEFECT, never a FACT — spec §4.2.1's *READS, then rejects* row), and that the qualname is **absent** from `declared_qualnames`. That is the only shape on which a one-sided reader disagrees, and it is the row that would have caught the rule-side plumbing gap Task 3 Step 4(c) closes. If the specification site names a row this step's prose does not, the row is still owed.
  - Ids match `FORM5_CASES`' (Task 2 Step 5) **for the ten rows it carries**, so each unit row and its end-to-end twin are greppable as a pair. The **invalid-token row has no unit twin and takes its own id** — that is expected, not a dropped row: `FORM5_CASES` parametrises `level_token`, which reads `'ASURED'` SUCCESSFULLY, so the row's discriminating behaviour is a `read_level` allow-check outcome rather than a `level_token` verdict and cannot be expressed as a `FORM5_CASES` entry. Do not invent a twin for it, and do not drop it for lacking one.

  Expected when written: **PASS, every row.** This is a receipt, not a TDD driver — Tasks 3, 5 and 7 and Step 3 above already landed the behaviour, and the point of writing it here is that here it can be green over BOTH readers instead of asserted where only one exists. A red is a real one-sided reader: **STOP and report which side disagrees.** Do not repair a reader from this task — its staged paths hold none.

- [ ] **Step 8: Guard every rule's `examples_clean` against the residual FACT — the all-rules assertion Task 2 Step 3 delegates here.** **Task 2 Step 3** records — in its *Neither deletion is forced by a failing test* paragraph — that PY-WL-114's `cfg.LEVEL` clean exemplar was deleted by hand because nothing forced it, and assigns the enforcing assertion to "the task that ships that FACT". This is that task. The shipped meta test filters to `Kind.DEFECT` (`tests/unit/scanner/rules/test_rule_examples_meta.py:64`), so a `Severity.NONE` FACT reds nothing there and the trap spec §4.2.1 says must not re-form has no guard at all. Append to that module, reusing its existing `_scan` helper and `_CLEAN_CASES` parametrisation:

```python
@pytest.mark.parametrize(("rule_id", "snippet"), _CLEAN_CASES)
def test_clean_example_never_ships_an_unreadable_level_value(
    tmp_path: Path, rule_id: str, snippet: str
) -> None:
    # Over ALL kinds, deliberately: WLN-ENGINE-UNREADABLE-MARKER-VALUE is
    # Severity.NONE + Kind.FACT, so the sibling test's Kind.DEFECT filter cannot
    # see it. A clean exemplar carrying an unreadable builtin LEVEL value teaches
    # agents that a fail-open construct is exemplary — the trap this plan removed
    # one rule over, and the one clause of rev 3.4's disposition that still stands.
    fired = {f.rule_id for f in _scan(tmp_path, snippet)}
    assert "WLN-ENGINE-UNREADABLE-MARKER-VALUE" not in fired, (
        f"{rule_id} clean example carries an unreadable builtin LEVEL value: {snippet!r}"
    )
```

  Expected when written: **PASS** — Task 2 Step 3(a) deleted PY-WL-114's `cfg.LEVEL` entry and rev 3.4 removed PY-WL-130's, and the census found no others. **If a third rule's snippet fires it, STOP and report the rule id and the snippet.** Deleting it means editing a rule module outside this task's staged paths, which the per-task path gate forbids — do not delete it here, and do not write it off to "the owning rule's task", which is the delegation-without-authority failure this revision exists to remove.

- [ ] **Step 9: Write PRD-0003 criterion 1's hole-3 exit-code repro — the committed artifact `wardline-2b2a6cddfa`'s close depends on.** Final verification's **hole 3** end-to-end repro bullet (`wardline-2b2a6cddfa`) and `wardline-5a795253f1`'s close criterion **(ii)** both READ this artifact; neither authors it, and Final verification carries no commit step, so a test produced there would never be committed. Step 10's ticket comment below asserts it exists — it exists because of this step. **Append** to `tests/unit/cli/test_false_green_exit_code_repros.py`, the module **Task 6 Step 7** creates (under the recommended numeric order it already exists; if it does not, create it — never a second module), following the shipped `tests/unit/cli/test_cli.py` idiom exactly: `from click.testing import CliRunner`, `from wardline.cli.main import cli`, one `tmp_path` project per repro.

```python
def test_hole3_unreadable_level_value_trips_the_gate(tmp_path: Path) -> None:
    # wardline-2b2a6cddfa: a DRY refactor of the level to a module constant used to
    # drop the seed SILENTLY — the function left declared_qualnames, every
    # tier-modulated rule went quiet, and the gate exited 0 on a real leak. P3 form 5
    # resolves it (Task 5), so PY-WL-101 fires and the gate trips. The assertion is on
    # the literal PROCESS EXIT CODE, which is what PRD-0003 criterion 1 reads; a
    # finding that exists without tripping the gate is the very failure being closed.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import external_boundary, trusted\n"
        "_SVC_LEVEL = 'INTEGRAL'\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level=_SVC_LEVEL)\ndef leaky(p):\n    return read_raw(p)\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["scan", str(proj), "--fail-on", "ERROR"])
    assert result.exit_code == 1, result.output
```

  `_SVC_LEVEL` is bound **once**, unconditionally, at module top level and lexically before a `def` that is a **direct element of the module body** — form 5 in full, so the specimen is the ticket's shape and not a near-miss. **Placement rule (spec §4.2.1), non-negotiable:** it lives in `tmp_path` and in **none** of `tests/corpus/fixtures`, `tests/golden/identity/corpus/*.json` or any Rust tree; a committed fixture is silently absorbed and converts PRD-0003 criterion 4's guard into a re-freeze. Expected when written: **PASS** — like Step 7 this is a receipt rather than a TDD driver, form 5 having landed at Task 5; what is missing until now is the *committed artifact*. Record the before state (exit 0) from the ticket's own reproduction, not from a re-run at this commit.

- [ ] **Step 10: Record the close *rationale* and the suppressibility asymmetry on their tickets.** Both commands below are `add-comment` — this step closes nothing. The close of `wardline-2b2a6cddfa` is **Step 14**, after Step 13's commit exists to anchor it; placing it here would have it carry a commit ref that does not yet exist. Run:

```bash
filigree --actor codex add-comment wardline-2b2a6cddfa \
  "Hole 3 closed in S0: P3 form 5 resolves a same-file module-level one-hop value reference in a builtin LEVEL slot on a module-top-level def (Tasks 3/5), and everything that stays unreadable takes WLN-ENGINE-UNREADABLE-MARKER-VALUE (Severity.NONE, Kind.FACT) instead of silence (Task 8). Both halves shipped; neither substitutes for the other. Five soundness conditions each pinned by a named test — see the plan's Task 8 ownership list. The exit-code repro is `tests/unit/cli/test_false_green_exit_code_repros.py::test_hole3_unreadable_level_value_trips_the_gate`, written and committed in this task's Step 9 — a tmp_path test, in NO frozen fixture tree."
filigree --actor codex add-comment wardline-c32e5d1420 \
  "Scope note from S0 Task 8: WLN-ENGINE-UNREADABLE-MARKER-VALUE joins WLN-ENGINE-UNPROVABLE-BOUNDARY and WLN-ENGINE-UNKNOWN-MARKER on the NON-suppressible side, structurally — apply_suppressions short-circuits before the waiver/judged/baseline join for any non-DEFECT, and _is_baselineable_finding admits only Kind.DEFECT, so build_baseline_document never generates a row for it. The claim is exactly that and no wider (spec rev 9 section 4.2.1 condition 3, which withdraws an earlier over-claim): a waiver — or a hand-authored baseline row — naming its fingerprint CAN be written and is simply inert, add_waiver never seeing a Finding and a loaded baseline being a bare set of fingerprints. Guarded by test_residual_fact_survives_a_baseline_and_a_waiver_on_its_own_fingerprint, which constructs both, and by test_residual_fact_is_never_generated_into_a_baseline_document. Whatever this ticket decides for PY-WL-130's repo-disableability must not be generalised to the observability FACTs."
```

- [ ] **Step 11: Run tests to verify they pass** — `uv run pytest tests/grammar/test_unreadable_marker_value.py tests/unit/core/test_suppression.py tests/unit/scanner/taint/test_summary_cache.py tests/grammar/test_unprovable_boundary.py tests/unit/scanner/test_marker_reader_agreement.py tests/unit/scanner/rules/test_rule_examples_meta.py tests/unit/cli/test_false_green_exit_code_repros.py tests/grammar tests/unit/scanner -q`. The three modules Steps 7-9 authored are named explicitly even though `tests/unit/scanner` already globs two of them: this run command is the task's receipt of what it wrote, and `tests/unit/cli/` is covered by no other path here. Expected: PASS with **no scan-golden regeneration** — the byte oracle streams `tests/corpus/fixtures`, every builtin `level=`/`to_level=` value under the frozen Python fixture trees is a `str` literal, and the identity corpus excludes FACTs by construction. If any frozen golden goes red the change is wrong: **stop and fix the change, never the golden** (the zero-scan-golden-drift Global Constraint, and PRD-0003 criterion 4's reject branch). One red is expected to point elsewhere and must not be misread as this task breaking: if `tests/grammar/test_provider_loop.py::test_unprovable_builtin_does_not_signal` is red or errors here, the missing work is upstream and **split across two tasks** — **Task 5 Step 1's** census-carrying `SeedContext` amendment, or **Task 7 Step 4.6's** `res.unreadable_level_values` assertion (see the Sequencing note) — not anything in Task 8, and `tests/grammar/test_provider_loop.py` is on neither this task's Files list nor its staged paths: do not repair it in this commit.

- [ ] **Step 12: Full suite** — `uv run pytest -q`. Expected: PASS. This is also where Task 6's single carried red — `test_unreadable_value_is_not_a_shape_offence`'s `WLN-ENGINE-UNREADABLE-MARKER-VALUE` assertion — first goes green; verify it here before closing this task.

- [ ] **Step 13: Commit** — `feat(engine): WLN-ENGINE-UNREADABLE-MARKER-VALUE — the residual channel and its five soundness conditions (wardline-2b2a6cddfa)`

- [ ] **Step 14 (orchestrator, after the commit): close `wardline-2b2a6cddfa`.** This is the step that **owns** the close. `wardline-5a795253f1`'s close condition (v)'s sibling, condition **(ii)** in Final verification, requires this ticket **CLOSED** — and through rev 3.7 no step produced that state, the ticket carrying an `add-comment` at Step 10 and nothing else. It runs **after** Step 13 rather than beside Step 10 because a close carries commit refs and Step 9's exit-code repro is not committed until then; it is gated on Step 11's targeted green, Step 12's full-suite green, and Step 13's commit sha. Subagents never run this — every Filigree write in this plan is the orchestrator's.

```bash
filigree --actor codex close wardline-2b2a6cddfa --commit "release/2.0.0@<Task 8 commit sha>" --reason "Hole 3 closed in S0 by both halves, neither substituting for the other (PDR-0018): P3 form 5 resolves a same-file module-level one-hop value reference in a builtin LEVEL slot on a module-top-level def (Tasks 3/5), and every value that stays unreadable takes WLN-ENGINE-UNREADABLE-MARKER-VALUE (Severity.NONE, Kind.FACT) instead of silence (Task 8). Exit-code repro committed at tests/unit/cli/test_false_green_exit_code_repros.py::test_hole3_unreadable_level_value_trips_the_gate (tmp_path; in no frozen fixture tree). The residual FACT's five soundness conditions are each pinned by a named test — see the plan's Task 8 ownership list."
```

If the close is refused because the ticket is not in a state the transition accepts, that is a **STOP and report**: do not reach for `--force`, and do not carry on to Task 9 assuming the tracker will be tidied later, because Final verification's close condition (ii) reads this ticket's real status and a `--force`d close leaves the normal workflow without a record of why.

---

### Task 9: `decorator_coverage` surfaces the unknown-marker AND unreadable-level-value counts — **two** new summary keys, five to seven (+ MCP golden re-freeze #1)

**Files:**
- Modify: `src/wardline/core/decorator_coverage.py:110-244`
- Modify: `src/wardline/mcp/server.py:3012-3035` (`_DECORATOR_COVERAGE_OUTPUT_SCHEMA` summary block)
- Modify: `src/wardline/cli/decorator_coverage.py:72-81` (`_render_human`)
- Modify: `tests/conformance/mcp_output_schemas.golden.json` + `tests/conformance/test_mcp_output_schema_golden.py:69` (`VENDORED_BLOB_SHA`)
- Modify: `tests/unit/core/test_decorator_coverage.py`
- Modify: `tests/unit/mcp/test_server_decorator_coverage.py`
- Modify: `tests/unit/cli/test_decorator_coverage_cmd.py`
- Modify: `tests/conformance/test_mcp_structured_output.py`

**Interfaces:**
- Consumes: BOTH marker FACT ids, matched by `rule_id` over `result.findings` — `"WLN-ENGINE-UNKNOWN-MARKER"` (Task 7) and `"WLN-ENGINE-UNREADABLE-MARKER-VALUE"` (Task 8).
- Produces: `DecoratorCoverageReport.unknown_marker_count: int = 0` and `DecoratorCoverageReport.unreadable_marker_value_count: int = 0`; the summary dict gains keys `"unknown_markers"` and `"unreadable_marker_values"` — **SEVEN keys**: `total, clean, defect, unknown, suppressed, unknown_markers, unreadable_marker_values`.
- The seventh key is spec §4.2.1 soundness condition 5's `decorator_coverage` count. It is a **sibling summary key**, named from its rule id by the same derivation that names `unknown_markers` from `WLN-ENGINE-UNKNOWN-MARKER`, with a report field mirroring `unknown_marker_count`, and the SAME one name in all four places it surfaces (core summary dict, MCP output schema, that schema's golden, CLI human renderer). It rides this task's **single** already-sanctioned re-freeze: the Global Constraint caps the NUMBER of re-freezes, not the keys changed within one, so that constraint needs no amendment and this must not become a third.

- [ ] **Step 1: Write the failing test** (in the existing core decorator-coverage test module, using its established build helper):

```python
def test_summary_counts_unknown_markers(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "import weft_markers\n"
        "from wardline.decorators import trusted\n"
        "@weft_markers.audit_record\n"
        "def new_style(e):\n"
        "    return e\n"
        "@trusted\n"
        "def declared(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    report = build_decorator_coverage(proj)
    assert report.summary["unknown_markers"] == 1
    # Rows are still provider-seeded entities only — the unknown-marker entity
    # has no row; the count is the side-channel that says WHY.
    assert report.summary["total"] == 1


def test_summary_counts_unreadable_marker_values(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\n"
        "def get_level():\n"
        "    return 'ASSURED'\n"
        "DYN = get_level()\n"
        "@trusted(level=DYN)\n"
        "def residual(p):\n"
        "    return p\n"
        "@trusted\n"
        "def declared(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    report = build_decorator_coverage(proj)
    assert report.summary["unreadable_marker_values"] == 1
    # Soundness condition 2 (spec §4.2.1): the residual FACT is NOT inertness-
    # clearing — the unreadable-value entity becomes no provider-seeded row and does
    # not move the posture denominator. `declared` is the only row.
    assert report.summary["total"] == 1
    # Condition 5's no-double-count clause: one unreadable value, one channel.
    assert report.summary["unknown_markers"] == 0
```

(Import: `from wardline.core.decorator_coverage import build_decorator_coverage` — the real entry point, `build_decorator_coverage(root: Path, *, config_path=None, ...) -> DecoratorCoverageReport` at `decorator_coverage.py:244`; the bare-`root` call above matches its signature.)

- [ ] **Step 2: Run to verify they fail** — `uv run pytest tests/unit/core/test_decorator_coverage.py -v`. Expected: **BOTH** FAIL — `test_summary_counts_unknown_markers` on `KeyError: 'unknown_markers'` and `test_summary_counts_unreadable_marker_values` on `KeyError: 'unreadable_marker_values'`. This task ships **two** keys, not one; a run that reds only the first has not exercised spec §4.2.1 soundness condition 5.

- [ ] **Step 3: Implement.**
  1. `core/decorator_coverage.py` — `DecoratorCoverageReport` gains a field and the summary a key:

```python
@dataclass(frozen=True, slots=True)
class DecoratorCoverageReport:
    rows: list[DecoratorCoverageRow]
    unknown_marker_count: int = 0
    unreadable_marker_value_count: int = 0

    @property
    def summary(self) -> dict[str, int]:
        total = len(self.rows)
        clean = sum(1 for row in self.rows if row.finding_state == "clean")
        defect = sum(1 for row in self.rows if row.finding_state == "defect")
        unknown = sum(1 for row in self.rows if row.finding_state == "unknown")
        suppressed = sum(1 for row in self.rows if row.finding_state == "suppressed")
        return {
            "total": total,
            "clean": clean,
            "defect": defect,
            "unknown": unknown,
            "suppressed": suppressed,
            "unknown_markers": self.unknown_marker_count,
            "unreadable_marker_values": self.unreadable_marker_value_count,
        }
```

  2. `decorator_coverage_from_scan` (end of function):

```python
    unknown_marker_count = sum(1 for f in result.findings if f.rule_id == "WLN-ENGINE-UNKNOWN-MARKER")
    unreadable_marker_value_count = sum(
        1 for f in result.findings if f.rule_id == "WLN-ENGINE-UNREADABLE-MARKER-VALUE"
    )
    # Both are side-channels: neither creates a row, so `total` is unmoved and an
    # otherwise-inert scan stays inert (spec §4.2.1, soundness condition 2).
    return DecoratorCoverageReport(
        rows=rows,
        unknown_marker_count=unknown_marker_count,
        unreadable_marker_value_count=unreadable_marker_value_count,
    )
```

  3. `mcp/server.py` `_DECORATOR_COVERAGE_OUTPUT_SCHEMA` summary block: add `"unknown_markers": {"type": "integer", "description": "Count of vocabulary-rooted decorators this engine does not recognise (WLN-ENGINE-UNKNOWN-MARKER FACTs) — newer weft-markers than wardline."}` AND `"unreadable_marker_values": {"type": "integer", "description": "Count of builtin marker LEVEL values that stay statically unreadable after P3 form 5 (WLN-ENGINE-UNREADABLE-MARKER-VALUE FACTs) — the seed dropped observably."}` to `properties`, and BOTH `"unknown_markers"` and `"unreadable_marker_values"` to `required` (the block is `additionalProperties: False`, so a key absent from `properties` fails validation outright; `required` is separate and load-bearing — `tests/conformance/test_mcp_structured_output.py` validates the live `structuredContent` against this schema via `jsonschema.validate` (`:25`, `:131-139`) and exercises `decorator_coverage` directly (`:297-299`), so only `required` pins that every renderer actually emits both counts. A key in `properties` but absent from `required` is OPTIONAL and validates fine when present, which is exactly the silent-stop-emitting case `required` exists to catch).
  4. `cli/decorator_coverage.py` `_render_human`: print `unknown_markers=<n>` then `unreadable_marker_values=<n>` after `suppressed`, reading `summary["unknown_markers"]` and `summary["unreadable_marker_values"]`.

⚠️ **NAME CONFIRMATION BEFORE THE RE-FREEZE.** Spec §4.2.1 condition 5 fixes the *derivation* of the seventh key and deliberately mints no string. `unreadable_marker_values` (summary key) and `unreadable_marker_value_count` (report field) are the names that derivation produces, and they are what this task ships — but the owner confirms them **before Step 4 runs**. Once the golden carries a name, changing it costs a second re-freeze of this file, and the Global Constraint permits exactly two in all of S0 (this one and Task 20's). Confirm, then re-freeze once.

- [ ] **Step 4: Re-freeze the MCP output-schema golden** (RE-FREEZE PROCEDURE from `tests/conformance/test_mcp_output_schema_golden.py:26-31`). **The handshake opt-out is not optional, and it is why this script is pinned in full rather than left to the module's header.** `_live_output_schemas()` (`:95-101`) asserts `"error" not in resp`, but the opt-out that lets `tools/list` be answered without an `initialize` round-trip lives **only** in that module's autouse pytest fixture `_handshake_preopened` (`:48-61`), which monkeypatches `JsonRpcServer.__init__` to force `require_handshake=False`. Outside pytest that fixture never runs: `WardlineMCPServer` constructs its `JsonRpcServer` with no such argument (`src/wardline/mcp/server.py:4730`), `src/wardline/mcp/protocol.py:37` defaults `require_handshake` to `True`, and `:103-104` answers every non-`initialize` method with `{"error": {"code": -32600, "message": "server not initialized"}}` — so the helper's assertion fires and the script dies **before a byte is written**. The script therefore mirrors the fixture itself, before importing the test module. Scratch script:

```bash
uv run python - <<'PY'
import hashlib, json, sys

sys.path.insert(0, "tests/conformance")

# Mirror the module's autouse `_handshake_preopened` fixture (:48-61). It does not run
# outside pytest, and without it `_live_output_schemas()` asserts on
# {"error": {"code": -32600, "message": "server not initialized"}}. Patch BEFORE the
# test module is imported.
from wardline.mcp.protocol import JsonRpcServer

_ORIG_RPC_INIT = JsonRpcServer.__init__


def _init(self, *, server_name, server_version, require_handshake=False):
    _ORIG_RPC_INIT(
        self, server_name=server_name, server_version=server_version, require_handshake=require_handshake
    )


JsonRpcServer.__init__ = _init

from test_mcp_output_schema_golden import _GOLDEN_PATH, _live_output_schemas

live = _live_output_schemas()
data = (json.dumps(live, indent=2, sort_keys=True) + "\n").encode("utf-8")
_GOLDEN_PATH.write_bytes(data)
print("new VENDORED_BLOB_SHA =", hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest())
PY
```

Verified against the tree as it stands at plan rev 3.8 (2026-08-11), with the `write_bytes` suppressed: the patched script runs to completion, reproduces all **18** tool schemas, and prints a digest **byte-for-byte equal to the committed golden and to whatever `VENDORED_BLOB_SHA` at `:69` currently holds**. (*Rev-3.10 correction, and the reason no digest is quoted here any more: this sentence has now gone stale **three times** — `b6b95b92…` (pre-Task-9) → `a3247bda…` (rev 3.9, re-measured 2026-08-12) → `8f54e83c…` (Task 20's sanctioned re-freeze, 2026-08-13). Each re-freeze moves the constant and re-falsifies any receipt that copies it, and a correct baseline reproducing the live value against a receipt naming an older one reads as golden drift — a manufactured STOP under this plan's STOP-on-unexpected discipline. `:69` is the single source; compare against it, never against a digest quoted in prose. The no-op-baseline reasoning below is unchanged.*) That is the no-op baseline, and it is what proves the script mechanism works before this task perturbs the schema; after Step 3's edit the digest moves, which is the point of the re-freeze.

Update `VENDORED_BLOB_SHA` at `test_mcp_output_schema_golden.py:69` to the printed value — SAME commit as the schema edit.

⚠️ **If the script fails, do NOT hand-edit `tests/conformance/mcp_output_schemas.golden.json` — regenerate it from the live surface.** The module forbids hand-editing by name: `test_golden_matches_vendored_blob_pin`'s own failure message reads *"someone edited the golden by hand (forbidden — regenerate it from the live surface; see the RE-FREEZE PROCEDURE in this module's header)"*. Hand-editing is the nearest wrong repair precisely because it looks cheap: a hand-typed golden plus a recomputed `VENDORED_BLOB_SHA` satisfies the byte-pin layer while breaking the live-equals-golden layer, and the tempting next move is then to bend the in-code schema to match the typed bytes rather than the reverse — which is the circularity this module exists to break. A failing script is a **STOP and report**, not a licence to type JSON. Note the budget: Global Constraints sanctions **exactly two** re-freezes of this file in all of S0 (this one and Task 20 Step 3), so there is no third attempt to spend on a repair-by-retry.

- [ ] **Step 5: Run** — `uv run pytest tests/unit/core/test_decorator_coverage.py tests/unit/mcp/test_server_decorator_coverage.py tests/unit/cli/test_decorator_coverage_cmd.py tests/conformance/test_mcp_output_schema_golden.py tests/conformance/test_mcp_structured_output.py -q`. Update every exact summary assertion in those named modules to include **both** `unknown_markers` **and** `unreadable_marker_values` — the five-key to seven-key move this step's closing paragraph states; then run the full suite. Expected: PASS.

Before the full suite, add `_UNKNOWN_SRC = "import weft_markers\n@weft_markers.audit_record\ndef f(): ...\n"` and `_UNREADABLE_SRC = "from wardline.decorators import trusted\ndef get_level():\n    return 'ASSURED'\nDYN = get_level()\n@trusted(level=DYN)\ndef g(p):\n    return p\n"` beside each module's existing `_SRC`. In `test_server_decorator_coverage.py`, plant both and assert `_mcp_call(...)["summary"]["unknown_markers"] == 1` and `... ["unreadable_marker_values"] == 1`. In `test_decorator_coverage_cmd.py`, plant both, invoke the human formatter, and assert the exact substrings `unknown_markers=1` and `unreadable_marker_values=1`. In `test_mcp_structured_output.py`, plant the same two sources, pass the server through `_validated`, and assert `out["summary"]["unknown_markers"] == 1` and `out["summary"]["unreadable_marker_values"] == 1`. Keep both core `build_decorator_coverage` assertions above. A schema-only pin is insufficient: all three live renderers must carry BOTH counts, and every exact summary-dict assertion in the four named modules moves from five keys to seven.

- [ ] **Step 6: Commit** — `feat(coverage): decorator_coverage surfaces the unrecognised-vocabulary AND unreadable-level-value counts — five summary keys to seven, spec §4.2.1 soundness condition 5; MCP schema golden re-frozen (S0)`

---

### Task 10: Corpus harness — strict manifest, preview reconciliation, per-kind FP gate (P1, P2, P3)

**Files:**
- Modify: `tests/corpus/harness.py`
- Modify: `tests/corpus/MANIFEST.yaml` (new rows + header ONLY — see the warning below)
- Modify: `tests/corpus/test_fp_rate.py`
- Create: `tests/corpus/sentinels/clean_matching_trust.py` (repeated matching trust markers; clean counterpart to the contradiction sentinel)

⚠️ `test_fired_sentinel_counts_against_budget` (`test_fp_rate.py:57-58`) string-matches the EXACT text `qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE` in MANIFEST.yaml. Do not reformat existing rows; add new fields on NEW rows only.

**Interfaces:**
- Consumes: `BUILTIN_RULE_CLASSES` metadata (rule_id → maturity).
- Produces: `Expectation` gains `maturity`, `kind`, `interaction`, and `section`; `Reconciliation` gains `active_by_kind` and `fp_by_kind` with `default_factory=dict`. The loader rejects malformed top-level/section/entry shapes, missing and unknown fields, unknown rules/files, bad maturity/kind/interaction/label values, maturity drift, and duplicate reconciliation keys. It computes live rule maturities once per load. The PREVIEW skip at `harness.py:96-97` is deleted. `interaction="contradiction"` is a true-positive interaction specimen; `interaction="match"` is its false-positive clean sentinel.

- [ ] **Step 1: Write the failing tests** — append to `tests/corpus/test_fp_rate.py`:

```python
import corpus.harness as harness  # type: ignore[import-not-found]
import pytest
from wardline.core.finding import Kind
from wardline.core.run import run_scan


def _scratch_manifest(tmp_path, text, *, complete=True):
    scratch = tmp_path / "MANIFEST.yaml"
    if complete:
        if "fixtures:" not in text:
            text += "fixtures: {}\n"
        if "sentinels:" not in text:
            text += "sentinels: {}\n"
    scratch.write_text(text, encoding="utf-8")
    return scratch


def test_manifest_rejects_unknown_keys(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-106, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE, maturty: stable}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="unknown key"):
        harness.load_manifest()


def test_manifest_rejects_unknown_rule_ids(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-999, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="unknown rule_id"):
        harness.load_manifest()


def test_manifest_maturity_must_match_the_rule(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  deser_sink.py:\n"
        '    - {rule_id: PY-WL-118, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE, maturity: stable}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="maturity"):
        harness.load_manifest()


def test_manifest_rejects_missing_fixture_files(tmp_path, monkeypatch):
    bad = _scratch_manifest(
        tmp_path,
        "fixtures:\n  no_such_file.py:\n"
        '    - {rule_id: PY-WL-106, qualname: "x.f", label: TRUE_POSITIVE}\n',
    )
    monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
    with pytest.raises(ValueError, match="no such fixture"):
        harness.load_manifest()


def test_manifest_rejects_unknown_kind_and_interaction(tmp_path, monkeypatch):
    for field_yaml, match in (("kind: sorcery", "kind"), ("interaction: frenemies", "interaction")):
        bad = _scratch_manifest(
            tmp_path,
            "fixtures:\n  deser_sink.py:\n"
            f'    - {{rule_id: PY-WL-106, qualname: "deser_sink.loads_untrusted", label: TRUE_POSITIVE, {field_yaml}}}\n',
        )
        monkeypatch.setattr(harness, "MANIFEST_PATH", bad)
        with pytest.raises(ValueError, match=match):
            harness.load_manifest()


def test_preview_finding_moves_numerator_and_denominator(monkeypatch, tmp_path):
    # THE discriminating case for P1: a corpus whose only findings come from
    # snippets built on a PREVIEW rule's own examples_violation (guaranteed to
    # fire by the examples contract). Under the old maturity skip reconcile()
    # counted nothing here (active_defects == 0); with the skip gone the preview
    # findings land in the denominator AND, labeled FALSE_POSITIVE, the
    # numerator.
    from wardline.scanner.rules.sql_injection import METADATA as SQLI

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    sentinels = tmp_path / "sentinels"
    sentinels.mkdir()
    (sentinels / "clean_placeholder.py").write_text("X = 1\n", encoding="utf-8")
    src = (
        "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
        + SQLI.examples_violation[0]
        + "\n"
    )
    (fixtures / "preview_fp.py").write_text(src, encoding="utf-8")

    # Discover every DEFECT the engine fires here, then manifest ALL of them so
    # the reconciliation is closed: PY-WL-118 rows as FALSE_POSITIVE (the point),
    # any co-firing stable rule as TRUE_POSITIVE.
    maturities = harness._rule_maturities()
    fired = [f for f in run_scan(fixtures).findings if f.kind is Kind.DEFECT]
    assert any(f.rule_id == "PY-WL-118" for f in fired), "PY-WL-118's violation example must fire it"
    rows = "".join(
        f'    - {{rule_id: {f.rule_id}, qualname: "{f.qualname}", '
        f"label: {'FALSE_POSITIVE' if f.rule_id == 'PY-WL-118' else 'TRUE_POSITIVE'}, "
        f"maturity: {maturities[f.rule_id]}, "
        f'note: "synthetic P1 gate row"}}\n'
        for f in fired
    )
    manifest = _scratch_manifest(tmp_path, "fixtures:\n  preview_fp.py:\n" + rows)
    monkeypatch.setattr(harness, "CORPUS_ROOT", fixtures)
    monkeypatch.setattr(harness, "SENTINEL_ROOT", sentinels)
    monkeypatch.setattr(harness, "MANIFEST_PATH", manifest)

    rec = harness.reconcile()
    n_preview = sum(1 for f in fired if f.rule_id == "PY-WL-118")
    assert rec.active_defects == len(fired)  # denominator includes preview (was: excluded)
    assert rec.false_positives == n_preview  # numerator includes the preview FP rows
    assert not rec.unaccounted


def test_per_kind_fp_rate_within_budget():
    # Spec §12 "Per-kind gates" (NOT P3 — P3 is the reconciliation-ordering
    # obligation that must be clean BEFORE any rate is evaluated, asserted in
    # test_fp_rate_within_budget): every declared kind has >=3 distinct clean
    # sentinel files and >=5 TP specimens. TP fixture-file diversity is retained
    # as an additional gate.
    # At >=10 active defects the kind meets the 5% FP budget; below 10 it is
    # sentinel-gated low-sample and its counts go into the implementation receipt.
    rec = harness.reconcile()
    from collections import Counter

    entries = harness.load_manifest()
    manifest_kinds = {e.kind for e in entries}
    true_fixture_paths = {
        kind: {e.path for e in entries if e.kind == kind and e.section == "fixtures"
               and e.label == harness.TRUE_POSITIVE}
        for kind in manifest_kinds
    }
    clean_sentinel_paths = {
        kind: {
            e.path for e in entries
            if e.kind == kind and e.section == "sentinels"
            and e.label == harness.FALSE_POSITIVE
        }
        for kind in manifest_kinds
    }
    true_specimens = Counter(e.kind for e in entries if e.label == harness.TRUE_POSITIVE)
    assert set(rec.active_by_kind) == manifest_kinds
    for kind in sorted(manifest_kinds):
        defects = rec.active_by_kind[kind]
        fps = rec.fp_by_kind.get(kind, 0)
        assert len(clean_sentinel_paths[kind]) >= 3, (
            f"kind {kind}: fewer than 3 distinct clean sentinel files"
        )
        assert len(true_fixture_paths[kind]) >= 3, f"kind {kind}: fewer than 3 true fixture files"
        assert true_specimens[kind] >= 5, f"kind {kind}: fewer than 5 true-positive specimens"
        if defects >= 10:
            assert fps / defects <= 0.05, f"kind {kind}: FP rate {fps}/{defects} exceeds 5%"
        else:
            assert defects >= 5, f"kind {kind}: fewer than 5 active defect specimens"
```

Add loader-negative tests for: non-mapping top level; an unknown/missing section; a section that is not a mapping; an entry that is not a mapping; each missing required field (`rule_id`, `qualname`, `label`); unknown label; duplicate `(section, path, rule_id, qualname)`; and a sentinel file placed under the wrong section. Pass `complete=False` only for tests whose purpose is malformed top-level/section structure. Add the same-rule pair assertion: PY-WL-110 must have both a `contradiction`/TRUE_POSITIVE interaction specimen and a `match`/FALSE_POSITIVE clean sentinel.

- [ ] **Step 2: Run to verify failures** — `cd tests && uv run pytest corpus/test_fp_rate.py -v`. Expected: the new tests FAIL (no strict keys, preview skip still present, no per-kind fields).

- [ ] **Step 3: Implement `harness.py`.**
  1. `Expectation` gains `maturity: str = "stable"`, `kind: str = "core"`, `interaction: str = ""`, `section: str = "fixtures"`.
  2. `Reconciliation` gains (with `from dataclasses import dataclass, field`):

```python
    active_by_kind: dict[str, int] = field(default_factory=dict)
    fp_by_kind: dict[str, int] = field(default_factory=dict)
```

  3. Strict loading — module-level:

```python
_ALLOWED_KEYS = frozenset({"rule_id", "qualname", "label", "note", "maturity", "kind", "interaction"})
_REQUIRED_KEYS = frozenset({"rule_id", "qualname", "label"})
_ALLOWED_SECTIONS = frozenset({"fixtures", "sentinels"})
_MATURITIES = frozenset({"stable", "preview"})
_ALLOWED_KINDS = frozenset({"core", "contracts", "facets", "restoration", "sensitivity", "dependency_taint"})
_ALLOWED_INTERACTIONS = frozenset({"", "contradiction", "match"})


def _rule_maturities() -> dict[str, str]:
    from wardline.scanner.rules import BUILTIN_RULE_CLASSES

    return {cls.metadata.rule_id: cls.metadata.maturity.value for cls in BUILTIN_RULE_CLASSES}
```

     At the top of `load_manifest`, validate the YAML root is a mapping with exactly `_ALLOWED_SECTIONS`, each section is a mapping, each path is a non-empty relative POSIX path, each rows value is a list, and each row is a mapping. Reject absolute paths, `..` components, and any resolved path escaping its section root. Require `rule_id`, `qualname`, `label`, `note`, `maturity`, `kind`, and `interaction` values (when present) to be strings before set/dict membership checks, so malformed YAML raises the promised `ValueError`, never incidental `TypeError`. Build `section_roots = {"fixtures": CORPUS_ROOT, "sentinels": SENTINEL_ROOT}` locally so monkeypatching works. Compute `maturities = _rule_maturities()` once before either loop. Inside the entry loop, before constructing `Expectation`:

```python
                unknown = set(entry) - _ALLOWED_KEYS
                if unknown:
                    raise ValueError(f"{path}: unknown key(s) {sorted(unknown)} in manifest entry")
                missing = _REQUIRED_KEYS - set(entry)
                if missing:
                    raise ValueError(f"{path}: missing required key(s) {sorted(missing)}")
                if not (section_roots[section] / path).is_file():
                    raise ValueError(f"{path}: no such fixture under {section}/")
                if entry["rule_id"] not in maturities:
                    raise ValueError(f"{path}: unknown rule_id {entry['rule_id']!r}")
                maturity = entry.get("maturity", "stable")
                if maturity not in _MATURITIES:
                    raise ValueError(f"{path}: bad maturity {maturity!r} (want one of {sorted(_MATURITIES)})")
                if maturities[entry["rule_id"]] != maturity:
                    raise ValueError(
                        f"{path}: {entry['rule_id']} maturity is {maturities[entry['rule_id']]!r} but the "
                        f"manifest says {maturity!r} — a graduated rule must update its entries"
                    )
                kind = entry.get("kind", "core")
                if kind not in _ALLOWED_KINDS:
                    raise ValueError(f"{path}: bad kind {kind!r} (want one of {sorted(_ALLOWED_KINDS)})")
                interaction = entry.get("interaction", "")
                if interaction not in _ALLOWED_INTERACTIONS:
                    raise ValueError(f"{path}: bad interaction {interaction!r}")
```

     Validate `label` against `{TRUE_POSITIVE, FALSE_POSITIVE}` and interaction/label pairing (`contradiction` → TRUE_POSITIVE, `match` → FALSE_POSITIVE). Preserve the existing ban on reusing one relative path across roots and reject duplicate `(section, path, rule_id, qualname)` keys. Then pass `maturity=maturity, kind=kind, interaction=interaction, section=section` to `Expectation`. Negative tests cover list/dict/scalar values for every string field plus absolute, parent-traversal, and symlink/resolve escapes.
  4. `reconcile()`: DELETE the preview skip (:96-97, `if finding.maturity is Maturity.PREVIEW: continue`) and drop `Maturity` from the import at `:25`. Add per-kind tallies inside the loop:

```python
        active_defects += 1  # global population is counted before lookup
        key = (finding.location.path, finding.rule_id, finding.qualname or "")
        expectation = by_key.get(key)
        if expectation is None:
            unaccounted.append(key)
            continue
        kind = expectation.kind
        active_by_kind[kind] = active_by_kind.get(kind, 0) + 1
        matched_keys.add(key)
        if expectation.label == FALSE_POSITIVE:
            false_positives += 1
            fp_by_kind[kind] = fp_by_kind.get(kind, 0) + 1
```

     After loading expectations, derive `manifest_kinds = {e.kind for e in expectations}` and initialise `active_by_kind = {kind: 0 for kind in manifest_kinds}` and `fp_by_kind = {kind: 0 for kind in manifest_kinds}` before the loop; do not silently attribute unaccounted findings to `core`. Add both to the `Reconciliation(...)` return. Update the module docstring: the FP population now includes preview DEFECTs (P1) — no maturity blind spot.

- [ ] **Step 4: Reconcile the real corpus.**

Run: `cd tests && uv run python -c "from corpus.harness import reconcile; r = reconcile(); [print(k) for k in r.unaccounted]"`
For EACH `(path, rule_id, qualname)` printed (these are the previously-skipped PREVIEW findings over fixtures/sentinels), add a manifest row under its file with `maturity: preview` and an honest label: `TRUE_POSITIVE` if the fixture genuinely exhibits that preview rule's defect shape at that site, `FALSE_POSITIVE` if the rule wrongly fires. Add a `note:` per row. Update the MANIFEST.yaml header comment to document the three new fields and their defaults. The dead PY-WL-118 sentinel row (`MANIFEST.yaml:60`) gains `maturity: preview` and is now LIVE.
Create `sentinels/clean_matching_trust.py` as the repeated-same-trust clean counterpart to the existing contradictory marker TP interaction specimen, and manifest the PY-WL-110 pair with `interaction: contradiction`/TRUE_POSITIVE and `interaction: match`/FALSE_POSITIVE. Populate every manifest kind to the floor asserted above.

After reconciliation is clean, generate the low-sample receipt rows:

```bash
cd tests
uv run python - <<'PY'
from collections import Counter
from corpus import harness

rec = harness.reconcile()
entries = harness.load_manifest()
tp = Counter(e.kind for e in entries if e.label == harness.TRUE_POSITIVE)
clean = {
    kind: len({
        e.path for e in entries
        if e.kind == kind and e.section == "sentinels"
        and e.label == harness.FALSE_POSITIVE
    })
    for kind in rec.active_by_kind
}
for kind in sorted(rec.active_by_kind):
    defects = rec.active_by_kind[kind]
    if defects < 10:
        print(
            f"{kind}|active_defects={defects}|fps={rec.fp_by_kind.get(kind, 0)}|"
            f"clean_sentinels={clean[kind]}|tp_specimens={tp[kind]}|"
            "status=sentinel-gated-low-sample"
        )
PY
```

Copy every emitted row into the Task 10 implementation receipt/Filigree comment. Do not report an FP percentage for those kinds as validated; the status is `sentinel-gated-low-sample`.

**Decision gate:** if the resulting global or per-kind budget fails, STOP — do not relabel findings to pass. Report the failing rate and offending rule ids (preview-rule triage is a separate decision).

- [ ] **Step 5: Run the corpus suite** — `cd tests && uv run pytest corpus -v`. Expected: PASS (or the documented STOP).

- [ ] **Step 6: Full suite** — `uv run pytest -q`. Expected: PASS.

- [ ] **Step 7: Commit** — `test(corpus): strict manifest (keys/rules/maturity/kind/files), preview findings reconciled, per-kind FP gate (S0 P1-P3)`

---

### Task 11: Determinism guard covers `sentinels/` (P4)

**Files:**
- Modify: `tests/grammar/test_output_determinism.py:27,30-39`

- [ ] **Step 1: Extend the corpus glob.** Replace the single-root constant (:27) and collection (:37):

```python
_CORPUS_ROOTS = (
    REPO_ROOT / "tests" / "corpus" / "fixtures",
    REPO_ROOT / "tests" / "corpus" / "sentinels",
)
```

and in `_corpus_findings`: `files = sorted(p for root in _CORPUS_ROOTS for p in root.rglob("*.py"))`. Update the docstring: "…over the fixed corpus (fixtures/ AND sentinels/ — P4: sentinel-shape churn gets the same two-run byte guard)". `test_builtin_source_defects_have_source_lines` (:53-59) inherits the wider glob unchanged.

- [ ] **Step 2: Run it twice to prove stability** — `uv run pytest tests/grammar/test_output_determinism.py -v && uv run pytest tests/grammar/test_output_determinism.py -v`. Expected: PASS both times.

- [ ] **Step 3: Commit** — `test(determinism): two-run byte guard covers corpus sentinels (S0 P4)`

---

### Task 12: Canonical-orderings pin (P7)

**Files:**
- Create: `tests/conformance/test_canonical_orderings.py`

All expectations below were VERIFIED against the live APIs on 2026-08-09 (baseline top-level keys `fingerprint_scheme/version/entries`; entry keys `fingerprint/rule_id/path/message`; dedup via `unique.setdefault(f.fingerprint, ...)`; sort key `(_SEVERITY_SORT, rule_id, path, fingerprint)`; `to_jsonl` keys sorted; `_canonical_bytes` compact key-sorted).

- [ ] **Step 1: Write the pins** (these pass immediately — they FREEZE current behaviour so the S1+ serialisation work cannot un-sort anything silently):

```python
"""P7 — canonical orderings pinned at every serialisation seam.

The declaration ledger (S1+) inherits these seams; each is pinned here so an
ordering regression is a named failure, not a byte-drift mystery."""

from __future__ import annotations

import json

from wardline.core.attest import _canonical_bytes
from wardline.core.baseline import build_baseline_document
from wardline.core.finding import Finding, Kind, Location, Severity, compute_finding_fingerprint


def _finding(rule_id: str, path: str, severity: Severity, qualname: str | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="m",
        severity=severity,
        kind=Kind.DEFECT,
        location=Location(path=path, line_start=1),
        fingerprint=compute_finding_fingerprint(rule_id=rule_id, path=path, qualname=qualname),
        qualname=qualname,
    )


def test_finding_jsonl_keys_are_sorted() -> None:
    payload = json.loads(_finding("PY-WL-101", "a.py", Severity.ERROR).to_jsonl())
    assert list(payload) == sorted(payload)


def test_attest_canonical_bytes_are_key_sorted_and_compact() -> None:
    assert _canonical_bytes({"b": 1, "a": {"d": 2, "c": 3}}) == b'{"a":{"c":3,"d":2},"b":1}'


def test_baseline_document_shape_is_pinned() -> None:
    doc = build_baseline_document([_finding("PY-WL-101", "a.py", Severity.ERROR)])
    assert list(doc) == ["fingerprint_scheme", "version", "entries"]
    assert list(doc["entries"][0]) == ["fingerprint", "rule_id", "path", "message"]


def test_baseline_orders_by_severity_then_rule_then_path_then_fingerprint() -> None:
    tie_a = _finding("PY-WL-101", "b.py", Severity.ERROR)               # no qualname
    tie_b = _finding("PY-WL-101", "b.py", Severity.ERROR, qualname="m.g")  # same (sev,rule,path), distinct fp
    findings = [
        _finding("PY-WL-108", "b.py", Severity.ERROR),
        _finding("PY-WL-101", "a.py", Severity.CRITICAL),
        tie_a,
        tie_b,
        _finding("PY-WL-101", "a.py", Severity.CRITICAL),  # duplicate fingerprint -> dedup, first wins
    ]
    doc = build_baseline_document(findings)
    assert len(doc["entries"]) == 4  # dedup collapsed the repeat
    assert [(e["rule_id"], e["path"]) for e in doc["entries"]] == [
        ("PY-WL-101", "a.py"),  # CRITICAL sorts first
        ("PY-WL-101", "b.py"),
        ("PY-WL-101", "b.py"),
        ("PY-WL-108", "b.py"),
    ]
    # The (severity, rule, path) tie breaks on the fingerprint hex, ascending.
    assert [e["fingerprint"] for e in doc["entries"][1:3]] == sorted([tie_a.fingerprint, tie_b.fingerprint])


def test_path_order_is_independent_of_input_and_fingerprint_order() -> None:
    from dataclasses import replace

    a = _finding("PY-WL-101", "a.py", Severity.ERROR)
    z = _finding("PY-WL-101", "z.py", Severity.ERROR)
    # Reverse fingerprint lexicographic order so this fails if fingerprint ever
    # outranks path, and reverse the input so iteration order cannot rescue it.
    a = replace(a, fingerprint="f" * 64)
    z = replace(z, fingerprint="0" * 64)
    doc = build_baseline_document([z, a])
    assert [entry["path"] for entry in doc["entries"]] == ["a.py", "z.py"]
```

- [ ] **Step 2: Run** — `uv run pytest tests/conformance/test_canonical_orderings.py -v`. Expected: PASS immediately (if any pin genuinely fails, that is a live serialisation bug — stop and report).

- [ ] **Step 3: Commit** — `test(conformance): pin canonical orderings at the serialisation seams (S0 P7)`

---

### Task 13: Provider-fingerprint mutation table + `builtin` joins the digest (P8)

**Files:**
- Modify: `src/wardline/scanner/taint/decorator_provider.py:274-289` (`_grammar_digest`)
- Create: `tests/unit/scanner/taint/test_provider_fingerprint_mutations.py`

**Interfaces:** `_grammar_digest` becomes a full 64-hex SHA-256 over compact, key-sorted canonical JSON for every `BoundaryType`: canonical name, module prefix, group, builtin flag, ordered level-argument schema, and structural seed identity. No delimiter-joined preimage and no truncated digest are permitted. This changes cache keys for custom grammars only; the builtin-only provider fingerprint remains the literal `"decorator-vocab:wardline-generic-2"`.

- [ ] **Step 1: Fix the digest.** Build a JSON-serializable list of typed records, encode with `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True)`, and return `hashlib.sha256(payload).hexdigest()`. Replace `_seed_identity`, closure/global/default value identities, and nested code identities with structured JSON values—no delimiter-joined string may survive inside the preimage. The seed record includes module and qualname as distinct fields plus a normalized code-object structure sufficient to distinguish bytecode, constants, names, freevars, and nested code while excluding filename/first-line/layout noise. Include `builtin` explicitly. The result is always 64 lowercase hex characters.

- [ ] **Step 2: Write the mutation table** — `tests/unit/scanner/taint/test_provider_fingerprint_mutations.py`:

```python
"""P8 — the provider fingerprint moves iff the declaration surface moves.

Mutation table: every component of a grammar's identity (name, prefix, group,
builtin flag, level-arg schema, seed body, order) must change the fingerprint.
Reformat stability: cosmetic re-authoring of an identical seed must NOT change
it. The builtin literal is pinned so a REGISTRY_VERSION drift in S0 is loud."""

from __future__ import annotations

import pytest

from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, LevelArg
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
from wardline.scanner.taint.provider import FunctionTaint

_ALLOWED = frozenset({TaintState.GUARDED, TaintState.ASSURED})


def _seed(levels):
    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])


def _bt(
    name="sanitized",
    prefix="myproj.trust",
    group=1,
    arg="to_level",
    allowed=_ALLOWED,
    default=None,
    seed=_seed,
    builtin=False,
):
    return BoundaryType(
        canonical_name=name,
        module_prefix=prefix,
        group=group,
        level_args=(LevelArg(arg, allowed, default),),
        seed=seed,
        builtin=builtin,
    )


def _fp(*bts) -> str:
    return DecoratorTaintSourceProvider(boundary_types=tuple(bts)).fingerprint()


BASE = _bt()

MUTATIONS = {
    "canonical_name": _bt(name="cleansed"),
    "module_prefix": _bt(prefix="otherproj.trust"),
    "group": _bt(group=2),
    "builtin_flag": _bt(builtin=True),
    "arg_name": _bt(arg="level"),
    "allowed_set": _bt(allowed=frozenset({TaintState.ASSURED})),
    "default": _bt(default=TaintState.GUARDED),
}


@pytest.mark.parametrize("label", sorted(MUTATIONS))
def test_mutation_changes_fingerprint(label: str) -> None:
    assert _fp(BASE) != _fp(MUTATIONS[label]), f"mutating {label} did not move the fingerprint"


def test_seed_body_mutation_changes_fingerprint() -> None:
    def other_seed(levels):
        return FunctionTaint(TaintState.UNKNOWN_RAW, levels["to_level"])

    assert _fp(BASE) != _fp(_bt(seed=other_seed))


def test_boundary_order_changes_fingerprint() -> None:
    a, b = _bt(name="alpha"), _bt(name="beta")
    assert _fp(a, b) != _fp(b, a)


def test_finite_mutation_table_has_distinct_fingerprints() -> None:
    fps = {_fp(BASE)} | {_fp(m) for m in MUTATIONS.values()} | {_fp(_bt(name="alpha"), _bt(name="beta"))}
    assert len(fps) == len(MUTATIONS) + 2


def test_adversarial_nul_delimiter_pairs_do_not_collide() -> None:
    # These would be ambiguous under delimiter-joined strings.
    left = _bt(name="a\0b", prefix="c")
    right = _bt(name="a", prefix="b\0c")
    assert _fp(left) != _fp(right)


def test_seed_module_qualname_delimiter_shift_does_not_collide() -> None:
    a = _compile_seed('    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])\n')
    b = _compile_seed('    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])\n')
    a.__module__, a.__qualname__ = "x|y", "z"
    b.__module__, b.__qualname__ = "x", "y|z"
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


def _compile_seed(body: str):
    ns = {"FunctionTaint": FunctionTaint, "TaintState": TaintState}
    exec(compile("def seed(levels):\n" + body, "<generated>", "exec"), ns)
    return ns["seed"]


def test_reformat_stability_of_an_identical_seed() -> None:
    a = _compile_seed('    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])\n')
    b = _compile_seed('    # layout-only change\n    return FunctionTaint( TaintState.EXTERNAL_RAW, levels["to_level"] )\n')
    assert _fp(_bt(seed=a)) == _fp(_bt(seed=b))


def test_same_module_qualname_body_mutation_changes_fingerprint() -> None:
    a = _compile_seed('    return FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"])\n')
    b = _compile_seed('    return FunctionTaint(TaintState.UNKNOWN_RAW, levels["to_level"])\n')
    assert a.__module__ == b.__module__ and a.__qualname__ == b.__qualname__
    assert _fp(_bt(seed=a)) != _fp(_bt(seed=b))


def test_custom_digest_is_full_sha256() -> None:
    prefix, sep, digest = _fp(BASE).partition("+grammar:")
    assert sep and prefix == "decorator-vocab:wardline-generic-2"
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")


def test_builtin_fingerprint_literal_is_pinned_for_s0() -> None:
    # S0 must not move the vocabulary version; the S1 generic-3 bump updates this pin.
    assert DecoratorTaintSourceProvider().fingerprint() == "decorator-vocab:wardline-generic-2"
```

Add a nested-code pair to the reformat test (a seed containing an inner helper/lambda): layout/comment-only edits remain stable, while a constant/body mutation inside the nested code moves the digest. The structural normalization recurses into nested `CodeType` constants; `repr(code.co_consts)` is not an accepted canonical form.

- [ ] **Step 3: Run** — `uv run pytest tests/unit/scanner/taint/test_provider_fingerprint_mutations.py tests/unit/scanner/taint -q` then full suite. Expected: PASS (the digest change invalidates no builtin cache and no test pins a custom digest).

- [ ] **Step 4: Commit** — `test(provider): fingerprint mutation table incl. builtin flag; collision pairs; reformat stability (S0 P8)`

---

### Task 14: Drop-coverage matrix + the malformity asymmetry, named pins (P10)

**Files:**
- Create: `tests/grammar/test_drop_coverage_matrix.py`
- Create: `tests/grammar/test_malformity_asymmetry.py`

**Interfaces:** Consumes Tasks 5–8. The matrix is the "specified and tested" answer to "fires exactly where the seed drops": every builtin seed-drop shape maps to EXACTLY ONE of **four** channels — `PY-WL-130` (call SHAPE), `PY-WL-114` (a value that READ but is not a legal token), `WLN-ENGINE-UNREADABLE-MARKER-VALUE` (`Severity.NONE` FACT — every builtin LEVEL value that stays unreadable after P3 form 5), and the ONE remaining pinned deliberate silence, a shadowed builtin vocabulary root, which disables the marker candidate so no builtin LEVEL slot exists at all. **A statically-unreadable builtin LEVEL value is NEVER silent** (spec rev 6 §4.2.1). **The shape gate short-circuits, and the matrix pins it:** Task 5 runs `call_shape_offences` before the levels loop, so a marker that is BOTH shape-malformed and value-unreadable takes `PY-WL-130` and NOT the FACT — the value was never read, so it never entered the verdict vocabulary. The honest reading, which no step or receipt may overstate: `PY-WL-130` gates but is a `Kind.DEFECT` and therefore suppressible, while the FACT is unsuppressible but never gates. Neither channel dominates; the ordering is justified on the shipped **secure default** — under `trust_suppressions=False`, `run_scan` rebuilds `gate_population_findings` with an empty `Baseline`, an empty `WaiverSet` and `judged=None`, so a waived or baselined `PY-WL-130` still trips `--fail-on` and the site loses its signal only under an explicit `--trust-suppressions` operator decision (spec rev 9 §4.2.1, which replaces rev 8's P13 clause; P13 is a **repository-scoped** ceiling and never bore that weight) — plus noise avoidance, and never on one channel being "strictly louder". **The matrix is builtin-only by construction** (`run_scan` loads no custom grammar), so the one custom-side cell it cannot reach — a positional argument on a custom `BoundaryType` with a **defaulted** `LevelArg`, which is `read_level`'s positional guard and nothing else, `call_shape_offences` being builtin-only — is pinned in Step 2's asymmetry module as `test_custom_positional_argument_never_takes_a_defaulted_level`. Without it the matrix has a hole on precisely the axis where a dropped guard mints a trusted seed with nothing red.

- [ ] **Step 1: Write the matrix** — `tests/grammar/test_drop_coverage_matrix.py`:

```python
"""The builtin seed-drop coverage matrix (P10 / wardline-4928b75782,
wardline-2b2a6cddfa).

Every shape that makes a builtin marker's seed drop is enumerated with the ONE
diagnostic channel that owns it. There are exactly FOUR channels: PY-WL-130
(call SHAPE), PY-WL-114 (a value that READ but is not a legal token),
WLN-ENGINE-UNREADABLE-MARKER-VALUE (a Severity.NONE FACT — every builtin LEVEL
value that stays unreadable after P3 form 5), and the ONE remaining deliberate
silence, a shadowed builtin vocabulary root, which disables the marker candidate
so no builtin LEVEL slot exists at all. A statically-unreadable builtin LEVEL
value is NEVER silent, and anything else going silent is a regression.

ORDERING IS NORMATIVE AND THIS MATRIX PINS IT. Task 5 runs call_shape_offences
BEFORE the levels loop, so a marker whose call shape is malformed drops its seed
without any level being read. A marker that is BOTH shape-malformed and
value-unreadable therefore takes PY-WL-130 and NOT the FACT; the
`malformed_shape_and_unreadable_value` row is what pins that, and the
`fired == {channel}` exclusivity assertion below is what carries its negative
half. Do not weaken that assertion to a presence-only check. Note the honest
reading: PY-WL-130 is a Kind.DEFECT and therefore suppressible, while the FACT
is unsuppressible but never gates — neither channel dominates, so the ordering
rests on noise avoidance and on the shipped secure default (at
trust_suppressions=False the gate population is rebuilt with an empty baseline
and waiver set, so a waived PY-WL-130 still trips --fail-on), not on dominance.

Task 5 deliberately does NOT demote a malformed builtin's seed to UNKNOWN_RAW:
that would move the function into RAW_ZONE, where modulate() returns
Severity.NONE and PY-WL-101 skips the declared tier — silencing the tier-gated
rules that currently fire on it.

ASSERTIONS RUN OVER ALL KINDS. Filtering to Kind.DEFECT would make the
Severity.NONE FACT invisible before any assertion saw it — a false green inside
the guard whose entire purpose is proving there are none.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.run import run_scan

# `Kind` is deliberately NOT imported: the assertions below run over ALL kinds,
# because a Kind.DEFECT filter would hide the Severity.NONE residual FACT.
_MARKER_CHANNELS = frozenset(
    {"PY-WL-130", "PY-WL-114", "WLN-ENGINE-UNREADABLE-MARKER-VALUE"}
)

_IMPORTS = "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
# CFG now RESOLVES under P3 form 5: one unconditional direct-top-level `str`
# binding, no other module-scope occurrence, lexically preceding a `def` that is a
# direct element of the module body, in a BUILTIN LEVEL slot. DYN does NOT: a call
# right-hand side is an explicitly refused shape (spec §4.2.1), so DYN is the
# binding that exercises the residual FACT. Neither name is rebound anywhere, and
# the module carries no star import — both preconditions the census checks.
_RUNTIME_VALUES = (
    "KW = {'level': 'ASSURED'}\nCFG = 'ASSURED'\nARGS = ()\n"
    "def get_level():\n    return 'ASSURED'\n"
    "DYN = get_level()\n"
    "def audit_fn(x):\n    return x\n"
)

# (case id, decorator line, expected channel, seed must drop)
MATRIX = [
    ("positional", "@trusted('ASSURED')", "PY-WL-130", True),
    ("undeclared_kwarg", "@trusted(level='ASSURED', audit=True)", "PY-WL-130", True),
    ("legacy_to_level", "@trusted(level='ASSURED', to_level='ASSURED')", "PY-WL-130", True),
    ("external_called_empty", "@external_boundary()", "PY-WL-130", True),
    ("external_called_empty_splat", "@external_boundary(**{})", "PY-WL-130", True),
    ("external_boundary_kwarg", "@external_boundary(source='http')", "PY-WL-130", True),
    ("dynamic_splat", "@trusted(**KW)", "PY-WL-130", True),
    ("invalid_literal_splat_key", "@trusted(**{1: 'ASSURED'})", "PY-WL-130", True),
    # Runtime-INVALID, like its neighbour above — which is why it sits ABOVE the
    # comment that follows rather than inside it. Verified at the interpreter:
    # `trusted(level='ASSURED', **{'level': 'ASSURED'})` raises TypeError (got
    # multiple values for keyword argument 'level'), and Task 6's clause table
    # correctly requires the runtime-invalid clause for its `duplicate_kwarg`
    # row. This matrix asserts CHANNELS only, so no diagnostic was ever
    # mis-built; what was wrong was the comment shipped over the row.
    ("duplicate_via_splat", "@trusted(level='ASSURED', **{'level': 'ASSURED'})", "PY-WL-130", True),
    # These four are RUNTIME-VALID calls that Wardline nonetheless refuses to
    # honour as declarations: they fire PY-WL-130 WITHOUT the runtime-invalid
    # clause (Task 6's truthfulness split — the diagnostic says the shape is
    # outside the statically readable declaration grammar, never that Python
    # raises TypeError). They are exactly Task 6's four `claims_runtime_invalid=
    # False` cases; the count in this comment is load-bearing, so keep the two
    # lists in step.
    ("positional_callable", "@trusted(audit_fn)", "PY-WL-130", True),
    ("star_args", "@trusted(*ARGS)", "PY-WL-130", True),
    ("computed_splat_key", "@trusted(**{'lev' + 'el': 'ASSURED'})", "PY-WL-130", True),
    ("external_called_with_callable", "@external_boundary(audit_fn)", "PY-WL-130", True),
    ("literal_splat_level_typo", "@trusted(**{'level': 'ASURED'})", "PY-WL-114", True),
    ("bare_required", "@trust_boundary", "PY-WL-130", True),
    ("zero_arg_required", "@trust_boundary()", "PY-WL-130", True),
    ("typo_level", "@trusted(level='ASURED')", "PY-WL-114", True),
    ("out_of_range_level", "@trust_boundary(to_level='INTEGRAL')", "PY-WL-114", True),
    # INVERTED at spec rev 6: CFG satisfies P3 form 5 in full, so this resolves and
    # the seed STANDS. The pre-rev-6 row pinned the silence as a passing contract.
    ("form5_module_constant_resolves", "@trusted(level=CFG)", "none", False),
    # What stays unreadable is OBSERVABLE, never silent — one row per builtin LEVEL
    # keyword, so `to_level=` on @trust_boundary is not left behind.
    ("unreadable_value_call_rhs", "@trusted(level=DYN)", "WLN-ENGINE-UNREADABLE-MARKER-VALUE", True),
    ("unreadable_to_level_call_rhs", "@trust_boundary(to_level=DYN)", "WLN-ENGINE-UNREADABLE-MARKER-VALUE", True),
    # THE SHORT-CIRCUIT ROW. Shape-malformed AND value-unreadable on one marker:
    # call_shape_offences runs BEFORE the levels loop, so no level is read and the
    # FACT is never emitted. The exclusivity assertion below carries the negative
    # half — this is the one row in the matrix that pins a channel's ABSENCE.
    ("malformed_shape_and_unreadable_value", "@trusted(level=DYN, audit=True)", "PY-WL-130", True),
    ("well_formed", "@trusted(level='ASSURED')", "none", False),
    ("bare_defaulted", "@trusted", "none", False),
]


@pytest.mark.parametrize(("case", "deco", "channel", "drops"), MATRIX, ids=[m[0] for m in MATRIX])
def test_drop_coverage(tmp_path: Path, case: str, deco: str, channel: str, drops: bool) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        f"{_IMPORTS}{_RUNTIME_VALUES}{deco}\ndef f(p):\n    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert result.context is not None
    assert ("svc.f" not in result.context.declared_qualnames) is drops, case
    # Over ALL kinds. The residual channel is a Severity.NONE FACT, so a
    # Kind.DEFECT filter here would make it invisible before any assertion saw it.
    fired = {f.rule_id for f in result.findings} & _MARKER_CHANNELS
    if channel == "none":
        # The pure-absence branch survives ONLY for rows whose channel is literally
        # "none", and only because those rows do not drop the seed.
        assert not drops, f"{case}: a dropped seed must always name a channel"
        assert not fired, f"{case}: expected no marker channel, fired {sorted(fired)}"
    else:
        # Presence AND exclusivity over the full marker channel set, in one
        # assertion. Do NOT weaken this to a presence-only check: exclusivity is the
        # never-two-channels property, and it is also the FACT-absent half of the
        # `malformed_shape_and_unreadable_value` row that pins the shape-gate
        # short-circuit.
        assert fired == {channel}, f"{case}: expected exactly {channel}, fired {sorted(fired)}"


def test_shadowed_root_is_the_only_deliberate_silence(tmp_path: Path) -> None:
    # The shadow disables the marker candidate wholesale, so no builtin LEVEL slot
    # exists to be read — this is the one silence left after spec rev 6.
    #
    # (Assertions below are unchanged and remain sound.)
    proj = tmp_path / "proj"
    (proj / "wardline" / "decorators").mkdir(parents=True)
    (proj / "wardline" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "wardline" / "decorators" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "svc.py").write_text(
        f"{_IMPORTS}@trusted(level='ASSURED', audit=True)\ndef f(p):\n    return p\n", encoding="utf-8"
    )
    result = run_scan(proj)
    assert not [f for f in result.findings if f.rule_id in ("PY-WL-130", "PY-WL-114")]
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames
```

- [ ] **Step 2: Write the asymmetry pin** — `tests/grammar/test_malformity_asymmetry.py`:

```python
"""P10 — the malformity asymmetry, pinned by name.

Malformed BUILTIN declarations are ERROR DEFECTs (PY-WL-130 for call shape,
PY-WL-114 for readable-but-invalid levels): the builtin vocabulary is provable,
so malformity gates. Malformed CUSTOM/pack declarations are FACTs
(WLN-ENGINE-UNPROVABLE-BOUNDARY): the custom path is the unprovable one, so it
observes without gating. Neither channel may leak into the other.

This module also carries the ONE custom-side cell the drop-coverage matrix
cannot reach. That matrix is builtin-only by construction (run_scan loads no
custom grammar, and _MARKER_CHANNELS holds three builtin channels), so the
custom arm of read_level's positional guard is pinned here — the axis on which
a dropped guard mints a trusted seed with nothing red."""

from __future__ import annotations

from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.core.run import run_scan
from wardline.core.taints import TaintState
from wardline.scanner.analyzer import build_analyzer
from wardline.scanner.grammar import BoundaryType, LevelArg, default_grammar
from wardline.scanner.taint.provider import FunctionTaint

_CUSTOM = BoundaryType(
    canonical_name="sanitized",
    module_prefix="myproj.trust",
    group=1,
    level_args=(LevelArg("to_level", frozenset({TaintState.GUARDED, TaintState.ASSURED}), None),),
    seed=lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]),
    builtin=False,
)


def test_builtin_malformed_call_is_an_error_defect_and_no_fact(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(
        "from wardline.decorators import trusted\n"
        "@trusted(level='INTEGRAL', audit=True)\n"
        "def f(p):\n"
        "    return p\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    hits = [f for f in result.findings if f.rule_id == "PY-WL-130"]
    assert len(hits) == 1 and hits[0].severity is Severity.ERROR and hits[0].kind is Kind.DEFECT
    assert not [f for f in result.findings if f.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]


def test_custom_malformed_marker_is_a_fact_and_never_pywl130(tmp_path: Path) -> None:
    # The exact construction tests/grammar/test_unprovable_boundary.py:19-26 uses.
    f = tmp_path / "m.py"
    f.write_text(
        "import myproj.trust\n@myproj.trust.sanitized(to_level=CFG, extra=1)\ndef g(p):\n    return p\n",
        encoding="utf-8",
    )
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(_CUSTOM,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    facts = [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]
    assert len(facts) == 1 and facts[0].severity is Severity.NONE and facts[0].kind is Kind.FACT
    assert not [x for x in findings if x.rule_id == "PY-WL-130"]
    assert analyzer.last_context is not None
    assert analyzer.last_context.project_taints["m.g"] == TaintState.UNKNOWN_RAW


def test_custom_level_marker_with_foreign_metadata_remains_unprovable(tmp_path: Path) -> None:
    f = tmp_path / "m.py"
    f.write_text(
        "import myproj.trust\n"
        "@myproj.trust.sanitized(to_level='ASSURED', extra=1)\n"
        "def g(p):\n    return p\n",
        encoding="utf-8",
    )
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(_CUSTOM,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    assert [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"]
    assert not [x for x in findings if x.rule_id == "PY-WL-130"]
    assert analyzer.last_context is not None
    assert analyzer.last_context.project_taints["m.g"] == TaintState.UNKNOWN_RAW


def test_custom_zero_level_metadata_is_ignored_and_still_seeds(tmp_path: Path) -> None:
    custom = BoundaryType(
        canonical_name="source",
        module_prefix="myproj.trust",
        group=1,
        level_args=(),
        seed=lambda _lv: FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.EXTERNAL_RAW),
        builtin=False,
    )
    f = tmp_path / "m.py"
    f.write_text(
        "import myproj.trust\n@myproj.trust.source(owner='payments')\ndef g(p):\n    return p\n",
        encoding="utf-8",
    )
    analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(custom,)))
    findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
    assert not [x for x in findings if x.rule_id == "PY-WL-130"]
    assert analyzer.last_context is not None
    assert analyzer.last_context.project_taints["m.g"] == TaintState.EXTERNAL_RAW


def test_custom_positional_argument_never_takes_a_defaulted_level(tmp_path: Path) -> None:
    # THE CUSTOM SIDE'S POSITIONAL GUARD, end to end — and the one cell on this
    # axis, because the drop-coverage matrix beside it is builtin-only by
    # construction (`run_scan` loads no custom grammar). `call_shape_offences`
    # and PY-WL-130 are builtin-only by design (spec §4.2.1; Global Constraints'
    # hard custom-pack gate), so `read_level`'s `if deco.args: return
    # _unreadable(None)` (Task 2 Step 1) is the ONLY thing between a positional
    # custom marker and a minted trusted seed.
    #
    # This pack declares a DEFAULTED `LevelArg` — the shape wardline's own
    # builtins use (boundary_types.py:108, :125), and therefore the one a pack
    # author copies. Drop the guard and both rows below take `_defaulted()`,
    # seeding ASSURED with no finding on any channel. Every custom `LevelArg` in
    # this tree passes `default=None` (measured 2026-08-10), so nothing else
    # would red: this row exists precisely because zero reds is the mechanism by
    # which that regression ships.
    custom = BoundaryType(
        canonical_name="sanitized",
        module_prefix="myproj.trust",
        group=1,
        level_args=(
            LevelArg(
                "to_level",
                frozenset({TaintState.GUARDED, TaintState.ASSURED}),
                TaintState.ASSURED,
            ),
        ),
        seed=lambda lv: FunctionTaint(TaintState.EXTERNAL_RAW, lv["to_level"]),
        builtin=False,
    )
    for deco in ("@myproj.trust.sanitized('ASSURED')", "@myproj.trust.sanitized(*ARGS)"):
        f = tmp_path / "m.py"
        f.write_text(
            f"import myproj.trust\nARGS = ('ASSURED',)\n{deco}\ndef g(p):\n    return p\n",
            encoding="utf-8",
        )
        analyzer = build_analyzer(grammar=default_grammar().extend(boundary_types=(custom,)))
        findings = analyzer.analyze([f], WardlineConfig(), root=tmp_path)
        assert [x for x in findings if x.rule_id == "WLN-ENGINE-UNPROVABLE-BOUNDARY"], deco
        assert not [x for x in findings if x.rule_id == "PY-WL-130"], deco
        assert analyzer.last_context is not None
        assert analyzer.last_context.project_taints["m.g"] == TaintState.UNKNOWN_RAW, deco
```

- [ ] **Step 3: Run** — `uv run pytest tests/grammar/test_drop_coverage_matrix.py tests/grammar/test_malformity_asymmetry.py -v`. Expected: PASS.

- [ ] **Step 4: Commit** — `test(grammar): builtin seed-drop coverage matrix + builtin-DEFECT vs custom-FACT asymmetry pins (S0 P10)`

---

### Task 15: Invariant split + RAW_ZONE matrix + inertness-denominator pins (P5, P6, P12) + preserve two already-filed defect pins

**Files:**
- Modify: `tests/unit/core/test_taint_invariants.py:29-41`
- Create: `tests/unit/core/test_raw_zone_matrix.py`
- Create: `tests/unit/core/test_resolution_posture_pins.py`

- [ ] **Step 1: Split the never-produced invariant (P5).** In `tests/unit/core/test_taint_invariants.py`, replace the `UNREACHABLE` definition (:29-30) and the trio test (:33-41) with:

```python
# P5 (declaration-surface-v2 §8.4): the old "trio" splits into two invariants
# with different lifetimes. MIXED_RAW is the taint_join falsification record —
# NEVER produced, permanently. UNKNOWN_ASSURED/UNKNOWN_GUARDED are reserved for
# witnessed restoration declarations (S3): until restoration ships they are
# equally unproduced, and after it ships they may appear ONLY with a witness.
NEVER_PRODUCED: frozenset[TaintState] = frozenset({TaintState.MIXED_RAW})
RESTORATION_ONLY: frozenset[TaintState] = frozenset(
    {TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_GUARDED}
)
UNREACHABLE: frozenset[TaintState] = NEVER_PRODUCED | RESTORATION_ONLY


def test_unreachable_set_is_the_two_partitions() -> None:
    assert UNREACHABLE == frozenset(TaintState) - REACHABLE
    assert NEVER_PRODUCED.isdisjoint(RESTORATION_ONLY)
```

Everything else in the file — `REACHABLE`, both closure tests, `_CORPUS`, `test_no_unreachable_state_in_scan_output` — stays byte-identical (the pipeline test still asserts `state not in UNREACHABLE`; S3 will narrow it to `NEVER_PRODUCED` + witness checks, not S0).

- [ ] **Step 2: RAW_ZONE × reserved-states matrix (P6)** — `tests/unit/core/test_raw_zone_matrix.py`. The `_DOWNGRADE` map below is copied verbatim from `src/wardline/scanner/rules/severity_model.py:38-44`; `_TRUSTED`/`_PARTIAL` from `:17-20`:

```python
"""P6 — the RAW_ZONE x reserved-states decision matrix, pinned before S3 exists.

Both restoration states sit OUTSIDE RAW_ZONE (they are uplifted, unknown-
provenance states, not raw ones), and the severity model already treats them as
_PARTIAL (one step down) — a deliberate, stated policy the S3 work must not
re-litigate silently."""

from __future__ import annotations

import itertools

import pytest

from wardline.core.finding import Severity
from wardline.core.taints import RAW_ZONE, TaintState
from wardline.scanner.rules.severity_model import modulate

_TRUSTED = {TaintState.INTEGRAL, TaintState.ASSURED}
_PARTIAL = {TaintState.GUARDED, TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_GUARDED}
_DOWNGRADE = {
    Severity.CRITICAL: Severity.ERROR,
    Severity.ERROR: Severity.WARN,
    Severity.WARN: Severity.INFO,
    Severity.INFO: Severity.INFO,  # floor — never below INFO via downgrade
    Severity.NONE: Severity.NONE,
}


def test_raw_zone_membership_is_pinned() -> None:
    assert RAW_ZONE == frozenset({TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW})
    assert TaintState.UNKNOWN_ASSURED not in RAW_ZONE
    assert TaintState.UNKNOWN_GUARDED not in RAW_ZONE


@pytest.mark.parametrize(
    ("base", "taint"),
    list(itertools.product((Severity.CRITICAL, Severity.ERROR, Severity.WARN, Severity.INFO), TaintState)),
)
def test_modulate_full_matrix(base: Severity, taint: TaintState) -> None:
    expected = base if taint in _TRUSTED else _DOWNGRADE[base] if taint in _PARTIAL else Severity.NONE
    assert modulate(base, taint) is expected
```

- [ ] **Step 3: Inertness-denominator pins (P12)** — `tests/unit/core/test_resolution_posture_pins.py`. (Names verified: `_MIN_FUNCTIONS` :48, `_RECOGNIZED_BOUNDARY_BUCKETS` :44 — Z spelling; `compute_resolution_posture(findings)` :78 reads `WLN-ENGINE-METRICS` properties.)

```python
"""P12 — the inertness denominators, decided and pinned (declaration-surface-v2 §11.4).

Decision of record for S0: recognition buckets are ("anchored", "config"); the
non-trivial-scan floor is 5 analyzed functions; the trip is recognized==0 over
a scan at/above the floor. S1's per-group arming EXTENDS this base (one counter
per declaration group; uplift-only groups never de-inert) — it must not move it.

KNOWN LIMITATION (filed, not fixed here): project_resolver.py:285-289 emits only
{anchored, module_default, fallback} into taint_source_counts — the "config" and
"callgraph" provenances never reach the histogram, so a config-sources-only
project computes INERT and functions_analyzed undercounts. These pins freeze the
POSTURE COMPUTATION's contract; the emission gap is the filed engine bug."""

from __future__ import annotations

from wardline.core.finding import Finding, Kind, Location, Severity, compute_finding_fingerprint
from wardline.core.resolution_posture import (
    _MIN_FUNCTIONS,
    _RECOGNIZED_BOUNDARY_BUCKETS,
    compute_resolution_posture,
)


def _metrics(counts: dict[str, int]) -> Finding:
    return Finding(
        rule_id="WLN-ENGINE-METRICS",
        message="m",
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path="<engine>"),
        fingerprint=compute_finding_fingerprint(rule_id="WLN-ENGINE-METRICS", path="<engine>"),
        properties={"taint_source_counts": counts},
    )


def test_denominator_constants_are_pinned() -> None:
    assert _MIN_FUNCTIONS == 5
    assert _RECOGNIZED_BOUNDARY_BUCKETS == ("anchored", "config")


def test_inert_iff_zero_recognized_at_or_above_floor() -> None:
    assert compute_resolution_posture([_metrics({"fallback": 5})]).inert is True
    assert compute_resolution_posture([_metrics({"fallback": 4})]).inert is False  # below floor
    assert compute_resolution_posture([_metrics({"fallback": 5, "anchored": 1})]).inert is False
    assert compute_resolution_posture([_metrics({"fallback": 5, "config": 1})]).inert is False
    # callgraph/module_default recognition does NOT clear the trip.
    assert compute_resolution_posture([_metrics({"fallback": 5, "callgraph": 3})]).inert is True
    assert compute_resolution_posture([_metrics({"fallback": 5, "module_default": 3})]).inert is True
```

- [ ] **Step 4: Run** — `uv run pytest tests/unit/core/test_taint_invariants.py tests/unit/core/test_raw_zone_matrix.py tests/unit/core/test_resolution_posture_pins.py -v`. Expected: PASS.

- [ ] **Step 5: The two discovered engine defects are ALREADY FILED** (2026-08-09, plan-revision pass; OUT of S0 scope because fixing them drifts the METRIC bytes in the golden / changes PY-WL-110 semantics) — nothing to do here beyond keeping the pin-file comments pointing at them:
  1. `wardline-7e0a3b1e3d` — `taint_source_counts` never emits the `config`/`callgraph` buckets (`project_resolver.py:285-289`); config-sources-only projects read INERT and `functions_analyzed` undercounts.
  2. `wardline-894faaec24` — PY-WL-110 counts markers off the AST irrespective of whether each seeded; its message can claim a clash resolution that never occurred.

- [ ] **Step 6: Commit** — `test(core): invariant split (NEVER_PRODUCED vs RESTORATION_ONLY), RAW_ZONE matrix, inertness denominator pins (S0 P5/P6/P12)`

---

### Task 16: Waiver ceiling decoupled from rule count (P13)

**Files:**
- Modify: `tests/corpus/test_waiver_discipline.py` (docstring :1-4; delete import :14; replace test :41-47)

- [ ] **Step 1: Replace the rule-count coupling.** Delete `from wardline.scanner.rules import _ALL_RULE_CLASSES` (:14). Rewrite the module docstring **by quotation, not by sentence ordinal** — verified against the live file, the coupling clause and the scope note sit in DIFFERENT sentences, so a literal "second sentence" rewrite would destroy the only record that this file guards the repo's own (dogfood) scan config rather than the corpus FP gate. In **sentence one**, replace `and waiver count does not outgrow rule count` with `and the waiver count stays within a fixed, reviewed budget`. Leave **sentence two** intact except its trailing `faster than the rule set that justifies it`, which becomes `beyond its reviewed budget`. Both clauses describe the coupling P13 removes; only the second one's sentence also carries the scope note, which is why it is edited by quotation and not replaced. The stale `# the curated builtin rule set (4 today)` comment (`:43` — the rule set is 27) needs no separate instruction: it lives inside the test the code block below replaces wholesale. Replace `test_waiver_count_not_outgrowing_rule_count` with:

```python
# P13: decoupled from rule count. The old `<= len(_ALL_RULE_CLASSES)` ceiling
# silently grew from 4 to 27 as rules shipped — a suppression budget must not
# scale with the detection surface it suppresses. The repo carries ZERO waivers
# today. Five is the reviewed risk ceiling (not current usage): enough room for
# explicitly triaged false positives without coupling growth to the number of
# rules. Raising this constant requires a dedicated review with a named owner
# and rationale; adding a rule never creates suppression headroom as a side effect.
_WAIVER_CEILING = 5


def test_waiver_count_within_fixed_ceiling():
    waiver_count = len(_repo_waivers())
    assert waiver_count <= _WAIVER_CEILING, (
        f"waiver count {waiver_count} exceeds the fixed ceiling {_WAIVER_CEILING} — "
        "suppression is outgrowing its reviewed budget (FP-economics breach)"
    )
```

- [ ] **Step 2: Run** — `uv run pytest tests/corpus/test_waiver_discipline.py -v`. Expected: PASS (repo has zero waivers).

- [ ] **Step 3: Commit** — `test(corpus): waiver ceiling is a fixed reviewed risk budget, decoupled from rule count (S0 P13)`

---

### Task 17: CODEOWNERS for the identity corpus + doc truth-up

**Files:**
- Create: `.github/CODEOWNERS`
- Modify: `tests/golden/identity/regen.py:6-8` (docstring), `tests/golden/identity/README.md:55-58`

- [ ] **Step 1: Create `.github/CODEOWNERS`:**

```
# Identity-corpus rekeys get routed to the maintainer for review. CODEOWNERS
# ROUTES review requests; it does not by itself enforce approval — enforcement
# is the branch-protection "require review from Code Owners" setting if/when
# enabled. The parity test remains the hard gate on the bytes themselves
# (tests/golden/identity/README.md).
/tests/golden/identity/corpus/ @tachyon-beep
```

- [ ] **Step 2: Truth-up the docs.** `regen.py` docstring: reword the enforcement claim to "the hard enforcement is the parity test; `.github/CODEOWNERS` routes `tests/golden/identity/corpus/` changes to the maintainer for review (approval enforcement requires the branch-protection Code Owners setting)". `README.md:55-58`: change "*Recommended complement* (not yet wired):" to "Wired: `.github/CODEOWNERS` routes `tests/golden/identity/corpus/` to the maintainer (routing, not approval enforcement)."

Optionally verify the live GitHub protection/ruleset through an authenticated read-only API call and record the result in the implementation receipt, but do not make a volatile protection-state claim in repository documentation. CODEOWNERS is routing only; the parity test is the repository gate.

- [ ] **Step 3: Commit** — `docs(golden): CODEOWNERS routing for the identity corpus; truth-up regen/README claims (S0)`

---

### Task 18: Changelog — S0 entries + version-bump discipline with precise terms

**Files:**
- Modify: `CHANGELOG.md` (under `## [Unreleased]`)

- [ ] **Step 1: Add under `### Added`:**

```markdown
- **PY-WL-130 — malformed or statically unverifiable builtin-marker calls are
  loud.** The diagnostic distinguishes three channels, and claims a runtime
  error only where the shipped signatures prove one. **Proved runtime-invalid:**
  a bare call-only marker, an undeclared or duplicated keyword, a missing
  required keyword, and a non-string constant `**` key. **Statically
  unverifiable:** a dynamic `**mapping`, or a literal dict with a computed key —
  both may be perfectly valid at runtime, but Wardline cannot prove they satisfy
  the marker grammar. **Declaration-grammar only:** calling a bare-only marker,
  and any positional or `*` argument — `@external_boundary(some_callable)` and
  `@trusted(audit_fn)` execute cleanly, they are simply not declarations
  Wardline will honour. A bare-only marker called with no argument
  (`@external_boundary()`, `@external_boundary(**{})`) is additionally a
  runtime `TypeError`; PY-WL-130's `call_not_allowed` message states that
  disjunction rather than picking a side. Every such shape previously
  UN-DECLARED the function silently (the seed dropped and every tier-modulated
  rule went quiet — the scan got greener on a typo). It is now an ERROR DEFECT
  sharing the exact call-shape validator seeding uses. **Two** companion FACTs
  ship beside it: `WLN-ENGINE-UNKNOWN-MARKER` surfaces vocabulary-rooted
  decorators this engine does not recognise (new-weft-markers-on-old-wardline
  skew), and `WLN-ENGINE-UNREADABLE-MARKER-VALUE` surfaces a builtin marker's
  LEVEL value that stays statically unreadable — counted in
  `decorator_coverage`'s new `unknown_markers` and `unreadable_marker_values`
  summary keys respectively.
- **A module-level constant is now read in a builtin marker's LEVEL slot (P3
  form 5).** `@trusted(level=_SVC_LEVEL)` with `_SVC_LEVEL = "ASSURED"` (or
  `TaintState.ASSURED`) at module top level now resolves, where it previously
  dropped the seed with no diagnostic on any channel. The discipline is
  deliberately narrow, and everything outside it stays unreadable: a bare name
  only — never a dotted attribute; the same file only; **one hop**, so a
  right-hand side that is itself a bare name does not resolve; exactly one
  binding of that name anywhere in module scope, at any statement depth,
  counting imports, `for`/`with`/`except` targets, augmented assignments
  (`+=`), `match` capture patterns, `del`, `def`, `class` and walrus
  bindings; that one binding direct-top-level, unconditional, a single
  `Name` target, and lexically before the decorated statement; no
  `global <name>` anywhere in the module; no unresolved star import in the
  module; and the decorated `def` / `async def` must itself be a **direct
  element of the module body** — a method, a nested `def`, or a
  conditionally-defined module-level `def` is unreadable whatever the module
  holds, because Python evaluates a decorator expression in the enclosing
  scope. **This changes gate colour.** Functions that were silently outside the
  declared set now enter it, so their tier-modulated defects fire; those
  findings are true positives by construction — the function was always a
  declared boundary and only the engine's inability to read the marker kept
  them quiet. `PY-WL-114` gains the same widened surface, so a named-but-invalid
  token such as `_SVC_LEVEL = "ASURED"` is now an ERROR DEFECT instead of
  silence.
- **`WLN-ENGINE-UNREADABLE-MARKER-VALUE` — what stays unreadable stays
  observable.** A `Severity.NONE` / `Kind.FACT` companion for a **builtin**
  marker's LEVEL value that no form resolves: a call, an f-string, a subscript,
  a two-hop name, an import-bound name, a twice-bound name, or any name in a
  star-import-poisoned module. It is builtin-only — a custom `BoundaryType`'s
  unreadable level value keeps `WLN-ENGINE-UNPROVABLE-BOUNDARY` and never also
  takes this one, so no site is reported on two channels or counted twice. It
  is not suppressible: non-`DEFECT` findings bypass the waiver/baseline join
  entirely, and a generated baseline never contains one. A waiver — or a
  hand-authored baseline row — naming its fingerprint is still accepted by the
  loaders; it simply has no effect, rather than being rejected. It never
  gates (`Severity.NONE` is absent from the gate's severity order), it survives
  an `untrusted_sources` override, and it is counted in `decorator_coverage`. It
  is **not** emitted where the marker's call SHAPE is malformed: the shape gate
  short-circuits, no level is read, and `PY-WL-130` is the whole verdict.
- **Marker grammar on the registry.** `RegistryEntry` now declares each
  marker's bare/called form, keyword set, and per-keyword `ArgKind` (`level` today;
  `token_set`/`ref` readers arrive with the declaration-surface stages), fused
  to the boundary types' level-arg schema by a load-time tripwire. The
  vocabulary descriptor and `REGISTRY_VERSION` are unchanged.
```

**Deliberately NOT a changelog bullet here.** The Rust `/// @trusted(...)`
recognise-then-parse widening (`wardline-b857b50b54`, spec §4.4) is **outside
S0** by owner ruling — a different frontend, zero golden blast radius, no
coupling to Task 2's reader — and closes on its own thread **before G2 is read**.
That thread writes its own `### Added` entry when it lands, routed through the
existing `WLN-ENGINE-RUST-INVALID-TRUST-MARKER` with no new rule id and no
vocabulary widening. Recorded here so the omission reads as ownership rather
than oversight: **S0's close does not close PRD-0003 criterion 6.** The binding
visible-owner statement lives in S0's close criteria, not in this task.

- [ ] **Step 2: Create the `### Changed` heading under `## [Unreleased]` (immediately after the `### Added` block — verified: `## [Unreleased]` currently has an `### Added` heading and no `### Changed`) and add under it (BREAKING for analyzer tolerance, not for any runtime API):**

```markdown
- **BREAKING (analyzer-only): the legacy `to_level=` tolerance on `@trusted` is
  removed.** The shape was always a runtime `TypeError`; the analyzer no longer
  seeds it, and PY-WL-130 flags it. Any called `@external_boundary` form,
  including `@external_boundary()` and `@external_boundary(**{})`, no longer
  seeds. Migrate to
  `@trusted(level=...)` / bare `@external_boundary`.
```

- [ ] **Step 3: Add the version-discipline record under the `### Changed` heading created in Step 2** (do not create a nonstandard `### Development` changelog category):

```markdown
- **Version-bump discipline (recorded).** Internal, non-serialized registry
  metadata requires no wire bump. Seeding/resolver semantic changes bump
  `_RESOLVER_VERSION`; serialized `FunctionSummary` structure changes bump
  `SUMMARY_SCHEMA_VERSION`; descriptor-envelope changes bump
  `DESCRIPTOR_SCHEMA`; serialized vocabulary changes bump `REGISTRY_VERSION`
  and, when seeding changes, `_RESOLVER_VERSION`; attestation wire changes bump
  `ATTEST_SCHEMA`; baseline document changes bump `BASELINE_VERSION`; a Legis
  artifact shape change mints the next artifact `vN`. MCP output-schema changes
  have no runtime version constant and re-freeze their schema golden. A custom
  grammar change moves its provider fingerprint automatically. S0's registry
  grammar changes seeding semantics but not Wardline's serialized vocabulary or
  attestation emission, so it moves `_RESOLVER_VERSION` from `sp1g` to `sp1h`
  and no Wardline wire version. The MCP schema changes re-freeze their golden;
  sibling consumer-reader changes do not change a Wardline wire version.
  Consumers ship before emission.
```

- [ ] **Step 4: Commit** — `docs(changelog): S0 hardening entries, tolerance-removal notice, bump discipline with defined terms (ticket 5a795253f1 item e)`

---

### Task 19: Loomweave dual-accept via (schema, version) pairs (§13.1 item 1) — repo `/home/john/loomweave`

**Files (all under `/home/john/loomweave`; NEVER touch `.worktrees/`):**
- Modify: `plugins/python/src/loomweave_plugin_python/wardline_descriptor.py` (:11-13 docstring; :20 `dataclasses` import; :30 constants; `_state_from_text` :146; `_parse_descriptor` :166-188)
- Modify: `plugins/python/src/loomweave_plugin_python/extractor.py` (`WardlineDecoratorMetadata` :173-178; `_attach_wardline_entity_metadata` :1288-1319)
- Modify: `plugins/python/plugin.toml:77-78` (`[integrations.wardline]`)
- Modify: `scripts/check-wardline-version-bounds.py`
- Modify: `plugins/python/tests/test_wardline_vocabulary_descriptor_conformance.py` (docstring of :250 test; new acceptance test; new end-to-end attribution test)
- Modify: `plugins/python/tests/test_extractor.py` (the `_wardline_vocabulary()` helper at `:2818-2843`)
- Modify: `plugins/python/tests/test_package.py:47-49` (manifest pin extension)
- Create: `plugins/python/tests/fixtures/wardline-vocabulary-descriptor.generic-3.preview.yaml`
- Test: `plugins/python/tests/test_wardline_descriptor.py` (extend)

⚠️ There are **three** `WardlineVocabulary` construction sites, not two — `wardline_descriptor.py:151` (the skew branch), `wardline_descriptor.py:183` (`_parse_descriptor`), and `tests/test_extractor.py:2822` (`_wardline_vocabulary()`, which passes exactly four kwargs). A non-defaulted `schema: str` is an immediate `TypeError` at the third, reddening every wardline extractor test. Step 4 converts the skew branch (`:151`) to `dataclasses.replace`, which needs no `schema=` argument, so after Step 4 exactly **two** literal constructions (`_parse_descriptor` `:183` and `test_extractor.py:2822`) must pass `schema=` explicitly.

**Interfaces:**
- Produces: `ACCEPTED_DESCRIPTORS: frozenset[tuple[str, str]]` = {(v1, generic-2), (v2, generic-3)}; the parser now READS the `schema` key (previously ignored; absent → `"wardline.vocabulary/v1"`, the pre-schema era). `WardlineVocabulary` gains `schema: str` **and** `facets_by_name: dict[str, DescriptorEntry]`, plus a `facet_for_decorator()` lookup mirroring the existing `entry_for_decorator()` (`:62-63`). Neither new field is defaulted: `schema` already forces every remaining construction site to be edited, so a default would only re-create the silent-drop vector this task exists to fix. Facets get their **own** map rather than being folded into `entries_by_name` — the only alternative discriminator would be the opaque `group == 3` integer, which re-creates exactly the implicit cross-repo coupling that produced this defect, and a single dict would turn a facet/entry name collision into a silent overwrite instead of an error. Wardline S1 depends on this landing FIRST (Rollout Fence).
- **Acceptance is accept-and-READ (spec rev 9 §4.3, §13.1 item 1).** Accepting the `(wardline.vocabulary/v2, wardline-generic-3)` pair obliges this reader to parse every section the v2 schema defines. **Task 19's engineering content is unchanged by revisions 6, 7, 8 and 9** — rev 6 amends §P3, §4.2.1, §4.4 and §13.2; rev 7 amends §4.2.1, §4.4 and §13.2; rev 8 amends §4.2.1 and §4.4; and rev 9 amends §4.2.1, §4.4 and §4.3's dead `plan line N` coordinates only. Not one of them touches §13.1 item 1's consumer contract or §4.3's accept-and-read rule, so the pin move from rev 5 to rev 9 is a provenance re-cut, not a behavioural amendment to this task. Accepting the pair while `_parse_descriptor` reads only `version` and `entries` would silently discard every facet while still reporting full `confidence_basis: "descriptor"` confidence — an accept-and-ignore fail-open, not acceptance.
- **Key constraints (verified 2026-08-09):** `manifest.rs:137` deserialises `[integrations.wardline]` as `BTreeMap<String, String>` — a TOML **array** value is a HARD manifest-parse failure (`LMWV-INFRA-MANIFEST-MALFORMED`; the plugin refuses to load). The accepted-set key below is therefore a space-separated STRING. `EXPECTED_DESCRIPTOR_VERSION` stays `"wardline-generic-2"` everywhere in S0 (the check script + `test_package.py:47` + CI `verify.yml:82-85` pin it). The generic-3 fixture is a SEMANTIC fixture — parsed and field-asserted, NOT byte-pinned; wardline's S1 producer output gets byte-frozen (and blob-pinned on both sides) when it exists.

- [ ] **Step 1: Write the failing tests** — append to `plugins/python/tests/test_wardline_descriptor.py` (its idiom: inline `mkdir` + `write_text` at `:214-221`; module fixture `_DESCRIPTOR` at `:15-29` carries NO schema line):

First move `Path` to runtime imports in that module (`from pathlib import Path`) and remove the now-unused `TYPE_CHECKING` import/block; the module-level fixture path below must exist during collection.

```python
GENERIC_3_FIXTURE = (
    Path(__file__).parent / "fixtures" / "wardline-vocabulary-descriptor.generic-3.preview.yaml"
)


def _plant(tmp_path: Path, text: str) -> None:
    descriptor = tmp_path / ".weft" / "wardline" / "vocabulary.yaml"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(text, encoding="utf-8")


def test_generic_3_descriptor_is_accepted_not_skew(tmp_path: Path) -> None:
    # Consumer-first dual-accept (wardline declaration-surface-v2 §13.1 item 1):
    # the (wardline.vocabulary/v2, wardline-generic-3) PAIR is accepted BEFORE
    # wardline can emit it — and acceptance means the v2 schema's `facets:`
    # section is READ, not tolerated as an unknown key (spec rev 9 §4.3, the
    # accept-and-read rule introduced at rev 5).
    _plant(tmp_path, GENERIC_3_FIXTURE.read_text(encoding="utf-8"))
    state = load_wardline_descriptor(tmp_path)
    assert state.status == "enabled"
    assert state.descriptor_version == "wardline-generic-3"
    assert state.vocabulary is not None
    vocab = state.vocabulary
    assert vocab.schema == "wardline.vocabulary/v2"
    assert vocab.confidence_basis == "descriptor"
    # Exact equality, not a superset: a dropped v2 entry must red.
    assert sorted(vocab.entries_by_name) == ["external_boundary", "trust_boundary", "trusted"]
    assert {n: e.attrs for n, e in vocab.entries_by_name.items()} == {
        "external_boundary": {},
        "trust_boundary": {"_wardline_to_level": "TaintState"},
        "trusted": {"_wardline_level": "TaintState"},
    }
    # The facets: section is READ, not silently ignored — the S1 defect.
    assert sorted(vocab.facets_by_name) == ["audit_record"]
    assert vocab.facets_by_name["audit_record"].group == 3
    assert vocab.facets_by_name["audit_record"].attrs == {}
    # …and it is a FACET, never folded into the seeding-marker table.
    assert "audit_record" not in vocab.entries_by_name
    assert vocab.entry_for_decorator("audit_record") is None
    assert vocab.facet_for_decorator("weft_markers.audit_record") is vocab.facets_by_name["audit_record"]


def test_generic_3_with_v1_schema_is_pair_mismatch_skew(tmp_path: Path) -> None:
    # Version alone is NOT enough: generic-3 under the v1 schema is not an
    # accepted PAIR — degrade to skew exactly like an unknown version.
    _plant(tmp_path, _DESCRIPTOR.replace("wardline-generic-2", "wardline-generic-3"))
    state = load_wardline_descriptor(tmp_path)
    assert state.status == "version_skew"
    assert state.descriptor_version == "wardline-generic-3"


def test_generic_9_is_still_version_skew(tmp_path: Path) -> None:
    _plant(tmp_path, _DESCRIPTOR.replace("wardline-generic-2", "wardline-generic-9"))
    state = load_wardline_descriptor(tmp_path)
    assert state.status == "version_skew"
    assert state.descriptor_version == "wardline-generic-9"
```

(`_DESCRIPTOR` has no `schema:` line — absent schema defaults to v1, so `test_generic_3_with_v1_schema_is_pair_mismatch_skew` exercises the pair rule through BOTH the absent-schema default and the version bump. The existing skew tests at `:52`, `:116`, `:213-227` keep passing unchanged for the same reason.)

Add these facet-reading tests to the same module (`plugins/python/tests/test_wardline_descriptor.py`). Every malformed-facet case degrades to `status="absent"`, `reason="invalid_descriptor"` — `_parse_facets` raises `_DescriptorError`, which `_state_from_text`'s existing `except (OSError, yaml.YAMLError, _DescriptorError)` already converts; the reader fails closed rather than honouring a half-understood v2 descriptor:

- `test_generic_3_facets_section_is_parsed` — the preview fixture's `facets:` reaches `facets_by_name` with `group == 3` and empty `attrs`.
- `test_v1_descriptor_without_facets_key_parses_with_empty_facets` — the `_DESCRIPTOR` module fixture still parses, `facets_by_name == {}`; every v1 descriptor is unchanged.
- `test_facets_section_that_is_not_a_list_degrades_to_absent`
- `test_malformed_facet_entry_degrades_to_absent` (non-mapping element; missing `canonical_name`/`group`)
- `test_facet_carrying_attrs_degrades_to_absent` — a facet seeds no taint, so attrs on a facet is a contract violation, never an honoured trust marker.
- `test_duplicate_facet_canonical_names_degrade_to_absent`
- `test_facet_colliding_with_entry_name_degrades_to_absent`
- `test_facets_section_under_v1_schema_degrades_to_absent` — v1's shape is known exactly; honouring a section the declared schema does not have is the fail-open this reader exists to avoid.
- `test_version_skew_preserves_parsed_facets` — the `dataclasses.replace` regression guard (Step 4.2): a hand-copied field-by-field skew rebuild would drop `facets_by_name` silently.
- `test_generic_3_preview_fixture_declares_only_known_sections` — needs `import yaml`; asserts the fixture's top-level key set is EXACTLY `{"schema", "version", "entries", "facets"}`. This is the tripwire that makes a future producer-added section red a test instead of being silently ignored.

In `plugins/python/tests/test_extractor.py`: extend the existing `_wardline_vocabulary()` helper (`:2818-2843`) with `schema`, `version` and `facets_by_name` keyword parameters whose defaults preserve today's v1 behaviour (`schema="wardline.vocabulary/v1"`, `version="wardline-generic-2"`, `facets_by_name={}`), then add:

- `test_wardline_facet_decorator_is_attributed_with_tag` — the emitted decorator record carries `kind: "facet"`, `attrs: {}`, `group: 3`, and `wardline:audit_record` is in the entity's `tags`.
- `test_wardline_entry_decorator_record_omits_kind` — pins that a seeding entry's record stays byte-identical to today's (no `kind` key), so no exact-dict assertion anywhere moves.

In `plugins/python/tests/test_wardline_vocabulary_descriptor_conformance.py`: add `test_consumer_attributes_v2_facet_through_extractor`, driving the preview fixture through the real `load_wardline_descriptor` and the real `extract` and asserting the facet tag survives producer-bytes → parse → attribution. This is the **non-circular** proof: every other facet test constructs its vocabulary in Python, so only this one shows that the bytes Wardline will emit actually reach an entity's tags.

- [ ] **Step 2: Author the semantic preview fixture** — `plugins/python/tests/fixtures/wardline-vocabulary-descriptor.generic-3.preview.yaml` (NO comments inside — content only; comments would survive into byte comparisons later):

```yaml
schema: wardline.vocabulary/v2
version: wardline-generic-3
entries:
- canonical_name: external_boundary
  group: 1
  attrs: {}
- canonical_name: trust_boundary
  group: 1
  attrs:
    _wardline_to_level: TaintState
- canonical_name: trusted
  group: 1
  attrs:
    _wardline_level: TaintState
facets:
- canonical_name: audit_record
  group: 3
```

- [ ] **Step 3: Run to verify failure** — from `/home/john/loomweave`:

```bash
uv run --project plugins/python --extra dev pytest \
  -o addopts='' \
  plugins/python/tests/test_wardline_descriptor.py -v
```

Expected: `test_generic_3_descriptor_is_accepted_not_skew` fails with `status == "version_skew"`; the pair-mismatch and generic-9 tests already pass.

- [ ] **Step 4: Implement (schema, version) pair acceptance** in `wardline_descriptor.py`:
  1. Replace `:30` with:

```python
EXPECTED_DESCRIPTOR_VERSION = "wardline-generic-2"
# Pre-schema descriptors (no `schema:` key) are the v1 era by definition.
_DEFAULT_SCHEMA = "wardline.vocabulary/v1"
# Consumer-first dual-accept (wardline declaration-surface-v2 §13.1 item 1): the
# (schema, version) PAIR gates acceptance — generic-3 is accepted only under
# the v2 schema, BEFORE wardline emits it. EXPECTED_DESCRIPTOR_VERSION remains
# the canonical current version for messages/tooling and the manifest pin.
ACCEPTED_DESCRIPTORS: frozenset[tuple[str, str]] = frozenset(
    {
        ("wardline.vocabulary/v1", "wardline-generic-2"),
        ("wardline.vocabulary/v2", "wardline-generic-3"),
    }
)
```

  2. `WardlineVocabulary` gains a field `schema: str` (after `version`); `_parse_descriptor` reads it:

```python
    schema = descriptor.get("schema")
    if schema is None:
        schema = _DEFAULT_SCHEMA
    if not isinstance(schema, str):
        msg = "descriptor schema must be a string when present"
        raise _DescriptorError(msg)
```

     …and passes `schema=schema` to `_parse_descriptor`'s own `WardlineVocabulary(...)` at `:183-188`. **Do NOT pass `schema=schema` to the skew-branch copy in `_state_from_text` `:151-156`: there is no `schema` local in that function.** That branch's hand-copied, field-by-field rebuild is *precisely* the mechanism that silently drops a newly-parsed field — it would have discarded `facets_by_name` the moment Step 5 adds it. Replace the whole rebuild with:

```python
            vocabulary=replace(vocabulary, confidence_basis="descriptor_version_skew"),
```

     adding `replace` to the `dataclasses` import at `:20` (`from dataclasses import dataclass, replace`). Every future field is then carried by construction, and `test_version_skew_preserves_parsed_facets` is its regression guard.
  3. The gate at `:146` becomes:

```python
    if (vocabulary.schema, vocabulary.version) not in ACCEPTED_DESCRIPTORS:
```

     (the degrade-to-`version_skew` body is otherwise unchanged).
  4. Rewrite the module docstring at `:11-13`. It currently claims "The parser ignores unknown top-level keys, so a future `schema` field is tolerated without change." That sentence is now FALSE, and it is the authority under which `facets:` was silently dropped — delete it. Replace it with an explicit enumeration of the four keys this parser reads: `schema` (absent = the pre-schema v1 era), `version`, `entries`, and — under `wardline.vocabulary/v2` — `facets`; plus the standing rule that when Wardline adds a section to a schema this reader accepts, the reader is extended in the same consumer-first change (spec P6). Acceptance of a schema is the obligation to read every section that schema defines, not permission to ignore the ones this reader has not learned yet.

- [ ] **Step 5: Parse the `facets:` section** in `wardline_descriptor.py`. This is the half that makes acceptance real.

`_parse_entry` **cannot** be reused for facets. It does `attrs = raw_entry.get("attrs")` then `if not isinstance(attrs, dict): raise _DescriptorError` (`:201-203`), so an ABSENT `attrs` key — exactly the shape a facet has per spec §7 — is rejected outright. A dedicated `_parse_facet` is required, and it must be *stricter* than `_parse_entry`, rejecting any facet that carries attrs at all: §7 registers facets in their own vocabulary group precisely so `apply_marker` rejects level attributes and a facet can never become a trust claim. Insert both functions after `_parse_entry`:

```python
def _parse_facets(
    descriptor: dict[Any, Any],
    schema: str,
    entries_by_name: dict[str, DescriptorEntry],
) -> dict[str, DescriptorEntry]:
    """Parse the ``wardline.vocabulary/v2`` ``facets:`` section.

    Facets are decorators that seed no taint (declaration-surface-v2 §7), which
    is why Wardline gives them their own section — and why Loomweave gives them
    their own map rather than folding them into ``entries_by_name``. An absent
    section yields an empty map, so every v1 descriptor parses unchanged.

    A ``facets:`` key under the v1 schema is a contract violation, not an
    unknown key: v1's shape is known exactly, and honouring a section the
    declared schema does not have is the fail-open this reader exists to avoid.
    """
    if "facets" not in descriptor:
        return {}
    if schema == _DEFAULT_SCHEMA:
        msg = "descriptor carries a facets section under the v1 schema"
        raise _DescriptorError(msg)
    facets = descriptor["facets"]
    if not isinstance(facets, list):
        msg = "descriptor facets must be a list"
        raise _DescriptorError(msg)

    facets_by_name: dict[str, DescriptorEntry] = {}
    for raw_facet in facets:
        facet = _parse_facet(raw_facet)
        if facet.canonical_name in facets_by_name:
            msg = f"duplicate Wardline descriptor facet: {facet.canonical_name}"
            raise _DescriptorError(msg)
        if facet.canonical_name in entries_by_name:
            msg = f"Wardline descriptor facet collides with an entry: {facet.canonical_name}"
            raise _DescriptorError(msg)
        facets_by_name[facet.canonical_name] = facet
    return facets_by_name


def _parse_facet(raw_facet: Any) -> DescriptorEntry:
    """Parse one ``facets:`` element.

    A facet carries ``canonical_name`` and ``group`` but stamps no
    ``_wardline_*`` level attributes — Wardline registers facets in their own
    vocabulary group precisely so ``apply_marker`` rejects level attributes and
    a facet can never become a trust claim (§7). ``attrs`` is therefore absent
    or an explicit empty mapping; a facet carrying attrs fails closed rather
    than being honoured as a trust marker.
    """
    if not isinstance(raw_facet, dict):
        msg = "descriptor facet must be a mapping"
        raise _DescriptorError(msg)
    canonical_name = raw_facet.get("canonical_name")
    group = raw_facet.get("group")
    if not isinstance(canonical_name, str) or not isinstance(group, int):
        msg = "descriptor facet must carry canonical_name and group"
        raise _DescriptorError(msg)
    attrs = raw_facet.get("attrs", {})
    if not isinstance(attrs, dict) or attrs:
        msg = "descriptor facet must not carry attrs (a facet seeds no taint)"
        raise _DescriptorError(msg)
    return DescriptorEntry(canonical_name=canonical_name, group=group, attrs={})
```

`_parse_descriptor`'s return becomes:

```python
    return WardlineVocabulary(
        version=version,
        schema=schema,
        source=source,
        confidence_basis="descriptor",
        entries_by_name=entries_by_name,
        facets_by_name=_parse_facets(descriptor, schema, entries_by_name),
    )
```

…and the `WardlineVocabulary` dataclass gains the lookup, beside the existing `entry_for_decorator` at `:62-63`:

```python
    def facet_for_decorator(self, qualified_name: str) -> DescriptorEntry | None:
        """A facet from the v2 ``facets:`` section. Facets are decorators too,
        but they seed no taint (declaration-surface-v2 §7), so they resolve
        through their own lookup and can never be mistaken for a trust claim."""
        return self.facets_by_name.get(qualified_name.rsplit(".", 1)[-1])
```

- [ ] **Step 6: Attribute facets in the extractor** — `plugins/python/src/loomweave_plugin_python/extractor.py`. A parsed facet that never reaches an entity is still a silently-ignored section, so parsing alone does not discharge the accept-and-read obligation.

`WardlineDecoratorMetadata` (`:173-178`) gains ONE additive key — `NotRequired` and `Literal` are already imported in that module (`:73`):

```python
    # Present only on facets (declaration-surface-v2 §7): a decorator that is
    # attributed but seeds no taint. Absent means a seeding entry, so every
    # pre-facet record is byte-identical and no exact-dict assertion moves.
    kind: NotRequired[Literal["facet"]]
```

and `_attach_wardline_entity_metadata` (`:1288-1319`) resolves entries first, then facets:

```python
        entry = vocabulary.entry_for_decorator(qualified_name)
        facet = None if entry is not None else vocabulary.facet_for_decorator(qualified_name)
        marker = entry if entry is not None else facet
        if marker is None:
            continue
        record: WardlineDecoratorMetadata = {
            "canonical_name": marker.canonical_name,
            "qualified_name": qualified_name,
            "group": marker.group,
            "attrs": dict(marker.attrs),
            "line": decorator.lineno,
        }
        if facet is not None:
            record["kind"] = "facet"
        decorators.append(record)
        tags.update({"wardline", f"wardline:{marker.canonical_name}"})
```

The `entity["wardline"]` block itself is UNCHANGED — same `descriptor_version`, `confidence_basis`, `decorators` shape. The existing tag expression is reused unmodified, so a facet simply gets `wardline:audit_record` alongside `wardline`, with no new tag-construction path to keep in sync. A facet's `attrs` is the truthful `{}` — the parser guarantees it, so `dict(marker.attrs)` needs no special case. Entry resolution is tried FIRST and facets only when it misses, so no seeding marker can ever be re-labelled a facet by a name collision (and the parser already rejects such a collision at load).

- [ ] **Step 7: plugin.toml + check script.** In `plugin.toml` `[integrations.wardline]` (:77-78) — STRING value, never an array (manifest.rs:137):

```toml
[integrations.wardline]
expected_descriptor_version = "wardline-generic-2"
accepted_descriptors = "wardline.vocabulary/v1@wardline-generic-2 wardline.vocabulary/v2@wardline-generic-3"
```

`accepted_descriptors` is a NEW key — verified 2026-08-09: `[integrations.wardline]` today contains ONLY `expected_descriptor_version` (`plugin.toml:77-78`), and no key named `accepted_descriptor_versions` exists anywhere in loomweave. This task INTRODUCES the accepted set; it does not replace a loose one. The pair-encoded `schema@version` string form is deliberate: a version-only list would destroy the schema/version association that the whole pair gate rests on, re-admitting "version alone unlocks v2 parsing". The final manifest contains exactly `expected_descriptor_version` plus the pair-encoded `accepted_descriptors` string shown above.

In `scripts/check-wardline-version-bounds.py` define:

```python
ACCEPTED_DESCRIPTORS = (
    ("wardline.vocabulary/v1", "wardline-generic-2"),
    ("wardline.vocabulary/v2", "wardline-generic-3"),
)
ACCEPTED_DESCRIPTOR_TOKENS = tuple(
    f"{schema}@{version}" for schema, version in ACCEPTED_DESCRIPTORS
)
```

Validate that `accepted_descriptors` is a string whose `.split()` equals `ACCEPTED_DESCRIPTOR_TOKENS` exactly. Reject missing, reordered, duplicated, malformed, or version-only values.

**Rev 3.9 — where the validation goes, and the one self-test fixture it reds.** Put the `accepted_descriptors` check inside `wardline_descriptor_version`, **after** the existing `expected_descriptor_version` pin check, never before it. Placement is the whole point: `run_self_test`'s negative fixtures reach `_expect(...)` on the earlier guards (`"expected_descriptor_version"` for the `min_version`/`max_version` manifest, `"plugin pin"` for the `wardline-generic-9` manifest, `"missing [integrations.wardline]"` for the bare-capability manifest, `"wardline_aware is false"` for the disabled one), so a post-pin-check placement leaves every one of them unchanged and still failing for its own stated reason. A pre-pin-check placement would re-label them and red five assertions instead of one.

**Exactly one self-test fixture needs the new key: the `aligned` string** (`scripts/check-wardline-version-bounds.py:118-124` — the `"[capabilities.runtime]\n" … f'expected_descriptor_version = "{EXPECTED_DESCRIPTOR_VERSION}"\n'` concatenation). Append the pair-encoded line to it:

```python
    tokens = " ".join(ACCEPTED_DESCRIPTOR_TOKENS)
    aligned = (
        "[capabilities.runtime]\n"
        "wardline_aware = true\n"
        "\n"
        "[integrations.wardline]\n"
        f'expected_descriptor_version = "{EXPECTED_DESCRIPTOR_VERSION}"\n'
        f'accepted_descriptors = "{tokens}"\n'
    )
```

Type it in **that** form — a precomputed `tokens` local plus a single-quoted f-string — rather than inlining the `join` with escaped inner quotes. It matches the fixture's own existing idiom (`f'expected_descriptor_version = "{…}"\n'`, single-quoted outer / double-quoted inner, no escapes), needs no escape under the plugin's `target-version = "py311"`, and is the low-risk form regardless of which ruff configuration applies. **Corrected 2026-08-12 (rev 3.9 erratum), measured in the loomweave tree:** the rev-3.9 justification for this sentence was FALSE. It claimed `plugins/python/pyproject.toml` selects `ALL` so `Q` (flake8-quotes) is live for this script — but that config governs `plugins/python/` only, and loomweave has **no root `pyproject.toml` and no root `ruff.toml`**, so `scripts/check-wardline-version-bounds.py` resolves ruff's **defaults**, which do not select `Q` at all. The instruction stands on its own merits (it matches the fixture's existing idiom and avoids escapes); only its stated reason was wrong. Recorded rather than quietly deleted, because a correct instruction resting on a false reason is precisely the defect class this revision's own item 9 was raised to fix — and this one was introduced *by* that revision. Note that **Step 9's gates are all `pytest` and `cargo`**: a lint red authored into this script would not surface in this task's own run at all, only later in loomweave's ruff pre-commit hook.

`aligned` is the only fixture that is expected to *succeed*, and it is reused by the two hook assertions at `:170-171`, so fixing it there **transitively** fixes them — no separate edit at those two lines, and no other fixture changes. Without this the self-test reds on the very first `assert check(manifest) == EXPECTED_DESCRIPTOR_VERSION`, which is a mid-task halt inside another repository.

Replace the hook with:

```python
def descriptor_cross_check_hook(
    resolved_descriptor_schema: str,
    resolved_descriptor_version: str,
    manifest_path: Path,
) -> bool:
    check(manifest_path)
    return (
        resolved_descriptor_schema,
        resolved_descriptor_version,
    ) in ACCEPTED_DESCRIPTORS
```

`rg` found no production callers outside the self-test, so change the signature directly.

**Rev 3.9 — one behavioural change in that replacement, stated rather than left silent.** The shipped hook is `expected = check(manifest_path); return expected is not None and resolved_descriptor_version == expected`. The `expected is not None` conjunct is a **capability guard**: for a manifest with `wardline_aware = false` and **no** `[integrations.wardline]` block, `check()` returns `None` without raising and the hook returns `False`. The replacement above calls `check(manifest_path)` for its raising side-effect and then answers purely from the pair, so that case now returns `True` for any accepted pair — a capability-off manifest would cross-check as aligned. This is **accepted, not overlooked**, on three grounds: the case is dormant (`rg` finds no production callers, so the hook has no live consumer to fail open on); the *enabled*-but-misconfigured manifests still raise `CheckError` inside `check()` and never reach the return; and the pair set is the thing this task exists to make authoritative. Record it here so a future reader does not "restore" the guard as a bug fix without re-deciding it. If a production caller is ever added, restore the guard as `expected = check(manifest_path)` plus `expected is not None and (schema, version) in ACCEPTED_DESCRIPTORS`.

Extend the self-test with v1/generic-2 and v2/generic-3 true; v1/generic-3, v2/generic-2, and v2/generic-9 false. In `test_package.py`, import runtime `ACCEPTED_DESCRIPTORS`, decode the manifest tokens back to pairs, and assert exact set equality.

- [ ] **Step 8: Update the conformance test's meaning.** In `test_wardline_vocabulary_descriptor_conformance.py`, the `:250` test (`test_consumer_version_gate_rejects_skew_copy`) still passes — the golden carries `schema: wardline.vocabulary/v1` (line 1), so the generic-3 substitution produces the UNACCEPTED pair (v1, generic-3). Update its docstring: "…the gate keys on the (schema, version) PAIR: the same golden bytes with only the version bumped are a pair mismatch — the proof that version alone cannot unlock v2 parsing." Add the acceptance twin right below it:

```python
def test_consumer_accepts_the_v2_pair(tmp_path: Path) -> None:
    # The dual-accept half: the (wardline.vocabulary/v2, wardline-generic-3)
    # pair from the SEMANTIC preview fixture is enabled, not skew. This fixture
    # is field-asserted, never byte-pinned — the byte-freeze happens in S1 when
    # wardline's producer emits real generic-3 bytes (Rollout Fence).
    preview = Path(__file__).parent / "fixtures" / "wardline-vocabulary-descriptor.generic-3.preview.yaml"
    _write_project_descriptor(tmp_path, preview.read_text(encoding="utf-8"))
    state = load_wardline_descriptor(tmp_path)
    assert state.status == "enabled"
    assert state.descriptor_version == "wardline-generic-3"
```

- [ ] **Step 9: Run the loomweave gates** — from `/home/john/loomweave`:
  1. `uv run --project plugins/python --extra dev pytest -o addopts='' plugins/python/tests/test_wardline_descriptor.py plugins/python/tests/test_wardline_vocabulary_descriptor_conformance.py plugins/python/tests/test_package.py -q` — PASS; the generic-2 golden byte-pin (`UPSTREAM_BLOB_SHA`) is untouched.
  2. `python scripts/check-wardline-version-bounds.py --self-test && python scripts/check-wardline-version-bounds.py` — both green.
  3. `cargo test -p loomweave-core manifest && cargo test -p loomweave-storage --test writer_actor python_plugin_edge_kinds_are_accepted_by_writer_contract` — proves the string key parses (manifest.rs:137) and the production manifest still loads.
  4. `uv run --project plugins/python --extra dev pytest plugins/python` — authoritative plugin CI-equivalent gate.

**Blast radius — what is verified UNAFFECTED (2026-08-09, in loomweave source):**
- The v1 vocabulary golden and its `UPSTREAM_BLOB_SHA` (`f5ad8d2346ffb6ea75aa469e423c6c7cfd16d40a`, `test_wardline_vocabulary_descriptor_conformance.py:92`) do NOT move: the v1 golden gains no facets, and the conformance byte-compare operates on the v1 golden only. The generic-3 preview fixture stays semantic/field-asserted (Rollout Fence §3 byte-freezes it in S1).
- `plugin.toml`'s `[ontology].classifier_tags` needs no change — `wardline:*` tags are not classifier tags.
- No Rust struct mirrors `WardlineVocabulary` or the decorator record: `RawEntity` (`crates/loomweave-core/src/plugin/host.rs:118-151`) carries the whole `wardline` block through its `#[serde(flatten)] extra: serde_json::Map<…>` field, "accepted without interpretation". Adding a dataclass field or a `kind` key is therefore invisible to Rust — no crate rebuild semantics change.
- **One deliberate non-change:** `wardline:audit_record` is NOT added to `ontology.rs`'s `tags::DEAD_CODE_ROOTS` (`crates/loomweave-core/src/ontology.rs:23-34`), whose only `wardline:*` members are `wardline:external_boundary` and `wardline:trusted`. A facet seeds no taint and is not an externally-reached entry point, so it must not become a reachability root — doing so would silently resurrect dead code on the strength of an audit annotation.

- [ ] **Step 10: Commit (orchestrator, `/home/john/loomweave`, `release/1.5.0`, explicit paths only)** — `feat(wardline-descriptor): dual-accept schema/version pairs, read and attribute the v2 facets section`

---

### Task 20: `wardline-attest-3` staged — contract doc, shared vector, verifier dual-read, MCP surface (§13.1 item 2, wardline side)

**Files:**
- Modify: `src/wardline/core/attest.py` (after :63; verify conjunct :368-374; the three return sites :379-384/:399-404/:408-413; docstring)
- Modify: `src/wardline/mcp/server.py` — **anchored by symbol, never by line** (rev-3.9: the rev-3.8 coordinates `:3509-3539` / `:3546-3547` had rotted ~18 lines and are deliberately not replaced with fresh numbers, because line coordinates are what rotted): the `_VERIFY_ATTESTATION_OUTPUT_SCHEMA` dict literal, its `"required": [...]` list and its `"additionalProperties": False` line; and inside the `_VERIFY_ATTESTATION_TOOL` dict literal, the tail of its `"description"` string ending `"Returns {signature_valid, reproduced, mismatches, note}."`
- Modify: `tests/conformance/mcp_output_schemas.golden.json` + `tests/conformance/test_mcp_output_schema_golden.py:69` (`VENDORED_BLOB_SHA`) — golden re-freeze #2
- Modify: `tests/conformance/test_mcp_structured_output.py` — **anchored by symbol** (rev-3.9: the rev-3.8 coordinate `:303-316` now straddles two unrelated tests and is not replaced with a fresh number): the function `test_attest_and_verify_attestation_structured_output`, at its `assert verified["signature_valid"] is True` line
- Modify: `tests/conformance/test_attest_contract_freeze.py`
- Modify: `docs/guides/attestation.md`
- Modify: `docs/reference/mcp.md` (the `verify_attestation` section's `**Returns:**` line — **added at rev 3.9**; Step 7 already restates that key set and the path was missing from this list, so the per-task path gate forbade the edit its own step requires. This is the one place verbatim execution of rev 3.8 would have shipped something false. No test pins this file.)
- Modify: `docs/contracts/wardline-attest-2.md`
- Modify: `docs/contracts/wardline-attest-2-consumer-prompt.md`
- Create: `docs/contracts/wardline-attest-3.md`
- Create: `tests/conformance/fixtures/wardline-attest-3.vector.json`
- Create: `tests/conformance/test_attest_dual_read.py`

**Interfaces:**
- Produces: `ACCEPTED_ATTEST_SCHEMAS: tuple[str, ...] = ("wardline-attest-2", "wardline-attest-3")` (LITERALS — never `(ATTEST_SCHEMA, ...)`, which would silently lose v2 when the constant bumps in S1); `verify_attestation` reports gain `"schema_recognized": bool` at ALL THREE return sites. Warpline (Task 21) vendors the vector byte-for-byte and re-derives its HMAC as the cross-impl pin.
- **Cross-task dependency — added at rev 3.9, and invisible from Task 23's own text.** `tests/conformance/test_attest_dual_read.py` is not merely this task's own receipt: **Task 23 Step 2 makes it the attest seam's `oracle_test`**, and `tests/conformance/test_seam_registry.py`'s `_has_shared_vector_pin` then greps this file's **source text** for three tokens, all three of which must be present or Task 23 reds: (1) a literal `GOLDEN_KEY` name, (2) a literal `sign_artifact(` call — regex `\bsign_artifact\s*\(` — and (3) at least one `*_FIELD` upper-case constant (regex `\b[A-Z][A-Z0-9_]*_FIELD\b`). **Wardline's signer is named `_sign`, not `sign_artifact`**, so token (2) exists only because the pinned test block below imports it as `from wardline.core.attest import _sign as sign_artifact` and calls it under that alias. Step 1's block already satisfies all three — **type it as written and do not "clean it up"**: dropping the alias for a direct `_sign(...)` call, inlining `GOLDEN_KEY` as a literal, or replacing `SCHEMA_FIELD` / `PAYLOAD_FIELD` / `SIGNATURE_FIELD` with bare strings each silently breaks a gate that fires **three tasks later**, in a task whose own text gives no hint of the cause. Task 23 Step 2 carries the reciprocal cross-reference.
- Verified mechanics this task rides: `_sign(payload, key, *, schema=ATTEST_SCHEMA)` already binds the BUNDLE'S OWN recorded schema at verify (`:366` passes `schema=schema`), which is exactly why the "correctly re-signed unknown schema" case is distinguishable only via the split; the MCP handler returns `verify_attestation`'s dict verbatim into an `additionalProperties: False` schema, so the schema + description + golden must move in this same commit.

- [ ] **Step 1: Write the failing tests** — `tests/conformance/test_attest_dual_read.py`:

```python
"""Consumer-first dual-read for wardline-attest-3 (declaration-surface-v2 §13.1 item 2).

Wardline still EMITS attest-2 (the freeze test pins that). This suite proves the
verifier RECOGNISES attest-3 — schema recognition is split out of
signature_valid so an attest-3 bundle is distinguishable from a bad key or a
tampered payload — and freezes the shared attest-3 vector warpline vendors."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# CROSS-TASK GATE — DO NOT SIMPLIFY (see this task's "Cross-task dependency" note).
# Task 23's seam-registry gate greps THIS FILE's source text. The `_sign as
# sign_artifact` alias, the `GOLDEN_KEY` name and the `*_FIELD` constants below are
# each load-bearing to that grep; inlining any of them reds Task 23.
from wardline.core.attest import (
    ACCEPTED_ATTEST_SCHEMAS,
    ATTEST_SCHEMA,
    _sign as sign_artifact,
    verify_attestation,
)

VECTOR = Path(__file__).parent / "fixtures" / "wardline-attest-3.vector.json"
SCHEMA_FIELD = "schema"
PAYLOAD_FIELD = "payload"
SIGNATURE_FIELD = "signature"
# Public, test-only key — a conformance artifact, never an operational secret.
GOLDEN_KEY = "wardline-attest-3-conformance-vector-key"


def _bundle() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_accepted_schemas_are_pinned() -> None:
    assert ATTEST_SCHEMA == "wardline-attest-2"  # S0 emits v2, unchanged
    assert ACCEPTED_ATTEST_SCHEMAS == ("wardline-attest-2", "wardline-attest-3")


def test_attest_3_vector_signature_is_internally_consistent() -> None:
    bundle = _bundle()
    assert bundle[SCHEMA_FIELD] == "wardline-attest-3"
    expected = sign_artifact(bundle[PAYLOAD_FIELD], GOLDEN_KEY, schema=bundle[SCHEMA_FIELD])
    assert bundle[SIGNATURE_FIELD]["value"] == expected["value"]


# ---- the six-case recognition/validity matrix ----


def test_valid_v3_is_recognised_and_valid() -> None:
    report = verify_attestation(_bundle(), GOLDEN_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is True


def test_wrong_key_is_recognised_but_invalid() -> None:
    report = verify_attestation(_bundle(), "not-the-vector-key")
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is False


def test_tampered_v3_is_recognised_but_invalid() -> None:
    bundle = _bundle()
    bundle["payload"]["commit"] = "0" * 40
    report = verify_attestation(bundle, GOLDEN_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is False


def test_correctly_resigned_unknown_schema_is_unrecognised() -> None:
    # THE case the split exists for: _sign binds the bundle's own recorded
    # schema tag, so a wardline-attest-9 bundle re-signed with the RIGHT key
    # over its own tag has a matching HMAC — recognition is the only thing
    # separating it from a real bundle. Both flags must be False.
    bundle = _bundle()
    bundle["schema"] = "wardline-attest-9"
    bundle["signature"] = sign_artifact(bundle["payload"], GOLDEN_KEY, schema="wardline-attest-9")
    report = verify_attestation(bundle, GOLDEN_KEY)
    assert report["schema_recognized"] is False
    assert report["signature_valid"] is False


def test_missing_schema_is_unrecognised() -> None:
    bundle = _bundle()
    del bundle["schema"]
    report = verify_attestation(bundle, GOLDEN_KEY)
    assert report["schema_recognized"] is False
    assert report["signature_valid"] is False


def test_attest_2_bundles_still_verify_with_the_new_key_present() -> None:
    payload = {"wardline_version": "1.5.0", "attested_at": "2026-08-09", "commit": None, "dirty": False}
    bundle = {"schema": ATTEST_SCHEMA, "payload": payload, "signature": sign_artifact(payload, GOLDEN_KEY)}
    report = verify_attestation(bundle, GOLDEN_KEY)
    assert report["schema_recognized"] is True
    assert report["signature_valid"] is True
    assert set(report) == {"schema_recognized", "signature_valid", "reproduced", "mismatches", "note"}


def test_vendored_warpline_copy_is_byte_identical_when_present() -> None:
    # Layer-2 cross-repo drift check (the loomweave descriptor-golden pattern):
    # Coordinated/release jobs arm this comparison with WARPLINE_REPO; a normal
    # standalone Wardline checkout may skip when the sibling is absent.
    configured_repo = os.environ.get("WARPLINE_REPO")
    repo = configured_repo or "/home/john/warpline"
    vendored = Path(repo) / "tests" / "fixtures" / "wardline-attest-3.vector.json"
    if not vendored.exists():
        if configured_repo is not None:
            pytest.fail(f"missing required Warpline receipt at {vendored}")
        pytest.skip(f"Warpline checkout not present at {vendored}; Task 23 supplies WARPLINE_REPO")
    assert vendored.read_bytes() == VECTOR.read_bytes()
```

- [ ] **Step 2: Recheck the spec blob pin (the static blob check from the execution preflight — currently blob `f4ba87c488778f2c315de1944818db12707d981f`, spec **revision 10**, committed at `aa10dd3d`; the governing spec is **revision 10** and the preflight's constant already carries it, so this task runs against that constant, never against a working-tree hash), then generate the non-normative preview vector once** (scratch script; the tests then freeze it — the HMAC pin makes any later edit loud). Mark the vector and contract status `DRAFT/S0 preview`; S1's first real serializer output must be byte- and semantic-compared before replacing it.

```bash
uv run python - <<'PY'
import json
from pathlib import Path

from wardline.core.attest import _sign

payload = {
    "wardline_version": "1.5.0",
    "attested_at": "2026-08-09",
    "commit": "ed7bfe860d83000000000000000000000000dead",
    "dirty": False,
    "ruleset_hash": "sha256:" + "ab" * 32,
    "posture": {"inert": False, "recognized_boundaries": 3, "functions_analyzed": 12},
    "boundaries": [
        {
            "qualname": "svc.fetch_order",
            "sei": "loomweave:eid:9adc480cd5aa4d71503c19fd8b29907e",
            "content_hash": "blake3:" + "cd" * 16,
            "verdict": "clean",
            "tier": "ASSURED",
        }
    ],
    "sei_source": "loomweave",
    "sei_diagnostics": [],
    # attest-3 additions (declaration-surface-v2 §11.2) — representative, not exhaustive:
    "declarations": [
        {
            "declaration_id": "wlds1:" + "ef" * 32,
            "kind": "facet",
            "content_digest": "sha256:" + "12" * 32,
            "verification_class": "machine_verified",
            "subject": "svc.write_audit_event",
        }
    ],
    "declaration_counts": {"contracts": 0, "facets": 1, "restoration": 0, "sensitivity": 0, "dependency_taint": 0},
    "declaration_debt": {"lapsed_expiries": 0, "stale_dependency_pins": 0, "record_only_claims": 0},
    "grants": {"trusted_packs": [], "trust_dependency_taint": False, "strict_defaults": False},
    "dependency_taint_digest": None,
    "authorship_note": "HMAC attests domain-internal integrity, not third-party identity; authorship lives in git.",
}
bundle = {
    "schema": "wardline-attest-3",
    "payload": payload,
    "signature": _sign(payload, "wardline-attest-3-conformance-vector-key", schema="wardline-attest-3"),
}
out = Path("tests/conformance/fixtures/wardline-attest-3.vector.json")
out.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("wrote", out)
PY
```

- [ ] **Step 3: Run to verify the dual-read failures** — `uv run pytest tests/conformance/test_attest_dual_read.py -v`. Expected: FAIL on the `ACCEPTED_ATTEST_SCHEMAS` import, then on `schema_recognized`.

- [ ] **Step 4: Implement the verifier split** in `src/wardline/core/attest.py`. After `:63` add:

```python
# Consumer-first dual-read (declaration-surface-v2 §13.1 item 2): the verifier
# RECOGNISES attest-3 before the builder EMITS it (S1). LITERALS on purpose —
# deriving the first element from ATTEST_SCHEMA would silently drop v2 from the
# accepted set the moment S1 bumps the constant. Order = oldest first.
ACCEPTED_ATTEST_SCHEMAS: tuple[str, ...] = ("wardline-attest-2", "wardline-attest-3")
```

Replace the conjunct block at `:368-374` with:

```python
    schema_recognized = isinstance(schema, str) and schema in ACCEPTED_ATTEST_SCHEMAS
    signature_valid = (
        isinstance(signature, dict)
        and schema_recognized
        and signature.get("alg") == "HMAC-SHA256"
        and signature.get("key_id") == key_id(key)
        and hmac.compare_digest(expected, str(signature.get("value") or ""))
    )
```

Add `"schema_recognized": schema_recognized,` as the FIRST key of ALL THREE return dicts (:379-384, :399-404, :408-413). Extend the docstring's signature paragraph: "An unrecognised schema reports `schema_recognized=False` — distinguishable from a wrong key or tamper even when the bundle was re-signed over its own unknown tag (the signer binds the recorded schema). A recognised non-current schema (`wardline-attest-3`) signature-verifies against its own recorded tag; `--reproduce` re-derives the CURRENT builder's payload, so a v3 bundle verified before S1 honestly reports the v3-only keys as mismatches (the `sei_diagnostics` precedent)."

- [ ] **Step 5: Update the MCP surface (same commit).**
  *(Rev-3.9 re-anchoring: every coordinate in this step had rotted ~18 lines. They are replaced by **symbol and quoted text**, deliberately not by corrected line numbers — line numbers are exactly what rotted, and this document has already lost anchors that way across five revisions. Locate each site by searching for the quoted symbol or string.)*
  1. The `_VERIFY_ATTESTATION_OUTPUT_SCHEMA` dict literal (find `_VERIFY_ATTESTATION_OUTPUT_SCHEMA: dict[str, Any] = {`; its `"required": ["signature_valid", "reproduced", "mismatches", "note"]` line and its `"additionalProperties": False` line are the last two entries of the same literal): add to `properties` (first entry) `"schema_recognized": {"type": "boolean", "description": "True iff the bundle's schema tag is one this verifier accepts (wardline-attest-2 | wardline-attest-3). False means signature_valid is necessarily false too — an unrecognised schema is not a validity verdict."}` and prepend `"schema_recognized"` to `required`.
  2. The `_VERIFY_ATTESTATION_TOOL` literal's `"description"` tail (find `_VERIFY_ATTESTATION_TOOL: dict[str, Any] = {`, then the continuation string ending `"Returns {signature_valid, reproduced, mismatches, note}."`): the prose embeds the key set — change that tail to `"Returns {schema_recognized, signature_valid, reproduced, mismatches, note}."`.
  3. Re-freeze `tests/conformance/mcp_output_schemas.golden.json` with the SAME scratch script as **Task 9 Step 4** — the *patched* one, which mirrors `test_mcp_output_schema_golden.py`'s autouse `_handshake_preopened` fixture (`:48-61`) before importing the module — and update `VENDORED_BLOB_SHA` (`:69`) in this same commit. **Copy that block verbatim; do not reconstruct it from the module's header RE-FREEZE PROCEDURE**, which describes the regeneration but says nothing about the handshake opt-out: an unpatched script dies on `{"error": {"code": -32600, "message": "server not initialized"}}` before writing a byte, and this is the **second and last** sanctioned re-freeze of this file in all of S0, so there is no third attempt budget. If it fails, that is a STOP — never hand-edit the golden (Task 9 Step 4 carries the prohibition and the reason).
  4. `tests/conformance/test_mcp_structured_output.py`, in the function `test_attest_and_verify_attestation_structured_output`: after `assert verified["signature_valid"] is True` add `assert verified["schema_recognized"] is True` (the `_validated` helper already jsonschema-validates the new key against the amended schema). *Rev-3.9: this said `:303-316`, a range that now straddles `test_assure_structured_output` and `test_decorator_coverage_structured_output` and contains neither the assertion nor the attest test; the assertion is inside the named function. Anchor on the function name and the quoted assertion, not on a line range.*

- [ ] **Step 6: Author `docs/contracts/wardline-attest-3.md`** with these sections (content from spec §11.2; follow `wardline-attest-2.md`'s structure): **Status** — DRAFT/non-normative S0 preview; consumers dual-read; Wardline emits v3 only after the Rollout Fence; **Envelope** — `{schema: "wardline-attest-3", payload, signature}`, HMAC-SHA256 over compact key-sorted JSON of `{"schema", "payload"}`, `key_id` = first 8 hex of sha256(key); **Payload** — everything in attest-2 PLUS the proposed declaration fields; **Shared vector** — the test-only vector/key; **Verification profiles** — the Wardline verifier holds the shared key, reports `schema_recognized`, and HMAC-verifies v2/v3, while the Warpline runtime receives a pushed untrusted bundle, holds no Wardline key, never verifies HMAC, and always reports `signature_verified: false`; **Migration** — attest-2 verifies unchanged and attest-1 remains rejected.

- [ ] **Step 7: Truth up existing docs and freeze tests.** Keep `test_attest_schema_tag_frozen` exactly as is; add the accepted-tuple and v3-doc pins. Update `docs/guides/attestation.md`, the v2 contract, and the consumer prompt with `schema_recognized` and the two verification profiles. **Also update `docs/reference/mcp.md` (added at rev 3.9):** in its `verify_attestation` section the line `**Returns:** \`{signature_valid, reproduced, mismatches, note}\`. Read-only.` restates the tool's key set and becomes false the moment Step 5.2 adds the key — change it to `**Returns:** \`{schema_recognized, signature_valid, reproduced, mismatches, note}\`. Read-only.` No test pins this file, so nothing reds if it is missed; that is exactly why it is named here as an explicit instruction rather than left to the Files list, and why it is the **one place** where executing rev 3.8 verbatim would have shipped a false statement to users. In the consumer prompt, delete the old instruction that gives Warpline the shared key or asks its runtime to verify HMAC; do not merely append a caveat. The operational sequence is: (1) in the key-holding domain run `wardline attest . --verify bundle.json`; (2) require both booleans true; (3) hand the exact verified bytes to Warpline; (4) treat Warpline's result as mechanical commit/SEI/content-hash relay, not cryptographic verification. The CLI exit rule remains valid because `signature_valid` implies schema recognition.

Do **not** touch `tests/conformance/seam_registry.json` in this task — it is deliberately absent from the Files list above, and editing it is a hard stop under the per-task path gate. The attest row stays exactly as shipped: `bar_verdict: "gap"`, null `oracle_shape` / `oracle_test` / `marker` / `drift_alarm` / `drift_test`, and its existing `seam` and `wire` prose. ***Rev-3.9 correction — the instruction is right, its stated reason was not.*** *Rev 3.8 justified the prohibition on the row's "warpline consumer NOT YET wired" clause being "**still true after this task**". That clause is **false today, before this task runs**: warpline ships `src/warpline/_attest.py`, whose `worklist_risk` is imported at `commands.py:8` and called at `commands.py:1117`, released in warpline 1.3.0. The correct reason to leave the row alone is the **per-task path gate**, full stop — `tests/conformance/seam_registry.json` is deliberately absent from this task's Files list, and the row's correction (including that stale wiring clause) is **Task 23's** atomic truth-up, which owns the path. Do not "fix" the clause here on the strength of this note.* Read that as a prohibition, not as an instruction to add a sentence saying the Wardline dual-read is staged: no such sentence exists in the row, and adding one is an edit to a path this task may not stage. **Task 23 owns the atomic truth-up**, including the staged-dual-read prose, and its Files list carries `tests/conformance/seam_registry.json` (attest row only) for exactly that.

- [ ] **Step 8: Run** — `uv run pytest tests/conformance/test_attest_dual_read.py tests/conformance/test_attest_contract_freeze.py tests/conformance/test_mcp_output_schema_golden.py tests/conformance/test_mcp_structured_output.py tests/conformance/test_seam_registry.py tests/unit/core/test_attest.py tests/unit/mcp/test_server_attest.py -q` then full suite `uv run pytest -q`. Expected: PASS. (The Layer-2 warpline test SKIPS until Task 21 lands the vendored copy — re-run it after Task 21.)

- [ ] **Step 9: Commit** — `feat(attest): stage wardline-attest-3 — contract doc, shared vector, verifier schema_recognized split, MCP schema+golden re-freeze (S0 §13.1 item 2)`

---

### Task 21: Warpline dual-accept `attest-2 | attest-3` (§13.1 item 2, consumer side) — repo `/home/john/warpline`

**Files (all under `/home/john/warpline`):**
- Modify: `src/warpline/_attest.py` (:44 constants; :182-187 gate; :260 `source`)
- Modify: `src/warpline/cli.py`
- Modify: `src/warpline/mcp.py`
- Modify: `src/warpline/commands.py`
- Modify: `src/warpline/loomweave.py`
- Modify: `contracts/reverify_worklist.v1.schema.json`
- Modify: `CHANGELOG.md` (Unreleased/Changed only)
- Create: `tests/fixtures/wardline-attest-3.vector.json` (byte-for-byte copy of wardline's `tests/conformance/fixtures/wardline-attest-3.vector.json`)
- Test: `tests/test_attest.py` (extend)

**Depends on Task 20 (vendors its vector).** Verified mechanics: the schema gate is `parsed["schema"] != ATTEST_SCHEMA` (:182); `source` is the CONSTANT, not a pass-through (:260) — it must become `parsed["schema"]` so the verdict names what it consumed; the bundle factory default is `schema: str = ATTEST_SCHEMA` (`tests/test_attest.py:47`); the attest-1 rejection is `:133-141` (and `:269-277` is a DIFFERENT guard — structurally-unusable — leave it alone).

- [ ] **Step 1: Write the failing tests** — append to `tests/test_attest.py` (reuse `_bundle`/`_boundary`/`_hashes`/`_risk`, `SEI_A`/`HASH_A`/`COMMIT`, `_COMPLETE` — all module helpers at :20-70):

```python
def test_attest_3_schema_is_accepted_and_named_as_source() -> None:
    verdict = _risk(
        impact_completeness=_COMPLETE,
        affected_seis=[SEI_A],
        bundle=_bundle(boundaries=[_boundary(SEI_A, HASH_A)], schema="wardline-attest-3"),
        current_commit=COMMIT,
        content_hash_for_sei=_hashes({SEI_A: HASH_A}),
    )
    assert verdict["risk"] == "proven"
    assert verdict["reason_code"] == "attested_clean"
    # The verdict names what it actually consumed — no constant echo.
    assert verdict["source"] == "wardline-attest-3"
    assert verdict["authority"] == "wardline"
    assert verdict["signature_verified"] is False


# NOTE: test_unknown_schema_is_rejected (:133-141, attest-1) and
# test_structurally_unusable_bundle_is_schema_unknown (:269-277) stay untouched
# and must remain green — attest-1 and garbage stay rejected under dual-accept.


def test_vendored_attest_3_vector_parses_and_pins_the_hmac() -> None:
    import hashlib
    import hmac as hmac_mod
    import json
    from pathlib import Path

    from warpline._attest import parse_attest_bundle

    vector = json.loads(
        (Path(__file__).parent / "fixtures" / "wardline-attest-3.vector.json").read_text(encoding="utf-8")
    )
    parsed = parse_attest_bundle(vector)
    assert parsed["schema"] == "wardline-attest-3"
    assert "loomweave:eid:9adc480cd5aa4d71503c19fd8b29907e" in parsed["by_sei"]

    # Test-time canonicalization/drift pin only — Warpline runtime has no
    # Wardline HMAC key and does not cryptographically verify pushed bundles.
    # re-derive wardline's HMAC from first principles — compact, key-sorted,
    # UTF-8 JSON over {"schema", "payload"} with the public conformance key.
    # If either side's canonical-JSON formula drifts, this stops reproducing.
    material = json.dumps(
        {"schema": vector["schema"], "payload": vector["payload"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected = hmac_mod.new(b"wardline-attest-3-conformance-vector-key", material, hashlib.sha256).hexdigest()
    assert vector["signature"]["value"] == expected
```

- [ ] **Step 2: Copy the vector** — byte-identical: `cp /home/john/wardline/tests/conformance/fixtures/wardline-attest-3.vector.json /home/john/warpline/tests/fixtures/wardline-attest-3.vector.json` (create `tests/fixtures/` if absent), then `cmp` both files. The armed Wardline receipt (`WARPLINE_REPO=...`) fails on drift; standalone tests enforce each side's signer/canonicalization half and may skip without the sibling.

- [ ] **Step 3: Run to verify failure** — from `/home/john/warpline`: `uv run pytest tests/test_attest.py -v`. Expected: the acceptance test FAILS with `reason_code == "attestation_schema_unknown"`; the vector test passes already (parse + HMAC need no code change).

- [ ] **Step 4: Implement.** In `src/warpline/_attest.py`:
  1. `:44` becomes:

```python
ATTEST_SCHEMA = "wardline-attest-2"
# Dual-accept (wardline declaration-surface-v2 §13.1 item 2): attest-3 is honored
# BEFORE wardline emits it. LITERALS on purpose (deriving from ATTEST_SCHEMA
# would lose v2 when the constant bumps). attest-1 and anything else stay
# rejected.
ACCEPTED_ATTEST_SCHEMAS: frozenset[str] = frozenset({"wardline-attest-2", "wardline-attest-3"})
```

  2. The gate at `:182-187` becomes:

```python
    if parsed["schema"] not in ACCEPTED_ATTEST_SCHEMAS:
        return _unavailable(
            "attestation_schema_unknown",
            cause=(
                f"attestation schema is {parsed['schema']!r}, not one of "
                f"{sorted(ACCEPTED_ATTEST_SCHEMAS)}"
            ),
            fix=(
                "supply a wardline-attest-2 or wardline-attest-3 bundle "
                "(other attest schemas are not honored)"
            ),
        )
```

*Rev 3.9 — why `cause=` and `fix=` are parenthesised here.* As pasted through rev 3.8 those two were **single lines of 110 and 112 characters**, against warpline's `[tool.ruff] line-length = 100` — two **E501** violations authored into a repo whose ruff baseline is clean, which would surface as a lint red in warpline's next release gate rather than in this task's own `pytest` step. The wrap above uses the module's **own** existing continuation idiom (`_attest.py`'s neighbouring `cause=(...)` / `fix=(...)` blocks) and changes no message text. Verified clean 2026-08-12 under warpline's exact configuration — `ruff --line-length 100 --target-version py312 --select E,F,I,UP,B` (warpline selects no `ISC` rules, so implicit string concatenation is the correct wrap here). Type the block as written; do not re-join the strings.

  3. The proven-verdict `source` at `:260` becomes `"source": parsed["schema"],` (the existing `:85` assertion `verdict["source"] == ATTEST_SCHEMA` still passes — an attest-2 bundle's parsed schema IS the constant).
  4. `parse_attest_bundle` needs no change (five-field projection; attest-3's additive payload keys pass through).
  5. Update every live operator-facing "attest-2 only" surface in the files above to "wardline-attest-2 or wardline-attest-3". Preserve historical release decisions and archived analyses as historical facts. Every live surface states: Warpline accepts pushed untrusted input; checks schema, clean-tree/commit equality, SEI, verdict, and current entity-body hash; holds no Wardline HMAC key; and does not verify the signature. The independent HMAC derivation is conformance-only.

  **Rev 3.9 — repo-relative paths only, in every file this step writes.** `CHANGELOG.md` is on this task's Files list **and** is a `PUBLIC_DOC_ROOTS` entry in `tests/test_public_docs_hygiene.py`, which asserts that no file under `README.md`, `CHANGELOG.md`, `docs/`, `spike/` or `src/warpline/skills/` contains the substring `/home/john` (one allowlisted exception, unrelated). Step 2's vendoring command is written with absolute paths, and the vector's provenance is exactly the kind of detail a changelog entry describes — so write `tests/fixtures/wardline-attest-3.vector.json` and "vendored byte-for-byte from wardline", never `/home/john/wardline/tests/conformance/fixtures/...`. The same rule applies to `docs/` and any skill text touched here. **`tests/test_public_docs_hygiene.py` is NOT on this task's Files list**, so a red there is an Unexpected-red STOP under Global Constraints, not something to fix in passing — and it is trivially avoidable by never typing an absolute path into a public doc.

- [ ] **Step 5: Run warpline's attest tests** — `uv run pytest tests/test_attest.py -v`. Expected: PASS, including the untouched `:133-141` attest-1 rejection, `:269-277` structural rejection, and the closed-vocab test (`:280-295` — no new reason codes were minted). Then from `/home/john/wardline`: `uv run pytest tests/conformance/test_attest_dual_read.py -q` — the Layer-2 byte-compare now runs and passes. **Rev 3.9 — also run warpline's `uv run pytest tests/test_public_docs_hygiene.py -q` before handing back**, because Step 4.5 edits `CHANGELOG.md`, that module treats it as a public doc, and a stray absolute `/home/john/...` path reds a test this task's Files list does not carry (see the repo-relative-paths rule at Step 4.5).

- [ ] **Step 6: Commit (orchestrator, `/home/john/warpline`, `main`, explicit paths)** — `feat(attest): dual-accept Wardline attest-2 and attest-3 as untrusted relay input`

---

### Task 22: Legis unknown-key tolerance pin + declarations preview vector (§13.1 item 3) — repos `/home/john/wardline` + `/home/john/legis`

**Files:**
- Create (wardline, the authority copy): `tests/conformance/fixtures/wardline-legis-declarations-preview.v1.json`
- Create (wardline): `tests/conformance/test_legis_declarations_preview_vector.py`
- Create (legis, byte-identical vendored copy): `tests/contract/weft/vectors/wardline_declarations_preview.v1.json`
- Create (legis): `tests/contract/weft/test_unknown_artifact_key_tolerance.py`

**Verified mechanics this task pins:** `wardline_artifact_fields` (`ingest.py:255-263`) copies every non-signature key — NO allowlist — so an additive `declarations` key is signature-covered automatically; `verify_wardline_artifact` (`:266-367`) requires only the four `ARTIFACT_PROVENANCE_FIELDS` + `artifact_signature` in keyed posture; `active_defects` (`:482-499`) requires `findings` present; `scan_digest` (`service/wardline.py:221`) = `sha256(canonical_json(artifact minus signature))`, so the added key SHIFTS it (additive but audit-visible, by design). The legis contract tests are vector-driven with the plain UTF-8 key `test-shared-secret-key` — no fixtures, no helpers. Spec §13.1 item 3: legis "receives the wire vectors for lockstep adoption" — wardline authors the preview vector; legis vendors it.

- [ ] **Step 1: Author the preview vector** (wardline authority copy) — `tests/conformance/fixtures/wardline-legis-declarations-preview.v1.json`. Modeled on the legis golden's shape (`wardline_scan_artifact.v1.json` `valid[0]`), widened with the S1-preview `declarations` key; NO `expected_signature` (the `clean_scan_empty_findings` precedent — the consumer test computes and verifies live, so no cross-side hex pin exists to re-freeze in S1):

```json
{
  "contract": "weft/wardline-scan-artifact-declarations-preview",
  "description": "S0 preview vector for wardline's S1 additive `declarations` member (declaration-surface-v2 §13.1 item 3). Pins legis's stated posture TODAY: unknown top-level keys are accepted, swept into the signed payload, and shift scan_digest (audit-visible, by design). Authored in wardline, vendored byte-identical in legis.",
  "signing": {
    "key_utf8": "test-shared-secret-key",
    "scheme": "hmac-sha256:v2",
    "policy": "no expected_signature hex: the consumer test signs and verifies live, so the S1 producer can extend `declarations` without a two-sided hex re-pin of THIS vector (the main scan-artifact vector keeps that role)."
  },
  "valid": [
    {
      "name": "declarations_preview_signed",
      "description": "The golden single-defect artifact widened with an empty declarations ledger: signature must cover it, verification must accept it, scan_digest must shift.",
      "artifact": {
        "scanner_identity": "wardline@1.5.0",
        "rule_set_version": "sha256:deadbeef",
        "commit_sha": "cccccccccccccccccccccccccccccccccccccccc",
        "tree_sha": "tttttttttttttttttttttttttttttttttttttttt",
        "findings": [
          {
            "rule_id": "PY-WL-101",
            "message": "leak",
            "severity": "ERROR",
            "kind": "defect",
            "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "qualname": "svc.leaky",
            "properties": {"declared_return": "INTEGRAL", "actual_return": "EXTERNAL_RAW"},
            "suppression_state": "active"
          }
        ],
        "declarations": []
      }
    }
  ]
}
```

- [ ] **Step 2: Write the legis pin** — `tests/contract/weft/test_unknown_artifact_key_tolerance.py`:

```python
"""Wardline declaration-surface-v2 §13.1 item 3 — legis's stated posture, pinned.

Legis accepts unknown top-level keys in the wardline scan artifact today:
``wardline_artifact_fields`` copies every non-signature key (no allowlist,
ingest.py:255-263) and ``verify_wardline_artifact`` requires only the four
provenance fields + the signature. Wardline's S1 additive ``declarations``
member depends on this tolerance, so it is pinned here — with its one
observable side effect: ``scan_digest`` covers the whole artifact, so the added
key SHIFTS the digest (additive, but visible in the audit record, by design).
Vector: vendored byte-identical from wardline (the authority copy)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from legis.canonical import content_hash
from legis.crypto.signing import sign
from legis.wardline.ingest import (
    active_defects,
    verify_wardline_artifact,
    wardline_artifact_fields,
)

VECTOR_PATH = Path(__file__).parent / "vectors" / "wardline_declarations_preview.v1.json"
VECTOR = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
_KEY = VECTOR["signing"]["key_utf8"].encode("utf-8")


def _ids(cases: list[dict]) -> list[str]:
    return [c["name"] for c in cases]


def test_vector_self_describes() -> None:
    assert VECTOR["contract"] == "weft/wardline-scan-artifact-declarations-preview"


@pytest.mark.parametrize("case", VECTOR["valid"], ids=_ids(VECTOR["valid"]))
def test_unknown_declarations_key_is_signature_covered_and_verifies(case: dict) -> None:
    artifact = dict(case["artifact"])
    fields = wardline_artifact_fields(artifact)
    assert "declarations" in fields  # swept into the signed payload — no allowlist
    signed = {**artifact, "artifact_signature": sign(fields, _KEY)}
    provenance = verify_wardline_artifact(signed, artifact_key=_KEY)
    assert provenance["artifact_status"] == "verified"
    # The gate population is untouched by the unknown key.
    assert [f.fingerprint for f in active_defects(signed)] == [
        f["fingerprint"] for f in artifact["findings"]
    ]


@pytest.mark.parametrize("case", VECTOR["valid"], ids=_ids(VECTOR["valid"]))
def test_added_key_shifts_the_scan_digest(case: dict) -> None:
    artifact = dict(case["artifact"])
    without = {k: v for k, v in artifact.items() if k != "declarations"}
    assert content_hash(wardline_artifact_fields(without)) != content_hash(
        wardline_artifact_fields(artifact)
    )
```

- [ ] **Step 3: Vendor + wardline-side receipt.** Copy the vector byte-identically: `cp /home/john/wardline/tests/conformance/fixtures/wardline-legis-declarations-preview.v1.json /home/john/legis/tests/contract/weft/vectors/wardline_declarations_preview.v1.json`, confirm with `cmp`. Then create the wardline-side Layer-2 receipt — `tests/conformance/test_legis_declarations_preview_vector.py`:

```python
"""The wardline↔legis declarations preview vector (spec §13.1 item 3): wardline
authors it, legis vendors it byte-identically. Coordinated/release jobs arm
the cross-repository byte comparison with LEGIS_REPO; standalone CI may skip."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

AUTHORITY = Path(__file__).parent / "fixtures" / "wardline-legis-declarations-preview.v1.json"


def test_vector_parses_and_carries_the_preview_key() -> None:
    vector = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    assert vector["contract"] == "weft/wardline-scan-artifact-declarations-preview"
    assert all("declarations" in case["artifact"] for case in vector["valid"])


def test_legis_vendored_copy_is_byte_identical_when_present() -> None:
    configured_repo = os.environ.get("LEGIS_REPO")
    repo = configured_repo or "/home/john/legis"
    vendored = Path(repo) / "tests" / "contract" / "weft" / "vectors" / "wardline_declarations_preview.v1.json"
    if not vendored.exists():
        if configured_repo is not None:
            pytest.fail(f"missing required Legis receipt at {vendored}")
        pytest.skip(f"Legis checkout not present at {vendored}; Task 23 supplies LEGIS_REPO")
    assert vendored.read_bytes() == AUTHORITY.read_bytes()
```

- [ ] **Step 4: Run** — from `/home/john/legis`: `uv run pytest tests/contract/weft/test_unknown_artifact_key_tolerance.py -v`. Expected: PASS — this pins EXISTING behaviour; if it fails, legis is NOT tolerant, spec §13.1 item 3's premise is wrong: STOP and report to John before any S1 work. From `/home/john/wardline`: `uv run pytest tests/conformance/test_legis_declarations_preview_vector.py -v`. Expected: PASS.

- [ ] **Step 5: Commits (orchestrator, after the dirty-target preflight).** Wardline `release/2.0.0`: `test(conformance): author wardline-legis declarations preview and receipt`. Legis `main`, explicit paths: `test(weft): pin unknown-artifact-key tolerance and vendor Wardline preview`.

---

### Task 23: Cross-consumer receipt and attest seam-registry truth-up

**Depends on:** Tasks 20 and 21; run after Task 22 so all consumer receipts exist.

**Files (Wardline `release/2.0.0`):**
- Modify: `tests/conformance/seam_registry.json` (attest row only)

- [ ] **Step 1: Require both receipts and byte identity; no skips.**

```bash
test -f /home/john/warpline/tests/fixtures/wardline-attest-3.vector.json
test -f /home/john/legis/tests/contract/weft/vectors/wardline_declarations_preview.v1.json
cmp \
  /home/john/wardline/tests/conformance/fixtures/wardline-attest-3.vector.json \
  /home/john/warpline/tests/fixtures/wardline-attest-3.vector.json
cmp \
  /home/john/wardline/tests/conformance/fixtures/wardline-legis-declarations-preview.v1.json \
  /home/john/legis/tests/contract/weft/vectors/wardline_declarations_preview.v1.json
WARPLINE_REPO=/home/john/warpline \
LEGIS_REPO=/home/john/legis \
uv run pytest \
  tests/conformance/test_attest_dual_read.py \
  tests/conformance/test_legis_declarations_preview_vector.py -q
```

- [ ] **Step 2: Truth up the attest seam atomically.** Replace the stale row with `authority="wardline"`, `consumer_or_second_producer="warpline"`, `two_sided=true`, `oracle_shape="shared_signed_vector"`, `oracle_test="tests/conformance/test_attest_dual_read.py"`, null marker/drift fields, `bar_verdict="at_bar"`, `deferred_reason=null`, and `wire_change="additive reader expansion; S0 emission remains wardline-attest-2"`.

The `seam` and `wire` prose must say all four truths: Wardline still emits attest-2 in S0; Wardline's key-holding verifier accepts v2/v3 and verifies HMAC; Warpline accepts v2/v3 as an untrusted relay and does not verify HMAC; and the coordinated Task 23/release receipt enforces byte identity while standalone suites enforce their respective signer/canonicalization halves. Add `peer_conformance` with the **actual Task 21 commit SHA** and `tests/test_attest.py`—never a placeholder. Evidence paths include Wardline's verifier, test, vector, both contract docs, guide, and consumer prompt. **Rev 3.9 — two additions to this step:**

  a. **The row's existing evidence path `src/wardline/core/attest.py:62` is stale and must be written as `src/wardline/core/attest.py:63`.** `:62` is a blank line; `ATTEST_SCHEMA = "wardline-attest-2"` is at `:63` (which is also the coordinate Global Constraints cites). Correct it in the same atomic rewrite. While you are there: the row's `wire` prose still says "warpline consumer NOT YET wired", which was already false before Task 20 (warpline ships `src/warpline/_attest.py`; `worklist_risk` imported at `commands.py:8`, called at `commands.py:1117`, released in 1.3.0) — this task is the first and only one whose Files list carries this path, so it is where that clause dies. Task 20's prohibition on touching this file is a path-gate rule, **not** an endorsement of that clause; see the rev-3.9 correction there.

  b. **The `oracle_test` you are about to name is grepped, not merely run.** Setting `oracle_shape="shared_signed_vector"` routes this row into `tests/conformance/test_seam_registry.py`'s `_has_shared_vector_pin`, which reads `tests/conformance/test_attest_dual_read.py`'s **source text** and requires all three of: a `GOLDEN_KEY` name, a literal `sign_artifact(` call (`\bsign_artifact\s*\(`), and a `*_FIELD` upper-case constant. Wardline's signer is `_sign`, so the middle token exists **only** via the `from wardline.core.attest import _sign as sign_artifact` alias in **Task 20 Step 1**'s pinned block. If Step 3 reds on `_has_shared_vector_pin`, the defect is in Task 20's authored file, not here — do **not** weaken the gate or the row; restore the alias/constants in `test_attest_dual_read.py` (Task 20's Files list owns that path, and this row's `oracle_test` claim is false without them). Task 20's Interfaces section carries the forward half of this dependency.

- [ ] **Step 3: Verify and commit.**

```bash
uv run pytest \
  tests/conformance/test_attest_dual_read.py \
  tests/conformance/test_seam_registry.py -q
```

Commit separately on Wardline `release/2.0.0`: `test(conformance): truth up two-sided attest seam after Warpline receipt`.

---

## Rollout Fence — what S1 may and may not assume (record of decision)

S0 stages consumers; S1 may develop against a coordinated local stack, but public producer emission has a separate release gate. These gates are cumulative and not interchangeable.

**1. Local coordination gate.** Record the task commit and integrated target-branch HEAD for all four repositories. Each task commit must be an ancestor of Wardline `release/2.0.0`, Loomweave `release/1.5.0`, or Warpline/Legis `main`, as applicable. Build cold-install inputs from Git archives of those recorded commits—never dirty checkout bytes:

```bash
(
set -euo pipefail
S0_COLD_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$S0_COLD_ROOT"' EXIT
S0_SNAPSHOT_ROOT="$S0_COLD_ROOT/snapshots"
S0_UV_TOOL_DIR="$S0_COLD_ROOT/tools"
S0_UV_BIN_DIR="$S0_COLD_ROOT/bin"
mkdir -p "$S0_SNAPSHOT_ROOT"/{wardline,loomweave,warpline,legis} \
  "$S0_UV_TOOL_DIR" "$S0_UV_BIN_DIR"

S0_WARDLINE_HEAD="$(git -C /home/john/wardline rev-parse refs/heads/release/2.0.0)"
S0_LOOMWEAVE_HEAD="$(git -C /home/john/loomweave rev-parse refs/heads/release/1.5.0)"
S0_WARPLINE_HEAD="$(git -C /home/john/warpline rev-parse refs/heads/main)"
S0_LEGIS_HEAD="$(git -C /home/john/legis rev-parse refs/heads/main)"

# Populate these four from the implementation receipt before running.
: "${S0_TASK19_COMMIT:?populate from the Task 19 implementation receipt}"
: "${S0_TASK21_COMMIT:?populate from the Task 21 implementation receipt}"
: "${S0_TASK22_LEGIS_COMMIT:?populate from the Task 22 implementation receipt}"
: "${S0_TASK23_COMMIT:?populate from the Task 23 implementation receipt}"
git -C /home/john/loomweave merge-base --is-ancestor "$S0_TASK19_COMMIT" "$S0_LOOMWEAVE_HEAD"
git -C /home/john/warpline merge-base --is-ancestor "$S0_TASK21_COMMIT" "$S0_WARPLINE_HEAD"
git -C /home/john/legis merge-base --is-ancestor "$S0_TASK22_LEGIS_COMMIT" "$S0_LEGIS_HEAD"
git -C /home/john/wardline merge-base --is-ancestor "$S0_TASK23_COMMIT" "$S0_WARDLINE_HEAD"

git -C /home/john/wardline archive "$S0_WARDLINE_HEAD" | tar -xf - -C "$S0_SNAPSHOT_ROOT/wardline"
git -C /home/john/loomweave archive "$S0_LOOMWEAVE_HEAD" | tar -xf - -C "$S0_SNAPSHOT_ROOT/loomweave"
git -C /home/john/warpline archive "$S0_WARPLINE_HEAD" | tar -xf - -C "$S0_SNAPSHOT_ROOT/warpline"
git -C /home/john/legis archive "$S0_LEGIS_HEAD" | tar -xf - -C "$S0_SNAPSHOT_ROOT/legis"

UV_TOOL_DIR="$S0_UV_TOOL_DIR" UV_TOOL_BIN_DIR="$S0_UV_BIN_DIR" \
  uv tool install --reinstall --no-cache "$S0_SNAPSHOT_ROOT/wardline[loomweave,rust]"
UV_TOOL_DIR="$S0_UV_TOOL_DIR" UV_TOOL_BIN_DIR="$S0_UV_BIN_DIR" \
  uv tool install --reinstall --no-cache "$S0_SNAPSHOT_ROOT/loomweave/plugins/python"
UV_TOOL_DIR="$S0_UV_TOOL_DIR" UV_TOOL_BIN_DIR="$S0_UV_BIN_DIR" \
  uv tool install --reinstall --no-cache "$S0_SNAPSHOT_ROOT/warpline"
UV_TOOL_DIR="$S0_UV_TOOL_DIR" UV_TOOL_BIN_DIR="$S0_UV_BIN_DIR" \
  uv tool install --reinstall --no-cache "$S0_SNAPSHOT_ROOT/legis"

# Probe installed environments; print module paths and distribution versions.
"$S0_UV_TOOL_DIR/wardline/bin/python" -c \
  "import wardline; from importlib.metadata import version; from wardline.core.attest import ATTEST_SCHEMA,ACCEPTED_ATTEST_SCHEMAS; assert ATTEST_SCHEMA=='wardline-attest-2'; assert ACCEPTED_ATTEST_SCHEMAS==('wardline-attest-2','wardline-attest-3'); print(wardline.__file__,version('wardline'))"
"$S0_UV_TOOL_DIR/loomweave-plugin-python/bin/python" - <<'PY'
import tempfile
from importlib.metadata import version
from pathlib import Path

import loomweave_plugin_python as p
from loomweave_plugin_python.wardline_descriptor import (
    ACCEPTED_DESCRIPTORS,
    load_wardline_descriptor,
)

assert ("wardline.vocabulary/v2", "wardline-generic-3") in ACCEPTED_DESCRIPTORS
# Acceptance is accept-and-READ (spec rev 9 §4.3, §13.1 item 1), so this probe
# proves the READ half as well: an accept-only probe passes against a reader
# that tolerates `facets:` as an unknown top-level key, which is exactly the
# accept-and-ignore fail-open the pair gate exists to prevent. The bytes are
# inline, mirroring the Legis probe below, because the wheel carries no test
# fixtures; Task 19 Step 1's
# `test_generic_3_preview_fixture_declares_only_known_sections` is what guards
# the fixture's own shape.
DESCRIPTOR = """schema: wardline.vocabulary/v2
version: wardline-generic-3
entries:
- canonical_name: external_boundary
  group: 1
  attrs: {}
- canonical_name: trust_boundary
  group: 1
  attrs:
    _wardline_to_level: TaintState
- canonical_name: trusted
  group: 1
  attrs:
    _wardline_level: TaintState
facets:
- canonical_name: audit_record
  group: 3
"""
with tempfile.TemporaryDirectory() as tmp:
    planted = Path(tmp) / ".weft" / "wardline" / "vocabulary.yaml"
    planted.parent.mkdir(parents=True)
    planted.write_text(DESCRIPTOR, encoding="utf-8")
    state = load_wardline_descriptor(Path(tmp))
# `descriptor_version` is what discriminates the planted v2 bytes from a
# fall-through to the installed wardline package's own v1 descriptor.
assert state.status == "enabled", state.status
assert state.descriptor_version == "wardline-generic-3"
assert state.vocabulary is not None
assert state.vocabulary.schema == "wardline.vocabulary/v2"
assert sorted(state.vocabulary.facets_by_name) == ["audit_record"]
assert (
    state.vocabulary.facet_for_decorator("weft_markers.audit_record")
    is state.vocabulary.facets_by_name["audit_record"]
)
print(p.__file__, version("loomweave-plugin-python"))
PY
"$S0_UV_TOOL_DIR/warpline/bin/python" -c \
  "import warpline; from importlib.metadata import version; from warpline._attest import ACCEPTED_ATTEST_SCHEMAS; assert 'wardline-attest-3' in ACCEPTED_ATTEST_SCHEMAS; print(warpline.__file__,version('warpline'))"
"$S0_UV_TOOL_DIR/legis/bin/python" - <<'PY'
import legis
from importlib.metadata import version
from legis.crypto.signing import sign
from legis.wardline.ingest import verify_wardline_artifact, wardline_artifact_fields
key = b"test-shared-secret-key"
artifact = {
    "scanner_identity": "wardline@local-s0", "rule_set_version": "sha256:deadbeef",
    "commit_sha": "c" * 40, "tree_sha": "t" * 40,
    "findings": [], "declarations": [],
}
fields = wardline_artifact_fields(artifact)
assert "declarations" in fields
signed = {**artifact, "artifact_signature": sign(fields, key)}
assert verify_wardline_artifact(signed, artifact_key=key)["artifact_status"] == "verified"
print(legis.__file__, version("legis"))
PY

printf 'integrated_heads wardline=%s loomweave=%s warpline=%s legis=%s\n' \
  "$S0_WARDLINE_HEAD" "$S0_LOOMWEAVE_HEAD" "$S0_WARPLINE_HEAD" "$S0_LEGIS_HEAD"
printf 'task_commits task19_loomweave=%s task21_warpline=%s task22_legis=%s task23_wardline=%s\n' \
  "$S0_TASK19_COMMIT" "$S0_TASK21_COMMIT" "$S0_TASK22_LEGIS_COMMIT" "$S0_TASK23_COMMIT"
)
```

Restart long-running Wardline/federation processes. Passing this gate permits local S1 implementation and locally coordinated emission only.

**2. Published-release gate.** A local merge/install never authorizes published producer emission. Before publishing any Wardline version that emits generic-3 or attest-3: publish Loomweave, Warpline, and Legis releases containing the recorded consumer commits and prove every release tag contains its task commit. Cold-install the exact published distributions into isolated `UV_TOOL_DIR` **and** `UV_TOOL_BIN_DIR` with `env -u PYTHONPATH` and `--no-sources`, then run installed-package probes only. Warpline/Legis wheels do not contain their test vectors, so run cross-repository vector receipts separately against temporary archives of the exact release tags. Tie those layers together with tag/version/commit evidence plus distribution hashes and CI/release URLs, then obtain release-train-owner authorization. S0 deliberately performs no consumer version bumps, so `published_emission_ready=false` at S0 close.

**3. S1 producer preflight.** In the same producer change that bumps `REGISTRY_VERSION`/`ATTEST_SCHEMA`, bump `_RESOLVER_VERSION` again beyond `sp1h`; re-vendor `vocabulary.yaml`, descriptor goldens, and blob pins; compare the first real generic-3 and attest-3 serializer outputs semantically and bytewise against the non-normative previews before replacing them; update Task 13's pinned builtin fingerprint and Task 20's emission freeze. Public emission additionally requires gate 2.

**4. The generic-3 inversion trap (S1 must re-tokenize two tests).** Exactly TWO loomweave tests derive their skew case by literally replacing `"wardline-generic-2"` → `"wardline-generic-3"`: `test_wardline_descriptor.py:217` and `test_wardline_vocabulary_descriptor_conformance.py:261`. (Corrected in rev 3.4: the previously-cited `test_wardline_descriptor.py:52` and `:116` substitute to `wardline-generic-**9**`, not generic-3 — they are unrelated fixtures for two different tests and are not part of this trap.) Once generic-3 is accepted-and-expected, those two derivations invert (the conformance one even self-asserts `skewed != golden` and reds). S1 switches their skew token to `"wardline-generic-9"`. Task 19 deliberately does NOT touch them — they still pass in S0 because (v1-or-absent schema, generic-3) remains an unaccepted pair.

**5. Legis two-sided re-pin (S1).** When S1 adds real `declarations` content to the MAIN scan-artifact vector (`wardline_scan_artifact.v1.json`), its `expected_signature` hex is pinned on BOTH sides (the legis vector note says the hex is identical to wardline's golden in `tests/unit/core/test_legis_artifact.py`) — a two-sided re-pin in one coordinated pair of commits, plus the documented `scan_digest` shift in every routed scan. The Task 22 preview vector deliberately carries no hex so it needs no re-pin.

**6. Rollback ordering.** If S1's flip misbehaves: revert the WARDLINE producer commit first (emission returns to generic-2/attest-2 — consumers' dual-accept keeps working); consumer dual-accept commits stay in place (harmless surplus acceptance). Never revert consumers while a producer emits the new formats.

**7. Shared-artifact discipline table.**

| Artifact | Authority | Vendored copy | Pin mechanism |
|---|---|---|---|
| vocabulary descriptor golden (generic-2) | wardline `tests/conformance/fixtures/` | loomweave `plugins/python/tests/fixtures/` | git-blob SHA both sides (`UPSTREAM_BLOB_SHA`) + Layer-2 byte-compare (existing) |
| generic-3 preview fixture | loomweave (SEMANTIC, Task 19) | — | field assertions only; byte-freeze deferred to S1 §3 |
| attest-3 vector | wardline `tests/conformance/fixtures/` (Task 20) | warpline `tests/fixtures/` (Task 21) | real Wardline signer round-trip + test-time independent HMAC derivation in Warpline (not runtime verification) + mandatory byte receipt |
| declarations preview vector | wardline `tests/conformance/fixtures/` (Task 22) | legis `tests/contract/weft/vectors/` | live sign/verify (legis) + Layer-2 byte-compare (wardline); no hex by design |
| MCP output-schema golden | wardline only | — | `VENDORED_BLOB_SHA` (re-frozen Tasks 9 + 20) |

---

## Final verification (after all tasks)

- [ ] Wardline: `uv run pytest -q`, `uv run lint-imports`, `uv run mypy`, `uv run ruff check src tests`, and `git diff --check` — all green. In one import probe assert `REGISTRY_VERSION == "wardline-generic-2"`, `ATTEST_SCHEMA == "wardline-attest-2"`, `DESCRIPTOR_SCHEMA == "wardline.vocabulary/v1"`, `BASELINE_VERSION == 1`, and `_RESOLVER_VERSION == "sp1h"`; also run the descriptor/vocabulary golden tests so their committed blob pins are checked, not merely described.
- [ ] **Blast-radius re-run (spec §4.2.1) — this bullet is the measurement's single definition.** With the form-5 plumbing in place, re-run the four frozen-oracle suites enumerated below and **re-confirm the blinded negative control LIVE in the same session**; record both results in the close receipt. The control is what makes an "all same" result meaningful rather than a no-op — "full suite green" cannot distinguish "form 5 moved nothing" from "the control stopped discriminating", and the over-approximation probe patched exactly two symbols and covered the recogniser only, not the module-level-constant plumbing, which did not yet exist.

  **Constituted at plan rev 3.8, not recovered — read the provenance honestly.** Through rev 3.7 this bullet and spec §4.2.1 both named "the same four frozen-oracle suites", "exactly two symbols" and "the blinded negative control" as prior artefacts, and a whole-repo grep found no definition of any of the three: the gate was executable in form and empty in content, which is the no-op receipt the paragraph above warns against. The suites, the probe's symbols and the control are **fixed here**. No count is asserted on its own — the mapping below is what makes the set checkable, because every artefact on the zero-scan-golden-drift Global Constraint's no-regeneration list appears in it.

  | # | Suite (exact invocation, from `/home/john/wardline`) | Frozen artefact(s) it oracles |
  |---|---|---|
  | 1 | `uv run pytest tests/grammar/test_golden_oracle.py -q` | `tests/grammar/golden/builtin_findings.jsonl` — the byte stream over `tests/corpus/fixtures` |
  | 2 | `uv run pytest tests/golden/identity/test_identity_parity.py -q` | `tests/golden/identity/corpus/*.json`, captured over `tests/golden/identity/fixtures/**` |
  | 3 | `uv run pytest tests/golden/identity/rust/test_rust_identity_parity.py -q` | `tests/golden/identity/rust/corpus/*.json`, captured over `tests/golden/identity/rust/fixtures/**` |
  | 4 | `uv run pytest tests/conformance/test_vocabulary_descriptor_wire_golden.py -q` | `tests/conformance/fixtures/wardline-vocabulary-descriptor.golden.yaml` + its `UPSTREAM_BLOB_SHA`, tied to the live producer by `test_golden_matches_live_descriptor_producer`, with `src/wardline/core/vocabulary.yaml` held in lockstep by that module's RE-VENDOR PROCEDURE |

  The seventh artefact on that list, `tests/corpus/rust/**`, is named here rather than added as a fifth suite, and the reason is stated rather than left inferable: its guard is `tests/unit/rust/test_corpus.py`, a parse-and-count/label gate, **not** a byte-frozen oracle — and form 5 is Python-and-builtin-`LEVEL`-only, so it cannot move under this change by construction. Its 21 canonical `/// @trusted(level=ASSURED)` markers stay covered by the no-regeneration prohibition either way.

  **The probe's two symbols**, named so that "the same" is a checkable claim: `wardline.scanner.rules.invalid_decorator_level._level_token` (the rule-side recogniser, `:73`) and `wardline.scanner.taint.decorator_provider._level_token` (the provider-side one, `:128`). Those are precisely the two readers **Task 2** unifies, which is also why the probe reached the recogniser and nothing else. The over-approximation is: make both return `value.id` for a bare `ast.Name` — strictly wider than form 5, which resolves only a same-file, module-level, one-hop binding. Measured live on the pre-Task-1 tree (2026-08-11): **zero delta** on suite 1, consistent with the value census's finding of zero bare-`ast.Name` LEVEL values in the frozen trees.

  ***Rev-3.9 addressing note — read the paragraph above as the dated pre-Task-1 record it is, and do not re-address it.*** *Both `_level_token` symbols it names existed on the pre-Task-1 tree; neither survives Task 2's unification. Post-Task-2, measured 2026-08-12: `hasattr(wardline.scanner.taint.decorator_provider, "_level_token")` is **False** (the module no longer defines one), and `wardline.scanner.rules.invalid_decorator_level._level_token` is no longer a function at `:73` at all — it is an **import alias** (`from wardline.scanner.marker_reader import level_token as _level_token`, `invalid_decorator_level.py:29`; `:73` is now inside that rule's `examples_violation` tuple). The single post-Task-2 reader is **`wardline.scanner.marker_reader.level_token`** (`marker_reader.py:260`). Rewriting this historical measurement onto one symbol would make the record a lie about what was measured, so it stands as written; the probe is **not** part of the Pass condition below and is not re-run at the close gate. Only the control is — and the control paragraph immediately following IS re-addressed, because it is a forward-looking instruction executed live at S0 close.*

  **The blinded negative control — the perturbed symbol plus the delta that must appear.** Perturb the **module attribute** `wardline.scanner.marker_reader.level_token` **alone** so that a token it would read as `"ASSURED"` is returned as `"GUARDED"`, leaving every other token untouched, then re-run suite 1. It **must** red. Measured live on the pre-Task-1 tree (2026-08-11) and **re-measured on the post-Task-18 tree 2026-08-12 against the corrected symbol, reproducing the same numbers**: a 32-line unified diff against the frozen stream (that count is the whole `difflib.unified_diff` output at `n=0`, i.e. **26 added/removed content lines** plus the `---` / `+++` headers and the hunk markers — the two figures are the same measurement counted two ways, and the rev-3.9 note below quotes the content figure) — **22 DEFECT lines lost** across PY-WL-101/102/105/106/107/108/109 (13 × PY-WL-101, 2 × PY-WL-102, 1 × PY-WL-105, 1 × PY-WL-106, 1 × PY-WL-107, 3 × PY-WL-108, 1 × PY-WL-109), 2 PY-WL-102 DEFECT lines gained, and the `WLN-ENGINE-METRICS` line moving `taint_source_counts.anchored` 43 → 18. So the control discriminates **semantically**, not merely bytewise, which matters because the property under measurement — form 5 changing seeding semantics — is semantic. Suites 2–4 are not expected to move under the control and their stillness is **not** a control failure: suites 3 and 4 cannot move under a Python-builtin-`LEVEL` perturbation by construction, and suite 2 was not measured under it. They are in the set because they oracle artefacts on the no-regeneration list, and their job is the zero-delta half.

  **The control is an in-process scratch perturbation and never a committed edit.** Monkeypatch the symbol inside a throwaway `uv run python` script that imports `grammar.golden_harness.produce_stream` and compares its output against `GOLDEN`; write no file, commit nothing, leave the tree untouched. A perturbation committed to source — or a specimen dropped into any tree named above — converts this guard into a re-freeze exactly as a stray fixture would, which is the hazard the placement rules elsewhere in this plan exist to prevent.

  ***Rev-3.9 blocking correction — the symbol swap is prescribed, not improvised.*** *Through rev 3.8 this control named `wardline.scanner.taint.decorator_provider._level_token`, which **Task 2 deleted**: measured 2026-08-12, `hasattr` on that module is `False`, so close condition (iv) had **no executable target** and the gate would have stalled at the S0 close — the last place a stall is affordable. The replacement is **exactly** `wardline.scanner.marker_reader.level_token` and the instruction is precise about how:*
  - *Rebind **only the module attribute** `wardline.scanner.marker_reader.level_token`. Do **not** also rebind `wardline.scanner.rules.invalid_decorator_level._level_token` or `wardline.scanner.module_census.level_token`. Both of those are `from … import … as` aliases **bound at import time**, so they are unaffected by patching the defining module — and that is precisely what makes this perturbation provider-side-only, i.e. the same blinding the pre-Task-1 control had. Measured 2026-08-12: patching the module attribute alone reproduces the recorded delta exactly (26 content lines, 22 DEFECTs lost, 2 gained, `anchored` 43 → 18); **also** rebinding the two aliases produces a different, wider delta (23 lost / 28 gained, including 25 spurious PY-WL-114 DEFECTs) that does **not** match the recorded numbers, so a receipt taken that way fails condition (iv) for the wrong reason.*
  - *Do **not** invent an equivalent perturbation. Naive re-addressings were tried and rejected on measurement: wrapping `read_level` to return a substituted `LevelRead` bypasses that function's own `allowed`-set gate and yields an **engine-unreachable** control — green where it must red. Swap the symbol as written; if it does not reproduce the recorded delta, that is the STOP, not a licence to improvise a substitute.*
  - *The Pass condition below is unchanged in form: the control run must red `tests/grammar/test_golden_oracle.py::test_builtin_findings_match_golden`. It does, under the corrected symbol.*

  **Pass condition, both halves in the same session:** suites 1–4 all green with **zero delta** on the unperturbed tree, **AND** the control run reds `tests/grammar/test_golden_oracle.py::test_builtin_findings_match_golden`. Either half alone is a no-op receipt. Record both, by suite, in the close receipt.

  **Any delta on suites 1–4 is PRD-0003 criterion 4's reject branch — stop and fix the change, never the golden.** It is NOT covered by spec §12's per-kind allowance of at most one reviewed rekey and one `regen.py --reason` re-freeze — that allowance is for new declaration kinds and revision 6 introduces none — and it is not one of the two sanctioned `mcp_output_schemas.golden.json` re-freezes either. The zero-scan-golden-drift Global Constraint already forbids re-freezing a red scan golden; what this bullet adds is the missing **positive** obligation to re-measure at all — and, at rev 3.8, the executable content that obligation had been missing since it was written.
- [ ] Self-scan gate (CLAUDE.md command, whole repo): `uv run wardline scan . --fail-on ERROR` — exit 0. If **PY-WL-130, PY-WL-114, or any tier-modulated DEFECT** newly fires anywhere in the repo, it is a REAL defect: spec §4.2.1 classifies **both** newly-firing populations — PY-WL-114's widened surface, and the tier-modulated DEFECTs on functions P3 form 5 moves into the declared set — as **true positives by construction**, so fix the source, never suppress (the self-hosting gate demands zero committed suppressions). This is an incompleteness in the gate's stated meaning, not a predicted red: spec §14 records a repo-wide census finding **zero** bare-`Name` level values. **Exit 0 says nothing about `WLN-ENGINE-UNREADABLE-MARKER-VALUE`**, which is `Severity.NONE` and never gates — `SEVERITY_ORDER` omits `Severity.NONE` by design. Verify that population separately with `uv run wardline decorator-coverage .`, reading the residual FACT's summary key added in **Task 9**, and confirm no committed waiver and no committed baseline row names its fingerprint — a hygiene check against the self-hosting gate's zero-committed-suppressions rule, **not** the mechanism, because such a row would be accepted and INERT rather than rejected (soundness condition 3 — never *suppressible*, which is not the same as never *writable*). Note what that condition is and is not: non-suppressibility is **structural and already shipped**, because `apply_suppressions` short-circuits every non-`Kind.DEFECT` finding before the waiver/judged/baseline join and `_is_baselineable_finding` admits only `Kind.DEFECT`, so no waiver, judged entry or baseline row can suppress it, and `build_baseline_document` never generates one for it. **The claim is exactly that and no wider (spec rev 9 §4.2.1 condition 3, which withdraws the earlier over-claim): a waiver — or a hand-authored baseline row — naming its fingerprint *can* be written, and is simply inert**, `add_waiver` never seeing a `Finding` and a loaded baseline being a bare set of fingerprints. The obligation on the implementation is therefore a **guard test, not a feature** — see the `wardline-5a795253f1` close criteria.
- [ ] End-to-end repro, **hole 1** (`wardline-4928b75782`, the ticket's scenario): a `tmp_path` project with `@trusted(level="INTEGRAL", audit=True)` + a taint sink now exits **1** at `--fail-on ERROR` (was: exit 0, the false green). Record the before/after in the `wardline-4928b75782` close comment — **and pin it by the committed test asserting the literal process exit code**, not merely the presence of a finding. That test is `tests/unit/cli/test_false_green_exit_code_repros.py::test_hole1_malformed_marker_call_trips_the_gate`, **authored and committed at Task 6 Step 7**; this bullet reads that receipt back and does not author it, because Final verification carries no commit step and a test produced here would never be committed. PRD-0003 criterion 1 requires a committed regression test for *each* of the three repros, and spec **rev 7** §4.2.1 obliges that artifact for **every** repro rather than only the rev-6 pair, so hole 1's artifact is obliged **here** as well as by the spec, and a scratch run whose only record is a Filigree comment does not discharge it. Placement rule (spec §4.2.1): the specimen lives in a `tmp_path` CLI or integration test — the shipped `tests/unit/cli/` `CliRunner` + `tmp_path` idiom — and in **none** of `tests/corpus/fixtures` or `tests/golden/identity/corpus/*.json`, both of which auto-absorb a stray `.py` file and would convert PRD-0003 criterion 4's guard into a re-freeze.
- [ ] End-to-end repro, **hole 3** (`wardline-2b2a6cddfa`, in S0 per the 2026-08-10 owner ruling): a `tmp_path` project whose only defect is `@trusted(level=_SVC_LEVEL)` with `_SVC_LEVEL = 'INTEGRAL'` bound once, unconditionally, at module top level and lexically preceding a `def` that is a **direct element of the module body**, plus a taint sink, exits **1** at `--fail-on ERROR` (was: exit 0). Pinned by a committed test asserting the **exit code**, not merely the presence of a finding — the exit code is what criterion 1 reads, and a finding that exists without tripping the gate is the very failure being closed (spec §4.2.1). That test is `tests/unit/cli/test_false_green_exit_code_repros.py::test_hole3_unreadable_level_value_trips_the_gate`, **authored and committed at Task 8 Step 9**, appended to the module Task 6 Step 7 creates; this bullet reads the receipt back and does not author it. Same placement rule as hole 1: `tmp_path` only, and in none of `tests/corpus/fixtures` or `tests/golden/identity/corpus/*.json`.
- [ ] **Hole 2** (`wardline-b857b50b54`, the Rust doc-comment marker shape channel) is **NOT verified here** — it is not an S0 deliverable (owner ruling, 2026-08-10): different frontend, no coupling to Task 2's reader, zero golden blast radius. Its exit-code repro — a `tmp_path` Rust project with a non-canonical `/// @trusted(...)` marker exiting **1** at `--fail-on ERROR` via `WLN-ENGINE-RUST-INVALID-TRUST-MARKER` where it exits 0 today, pinned by a committed test asserting the exit code (the `tests/unit/cli/test_scan_rust.py` `tmp_path` idiom), and committed to **none** of `tests/corpus/rust/**`, `tests/golden/identity/rust/corpus/*.json` or `tests/golden/identity/rust/fixtures/**` — belongs to spec §4.4's separately-owned thread, which must close **before G2 is read**. **S0's close does not close PRD-0003 criterion 6**, and §4.4 is its visible owner. Do not record criterion 6 as met, and do not read G2 as 0, on the strength of a green S0.
- [ ] **P9's receipt, read back by name.** `uv run pytest tests/unit/scanner/test_marker_reader_agreement.py -q` green, **and** `test_form5_agreement` present in that run with one case per row of the agreement list Task 2 Step 5 specifies — its `test_form5_agreement` bullet list, immediately after the **P9 is NOT closed by this task** paragraph — including the invalid-token row, each driven on the analyser's real construction path and asserting BOTH the rule-side finding set and the provider-side declared set on the same scan. The driver is `run_scan(tmp_path)` for every row **but one**: the custom-`BoundaryType` row takes the specification site's carve-out onto `build_analyzer(grammar=default_grammar().extend(boundary_types=(...,)))` and `analyzer.last_context`, because `run_scan` accepts no grammar — read that row's assertions off `analyzer.last_context.declared_qualnames` and `analyzer.last_context.project_taints[<qualname>]`, not `result.context`. A custom row driven through `run_scan` matches no loaded `BoundaryType` and asserts nothing, which is the green-by-absence this bullet exists to refuse. Authored at **Task 8 Step 7**; this bullet reads the receipt and does not author it, and the row count is not restated here because the specification site is authoritative. The generic `uv run pytest -q` above cannot discharge P9: a receipt that was never written is green by absence, which is exactly how rev 3.5 shipped an unownable P9. P9 is a spec §12 S0 prerequisite and a Goal condition (the plan's **Goal:** paragraph), so this bullet and close condition (v) are what make it checkable. It is also the discharge of the coverage map's "aspirational, not met" hedge in Self-review notes' **Revision 6 coverage** bullet.
- [ ] Loomweave: `(cd /home/john/loomweave && uv run --project plugins/python --extra dev pytest plugins/python && python scripts/check-wardline-version-bounds.py --self-test && python scripts/check-wardline-version-bounds.py && cargo test -p loomweave-core manifest && cargo test -p loomweave-storage --test writer_actor python_plugin_edge_kinds_are_accepted_by_writer_contract)`.
- [ ] Warpline: `(cd /home/john/warpline && uv run pytest tests/test_attest.py)`.
- [ ] Legis: `(cd /home/john/legis && uv run pytest tests/contract/weft -q)`.
- [ ] Cross-repo receipts: run Task 23's two `cmp` commands and both Wardline receipt tests with no skips; run the seam-registry test after the truth-up commit.
- [ ] Record the local archive-install receipt for all four integrated target heads. Assert each task commit is an ancestor of its named branch. Restart long-running processes and record installed module paths/versions.
- [ ] Record `published_emission_ready=false`; S0 has not published the consumer releases and cannot authorize public generic-3/attest-3 emission.
- [ ] Filigree (orchestrator): close `wardline-4928b75782` (Tasks 2–7, commit refs + repro) if not already closed — as the **call-shape half** per rev 3.3, **never as "the false green is fixed"** — and still name `wardline-b857b50b54` and `wardline-2b2a6cddfa` in the close comment — **by owning thread, never by status at that instant** (the Filigree discipline rule: do not assert a status the tracker can contradict). Their fates differ and the comment must say so. `wardline-2b2a6cddfa` is owned **inside S0** by spec §4.2.1's form 5 together with the residual FACT, and its owning action is **Task 8 Step 14**; because Final verification runs after Task 8, expect it **already CLOSED** here — read the tracker, do not assume, and note that close condition (ii) below reads that same status independently. `wardline-b857b50b54` is owned by spec §4.4's separately-owned thread and is still open at S0 close. **Rev-3.8 amendment:** rev 3.7 read "both are genuinely still open at that moment", which was false in the very branch this bullet's own "if not already closed" clause admits; the correction is recorded here rather than by rewriting what that revision believed.
- [ ] Filigree (orchestrator): close `wardline-5a795253f1` only when **all five** of these exist — (i) Task 23's integrated Wardline commit and the four-repo local-install receipt; (ii) `wardline-2b2a6cddfa` **CLOSED**, pinned by the committed exit-code regression test in the hole-3 bullet above — `tests/unit/cli/test_false_green_exit_code_repros.py::test_hole3_unreadable_level_value_trips_the_gate`, authored and committed at **Task 8 Step 9**; (iii) each of the residual FACT's **five soundness conditions** pinned by a **named** test — not voided by the `untrusted_sources` rebuild; not inertness-clearing (`summary.total` unmoved, no provider-seeded row, the scan stays inert); **not suppressible**, which is a *guard* test rather than an implementation — the FACT must survive `apply_suppressions` unchanged when a baseline **and** a waiver both carry its fingerprint, so that a future refactor of the `Kind.DEFECT` short-circuit reds something; the distinct fingerprint; and counted in `decorator_coverage` (spec §4.2.1); (iv) the blast-radius re-run recorded against Final verification's **blast-radius bullet**, which is its single authoritative definition — the four named frozen-oracle suites each recorded at **zero delta**, **and** the blinded negative control re-confirmed live in that same session by reding `tests/grammar/test_golden_oracle.py::test_builtin_findings_match_golden`; the suites, the probe's two `_level_token` symbols and the control's perturbation are enumerated there and deliberately **not** restated here, for the reason the Filigree discipline bullet above gives — **and at rev 3.9 the control's perturbed symbol was re-addressed** (the one it named was deleted by Task 2), so read the perturbation off that enumeration rather than from memory or from any earlier revision's text — two lists both claiming exhaustiveness is how a condition goes missing; and (v) **P9 CLOSED** — `tests/unit/scanner/test_marker_reader_agreement.py::test_form5_agreement` green over every row of the agreement list Task 2 Step 5 specifies — its `test_form5_agreement` bullet list, immediately after the **P9 is NOT closed by this task** paragraph — including the invalid-token row, each driven on the analyser's real construction path and asserting BOTH the rule-side finding set and the provider-side declared set on the same scan; the driver is `run_scan(tmp_path)` for every row **but** the custom-`BoundaryType` row, which the specification site carves out onto `build_analyzer` + `analyzer.last_context` because `run_scan` accepts no grammar (authored at **Task 8 Step 7**; read the specification site for the row set — the count is not frozen here). P9 is a spec §12 S0 prerequisite and a Goal condition (the plan's **Goal:** paragraph), so a close receipt that does not record it is not a close, and this condition is what discharges the coverage map's "aspirational, not met" hedge in Self-review notes' **Revision 6 coverage** bullet. **S0's close does not close PRD-0003 criterion 6** — `wardline-b857b50b54` is owned by spec §4.4's separately-owned thread and must close before G2 is read. Note that local S1 development is unblocked but public emission remains gated by consumer releases.

## Self-review notes (spec + review coverage)

- Ticket item (a) → Tasks 1–6; (b) → Tasks 7–9; (c) P1/P2/P3 → Task 10, P4 → Task 11, P7 → Task 12, P8 → Task 13, P9 → Task 2 (qualified below), P10 → Task 14, P13 → Task 16; (d) → Task 17; (e) → Task 18. Spec §12 P5/P6/P12 → Task 15; P11a → Task 7; P11b generic gate → the S2 sensitivity ticket; its Evidence-domain integration repeat → the S3 restoration ticket. P14 → Tasks 1–6. §13.1 item 1 → Task 19; §13.1 item 2 → Tasks 20–21 plus Task 23's receipt; §13.1 item 3 → Task 22; §13.1 sequencing → Rollout Fence.
- **Revision 6 coverage (added at rev 3.5). This map is NOT complete until every owner named here exists.** Spec §4.2.1's **P3 form 5** → Task 2's re-cut shared reader, whose produced interface carries the per-module census **and** the reference site as required, non-defaulted parameters. The **per-module census** — its three components, its once-per-module parse-loop build, and its `SeedContext` / `AnalysisContext` carriers → **Task 3**. The residual carrier's **declaration and population** (`SeedResult` / `FunctionSeed`, `taint_for`'s fourth arm, and soundness condition 1's configured-source preservation) → **Task 7**. **`WLN-ENGINE-UNREADABLE-MARKER-VALUE`** itself — the `pipeline.py` emission loop, the fingerprint (built with the **shipped `pipeline._fp` join-and-digest helper — no new helper**, with NFC-normalise-and-truncate applied to the unparsed-value-text part at the call site, spec §4.2.1 condition 4), and **soundness conditions 2, 3 and 4** → **Task 8**. Three further obligations that had no owning task at rev 3.5 and now do, each with its path on the owning task's Files list: **`test_form5_agreement`**, P9's both-sides receipt → **Task 8 Step 7**, the first commit at which the census and the FACT both exist and therefore the first at which the receipt can be green over both readers; the **all-rules `examples_clean` guard** — that no registered rule's clean exemplar emits `WLN-ENGINE-UNREADABLE-MARKER-VALUE`, asserted over ALL kinds rather than the shipped meta test's `Kind.DEFECT` filter — → **Task 8 Step 8**, which is the assertion **Task 2 Step 3** delegates to "the task that ships that FACT"; and **PRD-0003 criterion 1's exit-code repros** → **Task 6 Step 7** (hole 1) and **Task 8 Step 9** (hole 3), each committed by its own task's commit step, because Final verification reads those artifacts and has no commit step of its own. The seventh `decorator_coverage` summary key, which is soundness condition 5 → **Task 9**, inside its single already-sanctioned re-freeze (not a third one). The additive amendment to `tests/grammar/test_unprovable_boundary.py`'s `test_unprovable_builtin_emits_no_fact` (:72) → **Task 8**; the amendment to `tests/grammar/test_provider_loop.py`'s `test_unprovable_builtin_does_not_signal` (:111) → **split across Task 5 and Task 7, with the path on BOTH Files lists**: **Task 5 Step 1** takes the census-carrying `SeedContext` and the two surviving assertions, because that test hands the provider a bare `Name` in a LEVEL slot with no census and therefore goes red at the commit that makes the census a required reader input; **Task 7 Step 4.6** takes the `res.unreadable_level_values` assertion, because the field it reads is declared in Task 7 and a single-task fix would `AttributeError` at Task 5. Neither amendment is part of Task 5's *shape* work, and neither belongs to the fixture-migration task: both existing absence assertions are things revision 6 *requires* (a builtin unreadable LEVEL value never takes `WLN-ENGINE-UNPROVABLE-BOUNDARY` and never enters `unprovable_boundaries`), so they are kept, their "stays silent (no FACT)" comments corrected, and an assertion on the new channel added. **Spec §4.4 (the Rust recognise-then-parse split, `wardline-b857b50b54`) has NO S0 owner by design** — it is a separately-owned thread closing before G2 is read, and it owns **PRD-0003 criterion 6**, which S0's close does not close. **The "P9 → Task 2" entry above is discharged only once** Task 2's produced interface carries the census and the reference site *and* its CASES table carries spec §12 / §4.2.1's eight form-5 cases driven through the analyser's real construction path; until then that mapping is aspirational, not met, and the coverage map must not be presented as complete. **That hedge is discharged at the S0 close by `wardline-5a795253f1` close condition (v) and its matching Final-verification bullet**, which read P9's receipt back by name — because a whole-suite green cannot distinguish a passing receipt from a receipt nobody wrote.
- NO-GO findings disposition: `to_level` tolerance removed; complete call grammar and cache invalidation added; QE loader/population/per-kind floors made total; custom fingerprints made collision-resistant; waiver usage remains zero under a reviewed ceiling of five; descriptor acceptance made pair-aware; Warpline's non-key-holding role stated accurately; two-sided receipt precedes seam truth-up; and local coordination is separated from published emission readiness.
- Deliberately NOT in S0: any weft-markers export, `REGISTRY_VERSION`/`vocabulary.yaml`/`ATTEST_SCHEMA` changes, attest-3 EMISSION, the declarations inventory factory, per-group inertness arming, and fixes to the two Task 15-filed engine bugs (golden-drifting / semantics-changing — S1+ with their own tickets). **The two re-scoped false-green siblings no longer sit together on this list (owner ruling, 2026-08-10).** `wardline-2b2a6cddfa` (unreadable level value) is **IN S0**: spec revision 6 places P3 form 5 inside Task 2's produced interface and its P9 receipt, so the fix re-cuts S0's own engine core and cannot be additive work alongside a green S0 (spec §4.2.1, §13.2). `wardline-b857b50b54` (Rust marker shape channel) is **not an S0 task and is not deferred either** — it is a separately-owned thread, specified in full by spec §4.4 (different frontend, no coupling to Task 2's reader, zero golden blast radius), which must close **before G2 is read**. Both stay named in `wardline-4928b75782`'s close comment per rev 3.3, and **S0's close does not close PRD-0003 criterion 6**, whose visible owner is §4.4's thread (see the `wardline-5a795253f1` close-criteria bullet in Final verification).
- **Rev 3.4 amendments (2026-08-09).** The rev-3.2 go/no-go review's six pre-merge conditions are folded in: the Task 1 tripwire covers both builtin roots; Task 4's shape validator drops a malformed builtin's seed with PY-WL-130 (ERROR) as the loud channel, and a proposed demotion of that seed to `UNKNOWN_RAW` beside a provable sibling was **evaluated and REJECTED on measurement** — `UNKNOWN_RAW` is in `RAW_ZONE`, `modulate()` returns `NONE` there and PY-WL-101 skips a `RAW_ZONE` declared tier, so demoting silences the very rules the change exists to preserve, whereas dropping the malformed marker and letting the provable one stand is strictly louder than today (pinned by Task 4 Step 1's `test_malformed_sibling_never_reduces_the_error_population`); Task 6 Step 4.2 keeps its plain `taint_for` instruction; PY-WL-130 claims runtime-invalidity only where a `TypeError` is proved from the shipped signatures; PY-WL-130's `examples_clean` no longer freezes the `wardline-2b2a6cddfa` silence into a shipped contract; and Task 17 now READS the generic-3 descriptor's `facets:` section (parse + attribute + non-circular end-to-end proof) rather than accepting-and-ignoring it. At rev 3.4 the governing spec moved to rev 5 and the blob pin was re-cut to `9624f8925a006a80677c12eaa0951933d631920f`. That rev-3.4 site inventory was **five**, not three — the rev-3.2 blockquote, the Global Constraints pin bullet, the preflight `git hash-object` check, the Task-dependency-order line, and Task 18 Step 2's recheck instruction. The last two are prose references to "the rev-N pin" rather than literal hashes, which is exactly why an inventory built by grepping the hash missed them; grep the revision word as well as the digest. **Superseded at rev 3.5, again at rev 3.6 and again at rev 3.7 and later:** the governing spec is **revision 10**; blob `f4ba87c488778f2c315de1944818db12707d981f` at commit `aa10dd3d` **is revision 10's** and no re-pin is owed — rev 3.7 recorded it as revision 8's awaiting re-cut, which was corrected after measurement — and `9624f892…` joins `b43aab4b…`, `4956ba3b…` and `0f04eeb1…` as review provenance only. The rev-3.5 inventory is larger again — the go/no-go's condition 12 carries its full target list; the four sites re-pinned inside this consumer/self-review half are — in **live rev-3.5 numbering** — Task 19's accept-and-read bullet, its committed test comment, Task 20 Step 2's recheck instruction, and this record. The rev-3.4 lesson stands and is strengthened: grep the **premise** as well as the revision word and the digest, and treat the spec's supersession list as a floor rather than a closed set. Spec §4.2's reason vocabulary is deliberately left at **eight** values — the two dual-form reasons are split by offender token, not by minting new reasons, so no consumer's closed reason vocabulary widens. `wardline-b857b50b54` (Rust marker shape channel) and `wardline-2b2a6cddfa` (unreadable level value, lone or stacked) were recorded at rev 3.4 as out-of-S0 residue. **Rev 3.5 supersedes that framing (owner ruling, 2026-08-10):** `wardline-2b2a6cddfa` is **in S0**, closed by spec §4.2.1's form 5 together with the `WLN-ENGINE-UNREADABLE-MARKER-VALUE` residual FACT, and `wardline-b857b50b54` is a **separately-owned thread** under spec §4.4 that closes before G2 is read — out of S0, but not deferred, and the owner of PRD-0003 criterion 6.
