# Plan Review: CHANGES_REQUESTED

**Plan:** `docs/superpowers/plans/2026-08-09-s0-hardening-and-consumer-prep.md`
**Reviewed:** 2026-08-09
**Reviewers:** Reality, Architecture, Quality, Systems
**Synthesizer verdict:** `CHANGES_REQUESTED` — 7 blocking items (3 plan-text defects, 2 orchestrator pre-flight actions, 2 scope decisions)

---

## Executive Summary

The plan is **structurally sound and unusually well-grounded** — Reality verified >90% of ~150 file:line
citations byte-exact with no hallucinated symbols in the core engine surface, and Architecture found
no blocking pattern/complexity/debt issues. The verdict is `CHANGES_REQUESTED` not because the plan is
wrong-headed but because **four cheap, mechanical plan-text defects will burn subagent time**, **two
zero-cost coordination actions must happen before any task starts**, and **two scope questions are
John's to answer, not a subagent's**.

Nothing here requires re-designing S0. Estimated remediation: ~30 minutes of plan-text edits plus two
decisions.

**Execution is not fully blocked.** Tasks **7, 9, 12, 13, 14** carry zero findings from any reviewer
and can execute as literally written today (after pre-flight). The two scope decisions gate only
Tasks 3 and 15–18 respectively — they are a parallel track, not a full stop.

---

## Ordering: Priority Score ≠ Execution Order

The priority scores below rank *how much damage an item can do*. They do **not** give execution
sequence. Two blockers (B2, B6) score 12 and 6 respectively yet must be the *first* actions taken —
a race you prevent after it has fired is not prevented. Follow this spine:

```
1. (c) Orchestrator pre-flight   — B6, B2        [minutes, zero cost]
2. (b) Scope decisions           — B1, B7, D3    [John only]
3. (a) Plan-text patches         — B3, B4, B5 + warning-tier patches
4.     Execute                   — Tasks 7/9/12/13/14 can start after step 1
```

Note also that the formula ranks speculative-but-irreversible items (B1, B2 @ 12) above
certain-but-cheap ones (B3, B4 @ 9). That is the reversibility term working as designed — B3 will
*definitely* stop Task 18 dead, it is simply trivial to fix once noticed.

---

## Blocking Issues (7) — Must Resolve Before Execution

### B1 — Consumer-first vectors frozen against a spec still in P0 re-review
**Score 12** · Systems (blocking) + Architecture (one-way door, medium) · **Gates Tasks 15–18 only**

Tasks 15–17 hand-author a generic-3 fixture and attest-3 vector and pin consumer tests to them. Every
one of those tests validates the hand-authored artifact's *internal consistency only*. There is no
round-trip test against the eventual real S1 producer, and no mechanism enforcing byte-for-byte
agreement. If P0 re-review changes field names, nesting, the `verification_class` enum, or the
`declarations` shape, **two consumer repos ship green tests pinned to fiction** and nothing fails
until someone hand-diffs S1's real output.

**Recommended default:** Systems' option (a) — land the vectors labelled DRAFT/non-normative with a
spec-section checksum tripwire — **plus** Architecture's complement: make the *first* acceptance gate
of the S1 plan a round-trip byte-diff of hand-authored vector vs. real serializer. This keeps the
dual-accept mechanism (which is genuinely safe now) moving without pretending the bytes are settled.
Option (b) — defer byte-exact vectors entirely, land only dual-accept — is the conservative fallback
if John expects material P0 churn.

**If undecided:** Tasks 15–18 hold. Tasks 1–14 are unaffected.

### B2 — Shared-tree hazard: all three cross-repo targets have multiple active worktrees
**Score 12** · Systems · **Pre-flight** · **Gates Tasks 15–18**

loomweave (`chore/changelog-1.5.0`, `main`, `worktree-agent-a95b9655127cc130b` possibly live),
warpline (`c20`, `codex-c17-overflow-contract`), legis (`c20`, `plainweave-doctor-binding`,
`seam-debt`). `git status` in the primary checkout sees none of this. Combined with the project's
never-stash policy and its documented pre-commit shared-checkout race history, a subagent editing the
wrong checkout can destroy another agent's uncommitted work.

**Action:** enumerate worktrees (`git worktree list`) and liveness-check each of the three repos
before Tasks 15–18; record which checkout each task edits.

### B3 — Task 18 (legis) uses fabricated pytest fixtures *and* a wrong function signature
**Score 9** · Reality · **Plan patch**

Two compounding defects: (i) fixtures `base_artifact` / `sign_artifact` have **zero hits in the entire
legis tests/ tree** and there is no `conftest.py` in that directory — the real file drives from the
JSON vector (`VECTOR["valid"][i]["artifact"]`) plus
`from legis.crypto.signing import sign; sign(wardline_artifact_fields(artifact), _KEY)` with the key
from the vector's `signing.key_utf8`; (ii) the plan calls `verify_wardline_artifact(signed)` with one
argument, but the real signature is `verify_wardline_artifact(scan, artifact_key, *, allow_dirty=False)`
— `artifact_key` is required, so the call raises `TypeError` regardless of how (i) is resolved.

**Fix:** rewrite the Task 18 Step 1 sketch against the real vector + `sign()` pattern and the real
three-argument signature.

### B4 — Task 6 breaks four untouched existing `Reconciliation` construction sites
**Score 9** · **Reality + Quality (independently, both mechanically verified)** · **Plan patch**

Task 6 Step 3 adds `active_by_kind` / `fp_by_kind` to the frozen dataclass `Reconciliation` **with no
defaults**. The untouched existing test `test_fp_rate.py::test_reconciliation_fp_rate_arithmetic`
(lines 70–85) constructs `Reconciliation` with 4 positional args, four times → immediate breakage.
`harness.py` imports only `dataclass`, not `field`. Plan Step 5 expects PASS and offers no guidance,
so a subagent hits an unexplained red in a file the plan never mentions.

**Fix:** either add `field(default_factory=dict)` (and the `field` import) or update the four call
sites in the plan text. Also state in Step 5 that this red is expected if defaults are omitted.

### B5 — Task 8 test reads `doc["findings"]`; the real key is `"entries"`
**Score 6** · Reality · **Plan patch**

`build_baseline_document()` (`baseline.py:220-238`) returns key `"entries"`. The plan's own caveat
covers the inner entry *shape* only, not the wrong outer key. One-line fix — but see **WA**: Task 8's
soft STOP gate ("adjust key extraction if needed") gives a pressure-to-green subagent licence to
misclassify a genuine ordering regression as this extraction mismatch. Fix the key *and* harden the
gate together.

### B6 — Filigree ticket `wardline-4928b75782` is unclaimed; concurrent-agent race
**Score 6** · Systems · **Pre-flight — this is action #1**

`wardline-4928b75782` is `status=triage`, P1, unblocked, on the critical path;
`wardline-5a795253f1` is `is_ready:false` blocked by it. Any concurrent agent running
`start-next-work` can legitimately claim it and independently build the same fix Tasks 3–4 deliver,
on the same files. Cost of prevention is one command; cost of collision is duplicated work on shared
files plus a merge no one planned.

**Action:** claim `wardline-4928b75782` atomically (`work_start` / `start-work`) before Task 1.

### B7 — PY-WL-130 detects "too much" but never "too little" (required-kwarg-missing false green)
**Score 6** · Quality (blocking-tier) · **Scope decision** · **Gates Task 3's acceptance criteria**

`@trust_boundary()` — a bare call with the required `to_level` omitted (`LevelArg default=None` =
required) — makes `_read_level` return `None`, the seed is silently dropped, and **zero diagnostics
are emitted**. That is precisely the false-green shape `wardline-4928b75782` names, arriving via
omission instead of malformation. `RegistryEntry.kwargs` / `ArgKind` (Task 1) carries no "required"
concept; that lives only in `BoundaryType.level_args[].default`, and Task 3 never reconciles the two
models. `@trusted()` is safe only incidentally (its level defaults to `INTEGRAL`).

Repo policy is that preview gates like stable, so there is **no soft-launch window** in which to
retrofit this later without opening a second false-green window.

**Recommended default:** option (b) — scope it out explicitly, with a follow-up filigree ticket and a
changelog caveat naming the uncovered shape. Rationale: option (a) means threading "required" through
the registry model, which is real scope growth inside a hardening sprint, and Quality's grep found
**zero occurrences of bare `trust_boundary()` anywhere in the repo** — exposure today is nil. But this
is John's call, because shipping a rule that closes half of its own named bug class is a product
decision, not an engineering one.

**If undecided:** Task 3's acceptance criteria are unsettled and Task 1's `ArgKind` shape may need a
"required" concept. Tasks 2, 7, 9, 12, 13, 14 are unaffected.

---

## Scope Decisions for John (3)

| # | Decision | Recommended default | Blocks if undecided |
|---|----------|--------------------|---------------------|
| D1 | **B1** — hand-authored vectors vs. in-review spec | DRAFT-label + spec checksum tripwire, + S1 round-trip byte-diff as S1's first gate | Tasks 15–18 only |
| D2 | **B7** — required-kwarg false-green gap | Scope out with follow-up ticket + changelog caveat | Task 3 acceptance; Task 1 shape |
| D3 | **unknown-marker × `--fail-on-inert`** (see W-H) | Pin as a named decision + add the test to Task 4 | Task 11's completeness only |

**D3 detail:** an all-new-vocabulary tree scanned by an old wardline emits `WLN-ENGINE-UNKNOWN-MARKER`
FACTs *and* trips the inert gate (unknown seeds are not in `("anchored","config")`). Systems flags
this as plausibly intended UX but currently unstated and untested. It needs to be a pinned decision
with a test, not an emergent behaviour.

---

## Orchestrator Pre-Flight (do these before Task 1)

1. **Claim `wardline-4928b75782`** atomically. Note `wardline-5a795253f1` unblocks behind it. *(B6)*
2. **Enumerate + liveness-check worktrees** in loomweave, warpline, legis; record the target checkout
   per cross-repo task. *(B2)*
3. **Re-verify line anchors if HEAD has moved** past `ed7bfe86` — all citations were captured against
   that commit, and this repo has a documented line-anchor-rot failure class
   (`test_glossary_vocabulary.py` exists for exactly this reason). *(W-L)*
4. **State the dirty-tree rule in the runbook:** a Task 6 mid-flight STOP leaves `harness.py` dirty on
   `release/1.5.0` with Tasks 1–5 already committed. `tests/` is not packaged into the wheel (an
   unstated safety property that should be stated), and the never-stash policy makes
   *leave-dirty-and-wait* the only sanctioned default. *(W-K)*
5. **Issue stop-condition discipline** to every subagent (synthesis of Reality + Quality + Systems):
   an unanticipated red in a file the plan does not mention is a **STOP-and-report**, not a
   self-authorised fix and not automatically the plan's declared stop-condition. Two known instances
   already: B4's `test_fp_rate.py`, and the provider-direct positional-arg snippets in
   `test_decorator_provider.py` (W-M).

---

## Plan-Text Patches Required Before Handoff

| Task | Patch | Source |
|------|-------|--------|
| 18 | Rewrite Step 1 on the real JSON vector + `sign()` + three-arg `verify_wardline_artifact` | B3 |
| 6 | `field(default_factory=dict)` + `field` import, **or** update the four 4-arg call sites; note expected red in Step 5 | B4 |
| 8 | `doc["findings"]` → `doc["entries"]`; replace "adjust key extraction if needed" with a concrete disambiguation step | B5, W-A |
| 5 | Citation `mcp/server.py:3185-3193` → `3018-3030` (3185-3193 is an unrelated `rows.items` tail) | W-F |
| 15 | Replace placeholder `...` test bodies with real assertions (a pasted `...` is a vacuous always-pass); drop the non-existent `_project_with_descriptor` helper reference | W-C, W-J |
| 4 | Disambiguate the two same-named `_fp` helpers — `pipeline.py:32` local `_fp(*parts)` (positional, **correct as written**) vs. keyword-only `finding.compute_finding_fingerprint` | W-G |
| 2 | Repoint `contradictory_trust.py:30`'s `_is_builtin_decorator_fqn` import to `marker_reader`; extract `resolve_alias_map()` into `marker_reader.py` | W-E, W-D |
| 3 | Tighten "no existing fixture" to "no *golden-corpus* fixture"; add an explicit comment that omitting `maturity=` is correct (`RuleMetadata` defaults to `Maturity.STABLE`) | W-M, W-R |
| 5 | Deduplicate `-k coverage ... -k coverage` (pytest `-k` is store-last-wins/global; works today only because every relevant test name contains "coverage") | W-P |
| 6 | Remove `cd tests &&` or add a `cd` back — cwd persists between calls and Step 6 / Tasks 7+ use repo-root-relative paths | W-N |
| 10 | Note that inline `WardlineAnalyzer(boundary_types=...)` is not the real constructor; the plan's own pointer to `test_unprovable_boundary.py`'s `build_analyzer(grammar=...)` is the pattern to follow | W-Q |
| 17, 16 | Cosmetic: line-277 is a malformed-bundle case, not attest-1; the Task 16 vector's posture sub-object omits 3 keys `ResolutionPosture.to_dict()` always emits (harmless, vector is self-labelled representative) | W-R |

---

## Warnings (should fix, non-blocking)

| ID | Issue | Score | Source |
|----|-------|-------|--------|
| W-A | Task 8's soft STOP gate lets a pressure-to-green subagent reclassify a real ordering regression as a key-extraction mismatch | 6 | Quality + synthesis |
| W-B | FP validation for a new **ERROR / STABLE / gate-affecting** rule rests entirely on an author-written corpus — no organically-written consumer code exists anywhere to smoke against | 6 | Quality + Systems |
| W-C | Task 15 placeholder `...` bodies → vacuous always-pass if pasted | 6 | Reality |
| W-D | qualname→alias_map loop duplicated verbatim (`invalid_decorator_level.py:140-144` → `malformed_marker_call.py`); spec predicts a 3rd/4th copy in S2/S3 | 6 | Architecture |
| W-E | `contradictory_trust.py` (PY-WL-110) keeps working via a private transitive re-export, silently defeating "every validation rule reads through these primitives" and staying outside the agreement suite | 4 | Architecture |
| W-F | Task 5 wrong line citation | 4 | Reality |
| W-G | Two same-named `_fp` helpers never disambiguated | 4 | Reality |
| W-H | unknown-marker × `--fail-on-inert` interaction unstated and untested → see **D3** | 4 | Systems |
| W-I | Task 3 test gaps: async/method shapes, non-dict `**splat` / non-string keys, stacked-same-marker, **`offence_ordinal` 0/1 ordering unpinned** (determinism), star-import FN documented-not-tested | 4 | Quality |
| W-J | Task 15 references a non-existent `_project_with_descriptor` helper (real skew test inlines its setup) | 4 | Reality |
| W-K | Task 6 mid-flight STOP leaves the tree dirty; safety property (`tests/` not in wheel) and leave-dirty-and-wait default both unstated | 4 | Systems |
| W-L | No line-anchor tripwire for prose/doc steps (Task 16 Step 5 contract doc, `seam_registry.json`), unlike TDD-covered code | 4 | Systems |
| W-M | Task 3's "no existing fixture" is true for the golden corpus but imprecise as a blanket claim — `test_decorator_provider.py` has two positional-arg snippets exercised provider-directly and may go red | 4 | Systems + synthesis |
| W-N | Task 6 `cd tests &&` cwd drift | 2 | Quality |
| W-O | No wardline-side symmetric CI check that consumers shipped dual-accept before a future version bump (loomweave checks its own bounds; nothing checks outward) | 4 | Systems |
| W-P | Task 5 duplicate `-k coverage` (last-wins) | 1 | Quality |
| W-Q | Task 10 inline constructor kwarg mismatch (self-correcting) | 2 | Reality |
| W-R | Cosmetics: Task 17 line-277 mislabel, Task 16 posture keys, Task 3 maturity comment | 1 | Reality |

---

## Recommendations (consider — not required for S0)

- **[S1 gate]** Make the S1 plan's *first* acceptance gate a round-trip byte-diff of the hand-authored
  vectors against the real serializer. This is the mechanism that retires B1's one-way door. *(Architecture)*
- **[Refactor]** Extract `resolve_alias_map()` into `marker_reader.py` during Task 2 — it is the
  helper's stated home and prevents the predicted 3rd/4th copy. *(Architecture)*
- **[Determinism]** Pin `offence_ordinal` ordering for multi-offence-in-one-call. *(Quality)*
- **[Observability]** Decide whether `WLN-ENGINE-UNKNOWN-MARKER` should surface in `agent_summary` /
  dossier — currently unaddressed in either direction. *(Quality)*
- **[Low]** `ArgKind.TOKEN_SET` / `REF` have zero S0 consumers — justified by spec §13.2, noted only.
  Private-name pins (`_MIN_FUNCTIONS` et al.) are brittle-but-loud. *(Architecture)*

---

## Out of Scope (identified, not for this plan)

- Symmetric wardline-side consumer-compatibility CI check (W-O) — belongs with the version-bump work.
- Threading a "required" concept through `RegistryEntry` / `ArgKind` — only if D2 resolves toward
  option (a).

---

## Conflicts Resolved

| # | Conflict | Resolution |
|---|----------|------------|
| C1 | **Reconciliation break** — Reality: BLOCKING; Quality: BLOCKING-class but "self-correcting at execution"; Architecture/Systems silent | **BLOCKING.** Higher severity wins, and two reviewers verified it mechanically and independently. "Self-correcting" understates it: the red lands in a file the plan never names, which is exactly the shape a subagent misdiagnoses. |
| C2 | **Hand-authored vectors** — Architecture: one-way door, *no blocking*, mitigate in S1; Systems: BLOCKING, defer or DRAFT-label | **BLOCKING (as a decision).** Not actually contradictory — different axes. Architecture judged the *mechanism* sound (true: the split is minimal, the dual-accept is safe). Systems judged the *timing* unsound and holds the decisive fact Architecture did not weigh: the spec is still in P0 re-review. Conservative path adopts **both** mitigations. |
| C3 | **Blocking count** — Architecture: 0; Reality: 4; Systems: 3; Quality: 2 | **No genuine conflict.** Architecture's lane (patterns, complexity, debt, blast radius) legitimately contains no blockers. Every blocker lives in another lane: symbol reality, process state, or timing. Architecture's "no blocking" is not overridden — it is scoped. |
| C4 | **Task 3 "no existing fixture"** — Architecture: verified structurally true; Systems: false, provider-direct snippets exist | **Both correct at different scopes.** True for the golden corpus (Architecture's verification target), imprecise as a blanket statement (Systems' target). Resolution: tighten the wording *and* pre-warn the subagent those snippets may go red (W-M). |
| C5 | **PY-WL-130 consumer risk** — Quality: FP validation unvalidated, HIGH concern; Systems: blast radius near-zero, defused by evidence | **Both survive; the same fact cuts both ways.** Zero `wardline.decorators` usage across all four sibling repos genuinely defuses *deployment* blast radius — but it is also precisely *why* no organic FP evidence can exist. Kept as warning W-B, not a blocker. (elspeth's 731 `trust_boundary` hits are its own unrelated `elspeth_lints` decorator — a human-level name-collision risk only, correctly outside FACT scope.) |

---

## Execute-Ready Task Partition

Computed as the **intersection across all four reviewers**, not from any single lane:

| Bucket | Tasks | Condition |
|--------|-------|-----------|
| **Execute as literally written** | **7, 9, 12, 13, 14** | After pre-flight only |
| Ready once D2 resolves | 1 | `ArgKind` may need a "required" concept |
| Ready once D3 resolves | 11 | Inert-interaction test placement |
| Needs plan-text patch | 2, 3, 4, 5, 6, 8, 10 | See patch table |
| Needs D1 + B2 pre-flight | 15, 16, 17, 18 | Cross-repo; 18 also needs a rewrite |

> **Caution:** do not publish Reality's clean list (1, 2, 4, 7, 9, 11–14) as execute-ready. Architecture
> removes Task 2 (two findings), Reality's own `_fp` note removes Task 4, Systems' inert test touches
> Task 11, and D2 touches Task 1.

---

## Reviewer Summaries

| Reviewer | Status | Blocking | Warnings | Self-reported confidence |
|----------|--------|----------|----------|--------------------------|
| Reality | ISSUES_FOUND | 3 (+1 moderate) | 7 | High |
| Architecture | PASS_WITH_FINDINGS | 0 | 2 medium + 2 low | High |
| Quality | ISSUES_FOUND | 2 | ~6 | Moderate–High → recorded **Moderate** |
| Systems | ISSUES_FOUND | 3 | 4 | Moderate–High → recorded **Moderate** |

**Per-reviewer counts do not sum to the 7 consolidated blockers** — B4 is a Reality + Quality
duplicate, and B1 merges Systems' blocker with Architecture's lower-severity one-way-door finding.

---

## Confidence Assessment

**Overall Confidence: High.** The verdict is over-determined: three mechanically-verified plan-text
defects (one confirmed independently by two reviewers) force `CHANGES_REQUESTED` on their own, before
any judgment call is weighed. This is not averaging upward past two Moderate self-reports — the
Moderate signal attaches to the *timing and scope judgments* (B1, B7), which are shown at their own
confidence per row.

| Finding | Confidence | Basis |
|---------|-----------|-------|
| B3 (legis fixtures + signature) | High | Reality: zero fixture hits in the whole tests/ tree; real signature read directly |
| B4 (Reconciliation) | High | Reality **and** Quality, independently, both mechanically verified against `test_fp_rate.py:70-85` |
| B5 (findings→entries) | High | Reality: `baseline.py:220-238` returns `"entries"` |
| B6 (filigree race) | High | Systems read live ticket state (`triage`, unclaimed, P1) |
| B2 (worktrees) | High | Systems enumerated worktrees in all three repos |
| B1 (vectors vs. spec) | **Moderate** | Depends on unobservable P0 re-review outcome; the *mechanism* is verified sound (Architecture), only the *timing* is at risk |
| B7 (required-kwarg gap) | High on the gap, **Moderate** on severity | Quality traced `LevelArg default=None` → `_read_level` → dropped seed; severity depends on future organic usage, currently zero |
| W-B (FP corpus) | Moderate | Corroborated from both sides — Quality (no smoke corpus) and Systems (zero consumer usage, by grep) |

---

## Risk Assessment

**Implementation Risk: High** (max across blockers, as of this review, with B1/B2/B6 unaddressed).
Drops to **Medium** once pre-flight completes and the plan-text patches land — which matches the
reviewers' own post-mitigation reads (Reality: Medium; Architecture: Low–Medium; Quality: Medium–High;
Systems: Medium, "High if blockers 1–2 unaddressed").

**Reversibility: Difficult** (worst across blockers — Tasks 15–18 require a coordinated multi-repo
correction if the vectors are wrong). Tasks 1–14 are individually Easy to reverse.

| Risk | Severity | Likelihood | Mitigation |
|------|----------|-----------|------------|
| Two consumer repos ship green tests pinned to a superseded schema | High | Likely | D1: DRAFT-label + checksum tripwire, **or** defer vectors and land dual-accept only; S1 round-trip gate |
| Subagent edits the wrong worktree, destroying another agent's uncommitted work | High | Likely | Enumerate + liveness-check worktrees; never-stash discipline restated |
| Task 18 cannot execute at all (TypeError + non-existent fixtures) | High | Certain | Rewrite Step 1 before handoff |
| Unexplained red in `test_fp_rate.py` misdiagnosed as a stop-condition | High | Certain | Add defaults or update call sites; state expected red |
| Concurrent agent duplicates the Tasks 3–4 fix on the same files | High | Possible | Claim `wardline-4928b75782` first — one command |
| Shipped STABLE ERROR rule closes only half its named false-green class | High | Possible | D2: fix or explicitly scope out with ticket + changelog caveat |
| Subagent talks a real ordering regression green through a soft STOP gate | High | Possible | Concrete disambiguation step in Task 8 + stop-condition discipline |

---

## Information Gaps

Carried forward from all four reviewers, plus one synthesis-specific:

1. [ ] **Reality:** the plan gives subagents no rule for classifying an *unanticipated* red — whether
   it is a stop-condition or a signal to fix. Two known instances already exist (B4, W-M).
2. [ ] **Architecture:** no mechanism currently enforces byte-identity between the hand-authored
   vectors and S1's future serializer. Until S1 defines one, B1's door stays open.
3. [ ] **Quality:** no organically-written consumer code exists anywhere (all four sibling repos have
   zero `wardline.decorators` usage), so FP validation for a new gate-affecting ERROR rule cannot be
   corroborated against real-world code — only against the author's own corpus.
4. [ ] **Quality:** is the FACT's absence from `agent_summary` / dossier deliberate or an oversight?
   Unaddressed in either direction.
5. [ ] **Systems:** worktree liveness in the three consumer repos is unknown from the primary checkout
   — must be observed, not assumed.
6. [ ] **Systems:** is the unknown-marker × `--fail-on-inert` interaction intended UX? Currently
   emergent rather than decided.
7. [ ] **Synthesis:** *no reviewer could estimate the probability that P0 re-review changes the
   artifact schema* — and that probability is the entire tie-break on B1/D1. Only John or the P0
   reviewers can supply it. This is the single most load-bearing unknown in the review.

---

## Caveats & Required Follow-ups

### Before relying on this synthesis
- [ ] Confirm each blocker's resolution actually closes the originating reviewer's finding — in
      particular that the Task 18 rewrite is validated against the real legis source, not re-sketched.
- [ ] Re-run `/review-plan` after revisions; this pass does not carry forward.
- [ ] Have a human ratify C2 (the Architecture/Systems severity split on the vectors) — it is the one
      resolution that materially changes S0's shape.

### Assumptions made
- The priority formula (Severity × Likelihood × Reversibility) reflects this project's risk appetite.
- Reviewer scope boundaries were respected; no reviewer trespassed into another's lane.
- Tasks are executed by subagents **following the plan literally**, which is what converts wrong
  line citations and placeholder `...` bodies from cosmetic into costly.

### Limitations
- **This synthesis does not re-verify reviewer findings.** Per instruction, no repository was read. If
  a reviewer hallucinated, this synthesis inherits it. The mechanically-verified items (B4 especially,
  confirmed twice independently) carry the most weight for that reason.
- Two items are **synthesis-derived**, not raised verbatim by any single reviewer, and are labelled as
  such: the "provider-direct snippets may go red and be misread as a stop-condition" risk (composed
  from Systems' + Reality's facts), and the consolidated stop-condition discipline recommendation.
- Concerns outside the four declared lenses (legal, compliance, accessibility, cost) were not reviewed.

---

## Next Steps

**Status: `CHANGES_REQUESTED`**

1. Orchestrator: claim `wardline-4928b75782`, enumerate cross-repo worktrees.
2. John: decide D1 (vectors) and D2 (required-kwarg gap); pin D3 (`--fail-on-inert`).
3. Patch the plan text per the table above (~30 min).
4. Tasks 7, 9, 12, 13, 14 may begin immediately after step 1.
5. Re-run `/review-plan` on the patched plan.

---

## Machine-Readable Envelope

```json
{
  "verdict": "CHANGES_REQUESTED",
  "summary": "Plan is structurally sound and unusually well-grounded (>90% of ~150 citations byte-exact, no hallucinated core-engine symbols), but carries 7 blocking items: 3 mechanical plan-text defects that will stop or mislead subagents, 2 zero-cost orchestrator pre-flight actions, and 2 scope decisions only John can make. Remediation is ~30 minutes of plan-text edits plus two decisions; no redesign needed. Tasks 7/9/12/13/14 are execute-ready after pre-flight.",
  "plan_file": "docs/superpowers/plans/2026-08-09-s0-hardening-and-consumer-prep.md",
  "reviewed_at": "2026-08-09T00:00:00Z",
  "reviewers": ["reality", "architecture", "quality", "systems"],
  "blocking_issues": [
    {
      "id": "B1",
      "source": "systems + architecture",
      "bucket": "scope_decision",
      "issue": "Consumer-first vectors (generic-3 fixture, attest-3 vector) frozen against a spec still in P0 re-review, with no round-trip test to the eventual real producer",
      "evidence": "Tasks 15-17 validate the hand-authored artifact's internal consistency only; architecture confirms no mechanism enforces byte-for-byte agreement with S1's future serializer",
      "priority_score": 12,
      "severity": 3,
      "likelihood": 2,
      "reversibility": 2,
      "confidence": "Moderate",
      "gates_tasks": [15, 16, 17, 18],
      "resolution": "Recommended: label vectors DRAFT/non-normative with a spec-section checksum tripwire AND make S1's first acceptance gate a round-trip byte-diff. Fallback: defer byte-exact vectors, land only the dual-accept mechanism now."
    },
    {
      "id": "B2",
      "source": "systems",
      "bucket": "preflight",
      "issue": "All three cross-repo targets have multiple active worktrees invisible to the primary checkout's git status",
      "evidence": "loomweave: chore/changelog-1.5.0, main, worktree-agent-a95b9655127cc130b (possibly live); warpline: c20, codex-c17-overflow-contract; legis: c20, plainweave-doctor-binding, seam-debt",
      "priority_score": 12,
      "severity": 3,
      "likelihood": 2,
      "reversibility": 2,
      "confidence": "High",
      "gates_tasks": [15, 16, 17, 18],
      "resolution": "Enumerate worktrees and liveness-check all three repos before Tasks 15-18; record the target checkout per task"
    },
    {
      "id": "B3",
      "source": "reality",
      "bucket": "plan_text_patch",
      "issue": "Task 18 (legis) Step 1 uses fabricated pytest fixtures AND calls verify_wardline_artifact with the wrong arity",
      "evidence": "base_artifact/sign_artifact have zero hits in the entire legis tests/ tree, no conftest.py in that dir; real pattern is VECTOR['valid'][i]['artifact'] + legis.crypto.signing.sign(wardline_artifact_fields(artifact), _KEY); real signature is verify_wardline_artifact(scan, artifact_key, *, allow_dirty=False) - artifact_key required, so the one-arg call raises TypeError regardless",
      "priority_score": 9,
      "severity": 3,
      "likelihood": 3,
      "reversibility": 1,
      "confidence": "High",
      "gates_tasks": [18],
      "resolution": "Rewrite the Task 18 Step 1 sketch against the real JSON vector + sign() pattern and the real three-argument signature"
    },
    {
      "id": "B4",
      "source": "reality + quality",
      "bucket": "plan_text_patch",
      "issue": "Task 6 Step 3 adds active_by_kind/fp_by_kind to the frozen Reconciliation dataclass with no defaults, breaking four untouched existing construction sites",
      "evidence": "test_fp_rate.py::test_reconciliation_fp_rate_arithmetic lines 70-85 constructs Reconciliation with 4 positional args, four times; harness.py imports only 'dataclass', not 'field'; plan Step 5 expects PASS with no guidance",
      "priority_score": 9,
      "severity": 3,
      "likelihood": 3,
      "reversibility": 1,
      "confidence": "High",
      "gates_tasks": [6],
      "resolution": "Add field(default_factory=dict) plus the field import, or update the four call sites in plan text; state the expected red in Step 5",
      "note": "Independently and mechanically confirmed by two reviewers"
    },
    {
      "id": "B5",
      "source": "reality",
      "bucket": "plan_text_patch",
      "issue": "Task 8 test reads doc['findings']; build_baseline_document() returns key 'entries'",
      "evidence": "baseline.py:220-238 returns 'entries'; plan's own caveat covers inner entry shape only, not the outer key",
      "priority_score": 6,
      "severity": 2,
      "likelihood": 3,
      "reversibility": 1,
      "confidence": "High",
      "gates_tasks": [8],
      "resolution": "One-line key fix, applied together with hardening the Task 8 STOP gate (W-A)"
    },
    {
      "id": "B6",
      "source": "systems",
      "bucket": "preflight",
      "issue": "Filigree ticket wardline-4928b75782 is unclaimed (status=triage, P1, unblocked, critical path); a concurrent agent can claim it and duplicate the Tasks 3-4 fix on the same files",
      "evidence": "wardline-5a795253f1 is is_ready:false, blocked by 4928b75782",
      "priority_score": 6,
      "severity": 3,
      "likelihood": 1,
      "reversibility": 2,
      "confidence": "High",
      "gates_tasks": [],
      "resolution": "Claim wardline-4928b75782 atomically (work_start / start-work) as orchestrator action #1, before Task 1"
    },
    {
      "id": "B7",
      "source": "quality",
      "bucket": "scope_decision",
      "issue": "PY-WL-130 detects only 'too much' (extra positional/kwarg/splat), never 'too little' - a bare @trust_boundary() with required to_level omitted silently drops the seed with zero diagnostics",
      "evidence": "LevelArg default=None means required; _read_level returns None; RegistryEntry.kwargs/ArgKind (Task 1) carries no 'required' concept, which lives only in BoundaryType.level_args[].default, and Task 3 never reconciles the two models. @trusted() is safe only because its level defaults to INTEGRAL. Repo policy: preview gates like stable, so no soft-launch retrofit window.",
      "priority_score": 6,
      "severity": 3,
      "likelihood": 1,
      "reversibility": 2,
      "confidence": "High on the gap, Moderate on severity",
      "gates_tasks": [3, 1],
      "resolution": "Recommended: scope out explicitly with a follow-up filigree ticket and a changelog caveat naming the uncovered shape (zero occurrences of bare trust_boundary() exist in the repo today). Alternative: extend _offences() with a required-arg check, which means threading 'required' through the registry - real scope growth. John's call."
    }
  ],
  "scope_decisions": [
    {
      "id": "D1",
      "blocking_ref": "B1",
      "question": "Land hand-authored vectors now against an in-review spec, or defer byte-exact vectors?",
      "recommended_default": "Land DRAFT-labelled with a spec-section checksum tripwire, plus an S1 round-trip byte-diff as S1's first acceptance gate",
      "blocks_if_undecided": [15, 16, 17, 18]
    },
    {
      "id": "D2",
      "blocking_ref": "B7",
      "question": "Close the required-kwarg-missing false-green in S0, or scope it out?",
      "recommended_default": "Scope out with follow-up ticket + changelog caveat",
      "blocks_if_undecided": [3, 1]
    },
    {
      "id": "D3",
      "blocking_ref": "W-H",
      "question": "Is emitting WLN-ENGINE-UNKNOWN-MARKER FACTs AND tripping the inert gate on an all-new-vocabulary tree the intended UX?",
      "recommended_default": "Pin as a named decision and add the test to Task 4",
      "blocks_if_undecided": [11]
    }
  ],
  "preflight_actions": [
    "Claim filigree wardline-4928b75782 atomically before Task 1 (B6)",
    "Enumerate and liveness-check worktrees in loomweave, warpline, legis; record target checkout per cross-repo task (B2)",
    "Re-verify line anchors if HEAD moved past ed7bfe86 - documented line-anchor-rot failure class in this repo (W-L)",
    "State the dirty-tree rule: Task 6 mid-flight STOP leaves harness.py dirty on release/1.5.0; tests/ is not packaged into the wheel; never-stash makes leave-dirty-and-wait the only sanctioned default (W-K)",
    "Issue stop-condition discipline: an unanticipated red in an unmentioned file is STOP-and-report, not a self-authorised fix (synthesis: systems + reality)"
  ],
  "execute_ready_tasks": [7, 9, 12, 13, 14],
  "task_partition": {
    "execute_as_written": [7, 9, 12, 13, 14],
    "ready_once_D2_resolves": [1],
    "ready_once_D3_resolves": [11],
    "needs_plan_text_patch": [2, 3, 4, 5, 6, 8, 10],
    "needs_D1_and_worktree_preflight": [15, 16, 17, 18]
  },
  "warnings": [
    {"id": "W-A", "source": "quality + synthesis", "issue": "Task 8 soft STOP gate ('adjust key extraction if needed') lets a pressure-to-green subagent reclassify a real ordering regression", "priority_score": 6, "recommendation": "Replace with a concrete disambiguation step"},
    {"id": "W-B", "source": "quality + systems", "issue": "FP validation for a new ERROR/STABLE gate-affecting rule rests entirely on an author-written corpus; no organically-written consumer code exists in any of the four sibling repos", "priority_score": 6, "recommendation": "Accept knowingly, or construct an adversarial corpus"},
    {"id": "W-C", "source": "reality", "issue": "Task 15 placeholder test bodies are a literal '...' - vacuous always-pass if pasted", "priority_score": 6, "recommendation": "Write real assertions into the plan"},
    {"id": "W-D", "source": "architecture", "issue": "qualname->alias_map loop duplicated verbatim from invalid_decorator_level.py:140-144 into malformed_marker_call.py; spec predicts a 3rd/4th copy in S2/S3", "priority_score": 6, "recommendation": "Extract resolve_alias_map() into marker_reader.py during Task 2"},
    {"id": "W-E", "source": "architecture", "issue": "contradictory_trust.py:30 keeps importing _is_builtin_decorator_fqn via a private transitive re-export, silently defeating 'every validation rule reads through these primitives' and staying outside the agreement suite", "priority_score": 4, "recommendation": "One-line repoint to marker_reader in Task 2 Step 3"},
    {"id": "W-F", "source": "reality", "issue": "Task 5 cites mcp/server.py:3185-3193; the actual summary properties/required block is at 3018-3030 (3185-3193 is an unrelated rows.items tail)", "priority_score": 4, "recommendation": "Correct the citation"},
    {"id": "W-G", "source": "reality", "issue": "Two same-named _fp helpers never disambiguated: pipeline.py:32 local _fp(*parts) (positional, correct as written) vs keyword-only finding.compute_finding_fingerprint", "priority_score": 4, "recommendation": "Add a disambiguating note to Task 4"},
    {"id": "W-H", "source": "systems", "issue": "unknown-marker x --fail-on-inert interaction unstated and untested; unknown seeds are not in ('anchored','config') so an all-new-vocab tree both emits FACTs and trips the inert gate", "priority_score": 4, "recommendation": "See D3 - pin the decision and add a test"},
    {"id": "W-I", "source": "quality", "issue": "Task 3 test gaps: async/method shapes, non-dict **splat and non-string keys, stacked same marker, multi-offence ordering (offence_ordinal 0/1 unpinned), star-import FN documented-not-tested", "priority_score": 4, "recommendation": "Pin offence_ordinal ordering at minimum - it is a determinism property"},
    {"id": "W-J", "source": "reality", "issue": "Task 15 references a non-existent _project_with_descriptor helper; the real skew test inlines its setup", "priority_score": 4, "recommendation": "Drop the reference"},
    {"id": "W-K", "source": "systems", "issue": "Task 6 mid-flight STOP leaves harness.py dirty on release/1.5.0 with Tasks 1-5 committed; the safety property (tests/ not packaged into the wheel) and the leave-dirty-and-wait default are both unstated", "priority_score": 4, "recommendation": "State both in the runbook"},
    {"id": "W-L", "source": "systems", "issue": "No line-anchor tripwire for prose/doc steps (Task 16 Step 5 contract doc, seam_registry.json edits), unlike TDD-covered code; citations captured against ed7bfe86", "priority_score": 4, "recommendation": "Re-verify anchors at pre-flight if HEAD moved"},
    {"id": "W-M", "source": "systems + synthesis", "issue": "Task 3's 'no existing fixture' claim is true for the golden corpus but imprecise as a blanket statement; test_decorator_provider.py has two positional-arg snippets exercised provider-directly which may go red and be misread as a stop-condition", "priority_score": 4, "recommendation": "Tighten wording to 'no golden-corpus fixture' and pre-warn the subagent"},
    {"id": "W-N", "source": "quality", "issue": "Task 6 'cd tests &&' cwd drift; Step 6 and Tasks 7+ use repo-root-relative paths with no cd back, and cwd persists between calls", "priority_score": 2, "recommendation": "Remove the cd or add a cd back"},
    {"id": "W-O", "source": "systems", "issue": "Cross-repo sequencing is prose-only; no wardline-side CI check that consumers shipped dual-accept before a future version bump (loomweave checks its own bounds; nothing checks outward)", "priority_score": 4, "recommendation": "Out of scope for S0 - belongs with the version-bump work"},
    {"id": "W-P", "source": "quality", "issue": "Task 5 verify command has '-k coverage ... -k coverage'; pytest -k is store-last-wins and global, working today only because every relevant test name contains 'coverage'", "priority_score": 1, "recommendation": "Deduplicate; a future rename would silently drop coverage"},
    {"id": "W-Q", "source": "reality", "issue": "Task 10 inline WardlineAnalyzer(boundary_types=...) is not the real constructor; plan self-corrects by pointing at test_unprovable_boundary.py's build_analyzer(grammar=default_grammar().extend(...))", "priority_score": 2, "recommendation": "Note the mismatch so the subagent does not paste the inline form"},
    {"id": "W-R", "source": "reality", "issue": "Cosmetics: Task 17 line-277 mislabeled (malformed-bundle case, not attest-1; both stay green); Task 16 vector's posture sub-object omits 3 keys ResolutionPosture.to_dict() always emits (harmless); Task 3 METADATA omits maturity= but RuleMetadata defaults to Maturity.STABLE (correct by default, worth a comment)", "priority_score": 1, "recommendation": "Fix in the same editing pass"}
  ],
  "recommendations": [
    {"type": "ONE_WAY_DOOR_MITIGATION", "source": "architecture", "suggestion": "Make the S1 plan's first acceptance gate a round-trip byte-diff of hand-authored vectors against the real serializer"},
    {"type": "REFACTOR", "source": "architecture", "suggestion": "Extract resolve_alias_map() into marker_reader.py during Task 2 - its stated purpose, and it prevents the predicted 3rd/4th copy"},
    {"type": "DETERMINISM", "source": "quality", "suggestion": "Pin offence_ordinal ordering for multi-offence-in-one-call"},
    {"type": "OBSERVABILITY", "source": "quality", "suggestion": "Decide whether WLN-ENGINE-UNKNOWN-MARKER surfaces in agent_summary / dossier - currently unaddressed in either direction"},
    {"type": "INFORMATIONAL", "source": "architecture", "suggestion": "ArgKind TOKEN_SET/REF have zero S0 consumers (justified by spec 13.2); private-name pins (_MIN_FUNCTIONS et al.) are brittle-but-loud"}
  ],
  "out_of_scope": [
    "Symmetric wardline-side consumer-compatibility CI check (W-O) - belongs with the version-bump work",
    "Threading a 'required' concept through RegistryEntry/ArgKind - only if D2 resolves toward option (a)"
  ],
  "conflicts_resolved": [
    {
      "issue": "Reconciliation dataclass break severity",
      "reality_view": "BLOCKING",
      "quality_view": "BLOCKING-class but self-correcting at execution via Step 5 red",
      "architecture_view": "not raised",
      "systems_view": "not raised",
      "resolution": "BLOCKING. Higher severity wins and two reviewers verified it mechanically and independently. 'Self-correcting' understates it - the red lands in a file the plan never names, exactly the shape a subagent misdiagnoses."
    },
    {
      "issue": "Hand-authored consumer vectors - one-way door severity",
      "architecture_view": "One-way door, NOT blocking; mitigate via an S1 round-trip gate",
      "systems_view": "BLOCKING; DRAFT-label with checksum tripwire or defer byte-exact vectors",
      "resolution": "BLOCKING as a scope decision. Not contradictory - different axes. Architecture judged the mechanism sound (true); Systems judged the timing unsound and holds the decisive fact Architecture did not weigh: the spec is still in P0 re-review. Conservative path adopts both mitigations."
    },
    {
      "issue": "Blocking count disagreement (architecture 0, reality 4, systems 3, quality 2)",
      "resolution": "No genuine conflict. Architecture's lane (patterns, complexity, debt, blast radius) legitimately contains no blockers; every blocker lives in another lane - symbol reality, process state, or timing. Architecture's finding is scoped, not overridden."
    },
    {
      "issue": "Task 3 'no existing fixture' claim",
      "architecture_view": "Verified structurally true",
      "systems_view": "Imprecise - test_decorator_provider.py has two positional-arg snippets exercised provider-directly",
      "resolution": "Both correct at different scopes. True for the golden corpus, imprecise as a blanket statement. Tighten wording AND pre-warn the subagent those snippets may go red."
    },
    {
      "issue": "PY-WL-130 consumer risk",
      "quality_view": "HIGH concern - FP validation unvalidated against organic code",
      "systems_view": "Blast radius near-zero - zero wardline.decorators imports in all four sibling repos",
      "resolution": "Both survive; the same fact cuts both ways. Zero usage genuinely defuses deployment blast radius but is precisely why no organic FP evidence can exist. Kept as warning W-B, not a blocker. elspeth's 731 trust_boundary hits are its own unrelated elspeth_lints decorator - human-level name-collision risk only, correctly outside FACT scope."
    }
  ],
  "synthesis_derived_items": [
    "W-M's 'provider-direct snippets may go red and be misread as a stop-condition' risk - composed from Systems' + Reality's facts, raised verbatim by neither",
    "The consolidated stop-condition discipline pre-flight action - composed from Reality's, Quality's and Systems' separate observations"
  ],
  "reviewer_summaries": {
    "reality": {"status": "ISSUES_FOUND", "blocking": 3, "moderate": 1, "warnings": 7},
    "architecture": {"status": "PASS_WITH_FINDINGS", "blocking": 0, "warnings": 4},
    "quality": {"status": "ISSUES_FOUND", "blocking": 2, "warnings": 6},
    "systems": {"status": "ISSUES_FOUND", "blocking": 3, "warnings": 4}
  },
  "dedup_note": "Per-reviewer blocking counts do not sum to the 7 consolidated blockers: B4 merges a Reality + Quality duplicate, and B1 merges Systems' blocker with Architecture's lower-severity one-way-door finding.",
  "overall_confidence": "High",
  "implementation_risk": "High",
  "implementation_risk_post_mitigation": "Medium",
  "reversibility": "Difficult",
  "reversibility_tasks_1_14": "Easy",
  "information_gaps": [
    "Reality: the plan gives subagents no rule for classifying an unanticipated red as stop-condition vs fix-and-continue; two known instances already exist (B4, W-M)",
    "Architecture: no mechanism currently enforces byte-identity between hand-authored vectors and S1's future serializer",
    "Quality: no organically-written consumer code exists in any of the four sibling repos, so FP validation for a new gate-affecting ERROR rule cannot be corroborated against real-world code",
    "Quality: is the FACT's absence from agent_summary / dossier deliberate or an oversight? Unaddressed either way",
    "Systems: worktree liveness in the three consumer repos is unknown from the primary checkout - must be observed, not assumed",
    "Systems: is the unknown-marker x --fail-on-inert interaction intended UX, or emergent?",
    "SYNTHESIS: no reviewer could estimate the probability that P0 re-review changes the artifact schema, and that probability is the entire tie-break on B1/D1. Only John or the P0 reviewers can supply it - the most load-bearing unknown in this review."
  ],
  "caveats": [
    "This synthesis did not read the repositories (per instruction) and does not re-verify reviewer findings; if a reviewer hallucinated, the synthesis inherits it",
    "Two items are synthesis-derived rather than raised by any single reviewer and are labelled as such in synthesis_derived_items",
    "Confirm each blocker's resolution actually closes the originating reviewer's finding - in particular that the Task 18 rewrite is validated against real legis source, not re-sketched",
    "Re-run /review-plan after revisions; this pass does not carry forward",
    "Have a human ratify the C2 resolution (Architecture/Systems severity split on the vectors) - it is the one resolution that materially changes S0's shape",
    "Priority scores rank damage potential, not execution order; two of the highest-value actions (B6, B2) score mid-range yet must be executed first",
    "Assumes subagents follow the plan literally, which is what converts wrong line citations and placeholder '...' bodies from cosmetic into costly",
    "Concerns outside the four declared lenses (legal, compliance, accessibility, cost) were not reviewed"
  ],
  "reviewer_confidence_aggregation": {
    "reality": "High",
    "architecture": "High",
    "quality": "Moderate",
    "systems": "Moderate"
  },
  "reviewer_confidence_note": "Quality and Systems both self-reported 'Moderate-High'; recorded as Moderate to stay within the enum. Overall confidence remains High because the verdict is over-determined by three mechanically-verified plan-text defects independent of any Moderate-confidence judgment call."
}
```
