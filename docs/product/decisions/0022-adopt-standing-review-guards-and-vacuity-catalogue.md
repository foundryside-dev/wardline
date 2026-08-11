# PDR-0022 — Adopt the standing review guards and the vacuity catalogue as durable process

`Date: 2026-08-11` · `Status: ACCEPTED` · `Decided by: John (owner, three directives in session)`
· `Bet: cross-cutting — affects every bet's delivery` · `Metric: G1/G2 indirectly (defect escape
rate), not directly instrumented`

## Context

S0's execution surfaced a defect class the programme kept re-encountering: **a passing test suite
actively concealing a defect.** By this checkpoint the run had found **twelve tests that assert
nothing**, including two that were the very obligations a prior task had been dispatched to close,
and one that **certified a live collision as required behaviour**.

The pattern behind almost all of them was the same, and it survived increasingly careful review:
*a table is complete for what its author imagined and blind to whatever every row assumed.*
Instances measured: stability compared only fresh processes; cost measured on a module reference,
never a class; no row covered reordering; every fixture instantiated the class inside the function;
every fixture assigned `__module__`; a 48-row cross-product exercised two code paths.

## Decision

Three standing directives from the owner, adopted as durable process:

1. **A 5-round guard.** At every five-round boundary in a fix loop, dispatch an **independent**
   assessor — neither the implementer nor the round reviewer — to judge whether iteration is still
   buying anything. Its verdict is *a guide, not a gate*; the orchestrator still decides, and the
   verdict is logged either way.
2. **Evidence-based stopping, not count-based.** Continue while a round finds a live defect on an
   ordinary shape, measured. Stop when rounds find only exotic shapes, restatements of known
   residuals, or defects the previous round's own fix introduced.
3. **A living catalogue.** Capture each new *class* of failure in a durable artifact, with the
   measurement that found it. Shipped as **`.claude/skills/reviewing-for-vacuity/`**, at project
   scope, and extended five times during this session as new classes emerged.

## Alternatives considered

- **A fixed round cap.** Simple, and what was originally in place. Rejected on evidence: the cap
  would have stopped Task 13 with **four live collisions still open**.
- **Trust the assessor's verdict as a gate.** Rejected because it failed once, informatively: an
  assessor reasoning from the *pattern of findings* cannot see a defect nobody has looked for yet.
  Its STOP was overturned within hours by a parallel audit using unused angles. The lesson is in
  the catalogue — *change the method before concluding the search is exhausted.*
- **Leave the heuristics in review transcripts.** Rejected: the SDD workspace holding them is
  deleted at plan close, so they would not survive the work that produced them.

## Reversal trigger

Reconsider if the catalogue stops earning its place — specifically, if two consecutive review
cycles produce **no** finding attributable to one of its entries, suggesting it has become
ceremony. Track that qualitatively; it is not instrumented and should not pretend to be.

## Consequences

- The catalogue is already **transferring rather than being followed mechanically**: a verifier
  used it to find a collision in a different component within hours of it being written; a Task 14
  implementer declined, unprompted, to pin a live defect as expected behaviour, citing the entry;
  and reviewers now refute as often as they confirm.
- The 5-round guard and the stopping rule are also saved to project memory
  (`feedback_review_loop_guards`), because the ledger they were derived from is deleted at plan
  close.
- **The catalogue is version-controlled, despite living under `.claude/`.** That directory is
  otherwise ignored as local tooling config, so the skill is re-included by an explicit
  `.gitignore` negation (`.claude/skills/*` + `!.claude/skills/reviewing-for-vacuity/`). Every
  other skill under `.claude/skills/` is tool-installed by `filigree`/`loomweave`/`wardline` and
  stays ignored. Without this the catalogue would survive plan close but not a fresh clone —
  which is the same failure mode that ruled out leaving the heuristics in review transcripts.
- Standing cost: an independent assessor per five rounds, plus catalogue maintenance. Accepted by
  the owner explicitly — *"the capability is important"*.
- **A process failure this session belongs on the record.** A subagent ran `git checkout` and
  destroyed its own uncommitted work. The cause was mine: across ~20 dispatches I used an
  enumerated prohibition, then **shortened it for a task I judged small** — and that is the one
  that broke. Low-risk tasks are where the prohibition gets trimmed, so they are where it fails.
  Recorded in `feedback_subagent_git_prompt_strength`; enumerated form restored.

Related: [PDR-0021], `.claude/skills/reviewing-for-vacuity/SKILL.md`,
memory `feedback_review_loop_guards`, `feedback_subagent_git_prompt_strength`.
