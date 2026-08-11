---
name: reviewing-for-vacuity
description: Adversarial review heuristics for finding defects that a passing test suite is actively hiding — vacuous tests, shared assumptions across a test table, untested compositions, guards that disable themselves, fixes that swing one direction while breaking the other, and evidence artifacts that lie. Use this whenever reviewing code, reviewing tests, verifying that a fix actually works, or writing the prompt that dispatches a reviewer — and especially when a change comes with a green suite and a confident report, because that is exactly the condition these failures survive. Also use when a fix loop keeps finding "one more adjacent case" round after round, or when deciding whether a review has genuinely converged or merely exhausted one reviewer's imagination.
---

# Reviewing for vacuity

Most review advice tells you how to find bugs in code. This is about the harder case:
**defects that a passing test suite is actively concealing**, and the review habits that
surface them.

Every failure mode below was measured during one hardening programme on a static analyser's
cache key. That programme ran nine serial review rounds, an eleven-agent parallel audit, and
found twelve tests that asserted nothing — including two that certified a defect as required
behaviour. The specific examples are kept because concrete beats abstract; the shapes
generalise.

## The one question

If you take nothing else: when you look at a table of test cases, do not ask *what does each
row assert*. Ask:

> **What does every row assume?**

That question, asked once, would have caught four of the five worst misses in the source
programme. A test table is complete for what its author imagined and blind to whatever they
took for granted. The defect lives in the thing no row varies.

Worked examples of what "every row assumed" turned out to be:

- every stability check compared **fresh processes**, so a digest that mutated the object
  graph it hashed — two calls in one process disagreeing — was invisible for three rounds;
- every cost measurement used a **module** reference, never a **class** reference, hiding a
  3.2× blow-up;
- no row covered **reordering**, so swapping two dict keys silently changed behaviour;
- every row instantiated a class **inside** the function under test, so hoisting the
  instantiation to module scope escaped the whole table;
- a table with eight rows exercised **two** code paths, because seven fixtures shared one
  attribute.

## The failure catalogue

Each of these is a thing to go looking for, not a thing to notice by luck.

### 1. The test that cannot fail

A pin that passes whether or not the behaviour it names is present. Detection is mechanical
and non-negotiable: **break the behaviour and confirm the test goes red.** If you did not run
the mutation, you have not verified the test — you have read it.

Watch for assertions satisfied by the setup rather than the behaviour, `assert not [...]`
where nothing could ever populate the list, and pins written at the end of a round under time
pressure (two of the twelve were written that way).

### 2. The test that passes for the wrong reason

Worse than one that cannot fail, because it looks discriminating. One test compared two
digests that were both `uncacheable-<random>` — it passed on the randomness, never touching
the code path it named. Another asserted a property that held only because an unrelated guard
fired first.

Ask: *if this passes, what have I actually learned?* Then check that the mechanism you think
produced the pass is the one that did.

### 3. The test that certifies the defect

The most dangerous shape. A fix removes a distinction, and the same change adds a test pinning
the now-collapsed behaviour as **required**. From then on, restoring correctness reds the
suite, and the next person must argue with a shipped contract.

In the source case, a "reordering is behaviour-neutral" assumption was self-evidently true for
whitespace and false for an ordered mapping — and the test written alongside it converted a
live collision into a guarantee. When a fix *removes* sensitivity to something, ask what
depended on that sensitivity before you pin its absence.

**The remedy is an `xfail(strict=True)` against a filed ticket — and it has a trap of its own.**
An xfail must assert the property you *want*, not the behaviour you *observe*. A record that
asserts the broken values XPASSes the instant anyone fixes anything, or never flips at all; one
that asserts the weakest sound property flips exactly when the defect closes, under any
defensible repair. Strictness is what makes it self-retiring: without it, a stale record keeps
passing silently long after the defect is gone.

### 4. The untested composition

Every shape in the catalogue tested once, alone; no two together. Two confirmed collisions in
the source programme were compositions of shapes the table already contained — a package
topology plus a reach mechanism, each individually covered.

Prefer a **cross-product** over a flat list. If your cases are {A₁, A₂, A₃} and {B₁, B₂}, the
table has six cells, not five rows. A flat list is a weaker instrument and the difference is
invisible until something slips through.

### 5. The canary that cannot die

A sweep or guard-test added specifically to prevent recurrence, which structurally cannot fire.
One 29-row sweep was added to catch a widening of a trigger set — but no row contained a
trigger, so widening the set flipped zero rows. It would not have caught either regression it
was written for.

Test the canary: **widen or break the thing it watches, and confirm it dies.** A canary is a
test, and every rule about tests applies to it.

### 6. The evidence artifact that lies

Reports and harnesses need auditing as much as code, because they are what the next reviewer
trusts instead of re-deriving. Three real instances:

- a blast-radius check that took its "before" snapshot **after** running the formatter, so it
  could only ever pass;
- a baseline column silently mislabelled because a `sed` in a `||` branch never fired, so the
  harness compared against the wrong revision;
- a report claiming "no rejection path is untested" when three were fed manually once and
  listed in the matrix as covered.

A one-off manual check is not coverage. A harness that silently reports the wrong baseline is
the same defect class as a test that asserts nothing.

### 7. The single-direction fix

Fixes that tighten a property routinely loosen its dual, and vice versa. In the source
programme **three consecutive rounds** moved one direction while breaking the other:
over-discrimination traded for under-discrimination, precision traded for cost, a collision
fixed by making everything fail closed.

For any fix with two failure directions — too strict / too loose, false positive / false
negative, over-invalidate / under-invalidate — **demand evidence in both**, per case, not in
aggregate. Single-direction evidence failed three times running there.

### 8. The guard that disables itself

A fail-closed mechanism with an input state that silently switches it off. One guard was keyed
on a set that could legitimately be empty; when it was, the guard did nothing, with no
diagnostic. A guard that no-ops on empty input is the same defect class as a test that asserts
nothing — it reports safety it is not providing.

For every guard, ask: **what input makes this do nothing, and does it say so?**

**The sharper version: a guard that answers from a datum silently switches off wherever that
datum is absent.** If the check is "does this belong to us?" and the answer is derived from a
name, then anything with no name — or a name another mechanism has already claimed — reads as
*not applicable* rather than *unknown*, and a fail-closed guard fails open. In the source
programme the guard could only ever answer from a function's top-level package name, so a
function with no `__module__` bypassed it entirely; an ordinary `import jsonschema` pack visits
five such functions.

Trace the *datum* the decision rests on, not just the branches: **what makes it absent, and
what does absence mean to the code?** Absence should route to the safe answer, and almost never
does by default.

### 9. Reachability unchecked, in both directions

A defect real inside a component may be unreachable through the system that uses it — and a
fix for it can be worse than the defect. One residual looked live and cheap; measuring the
actual loader showed the collision could not be triggered, and the proposed fix would have
landed in the one function whose only prior change shipped a fail-open.

Symmetrically, a guard scoped by reasoning rather than measurement fired on a third-party
library's internals and would have disabled the feature it protected for every real user.

**Measure reachability before fixing, and measure the fix's blast radius before shipping it.**

### 10. The fix that introduces its own defect class

Check whether a fix reproduces the pattern it repairs. A back-reference added to stop
duplicate expansion **overwrote the very content it was meant to discriminate**. An
address-normalisation added for stability **created a collision**. A restructure that removed
an empty-set edge case **removed the coverage that set provided**.

After reading a fix, ask: *does this do the thing it was fixing, somewhere else?*

### 11. The hole one level up

The most expensive pattern here, because it consumes rounds one at a time. A fix is genuinely
correct at the level it addresses, and the identical hole reappears at the next level of
indirection.

Measured sequence: a guard was made reach-agnostic for the **dispatcher**, and the same guard
turned out to be globals-only for the **seed** — 30 of 42 cells still colliding, including the
plainest import spelling of the very topology the fix existed to cover. That was the second
occurrence; the first cost a full round to discover.

The trap is that each fix is *correct*, so nothing feels wrong. Verification confirms the level
you fixed and stops there.

**When you close a hole at level N, name level N+1 before you report.** Who calls this? What
holds the thing that holds it? Either cover it in the same pass or write it down as an
uncovered level. The cost of asking is one paragraph; the cost of not asking has been a round
each time.

### 12. The asymmetric fix — one side of the boundary generalised, the other left specific

Distinct from #11: not the next level up, but **the other side of the same level**. A property
is made general on one side of a boundary and stays specific on the other, and every test row
shares the untouched assumption.

Measured: a guard was made indifferent to *how the dispatcher obtains its module*, while still
requiring the *seed* to hold that module as a specific type in its own globals. A deliberately
built 48-row cross-product missed it entirely, because all 48 rows shared the seed-side
assumption. Rebuilt across the seed axis, 24 of 30 cells collided — including the plainest
import spelling of the exact topology the guard existed to cover.

**When a fix generalises one side of a relationship, ask what the other side still demands.**
Producer and consumer, caller and callee, read path and write path, encode and decode. The
generalised side is the one you were thinking about; the specific side is where it survives.

A useful corollary from the same round: when checking the next level, some shapes correctly
need **no** guard. Recording *why* one is safe is as valuable as fixing one that is not — it
stops a later round adding protection where none belongs.

### 13. The canary blind to the newest thing

A refinement of #5 worth stating separately because it is predictable rather than accidental.
The component most likely to be untested is **the one added most recently**, because the
fixtures were written before it existed and nobody revisited whether they still exercise
everything.

Measured: a 48-row table, deliberately built as a cross-product and genuinely thorough, did not
exercise the newest and most load-bearing gate **at all** — deleting that gate left all 48 rows
passing, because the fixture module carried no packaging metadata for it to read.

**After adding a component, delete it and confirm something goes red.** If nothing does, the
suite grew without growing coverage.

## Running the pass

**Measure, don't reason.** Almost every confirmed finding here came from building a shape and
running it; almost every refuted one came from an argument. Where you can construct the case,
construct it. Report an unmeasured finding as unmeasured.

**Reproduce before you accept.** Do not take a report's evidence at face value — several
reports in the source programme were sincere and wrong.

**Default to refuted.** When acting as a verifier, try to kill the finding. A finding that
survives a genuine attempt is worth something; one you agreed with is worth nothing.

**Report clean honestly.** A lens that finds nothing, said plainly, is a real result. Do not
manufacture findings to justify the review — it poisons the signal that decides whether to
keep going.

## Dispatching a reviewer

If you are writing the prompt rather than answering it:

- **Give the lens, not just the diff.** Independent lenses attacking in parallel found four
  collisions that nine serial rounds had missed. Name the angle: collisions, stability,
  crashes, cost, test-assumptions.
- **Make one lens audit the test suite's assumptions.** That is the lens that catches the
  recurring class, and no one assigns it by default.
- **Never pre-judge.** If your prompt contains "don't flag X" or "at most minor", you are
  sparing yourself a review loop at the cost of the review.
- **Ask for both directions explicitly**, per case.
- **State the tripwire.** Before a loop starts, define what finding would justify continuing
  versus what gets documented and accepted. Otherwise "one more round" has no stopping rule.
- **Measure a fix before prescribing it.** A finding says "this is broken"; a prescription says
  "do X". The second carries authority the first does not, and if you have not measured X you
  are lending confidence you have not earned. In the source programme three consecutive
  prescriptions had to be scoped by the implementer before they were safe — one would have
  disabled the feature it protected for every real user. The prescriptions that landed cleanly
  came with their cost already measured ("this closes six cells and re-bricks zero libraries").
  If you cannot measure it, describe the defect and let the implementer design the fix.

## Knowing when to stop

Fix loops do not converge just because rounds keep finding things. Distinguish:

- **new pre-existing defects on ordinary shapes** — keep going;
- **defects the previous round's own fix introduced** — the loop is churning; a 100%
  self-injection rate means the expected net gain of another round is near zero;
- **exotic shapes and by-design limits** — document and stop.

Track those three counts per round. And note the honest limit of this test: an assessor
reasoning from the *pattern of findings* cannot see a defect nobody has looked for yet. In the
source programme a well-argued "stop" was immediately overturned by a parallel audit that
attacked from angles the serial loop never used — so if the stakes justify it, **change the
method before concluding the search is exhausted.**

## What a good residual list looks like

The durable deliverable of a hard review is not "closed" — it is a residual list a maintainer
can act on years later without reading the history. Each entry needs:

- **failure direction** — under-discrimination (unsafe) vs over-invalidation (safe) vs
  operational. Without this, everything reads equally alarming.
- **reachability** — live / uncommon / exotic / measured-unreachable, with the measurement.
- **whether the fix is cheaper than the defect**, and if not, why.
- **a do-not-fix marker where it applies**, with the reason — otherwise someone re-opens it
  and touches risky code for nothing.

Anything not on the list is not claimed closed. Say that explicitly.

**A residual list that is not an artifact does not exist.** Check where it actually lives. In
the source programme the list was genuinely well-reasoned and lived only as prose scattered
through source comments and test docstrings, with the working copy in review appendices that
are deleted when the work closes. Findings that survive a hard review are worth exactly as
much as the document that carries them — write it into the repository, beside the code it
describes.

**Say which entries were re-measured and which were inherited.** A list that does not
distinguish them gets trusted uniformly, and the stale ones are exactly where the next defect
hides.

**Residual lists rot in one specific way: an entry that asserts a correction which does not
hold.** "This was true of the old design; it is covered now" is the single most damaging thing
a residual list can say wrongly, because it stops the next person from looking. In the source
programme one such entry was false for four of five mechanisms it claimed to cover. When you
mark a residual corrected, re-measure it — a stale "fixed" is worse than an honest "open".

**And once an entry has over-claimed, re-measure it every round.** The same entry over-claimed
three times across that programme, each time in a different direction, because each fix moved
the boundary it described without anyone re-deriving the sentence. The most dangerous version
is an entry that draws a *closeable/not-closeable* line in the wrong place — it does not merely
mislead, it tells the next maintainer the cheap case is expensive and sends them away.

## Keeping this current

Treat this catalogue as living. **When a review turns up a failure shape that is not already
here, add it** — with the measurement that found it, not a paraphrase. Every entry above was
earned by something surviving review, and the concrete example is what makes the shape
recognisable next time.

The reliable signal that you have found a new class rather than another instance: the existing
entries do not tell you where to look. If a finding is covered by "ask what every row assumes",
it belongs as an example under that entry. If it required a genuinely different question — as
"what is the next level up?" did — it is a new one.
