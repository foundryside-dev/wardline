# Improvement backlog — rules, tests, soundness

> **Status (2026-06-02, implemented):** Items **#1, #2, #3, #4, #5** (the cheap
> test guards) and **PY-WL-111** are DONE. #1 caught and fixed real `PY-WL-101`
> example-rot; #4 pins the *real* anchor-line fingerprint contract (the literal
> "blank-line insert → identical" framing below was incorrect — `line_start` is a
> fingerprint input, so a line shift changes it by design). #6 (mutation testing)
> is **deferred** — explicitly heavy, adds a dev dep + a CI-gate decision,
> lowest value-per-effort. The **soundness / FN closures** below remain a
> **separate batch** (each is real engine work with its own FP analysis +
> soundness-regression fixture; class-attribute taint is the highest-value start).
> Framework-specific sinks remain routed to trust-grammar packs (`wardline-6e4ac6c148`).
>
> Working notes captured 2026-06-02, after the T1.5 rule-breadth work (builtins
> 4 → 10, PY-WL-105–110). These are candidate follow-ups, grounded in the
> current engine and its FP-discipline — not a committed plan. Promote an item
> to a Track-1.6 plan + Filigree issue when you pick it up.
>
> **Recommended sequence:** land the cheap test guards (#1–#3 below) first
> (pure upside, no FP risk), add PY-WL-111 as the last generic builtin, and
> route the framework-specific sinks into the trust-grammar-packs work
> (`wardline-6e4ac6c148`) where they belong. Soundness/FN closures pay
> compounding interest and each should ship with a soundness-regression fixture
> per the DoD ("soundness regression test per closed hole").

## What's already solid (don't re-add)

Verified in the repo while drafting this, so the gaps below are real:

- **Lattice properties** — `tests/unit/core/test_taints.py` already pins
  `taint_join` exhaustively + commutativity, `least_trusted` "picks higher
  rank" (parametrized), `MIXED_RAW` absorbing, and the total-order of
  `TRUST_RANK`.
- **Corpus FP gate** — `tests/corpus/` already enforces every active DEFECT
  has a `MANIFEST.yaml` entry and FP rate ≤ 5%.
- **Builtin golden** — `tests/grammar/golden/builtin_findings.jsonl` pins the
  corpus-wide findings stream; warm/cold byte-identity is guarded.

## Tests / gates — highest value-per-effort

### 1. Rule-examples meta-test (do this first)

One parametrized test over `BUILTIN_RULE_CLASSES`: feed each rule's
`metadata.examples_violation` through the analyzer and assert it produces *that*
rule's finding; feed `examples_clean` and assert it does **not**.

- **Why:** the examples are agent-facing — they ship in `wardline explain` and
  the NG-25 vocab descriptor. Today they're rot-prone documentation with no
  contract. We hit example-rot during T1.5 (misleading PY-WL-105 example missing
  `@external_boundary`); this would have caught it.
- **Bonus:** becomes a forcing function — no future rule can ship without
  working, verified examples.
- **Cost:** small; no FP risk.

### 2. `RAW_ZONE` ↔ `TRUST_RANK` consistency pin

Assert `RAW_ZONE == {s for s in TaintState if TRUST_RANK[s] >= TRUST_RANK[EXTERNAL_RAW]}`.

- **Why:** rules gate on **both** `RAW_ZONE` set-membership and rank
  comparisons (e.g. PY-WL-101's strict-rank check vs. its declared-tier gate).
  If those two ever drift, rules misfire silently. One assertion closes the
  coupling.
- **Cost:** one line.

### 3. CLI ↔ MCP differential

Run the same fixture tree through `run_scan` as the CLI invokes it and as the
MCP `_scan` tool invokes it; assert identical findings + gate decision (modulo
the deliberate `confine_to_root=True` difference on the MCP side).

- **Why:** "CLI and MCP are identical by construction" is a core tenet
  (CLAUDE.md) but is asserted by design, not guarded. `tests/unit/cli/test_mcp_cli.py`
  only exercises the protocol loop, not finding-parity. A differential test
  catches drift (e.g. a future MCP-only path change leaking into results).
- **Cost:** moderate.

### 4. Fingerprint-stability corpus

Assert that cosmetic refactors — rename a local, reorder top-level functions,
insert blank lines / comments — leave finding fingerprints **byte-identical**.

- **Why:** CLAUDE.md calls a fingerprint change "breaking" (it silently
  invalidates baselines/waivers), yet nothing pins the *negative* case — that
  cosmetic edits *don't* move fingerprints. The fingerprint inputs are
  `(rule_id, path, line_start, qualname, taint_path)`; line-shifting edits are
  the obvious risk surface.
- **Cost:** moderate.

### 5. `least_trusted` idempotence + associativity (exhaustive)

Add exhaustive checks (8³ is tiny — no `hypothesis` dep needed):
`least_trusted(a, a) == a` and
`least_trusted(least_trusted(a, b), c) == least_trusted(a, least_trusted(b, c))`.

- **Why:** the L3 fixed point folds `least_trusted` over many return values;
  associativity is what makes that fold order-independent. Pinning it stops a
  future "simplification" into something order-dependent (e.g. accidentally
  swapping in `taint_join`).
- **Cost:** small.

### 6. (heavier, opt-in) Mutation testing on `taint/`

Wire `mutmut`/`cosmic-ray` as an opt-in dev extra to measure suite *strength*
on the taint engine, not just coverage. High signal for an analyzer where the
tests are the spec; gate optionally in CI on the `taint/` package.

- **Cost:** large; adds a dev-only dep behind an extra (base stays zero-dep).

## New rules

### Reframe: the generic sink space is largely mined out

106/107/108 cover the sinks that are dangerous **regardless of framework**
(deserialization, dynamic-exec, shell). The obvious next sinks are all
**framework-specific**:

- SQL injection (CWE-89) — `cursor.execute(...)`
- Template injection — `Template(...).render(...)`, `render_template_string`
- XXE (CWE-611) — `lxml.etree.parse`, `xml.etree`
- SSRF — `requests`/`urllib` with a tainted URL

Matching these generically would over-fire badly: the receiver is a **runtime
object**, not an importable symbol that `_sink_helpers` can resolve (`.execute`
/ `.render` are common method names on unrelated objects). So the FP-disciplined
home for them is **trust-grammar packs** (`wardline-6e4ac6c148`), not the
builtin set — power via opt-in *activation*, not always-on builtins. This is the
recommended route, not a builtin rule.

### PY-WL-111: `assert` as a trust boundary's only rejection path (CWE-617)

The one genuinely-generic rule still worth adding to builtins. A
`@trust_boundary` whose **sole** reject is `assert ...` is stripped under
`python -O` — the validation silently vanishes in production.

- **Generic** (no framework), **FP-safe** (declaration-gated on
  `@trust_boundary`; fires only when the only raise-shaped reject is an
  `assert`), and a true PY-WL-102-adjacent refinement.
- Pairs naturally with the existing boundary-without-rejection rule.

## Soundness / FN closures (make *every* rule sounder)

Precision work here compounds — it strengthens 101/105 and the sink rules at
once. Each must land with a soundness-regression fixture.

- **Class-attribute taint.** Raw assigned to `self.x` in a `@trusted` method,
  then returned/used elsewhere, currently escapes (engine is function-level).
  A real FN that weakens 101/105 on OO code.
- **`**kwargs` / `*args` propagation** — taint through these binding forms at
  call sites and in signatures.
- **Comprehension / walrus targets** — taint through `[x for x in raw]` and
  `(y := raw)`.
- **Decorator-wrapped callees** (`functools.wraps`) — taint through wrappers in
  the call graph.
- **Flow-sensitive call-arg taint.** The sink rules (106/107/108) currently use
  the **flow-insensitive** `worst_arg_taint` (reads final `function_var_taints`),
  which can over-fire on a trusted→raw reassignment after the sink call. A
  flow-sensitive call-site taint read would tighten all three. (Documented
  honestly in `_sink_helpers.py` today as a known over-fire.)
