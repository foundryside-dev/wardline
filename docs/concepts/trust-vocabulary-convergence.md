# Trust-vocabulary convergence

Weft has **one trust vocabulary and one judge**: Wardline *analyses* trust;
**legis** (the Weft governance plugin) *governs* it. This page records a deliberate
common-sense sweep (Track 5, T5.1) of the trust ideas that inspired Wardline's
model — chiefly the *effects* of a tiered `@trust_boundary` discipline — checking
that the suite delivers the useful ones and explicitly declining the rest. It is
a gap-check, not a feature: the conclusion is that the useful effects are already
delivered, in Weft's own terms.

## One judge, one vocabulary

- **Wardline analyses.** It owns the eight ordered trust tiers
  (`INTEGRAL → ASSURED → GUARDED → UNKNOWN_ASSURED → UNKNOWN_GUARDED →
  EXTERNAL_RAW → UNKNOWN_RAW → MIXED_RAW`; see [the model](model.md)) and the
  rules that police them.
- **legis governs.** It consumes Wardline's findings + gate verbatim and routes
  them through its enforcement policy. It carries Wardline's tiers as the shared
  vocabulary — *"carried, never re-derived"* — and never re-analyses. (See
  [the legis intake conformance tests](#one-judge-not-two).)

There is no second analyzer and no second vocabulary. A finding's trust tiers are
Wardline's; legis reasons about governance on top of them.

## The sweep: keep / adopt / drop

Each row is an effect from the tiered-trust-boundary lineage, with a verdict and
the Weft mechanism that delivers it (or the reason it is declined).

| Effect / idea | Verdict | Weft mechanism (or reason) |
|---|---|---|
| **Fabrication test** — a trust boundary must be able to say *no* (reject), or it isn't a boundary | **Covered** | **PY-WL-102** (`boundary_without_rejection`): a `@trust_boundary` with no rejection path is flagged — it cannot say no, so it cannot be trusted to raise trust |
| **Custody / provenance** — trust is earned and tracked, never assumed | **Covered** | the trust **lattice** (a value is only as trusted as its least-trusted contributor; `least_trusted` weakest-link meet) + `taint_provenance` (source + contributing callee), carried on every finding and in the dossier |
| **Fail-closed boundaries** — what cannot be proven is not trusted | **Covered** | the `UNKNOWN_*` states + observable `WLN-ENGINE-*` FACTs; a custom boundary the engine cannot prove seeds `UNKNOWN_RAW` and emits `WLN-ENGINE-UNPROVABLE-BOUNDARY` (T2.4) — the extension plane inherits the no-false-green guarantee |
| **Tiered boundary** — a validated boundary *raises* trust to a named tier | **Covered** | `@trust_boundary(to_level=GUARDED\|ASSURED)` — named Weft levels rather than integer tiers, the same "raise trust at a validated boundary" effect expressed in the lattice |
| **One judge** — governance reads the analyzer's verdict, it does not re-judge | **Covered** | legis ingests Wardline findings/gate and governs; the conformance tests prove legis's gate population reproduces Wardline's own `active` count without re-derivation |
| **A separate `tier=` integer decorator** | **Dropped** | redundant with named levels; adding a second spelling would fork the one vocabulary. Weft uses named tiers (`to_level=`), full stop |
| **A new worked custom-boundary example for this page** | **Dropped (cite existing)** | the T2 extension plane already ships one — see below — so a second would be duplicate apparatus |

Nothing in the sweep is **Adopt** (useful + genuinely missing): the useful
effects are already delivered. Two ideas are explicitly **Dropped** so the
decision is durable and not re-litigated.

## One grammar, demonstrated

"One `@trust_boundary` grammar across the suite" is not just the builtins. The
Track 2 **extension plane** lets an agent declare a *new* tiered boundary — in its
own namespace, with zero edits to Wardline core — and have it policed exactly like
a builtin. The shipped acceptance fixture
`tests/grammar/fixtures/custom_grammar.py` is precisely an
elspeth-style tiered boundary expressed in the one grammar:

```python
SANITIZED = BoundaryType(
    canonical_name="sanitized",
    module_prefix="myproj.trust",                      # the agent's own namespace
    level_args=(LevelArg("to_level", {GUARDED, ASSURED}, default=None),),
    seed=lambda levels: FunctionTaint(levels["to_level"], levels["to_level"]),
    builtin=False,
)
# builtins + the custom tiered boundary and its rule — one grammar
GRAMMAR = default_grammar().extend(boundary_types=(SANITIZED,), rules=(SanitizerReturnsRaw,))
```

A custom `@myproj.trust.sanitized(to_level=ASSURED)` raises trust to a Weft tier,
is policed by a custom rule (`MYPROJ-001`), and — if its required level cannot be
proven — fails closed with `WLN-ENGINE-UNPROVABLE-BOUNDARY`. The builtins remain
byte-identical (a corpus golden enforces it). This is the convergence in
executable form: one grammar, extensible, fail-closed, no second vocabulary.

## One judge, not two

The legis integration is data-flow-only and proven two ways:

- **Hermetic contract test** (`tests/conformance/test_legis_intake_contract.py`,
  always on): a real scan's emitted findings ingest into legis's documented
  `from_wire` shape, and legis's active-defect selection reproduces Wardline's own
  `summary.active` gate population exactly.
- **Live oracle** (`tests/e2e/test_legis_live.py`, opt-in `legis_e2e`): a real
  scan is POSTed to a running legis's `/wardline/scan-results`; legis routes the
  active defects into its 2×2 cell. Wardline never re-judges; legis never
  re-analyses.

Governance is legis's layer, not Wardline's — which is the whole point of one
judge.
