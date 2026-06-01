# Wardline — Track 2: the extensible trust grammar (design spec)

**Date:** 2026-06-02
**Status:** Track design spec — the *how* beneath the program spec's Track 2
(`2026-06-02-wardline-first-class-body-of-work-design.md` §2 "Track 2 — Extensible
trust grammar"). Sits below the program spec, above the implementation plan
(`docs/superpowers/plans/2026-06-02-wardline-track2-extensible-trust-grammar.md`).
Resume/status surface: the progress tracker
(`2026-06-02-wardline-first-class-progress-tracker.md`).
**Builds on:** Track 1 (engine-quality floor, done) — its sound engine and its
labeled FP corpus, which this track reuses as oracle substrate.

> **Thesis filter (governs every line).** Power via opt-in **activation**, never
> opt-in **configuration**. The extension plane is **agent-authored** (zero *human*
> config); the human supervises. The zero-dependency base stays zero-dependency —
> the grammar is a *code* seam (the same shape as `TaintSourceProvider`), not a new
> DSL, runtime, or dependency.

---

## 0. What this track is (and is not)

Wardline today knows exactly **three** trust decorators and **four** rules, all
hardcoded:

- `core/registry.py::REGISTRY` — 3 frozen `RegistryEntry` rows.
- `scanner/taint/decorator_provider.py::DecoratorTaintSourceProvider._match` — a
  hardcoded `if canonical == "external_boundary" / "trust_boundary" / "trusted"`
  dispatch that maps each decorator to its L1 seed `FunctionTaint(body, return)`.
- `scanner/rules/__init__.py::_ALL_RULE_CLASSES` — a frozen 4-tuple of rule classes.

Track 2 turns those three closed lists into **one open grammar** an agent can
extend **without editing engine source**, while the builtin vocabulary keeps
producing **byte-identical findings**. This is the hinge between "best analyzer"
and "Loom citizen": it is the substrate for T1.5 (rule breadth, authored *on* the
grammar) and Track 5 (suite trust-vocabulary convergence — elspeth/legis effects
expressed in Loom's own grammar).

**In scope (T2.1–T2.4):** the boundary-type meta-model; the boundary-type + rule
registry/provider seam; re-expressing the 4 builtins + 3 decorators on the seam
byte-identically; soundness inheritance (unprovable custom boundary → `UNKNOWN_*`
+ an observable FACT).

**Out of scope (named, not silent):** new *content* (T1.5's extra rules — this
track ships the seam they land on, not the rules); a CLI/MCP plugin-loading
mechanism that auto-discovers third-party grammar packages (the seam is exercised
by constructing the analyzer with an extended grammar — the activation path is
sketched in §7 but its packaging is deferred); any change to the lattice, the two
operators, fingerprints, or governance.

---

## 1. The acceptance fixture — design backward from this

The program spec's first DoD gate **is** the definition of done: *"an agent defines
a new boundary type + rule end-to-end and it fires correctly."* So it is the first
artifact, and the seam is designed backward from it.

**The litmus test (the one constraint that makes "open" real):**

> Landing the acceptance fixture requires **zero edits** to
> `decorator_provider._match`, `rules/__init__._ALL_RULE_CLASSES`, and
> `core/registry._ENTRIES`.
>
> If the design needs to touch any of those three to make the fixture fire, the
> grammar is a fake generalization that still only knows the 3 builtins.

**What the agent authors (the fixture, verbatim shape):**

```python
# tests/grammar/fixtures/custom_grammar.py  — authored entirely outside src/wardline
import ast
from wardline.core.taints import TaintState
from wardline.scanner.grammar import BoundaryType, LevelArg, FunctionTaint, TrustGrammar
from wardline.scanner.grammar import default_grammar
from wardline.scanner.rules.metadata import RuleMetadata
# (rule helper imports — Finding, Severity, Kind, _fp — from their public homes)

# 1. A NEW boundary type: @sanitized(to_level=...) living in the AGENT's own module.
SANITIZED = BoundaryType(
    canonical_name="sanitized",
    module_prefix="myproj.trust",            # NOT wardline.decorators
    group=1,
    level_args=(LevelArg("to_level", allowed=frozenset({TaintState.GUARDED, TaintState.ASSURED}), default=None),),
    seed=lambda levels: FunctionTaint(TaintState.EXTERNAL_RAW, levels["to_level"]),
    builtin=False,
)

# 2. A NEW rule enforced over the resolved taint state (a normal _Rule object).
class SanitizerMustNarrow:
    rule_id = "MYPROJ-001"
    metadata = RuleMetadata(rule_id="MYPROJ-001", base_severity=Severity.ERROR, kind=Kind.DEFECT, description="...")
    def __init__(self, base_severity=None): self.base_severity = base_severity or self.metadata.base_severity
    def check(self, context): ...   # reads context.project_taints etc., returns list[Finding]

# 3. Extend the default grammar — append, do not replace.
GRAMMAR = default_grammar().extend(boundary_types=(SANITIZED,), rules=(SanitizerMustNarrow,))
```

```python
# tests/grammar/test_acceptance_custom_grammar.py
def test_agent_defined_boundary_and_rule_fire_end_to_end(tmp_path):
    # A target file using the agent's OWN @sanitized marker (static; never executed).
    analyzer = build_analyzer_for(GRAMMAR)          # §2 wiring
    findings = analyzer.analyze([target], WardlineConfig(), root=tmp_path)
    assert any(f.rule_id == "MYPROJ-001" for f in findings)   # the custom rule fired
    # and @sanitized seeded the L2 taint the rule keyed on (assert via explain/context)
```

Everything below exists to make this fixture loadable and firing with the litmus
held.

---

## 2. The meta-model (T2.1) and the seam (T2.2)

Wardline already layers cleanly, and Track 2 **preserves that layering** (load-bearing):

- **Boundary types feed L1 seeding** (declaration → taint). This is where the 3
  decorators live today, hardcoded in `_match`.
- **Rules read the *resolved* taint state** (`AnalysisContext`), not the decorator.
  PY-WL-101 fires on *any* anchored function whose actual return rank exceeds its
  declared rank — it is not bound to a specific decorator.

So the grammar is **two open registries with one wiring object**, not one tightly
coupled "boundary-carries-its-rule" object. (The program spec's phrase "a declared
trust transition carrying an enforcement rule" describes the *meta-model's*
membership — the grammar registers both — not a per-instance Python coupling.
Tightening that coupling would force a rewrite of how rules query state and put the
oracle at risk for no benefit — explicitly rejected.)

### 2.1 `BoundaryType` — the generalization of a trust decorator

New module `src/wardline/scanner/grammar.py` (zero-dep, stdlib + `core.taints` +
`scanner.taint.provider` only):

```python
@dataclass(frozen=True, slots=True)
class LevelArg:
    """One statically-read keyword argument of a boundary marker (e.g. to_level)."""
    arg_name: str
    allowed: frozenset[TaintState]
    default: TaintState | None        # None => REQUIRED (unreadable/missing => fail-closed)

@dataclass(frozen=True, slots=True)
class BoundaryType:
    """A declared trust transition: a recognizable decorator marker + its L1 seed semantics.

    Generalizes one row of today's `_match`. `module_prefix` + `canonical_name`
    are how the engine RECOGNIZES the marker on a target's AST (alias-resolved);
    `level_args` is what the engine reads from the call site (generic machinery);
    `seed` maps the read levels to the function's seed taint.
    """
    canonical_name: str               # e.g. "trusted", or a custom "sanitized"
    module_prefix: str                # e.g. "wardline.decorators" (builtins) or "myproj.trust"
    group: int
    level_args: tuple[LevelArg, ...]
    seed: Callable[[Mapping[str, TaintState]], FunctionTaint]
    builtin: bool = False             # controls the T2.4 FACT (see §4)
```

The engine's recognition + reading machinery is **generic** (lifted out of
`_match`, reusing today's `_resolve_decorator_fqn` / `_read_level` /
`_level_token` verbatim): match `module_prefix + "." + canonical_name` against the
alias-resolved decorator FQN; for each `LevelArg` read it via `_read_level`;
default when absent; **fail closed** (return the unprovable signal — §4) when a
required arg is present-but-unreadable, an invalid state, or out of `allowed`.
Only after all args read does it call `seed(read_levels) -> FunctionTaint`.

The 3 builtins become 3 `BoundaryType` instances (one source of truth — see §3),
each with `builtin=True`:

| canonical_name | level_args | seed(levels) → FunctionTaint |
|---|---|---|
| `external_boundary` | () | `(EXTERNAL_RAW, EXTERNAL_RAW)` |
| `trust_boundary` | `to_level` ∈{GUARDED,ASSURED}, required | `(EXTERNAL_RAW, levels["to_level"])` |
| `trusted` | `level` ∈{INTEGRAL,ASSURED}, default INTEGRAL | `(levels["level"], levels["level"])` |

### 2.2 `TrustGrammar` — the wiring object (and the extension API)

```python
@dataclass(frozen=True, slots=True)
class TrustGrammar:
    boundary_types: tuple[BoundaryType, ...]
    rules: tuple[type[_Rule], ...]    # rule CLASSES; instantiated per-config (severity overrides) downstream

    def extend(self, *, boundary_types=(), rules=()) -> "TrustGrammar":
        """Append agent-defined types/rules to the defaults. Append, never replace —
        builtins are preloaded defaults (program spec T2.2)."""
        return TrustGrammar(self.boundary_types + tuple(boundary_types),
                            self.rules + tuple(rules))

def default_grammar() -> TrustGrammar:
    """The builtin grammar: the 3 boundary types + the 4 rule classes, in
    today's exact order. The byte-identity oracle (§5) pins this == today."""
```

### 2.3 How the seam reaches the engine (no new constructor surface)

The analyzer **already** accepts `provider` and `registry` (§`analyzer.py:62-71`).
Track 2 threads the grammar through them — no new top-level wiring:

- `DecoratorTaintSourceProvider(boundary_types=grammar.boundary_types)` — the
  provider's `_match` becomes a generic loop over `boundary_types` (default arg =
  `default_grammar().boundary_types`, so existing constructions are unchanged).
- `build_default_registry(config, rules=grammar.rules)` — `rules` defaults to
  `default_grammar().rules` (= today's `_ALL_RULE_CLASSES`), so existing behavior
  is unchanged; config gating/severity override logic is untouched.
- A thin helper `build_analyzer(grammar=default_grammar(), ...)` constructs both
  consistently (this is what the fixture's `build_analyzer_for(GRAMMAR)` calls).

`_ALL_RULE_CLASSES` and the `_match` if-ladder are **deleted** and replaced by the
`default_grammar()` data — proving the litmus (the builtins ride the same open
path a custom type does).

---

## 3. Preserving the released `REGISTRY` contract (BLOCKER)

`core/registry.py` declares itself "the import surface Clarion's plugin depends on
… do not break," and Clarion's repo references it. This is a **released** contract;
the "no back-compat shims for unreleased specs" license does **not** apply.

**Rule:** `wardline.core.registry.{REGISTRY, REGISTRY_VERSION, RegistryEntry}` stay
importable and identically shaped. The boundary-type registry is a **new, separate**
open structure (`scanner/grammar.py`); custom boundary types do **not** enter
`REGISTRY`. `REGISTRY` remains the frozen *builtin-vocabulary* contract.

**One source of truth for the builtins:** the 3 builtin `BoundaryType`s are derived
from / aligned with `REGISTRY` (names, group, attr schema), enforced by a
consistency test (builtin boundary-type names+attrs ≡ `REGISTRY`), so the two views
cannot drift. `REGISTRY` keeps the *declaration shape* (name/group/attrs); the
grammar adds the *seed semantics* `REGISTRY` never carried.

**Verify:** Clarion's plugin still imports clean after the refactor (read its
import sites; do not change the three names or `RegistryEntry`'s fields).

`descriptor.py` builds the NG-25 descriptor from `REGISTRY`; `vocabulary.yaml` is
its byte-identity-tested snapshot. Because `REGISTRY` is unchanged, the descriptor
and `vocabulary.yaml` are unchanged — **no regeneration**. (Test must stay green as
a tripwire.)

---

## 4. Soundness inheritance (T2.4) — scoped to customs

Today, when a decorator's level can't be read statically, the provider returns
`None` ("no opinion") and L1 falls back to `UNKNOWN_RAW` **silently**. T2.4 makes
this observable for the extension plane: an agent-defined boundary the engine
cannot prove emits `UNKNOWN_*` **+ an observable `WLN-ENGINE` FACT**, never a
false-green.

**The byte-identity constraint forces scoping (BLOCKER #4, locked):** a new FACT is
a finding in the stream (`Severity.NONE`, `Kind.FACT`). Emitting it for the
**builtin** path would change the findings stream and break both the oracle and
dogfood-clean. Therefore:

- The unprovable FACT fires **only for `builtin=False` boundary types.**
- Builtin types preserve today's exact behavior: unreadable → `None` → `UNKNOWN_RAW`,
  **no new FACT.**

**Mechanism (seam change, minimal):** the seeding seam carries an "unprovable custom
boundary" signal alongside the seed. The provider's per-entity result becomes a
small record:

```python
@dataclass(frozen=True, slots=True)
class SeedResult:
    taint: FunctionTaint | None                 # as today (None => UNKNOWN_RAW fallback)
    unprovable_boundary: str | None = None       # canonical_name of a matched-but-unprovable CUSTOM type
```

The analyzer's seeding step (which already collects engine FACTs via
`scanner/diagnostics.py`) turns a non-None `unprovable_boundary` into:

```
rule_id  = "WLN-ENGINE-UNPROVABLE-BOUNDARY"   # NEW; in UNANALYZED_RULE_IDS? NO —
                                              # it is a declared-but-unreadable annotation,
                                              # an honest under-seed, not a file under-scan.
                                              # Decide in plan against UNANALYZED_RULE_IDS semantics.
severity = Severity.NONE,  kind = Kind.FACT
message  = "{qualname}: custom boundary @{name} could not be proven (arg unreadable) — seeded UNKNOWN_RAW"
```

A matched custom type whose seed *succeeds* emits no FACT (it's proven). A custom
type that doesn't match (wrong module/name) is simply not this type's concern —
unchanged "no opinion" semantics, exactly as a non-vocabulary decorator today.

**T2.4 DoD test:** a custom boundary with an unreadable required level → the seeded
function resolves `UNKNOWN_RAW` **and** the stream contains exactly one
`WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT; the same shape on a *builtin* decorator emits
**no** such FACT (oracle-preserving twin test).

---

## 5. The byte-identity oracle (T2.3) — mechanized as Task 0, before any refactor

"Oracle held byte-for-byte" needs a frozen golden to diff against; RED-first for a
refactor = **snapshot first**. No full findings-stream golden exists today (only
`test_self_hosting.py`'s zero-DEFECT assertion, the warm/cold determinism test, and
the T1.4 corpus FP-rate — none is a full-stream before/after oracle).

**Task 0 (lands before any grammar code):** capture today's **complete** findings
stream — over **both** the dogfood tree (`src/wardline`) **and** the T1.4 corpus
(`tests/corpus/fixtures`) — including `FACT`s and **emission order**, serialized
canonically (the existing emitter's JSONL, fingerprints included), as a committed
golden. A test asserts the *current* engine reproduces it (proving the golden is
faithful before the refactor begins). After T2.3, the re-expressed builtin grammar
must reproduce the **same golden byte-for-byte**.

This golden is the gate on every subsequent task: any task that changes a single
byte of it (other than the intentionally-scoped new custom-only FACT, which never
fires on builtins) has broken the re-expression.

---

## 6. Fingerprint / grammar identity in the cache (BLOCKER #5)

`DecoratorTaintSourceProvider.fingerprint()` returns `decorator-vocab:{REGISTRY_VERSION}`
and is **len-prefixed into the SummaryCache key** (`summary.py:87`); the cache
**persists to disk** (`cache_dir` + `load()`/`save()`). Two different loaded
grammars sharing cached summaries would be a **false-green correctness bug**.

**Rule:**
- The provider's `fingerprint()` must incorporate **grammar identity** (a stable
  digest over the loaded boundary types: their names, prefixes, level-arg schemas,
  and a seed-identity tag). A custom grammar → a different fingerprint → no cache
  cross-contamination.
- The **builtin-only** grammar's fingerprint must remain **byte-identical to
  today's** string (`decorator-vocab:wardline-generic-1`) to avoid cache/baseline
  churn. Achieve this by special-casing: when the loaded boundary types are exactly
  the builtin set, emit the legacy string; otherwise append a grammar digest. (Test
  both: builtin grammar → legacy string; any custom type → a distinct, stable
  string.)

Rules do **not** affect seeding/summaries, so the rule set need not enter the
summary-cache fingerprint (rules run post-resolution). The plan must confirm no
other cache keys on the rule set.

---

## 7. Activation path (sketch; packaging deferred)

The DoD fixture exercises the seam by **constructing** the analyzer with an extended
grammar — which is exactly how sibling products consume it programmatically (legis
/ elspeth supply their effects as grammar extensions in Track 5; Clarion already
imports `REGISTRY`). That is sufficient for Track 2's DoD.

A CLI/MCP mechanism that *auto-loads* a project's grammar module (so `wardline scan`
picks up `@sanitized` with zero construction code) is the natural activation
increment but is **deferred** (its honest home is alongside T1.5/Track 5, and a
config-pointer to a grammar module brushes the "activation not configuration" line —
worth its own decision). Track 2 ships the seam and proves it; it does not ship
auto-discovery. *(Flagged, not silent.)*

---

## 8. Work units → DoD mapping

| Unit | Deliverable | DoD gate |
|---|---|---|
| **T0** (new) | Full-stream byte-identity golden over dogfood + corpus | golden committed; current engine reproduces it (RED-first baseline) |
| **T2.1** | `grammar.py`: `LevelArg` / `BoundaryType` / `FunctionTaint` / `TrustGrammar` / `default_grammar()` | meta-model defined; builtin types ≡ `REGISTRY` (consistency test) |
| **T2.2** | Provider `_match` → generic boundary-type loop; `build_default_registry(rules=)`; `build_analyzer(grammar=)` | seam wired; `_ALL_RULE_CLASSES` + `_match` if-ladder deleted; existing constructions unchanged |
| **T2.3** | 3 decorators + 4 rules re-expressed on `default_grammar()` | **golden reproduced byte-for-byte**; warm/cold byte-identical still green; dogfood clean; `vocabulary.yaml`/descriptor drift test green; Clarion import-surface intact |
| **T2.4** | `SeedResult.unprovable_boundary` + `WLN-ENGINE-UNPROVABLE-BOUNDARY` FACT, custom-only | unprovable custom → `UNKNOWN_*` + exactly one FACT; builtin twin → no FACT |
| **Acceptance** | The §1 fixture (custom boundary type + custom rule) | fires end-to-end with the litmus held (zero edits to `_match`/`_ALL_RULE_CLASSES`/`_ENTRIES`) |

**Program-spec DoD (§2 Track 2), all three:**
- Extensibility — acceptance fixture fires. ✔ (§1)
- Soundness inherited — unprovable custom → `UNKNOWN_*` + FACT. ✔ (§4)
- No regression — 4 builtins re-expressed produce byte-identical findings. ✔ (§5)

Plus the inherited engine gates: coverage 90% global / 95% on `scanner/taint/` (and
`scanner/grammar.py`), mypy/ruff clean, warm/cold byte-identical green, every closed
hole RED-first.

---

## 9. Invariants (must hold across the track)

- **Zero-dep base; code seam, not a DSL.** `grammar.py` imports only stdlib +
  `core.taints` + `scanner.taint.provider`. No new dependency, runtime, or config
  language.
- **Released `REGISTRY` contract preserved** (§3); Clarion import surface intact.
- **Static-only.** The engine recognizes custom markers by AST shape (module prefix
  + name + readable kwargs); it never imports or executes the scanned target — a
  custom boundary type is *data describing how to read a marker*, not target code
  Wardline runs.
- **Fail-closed / no false-green** inherited by the extension plane (§4): an
  unprovable custom boundary is an observable FACT, never a silent pass.
- **Byte-identical builtins** (§5) and **fingerprint stability** for the builtin
  grammar (§6).
- **Layering preserved:** boundary types seed L1; rules read resolved taint. Not
  coupled per-instance (§2).
