# Track 1.5 — Rule-set breadth (4 → 10) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or executing-plans). Steps use `- [ ]`.

**Goal:** Grow Wardline's curated builtin rule set from 4 to the DoD floor of **10**, authored **on the Track 2 grammar**, each rule FP-safe (Track 1's ≤5% bar), fail-closed/opt-in, shipping `examples_violation` + `examples_clean` and `tests/corpus/` fixtures with MANIFEST entries.

**Architecture:** Six new rule classes in `src/wardline/scanner/rules/`, each a `_RuleClass` (`rule_id` classvar, `metadata: RuleMetadata`, `__init__(base_severity=None)`, `check(context)->list[Finding]`) appended to `_ALL_RULE_CLASSES`/`BUILTIN_RULE_CLASSES` in `rules/__init__.py` (so `default_grammar()` and `build_default_registry(rules=)` pick them up and `wardline.yaml` `rules.enable`/`rules.severity` toggle them). Four are call-site/sink rules sharing one new helper module `rules/_sink_helpers.py` for argument-taint resolution. All read **resolved taint** from `AnalysisContext` — never decorators (except PY-WL-110, which *counts* grammar markers, gated on resolved provenance).

**The chosen set (user-selected 2026-06-02, "broad-to-10"):**

| Rule | Invariant | Gating | Sev | CWE |
|---|---|---|---|---|
| **PY-WL-105** | untrusted arg passed to a trusted project callee at a call site | declaration-gated (on the *callee*) | ERROR | CWE-501 |
| **PY-WL-106** | raw data reaches a **deserialization** sink (pickle/marshal/yaml.load/…) in a trusted-tier fn | tier-modulated | WARN | CWE-502 |
| **PY-WL-107** | raw data reaches a **dynamic-code-exec** sink (eval/exec/compile) in a trusted-tier fn | tier-modulated | WARN | CWE-95 |
| **PY-WL-108** | raw data reaches an **OS-command** sink (os.system/subprocess shell, os.popen) in a trusted-tier fn | tier-modulated | WARN | CWE-78 |
| **PY-WL-109** | None / implicit-None leaks from a trusted producer with a non-raw declared return | declaration-gated | WARN | CWE-394 |
| **PY-WL-110** | contradictory/ambiguous trust declaration (≥2 distinct grammar boundary markers on one entity) | declaration-gated | ERROR | — |

**Engine surfaces (confirmed in source):** `AnalysisContext` exposes `entities` (`Entity{node,location,qualname}`), `project_taints` (resolved body tier), `project_return_taints` (declared/effective return), `function_return_taints` (L2 actual return), `function_var_taints` (`{qualname:{var:TaintState}}`, **final** per-var map — flow-insensitive), `function_return_callee`, `taint_provenance` (`.source`=="anchored", `.via_callee`, `.resolved_call_count`, `.unresolved_call_count`). Rule pattern: see `broad_exception.py` (tier-modulated via `severity_model.modulate`) and `untrusted_reaches_trusted.py` (declaration-gated on `prov.source=="anchored"`). `_ast_helpers._own_statements` walks own-scope only (never nested defs). `_dotted_name` reconstructs `a.b.c`. Fingerprint via `compute_finding_fingerprint as _fp(rule_id, path, line_start, qualname, taint_path)`.

**FP-precision note (load-bearing):** `function_var_taints` is the **final** per-var taint (flow-insensitive). The sink/call-site rules read it for `ast.Name` args; for a direct nested `ast.Call` arg they resolve the callee's return taint; **anything else → treat as unknown and DO NOT fire** (under-fire, never guess). This is conservative-by-design; the reassignment-to-trusted-then-used-raw edge is a known, bounded under-precision documented in `_sink_helpers.py`. The corpus FP gate validates ≤5% empirically.

**Corpus gate (`tests/corpus/`):** every active DEFECT the engine produces over `tests/corpus/fixtures/` MUST have a `MANIFEST.yaml` entry keyed `(path, rule_id, qualname)`; an unaccounted finding **fails** the gate. FP rate = FALSE_POSITIVE / active DEFECTs ≤ 5%. So: (a) each new rule ships a violation fixture labeled TRUE_POSITIVE; (b) clean fixtures must produce no active DEFECT; (c) re-run the full corpus after EVERY rule — a new rule that fires on an *existing* fixture needs a MANIFEST entry or it fails unaccounted.

---

## Task order (simplest/safest first; validates the loop early)

1. **PY-WL-110** (contradictory decorators) — no arg resolution, near-zero FP. Establishes the rule+fixture+corpus+test loop.
2. **PY-WL-109** (None-leak) — own-scope return walk + guards.
3. **`_sink_helpers.py`** + **PY-WL-106** (deserialization) — builds the shared arg-taint helper, first sink rule.
4. **PY-WL-107** (dynamic-exec) + **PY-WL-108** (OS-command) — reuse the helper, new sink tables.
5. **PY-WL-105** (untrusted arg → trusted callee) — the hardest; callee-trust resolution.
6. **Wire-up + corpus + full gate + tracker/CHANGELOG + review panel.**

Each rule task = RED-first unit test → rule class + metadata → register in `__init__.py` → violation+clean fixtures → MANIFEST entries → unit tests green → **full corpus gate green** → commit.

---

## Task 1 — PY-WL-110: contradictory trust declaration

**Files:** create `src/wardline/scanner/rules/contradictory_trust.py`; test `tests/unit/scanner/rules/test_contradictory_trust.py`; fixture `tests/corpus/fixtures/contradictory.py` + MANIFEST entry; register in `rules/__init__.py`.

**Design.** Fire on an anchored entity (`prov.source=="anchored"`) whose `node.decorator_list` contains **≥2 distinct** grammar boundary markers (match each decorator via the same `(module_prefix, canonical_name)` rule the provider uses — import `BUILTIN_BOUNDARY_TYPES` from `grammar`, OR reuse the resolver). Distinctness is by `canonical_name`. Two `@trusted` (same marker) is NOT contradictory; `@trusted` + `@external_boundary` IS. Reads `entities` + `taint_provenance`. Declaration-gated, base ERROR. Counts markers only — does not infer taint from them (gate stays on resolved `prov.source`).

**FP safety:** closed grammar vocabulary; ignores non-trust decorators (`@staticmethod`, `@app.route`). Near-zero FP.

- [ ] RED test: an entity with `@trusted` + `@external_boundary` → one finding; `@trusted` alone, `@trusted`+`@staticmethod`, two `@trusted` → none.
- [ ] Implement (mirror `broad_exception.py` shape; resolve decorator FQNs via the alias map if available, else by `_dotted_name` last-segment + prefix against `BUILTIN_BOUNDARY_TYPES`). NOTE: prefer matching on the grammar's boundary-type `canonical_name`s so custom types count too.
- [ ] Register in `_ALL_RULE_CLASSES`.
- [ ] Fixture `contradictory.py`: `conflicting()` with both decorators (violation) + `single()` with one (clean). MANIFEST: `{rule_id: PY-WL-110, qualname: contradictory.conflicting, label: TRUE_POSITIVE}`.
- [ ] Unit tests green; full corpus gate green; commit.

## Task 2 — PY-WL-109: None leaks from a trusted producer

**Files:** `rules/none_leak.py`; test; fixture `none_leak.py` + MANIFEST; register.

**Design.** Anchored entity, `prov.source=="anchored"`, `declared = project_return_taints[qualname]` not in raw zone (trust-claim gate, same as 101), AND `function_return_taints[qualname]` is not None (a value-bearing path exists). Walk own-scope (`_own_statements`) for `ast.Return`: fire iff there is **both** a value-bearing `Return(value=expr)` AND a bare `Return(value=None)` or a fall-through (no terminal return on some path — approximate conservatively: presence of a bare `return`). **Skip generators** (own-scope contains `ast.Yield`/`ast.YieldFrom`). Declaration-gated, base WARN.

**FP safety (the riskiest rule):** require BOTH a value path and a bare-return path (pure-`return None` void functions don't fire — they have no value path; `function_return_taints` is None for them, excluded by the gate). Skip generators. Do NOT fire on `-> T | None` where every path is explicit (we only fire on the *mixed bare+value* shape). Corpus-validate; if FP appears, tighten.

- [ ] RED test: mixed bare+value return in `@trusted(level=ASSURED)` → fire; all-value → none; generator → none; pure `return None` → none.
- [ ] Implement; register; fixtures (`leaks()` mixed = violation; `consistent()` raises instead = clean); MANIFEST TRUE_POSITIVE.
- [ ] Unit tests + full corpus gate green; commit.

## Task 3 — `_sink_helpers.py` + PY-WL-106 (deserialization)

**Files:** create `rules/_sink_helpers.py`; `rules/untrusted_to_deserialization.py`; tests; fixture `deser_sink.py` + MANIFEST; register.

**`_sink_helpers.py`** (shared by 106/107/108):
```python
# Resolve the taint of a single call argument expression, CONSERVATIVELY.
# - ast.Name           -> function_var_taints[qualname].get(name, body_tier)
# - ast.Call (nested)  -> the callee's resolved return taint, if resolvable to a
#                         known entity; else body_tier
# - anything else      -> None  (UNKNOWN — caller must NOT fire)
# Returns the LEAST-trusted (highest TRUST_RANK) resolved arg taint, or None if
# no argument resolved. Flow-insensitive (final var map) — documented under-precision.
def worst_arg_taint(call, qualname, context) -> TaintState | None: ...

# Yield (call_node, dotted_name) for every own-scope ast.Call whose resolved
# dotted func name is in `sink_names`. Reuses _own_statements + _dotted_name.
def sink_calls(func_node, sink_names) -> Iterator[tuple[ast.Call, str]]: ...

_RAW_ZONE = frozenset({EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW})
```
Rule shape (106/107/108 identical except the sink table + metadata + CWE): tier-modulated (`modulate(base, project_taints[qualname])`); for each `sink_calls(...)` whose `worst_arg_taint` is in `_RAW_ZONE`, emit at the call line.

**PY-WL-106 sink table** (deserialization, dangerous direction): `pickle.loads pickle.load marshal.loads marshal.load yaml.load yaml.load_all` (NOT `yaml.safe_load`; NOT `json.loads` — defer json to opt-in to avoid noise). Base WARN, CWE-502.

- [ ] RED tests for `worst_arg_taint` (Name/nested-call/literal/unknown) AND for the rule (raw arg → fire; trusted arg → none; freedom-zone fn → none via modulate).
- [ ] Implement helper + rule; register; fixtures (`load_untrusted()` violation: `@trusted def f(p): b = read_raw(p); return pickle.loads(b)`; `load_trusted()` clean); MANIFEST.
- [ ] Unit + full corpus gate green; commit.

## Task 4 — PY-WL-107 (dynamic exec) + PY-WL-108 (OS command)

Reuse `_sink_helpers`. **107** sinks: `eval exec compile` (+ bare `eval`/`exec` builtins — handle the non-dotted Name case in `sink_calls`). Base WARN, CWE-95. **108** sinks: `os.system os.popen subprocess.call subprocess.run subprocess.Popen subprocess.check_output subprocess.check_call` — fire on a raw arg (for subprocess, fire when a raw arg is present; note `shell=True` raises severity conceptually but keep it simple: raw arg into any of these in a trusted-tier fn). Base WARN, CWE-78.

- [ ] Extend `sink_calls` to also match bare-name sinks (`eval(...)`) — match when `_dotted_name` is a bare name in the sink set.
- [ ] RED tests + rules + register + fixtures (`exec_sink.py`, `command_sink.py`) + MANIFEST for each.
- [ ] Unit + full corpus gate green; commit (may split 107/108 into two commits).

## Task 5 — PY-WL-105: untrusted arg → trusted callee

**Files:** `rules/untrusted_to_trusted_callee.py`; tests; fixture `trusted_callee.py` + MANIFEST; register.

**Design.** Walk own-scope of EVERY entity for `ast.Call` whose `_dotted_name(node.func)` resolves to a key in `context.entities` that is **anchored-trusted** (`taint_provenance[callee].source=="anchored"` AND `project_taints[callee]` in `{INTEGRAL, ASSURED, GUARDED}` — i.e. the callee consumes/produces trusted data). For each such call, if `worst_arg_taint(call, caller_qualname, context)` is in `_RAW_ZONE` → fire. **Declaration-gated on the callee** (base ERROR). Caller need not be anchored.

**FP safety:** callee must resolve to a known anchored-trusted entity (unresolved callees skipped → under-fire). No keyword/positional param binding → use the callee's whole-body declared tier (conservative). Subsumption: distinct from 101 (return-site) — document mutual non-subsumption.

- [ ] RED test: `store` is `@trusted`, caller passes `read_raw(p)` → fire; caller passes `validate(read_raw(p))` (trusted) → none; callee undecorated → none.
- [ ] Implement; register; fixtures (multi-function: anchored-trusted callee + caller passing raw); MANIFEST TRUE_POSITIVE.
- [ ] Unit + full corpus gate green; commit.

## Task 6 — Wire-up, full gate, docs, review

- [ ] Confirm all 6 in `_ALL_RULE_CLASSES` (order = emission order). Verify `wardline vocab` / `descriptor.py` picks up the new rules (the NG-25 descriptor builds from rule metadata — check `vocabulary.yaml` byte-identity test; regenerate if the descriptor includes rules).
- [ ] Full gate: `make ci` (ruff+mypy+test-cov 90%), `uv run pytest tests/corpus -v` (FP ≤5%, no unaccounted), dogfood `wardline scan src/wardline --fail-on ERROR` stays clean (the new rules must NOT fire on Wardline's own trust-annotated source — if they do, that's either a real finding to baseline or a rule to tighten), warm/cold byte-identical green.
- [ ] Each rule has `examples_violation` + `examples_clean` in its METADATA (DoD: "each with violation/clean fixtures").
- [ ] CHANGELOG `[Unreleased] Added`: the six new rules (ids + one-liners + CWEs).
- [ ] Update the progress tracker: Track 1 T1.5 → ☑; note "≥10 rules" DoD met; Current-position line.
- [ ] **Default code-review panel + static-analysis lens** (false-positive-analyst on the new rules' FP economics; rule-designer/SAE on subsumption + tier choices; security on the sink tables' completeness). Apply convergent must-fixes.
- [ ] Close the Filigree T1.5 issue with `--actor`.

## DoD (gate before done)
- [ ] 10 curated rules registered; each with violation/clean examples + corpus fixtures.
- [ ] Corpus FP rate ≤5%, zero unaccounted findings.
- [ ] `make ci` green; dogfood clean; warm/cold byte-identical green; `vocabulary.yaml` regenerated if needed.
- [ ] No rule fires on the freedom zone (undecorated code) — opt-in/fail-closed preserved.
- [ ] Review panel run; subsumption relationships documented (esp. 105 vs 101, 109 vs 102).
