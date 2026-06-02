# Workstream D1 — `assure` coverage posture + waiver-debt rollup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single structured read — `assure` — that reports Wardline's trust-surface *coverage* (how much of the declared trust surface the engine could conclusively reason about vs. how much is honestly unknown), plus a waiver-debt rollup, identical over MCP and CLI.

**Architecture:** A pure core aggregator (`core/assure.py`) runs one `run_scan`, classifies every **anchored** entity (a function carrying a trust decorator) by reusing the *same* per-entity verdict logic the dossier already uses, and rolls up waiver expiry from config. CLI (`wardline assure`) and the MCP `assure` tool are thin delegators to that one function — identical by construction. Adds one additive, defaulted field to `AnalysisContext` so the anchored set is read from engine output, not re-derived.

**Tech Stack:** Python 3, stdlib only (zero-dep base), `click` (scanner extra) for the CLI, existing `run_scan`/`AnalysisContext`/`core/taints`/`core/waivers`/`core/dossier` machinery.

---

## Design decisions (pinned BEFORE code — read first)

### What is the "trust surface" (the denominator)?

**The trust surface = the set of anchored entities** — functions/methods carrying one of the three trust decorators (`@external_boundary`, `@trust_boundary`, `@trusted`). These are exactly the entities that *claim* a trust level; Wardline's whole question ("is the data this function works with as trusted as it claims?") only applies to them. Undecorated code is the developer-freedom zone and is **not** counted — counting it would punish a project for having ordinary un-annotated functions and make coverage meaningless.

> The tracked issue says "anchored entities + boundary-crossing call edges." We deliberately scope v1's denominator to **anchored entities only**. A call-edge-weighted denominator is a richer future metric; coverage over *declared boundaries* is the honest, hand-countable v1 and is what `coverage_pct` and (later) `attest`'s headline number both ride on. This scoping is intentional and documented; it is not an under-build.

**Authoritative anchored set:** an entity is anchored iff the L1 provider seeded it from a declaration (`FunctionSeed.source == "provider"`). The analyzer already computes this per module; we surface it additively on the context as `declared_qualnames: frozenset[str]`. We do **not** re-parse decorators in `assure` (that would drift from the engine's own matching).

### Per-entity classification (reuse, do not re-invent)

For each anchored qualname, classify with the **same** verdict logic `core/dossier._build_trust` uses (extracted to a shared helper so the two cannot drift):

- **defect** — an *active* finding fires on the entity.
- **unknown** — the engine under-scanned it (a `WLN-ENGINE-*` under-scan FACT for this qualname, or no computed `function_return_taints` entry).
- **proven** — a declared posture that conforms: not defect, not unknown.

(An anchored entity always has a declared tier, so the dossier's "undeclared → unknown" branch does not apply here, but we reuse the exact same function regardless.)

### Coverage definition (load-bearing — hand-counted in the fixture)

```
coverage_pct = round(100 * (boundaries_total - unknown_count) / boundaries_total, 1)   # 100.0 when boundaries_total == 0
```

Coverage is the fraction of the trust surface for which the engine reached a **definite** verdict (proven clean **or** active defect) — i.e. *not* unknown. This matches Wardline's fail-closed thesis: coverage measures "what we know either way"; `unknown` is the honesty gap. A defect counts as *covered* (we analysed it and it is bad). The object also carries `proven`, `defect_total`, and `engine_limited` explicitly so the agent never has to do arithmetic (frictionless: structured output).

`engine_limited` (the issue's "J") = the subset of `unknown` entities whose unknown-ness is caused by an engine under-scan FACT (parse/recursion skip), as opposed to a missing return taint for other reasons. It is a sub-count of `unknown`, reported alongside `unanalyzed_rule_ids` (the distinct under-scan rule ids seen anywhere in the scan).

### The posture object (exact shape)

```json
{
  "boundaries_total": 7,
  "proven": 5,
  "defect_total": 1,
  "unknown": [
    {"qualname": "pkg.mod.f", "tier": "GUARDED", "location": {"path": "pkg/mod.py", "line": 12}, "reason": "..."}
  ],
  "engine_limited": 1,
  "coverage_pct": 85.7,
  "unanalyzed_rule_ids": ["WLN-ENGINE-FUNCTION-SKIPPED"],
  "waiver_debt": [
    {"fingerprint": "….", "expires": "2026-07-01", "days_left": 28, "reason": "third-party shim"}
  ],
  "baselined_total": 3,
  "judged_total": 0
}
```

**Determinism (hard requirement — suite runs under `pytest-randomly`):** every list is sorted — `unknown` by `qualname`, `waiver_debt` by `fingerprint`, `unanalyzed_rule_ids` lexicographically. The whole object is built deterministically so it can later feed `attest`'s reproducibility claim.

`waiver_debt`: one entry per *configured* waiver (from `wardline.yaml`'s `waivers:`), with `days_left = (expires - today).days` (negative if already expired — surfaced honestly, not dropped) and `expires: null` / `days_left: null` for a waiver with no expiry. `today` is injectable for tests (defaults to `date.today()`).

`baselined_total` / `judged_total`: counts of suppressed defects in those classes across the whole scan (from the scan summary), so the agent sees accepted debt alongside coverage.

---

## File Structure

- **Create** `src/wardline/core/assure.py` — `AssurancePosture` dataclass (+ `to_dict`), `WaiverDebtEntry`, `UnknownBoundary`, and `build_posture(root, *, config_path=None, confine_to_root=False, today=None) -> AssurancePosture`.
- **Modify** `src/wardline/core/dossier.py` — extract the per-entity verdict into a public `classify_entity_trust(result, context, qualname) -> EntityTrustVerdict` (a small frozen dataclass: `verdict`, `declared_tier`, `actual_tier`, `under_scan_reason`); promote `_UNKNOWN_TIERS`/`_UNDER_SCAN_RULE_IDS` to public `UNKNOWN_TIERS`/`UNDER_SCAN_RULE_IDS`. `_build_trust` calls the shared classifier (behavior-preserving — existing dossier tests are the gate).
- **Modify** `src/wardline/scanner/context.py` — add `declared_qualnames: frozenset[str] = frozenset()` (additive, defaulted, wrapped in `__post_init__` like the others — `frozenset` is already immutable so just assign).
- **Modify** `src/wardline/scanner/analyzer.py` — populate `declared_qualnames` from `modules`' seeds (`source == "provider"`) when constructing `AnalysisContext`.
- **Create** `src/wardline/cli/assure.py` — `wardline assure` (JSON default, `--format human`).
- **Modify** `src/wardline/cli/main.py` — register `assure`.
- **Modify** `src/wardline/mcp/server.py` — add `_assure(args, root)` handler + register the `assure` tool.
- **Modify** `tests/conformance/test_mcp_handshake.py` — add `assure` to the expected tool set.
- **Create** tests: `tests/unit/core/test_assure.py`, `tests/unit/cli/test_assure_cmd.py`, `tests/unit/mcp/test_server_assure.py`.
- **Modify** `tests/unit/scanner/` (a context/analyzer test) — assert `declared_qualnames` is populated.
- **Docs**: `docs/guides/assurance-posture.md` + nav + CHANGELOG `[Unreleased] Added`.

---

## Task 1: Surface the anchored set on the context (additive)

**Files:**
- Modify: `src/wardline/scanner/context.py`
- Modify: `src/wardline/scanner/analyzer.py:364` (the `AnalysisContext(...)` construction)
- Test: `tests/unit/scanner/test_analyzer_declared_qualnames.py` (create)

- [ ] **Step 1: Write the failing test.** A tiny project: one `@trusted(level='INTEGRAL')` function `m.good`, one `@external_boundary` function `m.src`, one undecorated `m.plain`. Run `WardlineAnalyzer().analyze(...)` (or `run_scan`) and assert `context.declared_qualnames == frozenset({"m.good", "m.src"})` (the undecorated `m.plain` is absent).

```python
def test_declared_qualnames_lists_only_anchored(tmp_path):
    (tmp_path / "m.py").write_text(
        "from wardline.decorators.trust import trusted, external_boundary\n"
        "@trusted(level='INTEGRAL')\n"
        "def good():\n    return 1\n"
        "@external_boundary\n"
        "def src():\n    return input()\n"
        "def plain():\n    return 2\n"
    )
    result = run_scan(tmp_path)
    assert result.context is not None
    assert result.context.declared_qualnames == frozenset({"m.good", "m.src"})
```

- [ ] **Step 2: Run it — expect FAIL** (`AnalysisContext` has no `declared_qualnames`). Run: `uv run pytest tests/unit/scanner/test_analyzer_declared_qualnames.py -v`.

- [ ] **Step 3: Add the field.** In `context.py`, add to `AnalysisContext` after `class_attr_taints`:

```python
    # Qualnames of entities the L1 provider seeded from a DECLARATION (a trust
    # decorator) — the "trust surface". Read by core/assure.py as the coverage
    # denominator. Additive + defaulted so direct constructions/tests need not
    # supply it; frozenset is already immutable so no proxy wrap is needed.
    declared_qualnames: frozenset[str] = frozenset()
```

- [ ] **Step 4: Populate it in the analyzer.** At the `AnalysisContext(...)` construction (~line 364), add `declared_qualnames=frozenset(q for m in modules for q, s in m.seeds.items() if s.source == "provider")`. (`modules` is in scope from the discovery loop; `ModuleInput.seeds` is `{qualname: FunctionSeed}`.)

- [ ] **Step 5: Run the test — expect PASS.** Then run the full scanner suite to confirm no regression: `uv run pytest tests/unit/scanner -q`.

- [ ] **Step 6: Commit.** `git add -A && git commit -m "feat(engine): surface anchored (trust-declared) set on AnalysisContext"`

---

## Task 2: Extract the shared per-entity verdict classifier

**Files:**
- Modify: `src/wardline/core/dossier.py:47-56` (constants), `:480-526` (`_build_trust`)
- Test: `tests/unit/core/test_dossier.py` (existing — must stay green), `tests/unit/core/test_classify_entity.py` (create)

- [ ] **Step 1: Write the failing test** for the new public classifier:

```python
def test_classify_entity_trust_proven_defect_unknown(tmp_path):
    # build a tree with one clean @trusted, one violating @trusted (PY-WL-101),
    # one @trusted whose body recurses too deep (engine under-scan) — assert
    # classify_entity_trust(...).verdict is "clean"/"defect"/"unknown" respectively
    ...
```

(Keep it focused: 2–3 entities, assert the `.verdict` strings and that `.declared_tier` is the declared value.)

- [ ] **Step 2: Run it — expect FAIL** (no `classify_entity_trust`). Run: `uv run pytest tests/unit/core/test_classify_entity.py -v`.

- [ ] **Step 3: Extract the classifier.** In `dossier.py`:
  - Rename `_UNKNOWN_TIERS` → `UNKNOWN_TIERS`, `_UNDER_SCAN_RULE_IDS` → `UNDER_SCAN_RULE_IDS` (update internal refs).
  - Add a frozen dataclass + function:

```python
@dataclass(frozen=True, slots=True)
class EntityTrustVerdict:
    verdict: str  # "defect" | "clean" | "unknown"
    declared_tier: str | None
    actual_tier: str | None
    under_scan_reason: str | None


def classify_entity_trust(result: ScanResult, context: AnalysisContext, qualname: str) -> EntityTrustVerdict:
    """The single source of truth for one entity's trust verdict (defect/clean/unknown).
    Reused by the dossier TrustSection and by core/assure — identical by construction."""
    declared = context.project_return_taints.get(qualname)
    actual = context.function_return_taints.get(qualname)
    has_active = any(
        f.qualname == qualname and f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE
        for f in result.findings
    )
    under_scan = next(
        (f for f in result.findings if f.qualname == qualname and f.rule_id in UNDER_SCAN_RULE_IDS),
        None,
    )
    declared_str = declared.value if declared is not None else None
    if has_active:
        verdict = "defect"
    elif under_scan is not None or actual is None:
        verdict = "unknown"
    elif declared_str is None or declared_str in UNKNOWN_TIERS:
        verdict = "unknown"
    else:
        verdict = "clean"
    return EntityTrustVerdict(
        verdict=verdict,
        declared_tier=declared_str,
        actual_tier=actual.value if actual is not None else None,
        under_scan_reason=under_scan.message if under_scan is not None else None,
    )
```

  - Rewrite `_build_trust` to call `classify_entity_trust(...)` for the verdict/declared/actual/reason, keeping its own `active_findings`/`suppressed_findings` projection. **Behavior must be identical** — the existing `test_dossier.py` is the gate.

- [ ] **Step 4: Run both** — `uv run pytest tests/unit/core/test_classify_entity.py tests/unit/core/test_dossier.py -v`. Expect PASS for both (dossier unchanged in behavior).

- [ ] **Step 5: Commit.** `git commit -am "refactor(dossier): extract shared classify_entity_trust (behavior-preserving)"`

---

## Task 3: The `build_posture` aggregator

**Files:**
- Create: `src/wardline/core/assure.py`
- Test: `tests/unit/core/test_assure.py`

- [ ] **Step 1: Write the hand-computed fixture test FIRST** (the gate per the advisor — do not back-fit). Build a tree with a known, hand-counted trust surface, e.g.:
  - `m.clean` `@trusted(level='INTEGRAL')` returning a constant → **proven**.
  - `m.leak` `@trusted(level='INTEGRAL')` returning `input()` → **defect** (PY-WL-101 active).
  - `m.boundary` `@trust_boundary(to_level='GUARDED')` that validates → **proven** (or defect if it can't reject — pick a clean one).
  - `m.deep` `@trusted(level='INTEGRAL')` whose body is engineered to trip the L2 recursion skip → **unknown / engine_limited**. (If reliably tripping recursion is impractical in a fixture, instead assert the unknown/engine_limited branch with a direct `AnalysisContext` unit test in a second test function, and keep the e2e fixture to proven+defect.)
  - One waiver in `wardline.yaml` with `expires` 28 days after a pinned `today`.

  Assert the full `build_posture(tmp_path, today=PINNED).to_dict()` equals the hand-computed object (boundaries_total, proven, defect_total, unknown list, coverage_pct, waiver_debt days_left, baselined/judged totals). **Hand-count every number in a comment.**

- [ ] **Step 2: Run — expect FAIL** (`core/assure` missing). Run: `uv run pytest tests/unit/core/test_assure.py -v`.

- [ ] **Step 3: Implement `core/assure.py`.** Dataclasses `UnknownBoundary(qualname, tier, path, line, reason)`, `WaiverDebtEntry(fingerprint, expires, days_left, reason)`, `AssurancePosture(...)` each with `to_dict()` (object shape above; `coverage_pct` computed as defined; lists sorted). `build_posture`:

```python
def build_posture(root, *, config_path=None, confine_to_root=False, today=None):
    today = today or date.today()
    result = run_scan(root, config_path=config_path, confine_to_root=confine_to_root)
    ctx = result.context
    if ctx is None:
        # whole scan failed to produce a context — honest empty surface, never a crash
        ...
    anchored = sorted(ctx.declared_qualnames)
    proven = defect = 0
    unknown: list[UnknownBoundary] = []
    engine_limited = 0
    for q in anchored:
        v = classify_entity_trust(result, ctx, q)
        if v.verdict == "clean": proven += 1
        elif v.verdict == "defect": defect += 1
        else:
            ent = ctx.entities.get(q)
            unknown.append(UnknownBoundary(q, v.declared_tier, ent.location.path if ent else None,
                                           ent.location.line_start if ent else None, v.under_scan_reason))
            if v.under_scan_reason is not None: engine_limited += 1
    total = len(anchored)
    coverage = 100.0 if total == 0 else round(100 * (total - len(unknown)) / total, 1)
    # waiver_debt from config waivers; baselined/judged from result.summary
    ...
```

  Load waivers via the same path `run_scan` uses (`config_mod.load(cfg_path).waivers` → `parse_waivers`); `unanalyzed_rule_ids` = sorted distinct `f.rule_id for f in result.findings if f.rule_id in UNDER_SCAN_RULE_IDS` (use the dossier-public constant — covers file AND function under-scans, matching `engine_limited`). `baselined_total`/`judged_total` from `result.summary`.

- [ ] **Step 4: Run — expect PASS.** Iterate until the hand-computed fixture matches.

- [ ] **Step 5: Dogfood sanity.** `uv run python -c "from pathlib import Path; from wardline.core.assure import build_posture; import json; print(json.dumps(build_posture(Path('src/wardline')).to_dict(), indent=2))"` — eyeball: coverage on Wardline's own annotated tree is plausible, waiver_debt reflects any waivers.

- [ ] **Step 6: Commit.** `git commit -am "feat(core): assure trust-surface posture + waiver-debt aggregator"`

---

## Task 4: CLI `wardline assure`

**Files:**
- Create: `src/wardline/cli/assure.py`
- Modify: `src/wardline/cli/main.py`
- Test: `tests/unit/cli/test_assure_cmd.py`

- [ ] **Step 1: Write failing tests** — `wardline assure <path>` prints the posture as JSON (parse stdout, assert keys); `--format human` prints a readable summary line containing the coverage %; exit 0 on success. Use `CliRunner`.

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** the command (mirror `cli/dossier.py` structure): args `path` (default `.`), `--config`, `--format [json|human]` (default `json`). Delegate to `build_posture`; JSON via `json.dumps(posture.to_dict())`; human via a small formatter. Map `WardlineError` → `error: …` + exit 2.

- [ ] **Step 4: Register** in `main.py` (`from wardline.cli.assure import assure` + `cli.add_command(assure)`).

- [ ] **Step 5: Run — expect PASS**, then `uv run wardline assure src/wardline` and `--format human` by hand.

- [ ] **Step 6: Commit.** `git commit -am "feat(cli): wardline assure (trust-surface coverage posture)"`

---

## Task 5: MCP `assure` tool (CLI=MCP parity)

**Files:**
- Modify: `src/wardline/mcp/server.py`
- Modify: `tests/conformance/test_mcp_handshake.py`
- Test: `tests/unit/mcp/test_server_assure.py`

- [ ] **Step 1: Write failing tests** — call the `assure` handler with `{"path": ...}`; assert the returned dict equals `build_posture(...).to_dict()` for the same tree (**parity test** — the MCP result is byte-identical to the core object / CLI JSON). Add an entry to the handshake tool-set test.

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** `_assure(args, root)` near `_dossier` — resolve the (confined) path under root like the other handlers, call `build_posture(resolved, config_path=..., confine_to_root=True)`, return `.to_dict()`. Register the tool with `input_schema` `{path?, config?}` and a description framing it as the pre-trust-decision posture read. Map `WardlineError` to the tool-execution error payload (the existing `_scan`/`_dossier` error path).

- [ ] **Step 4: Run — expect PASS** (incl. the updated handshake test).

- [ ] **Step 5: Commit.** `git commit -am "feat(mcp): assure tool (CLI=MCP trust-surface posture parity)"`

---

## Task 6: Docs + CHANGELOG

**Files:**
- Create: `docs/guides/assurance-posture.md`; Modify: `mkdocs.yml` nav, `CHANGELOG.md`

- [ ] **Step 1:** Write `docs/guides/assurance-posture.md`: what the trust surface is, the coverage definition (definite-verdict / unknown honesty gap), the object shape, an agent-first MCP example, and the waiver-debt rollup. Frame around agent-mediated consumption ("here's what we don't know").
- [ ] **Step 2:** Add it to `mkdocs.yml` nav; add a `[Unreleased] Added` CHANGELOG line.
- [ ] **Step 3:** `uv run mkdocs build --strict` to confirm the nav/build is clean.
- [ ] **Step 4: Commit.** `git commit -am "docs: assurance posture (wardline assure) guide"`

---

## Final gate (controller runs after all tasks)

- `uv run pytest` (full suite, random order) — green.
- `uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy` — clean.
- `uv run wardline scan src/wardline --fail-on ERROR` — dogfood exit 0 (no new self-findings).
- Confirm the five frictionless criteria for `assure`: one round-trip (single scan), structured (the posture object), zero-config (no new config), CLI=MCP (parity test), fail-closed (unknown surfaced honestly, never a false-green coverage of 100% over an under-scanned surface).
