# Pre-Rust Core Hardening — Plan (review-hardened)

## Context

Wardline is about to migrate its analysis **core** to Rust (PyO3 + maturin abi3 wheels — the pydantic-core packaging model; the Python CLI/MCP/decorators/scanner stay Python and import the compiled `wardline.core`). `packages/loom-markers/` stays pure-Python zero-dep forever. Before any Rust work, three Python-side hazards must be removed first, because the rewrite would amplify each:

- **Task A (do FIRST):** freeze the current engine's externally-observable **identity** as a byte-exact golden corpus + parity test — the load-bearing safety net that proves the future Rust engine reproduces Wardline's `fingerprint`s/`qualname`s/spans/facts before any cutover. Downstream Filigree associations and Clarion taint-fact bindings key on these; silent drift would orphan every association.
- **Task B (SECOND):** promote the on-disk NG-25 descriptor (`vocabulary.yaml`) to *the* versioned cross-product contract (add a self-describing `schema` field, ADR, federation-doc retirement note, Clarion hand-off) so once `wardline.core` is native, nothing outside Wardline imports it.
- **Task C (THIRD):** a declarative native-module allowlist so a compiled `wardline.core` (no Python AST) doesn't light up `WLN-ENGINE-UNKNOWN-IMPORT` on the self-scan.

This plan was reviewed by a 4-reviewer panel (reality / architecture / quality / systems); their convergent findings are folded in below. A companion bite-sized TDD task doc was drafted at `docs/superpowers/plans/2026-06-05-wardline-pre-rust-core-hardening.md` (predates the review fixes — **re-sync it as execution step 0**).

**Process constraints (all tasks):** TDD (failing test first); attribute filigree events `--actor wardline`; each external-contract change gets an ADR under `docs/decisions/` (date-slug, **no** ADR-NNN; the brief's `docs/architecture/decisions/` does not exist here); behaviour-preserving except Task B's additive `schema` field; do not touch `packages/loom-markers/` except to confirm zero-dep; subagents NEVER run git.

---

## Verified reality (from review panel, file:line)

- `descriptor.build_vocabulary_descriptor`/`descriptor_to_yaml`, `registry.{REGISTRY,REGISTRY_VERSION}` (=`"wardline-generic-2"`), `core/vocabulary.yaml` (wheel-shipped), `wardline vocab`, MCP `wardline://vocab`, and the **byte-identity drift test** (`tests/unit/core/test_descriptor.py::test_committed_vocabulary_yaml_matches_registry`) all already exist. Task B is mostly built — what's missing is the `schema` field, ADR, federation note, Clarion hand-off.
- Capture entry points (pure, reuse — do not reimplement): `core/run.run_scan(root,…)` (`run.py:78`); `clarion/facts.build_taint_facts(result, root)` (`facts.py:54`, needs `blake3` via `wardline[clarion]`); `core/sarif.build_sarif(findings, context)` (`sarif.py:127`, **embeds `__version__` at `sarif.py:152`**); `core/explain.explanation_from_context(finding, context)` (`explain.py:41`, pure — NOT `explain_finding`, which re-runs); `core/assure.build_posture(root).to_dict()` (`assure.py:233` / `cli/assure.py:46`).
- `Finding` (`finding.py:88-106`) has top-level `rule_id,message,severity,kind,location,fingerprint,qualname,properties, suppressed(SuppressionState), suggestion, confidence, related_entities, suppression_reason, maturity`; `Finding.to_jsonl()` (`finding.py:107`) is the real wire format. `Location`: `path,line_start,line_end,col_start,col_end`. Fingerprint = `sha256(rule_id\0path\0line_start\0qualname\0taint_path)`; `path` is repo-relative.
- `scanner/diagnostics.diagnose_unknown_imports(*, tree, module_path, project_modules, stdlib_keys, resolvable_star_modules)`; `_BUILTIN_MARKER_IMPORTS` is a **dict** (`diagnostics.py:25`, decorator *names* only — not the `taints` module); `project_modules` built at `analyzer.py:604`. Scanning `src/` today emits **zero** `wardline.*` unknown imports (forward-looking hazard only).
- **`TaintState` has no `TRUSTED`** — members `INTEGRAL,ASSURED,GUARDED,EXTERNAL_RAW,UNKNOWN_RAW,UNKNOWN_GUARDED,UNKNOWN_ASSURED,MIXED_RAW`; boundary levels `{GUARDED,ASSURED}`, trusted levels `{INTEGRAL,ASSURED}`. Decorators accept string tokens (sampleapp uses `"ASSURED"`).
- **`wardline scan . --fail-on ERROR` already exits 1** on main (intentional ERROR fixtures under `tests/`, no root `wardline.yaml`/baseline). CI dogfoods `wardline scan src` (`ci.yml:76`). CI test matrix runs **Python 3.12 + 3.13** (`ci.yml:53`); `pytest-randomly` is installed.
- Clarion: `plugin.toml wardline_aware = false`; no live `import wardline.core.registry` found in `plugins/python/src/`. The "half-migrated hazard" is likely **dormant** — frame the retirement as "Wardline side ready; Clarion switch pending (`clarion-1f6241b329`)", not as an active break.

---

## Task 0 — Filigree tracking + re-sync the doc plan

- Re-sync `docs/superpowers/plans/2026-06-05-wardline-pre-rust-core-hardening.md` with the fixes in this file (or treat this file as source of truth).
- Filigree (CLI verbs verified): `filigree types` (not `type-list`) to check the type set; create a milestone (parent issue or shared label `pre-rust-hardening` if no milestone primitive) + 3 children (A/B/C) with A→{B,C} dependency; claim with `filigree start-work <id> --assignee wardline --actor wardline`; comment with `filigree add-comment <id> "<text>" --actor wardline` (positional text, **no** `--body`); close with `filigree close <id> --actor wardline`.

---

## Task A — Identity / SEI parity oracle  *(brief Task 2; FIRST)*

**Critical files (all new):** `tests/golden/identity/{fixtures/,_capture.py,corpus/,regen.py,test_identity_parity.py,conftest.py,README.md,__init__.py}`, `tests/golden/__init__.py`, `.gitattributes`; ADR `docs/decisions/2026-06-05-wardline-finding-identity-frozen-contract.md`.

### Scope of the oracle (review-driven decision; user-confirmed)
Capture the **identity-bearing** surface only, via ONE positive allowlist predicate applied at every per-finding surface (NOT a denylist — a denylist leaks for a future `WLN-SECURITY-*` DEFECT rule or a `PY-WL-*` FACT rule):

```python
def _is_identity_bearing(f) -> bool:   # finding.py: Kind.DEFECT, rule_id "PY-WL-*"
    return f.rule_id.startswith("PY-WL-") and f.kind is Kind.DEFECT
```
Verified on the chosen fixture: `testo/sampleapp` emits 1 `PY-WL-101 (defect, ERROR)` plus engine noise (5 `WLN-ENGINE-UNKNOWN-IMPORT`, metrics, `WLN-L3-LOW-RESOLUTION`); the predicate keeps only the `PY-WL-101`. The engine noise is the app's own unresolved imports — NOT `wardline.core` — so Task C never touches it. Excluding it is what makes the oracle a true *cross-engine* contract (a Rust resolver may legitimately differ on import diagnostics) and is the durable fix for the Task-C-breaks-parity defect.

- **findings:** identity-bearing findings only, serialized via `Finding.to_jsonl()` (real wire format — message/qualname/span/fingerprint/properties/suppressed/maturity/etc.; already `sort_keys=True`, no `default=str`; JSON-parse then re-canonicalize).
- **SARIF:** call `build_sarif(<identity-filtered findings>, context)` — note `build_sarif` itself only drops `Kind.METRIC` (`sarif.py:136`), NOT `Kind.FACT`, so the corpus MUST pass it the pre-filtered list. Then **normalize `runs[0].tool.driver.version`** (`sarif.py:152`, the mutable tool version) to a sentinel; the static `version: "2.1.0"` (`sarif.py:144`, SARIF spec) and `$schema`/`informationUri` are constants, leave them. **Drop `results[].ruleIndex`** from the frozen projection — it is assigned in finding-emission order (`sarif.py:138-142`) and would be corrupted by sorting `rules` independently; it is fully recoverable from `ruleId`, so dropping it (rather than re-deriving) is the clean fix.
- **taint facts:** `build_taint_facts(result, root)` kept **whole** (Clarion consumes the blob byte-wise), but the **top-level facts array MUST be sorted by `qualname`** (unique per entity = total key) — `build_taint_facts` returns them in analyzer entity-insertion order (a Python-walker artifact a Rust engine won't reproduce). `content_hash_at_compute` is a blake3 of file bytes (engine-independent — safe to gate). The ADR notes that if a specific blob field later proves engine-divergent, per-field normalization is a documented rekey escape hatch.
- **assure posture:** `build_posture(root).to_dict()` (its `unknown[]`/`waiver_debt[]`/`unanalyzed_rule_ids[]` are already internally sorted — verified).
- **explain:** `explanation_from_context(finding, context)` (pure) for a deterministically chosen identity-bearing finding from **each** fixture (`dataclasses.asdict`; all `TaintExplanation` fields are str/int/None).

### Determinism (do BEFORE freezing — the load-bearing step)
1. **Strict canonical encoder** — `to_json` uses `json.dumps(indent=2, sort_keys=True, ensure_ascii=False)` **without `default=str`**; raise on unknown types; unwrap enums via `.value`. A `default=str` fallback would mask hash/address-dependent nondeterminism.
2. **Named-array canonicalization** (explicit per-array, NOT a generic deep-sort — a deep-sort would scramble SARIF `codeFlows[].threadFlows[].locations[]`, which are an *ordered causal taint sequence* that must be preserved): sort top-level findings by `(path, line_start, rule_id, qualname, fingerprint)`; the **top-level taint-facts array by `qualname`**; SARIF `results` by `(uri, startLine, ruleId, fingerprint)` and `rules` by `id` (then drop `ruleIndex`, per scope above); each fact's inner `wardline_json.findings` by `(rule_id, fingerprint)`; `related_entities` tuples sorted. Leave `codeFlows` location sequences in engine order. The cross-process + cross-interpreter proofs (below) backstop any un-enumerated array.
3. **Cross-process proof** — capture in two subprocesses with `PYTHONHASHSEED=0` and `=1`; assert byte-identical.
4. **Path-independence proof** — capture from the fixture dir and from a `copytree` at a different absolute path; assert identical (fingerprints fold in `path`, which must stay relative).
5. **Cross-interpreter** — run the capture under 3.12 and 3.13; if byte-identical, the parity test runs on both; if not, **pin the canonical interpreter (3.13)** and `skipif(sys.version_info[:2] != (3,13))` with rationale. Record the decision in the ADR.
6. Only after 1-5 pass: write `corpus/*.json` via `regen.py`.

### Fixtures
- **Source path moved during this session** — the brief's `/home/john/lacuna/sampleapp/` no longer exists (the user reorganized: it relocated to `/home/john/testo/sampleapp/`, and `/home/john/lacuna/specimen/` is a richer sibling). Vendor from **`/home/john/testo/sampleapp/`** (verified 2026-06-05: 6 files, fires 1 `PY-WL-101 (defect, ERROR)` — the original sampleapp posture of 4 boundaries / 1 defect). `cp /home/john/testo/sampleapp/*.py tests/golden/identity/fixtures/sampleapp/`; strip `__pycache__`; ensure **no `.wardline/`** travels (keeps `date.today()` waiver-expiry in `run.py:188`/`assure.py:248` inert). Vendoring a copy decouples the corpus from the external dir's churn. `/home/john/lacuna/specimen/` (8 boundaries / 4 defects, more rule variety) is a documented alternative if broader realistic-app coverage is wanted — the executor verifies non-vacuity against whatever is vendored.
- Author `fixtures/stress/identity_stress.py`: decorated boundaries via the **public `wardline.decorators` surface only**, levels as **string tokens `"ASSURED"`** (valid; NOT `TaintState.TRUSTED`, which doesn't exist); cover nested/async/overloaded fns, methods, classmethods, decorated classes, lambdas, comprehensions, multi-line signatures, unicode identifiers, and triggers for `PY-WL-101` (untrusted→trusted flow) + a second identity-bearing rule, e.g. `PY-WL-111` (assert-only-boundary / CWE-617) or `PY-WL-118` (sql-injection) — confirm the chosen rule's exact trigger pattern against `src/wardline/scanner/rules/` (PY-WL-111 = `assert_only_boundary.py`, PY-WL-118 = `sql_injection.py`; the round-1 draft mislabeled 111 as "sql"). **No `from wardline.core.* import …`** in the fixture (keeps it free of engine-diagnostic imports; also moot since those are excluded by the identity predicate).
- `.gitattributes`: `tests/golden/identity/fixtures/** text eol=lf` and `tests/golden/identity/corpus/** -text` so CRLF/autocrlf can't flip `blake3` content hashes.

### Tests / harness robustness
- **Import form (CI-correct):** the repo puts `tests/` on `sys.path` (pytest prepend mode; precedent `tests/grammar/test_golden_oracle.py` does `from grammar.golden_harness import …`). So intra-package imports are **`from golden.identity import _capture`** — **NOT** `from tests.golden.identity import …` (that fails under `uv run pytest`). Create `tests/golden/__init__.py` + `tests/golden/identity/__init__.py`; **do NOT create `tests/__init__.py`** (it would relocate the sys.path insert and break the existing `grammar` import). Run regen with `tests/` on the path (e.g. `cd tests && .venv/bin/python -m golden.identity.regen --reason "…"`), and `_capture.py`/`regen.py`/`test_identity_parity.py` all use the `golden.identity` form.
- `pytest.importorskip("blake3")` (or skip facts capture) so a bare `pip install wardline` env skips cleanly rather than erroring; CI has `--all-extras`.
- **Non-vacuity assertion** (a hard test, not a print) — **per input, per surface**: for BOTH fixtures assert findings non-empty, facts count > 0, SARIF `results` non-empty, explain captured; assert `PY-WL-101` present in sampleapp; assert `PY-WL-101` + ≥1 other identity-bearing rule present in the stress fixture; assert `posture.waiver_debt == []`. Prevents a silently-empty/shallow oracle from passing forever.
- **Fixture-hygiene guard:** before capture, assert `not (fixture_root / ".wardline").exists()` and no `wardline.yaml` in the fixture — so a future PR can't add a baseline/waiver that date-poisons the corpus.
- `conftest.py`: on parity failure, write the regenerated `actual` to `/tmp/corpus_actual_<name>.json` and emit a `difflib.unified_diff` head, so an engineer can tell a real regression from an intentional rekey on multi-KB JSON.
- **Regen accountability:** the *real* gate is the parity test itself (CI fails any PR that changes `corpus/*` without a matching production change) plus CODEOWNERS on `tests/golden/identity/corpus/**`; `regen.py --reason "<text>"` + a `corpus/META.json` (corpus_version + reason) is the **accountability record**, not the enforcement (a determined dev can edit corpus files directly — CI + review is what catches that). The ADR frames it this way.

### ADR (`…finding-identity-frozen-contract.md`)
Define `fingerprint`/`qualname`/spans precisely; state path-relativity; **scope** (identity-bearing findings [the `PY-WL-* ∧ Kind.DEFECT` predicate] + facts + SARIF + assure + explain; engine diagnostics excluded and why; note the "Kind.FACT finding" vs `build_taint_facts` payload naming collision so they're not conflated); SARIF `driver.version` normalization + `ruleIndex` drop; facts gated whole with per-field normalization as a documented future escape hatch; the **canonical-interpreter pin** — if 3.12/3.13 capture is not byte-identical, pin 3.13 and `skipif` 3.12, explicitly recording that **3.12 is then NOT identity-gated** (a known coverage trade-off; 3.13 is CI-primary for the non-test jobs anyway); regen accountability (CI parity test + CODEOWNERS is enforcement, `--reason`/META.json is the record); that identity is stable **across engine implementations** and any change is a **separate, versioned, rekey-with-migration** step; and that **"parity corpus green" is a HARD GATE on the Rust cutover** (must not be negotiated away).

---

## Task B — Descriptor as the cross-product contract  *(brief Task 1; SECOND)*

**Critical files:** `src/wardline/core/descriptor.py` (add `schema`), `src/wardline/core/vocabulary.yaml` (regenerate via `wardline vocab > …`), `tests/unit/core/test_descriptor.py` (envelope now 3 fields + `schema` + pure-data-read test); ADR `docs/decisions/2026-06-05-wardline-vocabulary-descriptor-cross-product-contract.md`; `docs/guides/loom.md` (retirement note); hand-off `docs/integration/2026-06-05-wardline-descriptor-clarion-handoff.md`.

- TDD: add `DESCRIPTOR_SCHEMA = "wardline.vocabulary/v1"` emitted first in the envelope (`{"schema","version","entries"}`); a single self-describing string, no version negotiation. `version` stays `REGISTRY_VERSION` (content version) — `schema` is the *format* version. Update the envelope-fields test; regenerate `vocabulary.yaml` so the byte-identity drift test passes.
- Add `test_committed_yaml_is_consumable_as_pure_data`: load `vocabulary.yaml` via `importlib.resources` + `yaml.safe_load`, assert `schema`/`version`/the three canonical entries **without importing `wardline.core.registry`** (proves the read-instead-of-import path).
- **Read-only** verify Clarion's expected shape (`clarion-1f6241b329`); confirm it needs canonical-name/group/attrs, not per-call-site levels (deliberately provider-owned). Do not edit Clarion.
- ADR: descriptor (generated from `REGISTRY`, drift-guarded) is the canonical cross-product contract; schema/stability guarantees; in-process-import coupling retired Wardline-side; `wardline.core` will be native so no peer may import it; **corpus-neutral** (descriptor/`vocabulary.yaml` not in the Task A oracle).
- `loom.md`: state the **Wardline side is ready**; remaining work is Clarion switching `import REGISTRY` → reading `vocabulary.yaml` (`clarion-1f6241b329`). Frame as pending, not an active hazard (Clarion `wardline_aware=false` today).
- Hand-off doc: paste exact `wardline vocab` output, wheel file location, an example read, what Clarion consumes, and the forward-compat rule (tolerate unknown future entry fields; gate on `schema`). Leave a filigree comment pointing to it.
- **Re-run the Task A parity gate** — must stay green (evidence B is corpus-neutral).

---

## Task C — Self-scan: `wardline.core` is first-party / native  *(brief Task 3; THIRD)*

**Critical files:** `src/wardline/scanner/diagnostics.py` (add allowlist), `tests/unit/scanner/test_diagnostics.py` (native-case + guards); ADR `docs/decisions/2026-06-05-wardline-native-module-import-resolution.md`; seam note in `docs/guides/loom.md` or a scanner guide.

- Add a **declarative module-level constant** (sibling to `_BUILTIN_MARKER_IMPORTS`, but a prefix set, not alias-specific):
  `_NATIVE_FIRST_PARTY_PREFIXES: frozenset[str] = frozenset({"wardline.core", "wardline.decorators"})` + `_is_native_first_party(mod)` returning `any(mod == p or mod.startswith(p + ".") for p in …)`. In `diagnose_unknown_imports`, after `if mod in project_modules: continue`, add `if _is_native_first_party(mod): continue`. (Constant satisfies "declarative"; YAML manifest is YAGNI for two entries — recorded in ADR.)
- **Failing-first test simulates the native case** (the obvious "scan self, assert no wardline.core unknown" is green today and gates nothing): build `project_modules=frozenset()` (as a `.so` presents) and assert `from wardline.core.registry import REGISTRY` resolves to `[]`; same for `wardline.decorators`. Guards: a genuine `from acme_totally_unknown_pkg import x` **still fires**; `wardline.experimental.zzz` (undeclared) **still fires**; `wardline.core_helpers` (adjacent prefix) is **not** suppressed (protects the `+ "."` boundary).
- Verify behaviour-neutrality: `wardline scan src --format jsonl` still emits 0 `WLN-ENGINE-UNKNOWN-IMPORT` in `src` (no regression).
- ADR: the allowlist concept, why (compiled core has no AST), declarative prefix mechanism, no over-suppression (guarded), and that **this list is the seam the Rust migration extends**.
- **Re-run the Task A parity gate** — stays green (engine diagnostics are out of corpus scope, so even pre-fix this holds; double assurance).

---

## Verification (end-to-end)

- `.venv/bin/pytest tests/golden/identity -q` — parity + non-vacuity green; collected in CI (`tests/golden/__init__.py` + `tests/golden/identity/__init__.py` added; in-test import is `from golden.identity import _capture`, NOT `tests.golden…`; no `tests/__init__.py`; CI `testpaths=["tests"]` auto-collects).
- Cross-process (`PYTHONHASHSEED=0` vs `=1`) and path-independence proofs pass; cross-interpreter decision recorded.
- `.venv/bin/pytest tests/unit/core/test_descriptor.py tests/unit/scanner/test_diagnostics.py -q` green.
- `.venv/bin/pytest -q` full suite green; `ruff`/`mypy` clean.
- **Gate:** `.venv/bin/wardline scan src --fail-on ERROR` clean (exit 0). NOTE the brief's literal `wardline scan . --fail-on ERROR` exits 1 on main today (pre-existing tests/ ERROR fixtures, no root config) — `scan src` is the real green dogfood gate (matches CI). Flag this discrepancy to the PO; do not "fix" unrelated tests/ fixtures to satisfy a `.`-scoped gate.
- `packages/loom-markers/` confirmed untouched + zero-dep.
- Three ADRs present; federation note + Clarion hand-off written; all filigree items closed.

## PO note (leave on the milestone)
1. **Clarion hand-off:** Wardline ships the versioned descriptor (`vocabulary.yaml`, `schema = wardline.vocabulary/v1`). The asterisk is half-retired; the other half is Clarion switching `import wardline.core.registry.REGISTRY` → reading the descriptor (`clarion-1f6241b329`). Doc: `docs/integration/2026-06-05-wardline-descriptor-clarion-handoff.md`.
2. **Identity oracle frozen + ready to gate the Rust cutover.** Treat "parity corpus green" as a **hard gate** on the Rust core landing — state it explicitly when commissioning the Rust work. Add **`clarion-1f6241b329` closed (or a thin Python REGISTRY shim) as a second Rust-cutover prerequisite**, so the native extension can't silently break a Clarion probe activated in the interim.
3. **Gate discrepancy:** `wardline scan . --fail-on ERROR` is not green on main (pre-existing); the project dogfoods `wardline scan src`.

## Decisions made (override at approval if desired)
- Oracle scope = positive predicate `PY-WL-* ∧ Kind.DEFECT` at every per-finding surface (findings + SARIF input); engine diagnostics excluded (true cross-engine contract; durably fixes Task-C-breaks-parity). Taint facts kept whole (sorted by qualname).
- Fixture source = `/home/john/testo/sampleapp/` (the relocated sampleapp — original `lacuna/sampleapp` was removed mid-session; fires PY-WL-101) + a purpose-built stress fixture; vendored into the repo to decouple from external churn. `lacuna/specimen` is the richer fallback.
- SARIF: normalize `driver.version`, drop `ruleIndex`, preserve `codeFlows` order.
- Canonical interpreter pinned (3.13) if cross-version byte-identity doesn't hold (3.12 then not identity-gated — recorded in ADR).
- Native-module list = module constant (not YAML manifest).
- Dogfood gate = `scan src` (the green one; brief's literal `scan .` exits 1 on main), discrepancy surfaced to PO.

## Round-2 review status
8/9 round-1 findings verified CLOSED at source (no new hallucinations); the 9th (array canonicalization) extended to cover SARIF `ruleIndex` + top-level facts array. New round-2 fixes folded in above: fixture path relocation, pytest import form (`golden.identity` not `tests.golden`), `ruleIndex` drop, facts-array sort, positive identity predicate, `codeFlows` order preservation, PY-WL-111 relabel, per-input non-vacuity, fixture-hygiene guard, cross-interp 3.12 coverage-hole note, regen-accountability reframe. No architectural change; all fixture/harness/spec level.
