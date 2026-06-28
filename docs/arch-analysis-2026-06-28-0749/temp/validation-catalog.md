# Validation Report — 02-subsystem-catalog.md

**Document under review:** `docs/arch-analysis-2026-06-28-0749/02-subsystem-catalog.md`
**Contract:** `temp/catalog-spec.md` (entry template + S1–S12 legend + evidence mandates)
**Canonical file map:** `temp/file-map.tsv` (182 files, one subsystem each)
**Target:** wardline @ `e4668abc`
**Validator:** analysis-validator (independent, fresh-eyes)
**Date:** 2026-06-28

---

## VERDICT: PASS-WITH-NOTES

The catalog is structurally sound, fully covers the 12 subsystems and all 182 mapped
files, conforms to the entry schema, and carries high-quality `path:line` evidence (8/8
adversarial spot-checks matched to the line; the headline layering finding was
independently reproduced by this validator). It is **usable as input to
`05-quality-assessment.md`** after **one required correction** plus a short list of
low-severity notes.

There is exactly one substantive defect: an **internal contradiction in S3's Concerns**
on the load-bearing headline finding. It does not invalidate the headline finding (which
is correct), but it must be fixed because a reader of S3 in isolation is told the
opposite of the truth. No BLOCK condition holds (no missing sections, no fabricated
citations, no coverage gap, headline finding empirically correct).

**Headline framing for the consumer:** the *cross-cutting synthesis layer* needs a small
correction pass (the two highest-value findings below both sit in or around the
orchestrator's cross-cutting header / its supporting entries); the *individual subsystem
entries are largely sound*.

---

## Dimension 1 — Coverage: PASS

- **All 12 subsystems S1–S12 present**, each as a `## SX — <Label>` section with the
  exact legend labels. No subsystem missing, none duplicated.
- **Location fields tile the file map.** Every subsystem's `Location` glob covers exactly
  its assigned files in `file-map.tsv`:
  - S1 (8), S2 (rules/ + decorators/ — 41), S3 (taint/ — 15), S4 (19 core + scanner/__init__ + __init__/_version + core/__init__ = 21), S5 (10), S6 (8), S7 (8 core + weft_dossier + weft_decorator_coverage = 10), S8 (7), S9 (3 core + loomweave/ 8 + filigree/ 3 + _live_oracle = 15), S10 (mcp/ 7 + lsp.py + mcp/__init__ via glob), S11 (cli/ 21 + install/ 8 = 29), S12 (rust/ 15).
  - All 182 rows in `file-map.tsv` fall inside exactly one subsystem's Location. No
    orphan file, no file claimed by two entries.
- **Minor (LOW):** several *file-count claims inside Confidence prose* are off by one vs
  the map — not coverage gaps, the Location globs are correct in every case:
  - S3 says "14 modules" but its own Location parenthetical lists 15 (`__init__.py` +14).
  - S4 says "read all 19 assigned files" but 21 files are assigned (the +2 are root
    `__init__.py`/`_version.py`, both actually referenced — `_version.py:259` is cited).
  - S11 says "read all 30 assigned files" but 29 are assigned (cli/ 21 + install/ 8).
  - One LOW note covers all three: reconcile the Confidence-section counts with the map.

## Dimension 2 — Schema conformance: PASS

Every one of the 12 entries carries all required sections in template order:
`Location` → `Responsibility` → `Key Components` → `Public surface / entry points` →
`Dependencies (Inbound / Outbound by S-label)` → `Patterns Observed` → `Concerns` →
`Confidence`. Inbound and Outbound are split in all 12. S10 adds an additive
`Tool surface (18, in published order)` subsection — a permitted extension, not a
violation. No section is empty or placeholdered.

## Dimension 3 — Evidence quality: PASS (strong)

8 high-stakes citations were verified by reading the cited source (not just trusting the
prose). **All 8 matched.** This is unusually clean for a parallel-authored set, so the
checks were chosen adversarially across multiple authors/files:

| # | Claim (catalog) | Cited loc | Verified result |
|---|-----------------|-----------|-----------------|
| a | `pipeline.py` imports `core.ruleset.ruleset_hash` (not `core.attest`) | `scanner/pipeline.py:134` | ✅ exact — `from wardline.core.ruleset import ruleset_hash` at line 134 |
| b | pytest handshake bypass `_initialized = "pytest" in sys.modules` | `mcp/protocol.py:43-46` | ✅ exact — lines 43-46 set `_initialized`/`_initializing` from `"pytest" in sys.modules` |
| c | `run_scan` is a ~374-line god-function (`run.py:221-594`) | `core/run.py:221` | ✅ `def run_scan(` at 221; body ends at 594 (next def `_would_trip_at` at 597) → 373 lines |
| d | `decorator_coverage` MCP tool unbounded (schema only `{path,config}`) | `mcp/server.py:3092-3115` | ✅ `_DECORATOR_COVERAGE_TOOL` dict; `input_schema` properties = `path`,`config` only — no `where`/`max_findings`/`offset`/truncation |
| e | `_analyze_inner` is a single large method | `scanner/analyzer.py:249` | ✅ exact — `def _analyze_inner(self, files, config, *, root)` at 249 |
| f | `variable_level.py` is 2,481 LOC | S3 | ✅ exact — `wc -l` = 2481 |
| g | `grammar.py` reaches `variable_level._SERIALISATION_SINKS` (cross-cutting #3) | `grammar.py:196` | ✅ exact — import at 196, used at 199 |
| h | No `core.attest` import anywhere in `scanner/` (headline finding) | S1/S3/S7 + header | ✅ `grep -rn core.attest scanner/` → zero matches |

Bonus LOC checks (all consistent with prose): `analyzer.py` 1120 ✓, `install/doctor.py`
947 ✓, `core/rekey.py` 828 (catalog "829", off by one, LOW), `mcp/server.py` 5002
(catalog "5003", off by one, LOW).

## Dimension 4 — Cross-reference consistency: PASS-WITH-NOTES

- **Vocabulary:** every cross-reference uses the shared S1–S12 labels with the correct
  legend names. No invented subsystem labels found.
- **Reciprocity:** all *major call edges* reciprocate (S11↔S4, S11↔S10, S10↔S4, S7↔S4,
  S6↔S4, S5↔S9, S8↔S9, S9↔S7, S1↔S2, S1↔S3, S12↔S4). **3 minor non-reciprocal edges**
  (LOW — the expected parallel-authoring kind, mostly type-import edges or hedged
  inferences; not contradictions):
  1. **S7→S1** — S1 Inbound says S7 reads `AnalysisContext` (`assure.py` reads
     `context.declared_qualnames`), but S7 Outbound omits S1. (S1 itself hedges this as
     docstring-derived.)
  2. **S6→S9** — S6 Outbound + cross-cutting #3 cite `delta_resolve.py:350` reaching
     `sei_resolver._client` (S9), but S9 Inbound omits S6.
  3. **S9→S5** — S9 Outbound imports `core.filigree_emit` helpers (S5), but S5 Inbound
     omits S9.

## Dimension 5 — Cross-cutting header support: PASS

All 5 orchestrator-synthesis findings are supported by the cited entries and consistent
with this validator's spot-checks:

1. **Layering "violation" already fixed (VERIFIED).** Supported by S1, S3, S7.
   **Independently reproduced:** this validator ran `uv run lint-imports` →
   *"Contracts: 1 kept, 0 broken"* (contract *"Taint engine must not import the
   attestation layer"* KEPT), and `grep` confirms zero `core.attest` imports in
   `scanner/`. `pyproject.toml:170-182` still declares the contract "BROKEN today" and CI
   runs `lint-imports || true` (non-gating) — the comment/`|| true` are stale, exactly as
   the header claims. **Correct.** (But see Required Correction #1 — S3's own bullet
   contradicts this.)
2. **God-functions are the dominant structural risk.** All four anchors verified:
   `_analyze_inner` 249-1105 (~857 lines; file is 1120 LOC), `run_scan` 221-594 (~374),
   `variable_level.py` 2481 LOC (exact), `install/doctor.py` 947 LOC (exact). **Correct.**
3. **Cross-subsystem private-name reach.** `grammar.py:196 → variable_level._SERIALISATION_SINKS`
   verified exact; the S2→`decorator_provider._is_builtin_decorator_fqn`,
   S6→`sei_resolver._client`, S11→`install.doctor` privates are each carried in the
   respective entry Concerns. **Supported.**
4. **Security invariants split caller/callee.** THREAT-001 split between
   `resolve_under_root` (S10 `mcp/tooling.py:78`) and `confine_to_root`/`safe_paths`
   (S4); fingerprint determinism in `_fingerprint.py` (S1/S2); secure-by-default in S6.
   **Supported** (see LOW note on the `_resolve_under_root` alias citation).
5. **pytest-coupled handshake bypass (S10).** `mcp/protocol.py:43-46` verified exact.
   **Correct.**

---

## REQUIRED CORRECTION (must fix before the catalog is consumed)

**[HIGH] S3 Concerns contradicts the headline finding and is factually wrong.**
Location: S3 — Taint Engine → Concerns → first bullet (catalog line ~228). The bullet
states:

> "The report-only import-linter contract (`pyproject.toml:178-182`, run as
> `lint-imports || true`) is **still broken — but only by S1's `scanner/pipeline.py`**…"

This is false. This validator **ran `lint-imports`: 1 kept, 0 broken** — the contract
PASSES. `pipeline.py:134` imports `core.ruleset.ruleset_hash`, not `core.attest`; a
project-wide `grep` finds zero `core.attest` imports in `scanner/`. The statement
directly contradicts (a) cross-cutting header #1 ("1 kept, 0 broken"), (b) S7's Concerns
(contract passes, issue `wardline-9ec283d168` closed), and (c) S1's own Concerns ("no
`attest` import anywhere" in `scanner/`).

**Fix:** change S3's bullet to say the contract is now **KEPT/passing** (0 broken); the
remaining accurate point — that the stale `pyproject.toml` comment and `wardline-9ec283d168`
*over-name* `project_resolver` — should be retained.

**Root cause (one line, worth recording):** S3 appears to have trusted the *spec's*
MANDATE #3 premise ("`scanner/pipeline.py` … import `wardline.core.attest`") about a file
it was told not to own, instead of verifying it. The spec premise is itself stale — a
finding in its own right: `catalog-spec.md` MANDATE #3 should be updated to note the
violation is remediated, so future re-runs don't re-inherit the wrong premise.

## NOTES (low severity — fix opportunistically, do not block)

- **[LOW] Confidence-prose file-count miscounts** (S3 "14 modules" lists 15; S4 "19" vs
  21 assigned; S11 "30" vs 29 assigned). Coverage is complete; reconcile the numbers.
- **[LOW] 3 non-reciprocal cross-reference edges** (S7→S1, S6→S9, S9→S5; see Dimension 4).
  Add the missing inbound/outbound mentions for symmetry.
- **[LOW] `_resolve_under_root` citation precision (cross-cutting #4 + S4).** The header
  and S4 cite `_resolve_under_root` and attribute it to `mcp/tooling.py`. The canonical
  definition is `resolve_under_root` (no underscore) at `tooling.py:78`; the underscore
  form is a *real import alias* introduced in `mcp/server.py:53`
  (`import resolve_under_root as _resolve_under_root`). Same symbol — not a fabricated
  citation — but the underscore name should be attributed to `mcp/server.py`, not
  `tooling.py`. S10's own citation is correct.
- **[LOW] Off-by-one LOC labels** (`server.py` "5003" vs 5002; `rekey.py` "829" vs 828).

---

## Confidence Assessment

**Overall confidence in this validation: HIGH for the structural verdict; MEDIUM-HIGH for
exhaustiveness of evidence checks.**

- I read the full catalog (all 12 entries + cross-cutting header), the full contract
  (`catalog-spec.md`), and the full file map (`file-map.tsv`).
- Coverage and schema conformance were checked exhaustively (every entry, every required
  section, every Location glob against the map) — HIGH confidence.
- Evidence quality was checked by *reading source* for 8 high-stakes citations spanning 6
  files and multiple authors; all matched — HIGH confidence in the sampled set, but this
  is a sample (see Information Gaps).
- The single contradiction (Required Correction #1) was settled *empirically* by running
  `lint-imports` and `grep`, not by reasoning — HIGH confidence it is a real defect.
- Cross-reference reciprocity was checked on the major edges and a representative sample
  of minor ones — MEDIUM-HIGH (not every one of the dozens of declared edges was traced
  both directions).

## Risk Assessment

- **Risk if shipped as-is (PASS-WITH-NOTES, uncorrected): MEDIUM-LOW.** The one HIGH item
  is an internal contradiction, not a wrong headline. `05-quality-assessment.md` consumes
  the *headline* finding (correct) and the god-function inventory (verified correct), so
  the most load-bearing inputs are sound. The risk is that a reader citing S3 in isolation
  repeats the false "contract still broken" claim. Correcting the S3 bullet retires this.
- **Risk of a false PASS (validator missed a real defect): LOW-MEDIUM.** Evidence checks
  were a sample; an unsampled citation could be wrong. Mitigated by the strong 8/8 hit
  rate and the independent reproduction of the single most consequential claim.
- **Risk of over-blocking: LOW.** I deliberately did not escalate the parallel-authoring
  reciprocity asymmetries or count nits to blocking status; they are cosmetic.

## Information Gaps

- **Evidence sampling:** 8 of *many* `path:line` citations were source-verified. Entries
  carry hundreds of citations; the unsampled remainder is assumed-good on the strength of
  the sample, not proven.
- **Reciprocity:** major edges traced both directions; not every declared edge was.
- **Loomweave graph edges not independently re-derived.** The catalog's Inbound/Outbound
  claims are stated as `entity_callers_list`/`entity_neighborhood_get`-derived; I did not
  re-run those graph probes to confirm each edge — I checked source `file:line`
  corroboration and internal reciprocity instead.
- **Technical accuracy out of scope.** Per the validator's scope boundary, I did not
  assess whether the *architectural judgments* (e.g. "weakest-link meet is correct",
  "secure-by-default is sound", PREVIEW-rule maturity calls) are technically right — only
  that claims carry evidence and are internally consistent. Technical-soundness review of
  the taint-lattice and security invariants would need `python-code-reviewer` /
  `threat-analyst` / `architecture-critic`.

## Caveats

- **Fresh-eyes, single-pass review.** I am not the original author of any entry; this is
  independent verification, but it is one validator's pass, not a panel.
- **The spec's own premise is stale.** `catalog-spec.md` MANDATE #3 asserts the layering
  violation is *present* and instructs authors to "confirm this from source." The catalog
  authors did exactly that and correctly found the premise outdated — so the catalog
  *overrides its own contract's premise with primary-source evidence*. I treat that as a
  **strength**, not a contract violation: the mandate asked for source confirmation and
  got it. The S3 defect is not that it overrode the spec, but that it overrode it
  *inconsistently* (S1/S7/header got the new truth; S3's bullet kept the old one).
- **Verdict vocabulary.** This report uses the task's `PASS / PASS-WITH-NOTES / BLOCK`
  scale. In the SME protocol's table this maps to `NEEDS_REVISION (warnings)` — non-
  critical, fixable, non-blocking.
- **Retry budget:** this is validation attempt 1 of the allowed 2. The Required
  Correction is mechanical (one bullet); a re-validation should be a quick re-read of S3.
