# ADR: Finding identity is a frozen, cross-engine contract

- **Status:** Accepted
- **Date:** 2026-06-05
- **Resolves:** Pre-Rust core hardening Task A (milestone `wardline-53412b86bc`,
  task `wardline-4e52be1efa`); the load-bearing safety net for the upcoming
  Rust-core migration (PyO3 + maturin abi3).

## Context

Wardline is about to migrate its analysis **core** to a Rust implementation
(likely parsing with `ruff_python_ast`). Downstream Loom peers key on Wardline's
externally-observable *identity*:

- **Filigree** associates issues to findings by `fingerprint`.
- **Clarion** binds taint facts to entities by `qualname` (and consumes the
  whole taint-fact payload byte-wise).
- SARIF consumers (GitHub Code Scanning) dedupe on
  `partialFingerprints.wardlineFingerprint/v1`.

The `fingerprint` is `sha256(rule_id \0 path \0 line_start \0 qualname \0
taint_path)` (`core/finding.py`), where `path` is repo-relative. If the Rust
parser produces even slightly different spans, qualnames, or fingerprints, every
existing association silently drifts — issues detach, taint bindings orphan — with
no error. This is the single highest-risk part of the migration, and it cannot be
guarded *after* the Python parser is gone. So the current Python engine's
identity output is frozen now, while it is still the source of truth.

## Decision

**Finding identity is a frozen contract, captured as a byte-exact golden corpus
(`tests/golden/identity/`) with a parity test that any engine implementation must
pass unchanged.** Concretely:

1. **Definitions.** `fingerprint`, `qualname`, and spans (`location.path` +
   `line_start`/`line_end`/`col_start`/`col_end`) are the identity fields. `path`
   is relative to the scan root (proven location-independent), so fingerprints do
   not depend on the absolute checkout path.

2. **Scope — identity-bearing only.** The corpus freezes findings matching a
   single positive predicate, `rule_id.startswith("PY-WL-") ∧ kind is
   Kind.DEFECT`, applied at every per-finding surface (findings list *and* the
   SARIF input). A positive allowlist, not a denylist: a future `WLN-SECURITY-*`
   DEFECT rule cannot silently enter the corpus, and a future `PY-WL-*` FACT rule
   cannot be silently dropped. **Engine diagnostics** (`WLN-ENGINE-*`,
   `WLN-L3-*`, `Kind.METRIC`, `Kind.FACT`) are excluded — a different engine
   (e.g. a Rust import resolver) may legitimately differ on them, and they are
   not what peers key on. (Naming note: a `Kind.FACT` *finding* is excluded; this
   is distinct from the `build_taint_facts` *payload*, which is kept — see §3.)

3. **Surfaces frozen.** Per input root: identity-bearing findings (real wire
   format, `Finding.to_jsonl()`); the taint-fact payload (`build_taint_facts`,
   kept whole); SARIF (`build_sarif` over the identity-filtered findings); the
   assure posture (`build_posture(...).to_dict()`); and an explain projection
   (`explanation_from_context`, pure).

4. **Canonicalisation.** Output is strict canonical JSON (`sort_keys`,
   `ensure_ascii=False`, no `default=str` — a custom encoder unwraps enums and
   *raises* on any other unknown type, so nondeterminism is never silently
   masked). Named arrays are sorted by total content keys — findings by
   `(path, line_start, rule_id, qualname, fingerprint)`; taint facts by
   `qualname` (and inner findings by `(rule_id, fingerprint)`); SARIF `results`
   by `(uri, startLine, ruleId, fingerprint)` and `rules` by `id`. SARIF
   `codeFlows` location sequences are an **ordered causal taint chain and are NOT
   sorted**. SARIF `driver.version` (the mutable tool version) is normalised to a
   sentinel so a release bump is not a spurious rekey; `results[].ruleIndex` is
   dropped (recoverable from `ruleId`, and would be corrupted by the rules sort).
   The taint fact's `content_hash_at_compute` is a `blake3` of the file's raw
   bytes — engine-independent, so safe to gate.

5. **Determinism verified before freeze.** In-process stable; path-independent;
   cross-process (`PYTHONHASHSEED` 0 vs 1); and **cross-interpreter** — frozen
   under CPython 3.12, reproduced byte-identical under 3.13. The parity test
   therefore runs on **both** CI interpreter legs with no skip (no coverage hole).

6. **Stability across implementations + rekey-only escape hatch.** This identity
   is stable across engine implementations (Python today, Rust tomorrow). Any
   deliberate change to the scheme is a **separate, versioned, rekey-with-
   migration** step — never a silent side effect. Enforcement is the parity test
   plus CODEOWNERS on `corpus/**` (CI fails any PR that changes the corpus
   without a matching production change); `regen.py --reason` + `corpus/META.json`
   is the accountability record, not the gate.

7. **Hard gate on the Rust cutover.** "Parity corpus green" is a hard
   prerequisite on the Rust core landing and must not be negotiated away under
   schedule pressure.

## Consequences

- **No silent drift.** A span/fingerprint/qualname change fails the parity test
  loudly, with `/tmp/corpus_actual_<name>.json` + a unified diff to distinguish a
  real regression from an intentional rekey.
- **Honest cross-engine contract.** By excluding engine diagnostics, the gate
  asserts what peers actually key on, not engine-internal observability the Rust
  port may legitimately render differently.
- **A discipline to uphold.** If a *specific* taint-fact field later proves
  engine-divergent (e.g. a resolution-heuristic count), per-field normalisation
  in `_capture._capture_facts` is the documented, separately-justified escape
  hatch — not a reason to weaken the whole-payload gate now (YAGNI).
- **Fixture hygiene is load-bearing.** Fixtures must never carry `.wardline/` or
  `wardline.yaml` (a waiver would date-poison the corpus via `date.today()`);
  a hygiene test enforces this.

## References

- `tests/golden/identity/` — `_capture.py` (harness), `corpus/` (frozen),
  `test_identity_parity.py` (gate + non-vacuity + hygiene), `regen.py`, `README.md`.
- `src/wardline/core/finding.py` — `compute_finding_fingerprint`, `Finding.to_jsonl`.
- `src/wardline/core/{run,sarif,assure,explain}.py`, `src/wardline/clarion/facts.py`
  — the reused capture entry points.
- `.gitattributes` — fixture LF pinning / corpus binary treatment.
