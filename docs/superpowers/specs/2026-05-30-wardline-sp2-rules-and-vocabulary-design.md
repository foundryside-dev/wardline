# SP2 — Wardline Rules + Trust Vocabulary (Design)

**Date:** 2026-05-30
**Status:** design — awaiting user review before per-stage implementation planning
**Sub-project:** SP2 of the generic-Wardline rebuild (see [SP1 spec](2026-05-29-wardline-sp1-analyzer-core-design.md) §6 for the analyzer core this builds on)
**Source engine:** `/home/john/wardline.old/src/wardline/{decorators,core/registry.py,core/matrix.py,scanner/rules,scanner/anchor_resolver.py}` (architecture mapped 2026-05-30)
**Contract:** [Loom integration brief](../../integration/2026-05-29-wardline-loom-integration-brief.md) §Round 1 (preserve `wardline.core.registry` import surface **and** emit an NG-25 vocabulary descriptor); §Filigree (fingerprint must disambiguate same-`(file,rule,line)` findings by taint path)

---

## 1. Goal

Turn the SP1 taint **engine** into a taint **policy tool**: ship a small generic *trust-declaration vocabulary*, a real `TaintSourceProvider` that seeds taints from it, a *hybrid* set of policy rules that consume the L3 taint map, and the Loom-clean vocabulary surface (registry import + NG-25 descriptor). SP2 **flips the self-hosting xfail** (`tests/test_self_hosting.py`): Wardline scans its own `src/wardline` with **zero `kind=DEFECT` findings**.

SP1 produced engine diagnostics only (facts/metrics). SP2 produces the first **defect** findings — by design, only where the author has *opted in* by declaring trust. Undecorated code stays in the developer-freedom zone and is silent. This is the "enterprise functionality with single-person simplicity" posture: no noise until you annotate; real taint enforcement once you do.

**User decisions (2026-05-30):**
- **Rules = Hybrid** — a small taint-flow + decorator-contract set, plus a couple of generic syntactic hygiene rules.
- **Vocabulary = Minimal generic family** — ~3 generic, domain-neutral decorators that map cleanly onto the lattice (NOT `.old`'s 17-group / 25-decorator vocabulary).
- **Severity = Compact tier modulation** — each rule declares a base severity; a ~10-line shared function modulates it by the function's taint tier (NOT `.old`'s 80-cell `(rule × taint)` matrix).

---

## 2. The trust vocabulary (minimal, generic)

Three canonical decorators, each a **runtime no-op marker** (importable so authors can apply them; they stamp `_wardline_*` attributes for runtime introspection, but static analysis reads them from the AST). They map onto the SP1 lattice
`INTEGRAL < ASSURED < GUARDED < UNKNOWN_ASSURED < UNKNOWN_GUARDED < EXTERNAL_RAW < UNKNOWN_RAW < MIXED_RAW`:

| Decorator | Role | `FunctionTaint(body, return)` the provider emits |
|---|---|---|
| `@external_boundary` | **Source** — function is an external entry point; its return carries untrusted data | `(EXTERNAL_RAW, EXTERNAL_RAW)` |
| `@trust_boundary(to_level=...)` | **Validator/transition** — validates/sanitizes and *raises* trust; body sees raw, return is the declared level | `(EXTERNAL_RAW, <to_level>)` where `<to_level> ∈ {GUARDED, ASSURED}` |
| `@trusted(level=...)` | **Trusted producer/sink** — declares the function operates on, and returns, trusted data (default `INTEGRAL`) | `(<level>, <level>)` where `<level> ∈ {INTEGRAL, ASSURED}` |

Design notes:
- **Generic names, no domain coupling.** No `validates_shape`/`validates_semantic`/`integral_writer`/secrets/PII — those carried `.old`'s domain model. `to_level`/`level` take a `TaintState` (by name string or enum), not `.old`'s opaque tier ints `1–4`.
- `@trust_boundary` subsumes `.old`'s `@validates_shape/semantic/external` (one generic transition decorator instead of three named ones) and `.old`'s `@trust_boundary(from_tier, to_tier)` (we keep only `to_level` — the *outcome* is what seeds taint; `from_tier` was advisory).
- `@trusted` subsumes `.old`'s `@integral_read/writer/construction`. Optional ergonomic sugar `@integral = @trusted(level="INTEGRAL")` MAY be added as a thin alias; not required for the minimal family.
- The decorators live in `src/wardline/decorators/` (re-establishing that package, generic-only). Argument validation rejects levels outside the allowed set with `ValueError` at decoration time (fail-fast for authors).

---

## 3. The provider (real seeding)

`DecoratorTaintSourceProvider` implements SP1's `TaintSourceProvider` Protocol (`src/wardline/scanner/taint/provider.py`) and **replaces `DefaultTaintSourceProvider` as the analyzer's default**:

- `taint_for(entity, ctx)` — inspect `entity.node.decorator_list`; resolve each decorator name against the trust vocabulary **through the import-alias map** (so `from wardline.decorators import trusted as t; @t` and `import wardline.decorators as wd; @wd.trusted` both resolve). On a vocabulary match, return the `FunctionTaint` from §2's table (reading `to_level`/`level` from the decorator's keyword args in the AST). On no match, return `None` (→ engine falls back to stdlib/UNKNOWN_RAW, unchanged).
- `fingerprint()` — derived from `REGISTRY_VERSION` + the vocabulary identity (e.g. `f"decorator-vocab:{REGISTRY_VERSION}"`). Already bound into the SP1 summary `cache_key`, so bumping the vocabulary version correctly invalidates cached summaries.

**SeedContext extension.** SP1's `SeedContext` carries only `module`. The provider needs the file's import-alias map to resolve aliased decorator names, so SP2 adds `alias_map: Mapping[str, str]` to `SeedContext` (the seam's docstring already authorizes additive fields). The analyzer already builds the alias map per file (`build_import_alias_map`); SP2 threads it into the `SeedContext` it constructs.

**Anchor precedence** stays the SP1-simplified `provider(decorator) > stdlib > UNKNOWN_RAW`. SP2 does **not** revive `.old`'s `dependency_taint` manifest tier. The dormant `module_default` tier (a `wardline.yaml` module-scope default) is **deferred** (see §7) — the minimal vocabulary plus stdlib is sufficient to make the engine produce real, non-trivial taints.

---

## 4. The rule set (hybrid)

Four rules. All consume the SP1 `AnalysisContext` (`project_taints`, `function_var_taints`, `entities[qualname].node`, `taint_provenance`) — sufficient for every rule below, so no new engine output is required. Rules are registered into the `RuleRegistry` SP1 left empty.

| Rule | Class | What it flags | Mechanism |
|---|---|---|---|
| **PY-WL-101 untrusted-reaches-trusted** | taint-flow | A `@trusted(level=L)` function whose returned value's **actual** taint is less-trusted than `L` — i.e. untrusted data flows out of a function that claims to produce trusted data, with no validation boundary. **`@trust_boundary` validators are exempt** (delegated to PY-WL-102 — see note below). | Compare the function's **actual returned taint** (`function_return_taints[qualname]`, the least-trusted of all return paths) against its declared return tier. Less-trusted ⇒ DEFECT, *unless* the function is a trust-raising transition (`@trust_boundary`). |
| **PY-WL-102 boundary-without-rejection** | decorator-contract (port of `.old` PY-WL-008) | A `@trust_boundary`-declared validator with **no rejection path** — no `raise`, no early `return None`/falsy-on-invalid branch. A validator that cannot reject is not validating. | AST walk of `entity.node` for any `Raise` or a guarded early-return; absence ⇒ DEFECT. |
| **PY-WL-103 broad-exception** | syntactic, tier-modulated (port of `.old` PY-WL-004) | `except:` / `except Exception` / `except BaseException` inside a **trusted-tier** function. | `ast.ExceptHandler` inspection; severity via §5 modulation (suppressed outside trusted tiers). |
| **PY-WL-104 silent-exception** | syntactic, tier-modulated (port of `.old` PY-WL-005) | An exception handler whose body is only `pass`/`...`/`continue`/`break` (swallows the error) in a **trusted-tier** function. | `ast.ExceptHandler` body inspection; severity via §5 modulation. |

- **Always-on vs tier-modulated.** PY-WL-101 and PY-WL-102 fire whenever the relevant *declaration* is present (the decorator IS the opt-in), independent of tier modulation. PY-WL-103/104 are tier-modulated and therefore silent on undecorated code.
- **PY-WL-101 / PY-WL-102 partition over the vocabulary (implementation refinement, 2026-05-30).** The rules key off taint *shape*, not decorator names, and partition cleanly: `@trusted` (body == return) is PY-WL-101's domain; `@trust_boundary` (a trust-raising transition: body strictly less-trusted than return) is PY-WL-102's domain and is *exempt* from PY-WL-101; `@external_boundary` (declared return in the raw/freedom zone) is gated out of both flow checks. The exemption is forced by the engine: a `@trust_boundary`'s parameters seed at the raw body taint and the L2 layer does not narrow taint after a `raise`, so *every* validator's actual return is raw — making PY-WL-101 fire on 100% of them (noise). The statically-decidable validator property is "can it reject", which is exactly PY-WL-102. A bare correct `@trust_boundary` (raise + return) therefore fires neither rule; one with no rejection path fires PY-WL-102. The `test_vocabulary_shape_pin` test pins the three shapes so SP2d cannot silently break this coupling.
- **Rule IDs** use the `PY-WL-1xx` band to mark them as the *generic rebuild's* rules — distinct from `.old`'s `PY-WL-0xx` (whose semantics/calibration we are deliberately not reproducing wholesale). Engine diagnostics keep their `WLN-ENGINE-*` / `WLN-L3-*` namespace.
- Each rule carries `RuleMetadata` (id, base severity, kind=DEFECT, short description, examples) for the NG-25 descriptor and future docs.

---

## 5. Severity model (compact tier modulation)

`src/wardline/scanner/rules/severity_model.py` — each rule declares a `base_severity: Severity`; a shared function modulates it by the function's resolved taint, mapping to SP0's `Severity` (`CRITICAL/ERROR/WARN/INFO/NONE`):

```
modulate(base, taint):
    trusted    (INTEGRAL, ASSURED)                  -> base            # the "this matters" zone
    partial    (GUARDED, UNKNOWN_ASSURED,
                UNKNOWN_GUARDED)                     -> downgrade(base) # flag for review, don't block
    freedom    (EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW)-> NONE            # developer-freedom / fail-closed zone -> suppressed
```

This captures `.old`'s "severity scales with consequence at tier" principle in ~10 lines instead of 80 cells. **Consequence for self-hosting:** undecorated code resolves to `UNKNOWN_RAW`, so tier-modulated rules emit `NONE` (suppressed) — Wardline scans itself clean *by construction*, and the tool is opt-in. Config plumbing (already present on `WardlineConfig`): `rules_enable` toggles rules; `rules_severity` overrides a rule's `base_severity` before modulation.

---

## 6. Registry + NG-25 descriptor (Loom contract)

- **`src/wardline/core/registry.py`** — port `.old`'s slim structure, generic entries only: `RegistryEntry(canonical_name, group, attrs)` (frozen, `attrs` wrapped `MappingProxyType`), `REGISTRY: MappingProxyType[str, RegistryEntry]` with the §2 vocabulary, and `REGISTRY_VERSION` (new line for the generic vocab, e.g. `"wardline-generic-1"`). **The public import surface `wardline.core.registry.{REGISTRY, REGISTRY_VERSION, RegistryEntry}` is the zero-day compat bridge Clarion's plugin imports — preserve it byte-stable** (integration brief §Round 1).
- **`src/wardline/core/descriptor.py`** — `build_vocabulary_descriptor() -> dict` exporting `{"version": REGISTRY_VERSION, "entries": [...]}` (canonical name, group, taint mapping, attrs) from `REGISTRY`; serialized to a committed `src/wardline/core/vocabulary.yaml` (shipped in the wheel, like `stdlib_taint.yaml`) and emitted by a new CLI subcommand `wardline vocab`. This is the **NG-25 descriptor** — the federation-clean *read-instead-of-import* path that retires the brief's "asterisk 2". A test asserts the descriptor round-trips `REGISTRY` and carries `REGISTRY_VERSION`.

No HMAC / signing / governance on the descriptor — it is a plain versioned YAML export.

---

## 7. Taint-path fingerprint identity

The SP1 deferral (`core/finding.py`'s `compute_placeholder_fingerprint`) is closed in SP2, because SP2 is where the first taint-path-bearing DEFECT findings are born. Replace the placeholder with a scheme that folds in `qualname` + a **taint-path signature** (derived from `taint_provenance` — the chain/source set the propagation recorded for the finding's function) so that **two taint paths into one sink** (same `file/rule/line`, different path) get **distinct** fingerprints, per the Filigree constraint (brief §Filigree Round 1). Engine facts/metrics keep their existing fixed-identity fingerprints.

---

## 8. What SP2 emits / changes end to end

After SP2, `wardline scan <project>` produces `findings.jsonl` with engine diagnostics (unchanged) **plus** `kind=DEFECT` policy findings wherever trust is declared. `WardlineAnalyzer.analyze` changes: default provider becomes `DecoratorTaintSourceProvider`; after building `AnalysisContext`, it runs the default-populated `RuleRegistry` (`registry.run(context)`) honoring `config.rules_enable`/`rules_severity`, and appends those findings. New CLI surface: `wardline vocab` (emit NG-25 descriptor). The self-hosting xfail flips to a passing test (0 DEFECT findings on `src/wardline`).

---

## 9. Sub-decomposition (each stage ends green & testable)

| Stage | Deliverable | Key acceptance |
|---|---|---|
| **SP2a** | Generic trust vocabulary (`decorators/`: `@external_boundary`, `@trust_boundary`, `@trusted` as runtime markers) + `core/registry.py` (`RegistryEntry`/`REGISTRY`/`REGISTRY_VERSION`) | decorators importable + apply cleanly; bad level args raise `ValueError`; registry import surface present; entries consistent with §2 |
| **SP2b** | `DecoratorTaintSourceProvider` + `SeedContext.alias_map` extension; wired as analyzer default | decorated functions seed correct `FunctionTaint`; aliased/`from`-import/attribute decorator forms resolve; `fingerprint()` stable and version-derived; engine produces non-trivial taints on a decorated fixture |
| **SP2c** | Severity model (tier modulation) + the 4 rules + taint-path fingerprint + default `RuleRegistry` + analyzer wiring + `rules_enable`/`rules_severity` honored; **flip self-hosting xfail** | per-rule positive/negative fixtures (decorated violation fires; clean/undecorated silent); modulation suppresses undecorated tiers; two-paths-one-sink ⇒ distinct fingerprints; `wardline scan src/wardline` ⇒ 0 DEFECT findings |
| **SP2d** | NG-25 vocabulary descriptor (`core/descriptor.py` + committed `vocabulary.yaml` + CLI `wardline vocab`) | descriptor round-trips `REGISTRY` + carries `REGISTRY_VERSION`; `wardline vocab` emits valid YAML; wheel ships the file |

Build order SP2a → SP2b → SP2c → SP2d. Each gets its own plan + subagent-driven execution (same cadence as SP1a–f).

---

## 10. Non-goals (deferred / never)

- **No `.old` 80-cell severity matrix**, no `.old` 17-group / 25-decorator vocabulary, no `dependency_taint` manifest tier.
- **`module_default` tier deferred.** A `wardline.yaml` module-scope default taint (the dormant SP1d tier) is a later refinement; the minimal vocabulary + stdlib already lifts the engine off the trivial all-`UNKNOWN_RAW` floor. Revisit if real projects want scope defaults without per-function decoration.
- **No SARIF / Filigree / Clarion emission** — SP4 (SP2 still writes `findings.jsonl` only). The NG-25 descriptor is a *vocabulary* export, not a findings transport.
- **No baseline / waivers** — SP3.
- **Never:** HMAC/signing/counter-signatures, BAR, IRAP, conformance evidence, governance gates on the descriptor.

---

## 11. Risks & mitigations

- **Self-hosting false positives.** If a rule fired on Wardline's own undecorated code the xfail-flip would fail. Mitigation: tier modulation suppresses non-trusted tiers (§5) and Wardline does not yet dogfood its own decorators, so PY-WL-101/102 (declaration-gated) and PY-WL-103/104 (tier-modulated) are all silent on `src/wardline` by construction; the flipped test pins this as a regression gate.
- **Decorator-name resolution fidelity.** Aliased/`from`/attribute import forms must all resolve, or trust declarations are silently dropped (under-taint, the dangerous direction). Mitigation: reuse SP1's `build_import_alias_map` + the multi-form resolution already proven in `call_taint_map`; discriminating tests per import form.
- **Anchored-function body taint.** PY-WL-101 must compare the declared level against the function's *actual* returned-value taint (L2), not the anchored `project_taints` value (which is pinned to the declaration). Mitigation: rule reads `function_var_taints` for the returned name, explicitly tested against a fixture where a `@trusted` function returns an `@external_boundary` result.
- **Registry import-surface drift.** Clarion's plugin imports `wardline.core.registry`. Mitigation: a contract test pins the public names + `REGISTRY_VERSION` presence; the NG-25 descriptor test pins round-trip equivalence.

---

## 12. Forward notes

- **SP3 (baseline/waivers)** consumes the SP2 taint-path fingerprint as its stable drift identity — verify the fingerprint is stable across runs for an unchanged finding while distinguishing two-paths-one-sink.
- **SP4 (outputs)** promotes DEFECT findings + the L3 metrics into SARIF/Filigree; the NG-25 descriptor is the artifact Clarion's plugin reader switches to (retiring brief asterisk 2 once Clarion ships the reader).
- **`module_default` tier** (deferred here) is the natural SP2-follow-on if scope-default taint is wanted; the SP1d anchor enum already reserves the `module_default` source class.
