## S2 — Rule Lattice

**Location:** `src/wardline/scanner/rules/` (26 PY-WL rules + shared infra), `src/wardline/decorators/` (the 3 runtime trust markers)

**Responsibility:** Define the trust-vocabulary defect rules — each a self-contained `check(context) -> list[Finding]` over the engine's `AnalysisContext` — plus the rule descriptor/severity model, the shared AST/sink helpers they run on, and the three static-analysis decorators (`@external_boundary` / `@trust_boundary` / `@trusted`) whose declarations the rules police.

**Key Components:**
- `scanner/rules/__init__.py` — registry factory + the canonical rule ordering. `_ALL_RULE_CLASSES`/`BUILTIN_RULE_CLASSES` (`__init__.py:52-86`, hand-ordered tuple; "registration order = emission order"); `build_default_registry(config, rules=None)` (`__init__.py:235`) honours `rules.enable` (fnmatch include) and `rules.severity` (per-rule base override); malformed config is surfaced as the engine self-diagnostic `WLN-ENGINE-POLICY-CONFIG` via `_PolicyConfigRule` (`__init__.py:88-135`).
- `scanner/rules/metadata.py` — `RuleMetadata` frozen descriptor (`metadata.py:15`): `rule_id`, `base_severity`, `kind`, `description`, examples, `maturity`, and the load-bearing `multi_emit` flag (`metadata.py:23-32`) that gates which fingerprint discriminator a rule may use.
- `scanner/rules/severity_model.py` — `modulate(base, taint)` (`severity_model.py:47`): the ~10-line tier-modulation matrix — trusted tiers keep base, partial tiers downgrade one step, freedom/fail-closed zone → `NONE`. The freedom-zone suppression is what keeps undecorated code (`UNKNOWN_RAW`) silent and the project self-host clean.
- `scanner/rules/_ast_helpers.py` — the boundary-integrity predicate library (~648 lines): own-scope reachability mini-CFG (`_reachable_statements_in_block`, `_stmt_always_terminates`), rejection-path detection (`has_rejection_path`/`has_real_rejection`/`asserts_are_sole_rejection`), one-hop same-module helper resolution (`rejecting_helper_calls`), fail-open detection (`handler_substitutes_on_failure`), and broad/silent-handler predicates. Encodes the 4-way boundary partition invariant (`_ast_helpers.py:382-392`).
- `scanner/rules/_sink_helpers.py` — the dangerous-sink machinery + `TaintedSinkRule` base (`_sink_helpers.py:735`, Loomweave-tagged `exported-api`). Name/alias canonicalization (`canonical_call_name`), binding-aware call resolution (`collect_sink_bindings`/`resolved_sink_calls`), the single fail-closed arg-taint resolver (`resolved_arg_taints`, `:483`), `ArgSpec` slot precision, and `build_sink_finding` (`:680`). `TaintedSinkRule.check` (`:843`) is the one loop the whole sink family runs.
- `scanner/rules/_fingerprint.py` — `entity_source_fingerprint` (`_fingerprint.py:49`): a position-free canonical-AST sha256, made byte-identical across CPython 3.12/3.13 (`_canonical_ast_dump`), used as the singleton-rule `taint_path` discriminator.
- `decorators/_base.py` + `decorators/trust.py` + `decorators/__init__.py` — `apply_marker` (`_base.py:39`) validates a marker against `core.registry.REGISTRY`, stamps `_wardline_*` attrs, and returns the function UNCHANGED (no runtime wrapper); `trust.py` exposes `external_boundary` / `trust_boundary(to_level=)` / `trusted(level=)`.
- The 26 rule modules (one class each, `rule_id`+`metadata`+`check`). 15 STABLE, 11 PREVIEW (`maturity=Maturity.PREVIEW`):
  - `untrusted_reaches_trusted.py` — **PY-WL-101** (ERROR): an anchored `@trusted` producer whose actual return is less-trusted than declared.
  - `boundary_without_rejection.py` — **PY-WL-102** (ERROR): a `@trust_boundary` with no rejection path of any shape.
  - `broad_exception.py` — **PY-WL-103** (WARN, tier-mod): bare/`Exception`/`BaseException` handler in a trusted-tier fn.
  - `silent_exception.py` — **PY-WL-104** (WARN, tier-mod): exception swallowed (`pass`/`...`) with no handling.
  - `untrusted_to_trusted_callee.py` — **PY-WL-105** (ERROR): provably-untrusted data passed to a trusted callee at a call site.
  - `untrusted_to_deserialization.py` — **PY-WL-106** (WARN, sink): untrusted bytes → pickle/yaml/marshal/dill/torch/numpy deserialization (CWE-502).
  - `untrusted_to_exec.py` — **PY-WL-107** (WARN, sink): untrusted → `eval`/`exec`/`compile`.
  - `untrusted_to_command.py` — **PY-WL-108** (ERROR, sink): untrusted → `os.system`/`subprocess` program-exec.
  - `none_leak.py` — **PY-WL-109** (WARN): `None` leaks out of a trusted producer.
  - `contradictory_trust.py` — **PY-WL-110** (WARN): ≥2 distinct trust markers on one entity (silently resolved clash).
  - `assert_only_boundary.py` — **PY-WL-111** (ERROR): boundary whose only rejection is `assert` (stripped under `-O`, CWE-617).
  - `untrusted_to_shell_subprocess.py` — **PY-WL-112** (ERROR, sink): untrusted → `shell=True` subprocess.
  - `failopen_boundary.py` — **PY-WL-113** (ERROR): a real rejection defeated by a fail-open handler (CWE-636/703).
  - `invalid_decorator_level.py` — **PY-WL-114** (ERROR): statically-readable but invalid/out-of-range decorator level (e.g. typo `'ASURED'` silently disables the gate).
  - `untrusted_to_import.py` — **PY-WL-115** (WARN, sink): untrusted → dynamic `import`/`__import__`/module-load.
  - `path_traversal.py` — **PY-WL-116** (WARN, sink, PREVIEW): untrusted → filesystem-path sink.
  - `ssrf.py` — **PY-WL-117** (WARN, sink, PREVIEW): untrusted → HTTP-client URL (SSRF).
  - `sql_injection.py` — **PY-WL-118** (ERROR, sink, PREVIEW): untrusted → SQL/DB execute.
  - `degenerate_boundary.py` — **PY-WL-119** (ERROR, PREVIEW): no-op `return <param>` validator.
  - `stored_taint.py` — **PY-WL-120** (ERROR, PREVIEW): stored/persisted taint reaches trusted state un-validated (suppress-and-delegate to 101).
  - `untrusted_to_xml.py` — **PY-WL-121** (ERROR, sink, PREVIEW): untrusted → XML parse (XXE, CWE-611).
  - `untrusted_to_template.py` — **PY-WL-122** (ERROR, sink, PREVIEW): untrusted → server-side template compile (SSTI, CWE-1336).
  - `untrusted_to_reflection.py` — **PY-WL-123** (WARN, sink, PREVIEW): tainted attribute NAME → `setattr`/`getattr` (CWE-915).
  - `untrusted_to_native.py` — **PY-WL-124** (ERROR, sink, PREVIEW): untrusted path → native-library load (CWE-114).
  - `untrusted_to_log.py` — **PY-WL-125** (INFO, sink, PREVIEW): untrusted as log format string (CWE-117).
  - `untrusted_to_mail.py` — **PY-WL-126** (WARN, sink, PREVIEW): untrusted recipient/message → `SMTP.sendmail` (CWE-93).

**Public surface / entry points:**
- `build_default_registry(config, rules=None) -> RuleRegistry` (`scanner/rules/__init__.py:235`) — THE registry factory.
- `BUILTIN_RULE_CLASSES` (`scanner/rules/__init__.py:86`) — single source of truth shared with the grammar.
- `RuleMetadata` (`scanner/rules/metadata.py:15`) and `modulate` (`scanner/rules/severity_model.py:47`).
- `TaintedSinkRule` (`scanner/rules/_sink_helpers.py:735`) — sink-rule base (template method).
- `external_boundary` / `trust_boundary` / `trusted` (`decorators/__init__.py:6`) — the trust vocabulary applied to user code.
- Each rule class satisfies the duck-typed `Rule` protocol (rule_id, metadata, `check`); they are registered, not called directly.

**Dependencies (graph-derived):**
- Inbound (who calls into this):
  - **S1 Scanner Engine** → `build_default_registry` — `WardlineAnalyzer._analyze_inner` imports it (`scanner/analyzer.py:31`) and calls it (`scanner/analyzer.py:960`); verified via `entity_callers_list` (one resolved caller: `_analyze_inner`).
  - **S1 Scanner Engine** → `BUILTIN_RULE_CLASSES` — `default_grammar()` imports and wraps it into the `TrustGrammar` (`scanner/grammar.py:228-230`).
  - **S3 Taint Engine** consumes the decorators (not a call edge): `trusted`/`trust_boundary`/`external_boundary` have ZERO project callers (`entity_callers_list` → empty) because they are AST markers. The taint `decorator_provider` reads the decorator SYNTAX from `entity.node.decorator_list` and matches by resolved FQN (`_is_builtin_decorator_fqn`) — the static analyzer parses source, so it never sees the runtime `_wardline_*` stamps, which exist only on a live function object (`decorators/_base.py:59-62`).
- Outbound (what this calls/imports):
  - **S1 Scanner Engine** — `scanner.context` (`AnalysisContext`, `RuleRegistry`, `_RuleClass` protocol), `scanner.grammar.BUILTIN_BOUNDARY_TYPES`, `scanner.index.Entity`, `scanner.ast_primitives.resolve_call_fqn`.
  - **S3 Taint Engine** — `core.taints` (the `TaintState` lattice, `RAW_ZONE`, `TRUST_RANK`); `scanner.taint.decorator_provider._is_builtin_decorator_fqn` + `_shadowed_builtin_roots` (used by PY-WL-110/114 — `contradictory_trust.py:30`, `invalid_decorator_level.py:20`).
  - **S5 Findings** — `core.finding.{Finding, Kind, Severity, Location, Maturity, ENGINE_PATH}` (the finding model every rule constructs).
  - **S8 Identity & SEI** — `core.finding.compute_finding_fingerprint` (every finding's identity). S2 owns its own `_fingerprint.entity_source_fingerprint`, which only feeds the `taint_path` argument to that S8 call.
  - **S4 Core Orchestration & Config** — `core.registry.REGISTRY` (decorator validation, `decorators/_base.py:16`), `core.protocols.Rule`, and `WardlineConfig` (`rules_enable`/`rules_severity`).

**Patterns Observed:**
- **Duck-typed, base-less rule contract.** Every rule is a plain class with `rule_id`, `metadata`, `__init__(self, base_severity=None)`, and `check(context) -> list[Finding]`; it structurally satisfies the `Rule` Protocol (S4) — no ABC, no inheritance except the sink family. Confirmed across all 26 files (e.g. `untrusted_reaches_trusted.py:79-86`).
- **Explicit central registration, not auto-discovery.** `_ALL_RULE_CLASSES` is a hand-ordered tuple (`__init__.py:52-80`) whose order is the deterministic emission order; `BUILTIN_RULE_CLASSES` is the single alias the grammar reuses so the two construction paths cannot drift (`__init__.py:83-86`). Config-malformation fails LOUD to a `WLN-ENGINE-POLICY-CONFIG` ERROR finding rather than silently mis-enabling rules.
- **Two gating regimes.** Declaration-gated rules (101/102/105/110/111/113/114/119) emit at base severity — the decorator IS the opt-in. Tier-modulated rules (103/104 + whole sink family) scale base by the resolved taint tier via `modulate` and go silent in the developer-freedom zone (`UNKNOWN_RAW → NONE`), so undecorated code stays quiet (`severity_model.py:47-53`, `broad_exception.py:49-52`, `_sink_helpers.py:849`).
- **Decorators are inert markers, read from the AST.** `apply_marker` stamps `_wardline_*` and returns the function unchanged — no wrapper, no runtime enforcement (`decorators/_base.py:1-10, 39-63`). This is the deliberate lightweight departure from wardline.old's runtime-enforcing factory.
- **Fingerprint-discriminator discipline (wlfp2).** `multi_emit` rules must discriminate co-located findings by entity-relative span/ordinal (call-line − def-line + col span, or PY-WL-114's decorator ordinal) since `line_start` left the hash; singletons use the position-free interpreter-stable `entity_source_fingerprint` so a comment move is stable but a body change is not (`metadata.py:23-32`, `build_sink_finding` `_sink_helpers.py:680-732`, `invalid_decorator_level.py:189-205`).
- **Template-method sink base.** `TaintedSinkRule.check` is the single check loop; subclasses set `SINKS`/`SINK_SPECS`/`SINK_SEVERITIES` and override `_accept_call`/`_arg_guarded`/`_taint_anchor_call`; `__init_subclass__` fails at import if required attrs are missing (`_sink_helpers.py:780-784`). Consolidated 2026-06-10 from two former mixins.
- **Fail-closed taint resolution in one place.** `resolved_arg_taints` is the sole arg resolver; a missing L2 snapshot yields a pessimistic `UNKNOWN_RAW` per arg and records the degradation as a per-scan FACT finding (not a `UserWarning`, so a warnings-as-error embedder can't abort a rule) — `_sink_helpers.py:483-520`.

**Concerns:**
- **Rules import engine-internal PRIVATE symbols across the subsystem boundary.** PY-WL-110 and PY-WL-114 import `_is_builtin_decorator_fqn` and `_shadowed_builtin_roots` from S3's `scanner.taint.decorator_provider` (`contradictory_trust.py:30`, `invalid_decorator_level.py:20`). Deliberate (the rules must use the engine's exact seeding predicate so they "cannot drift"), but it couples the rule layer to underscore-prefixed engine internals — a refactor of the provider's private API silently breaks two security rules.
- **Sink rules write into the "read-only" `AnalysisContext`.** `resolved_arg_taints` mutates `context.flow_insensitive_fallbacks` (`_sink_helpers.py:512`), the one field of the otherwise frozen/`MappingProxyType`-wrapped context left as a plain mutable `set` (`scanner/context.py:136`). Documented as a diagnostics side channel, but it punches a hole through the read-only contract every other field upholds, and it means a rule's `check()` has a side effect on shared engine state.
- **~648-line hand-rolled reachability/CFG in `_ast_helpers.py` is the soundness-critical surface.** The fail-open / no-rejection-path detection for the boundary-integrity family (102/111/113/119) lives entirely in intricate own-scope statement-walking with a documented 4-way partition invariant (`_ast_helpers.py:382-392`). A subtle bug in `_stmt_always_terminates`/`handler_substitutes_on_failure` directly produces FN/FP in security rules, and the logic duplicates control-flow reasoning rather than reusing the taint engine's.
- **Latent cross-subsystem invariant dependency (MIXED_RAW).** PY-WL-101 and `modulate` would DISAGREE on `MIXED_RAW` (101 fires; modulate suppresses) — currently inert only because the S3 engine guarantees `MIXED_RAW` is unreachable (`severity_model.py:21-36`, `untrusted_reaches_trusted.py:37-57`). The rule lattice's soundness here is hostage to an invariant maintained elsewhere; if S3's parser guards ever regress, the disagreement becomes live.
- **~42% of the lattice is PREVIEW.** 11 of 26 rules carry `Maturity.PREVIEW` (116-126 family + 119/120); `RuleRegistry.run` stamps that maturity onto every finding (`scanner/context.py:208-211`). Expected for the 2026-06-10 coverage-gap families, but nearly half the vocabulary is non-STABLE and the catalog should not treat sink coverage as settled.
- **Minor: reserved-but-unused parameters.** `module_prefix` on `collect_sink_bindings` (`_sink_helpers.py:249`) and `resolve_bound_call_fqn` (`:400`) are `# noqa: ARG001 — reserved` dead params for a local-class-constructor feature "not in v1" — mild YAGNI carried in the hot path.
- No base-package zero-dep violation observed (decorators import only `core.registry`/`core.taints`; rules use only stdlib `ast`/`hashlib`/`fnmatch`); `from __future__ import annotations` is universal.

**Confidence:** High — Read in full: `rules/__init__.py`, `metadata.py`, `severity_model.py`, `_ast_helpers.py`, `_sink_helpers.py`, `_fingerprint.py`, all three `decorators/*`, the S1 `scanner/context.py` contract, and 6 representative rules across families (101/102 boundary, 103 exception, 106 sink, 110/114 decorator-policing); skimmed `rule_id`/`severity`/`maturity`/docstring for the remaining 20 rules. Cross-subsystem edges are graph-derived (`entity_callers_list` confirmed S1 `_analyze_inner` → `build_default_registry` and zero runtime callers of the decorators) and corroborated with `file:line` imports (`analyzer.py:31/960`, `grammar.py:228-230`). Lower-confidence point: `core.taints`/`core.finding` are physically in `core/` and split across S3/S5/S8 by responsibility per the spec's label table rather than by an owned-file boundary; the exact S-label split of those modules is the owning agents' call.
