### 11. Verification properties

Six properties determine whether a wardline enforcement tool — or enforcement regime (§15.4) — is assessable by an independent evaluator (IRAP — Information Security Registered Assessors Program — or equivalent). These are evaluation criteria, not product features — they define what an assessor can verify, not what a vendor should market. In a multi-tool regime, each property applies per tool for the rules and layers that tool implements; the regime satisfies the property when its constituent tools collectively cover the full rule set.

**1. Golden corpus** *(framework invariant).* A curated set of known-good and known-bad specimens that the tool MUST correctly classify. Minimum smoke test: 3 true positives and 2 true negatives per rule — sufficient to verify basic functionality but not to establish statistical confidence in precision or recall. For meaningful measurement, the corpus SHOULD grow proportionally: sufficient samples per class (true positive, true negative, adversarial) per rule to support meaningful confidence intervals — approximately 30 or more per class as a practical lower bound for stabilising simple proportion estimates. The corpus MUST include adversarial specimens — code that looks like a violation but is not, and code that looks clean but contains one. The corpus is CODEOWNERS-protected; changes require designated reviewer approval. An assessor can run the corpus independently and compare results.

#### Specimen structure

Each corpus specimen is a self-contained, labelled test case in YAML format. A specimen declares: a unique identifier, the rule it tests, the taint state context, the expected severity and exceptionability, a verdict (positive — should fire, or negative — should not fire), a self-contained code fragment with wardline annotations, and the expected match (line and matched text). Specimens are organised by rule and taint state — `corpus/{rule}/{taint_state}/` — so that coverage gaps are visible at the filesystem level.

**Specimen YAML schema** (example shown for Python regime):

```yaml
# corpus/WL-001/INTEGRAL/wl001-audit-get-default.yaml
id: "WL-001-AT-001"
rule: "WL-001"                    # Framework rule identifier
binding_rule: "PY-WL-001"         # Binding-specific rule (if applicable)
taint_state: "INTEGRAL"        # One of the eight effective states (§6.1)
expected_severity: "ERROR"         # ERROR, WARNING, or SUPPRESS
expected_exceptionability: "UNCONDITIONAL"  # UNCONDITIONAL, STANDARD, or RELAXED
verdict: "positive"                # "positive" (should fire) or "negative" (should not)
category: "standard"               # "standard", "adversarial_false_positive",
                                   #   "adversarial_false_negative", or "taint_flow"
description: >
  A .get() call with a default value inside a @integral_read function.
  This is the canonical Tier 1 fabricated-default pattern.
fragment: |
  from wardline import integral_read

  @integral_read
  def get_audit_record(run_id: str) -> dict:
      record = db.fetch(run_id)
      classification = record.get("security_classification", "OFFICIAL")
      return {"run_id": run_id, "classification": classification}
expected_match:
  line: 6                          # 1-indexed line within the fragment
  text: 'record.get("security_classification", "OFFICIAL")'
  function: "get_audit_record"
```

**Required fields:** `id`, `rule`, `taint_state`, `expected_severity`, `expected_exceptionability`, `verdict`, `fragment`, `expected_match`. **Optional fields:** `binding_rule` (required for binding-specific corpus), `category` (defaults to "standard"), `description`.

**Fragment requirements:** Each fragment MUST be a syntactically valid, self-contained compilation unit for the target binding (e.g., a Python module for the Python regime). Fragments MUST include all necessary imports, including wardline decorator imports. Fragments MUST NOT depend on external state, files, or network resources. The fragment's decorator annotations establish the taint context for rule evaluation — a fragment testing WL-001 in INTEGRAL context MUST include a function decorated with `@integral_read`, `@integral_writer`, or equivalent Tier 1 decorator.

**Expected match format:** The `line` field is 1-indexed within the fragment (not within any external file). The `text` field is the matched source text as it appears in the fragment — not the AST `unparse()` output, but the literal source substring. For multi-line expressions, `line` refers to the first line of the expression and `text` is the full expression with internal whitespace preserved. The `function` field identifies the enclosing function for context. Verification compares these fields against the SARIF result's `locations[0].physicalLocation.region.startLine`, `locations[0].physicalLocation.region.snippet.text`, and the enclosing `logicalLocation`. The `text` field MUST match the SARIF `snippet.text` exactly. Where the tool's snippet range differs from the specimen's expected text, the specimen is treated as a verification failure. Corpus authors SHOULD verify expected text against at least one reference implementation's output.

Minimum corpus coverage: one positive specimen and one negative specimen per cell in the severity matrix (rule × taint state). The eight rules — six pattern rules (WL-001 through WL-006) and two structural verification rules (WL-007 and WL-008) — across eight taint states yield 64 cells. The nominal floor under the one-positive/one-negative-per-cell rule is 128 specimens. In matrices containing SUPPRESS cells, the effective minimum is reduced because SUPPRESS cells require only negative specimens (confirming the rule does not fire in that context) — no positive specimen is needed where the expected behaviour is suppression. With the current severity matrix, two cells carry SUPPRESS severity, producing an effective minimum of 126 specimens. The exact count derives from the canonical matrix and adjusts if the matrix is revised. **Adversarial specimens** — code that resembles a violation but is structurally clean, or code that appears clean but contains a violation — are required in addition to the minimum and MUST target the highest-risk cells (UNCONDITIONAL severity, Tier 1 taint states). Adversarial specimens use the `category` field in the specimen schema to declare their type.

Minimum adversarial specimen requirements:

| Category | Description | Minimum Count | Target |
|----------|-------------|---------------|--------|
| `adversarial_false_positive` | Code that *looks like* a violation but is structurally clean — the tool MUST NOT fire | 1 per rule (8 minimum) | Rules with known false-positive patterns: WL-001 in validation boundary bodies (member access with defaults is legitimate validation); WL-002 existence-check inside validation boundaries; WL-003 broad exception catch with immediate re-raise |
| `adversarial_false_negative` | Code that *looks clean* but contains a violation — the tool MUST fire | 1 per rule (8 minimum) | Rules with known evasion patterns: WL-001 fabricated default via helper function; WL-007 unreachable rejection path (constant-false guard); WL-004 exception suppression via language-specific suppression idioms |
| `taint_flow` | Specimens testing taint propagation correctness across boundaries — the tool MUST correctly assign taint states at merge points and across function calls | See property 6 below | Tier contamination through container operations; one-hop indirection; declared-domain-default marker with and without overlay declaration |
| `suppression_interaction` | Specimens testing WL-001 optional-field suppression (§8.2.1) — the three-condition suppression rule where the field is declared optional-by-contract, the default matches the approved default, and the access occurs within a declared validation boundary | 3 minimum | One negative (all three conditions met — suppressed); one positive (default differs from approved default — ERROR/UNCONDITIONAL mismatch); one positive (correct default but outside a validation boundary — not suppressed) |

The adversarial categories are not exhaustive — tool authors SHOULD add adversarial specimens for any pattern where the tool's analysis produces borderline results. The minimum counts above are the floor for conformance assessment.

The expected match in each specimen aligns with the SARIF result structure (§11.1): rule identifier, location (file, function, line), and matched text. Verification is a structural comparison — the enforcement tool's SARIF output for the specimen MUST match the specimen's expected result fields. This makes the "independently evaluable" claim concrete: an assessor runs the tool against the corpus, compares SARIF output to expected results, and produces a pass/fail determination without subjective judgement.

Specimen code fragments are language-specific — a Python regime's corpus contains Python code, a Go regime's contains Go code — but the specimen metadata schema (identifier, rule, taint state, verdict, expected match) is shared across all regimes. This means an assessor familiar with the corpus format can evaluate any regime's corpus without learning a new schema.

**Multi-tool corpus partitioning.** In an enforcement regime comprising multiple tools, each tool maintains corpus specimens for the rules it implements. A Wardline-Core linter that implements WL-001 through WL-004 maintains specimens for those four rules. A separate tool implementing WL-005 through WL-007 maintains specimens for those three rules. Each tool's specimens are tagged with the tool identifier so that an assessor can run each tool against its own specimen subset and verify independently. The regime's corpus is the union of all constituent tools' corpora; regime-level coverage MUST satisfy the minimum specimen counts (§11, per cell in the severity matrix) across the full rule set. Specimens MAY additionally be tagged with the enforcement layer they test (static analysis, type system, runtime structural) so that Wardline-Type tools can maintain type-system-specific specimens distinct from pattern-rule specimens. Taint-flow specimens are maintained by the tool that implements taint-flow tracking (conformance criterion 4, §15.2). In a multi-tool regime, this is typically the Wardline-Core scanner. Tools that implement only pattern detection without taint tracking are exempt from taint-flow specimens but MUST accept taint-state context from the taint-tracking tool's output or the regime orchestrator's equivalent interchange.

**Corpus independence.** A golden corpus maintained solely by the tool implementer without independent review is self-assessment — the same actor defines the tests and claims conformance. To support independent evaluation, the corpus MUST satisfy the following independence requirements:

- **Separate publication.** The corpus is published as a versioned artefact independent of the tool release. An assessor can obtain the corpus without obtaining the tool, and can verify that the corpus was not modified to match the tool's behaviour.
- **Version binding.** Each corpus release declares the specification version (e.g., "Wardline v0.2.0") and the severity matrix revision it tests. A corpus tested against a different matrix version is not evidence of conformance.
- **Independent review.** Corpus additions and modifications SHOULD be reviewed by at least one reviewer who is not a contributor to the enforcement tool's implementation. This prevents the corpus from being shaped to match the tool's false-negative surface. The CODEOWNERS protection on the corpus directory enforces this structurally.
- **Integrity verification.** The published corpus includes a manifest file listing all specimens with their SHA-256 hashes. An assessor verifies corpus integrity before running tests. A specimen whose hash does not match the manifest is rejected.
- **Reproducible evaluation.** The `wardline corpus verify` command (a Wardline-Governance capability — see §15.3.1) takes a corpus path and a tool binary, runs the tool against every specimen, and produces a structured pass/fail report. The evaluation is deterministic (verification property 5) — identical corpus + identical tool = identical report.

At DRAFT v0.3.0, the corpus is maintained alongside the specification and is not yet independently published. Full independence requirements apply from v1.0.

**2. Self-hosting gate** *(framework invariant).* Each enforcement tool's own source MUST pass the rules that tool implements. A linter plugin that detects WL-001 MUST NOT violate WL-001 in its own source. A type checker plugin that enforces tier mismatches MUST pass tier-mismatch checks on its own code. The tool is used as part of the CI setup for the project that builds it. A tool that cannot enforce its own wardline on itself lacks credibility. Self-hosting is both a verification property and a development discipline — it surfaces false positives early and ensures the tool's authors experience the governance model they impose on others. Tools that perform no code analysis (e.g., a pure governance orchestrator satisfying Wardline-Governance) are exempt from self-hosting.

**3. Measured precision.** The false positive rate MUST be measured, tracked, and published per cell (rule × taint state), not merely per rule *(framework invariant)*. The recommended calibration point is an 80% precision floor applied to each cell individually: below this threshold, a rule SHOULD NOT earn blocking status in that cell's CI gate context. A rule at 90% precision in INTEGRAL but 55% in UNKNOWN_GUARDED SHOULD NOT earn blocking status in the failing cell — the averaged number hides the context where trust is being lost. For MIXED_RAW cells specifically, a lower precision floor of 65% is permitted, acknowledging that the conservative join (§6.1) generates higher false-positive rates in mixed-taint contexts; this lower floor prevents MIXED_RAW noise from forcing premature demotion of rules that perform well in single-tier contexts. Projects MAY adjust thresholds with documented rationale — a greenfield project with limited corpus MAY accept 75% during early development. For systems under the ISM or equivalent high-assurance frameworks, the starting recommendation is 90% precision for UNCONDITIONAL cells, since false positives on invariant findings directly erode assessor confidence. The measurement and publication obligations are non-negotiable regardless of threshold. The golden corpus is already organised by rule and taint state (§11, property 1) — the infrastructure for per-cell measurement is present; this requirement makes the normative expectation match.

**Interaction with UNCONDITIONAL exceptionability.** The per-cell precision floor and the exceptionability model interact at a specific pressure point: if an UNCONDITIONAL cell measures below its precision floor, the rule cannot be granted exceptions in that cell (UNCONDITIONAL), cannot be demoted to STANDARD without modifying the specification, and cannot be made non-blocking without undermining the exceptionability model. The resolution: a cell below the precision floor is a *tool defect*, not a governance problem. The rule implementation for that context returns to development — the corpus is not adjusted to make the numbers work, because that would undermine the corpus's role as independent verification evidence. UNCONDITIONAL status is a commitment that the rule is correct when it fires; if it isn't, the rule is broken, not the policy.

Note: precision and recall measured against the golden corpus are *corpus precision* and *corpus recall* — they measure the tool's performance against curated specimens, not against the operational prevalence of violations in production code. Operational precision may differ from corpus precision if the corpus does not reflect the distribution of code patterns in the target codebase. Bindings SHOULD track operational precision alongside corpus precision, using developer-confirmed true/false positive classifications or equivalent production-use feedback. Where operational precision diverges significantly from corpus precision for a cell, the corpus SHOULD be reviewed for representativeness. Operational precision tracking is a tool quality target, not a conformance requirement.

**Precision segmentation by code origin.** Bindings SHOULD track operational precision segmented by code origin — specifically, agent-generated code versus human-written code. As annotation coverage grows, annotations constrain the generation space and agents produce fewer pattern-rule violations in annotated contexts, but the false-positive rate may differ systematically between agent-generated and human-written code. Segmented measurement empirically validates whether annotation-constrained generation reduces MIXED_RAW noise (the conservative join is the primary source of false positives on container types — §6.1) and identifies whether the precision floors need separate calibration for agent-heavy codebases. The segmentation mechanism is a binding-level decision — bindings MAY use VCS-level provenance metadata (e.g., commit author tags distinguishing human and agent contributions), IDE-level origin tracking, or any mechanism that reliably attributes code origin. This is a SHOULD-level binding requirement, not a framework invariant — it produces operational intelligence, not conformance evidence.

**Compound call pattern annotation.** When measuring precision and recall across implementations, the golden corpus SHOULD annotate specimens that contain compound call patterns (method chaining, generators, context managers, async iterators) so that divergent taint tracking at SHOULD-level patterns (§6.5) can be isolated from true precision/recall differences. Without this annotation, a scanner that tracks taint through method chains and one that falls back to UNKNOWN_RAW will appear to have different precision on the same corpus, confounding tool quality with compound-pattern support.

**4. Measured recall.** The false negative rate MUST be measured against the golden corpus and published *(framework invariant)*. The recommended calibration point is a 70% recall floor for STANDARD and RELAXED cells: a rule that misses more than 30% of known-bad specimens SHOULD NOT ship — it returns to development. **For UNCONDITIONAL cells, the recommended recall floor is 90%.** UNCONDITIONAL findings represent patterns that are categorically wrong in their declared context — the framework commits that these patterns cannot be overridden. A 70% recall floor on UNCONDITIONAL cells would mean up to 30% of known-bad patterns in the highest-severity contexts are missed, which is inconsistent with the assurance claim that these patterns "cannot be overridden." The higher floor reflects the higher consequence: if the framework declares a pattern is always wrong, the tool MUST detect it reliably. The recall floor is lower than the precision floor for STANDARD cells because false negatives are less immediately corrosive to developer trust than false positives, but a tool that misses known threats cannot justify its governance burden. Projects may adjust with documented rationale, but recall MUST be measured and tracked. The same corpus-vs-operational distinction applies: corpus recall measures detection against known specimens; operational recall depends on the diversity and representativeness of the corpus.

**5. Deterministic output.** The same tool binary, given identical input, MUST produce byte-identical SARIF output in verification mode (§11.1). No randomness, no model inference, no non-deterministic ordering. An assessor who runs the tool twice on the same codebase and gets different results cannot certify the tool. Determinism is a binding requirement — language-specific bindings MUST ensure deterministic output for their enforcement tools. It is not a quality-of-life feature — it is an auditability requirement. **Scope:** this property requires same-tool repeatability — the same tool binary run twice on the same input produces the same output. It does not require cross-tool byte-identity; different conformant tools will necessarily differ in `tool.driver` metadata, diagnostic phrasing, and serialization choices. Cross-tool comparison is performed at the semantic level (rule identifiers, taint states, severity levels), not at the byte level.

**6. Taint propagation correctness** *(binding requirement — tools implementing taint-flow tracking, conformance criterion 4).* Properties 1–5 verify that individual rules fire correctly in declared contexts. Property 6 verifies that the taint propagation engine correctly assigns taint states to values at merge points and across function boundaries. This is the core value claim of the framework — that data flowing from a Tier 4 source to a Tier 1 sink without passing through the required validation boundaries produces a finding — and it requires independent verification.

Taint-flow corpus specimens (category `taint_flow` in the specimen schema) test propagation correctness, not individual rule firing. Each specimen contains a multi-function code fragment where taint MUST be traced across at least one function boundary. Minimum taint-flow specimen requirements (binding-specific examples use Python syntax):

| Scenario | Description | Minimum |
|----------|-------------|---------|
| Direct boundary-to-boundary | Tier 4 return reaching Tier 1 sink without validation | 1 positive |
| Direct boundary-to-boundary (clean) | Tier 4 return reaching Tier 1 sink *with* shape and semantic validation | 1 negative |
| Two-hop indirection | Tier 4 data through up to two undecorated helpers to Tier 1 sink | 1 positive |
| Shape-only reaching T2 sink | Tier 3 (guarded) data reaching Tier 2 sink without semantic validation | 1 positive |
| Container contamination | Cross-tier container merge reaching a consumer at a different tier (e.g., Python: `{**tier1_data, **tier3_data}`) | 1 positive |
| Join semantics | Merge of two different-tier values produces MIXED_RAW | 1 positive |
| Declared-domain-default interaction | Correctly declared domain-default marker (binding-specific: Python `schema_default()`, other bindings substitute equivalent) does not fire WL-001 | 1 negative |
| Declared-domain-default without overlay | Domain-default marker wrapper with no overlay declaration fires WL-001 | 1 positive |

These specimens are in addition to the per-cell minimum (property 1) and the adversarial minimum. They are required for any tool claiming conformance criterion 4 (taint-flow tracking). Tools implementing only pattern detection without taint flow (e.g., advisory ruff rules) are exempt.

These properties are independently evaluable *(framework invariants — properties 1–4; binding requirements — properties 5–6)*. An assessor does not need access to the development team, the tool's source, or the project's history. They need the golden corpus, the tool binaries, and a test environment. For a single tool, if the tool satisfies all six properties for the rules it implements, the assessor can certify that the tool's declared enforcement behaviour is testable, deterministic, and evidenced against the supplied corpus. For an enforcement regime (§15.4), the assessor evaluates each constituent tool against the properties for its declared rule subset, then verifies that the union of all tools' coverage satisfies the regime-level requirements. If any tool or the regime as a whole does not satisfy its applicable properties, the claims are unverifiable regardless of actual capability.

#### 11.1 Findings interchange format

Enforcement tools MUST produce findings in SARIF v2.1.0 (Static Analysis Results Interchange Format, OASIS standard). SARIF is the established interchange format for static analysis tools; adopting it provides native integration with code scanning platforms (GitHub, Azure DevOps), IDE extensions, and existing assessment workflows without requiring custom tooling.

Wardline-specific metadata that SARIF does not natively represent is carried in SARIF's `properties` extension bags, which are designed for domain-specific extensions.

**Normative SARIF example.** The following example shows a complete single-finding SARIF result from a Wardline-Core scanner. This is the minimum structure an assessor should expect from any conformant tool:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "wardline-scanner",
        "version": "0.1.0",
        "rules": [{
          "id": "WL-001",
          "shortDescription": { "text": "Member access with fallback default" },
          "defaultConfiguration": { "level": "error" }
        }]
      }
    },
    "results": [{
      "ruleId": "WL-001",
      "level": "error",
      "message": {
        "text": "Fabricated default on tier-sensitive path: .get(\"security_classification\", \"OFFICIAL\")"
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "src/adapters/partner.py" },
          "region": {
            "startLine": 42,
            "snippet": { "text": "record.get(\"security_classification\", \"OFFICIAL\")" }
          }
        },
        "logicalLocations": [{
          "fullyQualifiedName": "src.adapters.partner.parse_partner_record",
          "kind": "function"
        }]
      }],
      "properties": {
        "wardline.taintState": "INTEGRAL",
        "wardline.enclosingTier": 1,
        "wardline.annotationGroups": [1, 5],
        "wardline.exceptionability": "UNCONDITIONAL",
        "wardline.excepted": false,
        "wardline.dataSource": "partner-api",
        "wardline.retroactiveScan": false
      }
    }],
    "properties": {
      "wardline.manifestHash": "sha256:a1b2c3d4e5f6...",
      "wardline.overlayHashes": ["sha256:f6e5d4c3b2a1..."],
      "wardline.expeditedExceptionRatio": 0.05,
      "wardline.coverageRatio": 0.73,
      "wardline.controlLaw": "normal",
      "wardline.deterministic": true,
      "wardline.inputHash": "sha256:7a8b9c0d1e2f...",
      "wardline.inputFiles": 142,
      "wardline.governanceProfile": "assurance"
    }
  }]
}
```

**Key structural points for assessors:**
- Each `result` carries wardline property bags declaring taint state, tier, exceptionability, and exception status
- Each `run` carries regime-level metrics: manifest hash, coverage ratio, expedited ratio, and control-law state
- The `ruleId` matches the framework rule identifier (WL-001–WL-008) or binding rule identifier (JV-WL-001, PY-WL-001)
- `wardline.excepted: true` findings are still emitted — exceptions suppress CI failure, not finding visibility
- In verification mode (see determinism requirements below), `run.invocations` is omitted for byte-identical output

The following wardline-specific properties are required:

**Property name reuse — `wardline.retroactiveScan`.** This property is defined at both `result` level and `run` level with distinct semantics. The result-level property marks individual findings arising from retrospective review of code merged during a prior direct-law or alternate-law window (§10.5). The run-level property marks the run as containing any retrospective findings. Both may be present simultaneously and are independently meaningful.

**On each `result` (individual finding):**

- `wardline.taintState` — the taint state of the enclosing context (e.g., INTEGRAL, ASSURED, EXTERNAL_RAW)
- `wardline.enclosingTier` — the authority tier (1, 2, 3, 4) of the enclosing scope
- `wardline.annotationGroups` — which of the 17 annotation groups are declared on the enclosing function. This is the cross-binding machine-readable identity for annotation context; bindings MUST use the Part I group numbers, not binding-specific annotation names
- `wardline.exceptionability` — the exceptionability class for this finding (UNCONDITIONAL, STANDARD, RELAXED, TRANSPARENT)
- `wardline.excepted` — boolean indicating whether an active exception covers this finding. Excepted findings are still emitted — they are visible, not suppressed
- `wardline.dataSource` — the named data source from the wardline manifest, if applicable
- `wardline.retroactiveScan` — boolean indicating whether this specific finding arose from retrospective review of code merged during a prior direct-law or alternate-law window (§10.5), as distinct from a finding caught at the normal enforcement boundary
- `wardline.exceptionRecurrence` *(SHOULD)* — integer count of how many times the exception at this location has been renewed (§10.4). Present only on findings with active exceptions. A count of 2 or more indicates the exception has been renewed at least once without resolving the underlying violation
- `wardline.tierLabel` *(SHOULD)* — see the definition below

**On each `run` (tool execution):**

- `wardline.manifestHash` — SHA-256 hash of the root wardline manifest file content (raw bytes as stored on disk), emitted as `sha256:<hex>`. The hash is computed over the file's byte content, not a parsed-and-reserialized form — this ensures any whitespace or formatting change is detected
- `wardline.overlayHashes` — SHA-256 hashes of all overlay manifest files consumed, each computed identically to `wardline.manifestHash`. The array MUST be sorted lexicographically by the overlay's forward-slash-normalized path relative to the project root, so that the ordering is deterministic regardless of filesystem enumeration order
- `wardline.expeditedExceptionRatio` — the proportion of active exceptions granted through the expedited governance path (§10.4), computed from the exception register
- `wardline.deferredFixRatio` — the proportion of active exceptions that represent deferred architectural fixes rather than genuine domain variance (§14.1.3)
- `wardline.coverageRatio` — annotation coverage from the fingerprint baseline (§10.2)
- `wardline.controlLaw` — current enforcement state: `"normal"`, `"alternate"`, or `"direct"` (§10.5)
- `wardline.controlLawDegradations` — when control law is alternate, lists the specific degradation conditions (e.g., `["precision_below_floor", "ratification_overdue"]`)
- `wardline.retroactiveScan` — boolean indicating whether this run includes retrospective findings from a prior direct-law or alternate-law window (§10.5)
- `wardline.deterministic` — boolean self-report that the tool believes its output is deterministic. This property is a declaration of intent, not verification evidence. Assessors verify determinism independently by comparing outputs from identical inputs (property 5). The self-report allows SARIF consumers that do not perform independent verification to distinguish runs that claim determinism from runs that do not
- `wardline.governanceProfile` — the declared governance profile: `"lite"` or `"assurance"` (§15.3.2). Recorded from the root manifest's `governance_profile` field
- `wardline.inputHash` — cryptographic hash of the analysed source files, computed using the hash-of-hashes construction defined below. This enables an assessor to verify determinism independently from the SARIF output alone: two runs with identical `wardline.inputHash` and identical `wardline.manifestHash` MUST produce byte-identical SARIF in verification mode (§11.1). Without this property, an assessor comparing two SARIF runs cannot distinguish "different output because different input" from "different output because non-deterministic tool"

Example run-level properties when pre-generation projection is available:

```json
{
  "wardline.manifestHash": "sha256:a1b2c3d4e5f6...",
  "wardline.inputHash": "sha256:0f9e8d7c6b5a...",
  "wardline.inputFiles": 42,
  "wardline.controlLaw": "normal",
  "wardline.projectionAvailable": true,
  "wardline.projectionCurrency": "2026-02-01T09:30:00Z"
}
```

If `wardline.projectionAvailable` is absent or `false`, consumers MUST NOT assume that projection currency is known; absence of `wardline.projectionCurrency` means the projection was not emitted for this run, not that the projection is current.

**`wardline.inputHash` computation.** The hash MUST be computed as follows:

1. **Determine the analysed file set.** The set of files the tool consumed during this run. Tools MUST emit a `wardline.inputFiles` run property (integer count) alongside `wardline.inputHash` so that an assessor can detect file-set divergence between tools in a multi-tool regime. The file set is tool-defined — different tools may analyse different file subsets (a Python linter analyses `.py` files; a manifest validator analyses `.yaml` files). Cross-tool inputHash comparison is not expected; the hash verifies same-tool repeatability.
2. **Resolve symlinks.** Symbolic links MUST be resolved to their target paths before hashing. The hash reflects the actual file content, not the link structure.
3. **Normalize paths.** Each file's path is expressed relative to the project root using forward-slash separators regardless of the host operating system. Leading `./` is stripped. Example: `src/adapters/partner.py`, not `.\src\adapters\partner.py`.
4. **Compute per-file digests.** For each file in the analysed set, compute SHA-256 of the file's raw byte content.
5. **Form digest records.** For each file, form a record: `<normalized-path>\x00<hex-digest>` (path, null byte, lowercase hex SHA-256 digest).
6. **Sort and hash.** Sort records lexicographically by normalized path. Compute SHA-256 over the concatenation of all records (each terminated by `\n`). Emit as `sha256:<hex>`.

This hash-of-hashes construction avoids boundary ambiguity that arises from concatenating file contents directly — file content containing the path separator or null bytes cannot produce collisions with the record structure.

**Annotation change impact preview.** When a tier assignment or annotation changes, enforcement tooling SHOULD support a cascade view showing the downstream effect of the change. The SARIF output enables this through an optional `relatedLocations` array on each result and a run-level `wardline.impactPreview` property:

- **Primary span.** The changed annotation or tier assignment — carried in the result's `locations[0]` as usual.
- **Secondary spans.** Code locations whose compliance status changes as a consequence of the annotation change — carried in the result's `relatedLocations` array. Each related location uses `wardline.impactKind` in its properties bag to declare the nature of the impact: `"newFinding"` (a rule that now applies but did not before), `"resolvedFinding"` (a rule that no longer applies), or `"severityChange"` (same rule, different severity or exceptionability class).
- **Run-level summary.** The `wardline.impactPreview` property on the `run` object is a summary object declaring the total counts: `{"newFindings": 3, "resolvedFindings": 1, "severityChanges": 2, "affectedModules": ["src/adapters/", "src/service/"]}`.

This metadata is sufficient for bindings to render a cascade view — e.g., "changing `@validates_shape` to `@validates_external` on `parsePartnerResponse()` resolves 1 finding and introduces 2 new findings across 2 modules." The presentation is a binding-level UX concern (see Part II); Part I specifies only the SARIF metadata that enables it. Tools that do not implement impact preview simply omit the `wardline.impactPreview` run property and the `relatedLocations` entries — existing SARIF consumers are unaffected.

The SARIF `tool.driver.rules` array carries the rule definitions (WL-001 through WL-008) with their framework-level default severity. Per-taint-state severity — which varies by enclosing context, not by rule alone — is expressed on each `result` through the `wardline.taintState` property and the result's own `level` field. The rule definition is global; the severity is context-sensitive. An assessor reads the rule definition once and evaluates each result's severity against its taint state.

Determinism (verification property 5) applies to the normative SARIF output. Enforcement tools MUST support a **verification-mode** output profile in which `run.invocations` is either omitted entirely or normalised to fixed values (no wall-clock timestamps, no process identifiers, no run-specific metadata). In verification mode, identical input (same code, same manifest, same configuration) run by the same tool binary MUST produce byte-identical SARIF. This requires deterministic ordering of results (by file path, then line number, then rule identifier, then startColumn). Where `startColumn` is unavailable or ties persist, `snippet.text` is used as the final tiebreak, compared lexicographically. Common non-determinism sources that implementations MUST eliminate in verification mode: hash-map iteration order in result collection, thread-pool or parallel-worker result aggregation order, locale-dependent string formatting, and floating-point representation instability across platforms (ratio values such as `wardline.coverageRatio` SHOULD use fixed decimal notation, e.g., `0.73` not `7.3e-1`). Outside verification mode, tools MAY include volatile invocation metadata for operational use, but that output is not subject to the byte-identical requirement and MUST NOT be used for independent assessment.

**Multi-tool SARIF aggregation.** In an enforcement regime (§15.4) comprising multiple tools, each tool produces its own SARIF `run` within the SARIF log. A SARIF log is defined as an array of runs; multi-tool output is a single SARIF log containing one run per tool. Each run identifies its producing tool via the `tool.driver` object and declares which wardline rules it covers in the `tool.driver.rules` array. Regime-level run properties — `wardline.coverageRatio`, `wardline.expeditedExceptionRatio`, `wardline.controlLaw` — are computed by the regime orchestrator (typically a Wardline-Governance tool) and carried on a dedicated aggregation run whose `tool.driver.name` identifies the orchestrator. The aggregation run contains no code-level findings; it exists solely to carry regime-level metrics and to declare the regime composition (constituent tools and their profiles) in a `wardline.regimeComposition` property. This convention ensures that an assessor can distinguish per-tool findings from regime-level reporting and can verify regime coverage completeness from the SARIF log alone.

**`wardline.tierLabel`** — human-readable label *(SHOULD)*. Bindings SHOULD include a `wardline.tierLabel` property on each `result`, providing a plain-language label alongside the canonical `wardline.taintState` token. Examples: `"integral"` for INTEGRAL, `"unknown origin, guarded"` for UNKNOWN_GUARDED, `"external, unvalidated"` for EXTERNAL_RAW. The label is a single short phrase — no sentence case, no terminal punctuation. The canonical token remains the machine-readable key; the label exists for SARIF viewers, IDE hover tooltips, and human readers who encounter raw SARIF output without access to the specification. Bindings MAY localise the label text provided the canonical token is unchanged. Cost: one string field per finding. Benefit: eliminates the need for downstream tools to maintain their own display-name mapping tables.

Binding-specific annotation names such as `@validates_shape` or `@ValidatesShape` MAY be carried in additional result properties (for example, `wardline.enclosingAnnotation`) for diagnostic context, but those names are not part of the framework's cross-binding interoperability contract.

#### 11.2 Finding presentation guidance

This subsection is non-normative except where explicitly marked. It provides binding guidance for how findings are rendered to developers — in terminal output, IDE diagnostics, CI summaries, and code review annotations. The underlying SARIF output (§11.1) is unchanged; this subsection addresses the presentation layer that sits between SARIF and the developer.

The core principle: developers interact with findings, not matrices. The eight-state taint model and the 64-cell severity matrix are analytically necessary for the framework's precision guarantees, but exposing this machinery in primary finding messages trains developers to ignore findings rather than act on them. The presentation layer exists to translate framework semantics into actionable developer guidance without losing the precision that assessors require.

##### Three-layer finding message format

Bindings SHOULD present findings in three layers, progressively disclosing detail:

**Primary line** (always visible): consequence and offending code. No taint state token, no tier number, no framework internals. The developer sees *what is wrong* and *where*, without needing to understand the classification model. Example:

```
error[WL-001]: Fabricated default masks missing field
  --> src/adapters/partner.py:42:5
   |
42 |     classification = record.get("security_classification", "OFFICIAL")
   |                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

**Context line** (on expand or hover): tier context, plain-language explanation, and annotation provenance. The developer sees *why this matters here* — the connection between the annotation that established the context and the finding it produced. Example:

```
   note: taint context established here
  --> src/adapters/partner.py:38:1
   |
38 | @integral_read
   | ^^^^^^^^^^^ this annotation declares integral context
   |
   = help: in integral data, member absence is an integrity failure —
           a fabricated default silently replaces missing evidence
   = note: this finding is UNCONDITIONAL and cannot be excepted
   = see: wardline explain WL-001 INTEGRAL
```

**Properties bag** (SARIF): full metadata unchanged. The `wardline.taintState`, `wardline.enclosingTier`, `wardline.exceptionability`, and all other properties defined in §11.1 remain in the SARIF output for assessors, governance tooling, and downstream automation. The presentation layer does not alter, filter, or summarise the SARIF — it renders a human-readable view on top of it.

The three-layer pattern follows established compiler diagnostic design (e.g., Rust's primary + secondary span model). The primary span marks the violation site; the secondary span marks the annotation that established the taint context. This dual-span rendering lets developers see both *what is wrong* and *where the context comes from* in a single diagnostic, without requiring them to understand the tier model before they can act on the finding.

##### Presentation-layer state collapse

For developer-facing output — terminal, IDE, code review — bindings SHOULD collapse the eight effective states into three groups:

| Presentation group | Effective states | Plain-language label |
|---|---|---|
| **Trusted** | INTEGRAL, ASSURED | "trusted data" |
| **Validated** | GUARDED, UNKNOWN_GUARDED, UNKNOWN_ASSURED | "validated data" [^validated-collapse] |
| **Untrusted** | EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW | "untrusted data" |

[^validated-collapse]: UNKNOWN_GUARDED and UNKNOWN_ASSURED are grouped under "validated" because their enforcement consequences are similar to GUARDED (the data has passed validation gates). However, these states lack provenance — the data's origin is unknown. The collapsed label "validated data" is correct for describing the developer's coding posture (field access is safe) but does not convey the provenance gap. Bindings MAY append a provenance qualifier in the context line (e.g., "validated data, unknown origin") when the effective state is on the UNKNOWN chain.

Findings display the collapsed group by default. The precise effective state is available on expansion (context line) and is always present in the SARIF output (properties bag). The collapsed groups are a rendering convenience — they do not alter the framework's eight-state model, the severity matrix, or any normative requirement. An assessor evaluating SARIF output sees the canonical tokens; a developer reading terminal output sees the group label unless they expand the finding.

The grouping reflects the developer's decision surface: trusted data requires no guard code, validated data has passed at least one verification gate, untrusted data requires validation before use. Distinctions within groups (e.g., GUARDED vs. UNKNOWN_ASSURED) matter for governance and assessment but rarely change what the developer does in response to a finding.

##### `wardline explain` subcommand

Bindings SHOULD implement a `wardline explain` subcommand that renders the full derivation for a finding, following the `rustc --explain` pattern. Two invocation forms:

- **`wardline explain WL-001 INTEGRAL`** — renders the full derivation for a specific rule in a specific taint-state context: why the rule exists, why it carries ERROR severity in this context, why it is UNCONDITIONAL, the relevant worked example from the severity matrix rationale (§8.4), and the detection approach. This is the developer's entry point to the matrix without reading a 64-cell table.

- **`wardline explain WL-001`** — renders the full row: the rule's purpose, its severity across all eight taint states, its exceptionability class, known false-positive patterns, and common resolution strategies. Equivalent to the rule's entry in the severity matrix with human-readable commentary.

The `wardline explain` output is static documentation derived from the specification — it does not depend on the current project's manifest, annotations, or configuration. Bindings MAY generate explain content from the specification at build time or bundle it as static text. The output SHOULD be renderable in a terminal (plain text with ANSI formatting) and as Markdown (for IDE hover panels and web documentation).

##### Disagree workflow for UNCONDITIONAL findings

The 41% UNCONDITIONAL ratio in the severity matrix is high by industry standards. Developers who encounter false positives on UNCONDITIONAL findings — which cannot be excepted — have no governance mechanism to manage the disagreement. Without a structured feedback channel, the likely response is disengagement: developers stop reading findings, which defeats the framework's purpose regardless of its analytical precision.

Bindings SHOULD implement a "disagree" workflow for UNCONDITIONAL findings. This is a feedback channel, not an exception mechanism — it creates an auditable record but does NOT suppress the finding, does NOT bypass CI, and does NOT alter the finding's exceptionability class. The workflow:

1. Developer marks a specific finding as disputed (e.g., `wardline disagree WL-001 src/adapters/partner.py:42` or an IDE action).
2. The tool records the disagreement in a structured log: finding identifier, location, developer identity, timestamp, and a required free-text rationale.
3. The disagreement log feeds corpus maintenance — disputed findings that recur across multiple developers or projects are candidates for corpus review, precision recalibration, or rule refinement.
4. The finding remains visible, remains blocking, and remains UNCONDITIONAL. The disagreement is metadata about the developer's judgement, not an override of the framework's.

This follows the pattern established by Google's Tricorder ("Not useful" button) — the primary mechanism for identifying precision problems at scale is structured developer feedback, not top-down rule tuning.

**Relationship to precision metrics.** Disagreements are a feedback signal, not a precision measurement. A disagreement does not automatically count as a false positive for property 3 (measured precision) — the disagreement log records the developer's judgement, which may be wrong. Disagreements that the corpus maintainer confirms as genuine false positives feed into corpus maintenance and precision recalibration; disagreements that are confirmed as correct findings feed into developer guidance. The disagree workflow and the precision metric operate on different timescales: disagreements are immediate developer feedback; precision updates occur at corpus review cadence.

**Consumption cadence.** A disagreement log without a review process is a write-only artefact. The corpus maintainer (or designated governance role) SHOULD review the disagreement log at a defined cadence — recommended: once per manifest ratification cycle or quarterly, whichever is shorter. The review assesses whether recurring disagreements indicate a precision problem (the rule fires correctly but the context makes it feel wrong), a corpus gap (the rule fires incorrectly and the corpus does not cover the pattern), or a governance communication failure (the developer does not understand why the finding matters in this context). Disagreements that recur across multiple developers or projects are candidates for corpus review and rule recalibration. The review outcome — "corpus updated," "rule refined," "finding confirmed correct, developer guidance issued," or "no action" — SHOULD be recorded against the disagreement log entries to close the feedback loop.

##### Visual distinction for exceptionability classes

Bindings SHOULD render UNCONDITIONAL findings with a visually distinct presentation from STANDARD and RELAXED findings. The specific mechanism is binding-dependent — different prefix markers, colour coding, iconography, or severity indicators are all acceptable — but the developer SHOULD be able to determine a finding's exceptionability class from its visual presentation without expanding the detail view. The distinction answers the immediate question: "Can I govern this finding away, or must I fix the code?"

Suggested conventions (non-normative):

- UNCONDITIONAL: rendered as `error` with a distinct marker (e.g., `error[WL-001]!` or a lock icon in IDE contexts)
- STANDARD: rendered as `error` with standard formatting
- RELAXED: rendered as `warning`

##### Taint state omission for structural verification rules

For WL-007 (validation boundary integrity), WL-008 (validation ordering integrity), and WL-009 (restoration symmetry), bindings SHOULD omit the taint state from primary finding messages. These structural verification rules are UNCONDITIONAL across all eight effective states — the taint state of the enclosing context is irrelevant to the finding because the rule fires on structural properties (boundary declaration completeness, rejection-path reachability, restoration evidence presence) rather than data-flow properties.

Including the taint state in WL-007/WL-008/WL-009 primary messages trains developers to believe it matters for structural verification, creating a false mental model of how these rules operate. The taint state remains in the SARIF properties bag (§11.1) for completeness and assessor use, but the presentation layer should not foreground it.

Example — WL-007 without taint state (preferred):

```
error[WL-007]!: Validation boundary has unreachable rejection path
  --> src/validators/partner_schema.py:15:1
   |
15 | @validates_shape("partner_record")
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
   = help: the rejection path in this validator is guarded by a
           constant-false condition and will never execute
   = note: this finding is UNCONDITIONAL and cannot be excepted
```

Example — WL-007 with taint state (discouraged in primary output):

```
error[WL-007]: Validation boundary has unreachable rejection path
  in INTEGRAL context (Tier 1)
  ...
```

The "in INTEGRAL context" qualifier adds no information — WL-007 fires identically regardless of context. Omitting it reinforces the correct understanding that structural verification is context-independent.
