# Prompt: Build the v1.0 verification walkthrough scaffold

This is an instruction prompt for a fresh session. It is self-contained. Do not
assume conversational context from the session that produced it.

## 1. Context: why this scaffold exists

Wardline is a semantic boundary enforcement framework for Python at
`/home/john/wardline`. The project is in v1.0.0 recertification. A prior
investigation (in session `phase-4.4-test-quality-gates` on 2026-04-12)
produced two findings that shape this task:

**Finding A — the compliance ledger is structurally incomplete.**
`docs/spec/wardline-01-15-conformance.md` §15.1 (lines 11–24) defines the
nine required fields of a compliance obligation record: obligation ID, exact
source reference, requirement summary, claim scope, implementation surface,
evidence classes, compliance state, freshness binding, and reviewer metadata.
The current `docs/verification/2026-04-12-v1-0-compliance-ledger.md` and
`wardline.compliance.json` only carry a reduced subset (id, source_refs,
summary, state, evidence, tracker_ids, notes). They are missing claim_scope,
implementation_surface, evidence_classes (distinct from evidence paths),
per-record freshness_binding, and reviewer_metadata. Several source_refs are
file-level instead of clause-level. The derived matrix at
`docs/verification/2026-04-12-v1-0-cell-certification-matrix.md` has rows
C02, C03, C08, and R01–R14 backed by prose or criterion numbers instead of
concrete obligation IDs, so the matrix cannot be mechanically reduced to the
catalog.

**Finding B — the claim surface includes features that were never built.**
Git archaeology confirmed these are NOT regressions from collapsed
duplication:

- `PY-WL-010` (framework WL-009, "Tier 1 promotion on serialisation without
  restoration evidence") has never existed in any commit.
  `docs/spec/wardline-02-A-python-binding.md §A.3`, `§A.4.4`, `§A.11` and the
  80-cell binding matrix all fully specify it.
  `docs/requirements/spec-fitness/04-python-binding.yaml:278` even names the
  expected path `src/wardline/scanner/rules/py_wl_010.py`. No rule file, no
  `RuleId` enum member, no tests, no corpus specimens have ever been present.
- `@layer(N)` decorator (Group 6 Layer Boundaries per §A.4.2) has never been
  implemented. No decorator file, no registry entry, no scanner rule. The
  spec has had this since Part I was frozen; code has not followed.
- `trust_boundary` and `tier_transition` are placed in Group 6 of
  `src/wardline/core/registry.py`, but spec §A.4.2 defines Group 6 as
  `@layer` only and Group 16 as `@trust_boundary` + `@data_flow`.
  `tier_transition` is not in §A.4.2 at all; its docstring says it is an
  SCN-021 contradiction marker. This is the one genuine regression and is
  traced to bulk commit `77d374d` (Groups 3-17 in one shot) and subsequent
  reconciler commits (`c0b8d6b`, `7caf751`) that skipped groups 6 and 16.

The user has explicitly instructed: **do not implement PY-WL-010, do not
implement `@layer`, do not fix the group 6/16 drift in this task.** Those are
separate work items. The user also instructed that the path to closing v1.0
is "go through the entire corpus systematically and verify completeness and
correctness, one at a time." This scaffold is the walkthrough workspace for
that review.

## 2. What the scaffold must produce

A review workspace that lets one reviewer pair (`johnm-dta` primary +
`claude-opus-4-6[1m]` tool-assisted independent, per the user's Lite
single-maintainer constraint) step through every obligation, every corpus
cell, every rule, and every annotation group **once**, marking verification
state as they go. The scaffold is empty — it enumerates what needs to be
reviewed and gives every item a standard YAML worksheet with the §15.1 fields
pre-filled where they can be derived from current sources of truth and left
blank where the reviewer must supply them.

The first act of the scaffold is to **refresh the claimed-surface obligation
catalog**. The current 16-record `wardline.compliance.json` is migration input,
not the catalog boundary. The walkthrough cannot begin from a partial catalog
and then discover the rest ad hoc; §15.6 requires the catalog refresh to happen
before evidence collection starts.

The scaffold must **not** record verification outcomes. Those are filled in
by the review walkthrough that happens after this task. The scaffold also
must not invent data; every pre-filled field must be traceable through the
worksheet's `seeded_from` map to the file and line it was seeded from.

### 2.1 Workspace layout

Create `docs/verification/2026-04-12-v1-0-review/` with exactly this
structure:

```
docs/verification/2026-04-12-v1-0-review/
├── README.md                        # how the walkthrough works, written as
│                                    # instructions to the reviewer, not to an
│                                    # automated agent
├── regime-surface.json              # generated: tools in claim, per-tool
│                                    # profiles, criterion/rule/obligation
│                                    # ownership — the authoritative scope map
├── catalog-status.json              # generated summary of refreshed claimed
│                                    # surface: obligation count, reused IDs,
│                                    # newly allocated IDs, unmapped sources,
│                                    # stale_candidates, tracker_drift,
│                                    # projection_backing_gaps, normative_conflicts
├── worksheets/
│   ├── obligations/                 # one YAML file per §15.1 obligation
│   │   ├── C-CRIT-1-EXPRESSIVENESS-17-GROUPS.yaml
│   │   ├── C-CRIT-2-PATTERN-RULE-DETECTION.yaml
│   │   ├── ... (one per obligation)
│   ├── corpus-cells/                # one YAML file per (rule × taint-state) cell
│   │   ├── PY-WL-001-INTEGRAL.yaml
│   │   ├── PY-WL-001-ASSURED.yaml
│   │   ├── ... (one per cell across implemented rules)
│   ├── rules/                       # one YAML file per rule in the claim surface
│   │   ├── PY-WL-001.yaml
│   │   ├── ...
│   │   ├── PY-WL-010.yaml           # included even though not implemented
│   │   ├── SCN-021.yaml
│   │   ├── SCN-022.yaml
│   │   ├── SUP-001.yaml
│   ├── decorator-groups/            # one YAML file per annotation group 1..17
│   │   ├── GROUP-01-AUTHORITY-TIER-FLOW.yaml
│   │   ├── ...
│   │   ├── GROUP-06-LAYER-BOUNDARIES.yaml
│   │   ├── ...
│   │   ├── GROUP-17-RESTORATION-BOUNDARIES.yaml
│   └── spec-clauses/                # one YAML file per MUST-bearing clause
│                                    # referenced by any obligation (stretch:
│                                    # only if Section 4 is attempted)
├── tools/
│   ├── seed.py                      # generate empty worksheets from sources
│   ├── compile.py                   # merge filled worksheets → compliance.json
│   ├── status.py                    # progress report
│   ├── validate.py                  # validate all worksheets against schemas
│   └── schema/
│       ├── obligation-worksheet.schema.json
│       ├── corpus-cell-worksheet.schema.json
│       ├── rule-worksheet.schema.json
│       ├── decorator-group-worksheet.schema.json
│       └── regime-surface.schema.json
└── review-status.md                 # generated, current progress
```

Every directory above must be created even if empty, with a `.gitkeep` if
needed, so follow-up sessions see the intended layout.

### 2.1.1 Regime surface artifact (`regime-surface.json`)

A good-faith assessor needs to know exactly what is being claimed before
reviewing individual obligations. The seeder generates `regime-surface.json`
at the workspace root, capturing the regime-level scope for the entire
walkthrough. This artifact answers the questions raised by Finding 2 of the
v1.0 conformance audit: which tools are in scope, what profile each tool
claims, and who owns which criteria, rules, and obligations.

**Schema (seeded, all fields required):**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": [
    "regime",
    "release",
    "profiles_claimed",
    "governance_profile",
    "binding",
    "tools_in_scope",
    "criterion_ownership",
    "rule_ownership",
    "seeded_from"
  ],
  "properties": {
    "regime": { "type": "string" },
    "release": { "type": "string" },
    "profiles_claimed": {
      "type": "array",
      "items": { "enum": ["wardline-core", "wardline-type", "wardline-governance", "wardline-full"] }
    },
    "governance_profile": { "enum": ["lite", "assurance"] },
    "binding": { "type": "string" },
    "tools_in_scope": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["tool_id", "profile", "self_hosting_target"],
        "properties": {
          "tool_id": { "type": "string" },
          "profile": { "type": "string" },
          "self_hosting_target": { "type": "string" },
          "notes": { "type": "string" }
        }
      }
    },
    "criterion_ownership": {
      "type": "object",
      "description": "Map from criterion ID (C01..C10) to the tool(s) that own it.",
      "patternProperties": {
        "^C[0-9]{2}$": {
          "type": "object",
          "required": ["owner", "profile"],
          "properties": {
            "owner": { "type": "string" },
            "profile": { "type": "string" },
            "notes": { "type": "string" }
          }
        }
      }
    },
    "rule_ownership": {
      "type": "object",
      "description": "Map from rule ID to the tool that implements it.",
      "additionalProperties": {
        "type": "object",
        "required": ["implemented_by", "present"],
        "properties": {
          "implemented_by": { "type": "string" },
          "present": { "type": "boolean" },
          "notes": { "type": "string" }
        }
      }
    },
    "obligation_ownership": {
      "type": "object",
      "description": "Map from obligation ID prefix to the tool that owns it.",
      "additionalProperties": { "type": "string" }
    },
    "seeded_from": {
      "type": "object",
      "description": "Provenance map for each field."
    }
  }
}
```

**Seeding rules:**

1. `regime`, `release`, `profiles_claimed`, `governance_profile`, `binding`
   are seeded from the existing `wardline.compliance.json` `claim_scope` block.
2. `tools_in_scope` is seeded by enumerating the distinct tools mentioned in
   the WL-FIT-* records' `target_paths` — specifically:
   - `wardline-scan` (owns `src/wardline/scanner/`, `corpus/`, SARIF output)
   - `wardline-manifest` (owns `src/wardline/manifest/`, `wardline.yaml`)
   - `wardline-cli` (owns `src/wardline/cli/`)
   - `wardline-decorators` (owns `src/wardline/decorators/`)
   - `wardline-runtime` (owns `src/wardline/runtime/`)
3. `criterion_ownership` maps each §15.2 criterion to the primary tool that
   satisfies it, seeded from §A.11 criterion mapping and WL-FIT-CONF-* records.
4. `rule_ownership` maps each rule to the tool that implements it (always
   `wardline-scan` for PY-WL-* and SCN-* rules), with `present: false` for
   rules that exist in spec but have no implementation file.
5. `obligation_ownership` maps obligation ID prefixes to tools (e.g.,
   `P1-S8-` → `wardline-scan`, `G-LITE-` → `wardline-manifest`).

The seeder MUST exit non-zero if it cannot derive tool ownership for any
criterion or any cataloged obligation. The walkthrough cannot proceed with
ambiguous scope.

### 2.2 Sources of truth the scaffold must read

The seeder reads these files and only these files. Each seeded field in a
worksheet must have an entry in the worksheet's top-level `seeded_from` map
pointing back at the file and line it came from, so a reviewer can audit the
provenance.

| Source | Purpose |
|---|---|
| `docs/spec/wardline-01-15-conformance.md` §15.1, §15.2, §15.3, §15.6 | Obligation record contract, ten criteria, conformance profiles, assessment procedure |
| `docs/spec/wardline-02-A-python-binding.md` §A.3, §A.4.2, §A.4.4, §A.11 | Python binding contract, decorator mapping table, PY-WL-010 subsection, criterion mapping |
| `docs/spec/wardline-01-07-annotation-vocabulary.md` | Part I 17 annotation groups |
| `docs/spec/wardline-01-08-pattern-rules.md` | Framework rules WL-001..WL-009 |
| `docs/requirements/spec-fitness/01-framework-core.yaml` through `07-conformance-profiles.yaml` | WL-FIT-* normative requirement records |
| `wardline.compliance.json` | Existing partial ledger: migrate IDs, tracker_ids, notes, and evidence_binding where they still map cleanly, but do not treat the 16 rows as the full catalog |
| `corpus/corpus_manifest.json` | Corpus specimen inventory — drives the corpus-cells worksheets |
| `src/wardline/core/severity.py` `RuleId` enum | Which rules actually exist in code |
| `src/wardline/core/registry.py` `REGISTRY` | Which decorators actually exist and their declared groups |
| `src/wardline/scanner/rules/__init__.py` `make_rules()` | Which rule classes are actually instantiated into the live scanner surface |
| `src/wardline/scanner/rules/` | Rule implementation files (for implementation_surface) |
| `src/wardline/decorators/` | Decorator implementation files |

### 2.3 Worksheet schemas

Each worksheet is a YAML file validated by a JSON Schema under `tools/schema/`.
The schemas must enforce the §15.1 record shape for obligation worksheets and
equivalent discipline for the other three worksheet types. Every schema must
set `additionalProperties: false`.

**Worksheet schemas are parallel schemas, not direct extensions.**
`src/wardline/manifest/schemas/compliance-ledger.schema.json` already validates
the **compiled ledger** shape. The worksheet shape is deliberately more
reviewer-friendly: structured `source_refs`, structured implementation entries,
and top-level provenance maps. Because the ledger schema is closed
(`additionalProperties: false`) and its field types differ from worksheet-time
types, the obligation worksheet schema MUST **not** directly `$ref` the
existing `$defs/obligation_record`.

Instead:

- `tools/schema/obligation-worksheet.schema.json` models the worksheet form
  directly, preserving the same nine §15.1 concepts plus review-only fields
- `tools/compile.py` is the only adapter from worksheet form to ledger form
- a dedicated unit test MUST prove that compiled obligation records validate
  against `src/wardline/manifest/schemas/compliance-ledger.schema.json`

This avoids an unimplementable `$ref` composition while still preventing
drift between the worksheet contract and the ledger contract.

**Source_refs format note.** The existing ledger schema requires each
`source_refs` item to be a **string** matching the pattern
`^docs/(spec|requirements)/... (§X.Y(...)| property N| WL-FIT-...)`. The
worksheet form below uses a structured `{file, clause, quote}` object because
reviewers need the quote for audit. The compiler (`tools/compile.py`) MUST
flatten each worksheet item to `f"{file} {clause}"` (dropping `quote`) when
emitting `wardline.compliance.json`, so ledger validation still passes. State
this flattening rule in the compiler's module docstring.

**Provenance model.** Every worksheet carries a top-level `seeded_from`
mapping keyed by dotted field path (for example `summary`,
`claim_scope.applies_to`, `implementation_surface[0].path`). Each value is
either `<path>:<line>` or `"(not available)"`. This is the single provenance
mechanism for seeded scalars and seeded structured values. Reviewer-filled
fields are omitted from `seeded_from`.

**Obligation worksheet** fields:

```yaml
id: <string>                              # seeded, required
source_refs:                              # seeded, required, minItems 1
  - file: <path>                          # required
    clause: "§X.Y" or "§X.Y(n)" or "property N"
    quote: <string>                       # seeded verbatim, reviewer may trim
summary: <string>                         # seeded from existing record or spec
claim_scope:                              # seeded, required
  regime: wardline-python-core-lite
  profiles: [wardline-core, wardline-governance]  # or subset
  binding: python
  rule: <rule-id or null>
  applies_to: <string>                    # seeded
implementation_surface:                   # seeded, required, minItems 1
  - path: <path or "(missing)">
    present: <bool>                       # seeded by file-exists check
evidence_classes:                         # seeded from spec-fitness verification blocks
  - class: <enum>
    target: <path or command>
    note: <string or null>
verification:                             # reviewer fills, seeded null
  state: null                             # null means "not yet reviewed"
  decided_by: null
  decided_date: null
  evidence_run:                           # the reviewer fills this list as they run checks
    - class: <enum>
      command: <string>
      exit_code: <int>
      timestamp: <iso8601>
      notes: <string>
  findings: null                          # free-text reviewer notes
  contradictions:                         # if verification state contradicts other worksheets
    - worksheet: <path>
      reason: <string>
freshness_binding:                        # seeded from current evidence_binding block
  commit_ref: <sha>
  tool_version: "1.0.0"
  manifest_hash: <sha256:...>
  corpus_hash: <sha256:...>
  self_hosting_input_hash: <sha256:...>
  evidence_artifact_hashes: {}
reviewer_metadata:                        # reviewer fills, seeded with scaffolded pair
  primary_reviewer: johnm-dta
  review_date: null
  independent_reviewer: "claude-opus-4-6[1m]"
  independent_review_date: null
  independence: tool_assisted
  independence_note: >
    Independent review performed by automated assistant under Lite
    single-maintainer constraint. Not equivalent to human independent review
    required by Assurance. Accepted for Lite until a second human reviewer is
    onboarded.
tracker_ids: []                           # seeded from existing record
notes: null
waiver: null                              # present only when reviewer later sets state: waived
seeded_from:
  id: <path:line>
  source_refs[0]: <path:line>
  summary: <path:line>
  claim_scope.applies_to: <path:line>
  implementation_surface[0].path: <path:line or "(not available)">
  freshness_binding.commit_ref: <path:line>
  reviewer_metadata.primary_reviewer: <path:line>
```

**Corpus-cell worksheet** fields:

```yaml
id: <rule-id>-<taint-state>               # e.g. PY-WL-001-INTEGRAL
rule: <rule-id>
taint_state: <enum from TaintState>
expected_verdict: <from 80-cell matrix>   # seeded from binding spec §A.3/§A.4.4
implementation_paths:                     # where the rule code lives
  - <path>
specimen_paths:                           # where the corpus specimens live
  - path: <path>
    kind: positive | negative | adversarial
    present: <bool>
severity_matrix_cell: <ER/U, W/U, ...>    # seeded from §A.3 80-cell table
verification:
  state: null
  decided_by: null
  decided_date: null
  corpus_verify_exit: null
  findings: null
reviewer_metadata:
  primary_reviewer: johnm-dta
  independent_reviewer: "claude-opus-4-6[1m]"
  independence: tool_assisted
notes: null
seeded_from:
  rule: <path:line>
  taint_state: <path:line>
  expected_verdict: <path:line>
  severity_matrix_cell: <path:line>
```

**Rule worksheet** fields:

```yaml
id: <rule-id>                             # e.g. PY-WL-001
framework_mapping: <WL-NNN>               # seeded from §A.3 mapping table
declared_in_claim_surface: <bool>         # seeded from refreshed regime surface
implementation:
  file: <path or "(missing)">
  present: <bool>
  rule_id_enum_present: <bool>            # from RuleId enum check
  registered_in_make_rules: <bool>        # from src/wardline/scanner/rules/__init__.py
tests:
  unit_test_file: <path or "(missing)">
  present: <bool>
corpus:
  directory: <path or "(missing)">
  specimen_count: <int or null>
  adversarial_count: <int or null>
severity_matrix_row_complete: <bool>      # all cells in the 80-cell row have a verdict
verification:
  state: null
  decided_by: null
  decided_date: null
  findings: null
reviewer_metadata:
  primary_reviewer: johnm-dta
  independent_reviewer: "claude-opus-4-6[1m]"
  independence: tool_assisted
notes: null
seeded_from:
  framework_mapping: <path:line>
  declared_in_claim_surface: <path:line>
  implementation.file: <path:line or "(not available)">
```

**Decorator-group worksheet** fields:

```yaml
group_id: <1..17>
group_name: <string>                      # from §A.4.2
part1_source_ref:
  file: docs/spec/wardline-01-07-annotation-vocabulary.md
  clause: <string>
binding_source_ref:
  file: docs/spec/wardline-02-A-python-binding.md
  clause: "§A.4.2"
spec_decorators:                          # seeded from §A.4.2 table
  - name: <string>
    parameters: <string or "(none)">
registry_decorators:                      # seeded from src/wardline/core/registry.py
  - name: <string>
    registered_group: <int>
drift:                                    # computed at seed time
  missing_from_registry: [<decorator>, ...]    # spec has, registry lacks
  extra_in_registry: [<decorator>, ...]        # registry has, spec lacks
  wrong_group: [{name, spec_group, registry_group}, ...]
implementation_paths:                     # src/wardline/decorators/*.py files that declare this group's decorators
  - <path>
verification:
  state: null
  decided_by: null
  decided_date: null
  findings: null
reviewer_metadata:
  primary_reviewer: johnm-dta
  independent_reviewer: "claude-opus-4-6[1m]"
  independence: tool_assisted
notes: null
seeded_from:
  group_name: <path:line>
  part1_source_ref.clause: <path:line>
  spec_decorators[0].name: <path:line>
  registry_decorators[0].name: <path:line or "(not available)">
```

### 2.4 Seeder (`tools/seed.py`)

Behaviour:

1. Idempotent. Running twice produces no change unless sources of truth have
   drifted. If a worksheet would be re-seeded with a different value, the
   seeder MUST print a diff and exit non-zero rather than overwrite a file
   that a reviewer may have partially filled.
2. Refreshes the obligation catalog for the walkthrough's **claimed surface**
   before any review starts. Inputs are the existing `wardline.compliance.json`
   rows plus the claimed Part I / Part II / governance-profile sources named in
   §2.2, especially the `WL-FIT-*` requirement records. Existing obligation IDs
   from `wardline.compliance.json` MUST be preserved where they still map
   cleanly. Missing claimed-surface obligations MUST receive new IDs following
   the top-level `id_schema`. The current 16 rows are migration input only; they
   are not the target count.
3. Writes `catalog-status.json` summarising:
   - `obligation_count`: total obligations in refreshed catalog
   - `reused_ids`: obligation IDs migrated from existing ledger
   - `newly_allocated_ids`: obligation IDs created for previously uncataloged claims
   - `unmapped_claim_sources`: WL-FIT-* records or spec clauses with no obligation
   - `catalog_status`: `complete` or `partial`
   - `stale_candidates`: obligations whose migrated `freshness_binding.commit_ref`
     differs from current `HEAD` — these are candidates for re-verification
   - `tracker_drift`: list of `{obligation_id, ledger_trackers, json_trackers}`
     where the markdown ledger and JSON ledger disagree on tracker_ids
   - `projection_backing_gaps`: matrix rows (C02, C03, C08, R01-R14) that are
     backed by prose or criterion references instead of concrete obligation IDs
   - `normative_conflicts`: list of `{obligation_id, source_a, source_b, conflict}`
     where the same claimed obligation maps to contradictory MUST-level sources
     (e.g., §10 SHOULD vs §15 MUST for the same Lite requirement)
   - `governance_must_controls_present`: boolean — true iff the catalog includes
     obligations for WL-FIT-GOV-002 (branch protection), WL-FIT-GOV-005 (audit
     logging), and WL-FIT-GOV-010 (direct-law exclusion)
   - `seeded_head`: the git HEAD sha at seed time (for freshness comparison)

   The seeder MUST exit non-zero if:
   - `unmapped_claim_sources` is non-empty, or
   - `normative_conflicts` is non-empty, or
   - `governance_must_controls_present` is false

   The walkthrough does not start from a partial catalog or conflicting sources.
4. Walks `corpus/corpus_manifest.json` and emits one corpus-cell worksheet
   per (rule, taint_state) combination that the manifest covers OR that the
   80-cell matrix row for the rule declares. Missing cells get
   `specimen_paths: []` and `present: false` markers.

   **Scope of the cell grid.** §A.3 line 276 declares the 80-cell matrix as
   10 rules (`PY-WL-001..010`) × 8 taint states. Corpus-cell worksheets are
   generated for these 80 cells only. `SCN-021`, `SCN-022`, and `SUP-001` are
   supplementary or binding-specific rules outside the 80-cell framework grid
   and do **not** get per-taint corpus-cell worksheets; they are reviewed via
   their rule worksheets in step 5.
5. Walks `src/wardline/core/severity.py` `RuleId` enum,
   `src/wardline/scanner/rules/__init__.py` `make_rules()`, and
   `docs/spec/wardline-02-A-python-binding.md §A.3` rule mapping table and
   emits one rule worksheet for every rule in the walkthrough surface
   (`PY-WL-001..010`, `SCN-021`, `SCN-022`, `SUP-001`) — including rules that
   are not implemented, so the walkthrough cannot skip them. A not-implemented
   rule gets `implementation.present: false`.
6. Walks `src/wardline/core/registry.py` `REGISTRY` and the §A.4.2 decorator
   mapping table and emits one decorator-group worksheet per Part I group
   1..17. Computes drift by set-diffing the §A.4.2 decorator list against the
   registry for each group, and fills `drift.missing_from_registry`,
   `drift.extra_in_registry`, `drift.wrong_group`.
7. Generates `regime-surface.json` per §2.1.1:
   - Enumerates tools in scope from WL-FIT-* `target_paths`
   - Assigns criterion ownership from §A.11 and WL-FIT-CONF-* records
   - Assigns rule ownership (all rules → `wardline-scan`)
   - Assigns obligation ownership by ID prefix
   - Validates against `tools/schema/regime-surface.schema.json`
   - Exits non-zero if any criterion or obligation prefix has no owner
8. Does not touch `wardline.compliance.json`, `wardline.yaml`, or any spec
   file.
9. Emits a run summary: how many obligation worksheets were generated, how many
   IDs were reused, how many new IDs were allocated, how many corpus-cell /
   rule / decorator worksheets were created, how many already existed, and how
   many would have changed if it had not bailed.
10. Exit code 0 on clean run or clean re-run; non-zero on drift or incomplete
    claimed-surface mapping.

The seeder may be implemented in Python using only the standard library plus
the project's existing deps (`pyyaml`, `jsonschema`). No new dependencies.

**Markdown table parsing is load-bearing.** The seeder extracts the §A.4.2
decorator mapping table and the §A.3 80-cell severity matrix from the
binding spec, and the §15.1 obligation field table from the conformance
spec. These are pipe-delimited markdown tables; parsing is stdlib-only
(`re` + line iteration), but a silent regex miss would quietly seed wrong
worksheets — exactly the failure mode the scaffold exists to prevent.

Therefore, the seeder's table extractors MUST be split into pure functions
(`parse_decorator_mapping_table`, `parse_severity_matrix`,
`parse_obligation_field_table`) and covered by unit tests under
`tests/unit/verification/test_seed_parsers.py`. Each test uses a small
hand-crafted markdown fixture and asserts exact extraction. These tests run
as part of `uv run pytest` and are part of acceptance criterion 8.

### 2.5 Compiler (`tools/compile.py`)

Behaviour:

1. Reads every worksheet under `docs/verification/2026-04-12-v1-0-review/worksheets/obligations/`.
2. **Integrity check:** Reads `catalog-status.json` and verifies that the
   worksheet filenames match the seeded obligation IDs exactly — no additions,
   no deletions. If any worksheet exists that was not in `catalog-status.json`,
   or any cataloged obligation has no worksheet, exit non-zero with an error
   listing the mismatches. This prevents fabricated worksheets from producing
   a valid-looking but wrong ledger.
3. Validates each against `tools/schema/obligation-worksheet.schema.json`.
4. Refuses to compile if any worksheet has `verification.state: null` —
   the compiler exists to produce the ledger from a *completed* review, not a
   partial one. Exit non-zero with a list of unfilled worksheets.
5. **Freshness check:** Refuses to compile if any worksheet's
   `freshness_binding.commit_ref` differs from current HEAD, unless
   `--allow-stale` is passed with explicit acknowledgment. This ensures the
   compiled ledger reflects evidence collected against the current codebase.
6. When every obligation is filled, produces `wardline.compliance.json` in
   the §15.1 record shape (all nine fields per record). The compile step also
   writes `docs/verification/2026-04-12-v1-0-compliance-ledger.md` as a
   derived human view.

   **Write target is the real ledger.** The compiler overwrites
   `wardline.compliance.json` and the dated compliance-ledger markdown in
   place. That is intentional — the walkthrough's final act is to replace
   the currently-reduced ledger with the §15.1-shaped one. Under this
   scaffold task the compiler is built but will never execute its write
   path (every worksheet ships with `verification.state: null`, so the
   refuse-to-compile gate in step 4 trips first). The README MUST make
   this explicit so a future reviewer is not surprised when the first
   successful compile rewrites the ledger.

   **Source_refs flattening.** Per §2.3, each worksheet's
   `source_refs: [{file, clause, quote}, ...]` is flattened by the
   compiler to the ledger-schema string form `f"{file} {clause}"` (dropping
   `quote`) before validation against
   `compliance-ledger.schema.json`. Put this rule in the compiler module
   docstring.
7. The compiler never writes verification state itself. It is a transform.

### 2.6 Status (`tools/status.py`)

Behaviour:

1. Reads every worksheet under `worksheets/`.
2. Prints a table grouped by worksheet type:
   ```
   Obligations:       x/y reviewed   (x verified, x non_compliant, x waived, x not_applicable)
   Corpus cells:      x/y reviewed
   Rules:             x/y reviewed
   Decorator groups:  x/y reviewed
   ```
3. Lists every worksheet where `verification.state: null` (work remaining).
4. Lists every worksheet where `drift.*` is non-empty (spec/code mismatches
   the review must resolve).
5. Reads `catalog-status.json` and reports:
   - Whether the obligation catalog is complete for the claimed surface
   - Any unmapped claim sources
   - **Stale candidates**: count and list of obligations where
     `freshness_binding.commit_ref` differs from current HEAD — these need
     re-verification before the walkthrough can mark them verified
   - **Tracker drift**: any obligation IDs where tracker mappings disagree
     between migrated sources — the reviewer must reconcile before compile
   - **Projection backing gaps**: matrix rows still backed by prose — these
     must be rewired to obligation IDs in a follow-up task
   - **Normative conflicts**: any contradictory MUST-level sources (should be
     empty if seeder ran clean, but re-check in case spec changed since seed)
6. Compares each worksheet's `freshness_binding.commit_ref` against current
   HEAD and reports: `Freshness drift: N worksheets seeded at <old>, now at <new>`
7. Reads `regime-surface.json` and reports tool ownership coverage:
   - Tools in scope
   - Criteria with no assigned owner (should be empty)
   - Rules with no implementation (`present: false`)
8. Writes the same content to `review-status.md` for browsing in git.
9. Exit 0 always. This is a report, not a gate.

## 3. What the scaffold must NOT do

1. **No implementation of PY-WL-010.** Do not create `py_wl_010.py`, do not
   add `PY_WL_010` to the `RuleId` enum, do not create
   `tests/unit/scanner/test_py_wl_010.py`, do not create `corpus/specimens/PY-WL-010/`.
   The PY-WL-010 *rule worksheet* is created (showing `implementation.present:
   false` with `seeded_from` pointing at the grep that proved absence), but
   no Python code is added.
2. **No implementation of `@layer`.** Same discipline. The Group 6
   *decorator-group worksheet* records `drift.missing_from_registry: ["layer"]`,
   but `src/wardline/decorators/layers.py` is not created.
3. **No fix of the group 6/16 drift.** The Group 6 and Group 16 decorator
   worksheets must record the drift honestly in `drift.wrong_group`, but
   `src/wardline/core/registry.py` and `src/wardline/decorators/boundaries.py`
   are not modified.
4. **No fill of any `verification.state` field.** Every worksheet ships with
   `verification.state: null`. The review walkthrough is a separate task.
5. **No rewrite of `wardline.compliance.json`, the compliance ledger markdown,
   or the certification matrix markdown.** The compile step will eventually
   regenerate the first two; that will be a separate task, gated by the
   walkthrough. Do not pre-empt it in this task.
6. **No new filigree issues.** Those are created during the walkthrough, if
   at all, as the reviewer finds gaps.
7. **No deletion of the existing seeded ledger or matrix.** They remain as
   the current source of truth until the compile step replaces them. Leave
   them untouched.

## 4. Acceptance criteria

1. `uv run python docs/verification/2026-04-12-v1-0-review/tools/seed.py`
   runs clean from a fresh state, creates the full worksheet tree, and writes
   `catalog-status.json` with `catalog_status: "complete"` and
   `unmapped_claim_sources: []`.
2. Re-running `seed.py` immediately afterward is a no-op (exit 0, no files
   changed, no diff printed).
3. Every worksheet file validates against its schema. The validation command
   is provided as a script `tools/validate.py` that:
   - Walks all worksheets under `worksheets/`
   - Validates each against its corresponding schema in `tools/schema/`
   - Exits 0 if all pass, non-zero with a list of failures otherwise
   
   Usage: `uv run python docs/verification/2026-04-12-v1-0-review/tools/validate.py`
4. `tools/status.py` runs and prints a sensible report. On a freshly-seeded
   tree the report shows `0/<total>` reviewed everywhere.
5. `tools/compile.py` on a freshly-seeded tree exits non-zero with a message
   like `refusing to compile: N obligation worksheets have verification.state:
   null`. It must not produce a partial or misleading compliance.json.
6. `uv run ruff check docs/verification/2026-04-12-v1-0-review/tools/` passes.
7. `uv run mypy docs/verification/2026-04-12-v1-0-review/tools/` passes in
   strict mode (same settings as the rest of the project).
8. `uv run pytest` for the existing suite still passes AND the new parser
   tests under `tests/unit/verification/test_seed_parsers.py` pass. The
   parser tests cover `parse_decorator_mapping_table`,
   `parse_severity_matrix`, and `parse_obligation_field_table` against
   hand-crafted markdown fixtures (see §2.4). Add one compiler-shape test as
   well: a filled obligation worksheet fixture compiles to a record that
   validates against `src/wardline/manifest/schemas/compliance-ledger.schema.json`.
9. `README.md` in the review directory tells a reviewer, in plain
   instructions, how to walk through the worksheets one at a time, what each
   field means, what evidence to collect, and when to mark each verification
   state. It is a how-to, not a project description.
10. The worksheet counts and catalog coverage align with the live claimed
    surface:
    - obligation worksheets: one per refreshed claimed-surface obligation; the
      exact count is derived, reported in `catalog-status.json`, and MUST be
      greater than the migrated 16-row starting point
    - 80 corpus-cell worksheets (10 rules `PY-WL-001..010` × 8 taint states;
      `SCN-021`, `SCN-022`, and `SUP-001` do NOT get per-taint cells — see
      §2.4 point 4)
    - 13 rule worksheets (`PY-WL-001..010` + `SCN-021` + `SCN-022` + `SUP-001`)
    - 17 decorator-group worksheets (Part I groups 1..17)

    Total: `obligation_count + 110` worksheets. The seeder summary MUST print
    each count and the total, and MUST exit non-zero if the corpus-cell, rule,
    or decorator counts differ from 80 / 13 / 17, or if `catalog-status.json`
    reports any unmapped claimed-surface requirement.
11. `regime-surface.json` exists and validates against its schema. Every
    criterion C01–C10 has an assigned owner. Every rule in the claim surface
    has an `implemented_by` entry. Every obligation ID prefix has a tool owner.
12. `catalog-status.json` includes standalone obligations for the three
    mandatory §10 governance controls:
    - WL-FIT-GOV-002 (branch protection CI gates)
    - WL-FIT-GOV-005 (governance audit logging)
    - WL-FIT-GOV-010 (governance-artefact exclusion during direct law)
    
    The seeder MUST exit non-zero if any of these are missing from the
    refreshed catalog. These are MUST-level Lite controls and cannot be
    omitted from the verification surface.
13. `catalog-status.json` reports `normative_conflicts: []`. If the seeder
    detects contradictory MUST-level sources for the same obligation (e.g.,
    §10 says SHOULD, §15 says MUST for Lite bootstrap corpus), it MUST exit
    non-zero and report the conflict. The scaffold cannot proceed from
    contradictory normative input.
14. `catalog-status.json` reports `stale_candidates`, `tracker_drift`, and
    `projection_backing_gaps` (may be non-empty — these are informational
    for the walkthrough, not blocking for scaffold creation). The status
    tool prints these in its report.
15. The compiler's worksheet set integrity check (step 2) is tested: a unit
    test adds a fabricated worksheet to a test fixtures directory and
    verifies the compiler exits non-zero with an appropriate error message.

## 5. Constraints (from CLAUDE.md and project memory, binding)

- No deferral language in worksheets, tools, or README. Every field is either
  seeded with a real value or explicitly `null` — do not write "TBD" or "in
  progress" or "pending review later".
- No backwards-compat shims. This is a fresh scaffold; there is nothing to be
  backwards-compatible with.
- Do not touch git. Do not stash, reset, restore, or checkout. If the working
  tree has uncommitted changes, investigate before editing files that might
  be in use by another session.
- Every pre-filled field in a worksheet must have a corresponding entry in the
  top-level `seeded_from` map (`<path>:<line>` or `"(not available)"`) so a
  reviewer can confirm the source. Unknown fields are `null`, not guessed.
- Do not invent corpus cells. The 80-cell matrix is normative in §A.3 — read
  it, do not improvise.
- Do not rename or move existing files in `docs/verification/` other than
  those inside `2026-04-12-v1-0-review/`.
- Zero new runtime dependencies. Seeder, compiler, and status use only the
  standard library, `pyyaml`, and `jsonschema` (already deps).
- Files created under `tools/` are executable scripts, not CLI subcommands of
  `wardline`. Do not plumb them into `src/wardline/cli/`. The scaffold is
  intentionally outside the scanner's command surface so it does not become
  load-bearing for anything else.
- Scripts must be deterministic: the same inputs produce byte-identical
  outputs. Sort keys, sort filenames, stable JSON/YAML dumps.
- README.md under the review directory, and README.md only under that
  directory — do not create READMEs anywhere else. This task only creates the
  one.

## 6. Out-of-scope for this task (explicit non-goals)

- Implementing PY-WL-010 detection.
- Implementing `@layer(N)` decorator or scanner rule.
- Fixing the Group 6/16 registry drift.
- Rewriting `wardline.compliance.json` or the compliance-ledger markdown.
- Rewiring the certification-matrix projection rows.
- Pre-deciding walkthrough outcomes. The scaffold **does** create any new
  obligation worksheets required to refresh the claimed-surface catalog; it
  does **not** mark them compliant, non-compliant, waived, or complete.
- Running the walkthrough. The scaffold is the workspace; the walkthrough is
  the follow-up task.

## 7. Reporting

When the task is complete, produce a summary (≤ 400 words) containing:

1. The commit SHA for the scaffold commit (or commits, if split).
2. The full list of files created, grouped by directory.
3. The seeder's run summary from the first clean run (counts of worksheets
   created per type).
4. The output of `tools/status.py` from a freshly-seeded tree.
5. Any field paths the seeder left `null` and marked as
   `"(not available)"` in the worksheet `seeded_from` maps — this is the list
   of things the reviewer will need to investigate first.
6. Any surprises encountered — for example, if the corpus manifest turns out
   to have entries that don't match any declared rule, or if a spec-fitness
   YAML records normative_sources that don't resolve.
7. A pointer back to this prompt file
   (`docs/superpowers/plans/2026-04-12-v1-0-verification-scaffold.md`) so
   the next session can continue the walkthrough.

Do not claim the task complete unless every acceptance criterion in section
4 has been independently demonstrated with a runnable command and an exit
code. "The scaffold looks right" is not acceptance — "I ran seed.py, it
created `<obligation_count> + 80 + 13 + 17` worksheets, catalog-status.json
shows a complete claimed surface, status.py prints `0/<total>` reviewed, mypy
passes, ruff passes" is acceptance.
