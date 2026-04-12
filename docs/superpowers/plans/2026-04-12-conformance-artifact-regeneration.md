# Prompt: Regenerate conformance artifacts from completed verification walkthrough

This is an instruction prompt for a fresh session. It is self-contained. Do not
assume conversational context from the session that produced it.

## 1. Context: why this regeneration is needed

Wardline is a semantic boundary enforcement framework for Python at
`/home/john/wardline`. The project is in v1.0.0 recertification. A conformance
audit on 2026-04-12 identified several findings related to artifact
inconsistency:

**Finding 4 (High):** The freshness model is not applied to the current
snapshot. The repo HEAD and compliance artifact commit refs disagree, but
`stale: 0` is reported. The system cannot truthfully answer "what is compliant
right now."

**Finding 6 (Medium):** The certification matrix uses an undefined row state
(`at risk`), and tracker mappings disagree between the ledger markdown and
JSON. There is no single, trustworthy blocker map.

These findings cannot be resolved by the verification scaffold alone. The
scaffold produces worksheets and, once filled, compiles them to a new
`wardline.compliance.json`. But the current certification matrix, the
projection views, and the derived blocker maps are separate artifacts that
must also be regenerated.

## 2. Prerequisites

This plan executes **after** the verification walkthrough is complete. It
requires:

1. **Lite governance reconciliation complete** — no normative conflicts between
   §10 and §15 (see `2026-04-12-lite-governance-reconciliation.md`)
2. **Verification scaffold built** — `docs/verification/2026-04-12-v1-0-review/`
   exists with all worksheets, tools, and schemas
3. **All obligation worksheets filled** — every worksheet has
   `verification.state != null`
4. **Compiler passes** — `tools/compile.py` runs successfully and produces a
   new `wardline.compliance.json`

If any prerequisite is not met, this plan cannot execute.

## 3. Scope of this task

This task regenerates all conformance artifacts from the compiled ledger:

1. **Rewrite `wardline.compliance.json`** with §15.1-compliant records,
   correct freshness binding, and stale-state logic applied
2. **Regenerate `docs/verification/2026-04-12-v1-0-compliance-ledger.md`** as
   the human-readable view of the ledger
3. **Regenerate `docs/verification/2026-04-12-v1-0-cell-certification-matrix.md`**
   with all rows backed by concrete obligation IDs, not prose
4. **Eliminate undefined row states** — no `at risk` or other undefined states;
   only the §15.6 states: `unassessed`, `implemented_no_evidence`, `evidenced`,
   `verified`, `non_compliant`, `waived`, `not_applicable`, `stale`
5. **Apply freshness-to-stale transition** — any obligation whose
   `freshness_binding.commit_ref` differs from current HEAD transitions to
   `stale` unless the evidence is re-run
6. **Reconcile tracker mappings** — one source of truth for tracker_ids

## 4. Artifact relationships

```
worksheets/obligations/*.yaml
        │
        ▼ (compile.py)
wardline.compliance.json (§15.1-shaped)
        │
        ├──▶ 2026-04-12-v1-0-compliance-ledger.md (human view)
        │
        └──▶ 2026-04-12-v1-0-cell-certification-matrix.md
                │
                └──▶ projection rows C01-C10, G01-G04, R01-R14
```

The certification matrix MUST be mechanically derivable from the ledger. Every
matrix row MUST reference one or more obligation IDs. No row may be backed by
prose, criterion descriptions, or "see §X.Y" references.

## 5. Implementation steps

### 5.1 Verify prerequisites

```bash
# Check all worksheets are filled
uv run python docs/verification/2026-04-12-v1-0-review/tools/status.py
# Expect: 0 worksheets with verification.state: null

# Check compiler passes
uv run python docs/verification/2026-04-12-v1-0-review/tools/compile.py --dry-run
# Expect: exit 0, "would write N records to wardline.compliance.json"
```

### 5.2 Run compiler to produce new ledger

```bash
uv run python docs/verification/2026-04-12-v1-0-review/tools/compile.py
```

This overwrites `wardline.compliance.json` and the compliance-ledger markdown.

### 5.3 Apply freshness-to-stale transitions

After compile, check each obligation's `freshness_binding.commit_ref` against
current HEAD:

```bash
current_head=$(git rev-parse HEAD)
# For each obligation in wardline.compliance.json:
#   if freshness_binding.commit_ref != current_head:
#     state = "stale"
```

If any obligations become stale, re-run their evidence and update the
worksheets, then recompile. The goal is `stale: 0` at release.

### 5.4 Regenerate certification matrix

Create or update `tools/generate_matrix.py` (or add to compile.py) to:

1. Read the compiled `wardline.compliance.json`
2. For each projection row (C01-C10, G01-G04, R01-R14):
   - Identify the obligations that back this row
   - Compute the aggregate state: if all are `verified`, row is green; if any
     is `non_compliant`, row is red; etc.
   - Generate the markdown table row with obligation IDs, not prose
3. Write `docs/verification/2026-04-12-v1-0-cell-certification-matrix.md`

The matrix generator MUST use only the §15.6 states. It MUST NOT emit `at risk`
or any other undefined state.

### 5.5 Reconcile tracker mappings

1. Read `tracker_ids` from every compiled obligation record
2. Ensure no duplicates (one obligation owns each tracker)
3. Ensure the filigree issues referenced by tracker_ids actually exist
4. Generate a `tracker-map.json` if needed for cross-reference

### 5.6 Validate final artifacts

```bash
# Validate ledger against schema
uv run python -c "
import json
import jsonschema
schema = json.load(open('src/wardline/manifest/schemas/compliance-ledger.schema.json'))
ledger = json.load(open('wardline.compliance.json'))
jsonschema.validate(ledger, schema)
print('Ledger validates')
"

# Check no undefined states
grep -E '"state":\s*"at risk"' wardline.compliance.json && echo "FAIL: undefined state" || echo "OK: no undefined states"

# Check freshness
python -c "
import json
import subprocess
ledger = json.load(open('wardline.compliance.json'))
head = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip()
stale = [o['id'] for o in ledger['obligations'] if o['freshness_binding']['commit_ref'] != head and o['state'] != 'stale']
print(f'Stale candidates not marked stale: {len(stale)}')
for oid in stale[:5]: print(f'  {oid}')
"
```

## 6. Acceptance criteria

1. `wardline.compliance.json` validates against
   `src/wardline/manifest/schemas/compliance-ledger.schema.json`
2. Every obligation record has all nine §15.1 fields populated
3. `wardline.compliance.json` `evidence_binding.repo_head` matches current HEAD
4. `summary.stale == 0` (all evidence is fresh) OR all stale obligations have
   `state: stale`
5. `docs/verification/2026-04-12-v1-0-cell-certification-matrix.md` exists and
   every row references concrete obligation IDs
6. No row in the certification matrix uses `at risk` or any undefined state
7. Tracker mappings are consistent: every `tracker_ids` reference is unique
   and points to an existing filigree issue
8. `tools/status.py` reports no drift, no tracker mismatches, no projection
   backing gaps

## 7. Constraints

- This plan does not fill worksheets — that is the walkthrough's job
- This plan does not build the scaffold — that is a prerequisite
- This plan does not implement missing features (PY-WL-010, @layer, etc.)
- The matrix generator must be deterministic: same input → byte-identical output
- Do not delete the old matrix/ledger before regenerating; overwrite in place

## 8. Reporting

When the task is complete, produce a summary containing:

1. The commit SHA for the regeneration commit
2. The final obligation count and state distribution:
   ```
   verified: N
   non_compliant: N
   waived: N
   not_applicable: N
   stale: N
   ```
3. The certification matrix summary:
   ```
   C01-C10: N green, N yellow, N red
   G01-G04: N green, N yellow, N red
   R01-R14: N green, N yellow, N red
   ```
4. Any obligations that transitioned to `stale` during regeneration
5. A pointer back to this prompt file
   (`docs/superpowers/plans/2026-04-12-conformance-artifact-regeneration.md`)

## 9. Relationship to other plans

| Plan | Relationship |
|------|--------------|
| `2026-04-12-lite-governance-reconciliation.md` | Must complete first (prerequisite) |
| `2026-04-12-v1-0-verification-scaffold.md` | Must complete first (prerequisite) |
| Verification walkthrough (no plan file) | Must complete first (worksheets filled) |
| This plan | Final step before release sign-off |

## 10. Post-regeneration: release sign-off gate

After this plan completes successfully, the release sign-off gate is:

1. All rows green OR explicitly waived with documented rationale
2. `stale: 0`
3. No `non_compliant` obligations that are not waived
4. Self-hosting scan passes with no new findings
5. `wardline.conformance.json` generated from fresh self-hosting run

If these conditions are met, v1.0 can ship.
