# Prompt: Reconcile Lite governance inconsistency between §10 and §15

This is an instruction prompt for a fresh session. It is self-contained. Do not
assume conversational context from the session that produced it.

## 1. Context: why this reconciliation is needed

Wardline is a semantic boundary enforcement framework for Python at
`/home/john/wardline`. The project is in v1.0.0 recertification. A conformance
audit on 2026-04-12 identified Finding 5 (severity: medium-high):

**The Lite governance posture is internally inconsistent between §10 and §15.**

Specifically:
- `docs/spec/wardline-01-10-governance-model.md` presents bootstrap corpus as
  Lite **SHOULD** (non-blocking for Lite conformance)
- The current `docs/spec/wardline-01-15-conformance.md` and the conformance
  baseline `docs/requirements/spec-fitness/07-conformance-profiles.yaml`
  WL-FIT-CONF-010 treat bootstrap corpus correctness as a Lite **MUST**
  (blocking for Lite conformance)
- The expedited-path expectations also shift between "documented process
  reviewed at ratification" (older §15 language) and the current merged
  checklist language

This inconsistency means two careful assessors can reach opposite Lite
pass/fail conclusions from the current normative set. That is exactly the kind
of ambiguity that must not survive spec lock.

## 2. Scope of this task

This task reconciles the §10/§15 Lite posture **in the spec and baseline files
only**. It does not:
- Build the verification scaffold (separate task)
- Run the compliance walkthrough (separate task)
- Regenerate compliance artifacts (separate task)
- Implement missing features like PY-WL-010 or @layer

## 3. Sources to review

| File | What to check |
|------|---------------|
| `docs/spec/wardline-01-10-governance-model.md` | §10.1, §10.2 governance requirements; any SHOULD/MUST language for Lite |
| `docs/spec/wardline-01-15-conformance.md` | §15.3.2 Lite governance checklist; §15.4 profile requirements |
| `docs/requirements/spec-fitness/07-conformance-profiles.yaml` | WL-FIT-CONF-010 (Lite governance checklist verifiable) |
| `docs/requirements/spec-fitness/06-governance-operations.yaml` | Any governance requirements that differ by profile |
| `docs/adr/` | Any ADRs that discuss Lite/Assurance governance distinction |

## 4. Decision points

The reconciliation must resolve these specific questions:

### 4.1 Bootstrap corpus requirement level

**Current state:**
- §10 implies SHOULD for Lite
- §15.3.2 / WL-FIT-CONF-010 implies MUST for Lite

**Options:**
1. **Align to MUST**: Update §10 to state that bootstrap corpus is MUST for
   all profiles (Lite and Assurance). Rationale: corpus correctness is
   fundamental to trust in the scanner's verdicts.
2. **Align to SHOULD**: Update §15.3.2 and WL-FIT-CONF-010 to treat bootstrap
   corpus as SHOULD for Lite. Rationale: Lite is the minimal viable
   governance profile, and corpus is enforcement-level, not governance-level.
3. **Clarify the distinction**: Bootstrap corpus *coverage* is SHOULD;
   bootstrap corpus *correctness* (specimens that exist must have correct
   verdicts) is MUST. Update both sections to be explicit.

**Recommendation:** Option 3 is most precise. A Lite adopter may have sparse
corpus coverage (SHOULD), but any specimens they do have must be correct (MUST).

### 4.2 Expedited-path documentation requirements

**Current state:**
- Older §15 language: "documented process reviewed at ratification"
- Current merged language: less specific

**Options:**
1. **Explicit checklist item**: Add "expedited governance process is
   documented and reviewed at ratification" as a MUST checklist item.
2. **Remove ambiguity**: State that expedited-path documentation is captured
   by the existing control-law requirements (WL-FIT-GOV-008, WL-FIT-GOV-009).

**Recommendation:** Option 2 — avoid redundant requirements; expedited
governance is already covered by the control-law model.

### 4.3 Branch protection, audit logging, direct-law exclusion

**Current state:**
- §10 lists these as MUST-level controls
- §15.3.2 Lite checklist does not explicitly enumerate them
- WL-FIT-GOV-002, WL-FIT-GOV-005, WL-FIT-GOV-010 exist but are not clearly
  bound to the Lite checklist

**Options:**
1. **Add to Lite checklist**: Explicitly list branch protection, audit
   logging, and direct-law exclusion as Lite MUST items in §15.3.2.
2. **Reference by WL-FIT-GOV-***: State that §15.3.2 Lite checklist includes
   all WL-FIT-GOV-* requirements at their stated levels.
3. **Leave as-is**: Trust that the WL-FIT-GOV-* records are authoritative and
   §15.3.2 is a summary.

**Recommendation:** Option 2 — make the binding explicit without duplicating
the requirement text.

## 5. Implementation steps

1. Read all four source files (§10, §15, 07-conformance-profiles.yaml,
   06-governance-operations.yaml) to understand the current language.
2. For each decision point (4.1, 4.2, 4.3), confirm the recommended option or
   choose an alternative based on what the spec actually says.
3. Draft edits to:
   - `docs/spec/wardline-01-10-governance-model.md` if §10 needs clarification
   - `docs/spec/wardline-01-15-conformance.md` §15.3.2 to resolve ambiguity
   - `docs/requirements/spec-fitness/07-conformance-profiles.yaml` WL-FIT-CONF-010
     if the verification statement needs updating
4. Ensure no circular or contradictory references remain.
5. Run the verification scaffold seeder's `normative_conflicts` check — it
   should report empty after these edits.

## 6. Acceptance criteria

1. After edits, `docs/spec/wardline-01-10-governance-model.md` and
   `docs/spec/wardline-01-15-conformance.md` do not contradict each other on
   Lite governance requirements.
2. `docs/requirements/spec-fitness/07-conformance-profiles.yaml` WL-FIT-CONF-010
   is consistent with the resolved §15.3.2 language.
3. Bootstrap corpus requirement level is unambiguous: either SHOULD or MUST
   for Lite, with explicit scope (coverage vs correctness).
4. Branch protection, audit logging, and direct-law exclusion are explicitly
   bound to the Lite profile (either in §15.3.2 or by reference to WL-FIT-GOV-*).
5. The verification scaffold seeder (once built) can run without detecting
   `normative_conflicts` for Lite governance requirements.
6. No other spec sections are broken by these edits — run a grep for any
   cross-references to the edited sections and verify they still make sense.

## 7. Constraints

- Do not add new requirements. This task reconciles existing requirements; it
  does not invent new governance controls.
- Do not change the Assurance profile. Focus only on Lite.
- Do not touch implementation code. This is spec-only.
- Preserve the existing ADR history. If a significant design decision is made,
  document it in a new ADR, but prefer minimal changes that align the spec.

## 8. Reporting

When the task is complete, produce a summary containing:

1. The commit SHA for the reconciliation commit.
2. The specific changes made to each file.
3. The resolution chosen for each decision point (4.1, 4.2, 4.3).
4. Any surprises encountered — for example, if the spec has additional
   inconsistencies beyond the three identified.
5. A pointer back to this prompt file
   (`docs/superpowers/plans/2026-04-12-lite-governance-reconciliation.md`) so
   the next session can verify the reconciliation.

## 9. Relationship to other plans

This plan must complete **before** the verification scaffold walkthrough can
produce a defensible Lite verdict. The scaffold seeder will fail with
`normative_conflicts` if this reconciliation is not done first.

| Plan | Dependency |
|------|------------|
| `2026-04-12-v1-0-verification-scaffold.md` | Depends on this plan (no normative conflicts) |
| `2026-04-12-conformance-artifact-regeneration.md` | Depends on scaffold (not this plan directly) |
