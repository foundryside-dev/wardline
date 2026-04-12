# BAR Runner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the Bootstrap Assurance Reference runner that executes `docs/governance/bar-review-pipeline.md`, emits immutable BAR evidence artefacts, and makes BAR-related governance claims truthful across manifest, regime, and ledger surfaces.

**Architecture:** Treat the BAR spec as implementation-shaped, not frozen. Land this work in three layers: (1) tighten the new BAR spec where it is currently ambiguous, (2) add truthful BAR manifest/regime plumbing in `src/wardline/manifest/` and `src/wardline/cli/regime_cmd.py`, and (3) add a new `src/wardline/bar/` package plus `wardline bar` CLI that loads the active policy tree, assembles obligation review bundles, runs the seven-role panel for exactly three stability runs, and writes immutable JSON artefacts under `docs/verification/bar-pipeline-runs/`. Keep the domain layer pure-stdlib and put live LLM calls behind a single optional adapter so the base package remains dependency-free.

**Tech Stack:** Python 3.12, Click, stdlib `hashlib`/`json`/`subprocess`/`importlib`, existing manifest loaders and regime helpers, optional `anthropic` extra for live BAR runs.

**Prerequisites:**
- Use a clean commit ref for BAR runs. The runner must refuse dirty worktrees and commits that modify both reviewed code and the active BAR policy tree.
- Land this plan on issue `wardline-cd6686b7a4`.
- Coordinate with `wardline-fae28f1be3` and `wardline-75a774e144`: the runner can be built against the current ledger shape, but release-signoff use should wait until the obligation ledger and catalog are complete.
- Add a new optional dependency group in `pyproject.toml` for live BAR execution, for example `bar = ["anthropic>=0.49"]`.
- Manual smoke runs require `ANTHROPIC_API_KEY` in the environment.
- Treat `docs/spec/`, `docs/adr/`, and `docs/governance/` as the published authority. Every material BAR behavior change in code, schema, CLI, or artefact format must flow back into those docs in the same implementation slice.

---

## Sequencing

Implement in this order:

1. Spec hardening for BAR edge cases.
2. Truthful BAR manifest/regime plumbing.
3. Policy-tree loading and hash verification.
4. Obligation input assembly and evidence execution.
5. Runner/adapters/artefact writing.
6. CLI integration and end-to-end dry run.

Do **not** start with the live LLM adapter. The contract surfaces and deterministic artefact format need to settle first.

## Authority Rule

This repository publishes a reference specification. For BAR work, the implementation is **not** allowed to outrun the published documents.

- If a BAR runner behavior changes, update the binding docs in the same task.
- If a schema constraint changes, update the conformance/spec text and the ADR rationale in the same task.
- If implementation reveals a better contract, fix the contract first and then implement against it.
- Do not leave BAR semantics “explained by tests” or “explained by code comments” alone; the published docs must stay authoritative.

## Task 1: Harden the BAR spec before code

**Files:**
- Modify: `docs/governance/bar-review-pipeline.md`
- Modify: `docs/spec/wardline-01-15-conformance.md`
- Modify: `docs/adr/ADR-005-bootstrap-assurance-reference.md`
- Test/verify against: `src/wardline/manifest/schemas/compliance-ledger.schema.json`

**Step 1: Write the failing doc/contract checks**

Capture the required spec deltas in a short checklist file or issue comment before editing the docs:

```text
- artefact path must distinguish run-1/run-2/run-3/audit
- BAR pass maps to ledger state=verified + independence=bootstrap_attested
- summary.verified excludes BAR-attested rows; summary.bootstrap_attested reports them separately
- citations are an ordered array of strings
- source_refs_content comes from deterministic clause extraction, not ad-hoc line picking
- unsupported evidence classes cause BAR refusal, not silent skip
```

**Why this check:** The BAR spec is new, and the current text is underspecified in exactly the places the implementation will otherwise guess.

**Step 2: Review the current text and confirm the ambiguities exist**

Run:

```bash
rg -n "Evidence artefact|stability_run_index|bootstrap_attested|summary|source_refs_content|citations" docs/governance/bar-review-pipeline.md docs/spec/wardline-01-15-conformance.md docs/adr/ADR-005-bootstrap-assurance-reference.md
```

Expected output:

```text
Matches exist, but there is no concrete per-run filename convention and no explicit ledger-state mapping for BAR passes.
```

**Step 3: Update the spec text**

Make these normative changes:

```md
- Change artefact location to `docs/verification/bar-pipeline-runs/<YYYY-MM-DD>/<OBLIGATION-ID>/run-1.json`, `run-2.json`, `run-3.json`, and `audit-rerun.json`.
- State explicitly: a successful BAR self-assessment yields ledger `state: verified` and `reviewer_metadata.independence: bootstrap_attested`.
- State explicitly: `summary.verified` counts only default-human `independent` verifications; `summary.bootstrap_attested` counts BAR substitutions.
- Define `citations` as `array[string]`.
- Define `source_refs_content` as deterministic clause excerpts resolved from ledger `source_refs`.
- State that unsupported evidence classes or unresolved clause extraction force `insufficient_evidence`, never `pass`.
```

**Why this implementation:** These are not code-style preferences; they are the minimum contract needed to make the runner deterministic and auditable.

**Step 4: Re-read the amended spec for contradiction**

Run:

```bash
rg -n "run-1.json|audit-rerun.json|state: verified|summary.bootstrap_attested|citations|insufficient_evidence" docs/governance/bar-review-pipeline.md docs/spec/wardline-01-15-conformance.md docs/adr/ADR-005-bootstrap-assurance-reference.md
```

Expected output:

```text
All new BAR runner contract points appear exactly once in the normative docs and do not conflict with the conformance chapter.
```

**Step 5: Commit**

```bash
git add docs/governance/bar-review-pipeline.md docs/spec/wardline-01-15-conformance.md docs/adr/ADR-005-bootstrap-assurance-reference.md
git commit -m "docs: tighten BAR runner contract

- define per-run evidence artefact paths
- make BAR ledger-state mapping explicit
- close review-input and citation ambiguities"
```

**Definition of Done:**
- [ ] BAR artefact naming is unambiguous
- [ ] BAR pass/fail state mapping is explicit
- [ ] Summary counting semantics are explicit
- [ ] Input and citation formats are explicit
- [ ] Published BAR docs remain the authority for the new behavior

## Task 2: Plumb BAR manifest data and Assurance threshold truthfully

**Files:**
- Modify: `src/wardline/manifest/models.py`
- Modify: `src/wardline/manifest/loader.py`
- Modify: `src/wardline/manifest/regime.py`
- Modify: `src/wardline/cli/regime_cmd.py`
- Modify: `src/wardline/manifest/schemas/wardline.schema.json`
- Modify: `wardline.yaml`
- Test: `tests/unit/manifest/test_models.py`
- Test: `tests/unit/manifest/test_loader.py`
- Test: `tests/unit/manifest/test_regime.py`
- Test: `tests/unit/manifest/test_schemas.py`
- Test: `tests/unit/cli/test_regime_cmd.py`

**Step 1: Write the failing tests**

Add targeted tests for:

```python
def test_load_manifest_exposes_bootstrap_assurance_reference() -> None: ...
def test_collect_manifest_metrics_reports_bar_fields() -> None: ...
def test_regime_verify_assurance_requires_declared_expedited_ratio_threshold() -> None: ...
def test_status_json_surfaces_bar_metadata() -> None: ...
def test_root_manifest_requires_graduation_auditor_for_external_audit() -> None: ...
```

**Why this test set:** These are the truthfulness gaps already identified in review. Do not build the BAR runner on top of a manifest model that still drops BAR or a regime command that still hard-codes 15%.

**Step 2: Run the focused tests to see the current failures**

Run:

```bash
uv run pytest -q tests/unit/manifest/test_loader.py tests/unit/manifest/test_regime.py tests/unit/manifest/test_schemas.py tests/unit/cli/test_regime_cmd.py
```

Expected output:

```text
Failures for missing bootstrap_assurance_reference fields and Assurance threshold declaration handling.
```

**Step 3: Implement the model/schema/CLI changes**

Use a dedicated BAR model instead of loose dicts:

```python
@dataclass(frozen=True)
class BootstrapAssuranceReference:
    sole_maintainer: str
    declared_at: str
    graduation_target_date: str
    graduation_mechanism: str
    graduation_plan_ref: str
    slip_count: int
    graduation_auditor: str | None = None


@dataclass(frozen=True)
class ManifestMetadata:
    organisation: str = ""
    ratified_by: MappingProxyType[str, str] | None = None
    ratification_date: str | None = None
    review_interval_days: int | None = None
    temporal_separation: TemporalSeparation | None = None
    expedited_ratio_threshold: float | None = None
```

Also:

```python
@dataclass(frozen=True)
class WardlineManifest:
    ...
    bootstrap_assurance_reference: BootstrapAssuranceReference | None = None
```

In `regime_cmd.py`, replace the hard-coded Assurance fallback:

```python
threshold = manifest_m.expedited_ratio_threshold
if manifest_m.governance_profile == "assurance" and threshold is None:
    checks.append({
        "check": "expedited_ratio_threshold_declared",
        "status": "fail",
        "message": "Assurance requires metadata.expedited_ratio_threshold to be declared.",
    })
else:
    ...
```

**Why minimal:** BAR work depends on the runtime seeing the manifest declaration truthfully. This task is not the BAR runner yet; it is the governance substrate the runner relies on.

**Step 4: Re-run the focused tests**

Run:

```bash
uv run pytest -q tests/unit/manifest/test_loader.py tests/unit/manifest/test_regime.py tests/unit/manifest/test_schemas.py tests/unit/cli/test_regime_cmd.py
```

Expected output:

```text
All targeted tests pass; regime output now reports the declared threshold and BAR block.
```

**Step 5: Commit**

```bash
git add src/wardline/manifest/models.py src/wardline/manifest/loader.py src/wardline/manifest/regime.py src/wardline/cli/regime_cmd.py src/wardline/manifest/schemas/wardline.schema.json wardline.yaml tests/unit/manifest/test_models.py tests/unit/manifest/test_loader.py tests/unit/manifest/test_regime.py tests/unit/manifest/test_schemas.py tests/unit/cli/test_regime_cmd.py
git commit -m "feat: expose BAR manifest metadata and assurance threshold

- add bootstrap assurance manifest model
- require declared expedited ratio threshold for assurance
- surface BAR data in regime metrics"
```

**Definition of Done:**
- [ ] `load_manifest()` exposes BAR data
- [ ] `collect_manifest_metrics()` reports BAR fields and threshold
- [ ] `regime status` and `regime verify` stop using a hidden 15% fallback for Assurance
- [ ] External-audit BAR declarations require `graduation_auditor`
- [ ] Any BAR-related runtime behavior change is reflected back into the published docs

## Task 3: Load and verify the active BAR policy tree

**Files:**
- Create: `src/wardline/bar/__init__.py`
- Create: `src/wardline/bar/models.py`
- Create: `src/wardline/bar/policy.py`
- Test: `tests/unit/bar/test_policy.py`
- Fixture reuse: `docs/governance/bar-policy/2026.04.12/`

**Step 1: Write the failing tests**

Add tests for:

```python
def test_load_policy_tree_reads_version_json_and_model_pin() -> None: ...
def test_load_policy_tree_imports_aggregation_module() -> None: ...
def test_load_policy_tree_rejects_hash_mismatch() -> None: ...
def test_active_policy_tree_exposes_panel_roles_from_aggregation_module() -> None: ...
```

**Why this test:** The spec explicitly says the aggregation code in the policy tree is authoritative and runners must load it at runtime. Re-implementing it in `src/wardline` would create drift immediately.

**Step 2: Run the new policy tests**

Run:

```bash
uv run pytest -q tests/unit/bar/test_policy.py
```

Expected output:

```text
Failures because no BAR package or runtime policy loader exists yet.
```

**Step 3: Implement the loader**

Use a pure-stdlib loader that imports `aggregation.py` from disk:

```python
@dataclass(frozen=True)
class LoadedBarPolicy:
    version: str
    root: Path
    pipeline_name: str
    policy_hash: str
    model_pin: Mapping[str, object]
    aggregation_module: types.ModuleType


def load_policy_tree(version: str | None = None) -> LoadedBarPolicy:
    root = _resolve_policy_root(version)
    version_data = json.loads((root / "version.json").read_text(encoding="utf-8"))
    module = _import_module(root / "aggregation.py", f"wardline_bar_policy_{version_data['pipeline_version']}")
    actual_hash = module.compute_policy_hash(root)
    if actual_hash != version_data["policy_hash"]:
        raise BarPolicyError(...)
    return LoadedBarPolicy(...)
```

**Why this implementation:** It matches the spec’s author-isolation model: decision semantics come from the version-locked policy tree, not from a copy in the application package.

**Step 4: Re-run the policy tests**

Run:

```bash
uv run pytest -q tests/unit/bar/test_policy.py
```

Expected output:

```text
PASS
```

**Step 5: Commit**

```bash
git add src/wardline/bar/__init__.py src/wardline/bar/models.py src/wardline/bar/policy.py tests/unit/bar/test_policy.py
git commit -m "feat: load and verify BAR policy trees

- import aggregation semantics from the active policy tree
- verify policy hash from version.json
- expose model pin and panel roles"
```

**Definition of Done:**
- [ ] The runner can load the active policy tree without copying its semantics
- [ ] Policy hash mismatches fail closed
- [ ] Panel roles come from the loaded policy tree
- [ ] The published governance docs still describe the active loader contract accurately

## Task 4: Assemble deterministic obligation review bundles

**Files:**
- Create: `src/wardline/bar/ledger.py`
- Create: `src/wardline/bar/inputs.py`
- Create: `src/wardline/bar/evidence_exec.py`
- Test: `tests/unit/bar/test_inputs.py`
- Test: `tests/unit/bar/test_evidence_exec.py`
- Fixture create: `tests/fixtures/bar/ledger/`

**Step 1: Write the failing tests**

Cover these cases:

```python
def test_load_obligation_from_compliance_ledger() -> None: ...
def test_clause_extractor_resolves_source_ref_excerpt() -> None: ...
def test_review_bundle_reads_implementation_surface_at_commit_ref() -> None: ...
def test_unsupported_evidence_class_refuses_bundle() -> None: ...
def test_dirty_commit_ref_is_rejected() -> None: ...
```

**Why this test set:** The BAR runner must review a frozen bundle, not whatever happens to be in the working tree when the command runs.

**Step 2: Run the bundle tests**

Run:

```bash
uv run pytest -q tests/unit/bar/test_inputs.py tests/unit/bar/test_evidence_exec.py
```

Expected output:

```text
Failures because no ledger parser, clause extractor, or evidence executor exists yet.
```

**Step 3: Implement bundle assembly**

Create a review-bundle dataclass and executor registry:

```python
@dataclass(frozen=True)
class BarReviewBundle:
    obligation_id: str
    obligation_record: Mapping[str, object]
    source_refs_content: tuple[ResolvedSourceRef, ...]
    implementation_surface_content: tuple[ResolvedFileContent, ...]
    evidence_class_outputs: tuple[EvidenceOutput, ...]
    commit_ref: str
    manifest_hash: str
    corpus_hash: str | None
    policy_hash: str
```

Important rules:

```python
- Parse `source_refs` from ledger strings like "docs/spec/... §15.2(5)".
- Resolve source excerpts deterministically by clause heading, not ad-hoc line slicing.
- Read implementation-surface files with `git show <commit_ref>:<path>` so the review bundle ignores the live working tree.
- Support only the evidence classes currently used by the real ledger and BAR gates in v1:
  unit_tests, corpus_verify, coherence_check, manifest_schema_validation,
  conformance_report, temporal_separation_audit, fingerprint_baseline_review,
  exception_register_audit, adversarial_corpus_minima_check, expedited_governance_ratio_check,
  static_code_review, ast_inspection, reviewer_attestation, ratification_record,
  sarif_rule_output.
- For any unsupported class, return a structured refusal and map the bundle to `insufficient_evidence`.
```

**Why minimal:** This keeps v1 aligned with the actual repo surface instead of pretending the runner can execute every theoretical evidence class in the schema.

**Step 4: Re-run the bundle tests**

Run:

```bash
uv run pytest -q tests/unit/bar/test_inputs.py tests/unit/bar/test_evidence_exec.py
```

Expected output:

```text
PASS
```

**Step 5: Commit**

```bash
git add src/wardline/bar/ledger.py src/wardline/bar/inputs.py src/wardline/bar/evidence_exec.py tests/unit/bar/test_inputs.py tests/unit/bar/test_evidence_exec.py tests/fixtures/bar/ledger
git commit -m "feat: build deterministic BAR review bundles

- load obligations from the compliance ledger
- resolve clause excerpts and implementation content at commit_ref
- execute supported evidence classes for BAR review inputs"
```

**Definition of Done:**
- [ ] BAR review input is a frozen bundle
- [ ] Clause extraction is deterministic
- [ ] Evidence execution fails closed on unsupported classes
- [ ] Dirty or ambiguous commit refs are rejected
- [ ] Review-bundle semantics are documented in the published BAR docs if they changed

## Task 5: Implement the BAR runner and immutable evidence artefacts

**Files:**
- Create: `src/wardline/bar/adapters.py`
- Create: `src/wardline/bar/runner.py`
- Create: `src/wardline/bar/evidence.py`
- Modify: `pyproject.toml`
- Test: `tests/unit/bar/test_runner.py`
- Test: `tests/unit/bar/test_evidence.py`
- Create: `docs/verification/bar-pipeline-runs/.gitkeep`

**Step 1: Write the failing tests**

Use a fake adapter to prove the runner contract before any networked provider is involved:

```python
def test_runner_executes_all_seven_roles_for_three_runs() -> None: ...
def test_runner_uses_policy_aggregation_module() -> None: ...
def test_runner_writes_run_artefacts_with_run_specific_paths() -> None: ...
def test_runner_refuses_unstable_pass() -> None: ...
def test_runner_returns_non_compliant_when_any_role_fails() -> None: ...
```

**Why this test:** The spec’s hard parts are unanimity, exact run count, imported aggregation semantics, and immutable artefact emission. The live adapter is secondary.

**Step 2: Run the runner tests**

Run:

```bash
uv run pytest -q tests/unit/bar/test_runner.py tests/unit/bar/test_evidence.py
```

Expected output:

```text
Failures because there is no BAR runner, no adapter protocol, and no evidence writer.
```

**Step 3: Implement the runner**

Keep the adapter thin and the runner deterministic:

```python
class ReviewerAdapter(Protocol):
    def review(self, *, role: str, prompt: str, model_pin: Mapping[str, object]) -> ReviewerResult: ...


def run_bar_review(bundle: BarReviewBundle, policy: LoadedBarPolicy, adapter: ReviewerAdapter) -> BarReviewOutcome:
    run_verdicts: list[dict[str, str]] = []
    artefacts: list[BarEvidenceArtifact] = []
    for run_index in (1, 2, 3):
        reviewer_results = _run_panel_once(bundle, policy, adapter)
        verdicts = {role: result.verdict for role, result in reviewer_results.items()}
        aggregate = policy.aggregation_module.aggregate(verdicts)
        artefacts.append(_write_run_artefact(..., stability_run_index=run_index))
        run_verdicts.append(verdicts)

    stable, reason = policy.aggregation_module.check_stability(run_verdicts)
    return _summarize_outcome(...)
```

Write artefacts to the spec-tightened layout:

```text
docs/verification/bar-pipeline-runs/<YYYY-MM-DD>/<OBLIGATION-ID>/run-1.json
docs/verification/bar-pipeline-runs/<YYYY-MM-DD>/<OBLIGATION-ID>/run-2.json
docs/verification/bar-pipeline-runs/<YYYY-MM-DD>/<OBLIGATION-ID>/run-3.json
docs/verification/bar-pipeline-runs/<YYYY-MM-DD>/<OBLIGATION-ID>/audit-rerun.json
```

Add one concrete live adapter only after the fake-adapter tests pass:

```python
class AnthropicReviewerAdapter:
    def __init__(self, client: Anthropic) -> None: ...
    def review(self, *, role: str, prompt: str, model_pin: Mapping[str, object]) -> ReviewerResult: ...
```

**Why this implementation:** It respects the zero-dependency core by isolating the live provider behind an optional extra and keeps the normative aggregation semantics sourced from the policy tree.

**Step 4: Re-run the runner tests**

Run:

```bash
uv run pytest -q tests/unit/bar/test_runner.py tests/unit/bar/test_evidence.py
```

Expected output:

```text
PASS
```

**Step 5: Commit**

```bash
git add src/wardline/bar/adapters.py src/wardline/bar/runner.py src/wardline/bar/evidence.py pyproject.toml tests/unit/bar/test_runner.py tests/unit/bar/test_evidence.py docs/verification/bar-pipeline-runs/.gitkeep
git commit -m "feat: implement BAR runner and evidence artefacts

- execute seven-role BAR panel for exactly three runs
- verify stability via imported policy semantics
- write immutable per-run BAR evidence artefacts"
```

**Definition of Done:**
- [ ] Runner executes exactly 7 roles × 3 runs
- [ ] Aggregation and stability come from the policy tree, not duplicate code
- [ ] Evidence artefacts are immutable and path-stable
- [ ] Live LLM execution is optional and adapter-scoped
- [ ] Artefact shape and lifecycle remain aligned with the published BAR docs

## Task 6: Add `wardline bar` CLI and wire BAR status into existing governance surfaces

**Files:**
- Create: `src/wardline/cli/bar_cmd.py`
- Modify: `src/wardline/cli/main.py`
- Modify: `src/wardline/cli/regime_cmd.py`
- Test: `tests/unit/cli/test_bar_cmd.py`
- Test: `tests/unit/cli/test_regime_cmd.py`

**Step 1: Write the failing CLI tests**

Add tests for:

```python
def test_bar_review_writes_three_run_artefacts_with_fake_adapter() -> None: ...
def test_bar_review_refuses_dirty_or_policy_mixed_commit() -> None: ...
def test_bar_rerun_writes_audit_artefact() -> None: ...
def test_regime_status_json_includes_bar_runner_readiness_fields() -> None: ...
```

**Why this test:** BAR needs a user-facing entry point and the governance dashboard needs to tell the truth about whether BAR is merely declared or actually runnable.

**Step 2: Run the CLI tests**

Run:

```bash
uv run pytest -q tests/unit/cli/test_bar_cmd.py tests/unit/cli/test_regime_cmd.py
```

Expected output:

```text
Failures because no `bar` command exists and regime output has no BAR-runner readiness fields.
```

**Step 3: Implement the CLI**

Add a new Click group:

```python
@click.group()
def bar() -> None:
    """Bootstrap Assurance Reference review runner."""


@bar.command("review")
@click.option("--ledger", type=click.Path(exists=True), required=True)
@click.option("--obligation", required=True)
@click.option("--policy-version")
@click.option("--path", "project_path", type=click.Path(exists=True), required=True)
@click.option("--json", "output_json", is_flag=True)
def review(...): ...


@bar.command("rerun")
def rerun(...): ...
```

Also extend `regime status --json` with BAR readiness/reporting fields:

```python
{
  "bootstrap_assurance_reference": {...} | null,
  "expedited_ratio_threshold": 0.15 | null,
  "bar_runner_ready": true | false,
  "bar_policy_version": "2026.04.12" | null,
}
```

**Why minimal:** BAR users need one self-assessment command and one audit re-run command. Anything broader can wait until the verification-scaffold/compiler work stabilizes.

**Step 4: Re-run the CLI tests**

Run:

```bash
uv run pytest -q tests/unit/cli/test_bar_cmd.py tests/unit/cli/test_regime_cmd.py
```

Expected output:

```text
PASS
```

**Step 5: Commit**

```bash
git add src/wardline/cli/bar_cmd.py src/wardline/cli/main.py src/wardline/cli/regime_cmd.py tests/unit/cli/test_bar_cmd.py tests/unit/cli/test_regime_cmd.py
git commit -m "feat: add BAR runner CLI

- add wardline bar review and rerun commands
- surface BAR runner readiness in regime status
- refuse dirty and policy-mixed review commits"
```

**Definition of Done:**
- [ ] `wardline bar review` performs BAR self-assessment
- [ ] `wardline bar rerun` performs the single audit rerun path
- [ ] `wardline regime status` surfaces BAR readiness truthfully
- [ ] Any new CLI-visible BAR behavior is described in the published docs, not only in help text

## Task 7: Full verification pass and controlled manual smoke run

**Files:**
- Verify: `src/wardline/bar/`
- Verify: `src/wardline/cli/bar_cmd.py`
- Verify: `src/wardline/manifest/`
- Optional manual smoke target: `wardline.compliance.json`

**Step 1: Run the full unit slices**

Run:

```bash
uv run pytest -q tests/unit/bar tests/unit/cli/test_bar_cmd.py tests/unit/cli/test_regime_cmd.py tests/unit/manifest/test_loader.py tests/unit/manifest/test_regime.py tests/unit/manifest/test_schemas.py
```

Expected output:

```text
PASS
```

**Step 2: Run lint and type-checking**

Run:

```bash
uv run ruff check src/ tests/
uv run mypy src/
```

Expected output:

```text
All checks pass with no BAR-package import or typing errors.
```

**Step 3: Run one controlled manual smoke with the fake adapter**

Run:

```bash
uv run wardline bar review --ledger wardline.compliance.json --obligation C-CRIT-10-MANIFEST-CONSUMPTION --path . --json
```

Expected output:

```json
{
  "obligation_id": "C-CRIT-10-MANIFEST-CONSUMPTION",
  "aggregate_verdict": "pass|fail|insufficient_evidence|refer",
  "stable": true,
  "artefacts": [
    "docs/verification/bar-pipeline-runs/2026-04-12/C-CRIT-10-MANIFEST-CONSUMPTION/run-1.json",
    "docs/verification/bar-pipeline-runs/2026-04-12/C-CRIT-10-MANIFEST-CONSUMPTION/run-2.json",
    "docs/verification/bar-pipeline-runs/2026-04-12/C-CRIT-10-MANIFEST-CONSUMPTION/run-3.json"
  ]
}
```

**Step 4: Optional live-provider smoke**

Run only after the fake-adapter path is green:

```bash
ANTHROPIC_API_KEY=... uv run wardline bar review --ledger wardline.compliance.json --obligation C-CRIT-10-MANIFEST-CONSUMPTION --path . --json
```

Expected output:

```text
Three run artefacts are written without mutating the ledger in place.
```

**Step 5: Commit**

```bash
git add docs/verification/bar-pipeline-runs
git commit -m "test: verify BAR runner end-to-end"
```

**Definition of Done:**
- [ ] Targeted BAR unit tests pass
- [ ] Ruff and mypy pass
- [ ] Fake-adapter smoke run writes the expected artefacts
- [ ] Live-provider smoke is optional and does not gate the merge
- [ ] Final BAR behavior is reflected in `docs/spec/`, `docs/adr/`, and `docs/governance/`

## Integration Notes

- The BAR runner should **not** directly rewrite `wardline.compliance.json` in its first landing. It should emit evidence artefacts and a structured outcome; the compliance-ledger/compiler work can consume that outcome once `wardline-fae28f1be3` settles the write path.
- For BAR-attested obligations, the intended ledger shape is `state: verified` with `reviewer_metadata.independence: bootstrap_attested`. The compiler or ledger updater must derive `summary.bootstrap_attested` separately and exclude those rows from `summary.verified`.
- The runner should refuse any review where the active policy version lives in the same reviewed commit as the implementation changes. That guard is part of BAR’s author-isolation property, not an optional hygiene check.
- If clause extraction from `source_refs` proves too lossy against the current ledger string format, extend the verification-scaffold/compiler work to retain explicit excerpts alongside the compiled strings rather than teaching the runner to guess.

## Residual Risks

- The obligation ledger is still incomplete. The runner can be implemented now, but the repository cannot make a release-wide BAR claim until the catalog work closes.
- Live LLM calls are inherently costly and can fail transiently. The adapter must surface transport failures as `insufficient_evidence`, not retries that mutate the input bundle.
- The new BAR package adds optional provider dependencies. Keep them out of the base install and out of core runtime paths.
- The spec may still need one follow-up clarification if audit stakeholders want a formal JSON Schema for the BAR evidence artefact itself.
