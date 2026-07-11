# Gate Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Wardline's parallel gate-population fields with one closed tagged value, then make the independent request-path and config-derived source-root confinement stages explicit without weakening either boundary.

**Architecture:** `ScanResult` will own one mandatory, frozen `GatePopulation` containing an immutable finding tuple and a closed suppression posture. `gate_decision`, gate explanations, and the Legis projection will consume that value directly, so there is no sentinel or parallel boolean to drift. Separately, a `SourceRootConfinement` enum will describe only discovery of paths named by untrusted configuration; MCP arguments remain independently confined by `resolve_under_root` before core scanning starts.

**Tech Stack:** Python 3.11+, frozen/slots dataclasses, `StrEnum`, pytest, Click CLI, Wardline MCP JSON-RPC, Filigree issue lifecycle.

---

## Delivery boundaries

This plan contains two independent Filigree close cycles and two independent commits:

1. `wardline-84e470ea62` — P1 `GatePopulation` representation, commit `refactor(gate): make gate population posture explicit`.
2. `wardline-07fa744fe1` — P2 two-stage confinement contract, commit `refactor(core): make source-root confinement explicit`.

Do not close parent `wardline-8a1399a8b5` in either cycle. Its fingerprint-determinism child has a separate disposition and must be resolved independently.

Do not mix changes from the two children. Finish focused tests, repository verification, commit, and Filigree closeout for the P1 child before starting the P2 child.

## File map

### Gate-population child

- Modify `src/wardline/core/run.py` — define the closed posture and frozen population types; construct one authoritative population; consume it in gate decisions, reasons, and migration hints.
- Modify `src/wardline/core/legis.py` — project exactly `result.gate_population.findings` to the Legis artifact.
- Modify `tests/unit/core/test_run.py` — add the illegal-state matrix and migrate secure/default/trusted/new-since assertions.
- Modify `tests/unit/core/test_run_affected.py` — prove delta and trusted-delta populations stay complete and correctly tagged.
- Modify `tests/unit/core/test_affected_invariants.py` — preserve INV-1, INV-3 full fallback, and INV-4 surgical-exclusion behavior.
- Modify `tests/conformance/test_warpline_delta_scope.py` — preserve the conformance-level delta gate population.
- Modify `tests/conformance/test_legis_intake_contract.py` — construct tagged populations and prove the Legis judge sees the same population.
- Modify every direct `ScanResult(...)` fixture listed by `rg -n 'ScanResult\\(' tests src --glob '*.py'` so the mandatory gate population is explicit; current files are `tests/unit/mcp/test_lsp.py`, `tests/unit/cli/test_scan_artifacts.py`, `tests/unit/core/test_assure.py`, `tests/unit/core/test_dossier_assembler.py`, and `tests/unit/core/test_legis_artifact.py`, in addition to the gate-focused files above.
- Modify `tests/e2e/test_legis_live.py` — consume the tagged population in the live parity assertion.
- Modify `tests/docs/test_glossary_vocabulary.py` and the current gate-population wording in `src/wardline/cli/scan.py` only where the old field/property names are pinned as documentation vocabulary.

### Confinement child

- Create `src/wardline/core/confinement.py` — own the closed source-root discovery policy.
- Modify `src/wardline/core/discovery.py` — consume the policy for configured roots, missing roots, and file-symlink traversal.
- Modify `src/wardline/core/run.py` — accept and thread `source_root_confinement`, secure by default.
- Modify the core wrappers that currently expose `confine_to_root`: `src/wardline/core/assure.py`, `attest.py`, `baseline_ops.py`, `decorator_coverage.py`, `dossier.py`, `explain.py`, and `judge_run.py`.
- Modify surface adapters that currently pass `confine_to_root`: `src/wardline/cli/assure.py`, `attest.py`, `decorator_coverage.py`, `dossier.py`, `explain_taint.py`, `judge.py`, `main.py`, `rekey.py`, and `scan.py`; `src/wardline/lsp.py`; `src/wardline/mcp/server.py`; `src/wardline/weft_decorator_coverage.py`; and `src/wardline/weft_dossier.py`.
- Modify `src/wardline/core/scan_file_workflow.py` to request the secure policy explicitly.
- Modify `tests/unit/core/test_discovery.py`, `test_root_confinement.py`, and `test_run.py` for config-root and symlink behavior.
- Modify `tests/unit/mcp/test_server_security.py` to retain direct MCP path confinement and poisoned-config coverage as two independent assertions.
- Modify test call sites found by `rg -l 'confine_to_root' tests --glob '*.py'`, including CLI, MCP, hostile-input, and identity capture tests, replacing the old boolean with the named policy.
- Modify `docs/reference/mcp.md`, `docs/reference/cli.md`, and `docs/guides/configuration.md` to document the two independent stages and the explicit legacy opt-out.

---

### Task 1: Claim and reproduce `wardline-84e470ea62`

**Files:**
- Test: `tests/unit/core/test_run.py`
- Test: `tests/unit/core/test_run_affected.py`
- Test: `tests/unit/core/test_affected_invariants.py`

- [ ] **Step 1: Atomically start the P1 child**

Use Filigree MCP `work_start` with:

```json
{
  "issue_id": "wardline-84e470ea62",
  "assignee": "codex",
  "actor": "john",
  "claim_commit": "release/consolidation-2026-06-26@HEAD"
}
```

Expected: status `in_progress`, assignee `codex`. If the issue is already owned by another live worker, stop this child and report the conflict; do not steal the claim.

- [ ] **Step 2: Record the confirmed root cause**

Add this Filigree comment as actor `john`, with `expected_assignee: "codex"`:

```text
Root cause confirmed in src/wardline/core/run.py: gate population selection is represented by the independently optional gate_findings and gate_honors_suppressions fields. Full trusted scans encode posture with a None sentinel, while trusted delta scans must materialize a list plus a parallel True flag. That makes contradictory selection/posture states constructible. The fix will replace both fields with one mandatory frozen tagged GatePopulation and preserve full, trusted-suppression, delta, and full-fallback behavior.
```

- [ ] **Step 3: Add a red illegal-state and posture matrix**

At the gate contract section of `tests/unit/core/test_run.py`, import `FrozenInstanceError`, then import the not-yet-created `GatePopulation` and `GateSuppressionPosture` from `wardline.core.run`. Add:

```python
@pytest.mark.parametrize(
    ("posture", "honors"),
    [
        (GateSuppressionPosture.UNSUPPRESSED, False),
        (GateSuppressionPosture.HONORS_SUPPRESSIONS, True),
    ],
)
def test_gate_population_closed_posture_matrix(posture: GateSuppressionPosture, honors: bool) -> None:
    population = GatePopulation(findings=(), posture=posture)

    assert population.honors_suppressions is honors


def test_gate_population_rejects_mutable_findings() -> None:
    with pytest.raises(TypeError, match="findings must be a tuple"):
        GatePopulation(findings=[], posture=GateSuppressionPosture.UNSUPPRESSED)  # type: ignore[arg-type]


def test_gate_population_rejects_untyped_posture() -> None:
    with pytest.raises(TypeError, match="GateSuppressionPosture"):
        GatePopulation(findings=(), posture="unsuppressed")  # type: ignore[arg-type]


def test_gate_population_is_frozen() -> None:
    population = GatePopulation.unsuppressed(())

    with pytest.raises(FrozenInstanceError):
        population.posture = GateSuppressionPosture.HONORS_SUPPRESSIONS  # type: ignore[misc]
```

Replace `test_directly_constructed_scanresult_falls_back_to_findings` with a constructor test that requires an explicit tag:

```python
def test_directly_constructed_scanresult_requires_explicit_gate_population() -> None:
    leak = Finding(
        rule_id="PY-WL-101",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="svc.py", line_start=1),
        fingerprint="a" * 64,
        suppressed=SuppressionState.ACTIVE,
    )
    result = ScanResult(
        findings=[leak],
        summary=ScanSummary(total=1, active=1, baselined=0, waived=0, judged=0),
        files_scanned=1,
        context=None,
        gate_population=GatePopulation.honoring((leak,)),
    )

    assert result.gate_population.posture is GateSuppressionPosture.HONORS_SUPPRESSIONS
    assert gate_decision(result, Severity.ERROR).tripped is True
```

Add explicit run-path assertions:

```python
def test_secure_default_builds_unsuppressed_tagged_population(tmp_path: Path) -> None:
    proj, fp = _leaky_proj(tmp_path)
    _write_baseline(proj, fp)

    result = run_scan(proj)

    assert result.gate_population.posture is GateSuppressionPosture.UNSUPPRESSED
    gate_leak = next(f for f in result.gate_population.findings if f.rule_id == "PY-WL-101")
    assert gate_leak.suppressed is SuppressionState.ACTIVE


def test_trust_suppressions_builds_honoring_tagged_population(tmp_path: Path) -> None:
    proj, fp = _leaky_proj(tmp_path)
    _write_baseline(proj, fp)

    result = run_scan(proj, trust_suppressions=True)

    assert result.gate_population.posture is GateSuppressionPosture.HONORS_SUPPRESSIONS
    gate_leak = next(f for f in result.gate_population.findings if f.rule_id == "PY-WL-101")
    assert gate_leak.suppressed is SuppressionState.BASELINED
    assert gate_decision(result, Severity.ERROR).tripped is False
```

- [ ] **Step 4: Run the red tests**

Run:

```bash
uv run pytest -q \
  tests/unit/core/test_run.py -k 'gate_population or directly_constructed or trust_suppressions' \
  tests/unit/core/test_run_affected.py \
  tests/unit/core/test_affected_invariants.py
```

Expected: collection fails because `GatePopulation` and `GateSuppressionPosture` do not exist. This is the intended red state; no production behavior has changed yet.

---

### Task 2: Introduce the tagged gate contract and migrate every consumer

**Files:**
- Modify: `src/wardline/core/run.py`
- Modify: `src/wardline/core/legis.py`
- Modify: every direct `ScanResult(...)` test fixture named in the file map
- Modify: `tests/unit/core/test_run.py`
- Modify: `tests/unit/core/test_run_affected.py`
- Modify: `tests/unit/core/test_affected_invariants.py`
- Modify: `tests/conformance/test_warpline_delta_scope.py`
- Modify: `tests/conformance/test_legis_intake_contract.py`
- Modify: `tests/e2e/test_legis_live.py`

- [ ] **Step 1: Define the closed, frozen value before `ScanResult`**

In `src/wardline/core/run.py`, import `StrEnum` from `enum`, then add immediately before `ScanResult`:

```python
class GateSuppressionPosture(StrEnum):
    """Whether the authoritative gate population honors repository suppressions."""

    UNSUPPRESSED = "unsuppressed"
    HONORS_SUPPRESSIONS = "honors_suppressions"


@dataclass(frozen=True, slots=True)
class GatePopulation:
    """One authoritative finding population plus its closed suppression posture."""

    findings: tuple[Finding, ...]
    posture: GateSuppressionPosture

    def __post_init__(self) -> None:
        if not isinstance(self.findings, tuple):
            raise TypeError("GatePopulation findings must be a tuple")
        if not isinstance(self.posture, GateSuppressionPosture):
            raise TypeError("GatePopulation posture must be a GateSuppressionPosture")

    @property
    def honors_suppressions(self) -> bool:
        return self.posture is GateSuppressionPosture.HONORS_SUPPRESSIONS

    @classmethod
    def unsuppressed(cls, findings: Sequence[Finding]) -> GatePopulation:
        return cls(tuple(findings), GateSuppressionPosture.UNSUPPRESSED)

    @classmethod
    def honoring(cls, findings: Sequence[Finding]) -> GatePopulation:
        return cls(tuple(findings), GateSuppressionPosture.HONORS_SUPPRESSIONS)
```

The `Sequence` import already exists. The runtime guards make illegal states fail immediately for direct Python callers instead of relying on type checking.

- [ ] **Step 2: Replace the two `ScanResult` fields with one mandatory field**

Move the gate contract beside the required scan fields, before defaulted `scanned_paths`, and delete `gate_findings`, `gate_honors_suppressions`, and the `honors_suppressions` property:

```python
@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: list[Finding]
    summary: ScanSummary
    files_scanned: int
    context: AnalysisContext | None
    gate_population: GatePopulation
    scanned_paths: tuple[str, ...] = ()
    analyzed_paths: tuple[str, ...] = ()
    scope: DeltaScopeReport | None = None
    annotated_findings: list[Finding] | None = None
```

Retain the existing comments for `scanned_paths`, `analyzed_paths`, `scope`, and `annotated_findings`. Replace the removed sentinel commentary with a comment saying the authoritative population is always concrete and its posture is closed by `GateSuppressionPosture`.

- [ ] **Step 3: Build exactly one concrete population in `run_scan`**

Replace the `gate_findings: list[Finding] | None` / `gate_honors_suppressions` flow with a concrete working list and posture:

```python
    if skip_suppression:
        findings = apply_suppressions(raw, Baseline(frozenset()), WaiverSet([]), today=today, judged=None)
        gate_findings = list(findings)
        gate_posture = GateSuppressionPosture.HONORS_SUPPRESSIONS
    else:
        baseline = load_baseline(baseline_path(root))
        waivers = WaiverSet(load_project_waivers(root))
        judged = load_judged(judged_path(root))
        findings = apply_suppressions(raw, baseline, waivers, today=today, judged=judged)
        if trust_suppressions:
            gate_findings = list(findings)
            gate_posture = GateSuppressionPosture.HONORS_SUPPRESSIONS
        else:
            gate_findings = apply_suppressions(
                raw,
                Baseline(frozenset()),
                WaiverSet([]),
                today=today,
                judged=None,
            )
            gate_posture = GateSuppressionPosture.UNSUPPRESSED
```

Under `new_since`, always scope both concrete lists:

```python
        findings = apply_delta_scope(findings)
        gate_findings = apply_delta_scope(gate_findings)
```

Under true `--affected` delta mode, retain the pre-display population without any sentinel materialization branch:

```python
    annotated_findings: list[Finding] | None = None
    if scope_mode == "delta":
        annotated_findings = list(findings)
        findings = filter_to_affected(findings, affected_qualnames, affected_files)
```

At the return site, replace both old keyword arguments with:

```python
        gate_population=GatePopulation(tuple(gate_findings), gate_posture),
```

This preserves the required behavior:

| Scan path | Population | Posture | Gate authority |
|---|---|---|---|
| full/default | pre-repository-suppression findings | `UNSUPPRESSED` | gate of record |
| full + trusted suppressions | annotated emitted population | `HONORS_SUPPRESSIONS` | gate of record |
| `--new-since` | same selected population with operator delta relabeling | unchanged tag | gate of record |
| affected delta/default | full analyzed-file population, never display-filtered | `UNSUPPRESSED` | advisory when scope says delta |
| affected delta/trusted | post-suppression analyzed-file population, never display-filtered | `HONORS_SUPPRESSIONS` | advisory when scope says delta |
| affected full fallback | full population, no display filter | selected tag | gate of record |
| rekey `skip_suppression` | empty-store transformed population | `HONORS_SUPPRESSIONS` | behavior preserved from old sentinel path |

- [ ] **Step 4: Make the decision and explanation paths consume only the tag**

At the start of `gate_decision`, replace selection and posture inference with:

```python
    gate_population = result.gate_population.findings
    honors_suppressions = result.gate_population.honors_suppressions
    would_trip_at = _would_trip_at(gate_population)
```

In `baseline_migration_hint`, use:

```python
    if result.gate_population.honors_suppressions:
        return None
```

In `_gate_reason`, use the authoritative tuple in both branches:

```python
    gate_pop = result.gate_population.findings
    if honors_suppressions:
        active, _ = gate_breakdown(gate_pop, fail_on)
        return f"{active} active {sev}+ defect(s) at or above {sev}"
```

Leave the existing annotated-finding classification intact for the unsuppressed branch, but iterate `gate_pop` rather than `result.gate_findings or []`.

Run this mechanical guard after editing:

```bash
rg -n 'gate_findings|gate_honors_suppressions|result\.honors_suppressions' src/wardline tests --glob '*.py'
```

Expected: no matches. References in historical archived design/audit documents are out of scope and must not be bulk-rewritten.

- [ ] **Step 5: Migrate Legis and direct fixture consumers**

In `src/wardline/core/legis.py`, replace the sentinel selection with:

```python
    gate_population = result.gate_population.findings
```

In every direct `ScanResult(...)` fixture, add one explicit value. Use the posture the fixture is modeling, never a blanket default:

```python
gate_population=GatePopulation.unsuppressed((active_finding,))
```

for secure-default/gating fixtures, or:

```python
gate_population=GatePopulation.honoring(tuple(findings))
```

for ordinary synthetic output/LSP/posture fixtures and trusted-suppression fixtures. For empty synthetic results, use:

```python
gate_population=GatePopulation.honoring(())
```

Update imports from `wardline.core.run` in each changed test file. Do not add a default to `ScanResult`; mandatory construction is the enforcement mechanism.

In `tests/conformance/test_legis_intake_contract.py`, encode the two existing divergence cases as:

```python
gate_population=GatePopulation.unsuppressed((active,))
```

and:

```python
gate_population=GatePopulation.honoring((baselined,))
```

Then assert the artifact population against `result.gate_population.findings`. Apply the same direct consumption in `tests/e2e/test_legis_live.py`.

- [ ] **Step 6: Preserve delta and full-fallback invariants explicitly**

In `tests/unit/core/test_run_affected.py` and `tests/unit/core/test_affected_invariants.py`, replace list/sentinel checks with tag assertions. The trusted delta test must include:

```python
assert delta.gate_population.posture is GateSuppressionPosture.HONORS_SUPPRESSIONS
assert _py101_quals(delta.gate_population.findings) == {"evil.backdoor"}
```

using the existing fixture's actual expected qualnames if it includes more than the backdoor.

The secure delta surgical-exclusion tests must include:

```python
assert delta.gate_population.posture is GateSuppressionPosture.UNSUPPRESSED
assert _py101_quals(delta.gate_population.findings) == {"svc.alpha", "svc.beta"}
```

The full-fallback invariant must compare both parts:

```python
assert fallback.gate_population.posture is full.gate_population.posture
assert _frozen_finding_repr(fallback.gate_population.findings) == _frozen_finding_repr(
    full.gate_population.findings
)
```

The INV-1 full/default test must compare the tagged populations and retain the existing assertions that no scope is emitted and no resolver is called.

- [ ] **Step 7: Run focused and migration tests**

Run:

```bash
uv run pytest -q \
  tests/unit/core/test_run.py \
  tests/unit/core/test_run_affected.py \
  tests/unit/core/test_affected_invariants.py \
  tests/unit/core/test_legis_artifact.py \
  tests/conformance/test_warpline_delta_scope.py \
  tests/conformance/test_legis_intake_contract.py \
  tests/unit/mcp/test_lsp.py \
  tests/unit/core/test_assure.py \
  tests/unit/core/test_dossier_assembler.py
```

Expected: all pass. If a direct `ScanResult` constructor was missed, pytest should fail at construction; add the explicit posture appropriate to that fixture rather than restoring a default.

- [ ] **Step 8: Run static checks for the migrated contract**

Run:

```bash
uv run ruff check src/wardline/core/run.py src/wardline/core/legis.py tests/unit/core tests/conformance/test_warpline_delta_scope.py tests/conformance/test_legis_intake_contract.py
uv run mypy src/wardline/core/run.py src/wardline/core/legis.py
```

Expected: both commands exit 0.

---

### Task 3: Verify, commit, and close `wardline-84e470ea62`

**Files:**
- Modify: gate child files only

- [ ] **Step 1: Run the repository verification required before a security closeout**

Run:

```bash
uv run pytest -q
uv run wardline scan . --fail-on ERROR
```

Expected: pytest passes. Wardline exits 0 with no ERROR gate finding. If the self-scan reports that its boundary inventory is inert or empty, record that limitation in the ticket verification comment and rely on the focused gate regression suite as the primary behavioral proof; do not describe an inert scan as security coverage.

- [ ] **Step 2: Review only the P1 diff**

Run:

```bash
git diff --check
git diff --stat
git diff -- src/wardline/core/run.py src/wardline/core/legis.py tests
```

Expected: no whitespace errors; no confinement-policy, MCP-path, or unrelated cleanup changes in this commit.

- [ ] **Step 3: Commit the P1 child**

Run:

```bash
git add src/wardline/core/run.py src/wardline/core/legis.py src/wardline/cli/scan.py \
  tests/unit tests/conformance tests/e2e tests/docs
git commit -m "refactor(gate): make gate population posture explicit"
git rev-parse HEAD
```

Expected: one commit containing only the `GatePopulation` migration and its tests, followed
by its full hexadecimal commit SHA. Preserve that exact output for the close operation.

- [ ] **Step 4: Close the P1 child**

Add a Filigree comment as `john`, `expected_assignee: "codex"`:

```text
Implemented one mandatory frozen GatePopulation carrying an immutable finding tuple and a closed UNSUPPRESSED/HONORS_SUPPRESSIONS posture. Removed gate_findings, gate_honors_suppressions, and sentinel inference. Focused tests preserve full/default, trusted-suppression, new-since, affected-delta, trusted-delta, and full-fallback semantics; illegal mutable/untyped states fail at construction. Legis now consumes the same tagged population as gate_decision. Verification: full pytest, ruff, mypy, and wardline gate run recorded on the close commit.
```

Close `wardline-84e470ea62` with actor `john`, `expected_assignee: "codex"`, and a
`close_commit` formed by appending the exact SHA printed by the preceding `git rev-parse
HEAD` to `release/consolidation-2026-06-26@`.

Expected: issue status `closed`; parent remains open.

---

### Task 4: Claim and reproduce `wardline-07fa744fe1`

**Files:**
- Create: `tests/unit/core/test_confinement_policy.py`
- Modify: `tests/unit/core/test_discovery.py`
- Modify: `tests/unit/mcp/test_server_security.py`

- [ ] **Step 1: Atomically start the P2 child**

Use Filigree MCP `work_start` with:

```json
{
  "issue_id": "wardline-07fa744fe1",
  "assignee": "codex",
  "actor": "john",
  "claim_commit": "release/consolidation-2026-06-26@HEAD"
}
```

Expected: status `in_progress`, assignee `codex`.

- [ ] **Step 2: Record the confirmed root cause**

Add this Filigree comment:

```text
Root cause confirmed: Wardline already has two legitimate read-confinement stages, but config-derived source-root and symlink policy is threaded as the ambiguous boolean confine_to_root across discovery, run_scan, wrappers, CLI, MCP, and LSP. Direct MCP arguments are separately confined by wardline.mcp.tooling.resolve_under_root. The implementation will preserve both defenses, replace the config/discovery boolean with a closed SourceRootConfinement policy, keep PROJECT_ROOT as the secure default, and retain only the explicitly named legacy opt-out.
```

- [ ] **Step 3: Add the red policy matrix**

Create `tests/unit/core/test_confinement_policy.py`:

```python
from wardline.core.confinement import SourceRootConfinement


def test_source_root_confinement_is_closed_and_named() -> None:
    assert SourceRootConfinement.PROJECT_ROOT.confines_to_project is True
    assert SourceRootConfinement.LEGACY_ALLOW_ESCAPE.confines_to_project is False
    assert {policy.value for policy in SourceRootConfinement} == {
        "project-root",
        "legacy-allow-escape",
    }
```

In `tests/unit/core/test_discovery.py`, replace the implicit opt-out in `test_no_confine_keeps_low_level_symlink_escape_behavior` and the out-of-root gitignore control with explicit `SourceRootConfinement.LEGACY_ALLOW_ESCAPE`. Add an explicit secure-default test:

```python
def test_discover_secure_default_rejects_poisoned_source_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("SECRET = 1\n", encoding="utf-8")
    cfg = WardlineConfig(source_roots=("../outside",))

    with pytest.raises(ConfigError, match="outside the project root"):
        discover(root, cfg)
```

Import `pytest`, `ConfigError`, and `SourceRootConfinement` at module scope.

- [ ] **Step 4: Pin the two-stage distinction at the MCP surface**

Keep `test_scan_absolute_path_out_of_root_is_iserror` unchanged: it proves the direct request argument is rejected by `resolve_under_root` before discovery.

Split `test_poisoned_source_roots_refused_by_mcp_and_core_by_default` into named checks so the second stage cannot be mistaken for certification of config contents:

```python
def test_mcp_confined_config_path_does_not_certify_source_roots_inside_it(tmp_path: Path) -> None:
    proj = _poisoned_project(tmp_path)
    server = WardlineMCPServer(root=proj)

    resp = _dispatch(server, "scan", {"config": "weft.toml"})

    _assert_iserror(resp, "source_root")
    _assert_iserror(resp, "outside the project root")
    assert "findings" not in resp["result"]
```

Add a local `_poisoned_project` helper using the existing fixture body, then retain a core discriminator:

```python
def test_core_source_root_policy_secure_default_and_legacy_opt_out(tmp_path: Path) -> None:
    proj = _poisoned_project(tmp_path)

    with pytest.raises(ConfigError, match="outside the project root"):
        run_scan(proj)

    result = run_scan(
        proj,
        source_root_confinement=SourceRootConfinement.LEGACY_ALLOW_ESCAPE,
    )
    assert result.files_scanned >= 1
```

- [ ] **Step 5: Run the red tests**

Run:

```bash
uv run pytest -q \
  tests/unit/core/test_confinement_policy.py \
  tests/unit/core/test_discovery.py -k 'confinement or escape or symlink or gitignore_does_not_prune_outside_root' \
  tests/unit/mcp/test_server_security.py -k 'root or source_root or config'
```

Expected: collection fails because `wardline.core.confinement` and the new `source_root_confinement` parameter do not exist.

---

### Task 5: Introduce and thread the explicit source-root policy

**Files:**
- Create: `src/wardline/core/confinement.py`
- Modify: every confinement child source file listed in the file map
- Modify: confinement child tests listed in the file map
- Modify: `docs/reference/mcp.md`
- Modify: `docs/reference/cli.md`
- Modify: `docs/guides/configuration.md`

- [ ] **Step 1: Create the closed source-root policy**

Create `src/wardline/core/confinement.py`:

```python
"""Explicit policy for paths named by untrusted scan configuration."""

from __future__ import annotations

from enum import StrEnum


class SourceRootConfinement(StrEnum):
    """Whether configured source roots and discovered symlinks may leave the scan root.

    This policy does not validate a caller-supplied MCP path or config argument. MCP
    request paths are independently confined by ``wardline.mcp.tooling.resolve_under_root``
    before the configuration is loaded. A config file being inside the project root does
    not make paths named by its contents safe; discovery applies this second policy.
    """

    PROJECT_ROOT = "project-root"
    LEGACY_ALLOW_ESCAPE = "legacy-allow-escape"

    @property
    def confines_to_project(self) -> bool:
        return self is SourceRootConfinement.PROJECT_ROOT
```

- [ ] **Step 2: Replace discovery's boolean with the policy**

In `src/wardline/core/discovery.py`, import `SourceRootConfinement`, then change both signatures:

```python
def discover(
    root: Path,
    config: WardlineConfig,
    *,
    source_root_confinement: SourceRootConfinement = SourceRootConfinement.PROJECT_ROOT,
    suffixes: frozenset[str] = frozenset({".py"}),
    respect_gitignore: bool = False,
) -> list[Path]:
```

```python
def missing_source_roots(
    root: Path,
    config: WardlineConfig,
    *,
    source_root_confinement: SourceRootConfinement = SourceRootConfinement.PROJECT_ROOT,
) -> list[str]:
```

At the start of each function, reject untyped values:

```python
    if not isinstance(source_root_confinement, SourceRootConfinement):
        raise TypeError("source_root_confinement must be a SourceRootConfinement")
```

Replace every `confine_to_root` condition with:

```python
source_root_confinement.confines_to_project
```

Update docstrings to say `PROJECT_ROOT` rejects an escaping configured root and skips an escaping file symlink; `LEGACY_ALLOW_ESCAPE` is an explicit compatibility opt-out.

- [ ] **Step 3: Replace `run_scan`'s boolean with the policy**

In `src/wardline/core/run.py`, import `SourceRootConfinement` and change the signature:

```python
def run_scan(
    root: Path,
    *,
    config_path: Path | None = None,
    cache_dir: Path | None = None,
    source_root_confinement: SourceRootConfinement = SourceRootConfinement.PROJECT_ROOT,
```

Thread the exact value to both discovery calls:

```python
files = discover(
    root,
    cfg,
    source_root_confinement=source_root_confinement,
    suffixes=suffixes,
)
```

```python
for src in missing_source_roots(
    root,
    cfg,
    source_root_confinement=source_root_confinement,
):
```

Document that this policy applies to config-derived roots and discovered symlinks only. Do not import MCP tooling into core and do not collapse `resolve_under_root` into this enum.

- [ ] **Step 4: Migrate shared core wrappers without compatibility booleans**

For each core wrapper listed in the file map, replace:

```python
confine_to_root: bool = True
```

with:

```python
source_root_confinement: SourceRootConfinement = SourceRootConfinement.PROJECT_ROOT
```

and thread:

```python
source_root_confinement=source_root_confinement
```

to `run_scan` or the next wrapper. Import the enum from `wardline.core.confinement`. This applies to build/verify attestation, posture, baseline collection/generation, decorator coverage, dossier, explain flows, and judge. Do not leave a deprecated boolean alias: two simultaneous knobs would recreate the ambiguity this ticket removes.

- [ ] **Step 5: Map every trusted surface to a named policy**

For CLI scan, replace the boolean expression with an explicit mapping at the top of the execution block:

```python
source_root_confinement = (
    SourceRootConfinement.LEGACY_ALLOW_ESCAPE
    if allow_source_root_escape
    else SourceRootConfinement.PROJECT_ROOT
)
```

Pass that same value to the first scan and the post-autofix rescan. This preserves `--allow-source-root-escape` as the sole public legacy opt-out.

For MCP, LSP, scan-file workflow, agent helpers, and CLI commands that do not expose the legacy flag, either rely on the secure default or pass:

```python
source_root_confinement=SourceRootConfinement.PROJECT_ROOT
```

explicitly where the source comment documents the security boundary. MCP must still call `resolve_under_root` on request arguments before invoking these functions.

Run the migration guard:

```bash
rg -n 'confine_to_root' src/wardline tests --glob '*.py'
```

Expected: no matches. Historical archived documents may retain the old name; current reference docs must use the new policy language.

- [ ] **Step 6: Pin direct, config-root, symlink, secure-default, and opt-out behavior**

Update current tests mechanically with the enum, then ensure these five distinct proofs remain:

1. Direct request path: `tests/unit/mcp/test_server_security.py::test_scan_absolute_path_out_of_root_is_iserror` rejects `/etc` through MCP `resolve_under_root`.
2. Config source root: `test_mcp_confined_config_path_does_not_certify_source_roots_inside_it` rejects an in-root config naming `../outside`.
3. Symlink: `tests/unit/core/test_discovery.py::test_confine_excludes_symlink_escaping_root` and `test_discover_rust_symlink_confined` pass `PROJECT_ROOT` and exclude the out-of-root target.
4. Secure default: `test_discover_secure_default_rejects_poisoned_source_root` and every test in `tests/unit/core/test_root_confinement.py` omit the policy and still reject.
5. Legacy opt-out: `test_core_source_root_policy_secure_default_and_legacy_opt_out`, the attestation reproduce legacy fixture, and low-level discovery controls pass `LEGACY_ALLOW_ESCAPE` explicitly and still scan the out-of-root fixture.

Add this negative type check to `tests/unit/core/test_confinement_policy.py`:

```python
def test_discovery_rejects_boolean_policy(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="SourceRootConfinement"):
        discover(
            tmp_path,
            WardlineConfig(),
            source_root_confinement=True,  # type: ignore[arg-type]
        )
```

This prevents a future caller from silently reintroducing the boolean dialect.

- [ ] **Step 7: Document the two-stage contract**

In `docs/reference/mcp.md`, add this paragraph beside the root guarantee:

```markdown
Confinement is applied twice. First, MCP `path`, `config`, `cache_dir`, and output
arguments are resolved under the server root by `resolve_under_root`. Second, after an
allowed config is loaded, `SourceRootConfinement.PROJECT_ROOT` independently rejects
escaping `source_roots` and skips escaping source-file symlinks during discovery. Passing
the first check does not certify paths named inside the config.
```

In `docs/reference/cli.md`, retain the current public option name and state:

```markdown
`--allow-source-root-escape` selects the explicit
`SourceRootConfinement.LEGACY_ALLOW_ESCAPE` compatibility policy. The default is
`PROJECT_ROOT`; automation and enforcement should not enable the legacy policy.
```

In `docs/guides/configuration.md`, after the `source_roots` example, state:

```markdown
Configured roots are untrusted path values. Wardline's secure default resolves each root
and every discovered source-file symlink under the scan root. A config file located inside
the project can still contain an escaping root, so config-path validation and source-root
discovery validation are independent checks.
```

- [ ] **Step 8: Run focused confinement tests**

Run:

```bash
uv run pytest -q \
  tests/unit/core/test_confinement_policy.py \
  tests/unit/core/test_discovery.py \
  tests/unit/core/test_root_confinement.py \
  tests/unit/core/test_run.py -k 'source_root or symlink or confinement' \
  tests/unit/mcp/test_server_security.py \
  tests/unit/mcp/test_server_assure.py \
  tests/unit/mcp/test_server_attest.py \
  tests/unit/cli/test_attest_cmd.py \
  tests/unit/core/test_cli_mcp_parity.py \
  tests/conformance/test_hostile_input_degrade.py
```

Expected: all pass.

- [ ] **Step 9: Run static checks for the migrated policy**

Run:

```bash
uv run ruff check src/wardline tests/unit/core/test_confinement_policy.py tests/unit/core/test_discovery.py tests/unit/mcp/test_server_security.py
uv run mypy src/wardline/core src/wardline/mcp src/wardline/cli
```

Expected: both commands exit 0. A missed boolean call site should be a mypy failure, not a compatibility shim.

---

### Task 6: Verify, commit, and close `wardline-07fa744fe1`

**Files:**
- Modify: confinement child files only

- [ ] **Step 1: Run full verification and the trust-boundary gate**

Run:

```bash
uv run pytest -q
uv run wardline scan . --fail-on ERROR
```

Expected: full pytest passes and Wardline exits 0 with no ERROR finding. Record any self-scan coverage limitation honestly in the ticket comment.

- [ ] **Step 2: Prove there is no old boolean dialect**

Run:

```bash
rg -n 'confine_to_root' src/wardline tests --glob '*.py'
rg -n 'source_root_confinement' src/wardline tests --glob '*.py'
git diff --check
git diff --stat
```

Expected: first command has no matches; second shows the enum threaded across the current shared entry points; diff check passes.

- [ ] **Step 3: Commit the P2 child**

Run:

```bash
git add src/wardline/core/confinement.py src/wardline/core src/wardline/cli src/wardline/mcp \
  src/wardline/lsp.py src/wardline/weft_decorator_coverage.py src/wardline/weft_dossier.py \
  tests docs/reference/mcp.md docs/reference/cli.md docs/guides/configuration.md
git commit -m "refactor(core): make source-root confinement explicit"
git rev-parse HEAD
```

Before committing, inspect `git diff --cached --name-only` and unstage any file belonging to another live worker. The shared worktree may contain unrelated changes.
Preserve the full SHA printed after the commit for the close operation.

- [ ] **Step 4: Close the P2 child**

Add a Filigree comment as `john`, `expected_assignee: "codex"`:

```text
Replaced confine_to_root booleans with the closed SourceRootConfinement policy throughout discovery, run_scan, core wrappers, and surfaces. PROJECT_ROOT remains the secure default; the CLI's existing --allow-source-root-escape maps explicitly to LEGACY_ALLOW_ESCAPE. MCP request arguments remain independently guarded by resolve_under_root, and discovery separately rejects config-derived escaping roots and source symlinks. Tests pin direct argument escape, poisoned config source_root, Python/Rust symlink escape, secure defaults, explicit legacy opt-out, and rejection of boolean policy values. Verification: full pytest, ruff, mypy, and wardline gate run recorded on the close commit.
```

Close `wardline-07fa744fe1` with actor `john`, `expected_assignee: "codex"`, and a
`close_commit` formed by appending the exact SHA printed by the preceding `git rev-parse
HEAD` to `release/consolidation-2026-06-26@`.

Expected: issue status `closed`; parent `wardline-8a1399a8b5` remains open until its fingerprint-determinism child is dispositioned.

---

## Final acceptance matrix

| Invariant | Required proof |
|---|---|
| Gate state is closed | `GatePopulation` is frozen, findings are tuple-backed, posture is a `StrEnum`, invalid strings/lists fail immediately |
| Full/default gate | Population is unsuppressed and authoritative |
| Trusted suppressions | Population is post-suppression and tagged `HONORS_SUPPRESSIONS` |
| Affected delta | Display filtering never narrows `gate_population.findings`; clean delta remains advisory |
| Trusted affected delta | Concrete pre-display population retains honoring posture without a parallel flag |
| Full fallback | Population, posture, findings, and gate authority equal the full path |
| Legis parity | Artifact projects the same tagged population consumed by `gate_decision` |
| Direct MCP path confinement | `/etc` request rejected by `resolve_under_root` before scan |
| Config-derived path confinement | In-root config naming `../outside` rejected during discovery |
| Symlink confinement | Python and Rust source symlinks escaping root are skipped under secure policy |
| Secure default | Omitting policy uses `PROJECT_ROOT` at discovery, scan, and every wrapper |
| Legacy opt-out | Only explicit `LEGACY_ALLOW_ESCAPE` / CLI flag permits old behavior |
| Defense in depth | Documentation and tests state that an allowed config path does not certify paths inside it |

## Plan self-review

- Spec coverage: gate representation, illegal-state matrix, full/default, trusted suppression, affected delta, trusted delta, full fallback, Legis parity, direct/config/symlink confinement, secure default, legacy opt-out, and defense-in-depth documentation all map to concrete tasks and tests.
- Placeholder scan: prohibited marker text, vague implementation language, unnamed test steps, and symbolic commit values are absent. Each close step obtains its exact commit SHA with `git rev-parse HEAD`.
- Type consistency: the only gate field is `ScanResult.gate_population: GatePopulation`; the only posture enum is `GateSuppressionPosture`; the only config-derived path policy is `SourceRootConfinement`; all call sites use `source_root_confinement=`. MCP `resolve_under_root` remains a separate first-stage guard.
- Commit isolation: P1 and P2 each have an independent claim, red/green cycle, verification, commit, and close operation.
