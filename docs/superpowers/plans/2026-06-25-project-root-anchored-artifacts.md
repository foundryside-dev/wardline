# Project-Root-Anchored Scan Artifacts + Doctor Hygiene — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `wardline scan` write its default findings artifact to one standard location anchored to the weft-project root (not the scan cwd), and make `wardline doctor --repair` set up `.gitignore` for it and sweep stray managed artifacts (deletion reachable from CLI and the MCP `doctor` tool).

**Architecture:** Part 1 adds two pure helpers to `core/paths.py` (`project_root_for`, `artifacts_dir`) that reuse the existing `weft_state_dir`/`enclosing_project_root` machinery, and re-anchors `core/artifacts.py` from the scan path to the project root. Part 2 adds two `DoctorCheck`-returning helpers to `install/doctor.py` (`_check_gitignore`, `_sweep_stray_artifacts`) wired into `machine_readable_doctor` and both `cli/doctor.py` render branches, plus the MCP `doctor` tool destructive-hint flip.

**Tech Stack:** Python 3.11+ (stdlib `pathlib`/`os`/`re`/`tomllib`), `click` CLI, `pytest`. Base package stays zero-dependency.

**Worktree:** Implement in `/home/john/wardline-artifacts` (branch `feat/project-root-anchored-artifacts`, off `release/consolidation-2026-06-25`). All paths below are relative to that worktree root. Run `git` only here.

**Spec:** `docs/superpowers/specs/2026-06-25-wardline-project-root-anchored-artifacts-design.md` (this worktree). Read it before starting; every task implements a part of it.

## Global Constraints

- Base package stays **zero-dependency**: only stdlib + already-present imports in touched modules. No new third-party imports.
- `weft.toml` is **untrusted** when scanning an untrusted repo: every new path resolution confines under the project root and every new write/delete is no-follow.
- No new config key. `artifacts.dir` (default `.wardline`) / `artifacts.retain` (default `20`) keep their meaning; only the *anchor* of `artifacts.dir` changes.
- Public signatures of `artifacts.write_scan_artifact` / `artifacts.timestamped_scan_artifact` stay unchanged (they still take the scan `root`).
- Run the suite with the project venv: `.venv/bin/pytest`. Lint/type with `.venv/bin/ruff check .` and `.venv/bin/mypy src`. Keep both clean.
- Commit after every task (each task ends green).

---

## File structure

| File | Change | Responsibility |
|------|--------|----------------|
| `src/wardline/core/paths.py` | modify | Own `DEFAULT_ARTIFACT_DIR`; add `project_root_for`, `artifacts_dir` |
| `src/wardline/core/config.py` | modify | Re-export `DEFAULT_ARTIFACT_DIR` from `paths` (drop local literal) |
| `src/wardline/core/artifacts.py` | modify | Anchor artifact dir + confinement base to project root |
| `src/wardline/core/run.py` | modify | Amend `WLN-ENGINE-NESTED-SCAN-ROOT` message clause |
| `src/wardline/core/discovery.py` | modify | Public alias `WALK_SKIP_DIRS` for `_ALWAYS_SKIP` |
| `src/wardline/install/doctor.py` | modify | `DoctorCheck` `removed`/`review` fields; `_check_gitignore`; `_sweep_stray_artifacts`; wire into `machine_readable_doctor` |
| `src/wardline/cli/doctor.py` | modify | Render the two new checks in `--repair` + check-only branches |
| `src/wardline/cli/scan.py` | modify | Fix the `doctor --repair` hint to point at the project root |
| `src/wardline/mcp/server.py` | modify | Flip `_DOCTOR_TOOL` `destructiveHint`; note deletion in description |
| `docs/getting-started.md`, `docs/guides/configuration.md`, `docs/guides/agents.md`, `CHANGELOG.md` | modify | Document the anchor change + doctor hygiene |
| `tests/unit/core/test_paths.py` | modify/create | `project_root_for`/`artifacts_dir` matrix |
| `tests/unit/core/test_artifacts.py` | modify | Anchoring + retention |
| `tests/unit/install/test_doctor_hygiene.py` | create | gitignore + sweep + wiring + MCP confinement |
| `tests/unit/cli/test_scan_artifacts.py` (or existing scan CLI test) | modify | End-to-end subdir/root/unfederated anchoring |

---

## Task 1: `paths` helpers + `config` re-export

**Files:**
- Modify: `src/wardline/core/paths.py`
- Modify: `src/wardline/core/config.py:25`
- Test: `tests/unit/core/test_paths.py`

**Interfaces:**
- Produces: `paths.DEFAULT_ARTIFACT_DIR: str` (`".wardline"`); `paths.project_root_for(scan_path: Path) -> Path` (always fully-resolved); `paths.artifacts_dir(scan_path: Path, artifacts_dir_value: str) -> Path` (resolved, confined under the project root; escape → default `<proj>/.wardline`).
- Consumes: existing `paths.enclosing_project_root`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/core/test_paths.py` (create the file with the standard imports if absent: `from pathlib import Path`, `import pytest`, `from wardline.core import paths`):

```python
def _mark_project(root: Path) -> None:
    (root / "weft.toml").write_text("[wardline]\n", encoding="utf-8")

def test_project_root_for_self_when_marked(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    assert paths.project_root_for(tmp_path) == tmp_path.resolve()

def test_project_root_for_climbs_to_enclosing(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    assert paths.project_root_for(sub) == tmp_path.resolve()

def test_project_root_for_unfederated_is_self(tmp_path: Path) -> None:
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    assert paths.project_root_for(sub) == sub.resolve()

def test_artifacts_dir_default(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    assert paths.artifacts_dir(tmp_path, ".wardline") == (tmp_path.resolve() / ".wardline")

def test_artifacts_dir_relative_override(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    assert paths.artifacts_dir(tmp_path, "out/wl") == (tmp_path.resolve() / "out" / "wl")

def test_artifacts_dir_absolute_inside_honored(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    inside = tmp_path.resolve() / "build" / "wl"
    assert paths.artifacts_dir(tmp_path, str(inside)) == inside

def test_artifacts_dir_absolute_outside_falls_back(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    assert paths.artifacts_dir(tmp_path, "/etc/wardline") == (tmp_path.resolve() / ".wardline")

def test_artifacts_dir_dotdot_escape_falls_back(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    assert paths.artifacts_dir(tmp_path, "../../etc") == (tmp_path.resolve() / ".wardline")

def test_artifacts_dir_anchors_to_enclosing_for_subdir(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    assert paths.artifacts_dir(sub, ".wardline") == (tmp_path.resolve() / ".wardline")
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/unit/core/test_paths.py -q`
Expected: FAIL — `AttributeError: module 'wardline.core.paths' has no attribute 'project_root_for'`.

- [ ] **Step 3: Implement the helpers in `paths.py`**

Add near the top (after `_WEFT_DIR = ".weft"`):

```python
DEFAULT_ARTIFACT_DIR = ".wardline"
```

Add at the end of `paths.py`:

```python
def project_root_for(scan_path: Path) -> Path:
    """The weft-project root governing a scan of *scan_path* (always resolved).

    enclosing_project_root() returns the nearest STRICT ancestor carrying project
    markers, or None when scan_path itself is a root OR no ancestor is one. In both
    None cases the governing root is scan_path itself.
    """
    return enclosing_project_root(scan_path) or scan_path.resolve()


def artifacts_dir(scan_path: Path, artifacts_dir_value: str) -> Path:
    """Resolved scan-artifact directory, anchored to project_root_for(scan_path).

    Mirrors weft_state_dir's confinement: a relative value resolves under the project
    root; an absolute value is honored only if inside it; any value resolving OUTSIDE
    (absolute elsewhere or a ``..`` escape) falls back to the default ``.wardline``
    under the project root. weft.toml is untrusted input, so this denies a malicious
    artifacts.dir both a write-redirect and an exit-2 DoS.
    """
    project_root = project_root_for(scan_path)  # already fully resolved
    default = project_root / DEFAULT_ARTIFACT_DIR
    candidate = Path(artifacts_dir_value)
    resolved = (candidate if candidate.is_absolute() else project_root / candidate).resolve()
    try:
        resolved.relative_to(project_root)
    except ValueError:
        return default
    return resolved
```

- [ ] **Step 4: Re-export from `config.py` (drop the local literal)**

In `src/wardline/core/config.py`, change the import block (currently lines 19-22) to add `DEFAULT_ARTIFACT_DIR`:

```python
from wardline.core.paths import (
    DEFAULT_ARTIFACT_DIR,
    legacy_sibling_dir,
    sibling_state_dir,
)
```

And delete the local literal at line 25 (`DEFAULT_ARTIFACT_DIR = ".wardline"`), keeping `DEFAULT_ARTIFACT_RETAIN = 20`. `ArtifactSettings.dir`'s default still resolves to the imported name. (No cycle: `config.py` already imports from `paths.py`, and `paths.py` imports nothing from `config.py`.)

- [ ] **Step 5: Run tests + lint/type**

Run: `.venv/bin/pytest tests/unit/core/test_paths.py -q && .venv/bin/ruff check src/wardline/core/paths.py src/wardline/core/config.py && .venv/bin/mypy src/wardline/core/paths.py src/wardline/core/config.py`
Expected: PASS, clean.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/core/paths.py src/wardline/core/config.py tests/unit/core/test_paths.py
git commit -m "feat(paths): project_root_for + artifacts_dir helpers (own DEFAULT_ARTIFACT_DIR)"
```

---

## Task 2: re-anchor `artifacts.py` to the project root

**Files:**
- Modify: `src/wardline/core/artifacts.py`
- Test: `tests/unit/core/test_artifacts.py`

**Interfaces:**
- Consumes: `paths.project_root_for`, `paths.artifacts_dir` (Task 1).
- Produces: `write_scan_artifact(root, fmt, config, content)` / `timestamped_scan_artifact(root, fmt, config)` unchanged signatures, now writing under `project_root_for(root)/<artifacts.dir>`.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/core/test_artifacts.py`:

```python
from wardline.core import artifacts
from wardline.core.config import WardlineConfig

def _project(tmp_path):
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")

def test_subdir_scan_anchors_artifact_to_project_root(tmp_path):
    _project(tmp_path)
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    out = artifacts.write_scan_artifact(sub, "jsonl", WardlineConfig(), "{}\n")
    assert out.parent == (tmp_path.resolve() / ".wardline")
    assert out.read_text(encoding="utf-8") == "{}\n"

def test_root_scan_unchanged(tmp_path):
    _project(tmp_path)
    out = artifacts.write_scan_artifact(tmp_path, "jsonl", WardlineConfig(), "{}\n")
    assert out.parent == (tmp_path.resolve() / ".wardline")

def test_unfederated_scan_writes_at_scan_path(tmp_path):
    sub = tmp_path / "loose"
    sub.mkdir()
    out = artifacts.write_scan_artifact(sub, "jsonl", WardlineConfig(), "{}\n")
    assert out.parent == (sub.resolve() / ".wardline")

def test_escaping_artifacts_dir_falls_back_under_project_root(tmp_path):
    _project(tmp_path)
    cfg = WardlineConfig(artifacts=__import__("wardline.core.config", fromlist=["ArtifactSettings"]).ArtifactSettings(dir="../../etc"))
    out = artifacts.write_scan_artifact(tmp_path, "jsonl", cfg, "{}\n")
    assert out.parent == (tmp_path.resolve() / ".wardline")
```

(If `WardlineConfig`'s `artifacts` field name differs, read `config.py` `WardlineConfig` and use the real field; the spec/code call it `config.artifacts.dir`.)

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/unit/core/test_artifacts.py -q -k anchor`
Expected: FAIL — artifact lands under the subdir, not the project root.

- [ ] **Step 3: Implement the anchor switch**

In `src/wardline/core/artifacts.py`:

- Add import: `from wardline.core import paths`.
- Change `_artifact_dir`:

```python
def _artifact_dir(root_resolved: Path, config: WardlineConfig) -> Path:
    return paths.artifacts_dir(root_resolved, config.artifacts.dir)
```

- In `timestamped_scan_artifact` and `write_scan_artifact`, compute the project root once and use it as the confinement base everywhere `root_resolved` was passed to `safe_project_path`:

```python
def timestamped_scan_artifact(root: Path, fmt: str, config: WardlineConfig) -> Path:
    project_root = paths.project_root_for(root)
    artifact_dir = _artifact_dir(root, config)
    suffix = artifact_suffix(fmt)
    for candidate in _timestamped_candidates(project_root, artifact_dir, suffix):
        if not candidate.exists():
            return candidate
    raise WardlineError(f"{suffix}: could not allocate a unique scan artifact name")


def write_scan_artifact(root: Path, fmt: str, config: WardlineConfig, content: str) -> Path:
    project_root = paths.project_root_for(root)
    artifact_dir = _artifact_dir(root, config)
    suffix = artifact_suffix(fmt)
    for candidate in _timestamped_candidates(project_root, artifact_dir, suffix):
        try:
            _write_text_exclusive(project_root, candidate, content, label=candidate.name)
        except FileExistsError:
            continue
        prune_scan_artifacts(project_root, candidate, fmt, config.artifacts.retain)
        return candidate
    raise WardlineError(f"{suffix}: could not allocate a unique scan artifact name")
```

Note `_artifact_dir` now takes the scan `root` (it calls `paths.artifacts_dir` which resolves internally), not the pre-resolved scan path. `prune_scan_artifacts(root, ...)` already calls `root.resolve()` internally; passing `project_root` (already resolved) is idempotent and correct.

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/unit/core/test_artifacts.py -q`
Expected: PASS (existing retention/collision tests still pass — pruning still runs in `artifact.parent`).

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/artifacts.py tests/unit/core/test_artifacts.py
git commit -m "feat(artifacts): anchor default scan artifacts to the weft-project root"
```

---

## Task 3: amend the `WLN-ENGINE-NESTED-SCAN-ROOT` message

**Files:**
- Modify: `src/wardline/core/run.py:441-446`
- Test: existing run/scan test (add an assertion) or `tests/unit/core/test_run.py`

**Interfaces:** none new — message-text-only change.

- [ ] **Step 1: Write the failing test**

Add a test that scans a subdir of a marked project and asserts the new message text:

```python
def test_nested_scan_root_message_drops_output_clause(tmp_path):
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    (sub / "m.py").write_text("x = 1\n", encoding="utf-8")
    # Use the same entry point existing run tests use to get findings; assert:
    msgs = [f.message for f in _run_and_collect(sub)]  # adapt to the test module's helper
    nested = [m for m in msgs if "is a subdirectory of the weft project" in m]
    assert nested, "expected the nested-scan-root FACT"
    assert "output defaults under the subdirectory" not in nested[0]
    assert "baseline/waivers/judged state is not loaded" in nested[0]
```

(Adapt `_run_and_collect` to whatever the run-test module already uses to invoke a scan and read `Finding.message`.)

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/unit/core/test_run.py -q -k nested_scan_root_message`
Expected: FAIL — current message still contains "output defaults under the subdirectory".

- [ ] **Step 3: Edit the message in `run.py`**

Change the `message=(...)` block (lines 441-446) to drop the output clause:

```python
                message=(
                    f"scan root '{rel.as_posix()}' is a subdirectory of the weft project at "
                    f"{enclosing}: {qualname_clause}and the project's baseline/waivers/judged "
                    "state is not loaded. Scan the project root for federation-stable results."
                ),
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/unit/core/test_run.py -q -k nested_scan_root`
Expected: PASS. Also run any glossary/vocabulary or golden test that pins this message and update the golden if it asserts the old text: `.venv/bin/pytest -q -k "nested or glossary"`.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/run.py tests/unit/core/test_run.py
git commit -m "fix(run): drop stale 'output defaults under the subdirectory' clause post-anchor"
```

---

## Task 4: end-to-end scan-CLI anchoring tests

**Files:**
- Test: `tests/unit/cli/test_scan_artifacts.py` (create) or extend the existing scan CLI test module.

**Interfaces:** none — integration coverage of Tasks 1-3 through `cli/scan.py`.

- [ ] **Step 1: Write the tests** (use the existing scan-CLI invocation helper / click `CliRunner`)

```python
def test_cli_subdir_scan_writes_artifact_at_project_root(tmp_path, run_scan_cli):
    (tmp_path / "weft.toml").write_text("[wardline]\nsource_roots = [\".\"]\n", encoding="utf-8")
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    (sub / "m.py").write_text("x = 1\n", encoding="utf-8")
    run_scan_cli([str(sub)])  # default output -> artifact written
    artifacts_dir = tmp_path / ".wardline"
    assert any(p.name.endswith("-findings.jsonl") for p in artifacts_dir.iterdir())
    assert not (sub / ".wardline").exists()

def test_cli_explicit_output_unaffected(tmp_path, run_scan_cli):
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    out = tmp_path / "ci" / "findings.jsonl"
    run_scan_cli([str(tmp_path), "--output", str(out)])
    assert out.exists()
    assert not (tmp_path / ".wardline").exists()
```

Add the unfederated-fallback and custom-`artifacts.dir` cases analogously (assert the artifact lands at `<scan-path>/.wardline` and `<root>/out/wl` respectively). For the MCP `scan` no-disk-artifact regression, assert `mcp.server._scan(...)` leaves no `.wardline` under root (the existing MCP scan test module likely already has a fixture).

- [ ] **Step 2: Run to verify** — failures here would indicate Tasks 1-2 wiring gaps; fix in those tasks, not here.

Run: `.venv/bin/pytest tests/unit/cli/test_scan_artifacts.py -q`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/cli/test_scan_artifacts.py
git commit -m "test(scan): pin project-root artifact anchoring end-to-end"
```

---

## Task 5: export the shared walk-skip set

**Files:**
- Modify: `src/wardline/core/discovery.py:16-30`

**Interfaces:**
- Produces: `discovery.WALK_SKIP_DIRS: frozenset[str]` (public alias of `_ALWAYS_SKIP`).

- [ ] **Step 1: Add the public alias** (no behavior change; trivial)

After the `_ALWAYS_SKIP = frozenset({...})` definition add:

```python
# Public alias for reuse by the doctor stray-artifact sweep (single source of the
# hard directory skip-set). Keep in sync with _ALWAYS_SKIP.
WALK_SKIP_DIRS = _ALWAYS_SKIP
```

- [ ] **Step 2: Run + commit**

Run: `.venv/bin/ruff check src/wardline/core/discovery.py && .venv/bin/pytest tests/unit/core/test_discovery.py -q`
Expected: PASS.

```bash
git add src/wardline/core/discovery.py
git commit -m "refactor(discovery): expose WALK_SKIP_DIRS for the doctor sweep"
```

---

## Task 6: `DoctorCheck` gains `removed`/`review` payload fields

**Files:**
- Modify: `src/wardline/install/doctor.py:45-60`
- Test: `tests/unit/install/test_doctor_hygiene.py` (create)

**Interfaces:**
- Produces: `DoctorCheck(id, status, fixed=False, message=None, removed=(), review=())`; `to_dict()` includes `removed`/`review` only when non-empty.

- [ ] **Step 1: Write the failing test**

```python
from wardline.install.doctor import DoctorCheck

def test_doctorcheck_to_dict_includes_payload_when_present():
    c = DoctorCheck("stray_artifacts", "ok", fixed=True, removed=["a/.wardline/x"], review=["findings.jsonl"])
    d = c.to_dict()
    assert d["removed"] == ["a/.wardline/x"]
    assert d["review"] == ["findings.jsonl"]

def test_doctorcheck_to_dict_omits_empty_payload():
    c = DoctorCheck("gitignore", "ok")
    assert "removed" not in c.to_dict() and "review" not in c.to_dict()
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_hygiene.py -q -k doctorcheck`
Expected: FAIL — `DoctorCheck.__init__` rejects `removed`/`review`.

- [ ] **Step 3: Extend the dataclass**

```python
from collections.abc import Sequence

@dataclass(frozen=True, slots=True)
class DoctorCheck:
    id: str
    status: str
    fixed: bool = False
    message: str | None = None
    removed: Sequence[str] = ()
    review: Sequence[str] = ()

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"id": self.id, "status": self.status, "fixed": self.fixed}
        if self.message:
            data["message"] = self.message
        if self.removed:
            data["removed"] = list(self.removed)
        if self.review:
            data["review"] = list(self.review)
        return data
```

- [ ] **Step 4: Run + commit**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_hygiene.py -q -k doctorcheck && .venv/bin/mypy src/wardline/install/doctor.py`
Expected: PASS, clean.

```bash
git add src/wardline/install/doctor.py tests/unit/install/test_doctor_hygiene.py
git commit -m "feat(doctor): DoctorCheck carries removed/review payload lists"
```

---

## Task 7: `_check_gitignore` helper

**Files:**
- Modify: `src/wardline/install/doctor.py` (new helper + imports)
- Test: `tests/unit/install/test_doctor_hygiene.py`

**Interfaces:**
- Consumes: `paths.artifacts_dir`, `paths.project_root_for`, `config.load`, `safe_paths.safe_read_text_if_regular`, `safe_paths.safe_write_text`.
- Produces: `_check_gitignore(proj: Path, *, fix: bool) -> DoctorCheck` (id `"gitignore"`). **Advisory status contract:** success (already-present, or repaired) → `status="ok"` (`fixed=True` when it wrote); a detected-but-unfixed gap in `fix=False` → still `status="ok"` with the gap in `message`; only a write refusal (symlinked `.gitignore`) → `status="error"`. Never returns `"created"`/`"updated"` (see the status-contract note under Step 3).

- [ ] **Step 1: Write the failing tests**

```python
from pathlib import Path
from wardline.install.doctor import _check_gitignore

def _proj(tmp_path: Path) -> Path:
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    return tmp_path

def test_gitignore_created_then_idempotent(tmp_path):
    proj = _proj(tmp_path)
    c1 = _check_gitignore(proj, fix=True)
    assert c1.status == "ok" and c1.fixed is True and "added" in (c1.message or "")  # success => ok (not created/updated)
    body = (proj / ".gitignore").read_text(encoding="utf-8")
    assert ".wardline/" in body and "findings.jsonl" in body
    c2 = _check_gitignore(proj, fix=True)
    assert c2.status == "ok"
    assert (proj / ".gitignore").read_text(encoding="utf-8") == body  # no duplicate append

def test_gitignore_tolerates_existing_bare_entry(tmp_path):
    proj = _proj(tmp_path)
    (proj / ".gitignore").write_text(".wardline\n", encoding="utf-8")  # no slash
    c = _check_gitignore(proj, fix=True)
    body = (proj / ".gitignore").read_text(encoding="utf-8")
    assert body.count(".wardline") == 1 + (1 if "findings.jsonl" not in ".wardline" else 0)  # .wardline not re-added
    assert "findings.jsonl" in body

def test_gitignore_crlf_idempotent(tmp_path):
    proj = _proj(tmp_path)
    (proj / ".gitignore").write_text(".wardline/\r\nfindings.jsonl\r\n", encoding="utf-8")
    c = _check_gitignore(proj, fix=True)
    assert c.status == "ok"  # both already present despite CRLF

def test_gitignore_preserves_existing_content(tmp_path):
    proj = _proj(tmp_path)
    (proj / ".gitignore").write_text("# mine\n*.log\n", encoding="utf-8")
    _check_gitignore(proj, fix=True)
    body = (proj / ".gitignore").read_text(encoding="utf-8")
    assert "*.log" in body and "# mine" in body

def test_gitignore_check_only_no_write(tmp_path):
    proj = _proj(tmp_path)
    c = _check_gitignore(proj, fix=False)
    assert c.status == "ok"                       # advisory — does NOT fail aggregation
    assert "missing" in (c.message or "")         # but the gap is reported
    assert not (proj / ".gitignore").exists()

def test_gitignore_commented_entry_does_not_satisfy(tmp_path):
    proj = _proj(tmp_path)
    (proj / ".gitignore").write_text("#.wardline/\n!findings.jsonl\n", encoding="utf-8")
    c = _check_gitignore(proj, fix=False)
    assert "missing" in (c.message or "")         # commented/negated lines don't count as present

def test_gitignore_symlink_reports_error_not_abort(tmp_path):
    import os
    proj = _proj(tmp_path)
    target = tmp_path.parent / "evil"
    target.write_text("", encoding="utf-8")
    os.symlink(target, proj / ".gitignore")       # untrusted-repo surface
    c = _check_gitignore(proj, fix=True)
    assert c.status == "error" and "symlink" in (c.message or "")
    assert target.read_text(encoding="utf-8") == ""  # never written through the link
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_hygiene.py -q -k gitignore`
Expected: FAIL — `_check_gitignore` undefined.

- [ ] **Step 3: Implement the helper**

Add imports at the top of `install/doctor.py`: `import re`, `from wardline.core import paths`, `from wardline.core.config import ArtifactSettings`. Then:

```python
_GITIGNORE_HEADER = "# Wardline scan artifacts"


def _artifacts_dir_relname(proj: Path) -> str:
    """The project-root-relative dir name to ignore (always in-tree by construction)."""
    try:
        cfg = load(weft_config_path(proj))
        artifacts_dir_value = cfg.artifacts.dir
    except (ConfigError, OSError):
        artifacts_dir_value = ArtifactSettings().dir
    resolved = paths.artifacts_dir(proj, artifacts_dir_value)
    rel = resolved.relative_to(proj.resolve())
    return rel.as_posix()


def _gitignore_present_entries(text: str) -> set[str]:
    out: set[str] = set()
    for raw in text.splitlines():           # handles \n, \r\n, \r
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        out.add(line.rstrip("/"))           # trailing-slash tolerant
    return out


def _check_gitignore(proj: Path, *, fix: bool) -> DoctorCheck:
    gitignore = proj / ".gitignore"
    dir_entry = _artifacts_dir_relname(proj) + "/"
    wanted = [dir_entry, "findings.jsonl"]
    existing = safe_read_text_if_regular(proj, gitignore, label=".gitignore") or ""
    present = _gitignore_present_entries(existing)
    missing = [w for w in wanted if w.rstrip("/") not in present]
    if not missing:
        return DoctorCheck("gitignore", "ok", message="present")
    if not fix:
        # ADVISORY: a missing ignore line must NOT make .ok False — that would flip
        # machine_readable_doctor's all(check.ok) and fail `doctor --fix` / MCP doctor.
        # Status stays "ok"; the gap is surfaced in the message.
        return DoctorCheck("gitignore", "ok", message="missing ignore lines: " + ", ".join(missing) + " (run --repair)")
    block = "\n".join([_GITIGNORE_HEADER, *missing]) + "\n"
    if existing and not existing.endswith("\n"):
        block = "\n" + block  # don't concatenate the header onto a no-newline last line
    try:
        safe_write_text(proj, gitignore, existing + block, label=".gitignore")
    except WardlineError:
        # A symlinked/escaping .gitignore is an untrusted-repo surface (spec §8). Report a
        # single check error rather than letting the raise abort the whole doctor run.
        return DoctorCheck("gitignore", "error", message="refused to write through a symlinked .gitignore")
    return DoctorCheck("gitignore", "ok", fixed=True, message="added " + ", ".join(missing))
```

**Status contract (must-fix from plan review):** these checks are *advisory*. A successful
repair returns `status="ok"` + `fixed=True` (never `"created"`/`"updated"` — `DoctorCheck.ok`
is `status == "ok"`, doctor.py:53, and `machine_readable_doctor` does `all(check.ok)`,
doctor.py:571, so a non-`"ok"` success status makes a clean `doctor --fix`/MCP
`doctor(repair:true)` report `ok:false` and exit 1). A detected-but-unfixed gap also stays
`"ok"` (advisory). The only `"error"` is a genuine write refusal (symlinked `.gitignore`),
caught here instead of propagating. `WardlineError` is already imported at doctor.py:16.

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_hygiene.py -q -k gitignore`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/doctor.py tests/unit/install/test_doctor_hygiene.py
git commit -m "feat(doctor): _check_gitignore — idempotent, CRLF-safe managed block"
```

---

## Task 8: `_sweep_stray_artifacts` helper

**Files:**
- Modify: `src/wardline/install/doctor.py`
- Test: `tests/unit/install/test_doctor_hygiene.py`

**Interfaces:**
- Consumes: `artifacts._managed_artifact_pattern`, `artifacts._is_regular_file_no_follow`, `paths.artifacts_dir`, `paths._has_project_markers`, `discovery.WALK_SKIP_DIRS`, `safe_paths.safe_project_path`.
- Produces: `_sweep_stray_artifacts(proj: Path, *, fix: bool) -> DoctorCheck` (id `"stray_artifacts"`). Deletes managed-pattern files inside non-standard `.wardline/` dirs when `fix=True`; reports unstamped + bare-managed strays as `review`; never mutates when `fix=False`.

- [ ] **Step 1: Write the failing tests**

```python
import os
from pathlib import Path
from wardline.install.doctor import _sweep_stray_artifacts

STAMP = "20260624T111539Z"

def _stray(proj: Path, rel: str) -> Path:
    p = proj / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{}\n", encoding="utf-8")
    return p

def test_sweep_removes_nested_wardline_managed_file(tmp_path):
    proj = _proj(tmp_path)
    stray = _stray(proj, f"src/pkg/.wardline/{STAMP}-findings.jsonl")
    c = _sweep_stray_artifacts(proj, fix=True)
    assert not stray.exists()
    assert not stray.parent.exists()              # emptied .wardline removed
    assert any(str(stray) in r or "src/pkg/.wardline" in r for r in c.removed)

def test_sweep_keeps_standard_dir(tmp_path):
    proj = _proj(tmp_path)
    keep = _stray(proj, f".wardline/{STAMP}-findings.jsonl")
    _sweep_stray_artifacts(proj, fix=True)
    assert keep.exists()                           # standard dir is skipped

def test_sweep_reports_unstamped_and_bare_managed(tmp_path):
    proj = _proj(tmp_path)
    bare = _stray(proj, "findings.jsonl")
    bare_managed = _stray(proj, f"logs/{STAMP}-findings.jsonl")   # managed name, NOT in a .wardline/ dir
    c = _sweep_stray_artifacts(proj, fix=True)
    assert bare.exists() and bare_managed.exists()
    assert any("findings.jsonl" in r for r in c.review)
    assert any(f"{STAMP}-findings.jsonl" in r for r in c.review)

def test_sweep_check_only_no_delete(tmp_path):
    proj = _proj(tmp_path)
    stray = _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    c = _sweep_stray_artifacts(proj, fix=False)
    assert stray.exists()
    assert not c.fixed

def test_sweep_does_not_descend_symlinked_dir(tmp_path):
    proj = _proj(tmp_path)
    outside = tmp_path.parent / "outside_wl"
    (outside / ".wardline").mkdir(parents=True)
    target = outside / ".wardline" / f"{STAMP}-findings.jsonl"
    target.write_text("{}\n", encoding="utf-8")
    os.symlink(outside, proj / "linked")
    _sweep_stray_artifacts(proj, fix=True)
    assert target.exists()                         # never followed out of root

def test_sweep_does_not_unlink_symlinked_managed_file(tmp_path):
    proj = _proj(tmp_path)
    real = tmp_path.parent / "real.jsonl"
    real.write_text("{}\n", encoding="utf-8")
    wd = proj / "src" / ".wardline"
    wd.mkdir(parents=True)
    os.symlink(real, wd / f"{STAMP}-findings.jsonl")
    _sweep_stray_artifacts(proj, fix=True)
    assert real.exists()                           # symlink skipped, target intact

def test_sweep_stops_at_nested_project_root(tmp_path):
    proj = _proj(tmp_path)
    nested = proj / "vendor" / "subproj"
    nested.mkdir(parents=True)
    (nested / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    keep = _stray(proj, f"vendor/subproj/.wardline/{STAMP}-findings.jsonl")
    _sweep_stray_artifacts(proj, fix=True)
    assert keep.exists()                           # nested project's artifacts untouched
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_hygiene.py -q -k sweep`
Expected: FAIL — `_sweep_stray_artifacts` undefined.

- [ ] **Step 3: Implement the sweep**

Add imports: `from wardline.core import artifacts as _artifacts`, `from wardline.core import discovery`, `from wardline.core.paths import _has_project_markers, project_root_for`, `from wardline.core.safe_paths import safe_project_path`. Then:

```python
_MANAGED_SUFFIXES = ("findings.jsonl", "findings.sarif", "findings.agent-summary.json", "scan.legis.json")


def _is_managed_name(name: str) -> bool:
    return any(_artifacts._managed_artifact_pattern(s).match(name) for s in _MANAGED_SUFFIXES)


def _sweep_stray_artifacts(proj: Path, *, fix: bool) -> DoctorCheck:
    proj = proj.resolve()
    standard = paths.artifacts_dir(proj, _artifacts_dir_relname(proj) or ".wardline")
    removed: list[str] = []
    review: list[str] = []
    emptied_dirs: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(proj, followlinks=False):
        here = Path(dirpath)
        # prune: hard-skip set, .git, the standard artifacts dir, and nested project roots
        dirnames[:] = [
            d
            for d in dirnames
            if d not in discovery.WALK_SKIP_DIRS
            and (here / d).resolve() != standard
            and not _has_project_markers(here / d)
        ]
        in_wardline_dir = here.name == ".wardline" and here.resolve() != standard
        for fname in filenames:
            fpath = here / fname
            managed = _is_managed_name(fname)                     # timestamped: 2026...-findings.jsonl
            bare = fname in _MANAGED_SUFFIXES and not managed     # unstamped: findings.jsonl
            if not managed and not bare:
                continue
            rel = str(fpath.relative_to(proj))
            # ONLY a timestamped (managed) file INSIDE a non-standard .wardline/ dir is
            # auto-deletable; bare-managed, or managed outside .wardline/, is REVIEW.
            if not (managed and in_wardline_dir):
                review.append(rel)
                continue
            if not _artifacts._is_regular_file_no_follow(fpath):
                continue                                          # symlink / non-regular -> skip
            if not fix:
                removed.append(rel)                               # would-remove (no unlink)
                continue
            try:
                safe = safe_project_path(proj, fpath, label=fname)
            except WardlineError:
                continue                                          # escaping entry -> skip, keep sweeping
            try:
                safe.unlink()
            except OSError:
                continue
            removed.append(rel)
            emptied_dirs.append(here)
    if fix:
        for d in emptied_dirs:
            try:
                if d.resolve() != standard and not d.is_symlink():
                    d.rmdir()                                     # os.rmdir only; ENOTEMPTY guards
            except OSError:
                pass
    # ADVISORY status (must-fix from plan review): stray artifacts are cleanup items, not a
    # health failure, so status stays "ok" and the sweep never flips machine_readable_doctor's
    # all(check.ok) aggregation (which would fail `doctor --fix` / MCP doctor on success).
    msg = (f"removed {len(removed)}, review {len(review)}" if fix
           else f"{len(removed)} removable, review {len(review)}")
    return DoctorCheck("stray_artifacts", "ok", fixed=bool(fix and removed), message=msg, removed=removed, review=review)
```

(Single walk: `managed` = timestamped name (auto-deletable only inside a non-standard `.wardline/`); `bare` = an unstamped `findings.jsonl`-family name (always REVIEW). The `os.walk(followlinks=False)` plus the `dirnames[:]` prune (hard-skip set + standard-dir + nested-marker) bounds the traversal and never descends a symlinked dir.)

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_hygiene.py -q -k sweep && .venv/bin/mypy src/wardline/install/doctor.py`
Expected: PASS, clean.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/doctor.py tests/unit/install/test_doctor_hygiene.py
git commit -m "feat(doctor): _sweep_stray_artifacts — confined, no-follow, nested-root-aware"
```

---

## Task 9: wire the two checks into doctor + fix the scan hint

**Files:**
- Modify: `src/wardline/install/doctor.py` (`machine_readable_doctor`)
- Modify: `src/wardline/cli/doctor.py` (both render branches)
- Modify: `src/wardline/cli/scan.py:238-240`
- Test: `tests/unit/install/test_doctor_hygiene.py`, `tests/unit/cli/test_doctor.py`

**Interfaces:**
- Consumes: `_check_gitignore`, `_sweep_stray_artifacts`, `paths.project_root_for`.

- [ ] **Step 1: Write the failing tests**

```python
from wardline.install.doctor import machine_readable_doctor

def test_machine_readable_includes_new_checks(tmp_path):
    proj = _proj(tmp_path)
    _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    payload = machine_readable_doctor(proj, fix=True)
    ids = {c["id"] for c in payload["checks"]}
    assert {"gitignore", "stray_artifacts"} <= ids

def test_successful_repair_new_checks_report_ok(tmp_path):
    # Must-fix (plan review): a SUCCESSFUL repair must return status "ok" so it does not
    # flip machine_readable_doctor's all(check.ok) aggregation and make `doctor --fix` /
    # MCP doctor exit 1 on success. (Asserting payload["ok"] is True would be wrong here —
    # other checks fail on a bare project — so pin the two new checks specifically.)
    proj = _proj(tmp_path)
    _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    by_id = {c["id"]: c for c in machine_readable_doctor(proj, fix=True)["checks"]}
    assert by_id["gitignore"]["status"] == "ok" and by_id["gitignore"]["fixed"] is True
    assert by_id["stray_artifacts"]["status"] == "ok"

def test_check_only_does_not_mutate(tmp_path):
    proj = _proj(tmp_path)
    stray = _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    payload = machine_readable_doctor(proj, fix=False)
    assert stray.exists()                           # no delete
    assert not (proj / ".gitignore").exists()       # no write
    sweep = next(c for c in payload["checks"] if c["id"] == "stray_artifacts")
    assert sweep["fixed"] is False

def test_subdir_root_climbs_to_project(tmp_path):
    proj = _proj(tmp_path)
    sub = proj / "src" / "pkg"
    sub.mkdir(parents=True)
    stray = _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    machine_readable_doctor(sub, fix=True)          # invoked at the SUBDIR
    assert (proj / ".gitignore").exists()           # gitignore written at the PROJECT root
    assert not stray.exists()                       # swept at the project root
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_hygiene.py -q -k "machine_readable or check_only or climbs"`
Expected: FAIL — new checks absent.

- [ ] **Step 3: Wire into `machine_readable_doctor`**

In `install/doctor.py`, after `config_missing_before = ...` (line 530) and **before** the `if fix:` block, snapshot the project root:

```python
    proj = project_root_for(root)  # snapshot BEFORE repair_install plants weft.toml at literal root
```

Then after the existing `checks.append(_check_filigree_auth(...))` (line 567) append:

```python
    checks.append(_check_gitignore(proj, fix=fix))
    checks.append(_sweep_stray_artifacts(proj, fix=fix))
```

- [ ] **Step 4: Wire into `cli/doctor.py` both branches**

In the `--repair` branch (after the `filigree.auth` line ~66), compute `proj` **before** `repair_install` (top of the branch) and render:

```python
        proj = project_root_for(root)   # project_root_for imported at module top
        # ... existing repair_install + after/config/filigree rendering ...
        gi = _check_gitignore(proj, fix=True)
        click.echo(f"  gitignore: {gi.status}" + (f" ({gi.message})" if gi.message else ""))
        sw = _sweep_stray_artifacts(proj, fix=True)
        click.echo(f"  stray artifacts: removed {len(sw.removed)}, review {len(sw.review)}")
        for r in sw.review:
            click.echo(f"    REVIEW   {r}  (unstamped/bare — remove by hand if it's a stray scan)")
```

In the check-only branch (after the `filigree.auth` line ~82):

```python
        proj = project_root_for(root)
        gi = _check_gitignore(proj, fix=False)
        # gi.status is advisory-"ok" even with a gap, so render on the message, not gi.ok.
        if gi.status == "error" or "missing" in (gi.message or ""):
            click.echo(f"  gitignore: {gi.message}")
        sw = _sweep_stray_artifacts(proj, fix=False)
        if sw.removed or sw.review:
            click.echo(f"  stray artifacts: {sw.message}")
```

Add `_check_gitignore`, `_sweep_stray_artifacts` to `cli/doctor.py`'s `from wardline.install.doctor import (...)` block, and `from wardline.core.paths import project_root_for` to its module-top imports (do NOT use function-local imports — see Task 9 Step 5 note). Because the two checks are advisory (status stays `"ok"` except on a symlink write-refusal), they do **not** enter the branch's `ok`/`SystemExit` accounting: a missing gitignore line or a present stray must NOT make `wardline doctor` exit 1. Leave the existing `all(check.ok for check in ...)` accounting untouched (gitignore/stray are rendered for information only); add a test asserting `wardline doctor` (check-only) exits 0 when the only "gap" is a missing gitignore line + a stray present.

- [ ] **Step 5: Fix the scan hint AND the stale docstring** (`cli/scan.py`)

(a) Add `project_root_for` to `cli/scan.py`'s existing `from wardline.core.paths import ...` block (it already imports `weft_config_path`). Replace the hint (lines 238-240) so it points at the project root, not the scanned subdir:

```python
            proj = project_root_for(path)
            click.echo(
                "warning: no weft.toml found; using built-in source_roots=['.'], which can make "
                "project-root scans broad and slow. Run `wardline doctor --repair --root "
                f"{proj}` to create a bounded default policy, or `wardline scan-job start {path}` "
                "for a pollable long-running scan.",
                err=True,
            )
```

(b) **Fix the stale `scan()` docstring** (lines 216-220, should-fix from plan review). It still
says a subdirectory scan "writes output into the subdirectory (wardline warns when it detects
this)" — false after Part 1 (output now lands at the project root). Change the tail of that
sentence:

```python
    root — a subdirectory scan mints qualnames other Weft tools
    (Loomweave/Filigree/dossier) will not match and misses the project's
    suppression state (wardline warns when it detects this). The default
    findings artifact still lands in the project root's .wardline/.
```

- [ ] **Step 6: Run tests**

Run: `.venv/bin/pytest tests/unit/install/test_doctor_hygiene.py tests/unit/cli/test_doctor.py -q && .venv/bin/pytest -q -k doctor`
Expected: PASS. Fix any existing doctor test that asserts the exact human-output line set (the new `gitignore`/`stray artifacts` lines are additive).

- [ ] **Step 7: Commit**

```bash
git add src/wardline/install/doctor.py src/wardline/cli/doctor.py src/wardline/cli/scan.py tests/
git commit -m "feat(doctor): wire gitignore+sweep into doctor; anchor to project_root_for; fix scan hint"
```

---

## Task 10: MCP `doctor` tool — honest destructive hint + confinement regression

**Files:**
- Modify: `src/wardline/mcp/server.py:4114-4148` (`_DOCTOR_TOOL`)
- Test: `tests/unit/install/test_doctor_hygiene.py` (MCP-surface path), `tests/unit/mcp/test_server*.py`

**Interfaces:** none new — the MCP `doctor` handler already routes through `machine_readable_doctor(fix=repair)` (server.py:4008), so the sweep is reachable once Task 9 lands. This task only makes the advertisement honest and pins confinement.

- [ ] **Step 1: Write the failing tests**

```python
from wardline.mcp.server import _DOCTOR_TOOL
from wardline.install.doctor import machine_readable_doctor

def test_doctor_tool_advertises_destructive():
    assert _DOCTOR_TOOL["annotations"]["destructiveHint"] is True

def test_mcp_path_deletes_confined_managed_only(tmp_path):
    proj = _proj(tmp_path)
    inside = _stray(proj, f"src/.wardline/{STAMP}-findings.jsonl")
    bare = _stray(proj, "findings.jsonl")
    # symlinked managed file -> must survive
    import os
    real = tmp_path.parent / "real.jsonl"; real.write_text("x", encoding="utf-8")
    wd = proj / "lib" / ".wardline"; wd.mkdir(parents=True)
    os.symlink(real, wd / f"{STAMP}-findings.jsonl")
    machine_readable_doctor(proj, fix=True)         # same builder the MCP _doctor handler calls
    assert not inside.exists()                       # managed-in-.wardline deleted
    assert bare.exists()                             # unstamped -> REVIEW, kept
    assert real.exists()                             # symlink target intact
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest -q -k "destructive or confined"`
Expected: FAIL — `destructiveHint` still `False`.

- [ ] **Step 3: Flip the hint + note deletion**

In `server.py` `_DOCTOR_TOOL`:
- Line 4145 `"destructiveHint": False,` → `"destructiveHint": True,`.
- Extend the tool `description` (ends ~line 4122) to add: `" With repair: true it also deletes stray wardline-managed scan artifacts (timestamped files inside .wardline/ dirs) under the project root."`
- Extend the `repair` property `description` (ends ~line 4131) similarly: `" Also sweeps stray managed scan artifacts under the project root."`

Leave `idempotentHint: True` (the sweep converges — a second run deletes nothing new).

- [ ] **Step 4: Run + commit**

Run: `.venv/bin/pytest -q -k "doctor or destructive or confined" && .venv/bin/pytest tests/unit/mcp -q`
Expected: PASS. Update any MCP golden/schema test that snapshots the doctor tool annotations.

```bash
git add src/wardline/mcp/server.py tests/
git commit -m "feat(mcp): doctor repair:true deletes strays; advertise destructiveHint: True"
```

---

## Task 11: docs + CHANGELOG

**Files:**
- Modify: `docs/getting-started.md`, `docs/guides/configuration.md`, `docs/guides/agents.md`, `CHANGELOG.md`

**Interfaces:** none.

- [ ] **Step 1: Update docs** — in each guide where artifacts/output are described, state: the default findings artifact lands in `‹project-root›/.wardline/`, anchored to the `weft.toml` directory, independent of where `wardline scan` is invoked; a subdir scan is still flagged `WLN-ENGINE-NESTED-SCAN-ROOT`; `wardline doctor --repair` (CLI and MCP `doctor` `repair:true`) sets up `.gitignore` and deletes stray managed artifacts under the project root.

- [ ] **Step 2: CHANGELOG `[Unreleased]`**

```markdown
### Changed
- Default scan artifacts now anchor to the weft-project root (the `weft.toml` directory)
  rather than the scan cwd, so a subdirectory scan writes to `‹project-root›/.wardline/`.
  Retention is therefore project-root-wide across heterogeneous subdir/root scans sharing
  one `.wardline/`. **Migration:** the artifact moves to the project root; `wardline doctor
  --repair` sweeps now-stale per-subdir `.wardline/` dirs — update any CI/automation reading
  a hardcoded `‹subdir›/.wardline/*-findings.jsonl` path.

### Added
- `wardline doctor --repair` gitignores the artifacts dir and sweeps stray managed
  artifacts; deletion is available on both the CLI and the MCP `doctor` tool (`repair:true`,
  advertised `destructiveHint: True`), bounded to managed-pattern files inside `.wardline/`
  dirs under the project root.
```

- [ ] **Step 3: Build docs (if a docs check exists) + commit**

Run: `.venv/bin/pytest -q -k "glossary or docs"` (whatever pins doc/vocab consistency).

```bash
git add docs/ CHANGELOG.md
git commit -m "docs: project-root-anchored artifacts + doctor hygiene"
```

---

## Final verification

- [ ] **Full suite + lint + type**

Run: `.venv/bin/pytest -q && .venv/bin/ruff check . && .venv/bin/mypy src`
Expected: all green, clean. Investigate and fix any red — no "pre-existing" excuses.

- [ ] **Manual smoke (optional)**

```bash
mkdir -p /tmp/wl-demo/src/pkg && cd /tmp/wl-demo && printf '[wardline]\nsource_roots=["."]\n' > weft.toml && printf 'x=1\n' > src/pkg/m.py
.venv/bin/wardline scan src/pkg ; ls -la .wardline/ ; ls -la src/pkg/.wardline 2>/dev/null || echo "no subdir .wardline (correct)"
.venv/bin/wardline doctor --repair --root . ; cat .gitignore
```

---

## Spec-coverage self-check (run before handing off)

| Spec requirement | Task |
|---|---|
| `project_root_for` / `artifacts_dir` (§3.1) + import-cycle resolution | 1 |
| artifacts anchored to project root (§3.2) | 2 |
| retention project-root-wide (documented) (§3.2) | 2 (test), 11 (doc) |
| WLN-ENGINE message amendment (§3.3) | 3 |
| subdir/root/unfederated/escape/--output/MCP-no-artifact (§6 1-7) | 2, 4 |
| `project_root_for`/`artifacts_dir` unit matrix (§6 #8) | 1 |
| `WALK_SKIP_DIRS` export (§4.2) | 5 |
| `DoctorCheck` removed/review (§4.3) | 6 |
| `_check_gitignore` idempotent/CRLF/never-clobber/commented (§4.1, §6 #9-10,17) | 7, 9 |
| `_sweep_stray_artifacts` confined/narrowed/nested-stop/symlink/rmdir (§4.2, §6 #12-16) | 8 |
| wire both checks + proj snapshot + scan hint (§4 intro, §4.3, must-fix #1) | 9 |
| MCP delete + destructiveHint True + confinement (§4.2, §6 #18, §8) | 10 |
| docs + CHANGELOG (§7) | 11 |
| self-describe artifacts | DEFERRED (§9) — not in this plan |
