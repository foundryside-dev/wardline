# Wardline project-root-anchored scan artifacts + doctor hygiene (design)

**Date:** 2026-06-25
**Status:** Design — implementation-ready. The agent executing it may produce its own
TDD plan (writing-plans) from this.
**Gate:** none — fully autonomous, Wardline-repo-only. No sibling dependency.
**Revision:** v2 — incorporates the 2026-06-25 adversarial panel review (7 lenses,
groups of 4, adversarial verification + synthesis). Verdict was *approve-with-changes*;
the two confirmed-HIGH blockers (doctor/artifact root divergence; MCP-reachable
destructive sweep) and the grounded medium fixes are folded in below. One downgraded
finding (artifact path self-description) is deferred to §9 backlog by scope discipline.

> **Why.** The configurable-scan-artifacts feature (`005be60d`, 2026-06-20) writes the
> default findings artifact to `‹scan-root›/.wardline/‹timestamp›-findings.‹ext›`, where
> the scan root is *whatever PATH you point `wardline scan` at*. So the artifact location
> follows the caller's cwd: scan a subdirectory and the `.wardline/` lands deep in the
> tree (observed live in `~/esper-lite`:
> `src/esper/simic/training/.wardline/20260624T111539Z-findings.jsonl`, carrying
> wardline's own `WLN-ENGINE-NESTED-SCAN-ROOT` self-diagnostic). Findings files end up in
> "weird locations." This spec makes scan artifacts land in **one standard, config-defined
> location anchored to the weft-project root**, regardless of where the scan is invoked —
> and makes `wardline doctor --repair` set that up and clean up the existing mess.

---

## 1. Scope & definition of done

**In scope (two parts):**

1. **Anchor scan artifacts to the weft-project root.** The default artifact directory
   (`config.artifacts.dir`, default `.wardline`) resolves against the **project root**
   (the directory carrying `weft.toml` / `.weft/wardline/`), not the scan PATH. A
   subdirectory scan writes to `‹project-root›/.wardline/…`, the same place a root scan
   does.
2. **`wardline doctor --repair` hygiene.** Two new repair actions: (a) ensure the
   project `.gitignore` ignores the artifacts dir + legacy `findings.jsonl`; (b) sweep
   wardline-**managed** stray artifacts out of the tree and report unstamped strays for
   manual review. The check-only `wardline doctor` reports the same gaps without acting.
   Both actions **anchor to the same project root Part 1 writes to** (§4 intro). The
   destructive delete is reachable from **both** the CLI and the MCP `doctor` tool
   (`repair:true`); its blast radius is bounded by confinement + the narrowed authorship
   heuristic (delete only managed-pattern files inside a `.wardline/` dir, under root,
   no-follow), and the MCP `doctor` tool's `destructiveHint` is flipped to `True` to
   advertise it honestly (§4.2 / §8).

**Definition of done:**

- `wardline scan ‹subdir›` writes its artifact to `‹project-root›/.wardline/…`; the
  `WLN-ENGINE-NESTED-SCAN-ROOT` warning still fires (with its message clause corrected,
  §3.3).
- `wardline scan .` at a true project root is unchanged (artifact at `‹root›/.wardline/`).
- A scan of an unfederated tree (no `weft.toml`/`.weft/wardline/` anywhere up the chain)
  still writes `.wardline/` at the scan path (today's behavior preserved).
- An escaping `artifacts.dir` (absolute-elsewhere or `..`-escape) silently falls back to
  the default `.wardline` under the project root — no write-redirect, no exit-2 DoS.
- `wardline doctor --repair` (CLI) adds the gitignore block (idempotently), deletes
  managed stray artifacts, leaves+reports unstamped strays, and emits this in both human
  and `--fix` JSON output. The two new actions target `project_root_for(root)`, the same
  dir Part 1 writes to (§4 intro).
- The MCP `doctor` tool with `repair:true` performs the **same** gitignore-ensure +
  stray-delete the CLI does, confined under the (possibly untrusted) server root by the
  managed-pattern + `.wardline/`-dir + no-follow guards; its `destructiveHint` is `True`
  (§8). An MCP-surface regression pins the confinement (§6 test #18).
- Full suite green; ruff/mypy clean; base stays zero-dep.

**Explicitly NOT in scope (YAGNI):**

- No new config key. `artifacts.dir` / `artifacts.retain` keep their meaning; only the
  *anchor* of `artifacts.dir` changes.
- No relocation of the artifact convention into `.weft/wardline/` (considered and
  rejected — keep the shipped, discoverable top-level `.wardline/`).
- No change to explicit `--output` (CI's out-of-tree sink), to the MCP `scan` tool
  (returns findings inline, writes no disk artifact), or to `scan-job` (which has its own
  `_write_scan_artifact` anchored to the job dir under the MCP `--root` — it does not call
  the function this spec changes).
- No change to where the **existing** doctor install artifacts (`CLAUDE.md`, `.mcp.json`,
  `weft.toml`, skills, state dir) are written: they keep anchoring to the literal `--root`.
  Only the two **new** hygiene actions adopt `project_root_for(root)` (§4 intro). The
  recommended invocation is at the project root, where the two roots coincide.
- doctor does **not** auto-delete unstamped files (e.g. a hand-created or
  unknown-provenance `findings.jsonl`); it reports them. It also does **not** auto-delete
  managed-pattern files sitting *outside* a `.wardline/`-named directory — those are
  report-only too (§4.2, narrowed authorship).
- No artifact-content self-description (a `scan_root` key / SARIF `uriBaseId`) in this
  spec — deferred to §9 backlog.

---

## 2. Background: how the location is decided today

`src/wardline/cli/scan.py` (default-output branches) calls
`write_scan_artifact(path, fmt, cfg, content)` where `path` is the `wardline scan` PATH
argument (default `.`). In `src/wardline/core/artifacts.py`:

```python
def write_scan_artifact(root, fmt, config, content):
    root_resolved = root.resolve()                       # = the SCAN path
    artifact_dir = _artifact_dir(root_resolved, config)  # root_resolved / config.artifacts.dir
    ...

def _artifact_dir(root_resolved, config):
    return safe_project_path(root_resolved, Path(config.artifacts.dir), label="wardline scan artifacts")
```

So the artifact dir is `‹scan-path›/‹artifacts.dir›` and `safe_project_path` confines it
**under the scan path**. Point the scan at a subdir → the artifact dir is under that
subdir.

**Wardline already solved this for its state.** `src/wardline/core/paths.py`
`weft_state_dir(root)` anchors `.weft/wardline/` (baseline/waivers/judged) to the
project root, honors a `[wardline].store_dir` override, and **confines** the override
under root (relative → under root; absolute → only if inside root; escape → default).
`enclosing_project_root(scan_path)` already walks up to find the project root and is what
powers the nested-scan-root warning. We reuse both. Scan artifacts are the lone on-disk
surface that escaped this convention; Part 1 brings them into line.

---

## 3. Part 1 — anchor artifacts to the project root

### 3.1 New helpers in `core/paths.py`

`paths.py` is the declared single source of truth for on-disk locations; both helpers
belong there next to `weft_state_dir`.

```python
DEFAULT_ARTIFACT_DIR = ".wardline"   # owned here (single source of truth); re-exported by config.py


def project_root_for(scan_path: Path) -> Path:
    """The weft-project root governing a scan of *scan_path*.

    enclosing_project_root() returns the nearest STRICT ancestor carrying project
    markers, or None when scan_path itself is a root OR no ancestor is one. In both
    None cases the governing root is scan_path itself:
      * scan_path has markers          -> it IS the root
      * scan_path is a project subdir  -> the enclosing root
      * no markers anywhere            -> fall back to scan_path (unfederated tree)
    Always returns a fully-resolved path: enclosing_project_root resolves internally
    and returns resolved ancestors; the fallback resolves scan_path.
    """
    return enclosing_project_root(scan_path) or scan_path.resolve()


def artifacts_dir(scan_path: Path, artifacts_dir_value: str) -> Path:
    """Resolved scan-artifact directory, anchored to project_root_for(scan_path).

    Mirrors weft_state_dir's confinement EXACTLY: artifacts_dir_value (default
    ".wardline") resolves under the project root; an absolute value is honored only
    if it lands inside the project root; any value resolving OUTSIDE (absolute
    elsewhere, or a `..` escape) is ignored and the default ".wardline" under the
    project root is used. weft.toml is untrusted input when scanning an untrusted
    repo, so this denies a malicious artifacts.dir both a write-redirect primitive
    and an exit-2 DoS."""
    project_root = project_root_for(scan_path)            # already fully resolved
    default = project_root / DEFAULT_ARTIFACT_DIR
    candidate = Path(artifacts_dir_value)
    resolved = (candidate if candidate.is_absolute() else project_root / candidate).resolve()
    try:
        resolved.relative_to(project_root)                # project_root is resolved; no re-resolve needed
    except ValueError:
        return default
    return resolved
```

**`DEFAULT_ARTIFACT_DIR` ownership (resolved — panel finding).** Define
`DEFAULT_ARTIFACT_DIR = ".wardline"` in `paths.py` (its single-source-of-truth role) and
re-export from `config.py` via `from wardline.core.paths import DEFAULT_ARTIFACT_DIR`.
The reverse (paths.py importing the constant from config.py) is a **real import cycle**:
`config.py` already imports from `paths.py` at module top, and `DEFAULT_ARTIFACT_DIR` is
defined *after* that import, so a top-level back-import fails with `ImportError` on a
partially-initialized module. Do not present the directions as equivalent; only the
paths.py-owns / config.py-re-exports direction is correct. (`DEFAULT_ARTIFACT_RETAIN`
stays in `config.py`; it is not referenced from `paths.py`.)

### 3.2 `core/artifacts.py` uses the project-root anchor

Replace the scan-root anchor with the project-root anchor and thread the project root as
the confinement base through every `safe_project_path` call:

- `_artifact_dir(root, config)` → resolve via `paths.artifacts_dir(root, config.artifacts.dir)`.
- `timestamped_scan_artifact` / `write_scan_artifact`: compute
  `project_root = paths.project_root_for(root)` once; pass `project_root` (not
  `root.resolve()`) as the confinement base to `_timestamped_candidates`,
  `prune_scan_artifacts`, and `_write_text_exclusive`.
- `prune_scan_artifacts(root, artifact, fmt, retain)`: its `safe_project_path(...)`
  guard base becomes the project root. Pruning still operates within
  `artifact.parent` (the resolved artifact dir), so per-directory retention mechanics are
  unchanged — it just runs in the right directory.

Public signatures of `write_scan_artifact` / `timestamped_scan_artifact` stay the same
(they still take the scan `root`); only the internal anchor changes. The `cli/scan.py`
call sites are untouched.

**Retention is now project-root-WIDE (panel finding — document, do not redesign).** Two
scans of two *different* subdirectories of one project now both write into and prune the
single `‹project-root›/.wardline/` pool. `prune_scan_artifacts` matches by suffix +
timestamp pattern only and cannot distinguish which scan produced a given artifact, so
retention is applied to the merged population, not per-origin. This is benign — no data
loss, and the `-NNN` collision counter (`artifacts.py`
`_timestamped_candidates`) already disambiguates same-second writes — but it is a real
change from the old per-subdir pools. The previous "retention unchanged" framing is true
*per directory* and false for the merged pool; state the project-wide behavior in
CHANGELOG/docs (§7). Per-origin partitioning is explicitly NOT pursued (YAGNI).

### 3.3 What does NOT change (and the one message that must)

- `config.artifacts.dir` default (`.wardline`) and `artifacts.retain` default (`20`),
  and `core/config_schema.py`. No new keys.
- The `WLN-ENGINE-NESTED-SCAN-ROOT` engine finding stays (a subdirectory scan is still
  wrong for identity/suppression reasons; anchoring the artifact does not make it
  correct) — **but its message text must be amended.** `core/run.py:441-446` currently
  ends `"…the project's baseline/waivers/judged state is not loaded, and output defaults
  under the subdirectory. Scan the project root for federation-stable results."` After
  Part 1 the **"output defaults under the subdirectory" clause is false** — output now
  defaults under the *project* root. Drop that clause; keep the real hazard (qualnames
  mis-minted relative to the subdir; project suppression state not loaded). New tail:
  `"…the project's baseline/waivers/judged state is not loaded. Scan the project root
  for federation-stable results."` This is the lone engine-message edit and must be
  listed in the implementation plan.
- Explicit `--output PATH` (all formats): writes verbatim to the chosen path via the
  no-follow sinks, exactly as today. This is CI's out-of-tree path
  (`--output "$RUNNER_TEMP/…"`).
- MCP `scan` (`mcp/server.py` `_scan`): returns findings inline, writes no disk
  artifact — unchanged. `scan-job` (`core/scan_jobs.py`) uses its own
  `_write_scan_artifact`, anchored to `job_dir(root, job_id)` under the MCP `--root`
  (not `artifacts.write_scan_artifact`), so it is unaffected. The only callers of
  `artifacts.write_scan_artifact` are the four default-output branches in `cli/scan.py`.

---

## 4. Part 2 — `wardline doctor --repair` hygiene

Both actions are **new `DoctorCheck`-returning helpers** in `install/doctor.py`,
appended to `machine_readable_doctor`'s `checks` list (after the existing `_check_*`
appends), exactly as `_check_config` is wired — **§4.3 is authoritative** on plumbing.
Two clarifications the panel forced, because the prior draft was ambiguous:

- **`repair_install`'s `dict[str, str]` return is NOT the home for these statuses.**
  `machine_readable_doctor` calls `repair_install(root)` purely for side effects and
  *discards its return value*; statuses placed there never reach the JSON `checks` array.
  Leave `repair_install`'s contract untouched.
- **`check_install` is NOT the check-only reporter for these.** It returns
  `list[CheckResult]` (`name/ok/message` — a different dataclass with no `fixed`/`removed`/
  `review` slot) and powers the read-only `before` snapshot plus the plain
  `wardline doctor` path; folding mutating logic there would mutate from read-only call
  sites. The new checks live on the `DoctorCheck` path only.

Both new helpers take a `fix: bool` and perform **zero filesystem mutation when
`fix=False`** (gitignore: report would-add lines; sweep: report would-remove /
would-review, no `unlink`). When `fix=True` the sweep deletes — on **both** the CLI and
the MCP `doctor` tool (`repair:true`), which route through the same
`machine_readable_doctor(root, fix=repair)` → `repair_install` path. The decision (your
call, 2026-06-25) is to allow MCP-triggered deletion rather than gate it CLI-only: an
agent operating the project should be able to clear stray artifacts, consistent with the
MCP-primary / "agents operate and extend" posture. Safety is carried by *bounding the
action*, not by hiding it from the agent surface — confinement under `proj`, the narrowed
authorship heuristic (§4.2), and no-follow — plus flipping the MCP `doctor` tool's
`destructiveHint` to `True` so the now-destructive op is advertised honestly. The MCP
`doctor` tool **must be added to §1 scope** (it was previously silent) and its deletion
reach justified under §8's untrusted-`weft.toml` threat model; a §6 regression (test #18)
drives the sweep through `machine_readable_doctor(fix=True)` and asserts confinement.

**Root reconciliation (must-fix #1).** The prior draft said the actions "hook into
`repair_install(root)`", which resolves `root` **literally** — but Part 1 writes the
artifact to `project_root_for(scan_path)`. For the headline subdir-scan case these
differ, and `cli/scan.py:238` even steers the subdir scanner to
`wardline doctor --repair --root ‹subdir›`, so the repair would gitignore/sweep the
*subdir* and never touch the `‹project-root›/.wardline/` that Part 1 actually populated.
Resolution: **the two new helpers compute `proj = paths.project_root_for(root)` and do
all of their work — config read for `artifacts.dir`, gitignore write, and the sweep
walk — against `proj`.** They are the same dir Part 1 writes to. The existing install
checks keep their literal-`--root` anchoring (out of scope, §1). Also **fix the
`cli/scan.py:238` hint** to recommend running doctor at the project root (e.g. drop the
`--root ‹subdir›` suffix, or point it at the enclosing project root) so the steered
invocation lands on the right tree.

**Snapshot `proj` BEFORE `repair_install` runs (ordering hazard).** `machine_readable_doctor`
computes `config_missing_before` and then, under `fix=True`, calls `repair_install(root)`
*before* the `checks` list is built — and `repair_install` → `_ensure_weft_config(root)`
plants a `weft.toml` at the **literal** `root` when absent. If the new helpers computed
`proj` *after* that, a fresh-subdir invocation (`doctor --repair --root ‹fresh-subdir›`
inside a federated project) would see the just-planted subdir `weft.toml`, so
`project_root_for(subdir)` would return the **subdir** (now a marker-carrying root) and
the climb to the enclosing project is defeated — and a nested `weft.toml` is left behind.
Compute `proj = paths.project_root_for(root)` once, alongside `config_missing_before`
(i.e. before the `if fix:` block), and thread that snapshot into both new helpers. After
the `scan.py:238` hint fix the steered invocation is already at the project root where
this never bites, but the snapshot makes the off-path manual invocation correct too.

### 4.1 `.gitignore` hygiene — `_check_gitignore(proj, *, fix)`

Ensure the project `.gitignore` ignores the **configured** artifacts dir (default
`.wardline/`) and the legacy top-level `findings.jsonl`.

- **Ignore target = the Part 1 resolver's output.** Compute the dir with the *same*
  `paths.artifacts_dir(proj, config.artifacts.dir)` resolver Part 1 uses, then gitignore
  its **project-root-relative** path (always in-tree by construction). This deletes the
  prior draft's "if the configured dir is absolute/outside root, ignore only
  `findings.jsonl`, note out-of-tree" branch: that branch was **unreachable and wrong** —
  Part 1's confinement makes an escaping `artifacts.dir` fall back to `‹proj›/.wardline`,
  so the dir that actually receives artifacts is always in-tree and must be the one
  ignored. Ignoring only `findings.jsonl` there would leave the real artifact dir
  un-ignored and committable — exactly the misconfigured-weft.toml case we must not leak.
- Append a managed block under a `# Wardline scan artifacts` comment, adding only the
  lines not already present (idempotent — running `--repair` twice adds nothing the
  second time). Match existing lines by exact normalized entry (`.wardline/`,
  `findings.jsonl`), tolerant of an existing trailing-slash/no-slash variant.
- **Idempotence must be CRLF- and edge-case-safe** (panel finding — the DoD says a
  second `--repair` is a no-op): split existing content with `str.splitlines()` (handles
  `\n`, `\r\n`, `\r`); `.strip()` each line before the normalized compare (so a
  `.wardline/\r` entry on a CRLF file still matches and is not re-appended); write the new
  block with explicit `\n` joins (LF is canonical for git-consumed files); if the
  existing file does not end in a newline, prepend one before the block so the comment
  header does not concatenate onto the last entry; and **exclude comment (`#`) and
  negation (`!`) lines from the already-present set** so a commented-out or `!.wardline/`
  line does not falsely satisfy the check.
- Never clobber existing content: read existing `.gitignore` (safe no-follow read),
  append, write atomically. **Prefer reusing the established `install/block.py`
  `inject_block` managed-block idiom** (used by `repair_install` today) — it gives atomic
  write (tempfile + `os.replace`) and foreign-block safety for free. If a `.gitignore`
  needs line-based rather than fenced-marker semantics and `inject_block` does not fit,
  use `safe_write_text` but preserve the same atomic-write + never-clobber properties and
  say so in the plan. Create `.gitignore` if absent.
- Runs on **both** CLI and MCP `fix=True` (an idempotent, in-root write of the project's
  own `.gitignore` is benign, same class as the existing `inject_block` CLAUDE.md write).
- Status: `created` / `updated` / `ok` (already present). Reported as a `gitignore`
  check (a `DoctorCheck`).

### 4.2 Stray-artifact sweep — `_sweep_stray_artifacts(proj, *, fix)`

Find wardline-**managed** artifacts sitting outside the standard dir and remove them (on
both the CLI and the MCP `doctor` tool when `fix=True`); report unstamped and
out-of-`.wardline` strays. No surface gate — deletion is bounded by the guards below, not
hidden from the agent surface (the 2026-06-25 "MCP can delete too" decision).

- **Managed pattern:** reuse `artifacts._managed_artifact_pattern(suffix)` across all
  four known suffixes (`findings.jsonl`, `findings.sarif`, `findings.agent-summary.json`,
  `scan.legis.json`): `^\d{8}T\d{6}Z(-\d{3})?-‹suffix›$`.
- **Narrowed authorship (panel finding — closes the data-loss channel).** A
  timestamp-pattern *name* is a heuristic, not proof of wardline authorship. **Auto-delete
  a managed-pattern file ONLY when it sits inside a `.wardline/`-named directory** (the
  observed mess: `‹subdir›/.wardline/‹stamp›-findings.jsonl`). A managed-pattern file
  sitting *bare* in an arbitrary tree location is treated as **REVIEW** (report-only),
  exactly like an unstamped file. State plainly in the code/docs that the name match is a
  heuristic. This narrowing is what makes the destructive action safe enough to exist.
- **Walk discipline — do NOT reuse `discover()`'s scoping** (panel finding). `discover()`
  walks `config.source_roots` (default `('src',)`), not the project root, and applies
  `config.exclude` as a *post-walk* `fnmatch` filter (default `()`), so "honor
  `config.exclude` like discover()" would both (a) miss strays outside `src/` and (b)
  give zero walk-pruning on a default-config repo (walk-DoS into `node_modules`/`.venv`).
  Instead: walk the **whole** `proj` with `os.walk(..., followlinks=False)`; prune
  directories via a shared hard-skip set (**export `core/discovery`'s `_ALWAYS_SKIP` as a
  public constant** and reference it) plus the root `.gitignore` matcher; always skip
  `.git/` and the resolved standard artifacts dir; treat `config.exclude` as an optional
  *post-match* filter only (a stray can legitimately sit under an excluded/non-source
  path, so excludes must not be a hard walk bound). `config.exclude` is read from `proj`'s
  weft.toml.
- **Stop at nested project roots (panel finding — hazard created by must-fix #1).** Since
  the sweep now walks from `project_root_for(root)`, it can reach a vendored sub-project
  that carries its *own* `weft.toml`/`.weft/wardline/` and whose `.wardline/` is its own
  legitimately-anchored artifact store. Do **not** descend into or sweep any directory
  that `_has_project_markers(dir)` reports True (mirror `enclosing_project_root`'s
  own-markers stop, `paths.py`). Otherwise the outer sweep deletes a nested project's
  current artifacts.
- **Delete mechanics.** Deletion happens when `fix=True` (both CLI and the MCP `doctor`
  tool). Delete managed files found **inside a `.wardline/`-named dir outside the standard
  artifacts dir**, confined under `proj` via `safe_project_path`, regular-file/no-follow
  checked (`_is_regular_file_no_follow`). Wrap each per-file `safe_project_path` call in
  `try/except WardlineError: continue` so one symlinked/escaping entry **skips** rather
  than aborting the whole sweep (`safe_project_path` raises on a symlinked final
  component). Remove a now-empty stray `.wardline/` with **`os.rmdir` only** (never
  `shutil.rmtree`/recursive), after an `lstat` non-symlink check + `safe_project_path`,
  letting `ENOTEMPTY`/`ENOTDIR` be the natural guard. Never delete through a symlink or
  outside `proj`.
- **Report, never delete:** unstamped files (a bare `findings.jsonl` of unknown
  provenance — e.g. esper-lite's 600-mode 834 KB root file) *and* managed-pattern files
  outside a `.wardline/` dir, listed under a `REVIEW` line for the human.
- **MCP posture (must-fix #2 — resolved "MCP can delete too").** The MCP `doctor` tool
  with `repair:true` performs the same delete as the CLI (same confined,
  `.wardline/`-narrowed, no-follow path), since both route through
  `machine_readable_doctor(root, fix=repair)` → `repair_install`. The implementation
  **must flip the doctor tool's `destructiveHint` from `False` to `True`** (`mcp/server.py`,
  the `_DOCTOR_TOOL` annotations) so a now-destructive op is not advertised as
  non-destructive, and the agent-facing tool description should note that `repair:true`
  may delete managed stray artifacts under the server root. See §8 for the threat-model
  justification and §6 test #18 for the confinement regression.
- Status: `stray_artifacts` check (a `DoctorCheck`) — reports counts of removed managed
  files and flagged-for-review files, with paths.

### 4.3 Output shape (authoritative on plumbing)

The two new checks are `DoctorCheck` instances appended to `machine_readable_doctor`'s
`checks` list (after the existing `_check_*` appends). `DoctorCheck` (or its `to_dict`)
is **extended with optional `removed: list[str]` and `review: list[str]` fields** so the
sweep's structured payload survives JSON serialization; absent fields stay omitted for
the other checks. (Alternative: the sweep returns a distinct richer result the JSON layer
folds in — implementer's call, but the dataclass extension is the smaller change.)

Both new checks are wired into **both** non-JSON `cli/doctor.py` render branches, since
neither routes through `machine_readable_doctor`: the `--repair` human path (`fix=True`,
as bespoke trailing lines alongside `weft.toml`/`filigree.auth`) and the check-only path
(`fix=False`).

Human (`wardline doctor --repair`):

```
wardline doctor:
  ...
  weft.toml: ok
  gitignore: updated (added .wardline/, findings.jsonl)
  stray artifacts:
    removed  src/esper/simic/training/.wardline/  (1 managed file)
    REVIEW   findings.jsonl  (unstamped; not wardline-managed — remove by hand if it's a stray scan)
```

`--fix` JSON (`machine_readable_doctor`): the `gitignore` and `stray_artifacts` checks
join the existing `checks` array with `{id, status, fixed, message}` plus, for the
sweep, the new structured `removed: [...]` and `review: [...]` path lists. Check-only
`doctor` (and `machine_readable_doctor(fix=False)`) prints the same gaps with no `fixed`,
no `removed` deletions, and no gitignore write.

---

## 5. Components & isolation

| Unit | Responsibility | Depends on |
|------|----------------|------------|
| `paths.DEFAULT_ARTIFACT_DIR` | single-source default dir name (re-exported by config) | — |
| `paths.project_root_for` | scan path → governing project root | `enclosing_project_root` |
| `paths.artifacts_dir` | project-root-anchored, confined artifact dir | `project_root_for`, `DEFAULT_ARTIFACT_DIR` |
| `artifacts.*` | timestamped name allocation, exclusive write, retention | `paths.artifacts_dir`, `safe_project_path` |
| `discovery._ALWAYS_SKIP` (newly exported) | shared hard walk-skip set | — |
| `install/doctor._check_gitignore` | idempotent, CRLF-safe managed-block gitignore on `project_root_for(root)` | `paths.artifacts_dir`, `install/block.inject_block` or `safe_write_text` |
| `install/doctor._sweep_stray_artifacts` | walk `project_root_for(root)`, delete managed strays (CLI), flag the rest | `_managed_artifact_pattern`, `_is_regular_file_no_follow`, `discovery._ALWAYS_SKIP`, `_has_project_markers`, `safe_project_path` |
| `cli/doctor` | render the two new checks in both branches | `install/doctor`, `machine_readable_doctor` |

Each unit is independently testable: the path resolvers are pure functions of
`(scan_path, fs-markers)`; the gitignore writer is a pure text transform plus one atomic
write; the sweep is a walk + filter + guarded unlink with deletion behind two booleans.

---

## 6. Test plan

**Artifact anchoring (`tests/unit/core/test_artifacts.py`, `test_paths.py`, + scan CLI tests):**

1. Subdir scan of a weft project → artifact at `‹project-root›/.wardline/`, NOT under the
   subdir; `WLN-ENGINE-NESTED-SCAN-ROOT` still present in findings/stderr **and its
   message no longer says "output defaults under the subdirectory"** (§3.3).
2. True-root scan → artifact at `‹root›/.wardline/` (unchanged).
3. Unfederated tree (no markers up the chain) → artifact at scan path (fallback preserved).
4. Custom `artifacts.dir = "out/wl"` → anchored to `‹project-root›/out/wl/`.
5. Escaping `artifacts.dir` — `"../../etc"` and an absolute path outside root — → falls
   back to `‹project-root›/.wardline/`; nothing written outside root (security).
6. Retention prunes to `retain` within the resolved dir; **plus a project-wide case**:
   two distinct subdir scans sharing one `‹project-root›/.wardline/` with `retain=2`
   prune the merged pool to 2 (pins the §3.2 project-wide-retention statement).
7. Explicit `--output` path unaffected; MCP `scan` writes no disk artifact (regression
   guard).
8. **Direct unit matrix for `project_root_for` / `artifacts_dir`** in `test_paths.py`
   (mirror the `weft_state_dir` matrix): scan_path-is-root, subdir, unfederated, relative
   override, absolute-inside-root HONORED, absolute-outside FALLBACK, `..`-escape,
   malformed value. (§5 calls these pure/independently-testable; don't cover them only via
   the CLI.)

**Doctor (`tests/unit/install/test_doctor*.py` / cli / mcp):**

9. `--repair` on a project missing the ignore lines → `.gitignore` gains the managed
   block; second `--repair` is a no-op (idempotent), including a **CRLF `.gitignore`** and
   a pre-existing bare `.wardline` (no slash) → no duplicate line; pre-existing unrelated
   `.gitignore` content preserved verbatim (never-clobber); a commented `#.wardline/` /
   `!.wardline/` line does NOT falsely satisfy the check.
10. Custom `artifacts.dir` → that dir's project-root-relative path is what gets ignored;
    the dead "absolute/outside → ignore only findings.jsonl" branch is gone (an escaping
    value still ignores `.wardline/` via the fallback).
11. **Root reconciliation:** `doctor --repair --root ‹subdir›` of a federated project
    gitignores and sweeps the **enclosing project root**, not the subdir (pins must-fix
    #1); the `cli/scan.py` hint points at the project root.
12. Sweep removes a nested `‹subdir›/.wardline/‹stamp›-findings.jsonl` and the emptied
    dir; **all four managed suffixes** covered, not just `findings.jsonl`.
13. Sweep **report-only** cases: a bare `findings.jsonl` is listed under REVIEW, never
    deleted; a managed-pattern file **outside any `.wardline/` dir** is REVIEW, not
    deleted (narrowed authorship).
14. **Negative control:** a managed file *inside* the standard `‹proj›/.wardline/`
    survives the sweep (guards the skip-standard-dir condition).
15. **Nested-root stop:** a vendored sub-project carrying its own `weft.toml` keeps its
    `.wardline/` artifacts through an outer sweep (pins the §4.2 nested-marker stop).
16. **Symlink safety, split:** (16a) walk-time — the sweep does not descend a symlinked
    directory; (16b) unlink-time — a managed-named file that is a symlink is not unlinked;
    each with an explicit post-sweep presence assertion. Never unlinks outside `proj`.
17. **Check-only non-mutation:** plain `wardline doctor` and
    `machine_readable_doctor(fix=False)` leave a planted stray on disk AND add NO managed
    gitignore block; `--fix` JSON includes `gitignore` and `stray_artifacts` checks with
    the right `status`/`removed`/`review` fields.
18. **MCP-surface deletion confinement (must-fix #2):** drive the sweep through
    `machine_readable_doctor(fix=True)` exactly as the MCP `doctor(repair:true)` handler
    does, against a planted tree containing (a) a managed stray inside a
    `‹subdir›/.wardline/` → deleted, (b) a managed-named file that is a **symlink** → not
    unlinked, (c) a managed-named file pointed at via an out-of-root **dir symlink** → not
    reached/deleted, (d) an unstamped + a bare-managed file → REVIEW, not deleted. Assert
    deletions are confined under root, match only the managed pattern inside `.wardline/`,
    and never follow a symlink. Pair with a unit asserting the MCP `doctor` tool's
    `_DOCTOR_TOOL` annotation reports `destructiveHint: True`.

---

## 7. Docs & changelog

- `docs/getting-started.md`, `docs/guides/configuration.md`, `docs/guides/agents.md` (and
  `docs/guides/weft.md` where artifacts are described): state that the default findings
  artifact lands in `‹project-root›/.wardline/` — anchored to the project root (the
  `weft.toml` directory), **independent of where `wardline scan` is invoked** — and that
  a subdir scan is still flagged. Note `wardline doctor --repair` sets up the gitignore
  and clears stray artifacts — available from both the CLI and the MCP `doctor` tool
  (`repair:true`), which deletes managed strays under the project root and is advertised
  `destructiveHint: True`.
- `CHANGELOG.md` `[Unreleased]`:
  - **Changed** — default scan artifacts now anchor to the weft-project root rather than
    the scan cwd; retention is therefore project-root-wide across heterogeneous
    subdir/root scans sharing one `.wardline/`. **Migration note:** after upgrade the
    artifact MOVES to the project root, and `wardline doctor --repair` will sweep the
    now-stale per-subdir `.wardline/` dirs — any CI/automation reading a hardcoded
    `‹subdir›/.wardline/*-findings.jsonl` path must be updated.
  - **Added** — `wardline doctor --repair` gitignores the artifacts dir and sweeps stray
    managed artifacts; deletion is available on both the CLI and the MCP `doctor` tool
    (`repair:true`, now advertised `destructiveHint: True`), bounded to managed-pattern
    files inside `.wardline/` dirs under the project root.

---

## 8. Risks & rollout

- **Behavior change to a shipped feature.** Default artifact location moves for
  subdirectory scans, and retention becomes project-wide. Intended fix, not a regression;
  per project convention no back-compat shim — the `artifacts.dir` key is unchanged, only
  its anchor. Documented under CHANGELOG **Changed** with the migration note.
- **Untrusted weft.toml.** `artifacts_dir` confinement (mirroring `weft_state_dir`) is
  the guard; test #5 pins it.
- **Destructive sweep, MCP-reachable — intended (must-fix #2, resolved "MCP can delete
  too").** The MCP `doctor` tool reads `repair` from agent args and calls the same
  `machine_readable_doctor(root, fix=repair)` → `repair_install` path, so the sweep's
  delete is reachable from the agent surface against the (possibly untrusted) server-root
  checkout. **Decision:** allow it rather than gate it CLI-only — an agent operating the
  project should be able to clear stray artifacts (MCP-primary / "agents operate and
  extend"). The risk is managed by *bounding the action and advertising it*, not by hiding
  it: (1) the delete is confined under `proj` via `safe_project_path`, no-follow, and
  matches **only** the managed timestamp pattern **inside a `.wardline/`-named dir** —
  blast radius is wardline's own stamped artifacts, never arbitrary source; (2) unstamped
  and bare-managed files are report-only; (3) the sweep stops at nested project markers;
  (4) the implementation **flips the `_DOCTOR_TOOL` `destructiveHint` to `True`** so the
  op is honestly advertised, and the tool description notes deletion. An agent that
  shouldn't delete simply does not pass `repair:true`. Tests #16 (symlink safety) and #18
  (MCP-surface confinement + `destructiveHint: True`) pin it. **Residual risk accepted:** a
  crafted untrusted repo could induce deletion of files it placed inside a `.wardline/`
  dir matching the stamp pattern — i.e. wardline deletes attacker-planted files that
  *look* like its own artifacts, which is a no-op-equivalent loss (the attacker's own
  planted bytes), not exfiltration or escape.
- **Authorship heuristic.** A timestamp-pattern filename is not proof of wardline
  authorship; auto-delete is narrowed to managed files *inside `.wardline/` dirs*, and
  everything else is report-only (§4.2). Bounds the blast radius of the destructive path
  to wardline's own artifact convention.
- **Nested vendored project.** Walking from `project_root_for(root)` could reach a
  sub-project's own `.wardline/`; the sweep stops at nested project markers (§4.2). Test
  #15 pins it.
- **Repair-ordering hazard (`_ensure_weft_config` vs the must-fix-#1 climb).** Under
  `fix=True`, `repair_install` plants a `weft.toml` at the literal `root` *before* the
  new checks run; computing `project_root_for(root)` after that would make a fresh-subdir
  invocation anchor to the subdir (now a root) and defeat the climb, leaving a nested
  `weft.toml`. Mitigation: snapshot `proj` before the `if fix:` block and thread it in
  (§4 intro). Benign on the steered project-root invocation; the snapshot fixes the
  off-path manual `--root ‹subdir›` case.
- **Import hygiene.** `paths.py` owns `DEFAULT_ARTIFACT_DIR`; `config.py` re-exports it
  (§3.1). The reverse direction is a real cycle and is rejected, not offered as an option.

---

## 9. Deferred (agent-attributed backlog — NOT in this spec)

The panel surfaced one improvement that is real but is **scope expansion**, not a fix to
shipped correctness, so it is recorded here rather than folded in (keeping this a tight
two-part change):

- **Self-describing relocated artifacts.** Relocating a *subdir* scan's artifact into the
  shared `‹project-root›/.wardline/` co-locates it with root-scan artifacts; its
  `location.path` values stay **scan-root-relative** (the subdir), and three of the four
  formats carry no base to disambiguate (`legis.json` already embeds `scan_root`;
  `findings.jsonl`, `findings.agent-summary.json`, and SARIF do not). A future change
  could add a project-root-relative `scan_root` key to the jsonl run-context and the
  agent-summary top-level object, and SARIF `originalUriBaseIds` + per-result
  `uriBaseId`, so a consumer can rebase the paths.
  - **Why deferred, not blocking:** a subdir scan is *already* flagged
    `WLN-ENGINE-NESTED-SCAN-ROOT` as wrong-for-identity, so its artifact is in a path the
    tool actively discourages; for the correct root-scan usage the artifact and its
    project-root-relative paths are fully self-consistent; federation consumers
    (Loomweave/Filigree/dossier) key on *fingerprint*, not path-relative resolution; and
    GitHub Code Scanning already resolves SARIF URIs against the repo root regardless of
    the `.sarif` file location. The net-new harm is limited to co-locating
    already-discouraged subdir-scan artifacts — worth a backlog item, not a redesign of
    the emitters in this pass. File it as an agent-attributed expansion ticket
    (`wardline` tracker, coverage/robustness label) when this ships.
