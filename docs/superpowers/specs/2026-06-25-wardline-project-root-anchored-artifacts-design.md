# Wardline project-root-anchored scan artifacts + doctor hygiene (design)

**Date:** 2026-06-25
**Status:** Design — implementation-ready. The agent executing it may produce its own
TDD plan (writing-plans) from this.
**Gate:** none — fully autonomous, Wardline-repo-only. No sibling dependency.

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

**Definition of done:**

- `wardline scan ‹subdir›` writes its artifact to `‹project-root›/.wardline/…`; the
  `WLN-ENGINE-NESTED-SCAN-ROOT` warning still fires.
- `wardline scan .` at a true project root is unchanged (artifact at `‹root›/.wardline/`).
- A scan of an unfederated tree (no `weft.toml`/`.weft/wardline/` anywhere up the chain)
  still writes `.wardline/` at the scan path (today's behavior preserved).
- An escaping `artifacts.dir` (absolute-elsewhere or `..`-escape) silently falls back to
  the default `.wardline` under the project root — no write-redirect, no exit-2 DoS.
- `wardline doctor --repair` adds the gitignore block (idempotently), deletes managed
  stray artifacts, leaves+reports unstamped strays, and emits this in both human and
  `--fix` JSON output.
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
- doctor does **not** auto-delete unstamped files (e.g. a hand-created or
  unknown-provenance `findings.jsonl`); it reports them.

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
def project_root_for(scan_path: Path) -> Path:
    """The weft-project root governing a scan of *scan_path*.

    enclosing_project_root() returns the nearest STRICT ancestor carrying project
    markers, or None when scan_path itself is a root OR no ancestor is one. In both
    None cases the governing root is scan_path itself:
      * scan_path has markers          -> it IS the root
      * scan_path is a project subdir  -> the enclosing root
      * no markers anywhere            -> fall back to scan_path (unfederated tree)
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
    project_root = project_root_for(scan_path)
    default = project_root / DEFAULT_ARTIFACT_DIR        # ".wardline"
    candidate = Path(artifacts_dir_value)
    resolved = (candidate if candidate.is_absolute() else project_root / candidate).resolve()
    try:
        resolved.relative_to(project_root.resolve())
    except ValueError:
        return default
    return resolved
```

`DEFAULT_ARTIFACT_DIR` lives in `core/config.py` today; either import it into `paths.py`
or pass the default in. Keep the import direction clean (paths.py is low-level — if a
cycle threatens, define `DEFAULT_ARTIFACT_DIR` in `paths.py` and re-export from
`config.py`, or pass `default` as an argument). Implementer's call; no behavior change
either way.

### 3.2 `core/artifacts.py` uses the project-root anchor

Replace the scan-root anchor with the project-root anchor and thread the project root as
the confinement base through every `safe_project_path` call:

- `_artifact_dir(root_resolved, config)` → resolve via `paths.artifacts_dir(root, config.artifacts.dir)`.
- `timestamped_scan_artifact` / `write_scan_artifact`: compute
  `project_root = paths.project_root_for(root)` once; pass `project_root` (not
  `root.resolve()`) as the confinement base to `_timestamped_candidates`,
  `prune_scan_artifacts`, and `_write_text_exclusive`.
- `prune_scan_artifacts(root, artifact, fmt, retain)`: its `safe_project_path(...)`
  guard base becomes the project root. Pruning still operates within
  `artifact.parent` (the resolved artifact dir), so retention is unchanged — it just
  runs in the right directory.

Public signatures of `write_scan_artifact` / `timestamped_scan_artifact` stay the same
(they still take the scan `root`); only the internal anchor changes. The `cli/scan.py`
call sites are untouched.

### 3.3 What does NOT change

- `config.artifacts.dir` default (`.wardline`) and `artifacts.retain` default (`20`),
  and `core/config_schema.py`. No new keys.
- The `WLN-ENGINE-NESTED-SCAN-ROOT` engine finding and its CLI/MCP surfacing. A
  subdirectory scan is still wrong for identity/suppression reasons; anchoring the
  artifact does not make it correct. The warning stays; the file just lands in the
  right place now.
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

Both actions hook into `install/doctor.py`. `repair_install(root)` gains two status
keys; `check_install` / `machine_readable_doctor` report the same gaps in check-only
mode. `cli/doctor.py` prints the new lines.

### 4.1 `.gitignore` hygiene

Ensure the project `.gitignore` ignores the **configured** artifacts dir (default
`.wardline/`) and the legacy top-level `findings.jsonl`.

- Resolve the dir name from weft.toml `[wardline].artifacts.dir` (default `.wardline`)
  so a custom dir is ignored, not a hardcoded one. Use the project-root-relative dir
  name (e.g. `.wardline/`); if the configured dir is absolute/outside root, ignore only
  `findings.jsonl` and note the custom dir is out-of-tree.
- Append a managed block under a `# Wardline scan artifacts` comment, adding only the
  lines not already present (idempotent — running `--repair` twice adds nothing the
  second time). Match existing lines by exact normalized entry (`.wardline/`,
  `findings.jsonl`), tolerant of an existing trailing-slash/no-slash variant.
- Never clobber: read existing `.gitignore` (safe no-follow read), append, write via
  the existing `safe_write_text`. Create `.gitignore` if absent.
- Status: `created` / `updated` / `ok` (already present). Reported as a `gitignore`
  check.

### 4.2 Stray-artifact sweep

Find wardline-**managed** artifacts sitting outside the standard dir and remove them;
report unstamped strays.

- **Managed pattern:** reuse `artifacts._managed_artifact_pattern(suffix)` across all
  four known suffixes (`findings.jsonl`, `findings.sarif`, `findings.agent-summary.json`,
  `scan.legis.json`): `^\d{8}T\d{6}Z(-\d{3})?-‹suffix›$`. A file matching this is
  unambiguously wardline-authored.
- **Walk** the tree from the project root, honoring the config `exclude` globs and
  always skipping `.git/`, the resolved standard artifacts dir, and not descending into
  symlinked directories. Bound the walk so it never traverses caches/venvs (the same
  exclusion discipline `discover()` uses).
- **Delete** managed files found **outside** the standard artifacts dir, confined under
  the project root via `safe_project_path`, regular-file/no-follow checked
  (`_is_regular_file_no_follow`). Remove a now-empty stray `.wardline/` directory left
  behind. Never delete through a symlink or outside the root.
- **Report, never delete, unstamped strays:** a bare `findings.jsonl` (or other
  unstamped name) at any location has unknown provenance (e.g. esper-lite's 600-mode
  834 KB root file) — list it under a `REVIEW` line for the human to remove by hand.
- Status: `stray_artifacts` check — reports counts of removed managed files and
  flagged-for-review files, with paths.

### 4.3 Output shape

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
sweep, structured `removed: [...]` and `review: [...]` path lists. Check-only `doctor`
prints the same gaps with no `fixed` and no deletions.

---

## 5. Components & isolation

| Unit | Responsibility | Depends on |
|------|----------------|------------|
| `paths.project_root_for` | scan path → governing project root | `enclosing_project_root` |
| `paths.artifacts_dir` | project-root-anchored, confined artifact dir | `project_root_for`, `DEFAULT_ARTIFACT_DIR` |
| `artifacts.*` | timestamped name allocation, exclusive write, retention | `paths.artifacts_dir`, `safe_project_path` |
| `install/doctor._ensure_gitignore` | idempotent managed-block gitignore | `safe_read/​write`, config artifacts.dir |
| `install/doctor._sweep_stray_artifacts` | find/remove managed strays, flag unstamped | `_managed_artifact_pattern`, config excludes, `safe_project_path` |
| `cli/doctor` | render the two new checks | `install/doctor` |

Each unit is independently testable: the path resolvers are pure functions of
`(scan_path, fs-markers)`; the gitignore writer is a pure text transform plus one write;
the sweep is a walk + filter + guarded unlink.

---

## 6. Test plan

**Artifact anchoring (`tests/unit/core/test_artifacts.py` + scan CLI tests):**

1. Subdir scan of a weft project → artifact at `‹project-root›/.wardline/`, NOT under the
   subdir; `WLN-ENGINE-NESTED-SCAN-ROOT` still present in findings/stderr.
2. True-root scan → artifact at `‹root›/.wardline/` (unchanged).
3. Unfederated tree (no markers up the chain) → artifact at scan path (fallback preserved).
4. Custom `artifacts.dir = "out/wl"` → anchored to `‹project-root›/out/wl/`.
5. Escaping `artifacts.dir` — `"../../etc"` and an absolute path outside root — → falls
   back to `‹project-root›/.wardline/`; nothing written outside root (security).
6. Retention still prunes to `retain` within the resolved dir.
7. Explicit `--output` path unaffected; MCP `scan` writes no disk artifact (regression
   guard).

**Doctor (`tests/unit/install/test_doctor*.py` / cli):**

8. `--repair` on a project missing the ignore lines → `.gitignore` gains the managed
   block; second `--repair` is a no-op (idempotent).
9. Custom `artifacts.dir` → that dir name is what gets ignored.
10. Sweep removes a nested `‹subdir›/.wardline/‹stamp›-findings.jsonl` and the emptied
    dir; leaves a bare `findings.jsonl` and lists it under REVIEW.
11. Sweep does not follow a symlinked dir and never unlinks outside the project root.
12. `--fix` JSON includes `gitignore` and `stray_artifacts` checks with the right
    `status`/`removed`/`review` fields; check-only `doctor` reports gaps and deletes
    nothing.

---

## 7. Docs & changelog

- `docs/getting-started.md`, `docs/guides/configuration.md`, `docs/guides/agents.md` (and
  `docs/guides/weft.md` where artifacts are described): state that the default findings
  artifact lands in `‹project-root›/.wardline/` — anchored to the project root (the
  `weft.toml` directory), **independent of where `wardline scan` is invoked** — and that
  a subdir scan is still flagged. Note `wardline doctor --repair` sets up the gitignore
  and clears stray artifacts.
- `CHANGELOG.md` `[Unreleased]`: **Changed** — default scan artifacts now anchor to the
  weft-project root rather than the scan cwd; **Added** — `wardline doctor --repair`
  gitignores the artifacts dir and sweeps stray managed artifacts.

---

## 8. Risks & rollout

- **Behavior change to a shipped feature.** Default artifact location moves for
  subdirectory scans. This is the intended fix, not a regression; per project
  convention no back-compat shim is added — the `artifacts.dir` key is unchanged, only
  its anchor. Documented under CHANGELOG **Changed**.
- **Untrusted weft.toml.** `artifacts_dir` confinement (mirroring `weft_state_dir`) is
  the guard; test #5 pins it. The doctor sweep runs on the operator's own local repo,
  but still confines deletions under root, matches only the managed pattern, and is
  no-follow — test #11 pins it.
- **Import hygiene.** `paths.py` referencing `DEFAULT_ARTIFACT_DIR` must not create an
  import cycle with `config.py`; §3.1 gives two clean resolutions.
