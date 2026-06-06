# Weft config/store consolidation (wardline) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse wardline's scattered dot-dir + config into the Weft federation convention — operator config moves from `wardline.yaml` to the read-only shared `weft.toml [wardline]` table; machine-written state moves from `.wardline/` to the member-owned `.weft/wardline/` subtree; sibling discovery prefers `.weft/<sibling>/` and tolerates legacy paths.

**Architecture:** Two surfaces, two owners. (1) `weft.toml` at project root is **operator-authored, read-only** for wardline — wardline reads its `[wardline]` table (or boots on `config_schema` defaults if the table/file is absent), and **never writes it**. (2) `.weft/wardline/` is **machine-written state owned exclusively by wardline** — `baseline.yaml`, `judged.yaml`, and (newly relocated) `waivers.yaml` live here. A single `core/paths.py` module is the one source of truth for both locations, killing the hardcoded-`".wardline"`-string scatter. The three former config *writers* (`add_waiver`, `record_bindings`, `activate_pack`) are re-routed: waivers become machine state under `.weft/wardline/`; binding-persistence is dropped in favour of live published-port discovery; pack activation becomes guidance-only (packs execute code, so they stay operator-authored in `weft.toml`).

**Tech Stack:** Python ≥3.12 (so `tomllib` is stdlib — reading `weft.toml` adds **no** dependency; base package stays zero-dep). `pyyaml`+`jsonschema`+`click` remain in the `scanner` extra: pyyaml still serialises `baseline.yaml`/`judged.yaml`/`waivers.yaml`; jsonschema still validates the `[wardline]` table.

---

## Clean-break / scope decisions (locked)

- **Config format:** `weft.toml [wardline]` **replaces** `wardline.yaml`. No fallback to `wardline.yaml` (clean break). The contract's fallback chain is "`[wardline]` if present, **else config_schema defaults**" — `wardline.yaml` is deliberately absent from it.
- **`waivers` leave the operator schema entirely.** They are fingerprint-keyed machine/CLI-written entries an operator never hand-authors; they become a `.weft/wardline/waivers.yaml` state file. Removed from `WARDLINE_SCHEMA` and from `WardlineConfig`.
- **`packs` stay operator-authored** in `weft.toml [wardline].packs` (they import/execute code; `_is_local_pack` guard exists for exactly this reason). `activate_pack` becomes guidance-only — it must not write `weft.toml`.
- **Binding persistence (`record_bindings`) is dropped.** Live discovery via the published `.weft/<sibling>/ephemeral.port` rung (already implemented in `resolve_*_url`) supersedes it; the operator may still set a URL by hand in `weft.toml`.
- **Sibling discovery is the ONE place legacy fallback is wanted:** prefer `.weft/loomweave|filigree/ephemeral.port`, fall back to legacy `.loomweave/`/`.filigree/`. Do NOT apply wardline's own clean-break policy here.
- **No nested `.weft/wardline/.gitignore`.** The subtree holds only committed artifacts (`baseline.yaml`, `judged.yaml`, `waivers.yaml`); the attest key lives in `.env`, not the dot-dir. A blanket ignore would silently untrack the baseline. Root `.gitignore`: drop the dead `.wardline-cache/` and the `wardline.yaml` line; do **not** add `.weft/`; do **not** ignore `weft.toml`.
- **Security guards preserved:** `_is_local_pack` (pack-load) and `_is_safe_url`/`trust_config_urls` (URL) stay — config remains untrusted input regardless of "operator-authored" framing.
- **Out of scope:** `.env`-based token reading (`loomweave/config.py`, `filigree/config.py`, `core/attest_key.py`) — those already follow the federation env-var discipline. SEI scheme (`loomweave:eid:`) is frozen and untouched.

## File Structure

**Created:**
- `src/wardline/core/paths.py` — single source of truth for `weft.toml` path and `.weft/wardline/` state-file paths.
- `tests/unit/core/test_paths.py` — unit tests for the path helpers.
- `tests/unit/core/test_config_toml.py` — tests for the TOML `[wardline]` loader.

**Modified (load-bearing core):**
- `src/wardline/core/config.py` — TOML loader; drop `waivers`; published-port rung prefers `.weft/<sibling>/`; default path → `weft.toml`.
- `src/wardline/core/config_schema.py` — drop `waivers`; docstring → `weft.toml [wardline]`.
- `src/wardline/core/waivers.py` — `add_waiver` writes `.weft/wardline/waivers.yaml`; add `load_project_waivers(root)`.
- `src/wardline/core/run.py` — baseline/judged/waivers via `core/paths`.
- `src/wardline/core/baseline.py` — baseline path via `core/paths`.
- `src/wardline/core/judge_run.py` — judged path via `core/paths`.
- `src/wardline/core/assure.py`, `src/wardline/core/attest.py` — waivers via `load_project_waivers(root)`; config path → `weft.toml`.
- `src/wardline/install/detect.py` — `record_bindings` → `detect_siblings` (detect-only, no write); port discovery prefers `.weft/<sibling>/`.
- `src/wardline/install/pack.py` — `activate_pack` → guidance-only.
- `src/wardline/install/doctor.py` — config check reads `weft.toml`; layout checks; may create own `.weft/wardline/`.
- `src/wardline/cli/install.py` — consume `detect_siblings` + guidance-only pack.
- `src/wardline/mcp/server.py`, `src/wardline/mcp/resources.py` — waiver_add → waivers state; config path → `weft.toml`.

**Modified (mechanical sweep — string/docstring/help/error references):** `cli/scan.py`, `cli/judge.py`, `cli/attest.py`, `cli/fix.py`, `cli/main.py`, `cli/file_finding.py`, `cli/scan_file_findings.py`, `cli/dossier.py`, `cli/decorator_coverage.py`, `core/errors.py`, `scanner/analyzer.py`, `scanner/context.py`, `scanner/grammar.py`, `scanner/rules/contradictory_trust.py`, `core/discovery.py`, `core/judged.py`.

**Modified (root config):** `.gitignore`.

**Modified (tests, ~20 files) and (docs, ~29 files):** enumerated in Task 11 & 12.

---

## Task 1: Central paths module

**Files:**
- Create: `src/wardline/core/paths.py`
- Test: `tests/unit/core/test_paths.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_paths.py
from pathlib import Path

from wardline.core import paths


def test_member_and_config_constants():
    assert paths.WEFT_MEMBER == "wardline"
    assert paths.WEFT_CONFIG_FILE == "weft.toml"


def test_config_path():
    root = Path("/proj")
    assert paths.weft_config_path(root) == root / "weft.toml"


def test_state_dir_and_files():
    root = Path("/proj")
    assert paths.weft_state_dir(root) == root / ".weft" / "wardline"
    assert paths.baseline_path(root) == root / ".weft" / "wardline" / "baseline.yaml"
    assert paths.judged_path(root) == root / ".weft" / "wardline" / "judged.yaml"
    assert paths.waivers_path(root) == root / ".weft" / "wardline" / "waivers.yaml"


def test_sibling_state_dir_prefers_weft():
    root = Path("/proj")
    assert paths.sibling_state_dir(root, "filigree") == root / ".weft" / "filigree"
    assert paths.legacy_sibling_dir(root, "filigree") == root / ".filigree"
    assert paths.legacy_sibling_dir(root, "loomweave") == root / ".loomweave"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/core/test_paths.py -q`
Expected: FAIL (`ModuleNotFoundError: wardline.core.paths`).

- [ ] **Step 3: Implement `core/paths.py`**

```python
# src/wardline/core/paths.py
"""Single source of truth for Weft federation on-disk locations.

Two surfaces, two owners (Weft convention C-9):

* ``weft.toml`` (project root) — OPERATOR-authored, read-only for wardline. We
  read our ``[wardline]`` table; we NEVER write this file.
* ``.weft/wardline/`` (project root) — machine-written state owned exclusively by
  wardline (``baseline.yaml``, ``judged.yaml``, ``waivers.yaml``). We are the sole
  writer of this subtree and never read or write a sibling's subtree.

Sibling runtime state lives under ``.weft/<sibling>/`` (preferred) with a
transition-window fallback to the legacy ``.{sibling}/`` dot-dir.
"""

from __future__ import annotations

from pathlib import Path

WEFT_MEMBER = "wardline"
WEFT_CONFIG_FILE = "weft.toml"
_WEFT_DIR = ".weft"


def weft_config_path(root: Path) -> Path:
    """Path to the shared operator-authored ``weft.toml`` (read-only for us)."""
    return root / WEFT_CONFIG_FILE


def weft_state_dir(root: Path) -> Path:
    """Wardline's exclusively-owned machine-state subtree."""
    return root / _WEFT_DIR / WEFT_MEMBER


def baseline_path(root: Path) -> Path:
    return weft_state_dir(root) / "baseline.yaml"


def judged_path(root: Path) -> Path:
    return weft_state_dir(root) / "judged.yaml"


def waivers_path(root: Path) -> Path:
    return weft_state_dir(root) / "waivers.yaml"


def sibling_state_dir(root: Path, sibling: str) -> Path:
    """Preferred location of a sibling member's runtime subtree."""
    return root / _WEFT_DIR / sibling


def legacy_sibling_dir(root: Path, sibling: str) -> Path:
    """Legacy pre-consolidation dot-dir for a sibling (transition-window fallback)."""
    return root / f".{sibling}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/core/test_paths.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/paths.py tests/unit/core/test_paths.py
git commit -m "feat(weft): add core/paths single-source-of-truth for weft.toml + .weft/wardline layout"
```

---

## Task 2: Config loader — read `weft.toml [wardline]` (TOML), drop `waivers`

**Files:**
- Modify: `src/wardline/core/config.py` (loader body, `_config_for` default path, `WardlineConfig.waivers` removal, published-port rungs in Task 5)
- Modify: `src/wardline/core/config_schema.py` (drop `waivers`, docstring)
- Test: `tests/unit/core/test_config_toml.py` (new), `tests/unit/core/test_config.py` (update)

- [ ] **Step 1: Write the failing test** (`tests/unit/core/test_config_toml.py`)

```python
from pathlib import Path

import pytest

from wardline.core import config as config_mod
from wardline.core.errors import ConfigError


def _write(root: Path, body: str) -> Path:
    p = root / "weft.toml"
    p.write_text(body, encoding="utf-8")
    return p


def test_absent_file_returns_defaults(tmp_path):
    cfg = config_mod.load(tmp_path / "weft.toml")
    assert cfg.source_roots == (".",)
    assert cfg.rules_enable == ("*",)


def test_reads_wardline_table(tmp_path):
    p = _write(
        tmp_path,
        """
[wardline]
source_roots = ["src"]
exclude = ["build"]

[wardline.rules]
enable = ["PY-WL-101"]
severity = { "PY-WL-101" = "ERROR" }

[wardline.filigree]
url = "http://localhost:8377/api/weft/scan-results"
""",
    )
    cfg = config_mod.load(p)
    assert cfg.source_roots == ("src",)
    assert cfg.exclude == ("build",)
    assert cfg.rules_enable == ("PY-WL-101",)
    assert cfg.rules_severity == {"PY-WL-101": "ERROR"}
    assert cfg.filigree_url == "http://localhost:8377/api/weft/scan-results"


def test_no_wardline_table_is_defaults(tmp_path):
    p = _write(tmp_path, "[loomweave]\nurl = \"http://x\"\n")
    cfg = config_mod.load(p)
    assert cfg.source_roots == (".",)


def test_malformed_toml_raises_configerror(tmp_path):
    p = _write(tmp_path, "[wardline]\nsource_roots = [")
    with pytest.raises(ConfigError):
        config_mod.load(p)


def test_unknown_key_rejected(tmp_path):
    p = _write(tmp_path, "[wardline]\nbogus_key = 1\n")
    with pytest.raises(ConfigError):
        config_mod.load(p)


def test_waivers_key_rejected_now_machine_state(tmp_path):
    # waivers are no longer an operator key — additionalProperties:false rejects them.
    p = _write(tmp_path, "[[wardline.waivers]]\nfingerprint = \"x\"\n")
    with pytest.raises(ConfigError):
        config_mod.load(p)
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pytest tests/unit/core/test_config_toml.py -q`
Expected: FAIL (loader still parses YAML / `weft.toml` not understood).

- [ ] **Step 3: Edit `core/config_schema.py`** — drop `waivers`, fix docstring.

Change the module docstring first line to:
```python
"""JSON Schema (draft 2020-12) for the ``[wardline]`` table of ``weft.toml``.
```
Delete the `"waivers": {"type": "array", "items": {"type": "object"}},` property line. Leave everything else (including `packs`) unchanged.

- [ ] **Step 4: Edit `core/config.py` loader.**

Replace the YAML read in `load()` with a TOML read that extracts the `[wardline]` table. Concretely:

In the imports, add `import tomllib` and drop the `require_yaml` call inside `load()` (keep `require_jsonschema`). Replace the file-read block:

```python
    # OLD:
    # yaml = require_yaml("loading wardline.yaml")
    # jsonschema = require_jsonschema("validating wardline.yaml")
    # try:
    #     raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    # except yaml.YAMLError as exc:
    #     raise ConfigError(f"malformed {path.name}: {exc}") from exc
    # if not isinstance(raw, dict):
    #     raise ConfigError(f"{path.name} must be a mapping at top level")

    # NEW:
    jsonschema = require_jsonschema("validating weft.toml [wardline]")
    try:
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {path.name}: {exc}") from exc
    table = parsed.get("wardline")
    if table is None:
        return WardlineConfig()
    if not isinstance(table, dict):
        raise ConfigError(f"[wardline] in {path.name} must be a table")
    raw = table
```

Remove the `baseline=` and `waivers=` construction args from the `WardlineConfig(...)` return (see Step 5 for the dataclass). Keep `packs`, `pack_modules`, everything else. The pack-merge loop, `_is_local_pack` guard, `autofix` validation, and `jsonschema.validate(merged_raw, WARDLINE_SCHEMA)` stay **unchanged** — they operate on the extracted `raw` dict exactly as before.

In `_config_for`, change the default:
```python
    return load(
        config_path if config_path is not None else weft_config_path(root),
        ...
    )
```
Add `from wardline.core.paths import weft_config_path` to the imports.

- [ ] **Step 5: Edit `WardlineConfig` (config.py).**

Remove the `baseline` and `waivers` fields from the dataclass (both were reserved/now-relocated): delete
```python
    baseline: Mapping[str, Any] = field(default_factory=dict)
    waivers: tuple[Mapping[str, Any], ...] = ()
```
Leave `judge`, `filigree`, `loomweave`, `packs`, etc. (Consumers of `.waivers`/`.baseline` are migrated in Task 3 & 4. Grep `cfg.baseline`/`config.baseline` first — confirm only the now-removed schema referenced it; the gate uses the on-disk `baseline.yaml`, not `cfg.baseline`.)

- [ ] **Step 6: Run the new + existing config tests**

Run: `.venv/bin/pytest tests/unit/core/test_config_toml.py tests/unit/core/test_config.py -q`
Expected: new file PASSES. `test_config.py` will have YAML-format failures — fix them in Task 11/12's test sweep; for now confirm the *TOML* file is green and note the YAML-format failures are expected-and-tracked.

- [ ] **Step 7: Commit**

```bash
git add src/wardline/core/config.py src/wardline/core/config_schema.py tests/unit/core/test_config_toml.py
git commit -m "feat(weft): config loader reads weft.toml [wardline] (tomllib, zero-dep); drop waivers/baseline from operator schema"
```

---

## Task 3: Waivers become machine state under `.weft/wardline/waivers.yaml`

**Files:**
- Modify: `src/wardline/core/waivers.py` (`add_waiver` target; add `load_project_waivers`)
- Modify consumers: `src/wardline/core/run.py:230`, `src/wardline/core/attest.py:313`, `src/wardline/core/assure.py:250`, `src/wardline/mcp/server.py:661-688`
- Test: `tests/unit/core/test_waivers.py` (update/extend)

- [ ] **Step 1: Write the failing test** (extend `tests/unit/core/test_waivers.py`)

```python
from datetime import date
from pathlib import Path

from wardline.core import paths
from wardline.core.waivers import add_waiver, load_project_waivers


def test_add_waiver_writes_to_weft_state(tmp_path):
    fp = "a" * 64
    w = add_waiver(paths.waivers_path(tmp_path), fingerprint=fp, reason="ok", expires=None, root=tmp_path)
    assert w.fingerprint == fp
    assert paths.waivers_path(tmp_path).is_file()
    # parent .weft/wardline/ was created
    assert paths.weft_state_dir(tmp_path).is_dir()


def test_load_project_waivers_roundtrip(tmp_path):
    fp = "b" * 64
    add_waiver(paths.waivers_path(tmp_path), fingerprint=fp, reason="why", expires=date(2030, 1, 1), root=tmp_path)
    loaded = load_project_waivers(tmp_path)
    assert [w.fingerprint for w in loaded] == [fp]
    assert loaded[0].expires == date(2030, 1, 1)


def test_load_project_waivers_absent_is_empty(tmp_path):
    assert load_project_waivers(tmp_path) == ()
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/pytest tests/unit/core/test_waivers.py -q -k "weft_state or project_waivers"`
Expected: FAIL (`load_project_waivers` undefined).

- [ ] **Step 3: Implement `load_project_waivers` in `core/waivers.py`.**

`add_waiver` already takes a `config_path` + `root` and appends to a `{waivers: [...]}` YAML doc — it works unchanged against `waivers_path(root)`; the only behavioural change is callers now pass `waivers_path(root)`. Add the reader:

```python
from wardline.core.paths import waivers_path  # add to imports


def load_project_waivers(root: Path) -> tuple[Waiver, ...]:
    """Read wardline's machine/CLI-written waivers from ``.weft/wardline/waivers.yaml``.

    Absent file → empty tuple. Validates via the same rules as :func:`parse_waivers`.
    """
    path = waivers_path(root)
    if not path.is_file():
        return ()
    yaml = require_yaml("loading waivers")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"{path.name} is not a mapping")
    raw = loaded.get("waivers")
    if raw is not None and not isinstance(raw, list):
        raise ConfigError(f"malformed {path.name}: 'waivers' must be a list")
    return parse_waivers(raw or ())
```

Also update the `require_yaml("updating wardline.yaml waivers")` label inside `add_waiver` to `require_yaml("updating waivers")`, and the module docstring's "Waivers live inline in `wardline.yaml`…" to "Waivers live in `.weft/wardline/waivers.yaml` (machine/CLI-written state)…".

- [ ] **Step 4: Migrate the 4 consumers.**

`core/run.py:230` — replace `waivers = WaiverSet(parse_waivers(cfg.waivers))` with:
```python
    from wardline.core.waivers import load_project_waivers
    waivers = WaiverSet(load_project_waivers(root))
```
(Keep the existing `WaiverSet, parse_waivers` import; add `load_project_waivers` to it.)

`core/attest.py:313` — replace `waivers = parse_waivers(config.waivers)` with `waivers = load_project_waivers(root)` (import it; `root` is in scope at that call — verify the local name).

`core/assure.py:250` — replace `waivers = parse_waivers(config_mod.load(cfg_path).waivers)` with `waivers = load_project_waivers(root)` (import it; confirm `root` is the param name).

`mcp/server.py` `_waiver_add` (≈661) — replace the dedup read and write target:
```python
    # OLD: cfg_path = _cfg(args, root) or (root / "wardline.yaml"); safe_cfg_path = ...
    #      for existing in parse_waivers(config_mod.load(safe_cfg_path).waivers):
    # NEW:
    from wardline.core.paths import waivers_path
    from wardline.core.waivers import load_project_waivers
    for existing in load_project_waivers(root):
        if existing.fingerprint == fp:
            return { ... already_exists: True ... }
    waiver = add_waiver(waivers_path(root), fingerprint=fp, reason=reason, expires=expires, root=root)
```
Drop the now-unused `parse_waivers` / `config_mod` imports in server.py only if nothing else uses them (grep first).

- [ ] **Step 5: Run consumer tests**

Run: `.venv/bin/pytest tests/unit/core/test_waivers.py tests/unit/mcp/test_server_suppression.py tests/unit/core/test_run.py -q`
Expected: new waiver tests PASS; pre-existing tests that wrote waivers into `wardline.yaml` will fail on format — fixed in test sweep (Task 12).

- [ ] **Step 6: Commit**

```bash
git add src/wardline/core/waivers.py src/wardline/core/run.py src/wardline/core/attest.py src/wardline/core/assure.py src/wardline/mcp/server.py tests/unit/core/test_waivers.py
git commit -m "feat(weft): relocate waivers to .weft/wardline/waivers.yaml machine state (drop config-write of operator file)"
```

---

## Task 4: Relocate `baseline.yaml` + `judged.yaml` to `.weft/wardline/`

**Files:**
- Modify: `src/wardline/core/run.py:229,231,348`, `src/wardline/core/baseline.py:100`, `src/wardline/core/judge_run.py:107,187`, `src/wardline/cli/main.py:75`, `src/wardline/mcp/server.py:632`
- Test: `tests/unit/core/test_baseline.py`, `test_baseline_generate.py`, `test_judge_run.py` (update), plus a new gate-path test.

- [ ] **Step 1: Write the failing test** (add to `tests/unit/core/test_baseline.py`)

```python
from wardline.core import paths
from wardline.core.baseline import generate_baseline  # adjust to actual writer entrypoint

def test_baseline_writes_under_weft_state(tmp_path):
    # generate a baseline from one finding; assert location
    # (mirror the existing generate test's fixture, just assert the path)
    ...
    assert paths.baseline_path(tmp_path).is_file()
    assert not (tmp_path / ".wardline").exists()
```

- [ ] **Step 2: Run to verify it fails** — Expected: writes still land in `.wardline/`.

- [ ] **Step 3: Replace every `root / ".wardline" / "baseline.yaml"` and `root / ".wardline" / "judged.yaml"` literal with the `core/paths` helper.**

- `core/run.py:229` `load_baseline(root / ".wardline" / "baseline.yaml")` → `load_baseline(baseline_path(root))`
- `core/run.py:231` `load_judged(root / ".wardline" / "judged.yaml")` → `load_judged(judged_path(root))`
- `core/run.py:348` `if not (root / ".wardline" / "baseline.yaml").is_file():` → `if not baseline_path(root).is_file():`
- `core/run.py:337` docstring `.wardline/baseline.yaml` → `.weft/wardline/baseline.yaml`
- `core/baseline.py:100` `baseline_path = root / ".wardline" / "baseline.yaml"` → `baseline_path = baseline_path_fn(root)` — **avoid shadowing**: import as `from wardline.core.paths import baseline_path as baseline_file` and use `baseline_file(root)`. Update docstrings at `baseline.py:4,85`.
- `core/judge_run.py:107` `judged_path = root / ".wardline" / "judged.yaml"` → import `from wardline.core.paths import judged_path as judged_file`; `judged_path = judged_file(root)`.
- `core/judge_run.py:187` `load_judged(root / ".wardline" / "judged.yaml")` → `load_judged(judged_file(root))`
- `cli/main.py:75` `baseline_path = path / ".wardline" / "baseline.yaml"` → `from wardline.core.paths import baseline_path as baseline_file`; `baseline_path = baseline_file(path)`. Update help/docstring at `main.py:101` `(.wardline/baseline.yaml)` → `(.weft/wardline/baseline.yaml)`.
- `mcp/server.py:632` `baseline_path = root / ".wardline" / "baseline.yaml"` → `baseline_file(root)`.

Add `from wardline.core.paths import baseline_path, judged_path` (aliased where a local var shadows) to each file's imports.

- [ ] **Step 4: Run** `.venv/bin/pytest tests/unit/core/test_baseline.py tests/unit/core/test_baseline_generate.py tests/unit/core/test_judge_run.py -q` — Expected: new path test PASSES; fixture-path failures fixed in Task 12.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(weft): relocate baseline.yaml + judged.yaml to .weft/wardline/ via core/paths"
```

---

## Task 5: Sibling discovery prefers `.weft/<sibling>/ephemeral.port`, tolerates legacy

**Files:**
- Modify: `src/wardline/core/config.py` (`_loomweave_published_url`, `_filigree_published_url`)
- Modify: `src/wardline/install/detect.py` (`_filigree_url_from_project`)
- Test: `tests/unit/core/test_config.py` (extend) + a detect test.

- [ ] **Step 1: Write the failing test**

```python
def test_loomweave_published_prefers_weft(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    (tmp_path / ".weft" / "loomweave").mkdir(parents=True)
    (tmp_path / ".weft" / "loomweave" / "ephemeral.port").write_text("7777", encoding="ascii")
    from wardline.core.config import resolve_loomweave_url
    assert resolve_loomweave_url(None, tmp_path) == "http://127.0.0.1:7777"


def test_loomweave_published_legacy_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    (tmp_path / ".loomweave").mkdir()
    (tmp_path / ".loomweave" / "ephemeral.port").write_text("8888", encoding="ascii")
    from wardline.core.config import resolve_loomweave_url
    assert resolve_loomweave_url(None, tmp_path) == "http://127.0.0.1:8888"


def test_filigree_published_prefers_weft(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    (tmp_path / ".weft" / "filigree").mkdir(parents=True)
    (tmp_path / ".weft" / "filigree" / "ephemeral.port").write_text("9001", encoding="ascii")
    from wardline.core.config import resolve_filigree_url
    assert resolve_filigree_url(None, tmp_path) == "http://localhost:9001/api/weft/scan-results"
```

- [ ] **Step 2: Run to verify it fails** — Expected: only legacy `.loomweave`/`.filigree` paths are read.

- [ ] **Step 3: Edit `_loomweave_published_url` / `_filigree_published_url` in `config.py`.**

Factor the read so it tries the preferred `.weft/<sibling>/ephemeral.port` first, then the legacy `.<sibling>/ephemeral.port`:

```python
from wardline.core.paths import sibling_state_dir, legacy_sibling_dir  # add import

def _read_port_file(root: Path, sibling: str) -> int | None:
    for base in (sibling_state_dir(root, sibling), legacy_sibling_dir(root, sibling)):
        port_file = base / "ephemeral.port"
        try:
            raw = port_file.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            continue
        if raw.isdigit() and 1 <= (port := int(raw)) <= 65535:
            return port
    return None


def _loomweave_published_url(root: Path) -> str | None:
    port = _read_port_file(root, "loomweave")
    return f"http://127.0.0.1:{port}" if port is not None else None


def _filigree_published_url(root: Path) -> str | None:
    port = _read_port_file(root, "filigree")
    return f"http://localhost:{port}/api/weft/scan-results" if port is not None else None
```

Update the two functions' docstrings (the `.loomweave/ephemeral.port` / `.filigree/ephemeral.port` references) to "`.weft/<sibling>/ephemeral.port` (preferred) or the legacy `.<sibling>/ephemeral.port`".

- [ ] **Step 4: Edit `detect.py` `_filigree_url_from_project`** to use the same prefer/fallback (it currently hardcodes `.filigree/ephemeral.port`):

```python
from wardline.core.paths import sibling_state_dir, legacy_sibling_dir

def _filigree_url_from_project(root: Path) -> str | None:
    for base in (sibling_state_dir(root, "filigree"), legacy_sibling_dir(root, "filigree")):
        port_file = base / "ephemeral.port"
        if not port_file.is_file():
            continue
        text = port_file.read_text(encoding="utf-8", errors="replace").strip()
        if text.isdigit() and 1 <= (port := int(text)) <= 65535:
            return f"http://localhost:{port}/api/weft/scan-results"
    return None
```

- [ ] **Step 5: Run** `.venv/bin/pytest tests/unit/core/test_config.py -q -k "published or weft or legacy"` — Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/core/config.py src/wardline/install/detect.py tests/unit/core/test_config.py
git commit -m "feat(weft): sibling port discovery prefers .weft/<sibling>/, tolerates legacy dot-dir"
```

---

## Task 6: `record_bindings` → `detect_siblings` (detect-only, no config write)

**Files:**
- Modify: `src/wardline/install/detect.py` (replace `record_bindings`; delete dead stanza-writer helpers)
- Modify: `src/wardline/cli/install.py:63`, `src/wardline/install/doctor.py:283`
- Test: `tests/unit/install/` (update any record_bindings test) + new detect-only test.

- [ ] **Step 1: Write the failing test**

```python
def test_detect_siblings_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    from wardline.install.detect import detect_siblings
    result = detect_siblings(tmp_path)
    assert set(result) == {"loomweave", "filigree"}
    assert not (tmp_path / "weft.toml").exists()      # never authored
    assert not (tmp_path / "wardline.yaml").exists()   # legacy file never created
```

- [ ] **Step 2: Run to verify it fails** — Expected: `detect_siblings` undefined.

- [ ] **Step 3: Replace `record_bindings` with `detect_siblings` in `detect.py`.**

```python
def detect_siblings(root: Path) -> dict[str, str]:
    """Detect sibling tools without persisting anything.

    Binding persistence was dropped in the Weft config consolidation: live URLs
    are discovered via the published ``.weft/<sibling>/ephemeral.port`` rung (see
    ``core/config.resolve_*_url``); an operator who wants a fixed URL sets it by
    hand in ``weft.toml [wardline.<sibling>].url``. We never write the operator's
    config file. Returns a per-sibling human-readable status.
    """
    results: dict[str, str] = {}
    for key, detector in (("loomweave", _detect_loomweave), ("filigree", _detect_filigree)):
        present, url, source = detector(root)
        if not present:
            results[key] = "absent"
        elif url:
            results[key] = f"detected ({source} URL)"
        else:
            results[key] = "detected (no URL — set weft.toml [wardline.%s].url or rely on live discovery)" % key
    return results
```

Delete the now-dead helpers: `_live_stanza`, `_COMMENTED`, `_has_live_key`, `_has_install_marker`, `_already_recorded`, `_replace_commented_binding` — **but first grep** `doctor.py` (`_check_bindings` imports `_already_recorded`, `_has_live_key`, `_has_install_marker`). Those are used by doctor's `_check_bindings`, which is also being simplified in Task 8 — coordinate: remove them only after Task 8 drops `_check_bindings`'s text-marker logic. If executing Task 6 before Task 8, keep the helpers and just add `detect_siblings`; delete the dead helpers in Task 8's commit. Update the module docstring (line 1) to drop "record bindings in wardline.yaml".

- [ ] **Step 4: Update callers.**

`cli/install.py:63` — `for name, status in record_bindings(root).items():` → `for name, status in detect_siblings(root).items():` (update the import on line 12). Adjust the surrounding echo text if it says "wired"/"recorded" → "detected".

`install/doctor.py` — `repair_install` (line 283) calls `record_bindings(root)`; replace with `detect_siblings(root)` and set `statuses["bindings"] = "detected"`. Update the import (line 17-24 block).

- [ ] **Step 5: Run** `.venv/bin/pytest tests/unit/install/ -q` — Expected: detect-only test PASSES; old record_bindings tests removed/updated in Task 12.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/install/detect.py src/wardline/cli/install.py src/wardline/install/doctor.py tests/unit/install/
git commit -m "feat(weft): drop binding persistence — detect_siblings reports, live discovery resolves, weft.toml stays operator-owned"
```

---

## Task 7: `activate_pack` → guidance-only

**Files:**
- Modify: `src/wardline/install/pack.py`, `src/wardline/cli/install.py:85`
- Test: `tests/unit/install/test_pack.py` (update)

- [ ] **Step 1: Write the failing test**

```python
def test_activate_pack_emits_guidance_writes_nothing(tmp_path):
    from wardline.install.pack import activate_pack
    msg = activate_pack(tmp_path, "myorg.trustpack")
    assert "weft.toml" in msg and "packs" in msg and "myorg.trustpack" in msg
    assert not (tmp_path / "weft.toml").exists()
    assert not (tmp_path / "wardline.yaml").exists()
```

- [ ] **Step 2: Run to verify it fails** — Expected: `activate_pack` still writes config.

- [ ] **Step 3: Rewrite `activate_pack`.**

```python
def activate_pack(root: Path, pack_name: str) -> str:
    """Return operator guidance for activating a trust-grammar pack.

    Packs import and execute code (see the ``_is_local_pack`` guard in
    ``core/config``), so they MUST be operator-authored — wardline never writes
    the shared, read-only ``weft.toml``. This emits the snippet for the operator
    to add by hand; runtime trust is still asserted separately via ``--trust-pack``.
    """
    return (
        f"To activate trust-grammar pack {pack_name!r}, add it to weft.toml under "
        f"[wardline]:\n\n    [wardline]\n    packs = [{pack_name!r}]\n\n"
        f"then pass --trust-pack {pack_name} at scan/judge time."
    )
```

(The `root` arg is now unused but kept for the caller's call shape; if mypy/ruff flags it, prefix `_root` or keep and `# noqa`-free by referencing in a no-op — prefer renaming the param to `root` and leaving it; ruff's ARG rules are not enabled here — verify with the lint run.)

- [ ] **Step 4: Update `cli/install.py:85`** — `status = activate_pack(root, pack)` still returns a string; ensure the echo prints it as guidance (it likely already does `click.echo(status)`), and that this path no longer claims the pack was "activated". Adjust wording to "guidance".

- [ ] **Step 5: Run** `.venv/bin/pytest tests/unit/install/test_pack.py -q` — Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/wardline/install/pack.py src/wardline/cli/install.py tests/unit/install/test_pack.py
git commit -m "feat(weft): activate_pack emits operator guidance (packs stay operator-authored in weft.toml, never CLI-written)"
```

---

## Task 8: `doctor` — config check reads `weft.toml`, layout checks, may create own subtree

**Files:**
- Modify: `src/wardline/install/doctor.py` (`_check_config`, `_check_bindings`, `_config_url`, `machine_readable_doctor`)
- Test: `tests/unit/install/test_doctor*.py` (update) + new layout test.

- [ ] **Step 1: Write the failing test**

```python
def test_doctor_config_check_reads_weft_toml(tmp_path):
    (tmp_path / "weft.toml").write_text("[wardline]\nsource_roots = [\"src\"]\n", encoding="utf-8")
    from wardline.install.doctor import machine_readable_doctor
    payload = machine_readable_doctor(tmp_path)
    cfg_check = next(c for c in payload["checks"] if c["id"] == "wardline.config")
    assert cfg_check["status"] == "ok"


def test_doctor_runs_clean_with_no_weft_toml(tmp_path):
    # acceptance: boots/checks with NO weft.toml and NO .weft subtree
    from wardline.install.doctor import machine_readable_doctor
    payload = machine_readable_doctor(tmp_path)
    cfg_check = next(c for c in payload["checks"] if c["id"] == "wardline.config")
    assert cfg_check["status"] == "ok"
```

- [ ] **Step 2: Run to verify it fails** — Expected: `_check_config` still loads `root / "wardline.yaml"`.

- [ ] **Step 3: Edit `doctor.py`.**

- `_check_config` (125): `load(root / "wardline.yaml")` → `load(weft_config_path(root))`; the `fixed=` expression at line 226 `not (root / "wardline.yaml").exists()` → `not weft_config_path(root).exists()`.
- `_config_url` (164-167): `load(root / "wardline.yaml")` → `load(weft_config_path(root))`.
- `_check_bindings` (105-122): it currently parses `wardline.yaml` text for `wardline-install:` markers. With persistence dropped, simplify it to a **detection report** that never reads config text: report which siblings are present (via `_detect_loomweave`/`_detect_filigree`) and whether a URL resolves — without the marker/`_has_live_key` machinery. Suggested:

```python
def _check_bindings(root: Path) -> CheckResult:
    detected = [k for k, det in (("loomweave", _detect_loomweave), ("filigree", _detect_filigree))
                if det(root)[0]]
    if not detected:
        return CheckResult("bindings", True, "no siblings detected")
    return CheckResult("bindings", True, "detected: " + ", ".join(detected))
```
Drop the now-unused imports `_already_recorded`, `_has_install_marker`, `_has_live_key` from the `install.detect` import block, and `record_bindings` (replaced by `detect_siblings` in Task 6). After this, delete the dead helpers in `detect.py` (deferred from Task 6 Step 3).
- Add `from wardline.core.paths import weft_config_path` to doctor's imports.
- **doctor MAY create its own subtree:** in `repair_install`, after the other repairs, ensure the state dir exists (harmless, idempotent, never touches weft.toml or a sibling):
```python
    from wardline.core.paths import weft_state_dir
    weft_state_dir(root).mkdir(parents=True, exist_ok=True)
    statuses["state_dir"] = "ensured"
```

- [ ] **Step 4: Run** `.venv/bin/pytest tests/unit/install/ -q` — Expected: new doctor tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/doctor.py src/wardline/install/detect.py tests/unit/install/
git commit -m "feat(weft): doctor reads weft.toml, reports sibling detection, may create own .weft/wardline subtree (never writes weft.toml/siblings)"
```

---

## Task 9: MCP resources + remaining server config-path references

**Files:**
- Modify: `src/wardline/mcp/resources.py:50`, `src/wardline/mcp/server.py:399,672,699,907`
- Test: `tests/unit/mcp/test_server_query_explain.py`, `test_server_suppression.py` (update)

- [ ] **Step 1:** Replace every MCP default config path `(... or (path / "wardline.yaml"))` / `root / "wardline.yaml"` with `weft_config_path(...)`:
  - `resources.py:50` `config_mod.load(root / "wardline.yaml")` → `config_mod.load(weft_config_path(root))`
  - `server.py:399` `_cfg(args, path) or (path / "wardline.yaml")` → `_cfg(args, path) or weft_config_path(path)`
  - `server.py:672` already handled in Task 3 (waiver_add) — confirm removed.
  - `server.py:699` `load(cfg_path or (path / "wardline.yaml"))` → `load(cfg_path or weft_config_path(path))`
  - `server.py:907` help string "(wardline.yaml)" → "(weft.toml [wardline])"
  Add `from wardline.core.paths import weft_config_path` to both files.

- [ ] **Step 2: Run** `.venv/bin/pytest tests/unit/mcp/ -q` — Expected: green after Task 12 fixture updates; config-path-resolution tests green now.

- [ ] **Step 3: Commit**

```bash
git add src/wardline/mcp/ tests/unit/mcp/
git commit -m "feat(weft): MCP config-path defaults resolve to weft.toml [wardline]"
```

---

## Task 10: Root `.gitignore`

**Files:** Modify `.gitignore`

- [ ] **Step 1:** Remove the dead `.wardline-cache/` line (used nowhere in src/tests) and the `wardline.yaml` line (config is now the committed, operator-authored `weft.toml`). Do **NOT** add `.weft/` (its contents — baseline/judged/waivers — are committed). Do **NOT** ignore `weft.toml`. Leave `.loomweave`, `.filigree/`, `.env`, `loomweave.yaml` as-is (legacy sibling locations still valid during the transition window; `.env` carries secrets).

- [ ] **Step 2: Verify** `git check-ignore -v .weft/wardline/baseline.yaml` prints **nothing** (not ignored), and `git check-ignore weft.toml` prints nothing.

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore(weft): drop dead .wardline-cache + wardline.yaml ignores; keep .weft/wardline committed, weft.toml tracked"
```

---

## Task 11: Mechanical sweep — source string/docstring/help/error references

**Files (dispatch a subagent per cluster; each does Edit only, NEVER git):**

- [ ] `core/errors.py:9` docstring "wardline.yaml is malformed" → "weft.toml [wardline] is malformed".
- [ ] `core/config.py` docstrings at lines 1, 338, 341, 379, 382, 427 — `wardline.yaml` → `weft.toml [wardline]` (or "weft.toml" for the URL-precedence lines).
- [ ] `core/discovery.py:23` comment "poisoned in-root wardline.yaml" → "weft.toml".
- [ ] `core/judged.py:4,7` docstrings `.wardline/judged.yaml` → `.weft/wardline/judged.yaml`; "Hand-authored waivers stay in `wardline.yaml`" → "Hand-authored waivers live in `.weft/wardline/waivers.yaml`".
- [ ] `core/waivers.py` docstring (done in Task 3 — verify).
- [ ] `cli/scan.py:73,97,103,193,238`, `cli/judge.py:48,66,79,97`, `cli/attest.py:52,65`, `cli/main.py:101,124,137,177,190`, `cli/fix.py:43`, `cli/file_finding.py:32,59`, `cli/scan_file_findings.py:25` — `--config`/help/error strings mentioning `wardline.yaml` → `weft.toml`/`weft.toml [wardline]`; `.wardline/judged.yaml` → `.weft/wardline/judged.yaml`. **The `config_path or (path / "wardline.yaml")` default-path expressions** in `cli/scan.py:193,238`, `cli/judge.py:97`, `cli/fix.py:43`, `core/judge_run.py:151`, `core/assure.py:249`, `core/attest.py:306` → `weft_config_path(path/root)` (import from `core.paths`).
- [ ] `scanner/analyzer.py:625,642` `Location(path="wardline.yaml")` → `Location(path="weft.toml")` (these are synthetic finding locations for config-sourced diagnostics).
- [ ] `scanner/context.py:134`, `scanner/grammar.py:153` docstrings; `scanner/rules/contradictory_trust.py:46` comment "promote via wardline.yaml" → "promote via weft.toml [wardline]".
- [ ] `install/detect.py` `_loomweave_url_from_config` reads sibling `loomweave.yaml` — **leave as legacy-tolerate** (sibling's own file; not our config). `install/pack.py` docstring (done Task 7).
- [ ] `filigree/config.py:5`, `loomweave/config.py:3` docstrings say tokens come "never from wardline.yaml" → "never from weft.toml" (cosmetic; the env/.env behaviour is unchanged).

After each cluster: `.venv/bin/ruff check src/ && .venv/bin/mypy src/wardline`. Commit per cluster.

---

## Task 12: Test sweep (~20 files)

Update fixtures/assertions from YAML `wardline.yaml` config + `.wardline/` paths to TOML `weft.toml [wardline]` + `.weft/wardline/`. **Dispatch subagents (Edit only, NEVER git).** Files: `tests/unit/core/test_config.py`, `test_run.py`, `test_judge_run.py`, `test_judged.py`, `test_explain_chain.py`, `test_dossier_assembler.py`, `test_decorator_coverage.py`, `test_baseline.py`, `test_baseline_generate.py`, `test_agent_summary.py`, `tests/unit/cli/test_cli.py`, `tests/unit/mcp/test_server_suppression.py`, `test_server_query_explain.py`, `tests/unit/loomweave/test_client_by_sei.py`, `tests/unit/install/test_mcp_json.py`, `tests/unit/scanner/taint/test_decorator_provider.py` (the `myweft.wardline` string is a NON-target false positive — leave), `tests/golden/identity/test_identity_parity.py` + `README.md` (likely `metadata.wardline.*` false positives — verify, leave if so), `tests/e2e/test_loomweave_live.py`.

Pattern guidance for fixtures that wrote config:
```python
# OLD: (root / "wardline.yaml").write_text("rules:\n  enable: ['*']\n")
# NEW: (root / "weft.toml").write_text("[wardline.rules]\nenable = ['*']\n")
# OLD waiver fixture in config → write .weft/wardline/waivers.yaml instead, OR use add_waiver(waivers_path(root), ...)
```

- [ ] Run the FULL suite after the sweep: `.venv/bin/pytest -q`. Expected: all green (the suite was ~2525 at rc3; confirm count, zero failures). Triage every red — "pre-existing" is not acceptable.
- [ ] Commit: `git commit -am "test(weft): migrate fixtures to weft.toml + .weft/wardline layout"`

---

## Task 13: Docs sweep (~29 files)

**Dispatch subagents (Edit only, NEVER git).** Priority/load-bearing:
- [ ] `docs/guides/configuration.md` — **rewrite config examples from YAML to TOML** `[wardline]` tables; rename the page's framing to "weft.toml `[wardline]`". This is the biggest doc change.
- [ ] `docs/guides/weft.md` — "See also: Configuration — `wardline.yaml` keys" → "weft.toml `[wardline]` keys"; any `--filigree-url ... else wardline.yaml` mentions.
- [ ] `docs/guides/suppression.md` — waivers now `.weft/wardline/waivers.yaml`; baseline `.weft/wardline/baseline.yaml`.
- [ ] `docs/guides/judge.md` — `.wardline/judged.yaml` → `.weft/wardline/judged.yaml`.
- [ ] `docs/guides/attestation.md` — attest key still in `.env` (unchanged); any `.wardline/` path refs → `.weft/wardline/`.
- [ ] `docs/reference/cli.md`, `docs/reference/finding-lifecycle-vocabulary.md` — path/config references.
- [ ] `UPGRADING.md` — add a **breaking-change** entry: config moved `wardline.yaml` → `weft.toml [wardline]` (no fallback); state moved `.wardline/` → `.weft/wardline/`; `waiver_add` writes `.weft/wardline/waivers.yaml`; `activate-pack` is guidance-only; binding persistence dropped (live discovery). Migration steps for an operator with an existing `wardline.yaml`.
- [ ] `CHANGELOG.md` — `[Unreleased]` Changed/Breaking entries mirroring UPGRADING.
- [ ] **Archived specs/plans** under `docs/superpowers/specs/archive/` and `plans/archive/` — historical record; **leave unchanged** (do not rewrite history). `docs/integration/*` and non-archive specs: update only if they describe current behaviour an agent would act on; otherwise leave.
- [ ] Run `.venv/bin/mkdocs build --strict` (the `docs` extra). Expected: clean build, no broken links.
- [ ] Commit: `git commit -am "docs(weft): config in weft.toml [wardline], state in .weft/wardline; UPGRADING + CHANGELOG breaking notes"`

---

## Task 14: Acceptance verification + review

- [ ] **Acceptance A — runs with NO weft.toml and NO `.weft/` subtree.** In a clean temp dir with a trivial `.py` source:
  ```bash
  cd $(mktemp -d) && mkdir src && echo "x = 1" > src/a.py
  /home/john/wardline/.venv/bin/wardline scan src    # exits cleanly, gate runs on defaults
  /home/john/wardline/.venv/bin/wardline doctor       # config check ok, no crash
  ```
  Expected: scan boots on `config_schema` defaults, writes `findings.jsonl`, gate runs; doctor's `wardline.config` check is `ok`. No `.wardline/` created.
- [ ] **Acceptance B — SEI scheme untouched.** `grep -rn "loomweave:eid:" src/` is unchanged from baseline; `git diff --stat origin/rc4 -- src/wardline/loomweave/` shows no SEI-scheme edits (only the port-discovery path change in `config.py`, which is the federation-discovery layer, not the SEI scheme).
- [ ] **Full gates:** `.venv/bin/pytest -q` (all green), `.venv/bin/ruff check src/ tests/`, `.venv/bin/mypy src/wardline`, `.venv/bin/mkdocs build --strict`.
- [ ] **Self-scan dogfood:** `.venv/bin/wardline scan src/wardline --format sarif --output /tmp/self.sarif` — no new engine errors from the migration (e.g. no `WLN-ENGINE-*` regressions).
- [ ] **Code-review panel** (per feedback_default_code_review_panel — SA, ST, PE, QE, SAE, SecArch) on the whole diff. Fix Important findings immediately; file the rest.
- [ ] **Live federation check (best-effort):** if a Filigree dashboard is up, confirm `wardline scan --filigree-url ...` still emits, and that published-port discovery resolves from `.weft/filigree/ephemeral.port` if present (else legacy). Note the federation members must adopt `.weft/<member>/` for the preferred rung to fire; legacy fallback keeps it working meanwhile.
- [ ] **Final commit / PR:** all work on `rc4` (single-branch rule). Update the version/CHANGELOG as appropriate for the RC.

---

## Self-review (spec coverage)

- Two surfaces (weft.toml read-only; `.weft/wardline/` owned) → Tasks 1,2,3,4,8. ✓
- Read `[wardline]` if present else config_schema defaults → Task 2 (`test_absent_file_returns_defaults`, `test_no_wardline_table_is_defaults`). ✓
- Installer/CLI/doctor MUST NOT write weft.toml → Tasks 6 (detect-only), 7 (pack guidance), 8 (doctor); tests assert `not weft.toml.exists()`. ✓
- doctor MAY create own `.weft/wardline/`, MUST NOT touch sibling subtree → Task 8 (`weft_state_dir(root).mkdir`). ✓
- Sibling discovery prefers `.weft/<sibling>/`, tolerates legacy → Task 5. ✓
- DROP `.wardline/` no fallback → Tasks 4 + 10 (and Acceptance A asserts `.wardline/` is never created). ✓
- Installs/runs with no weft.toml + no `.weft/` → Acceptance A; Task 2 defaults. ✓
- SEI scheme frozen → Acceptance B. ✓
- Federated ≠ sloppy / kill the scatter → Task 1 central `core/paths`. ✓
- Security guards preserved (`_is_local_pack`, `_is_safe_url`) → Task 2 Step 4 keeps them. ✓
