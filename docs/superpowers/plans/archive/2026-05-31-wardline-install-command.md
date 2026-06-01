# Wardline `install` Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `wardline install` command that pushes agent-enablement artifacts (a hash-fenced CLAUDE.md/AGENTS.md block, a `wardline-gate` skill, a merged `.mcp.json` entry) into a consuming project and detects/records Clarion & Filigree bindings.

**Architecture:** A prerequisite config change promotes `clarion.url`/`filigree.url` to runtime-read fields (precedence: CLI flag > env var > `wardline.yaml`). The command itself is a thin `click` orchestrator over four single-responsibility helper modules under `src/wardline/install/`, plus a bundled skill shipped as package data. No SessionStart hook — freshness is re-run-on-demand only.

**Tech Stack:** Python 3 stdlib (`hashlib`, `re`, `json`, `shutil`, `os`), `click`, `pyyaml`/`jsonschema` (already present via the `scanner` extra). No new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-05-31-wardline-install-command-design.md`

---

## File Structure

**Create:**
- `src/wardline/install/__init__.py` — package marker (empty).
- `src/wardline/install/block.py` — render + hash-fence inject/replace for `CLAUDE.md`/`AGENTS.md`.
- `src/wardline/install/skill.py` — copy the bundled skill into `.claude`/`.agents`.
- `src/wardline/install/mcp_json.py` — merge the `wardline` entry into `.mcp.json`.
- `src/wardline/install/detect.py` — presence detection + `wardline.yaml` stanza append.
- `src/wardline/cli/install.py` — the `install` click command + summary output.
- `src/wardline/skills/wardline-gate/SKILL.md` — bundled skill (package data).
- Tests: `tests/unit/install/test_block.py`, `test_skill.py`, `test_mcp_json.py`, `test_detect.py`; `tests/unit/cli/test_install.py`; additions to `tests/unit/core/test_config.py`.

**Modify:**
- `src/wardline/core/config_schema.py` — schema `url` properties for `clarion`/`filigree`.
- `src/wardline/core/config.py` — `clarion_url`/`filigree_url` properties + `resolve_*` helpers.
- `src/wardline/cli/scan.py` — resolve both URLs via the helpers.
- `src/wardline/cli/mcp.py` — resolve `clarion_url` via the helper.
- `src/wardline/cli/main.py` — register the `install` command.
- `pyproject.toml` — force-include the bundled skill in the wheel.
- `docs/agents.md` + `CHANGELOG.md` — document the command.

---

## Task 1: Config — `clarion.url` / `filigree.url` become real fields

**Files:**
- Modify: `src/wardline/core/config_schema.py:41-42`
- Modify: `src/wardline/core/config.py:17-28` (dataclass) and add module-level helpers
- Test: `tests/unit/core/test_config.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/core/test_config.py`:

```python
from pathlib import Path

from wardline.core import config as config_mod
from wardline.core.config import (
    WardlineConfig,
    load,
    resolve_clarion_url,
    resolve_filigree_url,
)


def test_clarion_and_filigree_url_read_from_config(tmp_path: Path) -> None:
    (tmp_path / "wardline.yaml").write_text(
        'clarion:\n  url: "http://clarion.local:9100"\n'
        'filigree:\n  url: "http://filigree.local/api/loom/scan-results"\n',
        encoding="utf-8",
    )
    cfg = load(tmp_path / "wardline.yaml")
    assert cfg.clarion_url == "http://clarion.local:9100"
    assert cfg.filigree_url == "http://filigree.local/api/loom/scan-results"


def test_urls_default_to_none() -> None:
    cfg = WardlineConfig()
    assert cfg.clarion_url is None
    assert cfg.filigree_url is None


def test_unknown_clarion_key_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "wardline.yaml").write_text(
        "clarion:\n  bogus: 1\n", encoding="utf-8"
    )
    import pytest

    from wardline.core.errors import ConfigError

    with pytest.raises(ConfigError):
        load(tmp_path / "wardline.yaml")


def test_resolve_precedence_flag_beats_env_beats_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wardline.yaml").write_text(
        'clarion:\n  url: "http://from-config"\n', encoding="utf-8"
    )
    # config only
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    assert resolve_clarion_url(None, tmp_path, None) == "http://from-config"
    # env beats config
    monkeypatch.setenv("WARDLINE_CLARION_URL", "http://from-env")
    assert resolve_clarion_url(None, tmp_path, None) == "http://from-env"
    # flag beats env
    assert resolve_clarion_url("http://from-flag", tmp_path, None) == "http://from-flag"


def test_resolve_filigree_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://fil-env")
    assert resolve_filigree_url(None, tmp_path, None) == "http://fil-env"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/core/test_config.py -k "clarion_url or filigree_url or resolve or unknown_clarion" -v`
Expected: FAIL — `resolve_clarion_url` / `clarion_url` do not exist; `test_unknown_clarion_key_is_rejected` fails because the schema currently allows any property under `clarion`.

- [ ] **Step 3: Tighten the schema**

In `src/wardline/core/config_schema.py`, replace lines 41-42:

```python
        "filigree": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"url": {"type": "string"}},
        },
        "clarion": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"url": {"type": "string"}},
        },
```

- [ ] **Step 4: Add properties + resolution helpers**

In `src/wardline/core/config.py`, add these two properties to the `WardlineConfig` dataclass (after line 28, inside the class body — properties are class-level so they coexist with `slots=True`):

```python
    @property
    def clarion_url(self) -> str | None:
        value = self.clarion.get("url")
        return value if isinstance(value, str) else None

    @property
    def filigree_url(self) -> str | None:
        value = self.filigree.get("url")
        return value if isinstance(value, str) else None
```

Add `import os` to the top imports, and append these module-level helpers after the `load` function:

```python
_CLARION_URL_ENV = "WARDLINE_CLARION_URL"
_FILIGREE_URL_ENV = "WARDLINE_FILIGREE_URL"


def _config_for(root: Path, config_path: Path | None) -> WardlineConfig:
    return load(config_path if config_path is not None else root / "wardline.yaml")


def resolve_clarion_url(
    flag: str | None, root: Path, config_path: Path | None = None
) -> str | None:
    """Clarion URL by precedence: explicit flag > env var > wardline.yaml."""
    if flag is not None:
        return flag
    env = os.environ.get(_CLARION_URL_ENV)
    if env:
        return env
    return _config_for(root, config_path).clarion_url


def resolve_filigree_url(
    flag: str | None, root: Path, config_path: Path | None = None
) -> str | None:
    """Filigree Loom URL by precedence: explicit flag > env var > wardline.yaml."""
    if flag is not None:
        return flag
    env = os.environ.get(_FILIGREE_URL_ENV)
    if env:
        return env
    return _config_for(root, config_path).filigree_url
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/core/test_config.py -v`
Expected: PASS (all, including the new cases).

- [ ] **Step 6: Commit**

```bash
git add src/wardline/core/config_schema.py src/wardline/core/config.py tests/unit/core/test_config.py
git commit -m "feat(config): clarion.url/filigree.url become runtime-read fields with flag>env>config resolution

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Wire URL resolution into `scan` and `mcp`

**Files:**
- Modify: `src/wardline/cli/scan.py:52-56` (top of `scan` body)
- Modify: `src/wardline/cli/mcp.py:18-20`
- Test: `tests/unit/cli/test_install.py` (new file; holds CLI-wiring tests too)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/cli/test_install.py`:

```python
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli


def test_scan_reads_filigree_url_from_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wardline.yaml").write_text(
        'filigree:\n  url: "http://configured-filigree"\n', encoding="utf-8"
    )
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    captured: dict[str, object] = {}

    class _FakeEmitter:
        def __init__(self, url: str) -> None:
            captured["url"] = url

        def emit(self, findings):  # noqa: ANN001
            from wardline.core.filigree_emit import EmitResult

            return EmitResult(reachable=False)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _FakeEmitter)
    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["url"] == "http://configured-filigree"


def test_mcp_resolves_clarion_url_from_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wardline.yaml").write_text(
        'clarion:\n  url: "http://configured-clarion"\n', encoding="utf-8"
    )
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, *, root: Path, clarion_url: str | None = None) -> None:
            captured["clarion_url"] = clarion_url
            self.rpc = self

        def run_stdio(self) -> None:
            captured["ran"] = True

    monkeypatch.setattr("wardline.cli.mcp.WardlineMCPServer", _FakeServer)
    result = CliRunner().invoke(cli, ["mcp", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["clarion_url"] == "http://configured-clarion"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/cli/test_install.py -k "scan_reads or mcp_resolves" -v`
Expected: FAIL — `scan` ignores config `filigree.url`; `mcp` passes the raw `None` flag through.

- [ ] **Step 3: Wire `scan`**

In `src/wardline/cli/scan.py`, add the import (next to the other `wardline.core.run` import):

```python
from wardline.core.config import resolve_clarion_url, resolve_filigree_url
```

Then at the very start of the `scan` body (immediately after the docstring on line 52), insert:

```python
    filigree_url = resolve_filigree_url(filigree_url, path, config_path)
    clarion_url = resolve_clarion_url(clarion_url, path, config_path)
```

- [ ] **Step 4: Wire `mcp`**

Replace the body of `src/wardline/cli/mcp.py`'s `mcp` function (lines 19-20) with:

```python
    """Run the Wardline MCP server over stdio (JSON-RPC 2.0)."""
    from wardline.core.config import resolve_clarion_url

    clarion_url = resolve_clarion_url(clarion_url, root, None)
    WardlineMCPServer(root=root, clarion_url=clarion_url).rpc.run_stdio()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/cli/test_install.py -v`
Expected: PASS.

- [ ] **Step 6: Run the full CLI/scan suite for regressions**

Run: `.venv/bin/pytest tests/unit/cli -v`
Expected: PASS (no behavior change when no config/env/flag URL is set).

- [ ] **Step 7: Commit**

```bash
git add src/wardline/cli/scan.py src/wardline/cli/mcp.py tests/unit/cli/test_install.py
git commit -m "feat(cli): scan/mcp resolve clarion+filigree URLs from config/env

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `block.py` — hash-fenced instruction block

**Files:**
- Create: `src/wardline/install/__init__.py` (empty)
- Create: `src/wardline/install/block.py`
- Test: `tests/unit/install/test_block.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/install/test_block.py`:

```python
from pathlib import Path

from wardline.install.block import inject_block, render_block


def test_render_block_is_fenced_and_mentions_the_gate() -> None:
    block = render_block()
    assert block.startswith("<!-- wardline:instructions:v")
    assert block.rstrip().endswith("<!-- /wardline:instructions -->")
    assert "wardline scan" in block
    assert "wardline-gate" in block


def test_inject_into_absent_file_creates_it(tmp_path: Path) -> None:
    f = tmp_path / "CLAUDE.md"
    assert inject_block(f) == "created"
    assert f.read_text(encoding="utf-8").count("wardline:instructions") == 1


def test_inject_appends_when_no_fence_present(tmp_path: Path) -> None:
    f = tmp_path / "CLAUDE.md"
    f.write_text("# My project\n\nExisting content.\n", encoding="utf-8")
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    assert "Existing content." in text
    assert "wardline:instructions" in text


def test_reinject_same_version_is_unchanged(tmp_path: Path) -> None:
    f = tmp_path / "CLAUDE.md"
    inject_block(f)
    before = f.read_text(encoding="utf-8")
    assert inject_block(f) == "unchanged"
    assert f.read_text(encoding="utf-8") == before


def test_inject_replaces_a_stale_fenced_block(tmp_path: Path) -> None:
    f = tmp_path / "CLAUDE.md"
    f.write_text(
        "intro\n\n<!-- wardline:instructions:v0:deadbeef -->\nOLD BODY\n"
        "<!-- /wardline:instructions -->\n\noutro\n",
        encoding="utf-8",
    )
    assert inject_block(f) == "updated"
    text = f.read_text(encoding="utf-8")
    assert "OLD BODY" not in text
    assert "intro" in text and "outro" in text
    assert text.count("wardline:instructions") == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/install/test_block.py -v`
Expected: FAIL — `wardline.install.block` does not exist.

- [ ] **Step 3: Implement `block.py`**

Create `src/wardline/install/__init__.py` (empty file), then `src/wardline/install/block.py`:

```python
"""Render + idempotently inject the hash-fenced wardline instruction block."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_BLOCK_VERSION = "1"

_BODY = (
    "This project uses **wardline** as its trust-boundary gate. Before handing "
    "back code that touches external input, run `wardline scan . --fail-on ERROR` "
    "(exit 0 = clean, 1 = gate tripped, 2 = wardline error) and fix findings at "
    "the boundary, not the sink. The full scan -> explain -> fix -> rescan loop "
    "and the baseline-vs-waiver discipline live in the `wardline-gate` skill and "
    "in `docs/agents.md`."
)

_FENCE_RE = re.compile(
    r"<!-- wardline:instructions:v\d+:[0-9a-f]+ -->.*?<!-- /wardline:instructions -->",
    re.DOTALL,
)


def _body_hash() -> str:
    return hashlib.sha256(_BODY.encode("utf-8")).hexdigest()[:8]


def render_block() -> str:
    return (
        f"<!-- wardline:instructions:v{_BLOCK_VERSION}:{_body_hash()} -->\n"
        f"{_BODY}\n"
        "<!-- /wardline:instructions -->"
    )


def inject_block(file_path: Path) -> str:
    """Create / append / replace the block. Returns created|updated|unchanged."""
    block = render_block()
    if not file_path.exists():
        file_path.write_text(block + "\n", encoding="utf-8")
        return "created"
    text = file_path.read_text(encoding="utf-8")
    match = _FENCE_RE.search(text)
    if match is None:
        sep = "" if text.endswith("\n") else "\n"
        file_path.write_text(f"{text}{sep}\n{block}\n", encoding="utf-8")
        return "updated"
    if match.group(0) == block:
        return "unchanged"
    new = text[: match.start()] + block + text[match.end() :]
    file_path.write_text(new, encoding="utf-8")
    return "updated"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/install/test_block.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/__init__.py src/wardline/install/block.py tests/unit/install/test_block.py
git commit -m "feat(install): hash-fenced instruction block render+inject

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Bundled `wardline-gate` skill + `skill.py` copier + packaging

**Files:**
- Create: `src/wardline/skills/wardline-gate/SKILL.md`
- Create: `src/wardline/install/skill.py`
- Modify: `pyproject.toml:55-57` (force-include)
- Test: `tests/unit/install/test_skill.py`

- [ ] **Step 1: Write the bundled skill**

Create `src/wardline/skills/wardline-gate/SKILL.md`:

```markdown
---
name: wardline-gate
description: >
  Use when scanning for or fixing trust-boundary / taint findings, when a
  `wardline scan` reports a defect, or when wiring wardline into an agent's
  edit-verify loop. Explains the scan -> explain -> fix-at-the-boundary ->
  rescan cycle and the baseline-vs-waiver discipline.
---

# Wardline: the trust-boundary gate

Wardline is a deterministic, whole-program static taint analyzer. It marks trust
boundaries with two decorators from `wardline.decorators`: `@external_boundary`
(untrusted data arriving from outside) and `@trusted` (a producer that must only
receive validated data). When untrusted data reaches a trusted producer it raises
`PY-WL-101` at `ERROR`.

## The loop

1. **Scan.** Run `wardline scan . --fail-on ERROR` (or call the `scan` MCP tool).
   Read the gate verdict and the active (non-suppressed) findings — `active` is
   the population the gate enforces on.
2. **Explain.** For each active defect, call `explain_taint` with the finding's
   `fingerprint`, `path`+`line`, and its `qualname` as `sink_qualname`. Do this
   right after the scan and before editing — a stale fingerprint returns an error.
   With a Clarion store configured, pass `chain: true` to walk the full taint
   chain back to the originating boundary.
3. **Fix at the BOUNDARY, not the sink.** Add validation or rejection at the hop
   where untrusted data should have been checked — not a band-aid at the sink.
4. **Re-scan.** Confirm the finding is gone.

## Exit codes (CLI path)

- `0` — clean (or gate not requested).
- `1` — the gate tripped: a non-suppressed defect at/above `--fail-on`.
- `2` — a wardline error (bad config, unreadable path). Not a finding.

Branch on the code. On a trip, read the structured report wardline just wrote —
the finding names the function, file, and lines, which is enough to locate the
leak.

## Suppression discipline

Prefer FIXING a finding. Suppress only a finding you have judged a true
non-issue, always with a reason:

- `baseline_create` / `baseline_update` — snapshot current defects so only NEW
  findings surface. A coarse, whole-set tool; requires a reason.
- `waiver_add` — waive ONE finding by fingerprint with a mandatory reason and an
  expiry date. An audited, time-boxed exception.
- `wardline judge` (opt-in, network) — an LLM pass that labels each defect
  TRUE/FALSE positive. Never runs automatically, never folded into scan; fails
  loud with no API key so "couldn't triage" is never mistaken for "nothing to
  triage". Above-floor false positives can be recorded as audited suppressions.

## CLI vs MCP

- **CLI:** `wardline scan`, `wardline judge`, `wardline baseline create/update`.
  Branch on the exit code; read the findings file it writes.
- **MCP:** `wardline mcp` exposes `scan`, `explain_taint`, `judge` (network),
  `baseline_create`, `baseline_update`, `waiver_add`; resources
  `wardline://vocab|rules|config|config-schema`; and the `wardline:loop` prompt.
  The server is stateless — the read-only tools are pure functions of your code
  on disk and your config.
```

- [ ] **Step 2: Write the failing test**

Create `tests/unit/install/test_skill.py`:

```python
from pathlib import Path

from wardline.install.skill import install_skill


def test_install_skill_creates_both_targets(tmp_path: Path) -> None:
    results = install_skill(tmp_path)
    assert results == {".claude": "created", ".agents": "created"}
    for base in (".claude", ".agents"):
        skill = tmp_path / base / "skills" / "wardline-gate" / "SKILL.md"
        assert skill.is_file()
        assert "name: wardline-gate" in skill.read_text(encoding="utf-8")


def test_reinstall_overwrites(tmp_path: Path) -> None:
    install_skill(tmp_path)
    stale = tmp_path / ".claude" / "skills" / "wardline-gate" / "SKILL.md"
    stale.write_text("STALE", encoding="utf-8")
    results = install_skill(tmp_path)
    assert results[".claude"] == "overwritten"
    assert "name: wardline-gate" in stale.read_text(encoding="utf-8")
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/install/test_skill.py -v`
Expected: FAIL — `wardline.install.skill` does not exist.

- [ ] **Step 4: Implement `skill.py`**

Create `src/wardline/install/skill.py`:

```python
"""Copy the bundled wardline-gate skill into a project's .claude / .agents."""

from __future__ import annotations

import shutil
from pathlib import Path


def _skill_source() -> Path:
    # src/wardline/install/skill.py -> src/wardline/skills/wardline-gate
    return Path(__file__).resolve().parent.parent / "skills" / "wardline-gate"


def install_skill(root: Path) -> dict[str, str]:
    """Copy the skill into .claude/skills and .agents/skills (idempotent overwrite).

    Returns a per-target status: created | overwritten.
    """
    src = _skill_source()
    results: dict[str, str] = {}
    for base in (".claude", ".agents"):
        dest = root / base / "skills" / "wardline-gate"
        existed = dest.exists()
        if existed:
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dest)
        results[base] = "overwritten" if existed else "created"
    return results
```

- [ ] **Step 5: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/install/test_skill.py -v`
Expected: PASS.

- [ ] **Step 6: Force-include the skill in the wheel**

In `pyproject.toml`, under `[tool.hatch.build.targets.wheel.force-include]` (after line 57), add:

```toml
"src/wardline/skills/wardline-gate/SKILL.md" = "wardline/skills/wardline-gate/SKILL.md"
```

- [ ] **Step 7: Verify the wheel includes the skill**

Run: `.venv/bin/python -m build --wheel 2>/dev/null && .venv/bin/python -c "import zipfile,glob; z=zipfile.ZipFile(sorted(glob.glob('dist/*.whl'))[-1]); print([n for n in z.namelist() if 'wardline-gate' in n])"`
Expected: prints a list containing `wardline/skills/wardline-gate/SKILL.md`. (If `build` is unavailable, instead confirm `Path` resolution with: `.venv/bin/python -c "from wardline.install.skill import _skill_source; print((_skill_source()/'SKILL.md').is_file())"` → `True`.)

- [ ] **Step 8: Commit**

```bash
git add src/wardline/skills/wardline-gate/SKILL.md src/wardline/install/skill.py pyproject.toml tests/unit/install/test_skill.py
git commit -m "feat(install): bundle wardline-gate skill + copier, ship in wheel

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `mcp_json.py` — merge the wardline MCP entry

**Files:**
- Create: `src/wardline/install/mcp_json.py`
- Test: `tests/unit/install/test_mcp_json.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/install/test_mcp_json.py`:

```python
import json
from pathlib import Path

import pytest

from wardline.core.errors import WardlineError
from wardline.install.mcp_json import merge_mcp_entry

_WARDLINE_ENTRY = {"type": "stdio", "command": "wardline", "args": ["mcp", "--root", "."]}


def test_create_when_absent(tmp_path: Path) -> None:
    assert merge_mcp_entry(tmp_path) == "created"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["wardline"] == _WARDLINE_ENTRY


def test_merge_preserves_siblings(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"filigree": {"type": "stdio", "command": "filigree-mcp", "args": []}}}),
        encoding="utf-8",
    )
    assert merge_mcp_entry(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["filigree"]["command"] == "filigree-mcp"
    assert data["mcpServers"]["wardline"] == _WARDLINE_ENTRY


def test_idempotent_when_entry_matches(tmp_path: Path) -> None:
    merge_mcp_entry(tmp_path)
    assert merge_mcp_entry(tmp_path) == "unchanged"


def test_malformed_json_raises_without_clobbering(tmp_path: Path) -> None:
    bad = tmp_path / ".mcp.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(WardlineError):
        merge_mcp_entry(tmp_path)
    assert bad.read_text(encoding="utf-8") == "{not json"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/install/test_mcp_json.py -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement `mcp_json.py`**

Create `src/wardline/install/mcp_json.py`:

```python
"""Merge a `wardline` stdio server into a project's .mcp.json, preserving siblings."""

from __future__ import annotations

import json
from pathlib import Path

from wardline.core.errors import WardlineError

_ENTRY = {"type": "stdio", "command": "wardline", "args": ["mcp", "--root", "."]}


def merge_mcp_entry(root: Path) -> str:
    """Add/replace the `wardline` entry under mcpServers. Returns created|updated|unchanged."""
    path = root / ".mcp.json"
    if not path.exists():
        payload = {"mcpServers": {"wardline": dict(_ENTRY)}}
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return "created"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WardlineError(f"malformed .mcp.json: {exc}") from exc
    if not isinstance(data, dict):
        raise WardlineError(".mcp.json must be a JSON object")
    servers = data.get("mcpServers")
    if servers is None:
        servers = {}
        data["mcpServers"] = servers
    if not isinstance(servers, dict):
        raise WardlineError(".mcp.json mcpServers must be an object")
    if servers.get("wardline") == _ENTRY:
        return "unchanged"
    servers["wardline"] = dict(_ENTRY)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return "updated"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/install/test_mcp_json.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/mcp_json.py tests/unit/install/test_mcp_json.py
git commit -m "feat(install): merge wardline entry into .mcp.json (preserve siblings)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: `detect.py` — Clarion/Filigree detection + wardline.yaml stanzas

**Files:**
- Create: `src/wardline/install/detect.py`
- Test: `tests/unit/install/test_detect.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/install/test_detect.py`:

```python
from pathlib import Path

from wardline.install.detect import record_bindings


def test_no_siblings_writes_nothing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    results = record_bindings(tmp_path)
    assert results == {"clarion": "absent", "filigree": "absent"}
    assert not (tmp_path / "wardline.yaml").exists()


def test_filigree_marker_writes_commented_stanza(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")
    results = record_bindings(tmp_path)
    assert results["filigree"] == "detected (commented)"
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert "wardline-install:filigree" in text
    assert "# filigree:" in text


def test_env_url_writes_live_stanza(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_CLARION_URL", "http://clar:9100")
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    results = record_bindings(tmp_path)
    assert results["clarion"] == "wired (env URL)"
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert 'clarion:\n  url: "http://clar:9100"' in text


def test_existing_key_left_untouched(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_CLARION_URL", "http://new")
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / "wardline.yaml").write_text(
        'clarion:\n  url: "http://existing"\n', encoding="utf-8"
    )
    results = record_bindings(tmp_path)
    assert results["clarion"] == "present (left untouched)"
    assert (tmp_path / "wardline.yaml").read_text(encoding="utf-8").count("clarion:") == 1
    assert "http://new" not in (tmp_path / "wardline.yaml").read_text(encoding="utf-8")


def test_rerun_does_not_duplicate_commented_stanza(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")
    record_bindings(tmp_path)
    record_bindings(tmp_path)
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert text.count("wardline-install:filigree") == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/unit/install/test_detect.py -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement `detect.py`**

Create `src/wardline/install/detect.py`:

```python
"""Detect sibling tools (Clarion, Filigree) and record bindings in wardline.yaml.

Presence is detectable (a marker file or a binary on PATH / an env URL); a service
URL is not discoverable, so we write a live stanza only when an env URL is set,
otherwise a commented stanza for the user to fill. Writes are text-appends guarded
by a key/sentinel check, so re-running never duplicates or clobbers.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path


def _detect_clarion() -> tuple[bool, str | None]:
    url = os.environ.get("WARDLINE_CLARION_URL") or None
    present = bool(url) or shutil.which("clarion") is not None
    return present, url


def _detect_filigree(root: Path) -> tuple[bool, str | None]:
    url = os.environ.get("WARDLINE_FILIGREE_URL") or None
    present = bool(url) or (root / ".filigree.conf").is_file()
    return present, url


def _live_stanza(key: str, url: str) -> str:
    return f'{key}:\n  url: "{url}"  # wardline-install:{key} (from env at install time)\n'


_COMMENTED = {
    "clarion": (
        "# wardline-install:clarion — Clarion taint store detected, no URL configured.\n"
        "# Set the taint-store URL to enable per-entity taint-fact enrichment:\n"
        "# clarion:\n"
        '#   url: "http://localhost:PORT"\n'
    ),
    "filigree": (
        "# wardline-install:filigree — Filigree detected (.filigree.conf), no URL configured.\n"
        "# Set the Loom scan-results URL to POST findings into Filigree:\n"
        "# filigree:\n"
        '#   url: "http://localhost:PORT/api/loom/scan-results"\n'
    ),
}


def _already_recorded(text: str, key: str) -> bool:
    # Live key at column 0, or our sentinel from a previous commented write.
    return bool(re.search(rf"(?m)^{key}:", text)) or f"wardline-install:{key}" in text


def record_bindings(root: Path) -> dict[str, str]:
    """Detect siblings and append stanzas to wardline.yaml. Returns per-key status."""
    cfg = root / "wardline.yaml"
    text = cfg.read_text(encoding="utf-8") if cfg.exists() else ""
    detections = {"clarion": _detect_clarion(), "filigree": _detect_filigree(root)}
    additions: list[str] = []
    results: dict[str, str] = {}
    for key, (present, url) in detections.items():
        if not present:
            results[key] = "absent"
            continue
        if _already_recorded(text + "".join(additions), key):
            results[key] = "present (left untouched)"
            continue
        if url:
            additions.append(_live_stanza(key, url))
            results[key] = "wired (env URL)"
        else:
            additions.append(_COMMENTED[key])
            results[key] = "detected (commented)"
    if additions:
        sep = "" if (not text or text.endswith("\n")) else "\n"
        lead = "\n" if text else ""
        cfg.write_text(text + sep + lead + "\n".join(additions), encoding="utf-8")
    return results
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/unit/install/test_detect.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/install/detect.py tests/unit/install/test_detect.py
git commit -m "feat(install): detect Clarion/Filigree and record wardline.yaml bindings

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: `install` CLI command + registration

**Files:**
- Create: `src/wardline/cli/install.py`
- Modify: `src/wardline/cli/main.py:13-14,29` (import + register)
- Test: `tests/unit/cli/test_install.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/cli/test_install.py`:

```python
def test_install_writes_all_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "CLAUDE.md").is_file()
    assert (tmp_path / "AGENTS.md").is_file()
    assert (tmp_path / ".claude" / "skills" / "wardline-gate" / "SKILL.md").is_file()
    assert (tmp_path / ".agents" / "skills" / "wardline-gate" / "SKILL.md").is_file()
    assert (tmp_path / ".mcp.json").is_file()
    assert "CLAUDE.md" in result.output


def test_install_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "unchanged" in result.output


def test_install_opt_outs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    result = CliRunner().invoke(
        cli,
        ["install", "--root", str(tmp_path), "--no-agents-md", "--no-skill",
         "--no-mcp", "--no-bindings"],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "CLAUDE.md").is_file()
    assert not (tmp_path / "AGENTS.md").exists()
    assert not (tmp_path / ".claude").exists()
    assert not (tmp_path / ".mcp.json").exists()


def test_install_fails_2_on_malformed_mcp_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".mcp.json").write_text("{bad", encoding="utf-8")
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 2
    assert "malformed .mcp.json" in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/cli/test_install.py -k install_writes -v`
Expected: FAIL — `install` command is not registered (`No such command 'install'`).

- [ ] **Step 3: Implement `cli/install.py`**

Create `src/wardline/cli/install.py`:

```python
# src/wardline/cli/install.py
"""`wardline install` — push agent-enablement artifacts into a project."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core.errors import WardlineError
from wardline.install.block import inject_block
from wardline.install.detect import record_bindings
from wardline.install.mcp_json import merge_mcp_entry
from wardline.install.skill import install_skill


@click.command()
@click.option("--root", type=click.Path(exists=True, file_okay=False, path_type=Path),
              default=".", help="Project root to install into (default: cwd).")
@click.option("--no-claude-md", is_flag=True, help="Skip the CLAUDE.md instruction block.")
@click.option("--no-agents-md", is_flag=True, help="Skip the AGENTS.md instruction block.")
@click.option("--no-skill", is_flag=True, help="Skip the wardline-gate skill.")
@click.option("--no-mcp", is_flag=True, help="Skip wiring .mcp.json.")
@click.option("--no-bindings", is_flag=True, help="Skip Clarion/Filigree detection.")
def install(
    root: Path,
    no_claude_md: bool,
    no_agents_md: bool,
    no_skill: bool,
    no_mcp: bool,
    no_bindings: bool,
) -> None:
    """Install wardline's agent-facing guidance and sibling bindings into ROOT."""
    lines: list[str] = []
    try:
        if not no_claude_md:
            lines.append(f"CLAUDE.md: {inject_block(root / 'CLAUDE.md')}")
        if not no_agents_md:
            lines.append(f"AGENTS.md: {inject_block(root / 'AGENTS.md')}")
        if not no_skill:
            for base, status in install_skill(root).items():
                lines.append(f"skill {base}/skills/wardline-gate: {status}")
        if not no_mcp:
            lines.append(f".mcp.json (wardline entry): {merge_mcp_entry(root)}")
        if not no_bindings:
            for name, status in record_bindings(root).items():
                lines.append(f"{name}: {status}")
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo("wardline install:")
    for line in lines:
        click.echo(f"  {line}")
```

- [ ] **Step 4: Register the command**

In `src/wardline/cli/main.py`, add after line 13 (`from wardline.cli.mcp import mcp`):

```python
from wardline.cli.install import install
```

and after line 29 (`cli.add_command(mcp)`):

```python
cli.add_command(install)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/cli/test_install.py -v`
Expected: PASS (all install tests).

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (no regressions across the suite).

- [ ] **Step 7: Lint + type-check**

Run: `.venv/bin/ruff check src/wardline/install src/wardline/cli/install.py && .venv/bin/mypy src/wardline/install src/wardline/cli/install.py`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/wardline/cli/install.py src/wardline/cli/main.py tests/unit/cli/test_install.py
git commit -m "feat(cli): wardline install command (block + skill + mcp + bindings)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Docs + changelog

**Files:**
- Modify: `docs/agents.md` (add an install section near the top)
- Modify: `CHANGELOG.md` ([Unreleased] Added)

- [ ] **Step 1: Add the install section to `docs/agents.md`**

Insert after the intro (before "## Gate the agent's work"):

```markdown
## One-command setup: `wardline install`

`wardline install` wires wardline into a project's agent context in one step:

- injects a small, hash-fenced block into `CLAUDE.md` and `AGENTS.md` pointing
  the agent at the gate and the loop;
- installs the `wardline-gate` skill into `.claude/skills/` and `.agents/skills/`;
- merges a `wardline` entry into `.mcp.json` (preserving any existing servers);
- detects a Clarion taint store (`clarion` on `PATH` or `WARDLINE_CLARION_URL`)
  and a Filigree project (`.filigree.conf`), recording a `clarion:`/`filigree:`
  binding in `wardline.yaml` — live when a URL env var is set, otherwise a
  commented stanza for you to fill.

```console
$ wardline install
wardline install:
  CLAUDE.md: created
  AGENTS.md: created
  skill .claude/skills/wardline-gate: created
  skill .agents/skills/wardline-gate: created
  .mcp.json (wardline entry): created
  clarion: detected (commented)
  filigree: detected (commented)
```

It is idempotent (re-run to refresh after upgrading wardline) and non-interactive
(safe in CI). Opt out of any piece with `--no-claude-md`, `--no-agents-md`,
`--no-skill`, `--no-mcp`, or `--no-bindings`. There is no SessionStart hook —
freshness is enforced only when you re-run `wardline install`.

Once installed, the MCP server resolves the Clarion URL from `wardline.yaml`, so
the `.mcp.json` entry stays a bare `wardline mcp --root .` with no URL in its args.
```

- [ ] **Step 2: Add the changelog entry**

Under `## [Unreleased]` → `### Added` in `CHANGELOG.md`:

```markdown
- `wardline install`: one-command agent enablement — injects a hash-fenced
  instruction block into `CLAUDE.md`/`AGENTS.md`, installs the `wardline-gate`
  skill, merges a `wardline` entry into `.mcp.json`, and detects Clarion/Filigree
  to record bindings in `wardline.yaml`. `clarion.url`/`filigree.url` are now
  runtime-read config fields (precedence: CLI flag > env var > `wardline.yaml`).
```

- [ ] **Step 3: Build the docs strictly (catches broken markdown/nav)**

Run: `.venv/bin/mkdocs build --strict 2>&1 | tail -5` (if the `docs` extra is installed; otherwise skip and eyeball the file).
Expected: build succeeds, no warnings.

- [ ] **Step 4: Commit**

```bash
git add docs/agents.md CHANGELOG.md
git commit -m "docs: document wardline install (agents.md + changelog)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification

- [ ] **Full suite + lint + types:** `.venv/bin/pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
- [ ] **Live smoke test in a temp dir:**

```bash
tmp=$(mktemp -d); .venv/bin/wardline install --root "$tmp"; \
  ls -R "$tmp"; cat "$tmp/CLAUDE.md"; \
  .venv/bin/wardline install --root "$tmp" | grep -q unchanged && echo "IDEMPOTENT OK"; \
  rm -rf "$tmp"
```

Expected: all artifacts present on the first run; the second run reports `unchanged` for the block/mcp entries.

---

## Notes / resolved open points

- **`.mcp.json` command string:** resolved to bare `wardline` — `pyproject.toml`
  declares `[project.scripts] wardline = "wardline.cli.main:cli"`, so the console
  script is on PATH wherever the package is installed.
- **Uninstall path:** out of scope. The fenced block, the skill directory, and the
  `.mcp.json` entry are all safe to remove by hand; add an `uninstall` verb later
  only if usage demands it.
- **No SessionStart hook:** deliberate (see spec non-goals). This is the "inject
  half" of filigree's pipeline.
