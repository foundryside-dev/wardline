# Wardline SP0 — Product Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable, installable `wardline` package whose only job is to lock the contracts and module boundaries (the `Finding` record, config, plugin Protocols, CLI shell, `findings.jsonl` writer) so SP1–SP5 are pure fill-in.

**Architecture:** `src`-layout Python package. A zero-dependency `core` (the `Finding` contract + errors), a `scanner`-extra layer (config/discovery/emit/CLI needing `pyyaml`+`click`), and empty `scanner`/`rules` packages exposing only Protocols. `wardline scan` wires discovery → a no-op analyzer → a JSONL sink and exits 0. No analysis, no governance, no network.

**Tech Stack:** Python ≥3.12, hatchling, click, pyyaml, pytest (+pytest-randomly, pytest-cov), ruff, mypy(strict).

**Spec:** [`docs/superpowers/specs/2026-05-29-wardline-sp0-skeleton-design.md`](../specs/2026-05-29-wardline-sp0-skeleton-design.md)
**Contract:** [`docs/integration/2026-05-29-wardline-loom-integration-brief.md`](../../integration/2026-05-29-wardline-loom-integration-brief.md)

---

## File Structure

| File | Responsibility |
|---|---|
| `pyproject.toml` | Packaging, optional extras, entry point, ruff/mypy/pytest config |
| `src/wardline/_version.py` | `__version__` (single source) |
| `src/wardline/__init__.py` | Re-export `__version__` |
| `src/wardline/py.typed` | PEP 561 marker |
| `src/wardline/core/errors.py` | `WardlineError`/`ConfigError`/`DiscoveryError` (stdlib-only) |
| `src/wardline/core/finding.py` | `Severity`/`Kind`/`Location`/`Finding` + `to_jsonl` + placeholder fingerprint + Filigree mapping helpers (stdlib-only) |
| `src/wardline/core/config.py` | `WardlineConfig` + `load()` (pyyaml) |
| `src/wardline/core/discovery.py` | `discover()` — source-root walk + excludes (stdlib) |
| `src/wardline/core/emit.py` | `Sink` Protocol + `JsonlSink` |
| `src/wardline/core/protocols.py` | `Analyzer`/`Rule` Protocols (SP1/SP2 plug points) |
| `src/wardline/scanner/__init__.py` | `NoOpAnalyzer` (SP1 replaces) |
| `src/wardline/rules/__init__.py` | empty package (SP2 fills) |
| `src/wardline/cli/main.py` | `click` group + `baseline`/`judge` stubs + `--version` |
| `src/wardline/cli/scan.py` | `wardline scan` command |
| `tests/...` | unit tests + a sample-project fixture + self-hosting seed |

Boundary rule: `core/finding.py` and `core/errors.py` import only the stdlib (zero-dep). Everything else may use the `scanner` extra. `core` never imports `scanner`/`rules`/`cli`.

---

## Task 1: Packaging, version, and tooling config

**Files:**
- Create: `src/wardline/_version.py`, `src/wardline/__init__.py`, `src/wardline/py.typed`
- Create: `pyproject.toml`, `README.md`, `CHANGELOG.md`
- Test: `tests/unit/test_package.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_package.py
import wardline


def test_version_is_exported() -> None:
    assert isinstance(wardline.__version__, str)
    assert wardline.__version__.startswith("0.1.0")
```

- [ ] **Step 2: Create the version + package init**

```python
# src/wardline/_version.py
__version__ = "0.1.0.dev0"
```

```python
# src/wardline/__init__.py
"""Wardline — generic semantic-tainting static analyzer."""

from wardline._version import __version__

__all__ = ["__version__"]
```

Create empty `src/wardline/py.typed` (zero bytes).

- [ ] **Step 3: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "wardline"
description = "Generic semantic-tainting static analyzer for Python"
readme = "README.md"
license = "MIT"
requires-python = ">=3.12"
dynamic = ["version"]
dependencies = []
authors = [{ name = "John Morrissey" }]
keywords = ["static-analysis", "taint-analysis", "trust-boundaries", "security"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Programming Language :: Python :: 3.12",
    "Typing :: Typed",
]

[project.optional-dependencies]
scanner = ["pyyaml>=6.0", "jsonschema>=4.0", "click>=8.0"]
loom = ["httpx>=0.27"]
judge = ["litellm>=1.0", "anthropic>=0.50.0"]
dev = [
    "wardline[scanner]",
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-randomly",
    "ruff>=0.8.0",
    "mypy>=1.13.0",
    "types-PyYAML",
]

[project.scripts]
wardline = "wardline.cli.main:cli"

[project.urls]
Homepage = "https://github.com/foundryside/wardline"
Repository = "https://github.com/foundryside/wardline"
Issues = "https://github.com/foundryside/wardline/issues"
Changelog = "https://github.com/foundryside/wardline/blob/main/CHANGELOG.md"

[tool.hatch.version]
path = "src/wardline/_version.py"

[tool.hatch.build.targets.wheel]
packages = ["src/wardline"]

[tool.ruff]
line-length = 120
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]

[tool.mypy]
python_version = "3.12"
strict = true
files = ["src/wardline"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-m 'not network'"
markers = ["network: tests that need network (none until SP4)"]
```

Create `README.md` (one paragraph + composition-law pointer) and a seeded `CHANGELOG.md` with an `## [Unreleased]` section.

- [ ] **Step 4: Install and run the test**

Run: `pip install -e .[dev] && pytest tests/unit/test_package.py -v`
Expected: PASS; `pip install` succeeds.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml README.md CHANGELOG.md src/wardline/_version.py src/wardline/__init__.py src/wardline/py.typed tests/unit/test_package.py
git commit -m "feat(sp0): package skeleton, version, tooling config"
```

---

## Task 2: Error hierarchy

**Files:**
- Create: `src/wardline/core/__init__.py` (empty), `src/wardline/core/errors.py`
- Test: `tests/unit/core/test_errors.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_errors.py
import pytest

from wardline.core.errors import ConfigError, DiscoveryError, WardlineError


def test_subclasses_are_wardline_errors() -> None:
    assert issubclass(ConfigError, WardlineError)
    assert issubclass(DiscoveryError, WardlineError)


def test_raises_and_is_catchable_as_base() -> None:
    with pytest.raises(WardlineError):
        raise ConfigError("bad config")
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `pytest tests/unit/core/test_errors.py -v`
Expected: FAIL with `ModuleNotFoundError: wardline.core.errors`

- [ ] **Step 3: Implement**

Create empty `src/wardline/core/__init__.py`.

```python
# src/wardline/core/errors.py
"""Wardline error hierarchy (stdlib-only)."""


class WardlineError(Exception):
    """Base class for all expected Wardline errors."""


class ConfigError(WardlineError):
    """Raised when wardline.yaml is malformed or invalid."""


class DiscoveryError(WardlineError):
    """Raised when source discovery cannot proceed."""
```

- [ ] **Step 4: Run it to confirm it passes**

Run: `pytest tests/unit/core/test_errors.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/__init__.py src/wardline/core/errors.py tests/unit/core/test_errors.py
git commit -m "feat(sp0): error hierarchy"
```

---

## Task 3: The `Finding` record

**Files:**
- Create: `src/wardline/core/finding.py`
- Test: `tests/unit/core/test_finding.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_finding.py
import json

from wardline.core.finding import (
    Finding,
    Kind,
    Location,
    Severity,
    compute_placeholder_fingerprint,
)


def _finding(**kw: object) -> Finding:
    base = dict(
        rule_id="WLN-001",
        message="boundary not validated",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/pkg/mod.py", line_start=10, line_end=10),
        fingerprint="deadbeef",
    )
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


def test_finding_is_frozen() -> None:
    f = _finding()
    try:
        f.rule_id = "x"  # type: ignore[misc]
    except AttributeError:
        return
    raise AssertionError("Finding must be immutable")


def test_to_jsonl_is_valid_json_with_expected_keys() -> None:
    line = _finding(suggestion="validate at boundary", qualname="pkg.mod.f").to_jsonl()
    obj = json.loads(line)
    assert obj["rule_id"] == "WLN-001"
    assert obj["severity"] == "ERROR"
    assert obj["kind"] == "defect"
    assert obj["location"]["line_start"] == 10
    assert obj["fingerprint"] == "deadbeef"
    assert obj["suggestion"] == "validate at boundary"
    assert obj["qualname"] == "pkg.mod.f"
    assert "\n" not in line


def test_placeholder_fingerprint_is_deterministic_and_path_sensitive() -> None:
    a = compute_placeholder_fingerprint("WLN-001", "a.py", 1, "msg")
    b = compute_placeholder_fingerprint("WLN-001", "a.py", 1, "msg")
    c = compute_placeholder_fingerprint("WLN-001", "b.py", 1, "msg")
    assert a == b
    assert a != c
    assert len(a) == 64
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `pytest tests/unit/core/test_finding.py -v`
Expected: FAIL with `ModuleNotFoundError: wardline.core.finding`

- [ ] **Step 3: Implement**

```python
# src/wardline/core/finding.py
"""The Finding record — the central cross-subproject contract (stdlib-only).

Designed as a superset of Filigree's scan-results intake so SP4 emission is
serialization, not translation. Wardline owns the analysis *fact*; finding
*lifecycle* (status, seen_count, issue_id, timestamps) is Filigree's domain
and is deliberately absent here.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARN = "WARN"
    INFO = "INFO"
    NONE = "NONE"  # facts / metrics carry no defect severity


class Kind(StrEnum):
    DEFECT = "defect"
    FACT = "fact"
    CLASSIFICATION = "classification"
    METRIC = "metric"
    SUGGESTION = "suggestion"


@dataclass(frozen=True, slots=True)
class Location:
    path: str  # repo-relative POSIX path; Filigree's file_path anchor
    line_start: int | None = None
    line_end: int | None = None
    col_start: int | None = None  # retained for SARIF; Filigree ignores columns
    col_end: int | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str  # namespaced WLN-*
    message: str
    severity: Severity
    kind: Kind
    location: Location
    fingerprint: str  # stable cross-run identity (SP1 folds in taint-path identity)
    suggestion: str | None = None
    qualname: str | None = None  # dotted module.qualified_name (Clarion reconciliation key)
    confidence: float | None = None
    related_entities: tuple[str, ...] = ()
    properties: Mapping[str, Any] = field(default_factory=dict)

    def to_jsonl(self) -> str:
        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "kind": self.kind.value,
            "location": {
                "path": self.location.path,
                "line_start": self.location.line_start,
                "line_end": self.location.line_end,
                "col_start": self.location.col_start,
                "col_end": self.location.col_end,
            },
            "fingerprint": self.fingerprint,
            "suggestion": self.suggestion,
            "qualname": self.qualname,
            "confidence": self.confidence,
            "related_entities": list(self.related_entities),
            "properties": dict(self.properties),
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=False)


# --- SP0 PLACEHOLDER ---------------------------------------------------------
# SP1 REPLACES this to fold in taint-path identity so two paths into one sink
# (same file/rule/line, different path) get distinct fingerprints. Do not treat
# this as the final scheme.
def compute_placeholder_fingerprint(
    rule_id: str, path: str, line_start: int | None, message: str
) -> str:
    digest = hashlib.sha256()
    digest.update(f"{rule_id}\x00{path}\x00{line_start}\x00{message}".encode())
    return digest.hexdigest()
```

- [ ] **Step 4: Run it to confirm it passes**

Run: `pytest tests/unit/core/test_finding.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/finding.py tests/unit/core/test_finding.py
git commit -m "feat(sp0): Finding record + placeholder fingerprint"
```

---

## Task 4: Filigree mapping helpers (pure)

**Files:**
- Modify: `src/wardline/core/finding.py` (append helpers)
- Test: `tests/unit/core/test_loom_mapping.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_loom_mapping.py
from wardline.core.finding import (
    Finding,
    Kind,
    Location,
    Severity,
    severity_to_filigree,
    to_filigree_metadata,
)


def test_severity_map_covers_all_levels() -> None:
    assert severity_to_filigree(Severity.CRITICAL) == "critical"
    assert severity_to_filigree(Severity.ERROR) == "high"
    assert severity_to_filigree(Severity.WARN) == "medium"
    assert severity_to_filigree(Severity.INFO) == "low"
    assert severity_to_filigree(Severity.NONE) == "info"


def test_metadata_namespaces_rich_fields_under_wardline() -> None:
    f = Finding(
        rule_id="WLN-002",
        message="m",
        severity=Severity.WARN,
        kind=Kind.DEFECT,
        location=Location(path="a.py", line_start=1),
        fingerprint="fp123",
        qualname="pkg.mod.C.method",
        confidence=0.9,
        properties={"cwe": "CWE-200"},
    )
    md = to_filigree_metadata(f)
    assert set(md) == {"wardline"}
    wl = md["wardline"]
    assert wl["fingerprint"] == "fp123"
    assert wl["internal_severity"] == "WARN"
    assert wl["kind"] == "defect"
    assert wl["qualname"] == "pkg.mod.C.method"
    assert wl["confidence"] == 0.9
    assert wl["properties"] == {"cwe": "CWE-200"}


def test_metadata_omits_absent_optionals() -> None:
    f = Finding(
        rule_id="WLN-003",
        message="m",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=Location(path="a.py"),
        fingerprint="fp",
    )
    wl = to_filigree_metadata(f)["wardline"]
    assert "qualname" not in wl
    assert "confidence" not in wl
    assert "properties" not in wl
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `pytest tests/unit/core/test_loom_mapping.py -v`
Expected: FAIL with `ImportError: cannot import name 'severity_to_filigree'`

- [ ] **Step 3: Implement (append to `src/wardline/core/finding.py`)**

```python
# --- Loom wire mapping (pure; SP4 uses these to build the scan-results body) -
_SEVERITY_TO_FILIGREE: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.ERROR: "high",
    Severity.WARN: "medium",
    Severity.INFO: "low",
    Severity.NONE: "info",
}


def severity_to_filigree(severity: Severity) -> str:
    """Map Wardline's 4-level (+NONE) vocabulary to Filigree's 5-level set."""
    return _SEVERITY_TO_FILIGREE[severity]


def to_filigree_metadata(finding: Finding) -> dict[str, Any]:
    """Build the ``metadata.wardline.*`` subtree (semantic JSON, not byte-stable)."""
    wardline: dict[str, Any] = {
        "fingerprint": finding.fingerprint,
        "internal_severity": finding.severity.value,
        "kind": finding.kind.value,
    }
    if finding.qualname is not None:
        wardline["qualname"] = finding.qualname
    if finding.confidence is not None:
        wardline["confidence"] = finding.confidence
    if finding.related_entities:
        wardline["related_entities"] = list(finding.related_entities)
    if finding.properties:
        wardline["properties"] = dict(finding.properties)
    return {"wardline": wardline}
```

- [ ] **Step 4: Run it to confirm it passes**

Run: `pytest tests/unit/core/test_loom_mapping.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/finding.py tests/unit/core/test_loom_mapping.py
git commit -m "feat(sp0): severity map + metadata.wardline.* builder"
```

---

## Task 5: Config loader

**Files:**
- Create: `src/wardline/core/config.py`
- Test: `tests/unit/core/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_config.py
import pytest

from wardline.core.config import WardlineConfig, load
from wardline.core.errors import ConfigError


def test_load_missing_returns_defaults(tmp_path) -> None:
    cfg = load(tmp_path / "nope.yaml")
    assert cfg.source_roots == (".",)
    assert cfg.exclude == ()
    assert cfg.rules_enable == ("*",)


def test_load_parses_known_keys_and_reserved_blocks(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text(
        "source_roots: [src]\n"
        "exclude: ['**/x/**']\n"
        "rules:\n  enable: ['WLN-001']\n  severity: {WLN-001: WARN}\n"
        "filigree: {url: http://x}\n",
        encoding="utf-8",
    )
    cfg = load(p)
    assert cfg.source_roots == ("src",)
    assert cfg.exclude == ("**/x/**",)
    assert cfg.rules_enable == ("WLN-001",)
    assert cfg.rules_severity == {"WLN-001": "WARN"}
    assert cfg.filigree == {"url": "http://x"}


def test_unknown_key_warns_not_raises(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("bogus: 1\n", encoding="utf-8")
    with pytest.warns(UserWarning, match="unknown wardline.yaml key"):
        cfg = load(p)
    assert isinstance(cfg, WardlineConfig)


def test_malformed_yaml_raises_config_error(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("a: [1, 2\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(p)
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `pytest tests/unit/core/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: wardline.core.config`

- [ ] **Step 3: Implement**

```python
# src/wardline/core/config.py
"""wardline.yaml loader. Uses the `scanner` extra (pyyaml)."""

from __future__ import annotations

import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from wardline.core.errors import ConfigError

_KNOWN_KEYS = frozenset(
    {"source_roots", "exclude", "rules", "baseline", "judge", "filigree", "clarion"}
)


@dataclass(frozen=True, slots=True)
class WardlineConfig:
    source_roots: tuple[str, ...] = (".",)
    exclude: tuple[str, ...] = ()
    rules_enable: tuple[str, ...] = ("*",)
    rules_severity: Mapping[str, str] = field(default_factory=dict)
    # reserved (declared so the shape is visible; inert in SP0)
    baseline: Mapping[str, Any] = field(default_factory=dict)
    judge: Mapping[str, Any] = field(default_factory=dict)
    filigree: Mapping[str, Any] = field(default_factory=dict)
    clarion: Mapping[str, Any] = field(default_factory=dict)


def load(path: Path | None) -> WardlineConfig:
    if path is None or not path.exists():
        return WardlineConfig()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed {path.name}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path.name} must be a mapping at top level")
    for key in raw:
        if key not in _KNOWN_KEYS:
            warnings.warn(f"unknown wardline.yaml key: {key!r}", stacklevel=2)
    rules = raw.get("rules") or {}
    return WardlineConfig(
        source_roots=tuple(raw.get("source_roots") or (".",)),
        exclude=tuple(raw.get("exclude") or ()),
        rules_enable=tuple(rules.get("enable") or ("*",)),
        rules_severity=dict(rules.get("severity") or {}),
        baseline=dict(raw.get("baseline") or {}),
        judge=dict(raw.get("judge") or {}),
        filigree=dict(raw.get("filigree") or {}),
        clarion=dict(raw.get("clarion") or {}),
    )
```

- [ ] **Step 4: Run it to confirm it passes**

Run: `pytest tests/unit/core/test_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/config.py tests/unit/core/test_config.py
git commit -m "feat(sp0): wardline.yaml config loader"
```

---

## Task 6: Source discovery

**Files:**
- Create: `src/wardline/core/discovery.py`
- Create: fixture `tests/fixtures/sample_project/wardline.yaml`, `tests/fixtures/sample_project/src/pkg/__init__.py`, `tests/fixtures/sample_project/src/pkg/mod.py`
- Test: `tests/unit/core/test_discovery.py`

- [ ] **Step 1: Create the fixture project**

`tests/fixtures/sample_project/wardline.yaml`:
```yaml
source_roots: ["src"]
```
`tests/fixtures/sample_project/src/pkg/__init__.py`: empty file.
`tests/fixtures/sample_project/src/pkg/mod.py`:
```python
def greet(name: str) -> str:
    return f"hi {name}"
```

- [ ] **Step 2: Write the failing test**

```python
# tests/unit/core/test_discovery.py
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.discovery import discover

FIXTURE = Path(__file__).parents[2] / "fixtures" / "sample_project"


def test_discovers_python_files_under_source_roots() -> None:
    cfg = WardlineConfig(source_roots=("src",))
    files = discover(FIXTURE, cfg)
    names = sorted(p.name for p in files)
    assert names == ["__init__.py", "mod.py"]


def test_respects_exclude_globs() -> None:
    cfg = WardlineConfig(source_roots=("src",), exclude=("*/mod.py",))
    files = discover(FIXTURE, cfg)
    assert all(p.name != "mod.py" for p in files)


def test_skips_pycache_and_warns_on_missing_root() -> None:
    cfg = WardlineConfig(source_roots=("does_not_exist",))
    import pytest

    with pytest.warns(UserWarning, match="source root does not exist"):
        files = discover(FIXTURE, cfg)
    assert files == []
```

- [ ] **Step 3: Run it to confirm it fails**

Run: `pytest tests/unit/core/test_discovery.py -v`
Expected: FAIL with `ModuleNotFoundError: wardline.core.discovery`

- [ ] **Step 4: Implement**

```python
# src/wardline/core/discovery.py
"""Discover Python source files under configured roots (stdlib-only)."""

from __future__ import annotations

import fnmatch
import warnings
from collections.abc import Iterable
from pathlib import Path

from wardline.core.config import WardlineConfig

_ALWAYS_SKIP = frozenset({"__pycache__", ".venv", "venv", ".git", ".mypy_cache"})


def discover(root: Path, config: WardlineConfig) -> list[Path]:
    root = root.resolve()
    found: list[Path] = []
    for src in config.source_roots:
        base = (root / src).resolve()
        if not base.exists():
            warnings.warn(f"source root does not exist: {base}", stacklevel=2)
            continue
        for path in sorted(base.rglob("*.py")):
            if any(part in _ALWAYS_SKIP for part in path.parts):
                continue
            relposix = (
                path.relative_to(root).as_posix()
                if path.is_relative_to(root)
                else path.as_posix()
            )
            if _excluded(relposix, config.exclude):
                continue
            found.append(path)
    return found


def _excluded(relposix: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(relposix, pattern) for pattern in patterns)
```

- [ ] **Step 5: Run it to confirm it passes**

Run: `pytest tests/unit/core/test_discovery.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/wardline/core/discovery.py tests/unit/core/test_discovery.py tests/fixtures/sample_project
git commit -m "feat(sp0): source discovery + sample fixture project"
```

---

## Task 7: Protocols and the JSONL sink

**Files:**
- Create: `src/wardline/core/protocols.py`, `src/wardline/core/emit.py`
- Test: `tests/unit/core/test_emit.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_emit.py
import json
from pathlib import Path

from wardline.core.emit import JsonlSink
from wardline.core.finding import Finding, Kind, Location, Severity


def _finding() -> Finding:
    return Finding(
        rule_id="WLN-001",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="a.py", line_start=1),
        fingerprint="fp",
    )


def test_jsonl_sink_writes_one_line_per_finding(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "findings.jsonl"
    JsonlSink(out).write([_finding(), _finding()])
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["rule_id"] == "WLN-001"


def test_jsonl_sink_writes_empty_file_for_no_findings(tmp_path: Path) -> None:
    out = tmp_path / "findings.jsonl"
    JsonlSink(out).write([])
    assert out.exists()
    assert out.read_text(encoding="utf-8") == ""
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `pytest tests/unit/core/test_emit.py -v`
Expected: FAIL with `ModuleNotFoundError: wardline.core.emit`

- [ ] **Step 3: Implement protocols + sink**

```python
# src/wardline/core/protocols.py
"""Plug-point Protocols for SP1 (Analyzer) and SP2 (Rule)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding


class Analyzer(Protocol):
    def analyze(
        self, files: Sequence[Path], config: WardlineConfig, *, root: Path
    ) -> Sequence[Finding]: ...


class Rule(Protocol):
    rule_id: str

    def check(self, *args: object, **kwargs: object) -> Sequence[Finding]: ...
```

```python
# src/wardline/core/emit.py
"""Finding sinks. JsonlSink is the SP0 default output."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from wardline.core.finding import Finding


class Sink(Protocol):
    def write(self, findings: Sequence[Finding]) -> None: ...


class JsonlSink:
    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, findings: Sequence[Finding]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("w", encoding="utf-8") as handle:
            for finding in findings:
                handle.write(finding.to_jsonl())
                handle.write("\n")
```

- [ ] **Step 4: Run it to confirm it passes**

Run: `pytest tests/unit/core/test_emit.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/core/protocols.py src/wardline/core/emit.py tests/unit/core/test_emit.py
git commit -m "feat(sp0): Analyzer/Rule/Sink protocols + JsonlSink"
```

---

## Task 8: No-op analyzer

**Files:**
- Create: `src/wardline/scanner/__init__.py`, `src/wardline/rules/__init__.py`
- Test: `tests/unit/scanner/test_noop.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/scanner/test_noop.py
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.scanner import NoOpAnalyzer


def test_noop_analyzer_returns_no_findings() -> None:
    result = NoOpAnalyzer().analyze([Path("a.py")], WardlineConfig(), root=Path("."))
    assert list(result) == []
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `pytest tests/unit/scanner/test_noop.py -v`
Expected: FAIL with `ImportError: cannot import name 'NoOpAnalyzer'`

- [ ] **Step 3: Implement**

Create empty `src/wardline/rules/__init__.py` with a docstring `"""Wardline rules. SP2 fills this package."""`.

```python
# src/wardline/scanner/__init__.py
"""Wardline analysis engine. SP0 ships a no-op; SP1 replaces it."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Finding


class NoOpAnalyzer:
    """Placeholder analyzer that performs no analysis (SP0)."""

    def analyze(
        self, files: Sequence[Path], config: WardlineConfig, *, root: Path
    ) -> Sequence[Finding]:
        return []


__all__ = ["NoOpAnalyzer"]
```

- [ ] **Step 4: Run it to confirm it passes**

Run: `pytest tests/unit/scanner/test_noop.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/__init__.py src/wardline/rules/__init__.py tests/unit/scanner/test_noop.py
git commit -m "feat(sp0): no-op analyzer + empty rules package"
```

---

## Task 9: CLI — `scan`, stubs, and `--version`

**Files:**
- Create: `src/wardline/cli/__init__.py` (empty), `src/wardline/cli/main.py`, `src/wardline/cli/scan.py`
- Test: `tests/unit/cli/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/cli/test_cli.py
import json
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli

FIXTURE = Path(__file__).parents[2] / "fixtures" / "sample_project"


def test_version() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "wardline" in result.output


def test_scan_writes_empty_findings_and_exits_zero(tmp_path: Path) -> None:
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(cli, ["scan", str(FIXTURE), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert out.read_text(encoding="utf-8") == ""


def test_scan_sarif_is_not_yet_implemented(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli, ["scan", str(FIXTURE), "--format", "sarif"])
    assert result.exit_code == 2


def test_baseline_and_judge_stubs_exit_2() -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["baseline"]).exit_code == 2
    assert runner.invoke(cli, ["judge"]).exit_code == 2
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `pytest tests/unit/cli/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: wardline.cli.main`

- [ ] **Step 3: Implement the scan command**

Create empty `src/wardline/cli/__init__.py`.

```python
# src/wardline/cli/scan.py
"""`wardline scan` — SP0 wires discovery → no-op analyzer → JSONL sink."""

from __future__ import annotations

from pathlib import Path

import click

from wardline.core import config as config_mod
from wardline.core.discovery import discover
from wardline.core.emit import JsonlSink
from wardline.core.errors import WardlineError
from wardline.scanner import NoOpAnalyzer


@click.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--format", "fmt", type=click.Choice(["jsonl", "sarif"]), default="jsonl")
@click.option("--output", type=click.Path(path_type=Path), default=Path("findings.jsonl"))
@click.option("--fail-on", type=click.Choice(["CRITICAL", "ERROR", "WARN", "INFO"]), default=None)
def scan(
    path: Path,
    config_path: Path | None,
    fmt: str,
    output: Path,
    fail_on: str | None,  # noqa: ARG001 — reserved for SP3, inert in SP0
) -> None:
    """Scan PATH for findings (SP0: discovery + no-op analyzer)."""
    if fmt == "sarif":
        click.echo("SARIF output is not yet implemented (SP4).", err=True)
        raise SystemExit(2)
    try:
        cfg_path = config_path or (path / "wardline.yaml")
        cfg = config_mod.load(cfg_path)
        files = discover(path, cfg)
        findings = NoOpAnalyzer().analyze(files, cfg, root=path)
        JsonlSink(output).write(findings)
    except WardlineError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(2) from exc
    click.echo(f"scanned {len(files)} file(s); {len(findings)} finding(s) -> {output}")
```

- [ ] **Step 4: Implement the group + stubs**

```python
# src/wardline/cli/main.py
"""Wardline CLI entry point."""

from __future__ import annotations

import click

from wardline._version import __version__
from wardline.cli.scan import scan


@click.group()
@click.version_option(version=__version__, prog_name="wardline")
def cli() -> None:
    """Wardline — generic semantic-tainting static analyzer."""


cli.add_command(scan)


@cli.command()
def baseline() -> None:
    """Manage the finding baseline (not yet implemented — SP3)."""
    click.echo("`wardline baseline` is not yet implemented (SP3).", err=True)
    raise SystemExit(2)


@cli.command()
def judge() -> None:
    """Run the opt-in LLM judge (not yet implemented — SP5)."""
    click.echo("`wardline judge` is not yet implemented (SP5).", err=True)
    raise SystemExit(2)
```

- [ ] **Step 5: Run the test to confirm it passes**

Run: `pytest tests/unit/cli/test_cli.py -v`
Expected: PASS

- [ ] **Step 6: Manual smoke check**

Run: `wardline scan tests/fixtures/sample_project --output /tmp/f.jsonl && echo "exit=$?" && wc -c /tmp/f.jsonl`
Expected: prints `scanned 2 file(s); 0 finding(s) -> /tmp/f.jsonl`, `exit=0`, and `0 /tmp/f.jsonl`.

- [ ] **Step 7: Commit**

```bash
git add src/wardline/cli tests/unit/cli/test_cli.py
git commit -m "feat(sp0): CLI scan command + baseline/judge stubs + --version"
```

---

## Task 10: Self-hosting seed + full green gate

**Files:**
- Create: `tests/test_self_hosting.py`, `tests/conftest.py` (if needed for import paths — `src`-layout install handles this, so keep empty with a docstring)
- Test: the whole suite + ruff + mypy

- [ ] **Step 1: Write the self-hosting seed (expected-fail until SP2)**

```python
# tests/test_self_hosting.py
import pytest


@pytest.mark.xfail(reason="no rules until SP2; Wardline cannot yet scan itself", strict=True)
def test_wardline_scans_itself_clean() -> None:
    # SP2 flips this on: run wardline's own rules over src/wardline and assert 0 findings.
    raise AssertionError("self-hosting not implemented until SP2")
```

- [ ] **Step 2: Run the seed to confirm it xfails (not errors)**

Run: `pytest tests/test_self_hosting.py -v`
Expected: `XFAIL` (1 xfailed).

- [ ] **Step 3: Run the entire test suite**

Run: `pytest -v`
Expected: all PASS (with 1 xfailed); no failures, no errors.

- [ ] **Step 4: Run ruff**

Run: `ruff check src tests`
Expected: no errors. Fix any reported issues inline, then re-run until clean.

- [ ] **Step 5: Run mypy (strict)**

Run: `mypy`
Expected: `Success: no issues found`. Fix any typing issues inline, then re-run until clean.

- [ ] **Step 6: Verify acceptance criteria end-to-end**

Run: `wardline --version && wardline baseline; echo "baseline exit=$?"`
Expected: version prints; baseline prints the SP3 stub message and `baseline exit=2`.

- [ ] **Step 7: Commit**

```bash
git add tests/test_self_hosting.py tests/conftest.py
git commit -m "test(sp0): self-hosting seed + green gate"
```

- [ ] **Step 8: Update CHANGELOG**

Add under `## [Unreleased]` in `CHANGELOG.md`:
```markdown
### Added
- SP0 product skeleton: `wardline scan` (discovery + no-op analyzer), `Finding`
  contract, config loader, JSONL sink, CLI with `baseline`/`judge` stubs.
```
Commit:
```bash
git add CHANGELOG.md
git commit -m "docs(sp0): changelog for skeleton"
```

---

## Definition of Done (verify all)

- [ ] `pip install -e .[dev]` succeeds; `wardline --version` prints the version.
- [ ] `wardline scan tests/fixtures/sample_project` exits 0 and writes a valid, empty `findings.jsonl`.
- [ ] `wardline baseline` / `wardline judge` exit 2 with clear "not yet implemented" messages.
- [ ] `Finding`, `Severity`, `Kind`, `Location`, `WardlineConfig`, and the `Analyzer`/`Rule`/`Sink` Protocols exist with the documented fields/signatures.
- [ ] `severity_to_filigree` and `to_filigree_metadata` are pure (no network).
- [ ] `pytest` (all pass, 1 xfail), `ruff check`, and `mypy` (strict) are all green.
- [ ] No HMAC, signing, baseline, SARIF, or network code present.
