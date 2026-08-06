# tests/unit/core/test_packs.py
"""Tests for trust-grammar packs config merging and analyzer integration."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest

from wardline.core.config import load
from wardline.core.errors import ConfigError
from wardline.core.finding import Severity
from wardline.core.run import run_scan
from wardline.scanner.analyzer import build_analyzer
from wardline.scanner.grammar import default_grammar
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider


@pytest.fixture(autouse=True)
def _project_root_on_syspath(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[3]))


def test_config_load_and_deep_merge_pack(tmp_path: Path) -> None:
    p = tmp_path / "weft.toml"
    p.write_text(
        "[wardline]\n"
        'packs = ["tests.unit.install.mock_pack"]\n'
        'exclude = ["local_exclude"]\n'
        "[wardline.rules]\n"
        'severity = { "PY-WL-103" = "WARN" }\n',
        encoding="utf-8",
    )
    cfg = load(p, trust_local_packs=True, trusted_packs=("tests.unit.install.mock_pack",))
    assert "tests.unit.install.mock_pack" in cfg.packs
    assert "**/mock_exclude/**" in cfg.exclude
    assert "local_exclude" in cfg.exclude
    # Local severity override takes precedence over mock_pack's config (which overrides it to INFO)
    assert cfg.rules_severity.get("PY-WL-103") == "WARN"


def test_missing_pack_raises_config_error(tmp_path: Path) -> None:
    p = tmp_path / "weft.toml"
    p.write_text('[wardline]\npacks = ["non_existent_pack_xyz"]\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="failed to load trust-grammar pack"):
        load(p, trusted_packs=("non_existent_pack_xyz",))


def test_pack_config_is_rejected_by_default_without_importing(tmp_path: Path) -> None:
    p = tmp_path / "weft.toml"
    p.write_text('[wardline]\npacks = ["import_side_effect_pack"]\n', encoding="utf-8")
    pytest.importorskip("jsonschema")

    with patch("importlib.import_module") as mock_import, pytest.raises(ConfigError, match="not trusted"):
        load(p)

    mock_import.assert_not_called()


def test_local_dotted_pack_guard_does_not_execute_parent_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    marker = project / "PARENT_INIT_EXECUTED.txt"
    package_dir = project / "evil"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text(
        "from pathlib import Path\n"
        "Path(__file__).parent.parent.joinpath('PARENT_INIT_EXECUTED.txt').write_text('executed')\n",
        encoding="utf-8",
    )
    (package_dir / "sub.py").write_text("config = {}\n", encoding="utf-8")
    config_path = project / "weft.toml"
    config_path.write_text('[wardline]\npacks = ["evil.sub"]\n', encoding="utf-8")
    monkeypatch.syspath_prepend(str(project))

    with pytest.raises(
        ConfigError, match="loading trust-grammar pack 'evil.sub' from local project directory is disabled"
    ):
        load(config_path, trusted_packs=("evil.sub",))

    assert not marker.exists()


def test_invalid_grammar_attribute_raises_config_error(tmp_path: Path) -> None:
    fake_module = ModuleType("invalid_grammar_pack")
    fake_module.grammar = "not a TrustGrammar"  # type: ignore
    sys.modules["invalid_grammar_pack"] = fake_module

    try:
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "weft.toml").write_text('[wardline]\npacks = ["invalid_grammar_pack"]\n', encoding="utf-8")
        (proj / "m.py").write_text("def f(): pass\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="attribute 'grammar' must be a TrustGrammar instance"):
            run_scan(proj, trust_local_packs=True, trusted_packs=("invalid_grammar_pack",))
    finally:
        sys.modules.pop("invalid_grammar_pack", None)


def test_analyzer_pack_integration(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "weft.toml").write_text(
        '[wardline]\npacks = ["tests.unit.install.mock_pack"]\n',
        encoding="utf-8",
    )
    # The rule PY-WL-901 fires on function/entity named "violator"
    # The boundary type "mock_boundary" seeds the function as EXTERNAL_RAW input / GUARDED output.
    source = "from tests.unit.install.mock_pack import mock_boundary\n\n@mock_boundary\ndef violator():\n    pass\n"
    (proj / "m.py").write_text(source, encoding="utf-8")

    res = run_scan(proj, trust_local_packs=True, trusted_packs=("tests.unit.install.mock_pack",))

    # 1. Custom rule should have run and fired on 'violator'
    findings = [f for f in res.findings if f.rule_id == "PY-WL-901"]
    assert len(findings) == 1
    assert findings[0].message == "Found a violator!"
    assert findings[0].severity == Severity.WARN

    # 2. Custom boundary should have seeded the function (input EXTERNAL_RAW, output/return GUARDED)
    assert res.context is not None
    assert "m.violator" in res.context.project_return_taints
    from wardline.core.taints import TaintState

    assert res.context.project_return_taints["m.violator"] == TaintState.GUARDED


def _local_pack_project(tmp_path: Path, pack_module: str, pack_body: str) -> Path:
    """A project whose weft.toml declares a repo-local pack ``scripts.<pack_module>``,
    with the project directory deliberately NOT on sys.path."""
    proj = tmp_path / "proj"
    (proj / "scripts").mkdir(parents=True)
    (proj / "scripts" / f"{pack_module}.py").write_text(pack_body, encoding="utf-8")
    (proj / "weft.toml").write_text(
        f'[wardline]\npacks = ["scripts.{pack_module}"]\n',
        encoding="utf-8",
    )
    return proj


def _forget_scripts_modules(pack_module: str) -> None:
    sys.modules.pop(f"scripts.{pack_module}", None)
    sys.modules.pop("scripts", None)


def test_local_pack_loads_without_caller_syspath_when_granted(tmp_path: Path) -> None:
    """Gap B (wardline-7a76f6c5a0): a granted repo-local pack must import without the
    caller pre-arranging PYTHONPATH — wardline itself supplies the config's directory."""
    proj = _local_pack_project(tmp_path, "pack_selfimport", 'config = {"exclude": ["pack_marker/**"]}\n')
    syspath_before = list(sys.path)
    try:
        cfg = load(
            proj / "weft.toml",
            trusted_packs=("scripts.pack_selfimport",),
            trust_local_packs=True,
        )
    finally:
        _forget_scripts_modules("pack_selfimport")
    assert "scripts.pack_selfimport" in cfg.packs
    assert "pack_marker/**" in cfg.exclude
    assert sys.path == syspath_before


def test_local_pack_off_syspath_still_requires_local_grant(tmp_path: Path) -> None:
    """Locality must be detected against the config directory itself, not just via
    existing sys.path entries: a repo-local pack with the project off sys.path is
    refused with the local-pack security error, not a generic import failure."""
    proj = _local_pack_project(tmp_path, "pack_ungranted", "config = {}\n")
    try:
        with pytest.raises(ConfigError, match="local project directory is disabled"):
            load(proj / "weft.toml", trusted_packs=("scripts.pack_ungranted",))
    finally:
        _forget_scripts_modules("pack_ungranted")


def test_syspath_restored_when_local_pack_import_fails(tmp_path: Path) -> None:
    """The temporary sys.path insertion must not leak when the pack itself fails to
    import — and the failure must be the pack's own error, proving the config
    directory WAS importable."""
    proj = _local_pack_project(tmp_path, "pack_broken", "import definitely_missing_module_xyz\n")
    syspath_before = list(sys.path)
    try:
        with pytest.raises(ConfigError, match="definitely_missing_module_xyz"):
            load(
                proj / "weft.toml",
                trusted_packs=("scripts.pack_broken",),
                trust_local_packs=True,
            )
    finally:
        _forget_scripts_modules("pack_broken")
    assert sys.path == syspath_before


def test_fingerprint_updates_with_packed_boundaries() -> None:
    from tests.unit.install.mock_pack import grammar as mock_grammar

    base_provider = DecoratorTaintSourceProvider()
    extended_grammar = default_grammar().extend(
        boundary_types=mock_grammar.boundary_types,
        rules=mock_grammar.rules,
    )
    extended_analyzer = build_analyzer(grammar=extended_grammar)

    assert extended_analyzer._provider.fingerprint() != base_provider.fingerprint()
