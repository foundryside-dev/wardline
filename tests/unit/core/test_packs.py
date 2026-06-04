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
    p = tmp_path / "wardline.yaml"
    p.write_text(
        "packs:\n"
        "  - tests.unit.install.mock_pack\n"
        "exclude:\n"
        "  - local_exclude\n"
        "rules:\n"
        "  severity:\n"
        "    PY-WL-103: WARN\n",
        encoding="utf-8",
    )
    cfg = load(p, trust_local_packs=True, trusted_packs=("tests.unit.install.mock_pack",))
    assert "tests.unit.install.mock_pack" in cfg.packs
    assert "**/mock_exclude/**" in cfg.exclude
    assert "local_exclude" in cfg.exclude
    # Local severity override takes precedence over mock_pack's config (which overrides it to INFO)
    assert cfg.rules_severity.get("PY-WL-103") == "WARN"


def test_missing_pack_raises_config_error(tmp_path: Path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("packs:\n  - non_existent_pack_xyz\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="failed to load trust-grammar pack"):
        load(p, trusted_packs=("non_existent_pack_xyz",))


def test_pack_config_is_rejected_by_default_without_importing(tmp_path: Path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("packs:\n  - import_side_effect_pack\n", encoding="utf-8")
    pytest.importorskip("jsonschema")

    with patch("importlib.import_module") as mock_import, pytest.raises(ConfigError, match="not trusted"):
        load(p)

    mock_import.assert_not_called()


def test_invalid_grammar_attribute_raises_config_error(tmp_path: Path) -> None:
    fake_module = ModuleType("invalid_grammar_pack")
    fake_module.grammar = "not a TrustGrammar"  # type: ignore
    sys.modules["invalid_grammar_pack"] = fake_module

    try:
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "wardline.yaml").write_text("packs:\n  - invalid_grammar_pack\n", encoding="utf-8")
        (proj / "m.py").write_text("def f(): pass\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="attribute 'grammar' must be a TrustGrammar instance"):
            run_scan(proj, trust_local_packs=True, trusted_packs=("invalid_grammar_pack",))
    finally:
        sys.modules.pop("invalid_grammar_pack", None)


def test_analyzer_pack_integration(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "wardline.yaml").write_text(
        "packs:\n  - tests.unit.install.mock_pack\n",
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


def test_fingerprint_updates_with_packed_boundaries() -> None:
    from tests.unit.install.mock_pack import grammar as mock_grammar

    base_provider = DecoratorTaintSourceProvider()
    extended_grammar = default_grammar().extend(
        boundary_types=mock_grammar.boundary_types,
        rules=mock_grammar.rules,
    )
    extended_analyzer = build_analyzer(grammar=extended_grammar)

    assert extended_analyzer._provider.fingerprint() != base_provider.fingerprint()
