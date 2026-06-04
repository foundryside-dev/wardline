from pathlib import Path

import pytest

from wardline.core.config import (
    WardlineConfig,
    load,
    resolve_clarion_url,
    resolve_filigree_url,
)
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


def test_malformed_yaml_raises_config_error(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("a: [1, 2\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(p)


def test_waivers_block_is_parsed_raw(tmp_path) -> None:
    from wardline.core import config as config_mod

    p = tmp_path / "wardline.yaml"
    p.write_text(
        "waivers:\n  - fingerprint: " + ("a" * 64) + "\n    reason: ok\n",
        encoding="utf-8",
    )
    cfg = config_mod.load(p)
    assert cfg.waivers == ({"fingerprint": "a" * 64, "reason": "ok"},)


def test_waivers_key_does_not_warn(recwarn, tmp_path) -> None:
    from wardline.core import config as config_mod

    p = tmp_path / "wardline.yaml"
    p.write_text("waivers: []\n", encoding="utf-8")
    config_mod.load(p)
    assert not [w for w in recwarn.list if "waivers" in str(w.message)]


def test_judge_settings_defaults() -> None:
    from wardline.core.config import parse_judge_settings

    s = parse_judge_settings({})
    assert s.model == "anthropic/claude-opus-4-8"
    assert s.context_lines == 30
    assert s.max_findings is None
    assert s.policy_file is None


def test_judge_settings_from_mapping() -> None:
    from wardline.core.config import parse_judge_settings

    s = parse_judge_settings(
        {"model": "anthropic/claude-sonnet-4-6", "context_lines": 10, "max_findings": 50, "policy_file": "POLICY.md"}
    )
    assert s.model == "anthropic/claude-sonnet-4-6" and s.context_lines == 10
    assert s.max_findings == 50 and s.policy_file == "POLICY.md"


def test_judge_settings_bad_type_raises() -> None:
    import pytest

    from wardline.core.config import parse_judge_settings
    from wardline.core.errors import ConfigError

    with pytest.raises(ConfigError):
        parse_judge_settings({"context_lines": "lots"})


def test_judge_settings_rejects_nonpositive_max_findings() -> None:
    import pytest

    from wardline.core.config import parse_judge_settings
    from wardline.core.errors import ConfigError

    with pytest.raises(ConfigError):
        parse_judge_settings({"max_findings": 0})


def test_judge_settings_write_confidence_floor() -> None:
    from wardline.core.config import parse_judge_settings

    assert parse_judge_settings({}).write_confidence_floor == 0.5
    assert parse_judge_settings({"write_confidence_floor": 0.0}).write_confidence_floor == 0.0


def test_judge_settings_rejects_out_of_range_floor() -> None:
    import pytest

    from wardline.core.config import parse_judge_settings
    from wardline.core.errors import ConfigError

    with pytest.raises(ConfigError):
        parse_judge_settings({"write_confidence_floor": 1.5})


def test_unknown_top_level_key_raises(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("bogus: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid"):
        load(p)


def test_full_valid_config_passes(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text(
        "source_roots: [src]\n"
        "exclude: ['**/x/**']\n"
        "rules:\n  enable: ['WLN-001']\n  severity: {WLN-001: WARN}\n"
        "baseline: {path: .wardline/baseline.yaml}\n"
        "waivers:\n  - fingerprint: " + ("a" * 64) + "\n    reason: ok\n"
        "judge:\n  model: anthropic/claude-opus-4-8\n  context_lines: 10\n"
        "  max_findings: 50\n  write_confidence_floor: 0.7\n"
        "filigree: {url: http://x}\n"
        "clarion: {url: http://clarion.local:9100}\n",
        encoding="utf-8",
    )
    cfg = load(p)
    assert cfg.source_roots == ("src",)
    assert cfg.judge == {
        "model": "anthropic/claude-opus-4-8",
        "context_lines": 10,
        "max_findings": 50,
        "write_confidence_floor": 0.7,
    }


def test_bad_judge_context_lines_type_raises(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("judge:\n  context_lines: lots\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(p)


def test_yaml_bool_is_not_a_valid_integer(tmp_path) -> None:
    # Regression guard: YAML `true` is a bool, not an int. The schema's
    # {"type": "integer"} must reject it (jsonschema draft 2020-12 semantics),
    # matching parse_judge_settings' explicit bool guard.
    p = tmp_path / "wardline.yaml"
    p.write_text("judge:\n  context_lines: true\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(p)


def test_out_of_range_floor_raises(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("judge:\n  write_confidence_floor: 2.0\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(p)


def test_unknown_judge_key_raises(tmp_path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("judge:\n  bogus_setting: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(p)


@pytest.mark.parametrize(
    "exception_name",
    [
        "ValueError; import os",
        "class",
        "pkg.class",
        "pkg.1Bad",
        "",
    ],
)
def test_autofix_boundary_exception_rejects_invalid_identifier(tmp_path: Path, exception_name: str) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text(f"autofix:\n  boundary_exception: {exception_name!r}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="boundary_exception"):
        load(p)


def test_autofix_boundary_exception_accepts_dotted_identifier(tmp_path: Path) -> None:
    p = tmp_path / "wardline.yaml"
    p.write_text("autofix:\n  boundary_exception: mypkg.ValidationError\n", encoding="utf-8")
    assert load(p).boundary_exception == "mypkg.ValidationError"


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
    (tmp_path / "wardline.yaml").write_text("clarion:\n  bogus: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load(tmp_path / "wardline.yaml")


def test_resolve_precedence_flag_beats_env_beats_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wardline.yaml").write_text('clarion:\n  url: "http://localhost:9100"\n', encoding="utf-8")
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    assert resolve_clarion_url(None, tmp_path, None) == "http://localhost:9100"
    monkeypatch.setenv("WARDLINE_CLARION_URL", "http://from-env")
    assert resolve_clarion_url(None, tmp_path, None) == "http://from-env"
    assert resolve_clarion_url("http://from-flag", tmp_path, None) == "http://from-flag"


def test_resolve_urls_rejects_unsafe_config_urls(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wardline.yaml").write_text('clarion:\n  url: "http://attacker-controlled.com"\n', encoding="utf-8")
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    with pytest.raises(ConfigError, match="disabled by default for security"):
        resolve_clarion_url(None, tmp_path, None)
    # Passing trust_config_urls=True bypasses the block
    assert resolve_clarion_url(None, tmp_path, None, trust_config_urls=True) == "http://attacker-controlled.com"


def test_resolve_filigree_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://fil-env")
    assert resolve_filigree_url(None, tmp_path, None) == "http://fil-env"


def test_resolve_filigree_flag_beats_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://fil-env")
    assert resolve_filigree_url("http://fil-flag", tmp_path, None) == "http://fil-flag"


def test_resolve_filigree_rejects_unsafe_config_urls(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wardline.yaml").write_text('filigree:\n  url: "http://attacker-controlled.com"\n', encoding="utf-8")
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    with pytest.raises(ConfigError, match="disabled by default for security"):
        resolve_filigree_url(None, tmp_path, None)
    assert resolve_filigree_url(None, tmp_path, None, trust_config_urls=True) == "http://attacker-controlled.com"
