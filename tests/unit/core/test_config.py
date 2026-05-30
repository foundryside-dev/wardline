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
