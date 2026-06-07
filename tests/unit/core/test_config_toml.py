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
""",
    )
    cfg = config_mod.load(p)
    assert cfg.source_roots == ("src",)
    assert cfg.exclude == ("build",)
    assert cfg.rules_enable == ("PY-WL-101",)
    assert cfg.rules_severity == {"PY-WL-101": "ERROR"}


def test_no_wardline_table_is_defaults(tmp_path):
    p = _write(tmp_path, '[loomweave]\nurl = "http://x"\n')
    cfg = config_mod.load(p)
    assert cfg.source_roots == (".",)


def test_malformed_toml_implicit_warns_and_falls_back(tmp_path):
    # C-9c: a malformed shared weft.toml is treated as absent — never a hard fail
    # (it could be another member's section that broke parsing). But an IMPLICIT
    # (auto-discovered) load now WARNS so the silent policy-downgrade is visible.
    p = _write(tmp_path, "[wardline]\nsource_roots = [")
    with pytest.warns(UserWarning, match="weft.toml"):
        cfg = config_mod.load(p)
    assert cfg.source_roots == (".",)


def test_non_table_wardline_implicit_warns_and_falls_back(tmp_path):
    p = _write(tmp_path, 'wardline = "oops"\n')
    with pytest.warns(UserWarning, match="must be a table"):
        cfg = config_mod.load(p)
    assert cfg.source_roots == (".",)


def test_malformed_toml_explicit_raises(tmp_path):
    # An EXPLICIT --config that the operator named must NOT silently drop their
    # policy — a malformed (but existing) file raises ConfigError (false-green guard).
    p = _write(tmp_path, "[wardline]\nsource_roots = [")
    with pytest.raises(ConfigError):
        config_mod.load(p, explicit=True)


def test_non_table_wardline_explicit_raises(tmp_path):
    p = _write(tmp_path, 'wardline = "oops"\n')
    with pytest.raises(ConfigError):
        config_mod.load(p, explicit=True)


def test_explicit_missing_config_raises(tmp_path):
    with pytest.raises(ConfigError):
        config_mod.load(tmp_path / "nope.toml", explicit=True)


def test_no_wardline_table_stays_silent_even_implicit(tmp_path, recwarn):
    # A file with no [wardline] section at all is "no policy declared", not a
    # broken file — defaults, NO warning, in both implicit and explicit modes.
    p = _write(tmp_path, '[loomweave]\nurl = "http://x"\n')
    cfg = config_mod.load(p)
    assert cfg.source_roots == (".",)
    assert config_mod.load(p, explicit=True).source_roots == (".",)
    assert not recwarn.list


def test_unknown_key_rejected(tmp_path):
    p = _write(tmp_path, "[wardline]\nbogus_key = 1\n")
    with pytest.raises(ConfigError):
        config_mod.load(p)


def test_waivers_key_rejected_now_machine_state(tmp_path):
    # waivers are no longer an operator key — additionalProperties:false rejects them.
    p = _write(tmp_path, '[[wardline.waivers]]\nfingerprint = "x"\n')
    with pytest.raises(ConfigError):
        config_mod.load(p)


def test_judge_table_parsed(tmp_path):
    p = _write(
        tmp_path,
        """
[wardline.judge]
model = "anthropic/claude-opus-4-8"
context_lines = 10
""",
    )
    cfg = config_mod.load(p)
    assert cfg.judge == {"model": "anthropic/claude-opus-4-8", "context_lines": 10}
