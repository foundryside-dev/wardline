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
    p = _write(tmp_path, '[loomweave]\nurl = "http://x"\n')
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
