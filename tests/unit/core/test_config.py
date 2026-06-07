from pathlib import Path

import pytest

from wardline.core.config import (
    load,
    resolve_filigree_url,
    resolve_loomweave_url,
)
from wardline.core.errors import ConfigError


def _write_cfg(root: Path, body: str) -> Path:
    """Write a weft.toml carrying a ``[wardline]`` table and return its path."""
    p = root / "weft.toml"
    p.write_text(body, encoding="utf-8")
    return p


def test_load_missing_returns_defaults(tmp_path) -> None:
    cfg = load(tmp_path / "weft.toml")
    assert cfg.source_roots == (".",)
    assert cfg.exclude == ()
    assert cfg.rules_enable == ("*",)


def test_load_parses_known_keys_and_reserved_blocks(tmp_path) -> None:
    p = _write_cfg(
        tmp_path,
        """
[wardline]
source_roots = ["src"]
exclude = ["**/x/**"]

[wardline.rules]
enable = ["WLN-001"]
severity = { "WLN-001" = "WARN" }
""",
    )
    cfg = load(p)
    assert cfg.source_roots == ("src",)
    assert cfg.exclude == ("**/x/**",)
    assert cfg.rules_enable == ("WLN-001",)
    assert cfg.rules_severity == {"WLN-001": "WARN"}


def test_malformed_toml_falls_back_to_defaults(tmp_path) -> None:
    # C-9c: malformed weft.toml is treated as absent (silent defaults, never hard-fail).
    p = _write_cfg(tmp_path, "[wardline]\nsource_roots = [1, 2\n")
    assert load(p).source_roots == (".",)


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
    from wardline.core.config import parse_judge_settings
    from wardline.core.errors import ConfigError

    with pytest.raises(ConfigError):
        parse_judge_settings({"context_lines": "lots"})


def test_judge_settings_rejects_nonpositive_max_findings() -> None:
    from wardline.core.config import parse_judge_settings
    from wardline.core.errors import ConfigError

    with pytest.raises(ConfigError):
        parse_judge_settings({"max_findings": 0})


def test_judge_settings_write_confidence_floor() -> None:
    from wardline.core.config import parse_judge_settings

    assert parse_judge_settings({}).write_confidence_floor == 0.5
    assert parse_judge_settings({"write_confidence_floor": 0.0}).write_confidence_floor == 0.0


def test_judge_settings_rejects_out_of_range_floor() -> None:
    from wardline.core.config import parse_judge_settings
    from wardline.core.errors import ConfigError

    with pytest.raises(ConfigError):
        parse_judge_settings({"write_confidence_floor": 1.5})


def test_unknown_top_level_key_raises(tmp_path) -> None:
    p = _write_cfg(tmp_path, "[wardline]\nbogus = 1\n")
    with pytest.raises(ConfigError, match="invalid"):
        load(p)


def test_full_valid_config_passes(tmp_path) -> None:
    p = _write_cfg(
        tmp_path,
        """
[wardline]
source_roots = ["src"]
exclude = ["**/x/**"]

[wardline.rules]
enable = ["WLN-001"]
severity = { "WLN-001" = "WARN" }

[wardline.judge]
model = "anthropic/claude-opus-4-8"
context_lines = 10
max_findings = 50
write_confidence_floor = 0.7
""",
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
    p = _write_cfg(tmp_path, '[wardline.judge]\ncontext_lines = "lots"\n')
    with pytest.raises(ConfigError):
        load(p)


def test_bool_is_not_a_valid_integer(tmp_path) -> None:
    # Regression guard: a TOML boolean is not an int. The schema's
    # {"type": "integer"} must reject it (jsonschema draft 2020-12 semantics),
    # matching parse_judge_settings' explicit bool guard.
    p = _write_cfg(tmp_path, "[wardline.judge]\ncontext_lines = true\n")
    with pytest.raises(ConfigError):
        load(p)


def test_out_of_range_floor_raises(tmp_path) -> None:
    p = _write_cfg(tmp_path, "[wardline.judge]\nwrite_confidence_floor = 2.0\n")
    with pytest.raises(ConfigError):
        load(p)


def test_unknown_judge_key_raises(tmp_path) -> None:
    p = _write_cfg(tmp_path, "[wardline.judge]\nbogus_setting = 1\n")
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
    p = _write_cfg(tmp_path, f'[wardline.autofix]\nboundary_exception = "{exception_name}"\n')
    with pytest.raises(ConfigError, match="boundary_exception"):
        load(p)


def test_autofix_boundary_exception_accepts_dotted_identifier(tmp_path: Path) -> None:
    p = _write_cfg(tmp_path, '[wardline.autofix]\nboundary_exception = "mypkg.ValidationError"\n')
    assert load(p).boundary_exception == "mypkg.ValidationError"


def test_loomweave_loomweave_url_keys_rejected_now_hub_pending(tmp_path: Path) -> None:
    # Sibling-endpoint config keys are NOT defined by wardline (hub-pinned, pending).
    # additionalProperties:false therefore rejects a [wardline.loomweave]/[wardline.filigree] table.
    for body in ('[wardline.loomweave]\nurl = "http://x"\n', '[wardline.filigree]\nurl = "http://x"\n'):
        p = _write_cfg(tmp_path, body)
        with pytest.raises(ConfigError):
            load(p)


def test_resolve_precedence_flag_beats_env_beats_published(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    # No flag, no env, no published port -> None (no config rung exists).
    assert resolve_loomweave_url(None, tmp_path, None) is None
    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://from-env")
    assert resolve_loomweave_url(None, tmp_path, None) == "http://from-env"
    assert resolve_loomweave_url("http://from-flag", tmp_path, None) == "http://from-flag"


def test_resolve_filigree_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://fil-env")
    assert resolve_filigree_url(None, tmp_path, None) == "http://fil-env"


def test_resolve_filigree_flag_beats_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://fil-env")
    assert resolve_filigree_url("http://fil-flag", tmp_path, None) == "http://fil-flag"


# --- ADR-044: published ephemeral.port resolution (consumer half) ---
#
# Discovery prefers the consolidated .weft/<sibling>/ephemeral.port and tolerates
# the legacy .<sibling>/ephemeral.port during the federation transition window.
# There is NO config-file URL rung: sibling endpoints are hub-pinned and pending.


def _publish_port(root: Path, raw: str, *, legacy: bool = False) -> None:
    """Write a raw loomweave ephemeral.port payload (as Loomweave's publisher would)."""
    d = (root / ".loomweave") if legacy else (root / ".weft" / "loomweave")
    d.mkdir(parents=True, exist_ok=True)
    (d / "ephemeral.port").write_text(raw, encoding="ascii")


def test_published_port_prefers_weft_location(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    _publish_port(tmp_path, "7777")
    assert resolve_loomweave_url(None, tmp_path, None) == "http://127.0.0.1:7777"


def test_published_port_legacy_fallback(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    _publish_port(tmp_path, "8888", legacy=True)
    assert resolve_loomweave_url(None, tmp_path, None) == "http://127.0.0.1:8888"


def test_published_port_weft_beats_legacy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    _publish_port(tmp_path, "8888", legacy=True)
    _publish_port(tmp_path, "7777")
    assert resolve_loomweave_url(None, tmp_path, None) == "http://127.0.0.1:7777"


def test_published_port_loses_to_flag_and_env(tmp_path: Path, monkeypatch) -> None:
    _publish_port(tmp_path, "54321")
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    assert resolve_loomweave_url("http://from-flag", tmp_path, None) == "http://from-flag"
    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://from-env")
    assert resolve_loomweave_url(None, tmp_path, None) == "http://from-env"


@pytest.mark.parametrize(
    "raw",
    [
        "abc",
        "",
        "  ",
        "99999",
        "0",
        "-1",
        "65536",
        "80x",
        "+80",
        "9111 9112",
        # An all-digit payload over CPython's 4300-digit int(str) cap: isdigit() is
        # True but int() would raise ValueError. Must stay fail-soft -> None, never
        # crash the scan (a planted ephemeral.port DoS).
        pytest.param("9" * 5000, id="over-4300-digit-cap"),
    ],
)
def test_published_port_malformed_returns_none(tmp_path: Path, monkeypatch, raw: str) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    _publish_port(tmp_path, raw)
    assert resolve_loomweave_url(None, tmp_path, None) is None


def test_published_port_boundaries_accepted(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    _publish_port(tmp_path, "1")
    assert resolve_loomweave_url(None, tmp_path, None) == "http://127.0.0.1:1"
    _publish_port(tmp_path, "65535")
    assert resolve_loomweave_url(None, tmp_path, None) == "http://127.0.0.1:65535"


def test_missing_published_port_returns_none(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    assert resolve_loomweave_url(None, tmp_path, None) is None


def test_published_port_skipped_under_strict_defaults(tmp_path: Path, monkeypatch) -> None:
    # Hermetic defaults: no project-derived discovery (the published file is ignored).
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    _publish_port(tmp_path, "54321")
    assert resolve_loomweave_url(None, tmp_path, None, strict_defaults=True) is None
    # ...but flag/env still win even under strict_defaults.
    assert resolve_loomweave_url("http://from-flag", tmp_path, None, strict_defaults=True) == "http://from-flag"


def test_published_port_unreadable_is_soft(tmp_path: Path, monkeypatch) -> None:
    # A directory where the port file is expected -> OSError on read -> None, no raise.
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    (tmp_path / ".weft" / "loomweave").mkdir(parents=True)
    (tmp_path / ".weft" / "loomweave" / "ephemeral.port").mkdir()
    assert resolve_loomweave_url(None, tmp_path, None) is None


# --- ADR-044 twin: published filigree ephemeral.port resolution (consumer half) ---


def _publish_filigree_port(root: Path, raw: str, *, legacy: bool = False) -> None:
    """Write a raw filigree ephemeral.port payload (as Filigree's publisher would)."""
    d = (root / ".filigree") if legacy else (root / ".weft" / "filigree")
    d.mkdir(parents=True, exist_ok=True)
    (d / "ephemeral.port").write_text(raw, encoding="ascii")


def test_filigree_published_port_prefers_weft_location(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    _publish_filigree_port(tmp_path, "9001")
    assert resolve_filigree_url(None, tmp_path, None) == "http://localhost:9001/api/weft/scan-results"


def test_filigree_published_port_legacy_fallback(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    _publish_filigree_port(tmp_path, "9002", legacy=True)
    assert resolve_filigree_url(None, tmp_path, None) == "http://localhost:9002/api/weft/scan-results"


def test_filigree_published_port_loses_to_flag_and_env(tmp_path: Path, monkeypatch) -> None:
    _publish_filigree_port(tmp_path, "54321")
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    assert resolve_filigree_url("http://from-flag", tmp_path, None) == "http://from-flag"
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://from-env")
    assert resolve_filigree_url(None, tmp_path, None) == "http://from-env"


@pytest.mark.parametrize(
    "raw",
    [
        "abc",
        "",
        "  ",
        "99999",
        "0",
        "-1",
        "65536",
        "80x",
        "+80",
        "9111 9112",
        # Over CPython's 4300-digit int(str) cap: isdigit() True, int() would raise.
        pytest.param("9" * 5000, id="over-4300-digit-cap"),
    ],
)
def test_filigree_published_port_malformed_returns_none(tmp_path: Path, monkeypatch, raw: str) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    _publish_filigree_port(tmp_path, raw)
    assert resolve_filigree_url(None, tmp_path, None) is None


def test_filigree_published_port_boundaries_accepted(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    _publish_filigree_port(tmp_path, "1")
    assert resolve_filigree_url(None, tmp_path, None) == "http://localhost:1/api/weft/scan-results"
    _publish_filigree_port(tmp_path, "65535")
    assert resolve_filigree_url(None, tmp_path, None) == "http://localhost:65535/api/weft/scan-results"


def test_missing_filigree_published_port_returns_none(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    assert resolve_filigree_url(None, tmp_path, None) is None


def test_filigree_published_port_skipped_under_strict_defaults(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    _publish_filigree_port(tmp_path, "54321")
    assert resolve_filigree_url(None, tmp_path, None, strict_defaults=True) is None
    assert resolve_filigree_url("http://from-flag", tmp_path, None, strict_defaults=True) == "http://from-flag"


def test_filigree_published_port_unreadable_is_soft(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    (tmp_path / ".weft" / "filigree").mkdir(parents=True)
    (tmp_path / ".weft" / "filigree" / "ephemeral.port").mkdir()
    assert resolve_filigree_url(None, tmp_path, None) is None
