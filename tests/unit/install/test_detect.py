from pathlib import Path

import pytest

from wardline.install.detect import detect_siblings


def _assert_no_config_written(root: Path) -> None:
    # detect_siblings is detection-only — it must never author config.
    assert not (root / "wardline.yaml").exists()
    assert not (root / "weft.toml").exists()


def test_no_siblings_returns_absent_and_writes_nothing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    results = detect_siblings(tmp_path)
    assert results == {"loomweave": "absent", "filigree": "absent"}
    _assert_no_config_written(tmp_path)


def test_filigree_published_port_is_detected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    port_dir = tmp_path / ".weft" / "filigree"
    port_dir.mkdir(parents=True)
    (port_dir / "ephemeral.port").write_text("8628", encoding="utf-8")

    results = detect_siblings(tmp_path)

    assert results["filigree"] == "detected (discovered URL)"
    assert results["loomweave"] == "absent"
    _assert_no_config_written(tmp_path)


@pytest.mark.parametrize(
    "payload",
    [
        # All-digit payload over CPython's 4300-digit int(str) cap.
        pytest.param("9" * 5000, id="over-4300-digit-cap"),
        # Unicode "digit" chars (superscripts): isdigit() True but int() raises,
        # and they are short — so a length bound alone would not catch them.
        pytest.param("²³⁴", id="unicode-isdigit"),
    ],
)
def test_filigree_isdigit_but_unparseable_port_is_soft(
    tmp_path: Path, monkeypatch, payload: str
) -> None:
    # A planted ephemeral.port whose payload passes str.isdigit() but raises in
    # int(). Detection must stay fail-soft (treat as absent), never crash.
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    port_dir = tmp_path / ".weft" / "filigree"
    port_dir.mkdir(parents=True)
    (port_dir / "ephemeral.port").write_text(payload, encoding="utf-8")

    results = detect_siblings(tmp_path)

    assert results["filigree"] == "absent"
    _assert_no_config_written(tmp_path)


def test_filigree_legacy_dot_dir_port_is_detected(tmp_path: Path, monkeypatch) -> None:
    # The legacy .filigree/ dot-dir is tolerated during the federation transition.
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    filigree_dir = tmp_path / ".filigree"
    filigree_dir.mkdir()
    (filigree_dir / "ephemeral.port").write_text("8628", encoding="utf-8")

    results = detect_siblings(tmp_path)

    assert results["filigree"] == "detected (discovered URL)"
    _assert_no_config_written(tmp_path)


def test_env_url_is_detected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://clar:9100")
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    results = detect_siblings(tmp_path)
    assert results["loomweave"] == "detected (env URL)"
    _assert_no_config_written(tmp_path)


def test_present_without_url_reports_no_url(tmp_path: Path, monkeypatch) -> None:
    # A sibling marker present but no resolvable URL → detected, but the status
    # records that no URL is known (operator must wire one or rely on live discovery).
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")

    results = detect_siblings(tmp_path)

    assert results["filigree"].startswith("detected (no URL")
    _assert_no_config_written(tmp_path)


def test_both_siblings_via_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://clar:9100")
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://fil:9200/api/weft/scan-results")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    results = detect_siblings(tmp_path)
    assert results == {"loomweave": "detected (env URL)", "filigree": "detected (env URL)"}
    _assert_no_config_written(tmp_path)


# --- loomweave.yaml discovery (_loomweave_url_from_config / _http_url_from_bind) ---
# This parsing logic is live (detect_siblings -> _detect_loomweave -> _loomweave_url_from_config);
# these tests restore the coverage that moved out with the old record_bindings tests.

_LOOMWEAVE_YAML = "serve:\n  http:\n    enabled: {enabled}\n    bind: {bind}\n"


def test_loomweave_yaml_enabled_is_detected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / "loomweave.yaml").write_text(
        _LOOMWEAVE_YAML.format(enabled="true", bind="127.0.0.1:9111"), encoding="utf-8"
    )
    results = detect_siblings(tmp_path)
    assert results["loomweave"] == "detected (discovered URL)"
    _assert_no_config_written(tmp_path)


def test_loomweave_yaml_disabled_reports_no_url(tmp_path: Path, monkeypatch) -> None:
    # enabled: false -> no URL discovered, but the file's presence still means "detected".
    # A regression here would silently wire a deliberately-disabled endpoint.
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / "loomweave.yaml").write_text(
        _LOOMWEAVE_YAML.format(enabled="false", bind="127.0.0.1:9111"), encoding="utf-8"
    )
    results = detect_siblings(tmp_path)
    assert results["loomweave"].startswith("detected (no URL")
    _assert_no_config_written(tmp_path)


def test_loomweave_binary_on_path_reports_no_url(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr(
        "wardline.install.detect.shutil.which", lambda name: "/usr/bin/loomweave" if name == "loomweave" else None
    )
    results = detect_siblings(tmp_path)
    assert results["loomweave"].startswith("detected (no URL")
    _assert_no_config_written(tmp_path)


def test_http_url_from_bind_normalizes_wildcard_host() -> None:
    from wardline.install.detect import _http_url_from_bind

    assert _http_url_from_bind("0.0.0.0:9111") == "http://127.0.0.1:9111"
    assert _http_url_from_bind("127.0.0.1:9100") == "http://127.0.0.1:9100"
    assert _http_url_from_bind("http://already:9100") == "http://already:9100"
    assert _http_url_from_bind("::1:9100") == "http://[::1]:9100"
    assert _http_url_from_bind("no-port") is None


def test_loomweave_url_from_config_extracts_bind(tmp_path: Path) -> None:
    from wardline.install.detect import _loomweave_url_from_config

    (tmp_path / "loomweave.yaml").write_text(
        _LOOMWEAVE_YAML.format(enabled="true", bind="0.0.0.0:9111"), encoding="utf-8"
    )
    assert _loomweave_url_from_config(tmp_path) == "http://127.0.0.1:9111"
    # disabled -> None
    (tmp_path / "loomweave.yaml").write_text(
        _LOOMWEAVE_YAML.format(enabled="false", bind="0.0.0.0:9111"), encoding="utf-8"
    )
    assert _loomweave_url_from_config(tmp_path) is None
