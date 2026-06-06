from pathlib import Path

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
