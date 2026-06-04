from pathlib import Path

import pytest

from wardline.core.errors import WardlineError
from wardline.install.detect import record_bindings


def test_no_siblings_writes_nothing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    results = record_bindings(tmp_path)
    assert results == {"clarion": "absent", "filigree": "absent"}
    assert not (tmp_path / "wardline.yaml").exists()


def test_filigree_marker_writes_commented_stanza(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")
    results = record_bindings(tmp_path)
    assert results["filigree"] == "detected (commented)"
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert "wardline-install:filigree" in text
    assert "# filigree:" in text


def test_filigree_ephemeral_port_writes_live_stanza(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")
    filigree_dir = tmp_path / ".filigree"
    filigree_dir.mkdir()
    (filigree_dir / "ephemeral.port").write_text("8628", encoding="utf-8")

    results = record_bindings(tmp_path)

    assert results["filigree"] == "wired (discovered URL)"
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert 'filigree:\n  url: "http://localhost:8628/api/loom/scan-results"' in text


def test_clarion_yaml_http_bind_writes_live_stanza(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: "clarion")
    (tmp_path / "clarion.yaml").write_text(
        "serve:\n  http:\n    enabled: true\n    bind: 127.0.0.1:9111\n",
        encoding="utf-8",
    )

    results = record_bindings(tmp_path)

    assert results["clarion"] == "wired (discovered URL)"
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert 'clarion:\n  url: "http://127.0.0.1:9111"' in text


def test_clarion_yaml_http_disabled_remains_commented(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: "clarion")
    (tmp_path / "clarion.yaml").write_text(
        "serve:\n  http:\n    enabled: false\n    bind: 127.0.0.1:9111\n",
        encoding="utf-8",
    )

    results = record_bindings(tmp_path)

    assert results["clarion"] == "detected (commented)"
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert "# clarion:" in text
    assert 'url: "http://127.0.0.1:9111"' not in text


def test_record_bindings_rejects_symlinked_wardline_yaml(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_CLARION_URL", "http://clar:9100")
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    outside = tmp_path / "outside.yaml"
    outside.write_text("existing: true\n", encoding="utf-8")
    (tmp_path / "wardline.yaml").symlink_to(outside)

    with pytest.raises(WardlineError, match="symlink"):
        record_bindings(tmp_path)

    assert outside.read_text(encoding="utf-8") == "existing: true\n"


def test_env_url_writes_live_stanza(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_CLARION_URL", "http://clar:9100")
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    results = record_bindings(tmp_path)
    assert results["clarion"] == "wired (env URL)"
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert 'clarion:\n  url: "http://clar:9100"' in text


def test_existing_key_left_untouched(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_CLARION_URL", "http://new")
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / "wardline.yaml").write_text('clarion:\n  url: "http://existing"\n', encoding="utf-8")
    results = record_bindings(tmp_path)
    assert results["clarion"] == "present (left untouched)"
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert text.count("clarion:") == 1
    assert "http://new" not in text


def test_rerun_does_not_duplicate_commented_stanza(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")
    record_bindings(tmp_path)
    record_bindings(tmp_path)
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert text.count("wardline-install:filigree") == 1


def test_both_siblings_live_written_once(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_CLARION_URL", "http://clar:9100")
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://fil:9200/api/loom/scan-results")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    results = record_bindings(tmp_path)
    assert results == {"clarion": "wired (env URL)", "filigree": "wired (env URL)"}
    text = (tmp_path / "wardline.yaml").read_text(encoding="utf-8")
    assert text.count("clarion:") == 1
    assert text.count("filigree:") == 1


def test_appends_to_file_without_trailing_newline(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_CLARION_URL", "http://clar:9100")
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / "wardline.yaml").write_text("exclude:\n  - build", encoding="utf-8")  # no trailing \n
    assert record_bindings(tmp_path)["clarion"] == "wired (env URL)"
    # The result must still be loadable (no run-together lines).
    from wardline.core.config import load

    cfg = load(tmp_path / "wardline.yaml")
    assert cfg.clarion_url == "http://clar:9100"
    assert cfg.exclude == ("build",)


def test_url_with_quote_stays_valid_yaml(tmp_path: Path, monkeypatch) -> None:
    weird = 'http://h/p?q="v"'
    monkeypatch.setenv("WARDLINE_CLARION_URL", weird)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    record_bindings(tmp_path)
    from wardline.core.config import load

    cfg = load(tmp_path / "wardline.yaml")
    assert cfg.clarion_url == weird
