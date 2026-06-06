"""load_filigree_token — env wins, then a single KEY=VALUE line in root/.env, else None.
Mirrors the loomweave token loader (tests/unit/loomweave/test_config.py shape)."""

from __future__ import annotations

from pathlib import Path

from wardline.filigree.config import WARDLINE_FILIGREE_TOKEN_ENV, load_filigree_token


def test_env_value_wins(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(WARDLINE_FILIGREE_TOKEN_ENV, "from-env")
    (tmp_path / ".env").write_text(f"{WARDLINE_FILIGREE_TOKEN_ENV}=from-file\n", encoding="utf-8")
    assert load_filigree_token(tmp_path) == "from-env"


def test_dot_env_fallback_when_env_unset(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv(WARDLINE_FILIGREE_TOKEN_ENV, raising=False)
    (tmp_path / ".env").write_text(f'{WARDLINE_FILIGREE_TOKEN_ENV}="from-file"\n', encoding="utf-8")
    assert load_filigree_token(tmp_path) == "from-file"  # surrounding quotes stripped


def test_none_when_unset_and_no_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv(WARDLINE_FILIGREE_TOKEN_ENV, raising=False)
    assert load_filigree_token(tmp_path) is None


def test_none_when_dot_env_lacks_the_key(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv(WARDLINE_FILIGREE_TOKEN_ENV, raising=False)
    (tmp_path / ".env").write_text("OTHER=x\n", encoding="utf-8")
    assert load_filigree_token(tmp_path) is None
