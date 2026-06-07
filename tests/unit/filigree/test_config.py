"""load_filigree_token — the federation-scoped WEFT_FEDERATION_TOKEN is preferred
(env wins, then a single KEY=VALUE line in root/.env), with the deprecated
WARDLINE_FILIGREE_TOKEN honored as a fallback. Else None.
Mirrors the loomweave token loader (tests/unit/loomweave/test_config.py shape)."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.filigree.config import (
    WARDLINE_FILIGREE_TOKEN_ENV,
    WEFT_FEDERATION_TOKEN_ENV,
    load_filigree_token,
)


@pytest.fixture(autouse=True)
def _clear_token_env(monkeypatch) -> None:
    # Both names may leak in from the real environment — clear them so each test
    # controls the full picture.
    monkeypatch.delenv(WEFT_FEDERATION_TOKEN_ENV, raising=False)
    monkeypatch.delenv(WARDLINE_FILIGREE_TOKEN_ENV, raising=False)


def test_env_value_wins(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(WEFT_FEDERATION_TOKEN_ENV, "from-env")
    (tmp_path / ".env").write_text(f"{WEFT_FEDERATION_TOKEN_ENV}=from-file\n", encoding="utf-8")
    assert load_filigree_token(tmp_path) == "from-env"


def test_dot_env_fallback_when_env_unset(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(f'{WEFT_FEDERATION_TOKEN_ENV}="from-file"\n', encoding="utf-8")
    assert load_filigree_token(tmp_path) == "from-file"  # surrounding quotes stripped


def test_none_when_unset_and_no_file(tmp_path: Path) -> None:
    assert load_filigree_token(tmp_path) is None


def test_none_when_dot_env_lacks_the_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("OTHER=x\n", encoding="utf-8")
    assert load_filigree_token(tmp_path) is None


def test_legacy_name_honored_as_fallback_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(WARDLINE_FILIGREE_TOKEN_ENV, "legacy-env")
    assert load_filigree_token(tmp_path) == "legacy-env"


def test_legacy_name_honored_as_fallback_dot_env(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(f"{WARDLINE_FILIGREE_TOKEN_ENV}=legacy-file\n", encoding="utf-8")
    assert load_filigree_token(tmp_path) == "legacy-file"


def test_new_name_wins_over_legacy_when_both_set(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(WEFT_FEDERATION_TOKEN_ENV, "new")
    monkeypatch.setenv(WARDLINE_FILIGREE_TOKEN_ENV, "legacy")
    assert load_filigree_token(tmp_path) == "new"


def test_new_name_in_dot_env_wins_over_legacy_in_dot_env(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        f"{WARDLINE_FILIGREE_TOKEN_ENV}=legacy-file\n{WEFT_FEDERATION_TOKEN_ENV}=new-file\n",
        encoding="utf-8",
    )
    assert load_filigree_token(tmp_path) == "new-file"


def test_new_name_in_dot_env_wins_over_legacy_in_environment(monkeypatch, tmp_path: Path) -> None:
    # The migration-relevant cross-tier rung: the new name is resolved FULLY (env then
    # .env) before the legacy name is consulted at all, so the new name in .env (rung 2)
    # beats the legacy name in the actual environment (rung 3) — a file entry outranks an
    # env var across the name boundary. This pins "new-name-first" where it could silently
    # regress to legacy-first (relevant while lacuna still exports WARDLINE_FILIGREE_TOKEN).
    monkeypatch.setenv(WARDLINE_FILIGREE_TOKEN_ENV, "legacy-env")
    (tmp_path / ".env").write_text(f"{WEFT_FEDERATION_TOKEN_ENV}=new-file\n", encoding="utf-8")
    assert load_filigree_token(tmp_path) == "new-file"
