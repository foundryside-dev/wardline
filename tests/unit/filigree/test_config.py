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


def test_legacy_environment_wins_over_new_name_in_dot_env(monkeypatch, tmp_path: Path) -> None:
    # Process environment is operator-controlled; root/.env may come from the scanned
    # repository. All environment aliases must outrank all project .env aliases, even
    # across the canonical/legacy name boundary.
    monkeypatch.setenv(WARDLINE_FILIGREE_TOKEN_ENV, "legacy-env")
    (tmp_path / ".env").write_text(f"{WEFT_FEDERATION_TOKEN_ENV}=new-file\n", encoding="utf-8")
    assert load_filigree_token(tmp_path) == "legacy-env"


# ---------------------------------------------------------------------------
# Rung 3: filigree's auto-minted project-store federation_token (F1 / C-3).
# The zero-ceremony rung — a same-host install with NO env/.env/.mcp.json reads
# the file filigree mints and validates against, so the client token matches the
# daemon with no operator config.
# ---------------------------------------------------------------------------


def _mint_filigree_token(root: Path, value: str) -> Path:
    """Write a 0600 federation_token under <root>/.weft/filigree/ as filigree would."""
    store = root / ".weft" / "filigree"
    store.mkdir(parents=True, exist_ok=True)
    path = store / "federation_token"
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def test_mint_file_read_when_env_and_dot_env_unset(tmp_path: Path) -> None:
    _mint_filigree_token(tmp_path, "minted-tok")
    assert load_filigree_token(tmp_path) == "minted-tok"  # trailing newline stripped


def test_env_overrides_mint_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(WEFT_FEDERATION_TOKEN_ENV, "from-env")
    _mint_filigree_token(tmp_path, "minted-tok")
    assert load_filigree_token(tmp_path) == "from-env"


def test_dot_env_overrides_mint_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(f"{WEFT_FEDERATION_TOKEN_ENV}=from-file\n", encoding="utf-8")
    _mint_filigree_token(tmp_path, "minted-tok")
    assert load_filigree_token(tmp_path) == "from-file"


def test_legacy_env_overrides_mint_file(monkeypatch, tmp_path: Path) -> None:
    # Process environment is operator-controlled and outranks every repo-local token
    # source, including the same-host mint file.
    monkeypatch.setenv(WARDLINE_FILIGREE_TOKEN_ENV, "legacy-env")
    _mint_filigree_token(tmp_path, "minted-tok")
    assert load_filigree_token(tmp_path) == "legacy-env"


def test_mint_file_wins_over_legacy_dot_env(tmp_path: Path) -> None:
    # The same-host mint file still outranks a deprecated repo-local .env fallback.
    (tmp_path / ".env").write_text(f"{WARDLINE_FILIGREE_TOKEN_ENV}=legacy-file\n", encoding="utf-8")
    _mint_filigree_token(tmp_path, "minted-tok")
    assert load_filigree_token(tmp_path) == "minted-tok"


def test_missing_mint_file_falls_through_to_legacy(monkeypatch, tmp_path: Path) -> None:
    # No mint file present → clean fall-through to the legacy rung (no crash).
    monkeypatch.setenv(WARDLINE_FILIGREE_TOKEN_ENV, "legacy-env")
    assert load_filigree_token(tmp_path) == "legacy-env"


def test_empty_mint_file_falls_through(tmp_path: Path) -> None:
    # A blank/whitespace mint file is treated as absent (→ off here).
    _mint_filigree_token(tmp_path, "   ")
    assert load_filigree_token(tmp_path) is None


def test_unreadable_mint_dir_falls_through_cleanly(tmp_path: Path) -> None:
    # A directory where the file should be (or any OSError) must not crash — emit
    # soft-fails, never hard-fails the scan.
    store = tmp_path / ".weft" / "filigree"
    store.mkdir(parents=True, exist_ok=True)
    (store / "federation_token").mkdir()  # a dir, not a file → read_text raises OSError
    assert load_filigree_token(tmp_path) is None
