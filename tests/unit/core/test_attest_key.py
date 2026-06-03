# tests/unit/core/test_attest_key.py
"""Tests for wardline.core.attest_key: load, mint, key_id."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from wardline.core.attest_key import (
    WARDLINE_ATTEST_KEY_ENV,
    key_id,
    load_attest_key,
    mint_attest_key,
)
from wardline.core.errors import WardlineError

# ---------------------------------------------------------------------------
# Test 1: load_attest_key — env wins
# ---------------------------------------------------------------------------


def test_load_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Env var takes priority; no .env file needed."""
    monkeypatch.setenv(WARDLINE_ATTEST_KEY_ENV, "secret-from-env")
    assert load_attest_key(tmp_path) == "secret-from-env"


def test_load_returns_none_when_unset_and_no_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns None when env unset and root/.env absent."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    assert load_attest_key(tmp_path) is None


# ---------------------------------------------------------------------------
# Test 2: load_attest_key — parses .env with quotes stripped
# ---------------------------------------------------------------------------


def test_load_from_dotenv_double_quoted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reads double-quoted value from .env when env var is unset."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    (tmp_path / ".env").write_text('WARDLINE_ATTEST_KEY="abc123"\n', encoding="utf-8")
    assert load_attest_key(tmp_path) == "abc123"


def test_load_from_dotenv_single_quoted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reads single-quoted value from .env when env var is unset."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    (tmp_path / ".env").write_text("WARDLINE_ATTEST_KEY='abc123'\n", encoding="utf-8")
    assert load_attest_key(tmp_path) == "abc123"


def test_load_from_dotenv_unquoted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reads unquoted value from .env."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    (tmp_path / ".env").write_text("WARDLINE_ATTEST_KEY=plainvalue\n", encoding="utf-8")
    assert load_attest_key(tmp_path) == "plainvalue"


def test_load_env_wins_over_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Env var wins even when .env has a different value."""
    monkeypatch.setenv(WARDLINE_ATTEST_KEY_ENV, "from-env")
    (tmp_path / ".env").write_text('WARDLINE_ATTEST_KEY="from-dotenv"\n', encoding="utf-8")
    assert load_attest_key(tmp_path) == "from-env"


# ---------------------------------------------------------------------------
# Test 3: mint_attest_key — idempotency, key format, no duplicate lines
# ---------------------------------------------------------------------------


def test_mint_creates_dotenv_with_64hex_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh mint creates .env containing a 64-hex key and returns status='minted'."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    key, status = mint_attest_key(tmp_path)
    assert status == "minted"
    assert re.fullmatch(r"[0-9a-f]{64}", key), f"key not 64 hex: {key!r}"


def test_mint_rejects_symlinked_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    outside = tmp_path / "outside.env"
    outside.write_text("", encoding="utf-8")
    (tmp_path / ".env").symlink_to(outside)

    with pytest.raises(WardlineError, match="symlink"):
        mint_attest_key(tmp_path)

    assert outside.read_text(encoding="utf-8") == ""


def test_mint_key_loadable_after_mint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """load_attest_key returns the minted key immediately after minting."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    key, _ = mint_attest_key(tmp_path)
    assert load_attest_key(tmp_path) == key


def test_mint_idempotent_second_call_returns_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Second mint call returns same key with status='present'."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    key1, status1 = mint_attest_key(tmp_path)
    key2, status2 = mint_attest_key(tmp_path)
    assert status1 == "minted"
    assert status2 == "present"
    assert key1 == key2


def test_mint_no_duplicate_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """After two mint calls, .env has exactly one WARDLINE_ATTEST_KEY= line."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    mint_attest_key(tmp_path)
    mint_attest_key(tmp_path)
    lines = (tmp_path / ".env").read_text(encoding="utf-8").splitlines()
    matching = [ln for ln in lines if ln.startswith("WARDLINE_ATTEST_KEY=")]
    assert len(matching) == 1, f"Expected 1 WARDLINE_ATTEST_KEY= line, got: {matching}"


# ---------------------------------------------------------------------------
# Test 4: mint_attest_key — .gitignore handling
# ---------------------------------------------------------------------------


def test_mint_creates_gitignore_with_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh mint creates .gitignore containing '.env'."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    mint_attest_key(tmp_path)
    gi = tmp_path / ".gitignore"
    assert gi.exists()
    lines = {ln.strip() for ln in gi.read_text(encoding="utf-8").splitlines()}
    assert ".env" in lines


def test_mint_appends_dotenv_to_existing_gitignore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Mint appends .env to a pre-existing .gitignore that lacks it."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    gi = tmp_path / ".gitignore"
    gi.write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
    mint_attest_key(tmp_path)
    lines = {ln.strip() for ln in gi.read_text(encoding="utf-8").splitlines()}
    assert ".env" in lines
    assert "__pycache__/" in lines  # original lines preserved


def test_mint_does_not_duplicate_dotenv_in_gitignore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Mint does not add a second .env line when .gitignore already has one."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    gi = tmp_path / ".gitignore"
    gi.write_text(".env\n*.pyc\n", encoding="utf-8")
    mint_attest_key(tmp_path)
    lines = [ln.strip() for ln in gi.read_text(encoding="utf-8").splitlines() if ln.strip()]
    dotenv_count = lines.count(".env")
    assert dotenv_count == 1, f"Expected 1 .env line, got {dotenv_count}"


# ---------------------------------------------------------------------------
# Test 5: key_id
# ---------------------------------------------------------------------------


def test_key_id_is_8_lowercase_hex(monkeypatch: pytest.MonkeyPatch) -> None:
    """key_id returns 8 lowercase hex characters."""
    kid = key_id("some-key")
    assert re.fullmatch(r"[0-9a-f]{8}", kid), f"key_id not 8 hex: {kid!r}"


def test_key_id_stable_for_same_key() -> None:
    """key_id is deterministic for the same input."""
    assert key_id("stable-key") == key_id("stable-key")


def test_key_id_different_for_different_keys() -> None:
    """key_id differs for different keys."""
    assert key_id("key-one") != key_id("key-two")


def test_mint_sets_permissions_on_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """mint_attest_key sets .env file permissions to owner-only read/write (0o600)."""
    import stat
    import sys

    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    mint_attest_key(tmp_path)
    env_file = tmp_path / ".env"
    assert env_file.exists()

    if sys.platform != "win32":
        mode = env_file.stat().st_mode
        # Mode on POSIX check for owner-only read/write (0o600 -> S_IRUSR | S_IWUSR)
        assert stat.S_IMODE(mode) == 0o600
