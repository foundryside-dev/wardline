"""Security: .env / federation-token reads must refuse a symlink that escapes the
project root, so an attacker-authored repo cannot exfil an outside file's contents
as a bearer token / judge API key (wardline-db67828599). Mirrors the symlink-refusal
shape of tests/unit/core/test_attest_key.py::test_mint_rejects_symlinked_dotenv."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from wardline.core.errors import WardlineError
from wardline.core.judge import _API_KEY_ENV
from wardline.core.judge_run import load_env_key
from wardline.filigree.config import (
    _FILIGREE_MINT_RELPATH,
    WARDLINE_FILIGREE_TOKEN_ENV,
    WEFT_FEDERATION_TOKEN_ENV,
    load_filigree_token,
)


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    # All three credential env names may leak in from the real environment — clear
    # them so each test controls the full picture (an unset env is the case where
    # the file-based read actually runs).
    monkeypatch.delenv(WEFT_FEDERATION_TOKEN_ENV, raising=False)
    monkeypatch.delenv(WARDLINE_FILIGREE_TOKEN_ENV, raising=False)
    monkeypatch.delenv(_API_KEY_ENV, raising=False)


def _outside_secret(tmp_path: Path, name: str, content: str) -> Path:
    """Write a secret file OUTSIDE the project root and return its path."""
    outside_root = tmp_path / "outside"
    outside_root.mkdir(exist_ok=True)
    secret = outside_root / name
    secret.write_text(content, encoding="utf-8")
    return secret


# ---------------------------------------------------------------------------
# Symlink-escape must be REFUSED (no token returned; behaves like attest_key)
# ---------------------------------------------------------------------------


def test_filigree_dotenv_symlink_escape_refused(tmp_path: Path) -> None:
    """_read_token: a .env symlinked to an outside secret is refused, not followed."""
    root = tmp_path / "root"
    root.mkdir()
    secret = _outside_secret(tmp_path, "stolen.env", f"{WEFT_FEDERATION_TOKEN_ENV}=EXFIL\n")
    (root / ".env").symlink_to(secret)
    with pytest.raises(WardlineError, match="symlink"):
        load_filigree_token(root)


def test_filigree_mint_symlink_escape_refused(tmp_path: Path) -> None:
    """_read_filigree_mint: a federation_token symlinked outside root is refused."""
    root = tmp_path / "root"
    root.mkdir()
    secret = _outside_secret(tmp_path, "stolen_token", "EXFIL-MINT")
    mint = root.joinpath(*_FILIGREE_MINT_RELPATH)
    mint.parent.mkdir(parents=True)
    mint.symlink_to(secret)
    with pytest.raises(WardlineError, match="symlink"):
        load_filigree_token(root)


def test_judge_dotenv_symlink_escape_refused(tmp_path: Path) -> None:
    """load_env_key: a .env symlinked to an outside secret is refused; the OpenRouter
    key is never set into the environment."""
    root = tmp_path / "root"
    root.mkdir()
    secret = _outside_secret(tmp_path, "stolen.env", f"{_API_KEY_ENV}=EXFIL-KEY\n")
    (root / ".env").symlink_to(secret)
    with pytest.raises(WardlineError, match="symlink"):
        load_env_key(root)
    assert _API_KEY_ENV not in os.environ


# ---------------------------------------------------------------------------
# Happy path preserved: a regular in-root file still yields the value
# ---------------------------------------------------------------------------


def test_filigree_normal_dotenv(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / ".env").write_text(f'{WEFT_FEDERATION_TOKEN_ENV}="ok"\n', encoding="utf-8")
    assert load_filigree_token(root) == "ok"


def test_filigree_normal_mint(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    mint = root.joinpath(*_FILIGREE_MINT_RELPATH)
    mint.parent.mkdir(parents=True)
    mint.write_text("mint-ok\n", encoding="utf-8")
    assert load_filigree_token(root) == "mint-ok"


def test_judge_normal_dotenv(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / ".env").write_text(f"{_API_KEY_ENV}=key-ok\n", encoding="utf-8")
    load_env_key(root)
    assert os.environ.get(_API_KEY_ENV) == "key-ok"
