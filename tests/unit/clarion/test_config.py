# tests/unit/clarion/test_config.py
from wardline.clarion.config import (
    WARDLINE_CLARION_TOKEN_ENV,
    load_clarion_token,
    resolve_project_name,
)


def test_env_var_wins_over_dotenv(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(f"{WARDLINE_CLARION_TOKEN_ENV}=from-dotenv\n", encoding="utf-8")
    monkeypatch.setenv(WARDLINE_CLARION_TOKEN_ENV, "from-env")
    assert load_clarion_token(tmp_path) == "from-env"


def test_dotenv_used_when_env_unset(tmp_path, monkeypatch):
    monkeypatch.delenv(WARDLINE_CLARION_TOKEN_ENV, raising=False)
    (tmp_path / ".env").write_text(f'{WARDLINE_CLARION_TOKEN_ENV}="quoted-secret"\n', encoding="utf-8")
    assert load_clarion_token(tmp_path) == "quoted-secret"


def test_dotenv_single_quoted_value_is_unquoted(tmp_path, monkeypatch):
    monkeypatch.delenv(WARDLINE_CLARION_TOKEN_ENV, raising=False)
    (tmp_path / ".env").write_text(f"{WARDLINE_CLARION_TOKEN_ENV}='single-secret'\n", encoding="utf-8")
    assert load_clarion_token(tmp_path) == "single-secret"


def test_returns_none_when_unset_and_no_dotenv(tmp_path, monkeypatch):
    monkeypatch.delenv(WARDLINE_CLARION_TOKEN_ENV, raising=False)
    assert load_clarion_token(tmp_path) is None


def test_project_name_is_the_root_directory_name(tmp_path):
    proj = tmp_path / "my-project"
    proj.mkdir()
    assert resolve_project_name(proj) == "my-project"
