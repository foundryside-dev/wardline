# tests/unit/loomweave/test_config.py
from wardline.loomweave.config import (
    WARDLINE_LOOMWEAVE_TOKEN_ENV,
    load_loomweave_token,
    resolve_project_name,
)


def test_env_var_wins_over_dotenv(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(f"{WARDLINE_LOOMWEAVE_TOKEN_ENV}=from-dotenv\n", encoding="utf-8")
    monkeypatch.setenv(WARDLINE_LOOMWEAVE_TOKEN_ENV, "from-env")
    assert load_loomweave_token(tmp_path) == "from-env"


def test_dotenv_used_when_env_unset(tmp_path, monkeypatch):
    monkeypatch.delenv(WARDLINE_LOOMWEAVE_TOKEN_ENV, raising=False)
    (tmp_path / ".env").write_text(f'{WARDLINE_LOOMWEAVE_TOKEN_ENV}="quoted-secret"\n', encoding="utf-8")
    assert load_loomweave_token(tmp_path) == "quoted-secret"


def test_dotenv_single_quoted_value_is_unquoted(tmp_path, monkeypatch):
    monkeypatch.delenv(WARDLINE_LOOMWEAVE_TOKEN_ENV, raising=False)
    (tmp_path / ".env").write_text(f"{WARDLINE_LOOMWEAVE_TOKEN_ENV}='single-secret'\n", encoding="utf-8")
    assert load_loomweave_token(tmp_path) == "single-secret"


def test_returns_none_when_unset_and_no_dotenv(tmp_path, monkeypatch):
    monkeypatch.delenv(WARDLINE_LOOMWEAVE_TOKEN_ENV, raising=False)
    assert load_loomweave_token(tmp_path) is None


def test_project_name_is_the_root_directory_name(tmp_path):
    proj = tmp_path / "my-project"
    proj.mkdir()
    assert resolve_project_name(proj) == "my-project"
