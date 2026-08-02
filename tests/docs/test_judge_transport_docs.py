from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_judge_docs_name_transport_selection_and_provenance() -> None:
    judge = _read("docs/guides/judge.md")
    config = _read("docs/guides/configuration.md")
    suppression = _read("docs/guides/suppression.md")

    assert all(value in judge for value in ("auto", "codex-cli", "openrouter"))
    assert "codex_model" in config and "transport" in config
    assert "judge_transport: codex-cli" in suppression
    assert "version: 2" in suppression


def test_judge_guide_documents_selection_isolation_and_live_verification() -> None:
    judge = _read("docs/guides/judge.md")

    assert "codex login" in judge
    assert "WARDLINE_OPENROUTER_API_KEY" in judge
    assert "does not switch" in judge
    assert "read_file" in judge and "grep_files" in judge and "glob_files" in judge
    assert "empty temporary" in judge
    assert "gpt-5.6-sol" in judge
    assert "reasoning effort" in judge
    assert "WARDLINE_CODEX_LIVE=1" in judge and "-m codex_live" in judge
    assert "initial finding excerpt is not secret-scrubbed" in judge
    assert "inspect every rationale before committing" in judge
    assert "HTTP 401/403" in judge and "skipped: transport" in judge
    assert "CLI and MCP" in judge and ".env" in judge


def test_cli_and_mcp_references_document_both_models_and_wire_provenance() -> None:
    cli = _read("docs/reference/cli.md")
    mcp = _read("docs/reference/mcp.md")

    assert "--transport" in cli and "--codex-model" in cli and "--model" in cli
    assert "judge_transport" in cli and "model_id" in cli
    assert "transport" in mcp and "codex_model" in mcp and "model" in mcp
    assert "judge_transport" in mcp and "model_id" in mcp


def test_public_docs_cover_v1_compatibility_and_remove_openrouter_only_claims() -> None:
    readme = _read("README.md")
    changelog = _read("CHANGELOG.md")
    suppression = _read("docs/guides/suppression.md")
    agents = _read("docs/guides/agents.md")

    assert "Codex CLI" in readme and "OpenRouter" in readme
    assert "Codex CLI judge transport" in changelog
    assert "legacy v1" in suppression and "OpenRouter" in suppression
    assert "version control" in suppression and "rollback" in suppression.lower()
    assert "--transport codex-cli" in agents and "--transport openrouter" in agents
    assert "OpenRouter-only" not in readme
    assert "OpenRouter-only" not in _read("docs/guides/judge.md")


def test_packaging_comment_describes_both_transport_adapters() -> None:
    pyproject = _read("pyproject.toml")

    assert "installed Codex CLI" in pyproject
    assert "stdlib urllib -> OpenRouter" not in pyproject
