# src/wardline/install/pre_commit.py
"""Setup pre-commit hook integration in .pre-commit-config.yaml."""

from __future__ import annotations

from pathlib import Path


def install_pre_commit_hook(root: Path) -> str:
    config_path = root / ".pre-commit-config.yaml"
    if not config_path.exists():
        return "skipped (no .pre-commit-config.yaml)"

    try:
        content = config_path.read_text(encoding="utf-8")
    except Exception as exc:
        return f"failed to read: {exc}"

    if "id: wardline-scan" in content:
        return "already configured"

    hook_block = """  - repo: local
    hooks:
      - id: wardline-scan
        name: wardline scan
        entry: wardline scan
        language: system
        types: [python]
        pass_filenames: false
"""
    try:
        if not content.strip():
            config_path.write_text("repos:\n" + hook_block, encoding="utf-8")
            return "added"

        if content.strip().endswith("repos:"):
            new_content = content + "\n" + hook_block
        else:
            new_content = content.rstrip() + "\n" + hook_block
        config_path.write_text(new_content + "\n", encoding="utf-8")
        return "added"
    except Exception as exc:
        return f"failed to write: {exc}"
