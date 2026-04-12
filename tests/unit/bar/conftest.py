"""Shared fixtures for BAR unit tests."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from wardline import __version__ as _WARDLINE_VERSION
from wardline.cli.corpus_cmds import _compute_corpus_hash

_FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "bar" / "ledger"


@pytest.fixture()
def bar_fixture_repo(tmp_path: Path) -> Path:
    """Create a tiny committed git repo for BAR bundle tests."""
    repo_root = tmp_path / "repo"
    shutil.copytree(_FIXTURE_ROOT, repo_root)

    _git(repo_root, "init")
    _git(repo_root, "config", "user.email", "fixture@example.com")
    _git(repo_root, "config", "user.name", "Fixture User")
    _git(repo_root, "add", ".")
    _git(repo_root, "commit", "-m", "fixture snapshot")
    commit_ref = _git(repo_root, "rev-parse", "HEAD")

    template_path = repo_root / "ledger-template.json"
    template = json.loads(template_path.read_text(encoding="utf-8"))
    freshness_binding = template["obligations"][0]["freshness_binding"]
    manifest_hash = _sha256(repo_root / "wardline.yaml")
    corpus_hash = _compute_corpus_hash(repo_root / "corpus")
    freshness_binding["commit_ref"] = commit_ref
    freshness_binding["manifest_hash"] = manifest_hash
    freshness_binding["corpus_hash"] = corpus_hash
    (repo_root / "wardline.compliance.json").write_text(
        json.dumps(template, indent=2) + "\n",
        encoding="utf-8",
    )
    (repo_root / "wardline.conformance.json").write_text(
        json.dumps(
            {
                "cells_below_precision_floor": [],
                "cells_below_recall_floor": [],
                "gaps": [],
                "inputs": {
                    "tool_version": _WARDLINE_VERSION,
                    "commit_ref": commit_ref,
                    "manifest_hash": manifest_hash,
                    "corpus_hash": corpus_hash,
                },
                "summary": {
                    "failing_cells": 0,
                },
                "status": "pass",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    return repo_root


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
