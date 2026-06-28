from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FULL_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")


def test_pages_workflow_pins_site_kit_fetch_to_commit_sha() -> None:
    workflow = (ROOT / ".github" / "workflows" / "deploy-site.yml").read_text(encoding="utf-8")

    ref_match = re.search(r"WEFT_SITE_KIT_REF:\s*([0-9a-f]{40})\b", workflow)

    assert ref_match is not None
    assert FULL_SHA_RE.fullmatch(ref_match.group(1))
    assert "WEFT_SITE_KIT_REF || 'main'" not in (ROOT / "site" / "scripts" / "fetch-site-kit.mjs").read_text(
        encoding="utf-8"
    )


def test_fetch_site_kit_rejects_mutable_ref_in_github_actions() -> None:
    env = {
        **os.environ,
        "GITHUB_ACTIONS": "true",
        "WEFT_SITE_KIT_REMOTE": "1",
        "WEFT_SITE_KIT_REPO": "file:///definitely/not/a/repo.git",
        "WEFT_SITE_KIT_REF": "main",
    }

    result = subprocess.run(
        ["node", "scripts/fetch-site-kit.mjs"],
        cwd=ROOT / "site",
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 1
    assert "WEFT_SITE_KIT_REF must be a 40-character commit SHA" in result.stderr
    assert "not a git repository" not in result.stderr.lower()
