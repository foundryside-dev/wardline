"""Copy the bundled wardline-gate skill into a project's .claude / .agents."""

from __future__ import annotations

import shutil
from pathlib import Path


def _skill_source() -> Path:
    # src/wardline/install/skill.py -> src/wardline/skills/wardline-gate
    return Path(__file__).resolve().parent.parent / "skills" / "wardline-gate"


def install_skill(root: Path) -> dict[str, str]:
    """Copy the skill into .claude/skills and .agents/skills (idempotent overwrite).

    Returns a per-target status: created | overwritten.
    """
    src = _skill_source()
    results: dict[str, str] = {}
    for base in (".claude", ".agents"):
        dest = root / base / "skills" / "wardline-gate"
        existed = dest.exists()
        if existed:
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dest)
        results[base] = "overwritten" if existed else "created"
    return results
