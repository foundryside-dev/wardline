"""Copy the bundled wardline-gate skill into a project's .claude / .agents."""

from __future__ import annotations

import shutil
from pathlib import Path

from wardline.core.errors import WardlineError
from wardline.core.safe_paths import safe_project_path


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
        label = f"{base}/skills/wardline-gate"
        dest = safe_project_path(root, root / base / "skills" / "wardline-gate", label=label)
        existed = dest.exists() or dest.is_symlink()
        if existed:
            if dest.is_symlink():
                raise WardlineError(f"{label}: refusing to overwrite a symlink")
            if not dest.is_dir():
                raise WardlineError(f"{label}: expected a directory")
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest = safe_project_path(root, dest, label=label)
        shutil.copytree(src, dest)
        results[base] = "overwritten" if existed else "created"
    return results
