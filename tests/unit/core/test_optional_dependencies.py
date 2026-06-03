from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_BLOCK_OPTIONAL_IMPORTS = r"""
import importlib.abc
import sys


class BlockOptional(importlib.abc.MetaPathFinder):
    def __init__(self, names):
        self.names = set(names)

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".", 1)[0] in self.names:
            raise ModuleNotFoundError(f"No module named {fullname!r}", name=fullname.split(".", 1)[0])
        return None


for loaded in list(sys.modules):
    if loaded.split(".", 1)[0] in {"click", "jsonschema", "yaml"}:
        del sys.modules[loaded]
sys.meta_path.insert(0, BlockOptional({"click", "jsonschema", "yaml"}))
"""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _run_blocked_optional_script(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    repo = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{repo / 'src'}{os.pathsep}{repo}{os.pathsep}{env.get('PYTHONPATH', '')}"
    return subprocess.run(
        [sys.executable, "-c", _BLOCK_OPTIONAL_IMPORTS + script, *args],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_base_import_surface_does_not_import_scanner_extra_modules() -> None:
    result = _run_blocked_optional_script(
        """
import importlib

for module in [
    "wardline",
    "wardline.core.errors",
    "wardline.core.finding",
    "wardline.core.taints",
    "wardline.core.config",
    "wardline.core.baseline",
    "wardline.core.descriptor",
    "wardline.core.judged",
    "wardline.core.waivers",
    "wardline.scanner.taint.stdlib_taint",
    "wardline.install.pack",
    "wardline.cli.entrypoint",
]:
    importlib.import_module(module)
"""
    )

    assert result.returncode == 0, result.stderr


def test_yaml_operations_report_missing_scanner_extra(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.yaml"
    baseline_path.write_text("version: 1\nentries: []\n", encoding="utf-8")

    result = _run_blocked_optional_script(
        """
from pathlib import Path

from wardline.core.baseline import load_baseline
from wardline.core.errors import ConfigError

try:
    load_baseline(Path(sys.argv[1]))
except ConfigError as exc:
    assert "wardline[scanner]" in str(exc), str(exc)
else:
    raise AssertionError("expected ConfigError when PyYAML is missing")
""",
        str(baseline_path),
    )

    assert result.returncode == 0, result.stderr


def test_console_script_targets_dependency_free_entrypoint() -> None:
    pyproject = (_repo_root() / "pyproject.toml").read_text(encoding="utf-8")
    assert 'wardline = "wardline.cli.entrypoint:main"' in pyproject
