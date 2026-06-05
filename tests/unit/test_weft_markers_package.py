from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_weft_markers_runtime_import_does_not_require_wardline_package(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2]
    package_src = repo / "packages" / "weft-markers" / "src"
    script = tmp_path / "app.py"
    script.write_text(
        "import importlib.abc\n"
        "import sys\n"
        "\n"
        "class BlockWardline(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, fullname, path=None, target=None):\n"
        "        if fullname == 'wardline' or fullname.startswith('wardline.'):\n"
        "            raise ModuleNotFoundError('blocked wardline import', name='wardline')\n"
        "        return None\n"
        "\n"
        "sys.meta_path.insert(0, BlockWardline())\n"
        "\n"
        "from weft_markers import external_boundary, trust_boundary, trusted\n"
        "\n"
        "@external_boundary\n"
        "def read_raw():\n"
        "    return 'raw'\n"
        "\n"
        "@trust_boundary(to_level='ASSURED')\n"
        "def validate(value):\n"
        "    return value\n"
        "\n"
        "@trusted\n"
        "def produce():\n"
        "    return validate(read_raw())\n"
        "\n"
        "print(produce())\n"
        "print(hasattr(read_raw, '_wardline_groups'))\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(package_src)

    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["raw", "True"]
