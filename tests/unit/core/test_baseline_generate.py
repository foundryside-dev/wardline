from pathlib import Path

import pytest
import yaml

from wardline.core.baseline import generate_baseline, load_baseline
from wardline.core.paths import baseline_path
from wardline.core.run import run_scan

# A trusted boundary returning an external-tainted value: PY-WL-101 ERROR defect.
# sample_project itself is CLEAN (zero defects), so we build a leaky project here.
# Mirrors `_LEAKY` in tests/unit/core/test_run.py and tests/unit/cli/test_cli.py.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _leaky_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def test_generate_baseline_writes_file_and_counts(tmp_path: Path) -> None:
    proj = _leaky_project(tmp_path)
    count = generate_baseline(proj, overwrite=False)
    bl_path = baseline_path(proj)
    assert bl_path.is_file()
    assert count >= 1
    assert len(load_baseline(bl_path).fingerprints) == count


def test_generate_baseline_refuses_existing_without_overwrite(tmp_path: Path) -> None:
    proj = _leaky_project(tmp_path)
    generate_baseline(proj, overwrite=False)
    try:
        generate_baseline(proj, overwrite=False)
    except FileExistsError:
        pass
    else:
        raise AssertionError("expected FileExistsError when baseline exists")


def test_generate_baseline_overwrite_succeeds(tmp_path: Path) -> None:
    proj = _leaky_project(tmp_path)
    generate_baseline(proj, overwrite=False)
    count = generate_baseline(proj, overwrite=True)
    assert count >= 1


def test_generate_baseline_uses_scan_pipeline_for_trusted_packs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_root = Path(__file__).resolve().parents[3]
    monkeypatch.syspath_prepend(str(project_root))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "weft.toml").write_text('[wardline]\npacks = ["tests.unit.install.mock_pack"]\n', encoding="utf-8")
    (proj / "m.py").write_text("def violator():\n    pass\n", encoding="utf-8")

    scan = run_scan(
        proj,
        trust_local_packs=True,
        trusted_packs=("tests.unit.install.mock_pack",),
    )
    scan_fingerprints = {f.fingerprint for f in scan.findings if f.rule_id == "PY-WL-901"}
    assert scan_fingerprints

    count = generate_baseline(
        proj,
        overwrite=False,
        trust_local_packs=True,
        trusted_packs=("tests.unit.install.mock_pack",),
    )

    baseline_doc = yaml.safe_load(baseline_path(proj).read_text(encoding="utf-8"))
    baseline_entries = baseline_doc["entries"]
    assert count >= 1
    assert any(
        entry["rule_id"] == "PY-WL-901" and entry["fingerprint"] in scan_fingerprints for entry in baseline_entries
    )
