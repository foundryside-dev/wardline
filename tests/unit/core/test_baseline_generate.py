from pathlib import Path

from wardline.core.baseline import generate_baseline, load_baseline

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
    baseline_path = proj / ".wardline" / "baseline.yaml"
    assert baseline_path.exists()
    assert count >= 1
    assert len(load_baseline(baseline_path).fingerprints) == count


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
