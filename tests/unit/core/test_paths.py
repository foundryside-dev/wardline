from pathlib import Path

from wardline.core import paths


def test_member_and_config_constants():
    assert paths.WEFT_MEMBER == "wardline"
    assert paths.WEFT_CONFIG_FILE == "weft.toml"


def test_config_path():
    root = Path("/proj")
    assert paths.weft_config_path(root) == root / "weft.toml"


def test_state_dir_and_files():
    root = Path("/proj")
    assert paths.weft_state_dir(root) == root / ".weft" / "wardline"
    assert paths.baseline_path(root) == root / ".weft" / "wardline" / "baseline.yaml"
    assert paths.judged_path(root) == root / ".weft" / "wardline" / "judged.yaml"
    assert paths.waivers_path(root) == root / ".weft" / "wardline" / "waivers.yaml"


def test_sibling_state_dir_prefers_weft():
    root = Path("/proj")
    assert paths.sibling_state_dir(root, "filigree") == root / ".weft" / "filigree"
    assert paths.legacy_sibling_dir(root, "filigree") == root / ".filigree"
    assert paths.legacy_sibling_dir(root, "loomweave") == root / ".loomweave"


def test_store_dir_default_when_no_config(tmp_path):
    assert paths.weft_state_dir(tmp_path) == tmp_path / ".weft" / "wardline"


def test_store_dir_relative_override(tmp_path):
    (tmp_path / "weft.toml").write_text('[wardline]\nstore_dir = "var/wardline-state"\n', encoding="utf-8")
    assert paths.weft_state_dir(tmp_path) == tmp_path / "var" / "wardline-state"
    assert paths.baseline_path(tmp_path) == tmp_path / "var" / "wardline-state" / "baseline.yaml"


def test_store_dir_absolute_override(tmp_path):
    target = tmp_path / "abs-state"
    (tmp_path / "weft.toml").write_text(f'[wardline]\nstore_dir = "{target}"\n', encoding="utf-8")
    assert paths.weft_state_dir(tmp_path) == target


def test_store_dir_malformed_config_falls_back(tmp_path):
    (tmp_path / "weft.toml").write_text("[wardline]\nstore_dir = [\n", encoding="utf-8")
    assert paths.weft_state_dir(tmp_path) == tmp_path / ".weft" / "wardline"


def test_store_dir_absolute_outside_root_falls_back_to_default(tmp_path):
    # A malicious/typo'd absolute store_dir outside root must NOT redirect state
    # (consistent with the writers' safe_project_file confinement).
    outside = tmp_path.parent / "elsewhere-state"
    (tmp_path / "weft.toml").write_text(f'[wardline]\nstore_dir = "{outside}"\n', encoding="utf-8")
    assert paths.weft_state_dir(tmp_path) == tmp_path / ".weft" / "wardline"


def test_store_dir_relative_escape_falls_back_to_default(tmp_path):
    (tmp_path / "weft.toml").write_text('[wardline]\nstore_dir = "../escape"\n', encoding="utf-8")
    assert paths.weft_state_dir(tmp_path) == tmp_path / ".weft" / "wardline"


# --- enclosing_project_root (N-3: the scan root governs qualnames) -----------


def test_enclosing_project_root_none_when_root_has_weft_toml(tmp_path):
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    assert paths.enclosing_project_root(tmp_path) is None


def test_enclosing_project_root_none_when_root_has_state_dir(tmp_path):
    (tmp_path / ".weft" / "wardline").mkdir(parents=True)
    assert paths.enclosing_project_root(tmp_path) is None


def test_enclosing_project_root_finds_weft_toml_ancestor(tmp_path):
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    sub = tmp_path / "specimen"
    sub.mkdir()
    assert paths.enclosing_project_root(sub) == tmp_path.resolve()


def test_enclosing_project_root_finds_state_dir_ancestor_deep(tmp_path):
    (tmp_path / ".weft" / "wardline").mkdir(parents=True)
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    assert paths.enclosing_project_root(sub) == tmp_path.resolve()


def test_enclosing_project_root_nested_project_is_its_own_root(tmp_path):
    # A subdirectory that is its OWN weft project root (vendored tree) is not
    # "nested" — its markers win and no enclosing root is reported.
    (tmp_path / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    sub = tmp_path / "vendored"
    sub.mkdir()
    (sub / "weft.toml").write_text("[wardline]\n", encoding="utf-8")
    assert paths.enclosing_project_root(sub) is None


def test_enclosing_project_root_ignores_sibling_only_weft_dir(tmp_path):
    # A .weft/ holding only SIBLING members (filigree/loomweave) marks nothing for
    # wardline: neither operator config (weft.toml) nor wardline state exists, so
    # there is no baseline to miss and no [wardline] config to skip. (This also keeps
    # wardline's own repo — .weft/filigree only — from warning on in-repo fixture scans.)
    (tmp_path / ".weft" / "filigree").mkdir(parents=True)
    sub = tmp_path / "specimen"
    sub.mkdir()
    assert paths.enclosing_project_root(sub) is None


# --- project_root_for + artifacts_dir helpers --------------------------------


def _mark_project(root: Path) -> None:
    (root / "weft.toml").write_text("[wardline]\n", encoding="utf-8")


def test_project_root_for_self_when_marked(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    assert paths.project_root_for(tmp_path) == tmp_path.resolve()


def test_project_root_for_climbs_to_enclosing(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    assert paths.project_root_for(sub) == tmp_path.resolve()


def test_project_root_for_unfederated_is_self(tmp_path: Path) -> None:
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    assert paths.project_root_for(sub) == sub.resolve()


def test_artifacts_dir_default(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    assert paths.artifacts_dir(tmp_path, ".wardline") == (tmp_path.resolve() / ".wardline")


def test_artifacts_dir_relative_override(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    assert paths.artifacts_dir(tmp_path, "out/wl") == (tmp_path.resolve() / "out" / "wl")


def test_artifacts_dir_absolute_inside_honored(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    inside = tmp_path.resolve() / "build" / "wl"
    assert paths.artifacts_dir(tmp_path, str(inside)) == inside


def test_artifacts_dir_absolute_outside_falls_back(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    assert paths.artifacts_dir(tmp_path, "/etc/wardline") == (tmp_path.resolve() / ".wardline")


def test_artifacts_dir_dotdot_escape_falls_back(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    assert paths.artifacts_dir(tmp_path, "../../etc") == (tmp_path.resolve() / ".wardline")


def test_artifacts_dir_anchors_to_enclosing_for_subdir(tmp_path: Path) -> None:
    _mark_project(tmp_path)
    sub = tmp_path / "src" / "pkg"
    sub.mkdir(parents=True)
    assert paths.artifacts_dir(sub, ".wardline") == (tmp_path.resolve() / ".wardline")
