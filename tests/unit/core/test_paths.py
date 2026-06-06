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
