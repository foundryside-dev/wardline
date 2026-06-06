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
