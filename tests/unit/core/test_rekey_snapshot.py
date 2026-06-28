"""P4 S4 — pre-flight snapshot: copy existing stores only, never clobber."""

from __future__ import annotations

from pathlib import Path

from wardline.core import paths
from wardline.core.rekey import snapshot_dir, snapshot_stores


def test_snapshot_copies_existing_stores_only(tmp_path: Path) -> None:
    root = tmp_path
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    (state / "baseline.yaml").write_text("baseline-bytes", encoding="utf-8")
    (state / "waivers.yaml").write_text("waivers-bytes", encoding="utf-8")
    # judged.yaml deliberately absent

    present = snapshot_stores(root)
    assert set(present) == {"baseline.yaml", "waivers.yaml"}

    sdir = snapshot_dir(root)
    assert (sdir / "baseline.yaml").read_text(encoding="utf-8") == "baseline-bytes"
    assert (sdir / "waivers.yaml").read_text(encoding="utf-8") == "waivers-bytes"
    assert not (sdir / "judged.yaml").exists()


def test_snapshot_is_idempotent_and_never_clobbers(tmp_path: Path) -> None:
    root = tmp_path
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    (state / "baseline.yaml").write_text("ORIGINAL", encoding="utf-8")
    snapshot_stores(root)

    # A second invocation after the live store changed must NOT overwrite the
    # snapshot — it is the immutable pre-migration provenance source.
    (state / "baseline.yaml").write_text("REWRITTEN-BY-A-PARTIAL-RUN", encoding="utf-8")
    present = snapshot_stores(root)
    assert "baseline.yaml" in present
    assert (snapshot_dir(root) / "baseline.yaml").read_text(encoding="utf-8") == "ORIGINAL"


def test_snapshot_skips_symlinked_live_store(tmp_path: Path) -> None:
    root = tmp_path
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    outside = tmp_path.parent / f"{tmp_path.name}-outside-baseline.yaml"
    outside.write_text("SECRET-BYTES", encoding="utf-8")
    (state / "baseline.yaml").symlink_to(outside)

    assert snapshot_stores(root) == ()
    assert not (snapshot_dir(root) / "baseline.yaml").exists()
