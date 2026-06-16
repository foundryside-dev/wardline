"""P4 S10 — forward-only rollback: restore YAML byte-identical, remove journal+snapshot."""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core import paths
from wardline.core.errors import WardlineError
from wardline.core.rekey import rollback, snapshot_dir


def test_rollback_restores_yaml_byte_identical(tmp_path: Path) -> None:
    root = tmp_path
    state = paths.weft_state_dir(root)
    state.mkdir(parents=True)
    sdir = snapshot_dir(root)
    sdir.mkdir(parents=True)

    original = b"fingerprint_scheme: wlfp1\nversion: 1\nentries: []\n"
    (sdir / "baseline.yaml").write_bytes(original)  # the pre-migration snapshot
    (state / "baseline.yaml").write_bytes(b"REKEYED-wlfp2-CONTENT")  # the migrated live store
    paths.migration_journal_path(root).write_text("schema_version: 1\nremap: {}\n", encoding="utf-8")

    result = rollback(root)

    assert result.restored == ("baseline.yaml",)
    assert (state / "baseline.yaml").read_bytes() == original  # byte-identical restore
    assert not paths.migration_journal_path(root).exists()  # journal removed
    assert not (sdir / "baseline.yaml").exists()  # snapshot cleaned up


def test_rollback_without_snapshot_raises(tmp_path: Path) -> None:
    with pytest.raises(WardlineError, match="nothing to roll back"):
        rollback(tmp_path)
