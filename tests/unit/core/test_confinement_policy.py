from pathlib import Path

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.confinement import SourceRootConfinement
from wardline.core.discovery import discover


def test_source_root_confinement_is_closed_and_named() -> None:
    assert SourceRootConfinement.PROJECT_ROOT.confines_to_project is True
    assert SourceRootConfinement.LEGACY_ALLOW_ESCAPE.confines_to_project is False
    assert {policy.value for policy in SourceRootConfinement} == {
        "project-root",
        "legacy-allow-escape",
    }


def test_discovery_rejects_boolean_policy(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="SourceRootConfinement"):
        discover(
            tmp_path,
            WardlineConfig(),
            source_root_confinement=True,  # type: ignore[arg-type]
        )
