"""The wardline↔legis declarations preview vector (spec §13.1 item 3): wardline
authors it, legis vendors it byte-identically. Coordinated/release jobs arm
the cross-repository byte comparison with LEGIS_REPO; standalone CI may skip."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

AUTHORITY = Path(__file__).parent / "fixtures" / "wardline-legis-declarations-preview.v1.json"


def test_vector_parses_and_carries_the_preview_key() -> None:
    vector = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    assert vector["contract"] == "weft/wardline-scan-artifact-declarations-preview"
    # `all(...)` over an empty list is True, so the non-emptiness check is what makes
    # the line below mean anything. Measured: emptying `valid` leaves this test green
    # here AND turns legis's two parametrised consumers into skips, so the property
    # this vector exists to pin would go unasserted in both repos at once.
    assert vector["valid"], "the preview vector must carry at least one case"
    assert all("declarations" in case["artifact"] for case in vector["valid"])


def test_legis_vendored_copy_is_byte_identical_when_present() -> None:
    configured_repo = os.environ.get("LEGIS_REPO")
    repo = configured_repo or "/home/john/legis"
    vendored = Path(repo) / "tests" / "contract" / "weft" / "vectors" / "wardline_declarations_preview.v1.json"
    if not vendored.exists():
        if configured_repo is not None:
            pytest.fail(f"missing required Legis receipt at {vendored}")
        pytest.skip(f"Legis checkout not present at {vendored}; Task 23 supplies LEGIS_REPO")
    assert vendored.read_bytes() == AUTHORITY.read_bytes()
