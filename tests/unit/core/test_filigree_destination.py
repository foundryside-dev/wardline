"""N1 / C-10(a): the emit destination must be visible at the caller so a wrong-project
write cannot read as silent success."""

from __future__ import annotations

from wardline.core.filigree_emit import filigree_destination, filigree_url_project


def test_url_project_from_query() -> None:
    assert filigree_url_project("http://127.0.0.1:8749/api/weft/scan-results?project=lacuna") == "lacuna"


def test_url_project_from_path() -> None:
    assert filigree_url_project("http://127.0.0.1:8749/api/p/lacuna/weft/scan-results") == "lacuna"


def test_url_project_none_when_unpinned() -> None:
    # The contamination shape: a bare endpoint pins no project, so Filigree resolves it
    # server-side and a misroute is invisible unless surfaced.
    assert filigree_url_project("http://127.0.0.1:8749/api/weft/scan-results") is None
    assert filigree_url_project(None) is None


def test_destination_pinned() -> None:
    d = filigree_destination("http://127.0.0.1:8749/api/weft/scan-results?project=lacuna")
    assert d == {
        "url": "http://127.0.0.1:8749/api/weft/scan-results?project=lacuna",
        "project": "lacuna",
        "project_pinned": True,
    }


def test_destination_unpinned_is_visible() -> None:
    d = filigree_destination("http://127.0.0.1:8749/api/weft/scan-results")
    assert d == {
        "url": "http://127.0.0.1:8749/api/weft/scan-results",
        "project": None,
        "project_pinned": False,
    }
