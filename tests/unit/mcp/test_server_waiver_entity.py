"""waiver_add inline SEI-on-entry (the doctrine spine): a hand-filed waiver may bind
the code entity it suppresses, additively. entity_id (L1, opaque) is carried verbatim;
entity_symbol (L2) resolves through Loomweave; a non-resolving symbol returns
unresolved_input and writes NOTHING."""

from wardline.core.paths import waivers_path
from wardline.core.waivers import load_project_waivers
from wardline.mcp.server import _waiver_add

FP = "a" * 64


class SeiLoomweave:
    def capabilities(self):
        return {"sei": {"supported": True, "version": 1}}

    def resolve_identity(self, locator):
        return {
            "alive": True,
            "sei": "loomweave:eid:abc",
            "current_locator": locator,
            "content_hash": "hash-v1",
        }

    def resolve_sei(self, sei):
        return {"alive": True}


class DownLoomweave:
    def capabilities(self):
        return None


def test_waiver_add_no_entity_is_unchanged(tmp_path):
    out = _waiver_add(
        {"fingerprint": FP, "reason": "validated upstream", "expires": "2026-12-31"},
        tmp_path,
    )
    assert out["already_exists"] is False
    assert out["entity_sei"] is None
    assert out["entity_locator"] is None
    assert out["binding_kind"] is None
    (loaded,) = load_project_waivers(tmp_path)
    assert loaded.entity_sei is None


def test_waiver_add_l1_entity_id_carried_verbatim(tmp_path):
    out = _waiver_add(
        {
            "fingerprint": FP,
            "reason": "validated upstream",
            "expires": "2026-12-31",
            "entity_id": "loomweave:eid:held",
        },
        tmp_path,
        loomweave=None,  # L1 needs no resolve transport
    )
    assert out["entity_sei"] == "loomweave:eid:held"
    assert out["binding_kind"] == "sei"
    (loaded,) = load_project_waivers(tmp_path)
    assert loaded.entity_sei == "loomweave:eid:held"


def test_waiver_add_l2_symbol_resolves_to_sei(tmp_path):
    out = _waiver_add(
        {
            "fingerprint": FP,
            "reason": "validated upstream",
            "expires": "2026-12-31",
            "entity_symbol": "pkg.mod.leaky",
        },
        tmp_path,
        loomweave=SeiLoomweave(),
    )
    assert out["entity_sei"] == "loomweave:eid:abc"
    assert out["entity_locator"] == "python:function:pkg.mod.leaky"
    assert out["binding_kind"] == "sei"
    assert out["already_exists"] is False
    (loaded,) = load_project_waivers(tmp_path)
    assert loaded.entity_sei == "loomweave:eid:abc"


def test_waiver_add_l2_unresolved_writes_nothing(tmp_path):
    out = _waiver_add(
        {
            "fingerprint": FP,
            "reason": "validated upstream",
            "expires": "2026-12-31",
            "entity_symbol": "pkg.mod.ghost",
        },
        tmp_path,
        loomweave=DownLoomweave(),
    )
    assert out["created"] is False
    assert out["unresolved_input"]["reason_class"] == "unresolved_input"
    assert out["unresolved_input"]["cause"]
    assert out["unresolved_input"]["fix"]
    # The honesty contract: NOTHING was written.
    assert not waivers_path(tmp_path).exists()
    assert load_project_waivers(tmp_path) == ()


def test_waiver_add_l2_no_client_is_unresolved(tmp_path):
    out = _waiver_add(
        {
            "fingerprint": FP,
            "reason": "validated upstream",
            "expires": "2026-12-31",
            "entity_symbol": "pkg.mod.leaky",
        },
        tmp_path,
        loomweave=None,
    )
    assert out["unresolved_input"]["reason_class"] == "unresolved_input"
    assert not waivers_path(tmp_path).exists()


def test_waiver_add_existing_reports_stored_binding(tmp_path):
    _waiver_add(
        {
            "fingerprint": FP,
            "reason": "first",
            "expires": "2026-12-31",
            "entity_id": "loomweave:eid:held",
        },
        tmp_path,
    )
    out = _waiver_add(
        {"fingerprint": FP, "reason": "second", "expires": "2027-01-01"},
        tmp_path,
    )
    assert out["already_exists"] is True
    assert out["entity_sei"] == "loomweave:eid:held"
    assert out["binding_kind"] == "sei"
