"""Track 3 T3.1 — the SEI-client model: capability parse, opaque binding handle,
two orthogonal status axes. Bodies are anchored to Clarion's normative fixtures
(get-api-v1-capabilities.json / sei-conformance-oracle.json)."""

from __future__ import annotations

from wardline.clarion.identity import (
    ContentStatus,
    EntityBinding,
    IdentityStatus,
    SeiCapability,
    content_status,
)

# From get-api-v1-capabilities.json -> examples[0].response.body
_CAPS_SEI_PRESENT = {
    "registry_backend": True,
    "api_version": 1,
    "linkages": {"http": True},
    "sei": {"supported": True, "version": 1},
}


def test_capability_present_from_fixture() -> None:
    cap = SeiCapability.from_capabilities(_CAPS_SEI_PRESENT)
    assert cap.supported is True
    assert cap.version == 1


def test_capability_absent_when_no_sei_key() -> None:
    cap = SeiCapability.from_capabilities({"registry_backend": True, "linkages": {"http": True}})
    assert cap.supported is False
    assert cap.version is None


def test_capability_absent_when_supported_false() -> None:
    assert SeiCapability.from_capabilities({"sei": {"supported": False}}).supported is False


def test_capability_fail_closed_on_garbage() -> None:
    # None / non-mapping / malformed sei -> unsupported, never raises.
    assert SeiCapability.from_capabilities(None).supported is False
    assert SeiCapability.from_capabilities({"sei": "yes"}).supported is False  # type: ignore[arg-type]
    assert SeiCapability.from_capabilities({"sei": {"supported": True}}).version is None


def test_binding_prefers_sei_when_present() -> None:
    b = EntityBinding(
        locator="python:function:pkg.mod.f",
        sei="clarion:eid:0123456789abcdef0123456789abcdef",
        identity=IdentityStatus.ALIVE,
    )
    assert b.keyed_on_sei is True
    assert b.binding_key == "clarion:eid:0123456789abcdef0123456789abcdef"


def test_binding_falls_back_to_locator_explicitly_when_no_sei() -> None:
    b = EntityBinding(locator="python:function:pkg.mod.f")
    assert b.keyed_on_sei is False
    assert b.binding_key == "python:function:pkg.mod.f"
    assert b.identity is IdentityStatus.UNAVAILABLE  # honest, not a silent identity


def test_axes_are_orthogonal_defaults() -> None:
    # Neither axis is inferred from the other; both default to the honest "unknown".
    b = EntityBinding(locator="x")
    assert b.identity is IdentityStatus.UNAVAILABLE
    assert b.content is ContentStatus.UNKNOWN


def test_content_status_same_granularity_compare() -> None:
    assert content_status("h", "h") is ContentStatus.FRESH
    assert content_status("h", "h2") is ContentStatus.STALE
    assert content_status(None, "h") is ContentStatus.UNKNOWN
    assert content_status("h", None) is ContentStatus.UNKNOWN
