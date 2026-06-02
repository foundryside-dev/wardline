"""Track 3 T3.1/T3.2 — SeiResolver: capability detection, prefer-SEI resolution, and
graceful degrade. Anchored to the SEI conformance oracle's two consumer-side
scenarios: `identity_round_trip_and_opacity` and `capability_absent`."""

from __future__ import annotations

from wardline.clarion.identity import IdentityStatus, SeiCapability, SeiResolver


class FakeClient:
    """Stands in for ClarionClient at the method boundary the resolver uses."""

    def __init__(self, *, caps=None, resolve=None, resolve_sei=None):
        self._caps = caps
        self._resolve = resolve
        self._resolve_sei = resolve_sei
        self.resolve_calls: list[str] = []
        self.sei_calls: list[str] = []
        self.capabilities_calls = 0

    def capabilities(self):
        self.capabilities_calls += 1
        return self._caps

    def resolve_identity(self, locator):
        self.resolve_calls.append(locator)
        return self._resolve

    def resolve_sei(self, sei):
        self.sei_calls.append(sei)
        return self._resolve_sei


_CAPS_PRESENT = {"sei": {"supported": True, "version": 1}}


def test_detect_reads_capability() -> None:
    r = SeiResolver.detect(FakeClient(caps=_CAPS_PRESENT))
    assert r.capability == SeiCapability(supported=True, version=1)


def test_round_trip_carries_opaque_sei_alive() -> None:
    # Oracle: identity_round_trip_and_opacity.
    resolve = {
        "sei": "clarion:eid:0123456789abcdef0123456789abcdef",
        "current_locator": "python:function:pkg.mod.renamed",
        "content_hash": "bodyhash",
        "alive": True,
    }
    client = FakeClient(caps=_CAPS_PRESENT, resolve=resolve)
    b = SeiResolver.detect(client).resolve_locator("python:function:pkg.mod.f")
    assert b.identity is IdentityStatus.ALIVE
    assert b.sei == "clarion:eid:0123456789abcdef0123456789abcdef"
    assert b.keyed_on_sei is True
    assert b.binding_key == b.sei
    assert b.locator == "python:function:pkg.mod.renamed"  # current_locator carried
    assert b.content_hash == "bodyhash"


def test_capability_absent_degrades_without_touching_wire() -> None:
    # Oracle: capability_absent — honest "identity unavailable", no crash, no resolve call.
    client = FakeClient(caps={"linkages": {"http": True}})  # no sei key
    r = SeiResolver.detect(client)
    b = r.resolve_locator("python:function:pkg.mod.f")
    assert r.capability.supported is False
    assert b.identity is IdentityStatus.UNAVAILABLE
    assert b.sei is None
    assert b.keyed_on_sei is False
    assert b.binding_key == "python:function:pkg.mod.f"  # works on the locator, honestly
    assert client.resolve_calls == []  # short-circuits — never hits the wire


def test_probe_outage_degrades() -> None:
    # capabilities() returns None (pre-SEI 404 / outage) -> unsupported -> degrade.
    client = FakeClient(caps=None)
    r = SeiResolver.detect(client)
    assert r.capability.supported is False
    assert r.resolve_locator("python:function:m.f").identity is IdentityStatus.UNAVAILABLE


def test_resolve_alive_false_is_unavailable_not_a_crash() -> None:
    client = FakeClient(caps=_CAPS_PRESENT, resolve={"alive": False})
    b = SeiResolver.detect(client).resolve_locator("python:function:gone")
    assert b.identity is IdentityStatus.UNAVAILABLE
    assert b.sei is None


def test_resolve_soft_outage_is_unavailable() -> None:
    client = FakeClient(caps=_CAPS_PRESENT, resolve=None)  # soft outage on resolve
    assert SeiResolver.detect(client).resolve_locator("m.f").identity is IdentityStatus.UNAVAILABLE


def test_alive_without_usable_sei_degrades_fail_closed() -> None:
    # Malformed: alive:true but no usable `sei` (missing / empty / non-str). The
    # resolver must NOT claim ALIVE without an identity — degrade to UNAVAILABLE.
    for bad in ({"alive": True}, {"alive": True, "sei": ""}, {"alive": True, "sei": 123}):
        client = FakeClient(caps=_CAPS_PRESENT, resolve=bad)
        b = SeiResolver.detect(client).resolve_locator("python:function:m.f")
        assert b.identity is IdentityStatus.UNAVAILABLE
        assert b.sei is None


def test_sei_carried_verbatim_never_parsed() -> None:
    # Guardrail 4: an ATYPICAL opaque token round-trips verbatim with no branching on
    # its content. The resolver must not validate, prefix-check, or transform it.
    weird = "TOTALLY-not-a-real-sei::///☃ #$%"
    client = FakeClient(caps=_CAPS_PRESENT, resolve={"sei": weird, "alive": True})
    b = SeiResolver.detect(client).resolve_locator("python:function:m.f")
    assert b.sei == weird
    assert b.binding_key == weird


def test_is_orphaned_maps_resolve_sei() -> None:
    alive = SeiResolver.detect(FakeClient(caps=_CAPS_PRESENT, resolve_sei={"alive": True}))
    assert alive.is_orphaned("clarion:eid:x") is IdentityStatus.ALIVE

    orph = SeiResolver.detect(FakeClient(caps=_CAPS_PRESENT, resolve_sei={"alive": False, "lineage": []}))
    assert orph.is_orphaned("clarion:eid:x") is IdentityStatus.ORPHANED

    # capability absent OR soft outage -> UNAVAILABLE (never guess alive/orphaned).
    assert SeiResolver(FakeClient(), SeiCapability(False)).is_orphaned("clarion:eid:x") is IdentityStatus.UNAVAILABLE
    soft = SeiResolver.detect(FakeClient(caps=_CAPS_PRESENT, resolve_sei=None))
    assert soft.is_orphaned("clarion:eid:x") is IdentityStatus.UNAVAILABLE
