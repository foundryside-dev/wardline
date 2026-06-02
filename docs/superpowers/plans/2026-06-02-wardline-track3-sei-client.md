# Track 3 — SEI-client groundwork (T3.1–T3.3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Wardline a SEI-client abstraction that carries Clarion's Stable Entity Identity (SEI) as the opaque, preferred cross-tool binding handle, detects the `sei` capability and degrades honestly when it is absent, and proves the SEI never enters Wardline finding fingerprints — all built against the *spec'd* wire contract (Clarion does not serve SEI at runtime yet).

**Architecture:** A new stdlib-only module `src/wardline/clarion/identity.py` defines the two-axis status model (`IdentityStatus` alive/orphaned/unavailable × `ContentStatus` fresh/stale/unknown — never collapsed), an opaque `EntityBinding` handle (prefer SEI over locator, fallback explicit), `SeiCapability` detection, and a `SeiResolver` that wraps the existing `ClarionClient`. Three thin fail-soft methods are added to `ClarionClient` for the pinned `/api/v1/identity/*` + `/api/v1/_capabilities` routes. The change is **strictly additive**: `build_taint_facts` stays qualname-keyed (the locator→SEI re-key is T3.4, gated on Clarion shipping SEI). A direct golden-digest guard on `compute_finding_fingerprint` proves fingerprint isolation.

**Tech Stack:** Python 3 stdlib only (`dataclasses`, `enum`, `urllib`, `json`, `hashlib`). The base package stays zero-dependency; `identity.py` must not import `blake3` or any extra. Tests use the existing `FakeTransport` pattern + the normative Clarion fixtures (`get-api-v1-capabilities.json`, `sei-conformance-oracle.json`). `pytest-randomly` is in force (order-independence required).

**Source-of-truth contract (build against this, not an invented shape):**
- SEI standard §4 (wire contract) + §2/§2.1 (opacity, two orthogonal axes) — `docs/superpowers/specs/2026-06-01-loom-stable-entity-identity-conformance.md`
- Clarion ADR-038 — token `clarion:eid:<32hex>` (opaque, reserved prefix), `_capabilities.sei = {supported, version}`
- Pinned routes (Clarion integrated delivery plan T2.4): `POST /api/v1/identity/resolve` `{locator}` → `{sei, current_locator, content_hash, alive}` | `{alive:false}`; `GET /api/v1/identity/sei/{sei}` → `{current_locator, content_hash, alive}` | `{alive:false, lineage:[...]}`; `GET /api/v1/_capabilities`
- Normative fixtures: `/home/john/clarion/docs/federation/fixtures/get-api-v1-capabilities.json` and `.../sei-conformance-oracle.json` (the six shared scenarios; T3 implements the two consumer-side ones: `identity_round_trip_and_opacity`, `capability_absent`)

**Six build-time guardrails (advisor-reviewed — fold into the relevant tasks):**
1. **Hash-granularity false-green.** Clarion's resolve `content_hash` is the *entity-body* hash; Wardline's `content_hash_at_compute` is the *whole-file* hash. `content_status` is a dumb SAME-granularity compare of two caller-supplied values — it must NOT pull from two sources or mix the two granularities. No cross-source comparison anywhere in this track (that's T4.3).
2. **Degrade is fail-soft on EVERY failure mode** — including the capability probe. The probe and the resolve methods must NOT route through `_require_ok` (it raises). 404 / 401 / outage / missing-field / bad-body all collapse to "unsupported" / UNAVAILABLE, never an exception.
3. **Fingerprint isolation bite is the DIRECT guard** on `compute_finding_fingerprint` (golden digest + param-absence), not a scan test (near-vacuous since SEI isn't wired into the scan path). Demonstrate RED-first.
4. **Never-parse proof uses an ATYPICAL opaque token** round-tripped verbatim with no branching on its content (asserting the `clarion:eid:` prefix is itself a form of parsing — fine for the opacity round-trip assertion, but not the never-parse proof).
5. **Anchor tests to the normative fixtures** (drive mock bodies from them).
6. **Scope discipline:** additive only; `build_taint_facts` stays qualname-keyed; `resolve_sei` is IN (it is how ORPHANED is represented — consumer round-trip surface); `lineage` is DEFERRED (no T3.1–T3.3 consumer) — note this visibly, not silently.

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `src/wardline/clarion/identity.py` | The SEI-client abstraction: `IdentityStatus`, `ContentStatus`, `SeiCapability`, `EntityBinding`, `content_status`, `SeiResolver`. Stdlib-only. | Create |
| `src/wardline/clarion/client.py` | Add 3 fail-soft wire methods + 1 private soft-JSON helper for the SEI routes. | Modify |
| `tests/unit/core/test_fingerprint_sei_isolation.py` | T3.3 load-bearing guard: golden digest + param-absence on `compute_finding_fingerprint`. | Create |
| `tests/unit/clarion/test_sei_identity.py` | T3.1 model unit tests (capability parse, binding key preference, content_status, axis orthogonality). | Create |
| `tests/unit/clarion/test_sei_client_wire.py` | Wire-method tests (routes, payloads, HMAC, fail-soft bands). | Create |
| `tests/unit/clarion/test_sei_resolver.py` | T3.1/T3.2 resolver tests (capability gating, ALIVE/ORPHANED/UNAVAILABLE, never-parse, fixture-anchored). | Create |
| `tests/e2e/test_clarion_live.py` | T3.2 live degrade proof against a real `clarion serve` (no `sei` cap → honest fallback). | Modify |
| `docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md` | Tick T3.1–T3.3, set T3.4 ⛔, update Current-position. | Modify |
| `CHANGELOG.md` | `[Unreleased] Added` entry. | Modify |

---

## Task 1: Fingerprint-isolation guard (T3.3) — load-bearing, RED-first

**Files:**
- Test: `tests/unit/core/test_fingerprint_sei_isolation.py` (create)
- (No src change — `compute_finding_fingerprint` in `src/wardline/core/finding.py:133` already excludes SEI; this task PROVES and LOCKS that.)

The guard lives next to what it protects (`core.finding`, zero-dep). The golden hex is computed **independently** (not via the function under test) so the test is not self-referential: a change to the fingerprint input set (e.g. folding `sei` in) flips the literal and the test goes red.

- [ ] **Step 1: Write the guard test.**

```python
# tests/unit/core/test_fingerprint_sei_isolation.py
"""Track 3 T3.3 — the SEI must NOT enter Wardline finding fingerprints.

The finding fingerprint is the stable cross-run identity baselines and waivers key
on; the SEI is a cross-tool BINDING key, a different concept. If the SEI ever leaked
into `compute_finding_fingerprint` it would silently invalidate every baseline/waiver
and break the warm/cold byte-identical guarantee. This guard locks the fingerprint's
input set: the golden hex below is computed INDEPENDENTLY of the function (see the
module docstring's recipe), so any added/removed input — including an SEI — flips it.
"""

from __future__ import annotations

import inspect

from wardline.core.finding import compute_finding_fingerprint

# Independently computed (NOT via compute_finding_fingerprint):
#   parts = ("PY-WL-101", "pkg/mod.py", "42", "pkg.mod.f", "EXTERNAL_RAW")
#   hashlib.sha256("\x00".join(parts).encode()).hexdigest()
_GOLDEN = "2f10c79df56839bfce49b31359bd392240cf146ef7280190baa5666d1ff25126"


def test_fingerprint_matches_independent_golden() -> None:
    # If anyone folds a new input (e.g. an SEI) into the fingerprint, this fails.
    fp = compute_finding_fingerprint(
        rule_id="PY-WL-101",
        path="pkg/mod.py",
        line_start=42,
        qualname="pkg.mod.f",
        taint_path="EXTERNAL_RAW",
    )
    assert fp == _GOLDEN


def test_fingerprint_has_no_sei_or_identity_parameter() -> None:
    # Structural guard: the fingerprint signature must not grow an SEI/identity input.
    params = set(inspect.signature(compute_finding_fingerprint).parameters)
    assert "sei" not in params
    assert "identity" not in params
    assert "binding_key" not in params
    assert params == {"rule_id", "path", "line_start", "qualname", "taint_path"}


def test_fingerprint_rejects_sei_keyword() -> None:
    # Belt-and-braces: passing an SEI keyword is a TypeError (no such input exists).
    import pytest

    with pytest.raises(TypeError):
        compute_finding_fingerprint(  # type: ignore[call-arg]
            rule_id="PY-WL-101", path="p.py", line_start=1, sei="clarion:eid:deadbeef"
        )
```

- [ ] **Step 2: Run it — expect GREEN** (the impl already isolates SEI; this is a characterization guard, not a feature).

Run: `uv run pytest tests/unit/core/test_fingerprint_sei_isolation.py -v`
Expected: 3 passed.

- [ ] **Step 3: Demonstrate the guard BITES (RED-first proof).** Temporarily edit `src/wardline/core/finding.py:142` to fold an SEI placeholder into the tuple:

```python
    parts = (rule_id, path, str(line_start), qualname or "", taint_path or "", "sei-leak")
```

Run: `uv run pytest tests/unit/core/test_fingerprint_sei_isolation.py::test_fingerprint_matches_independent_golden -v`
Expected: **FAIL** (digest differs from `_GOLDEN`). This proves the guard would catch an SEI leak.

- [ ] **Step 4: Revert the `finding.py` edit exactly** (restore line 142 to the original 5-tuple). Re-run Step 2 → GREEN. `git diff src/wardline/core/finding.py` must be empty.

- [ ] **Step 5: Commit.**

```bash
git add tests/unit/core/test_fingerprint_sei_isolation.py
git commit -m "test(track3): fingerprint-isolation guard — SEI must not enter finding fingerprints (T3.3)"
```

---

## Task 2: The SEI-client model (T3.1) — `identity.py`

**Files:**
- Create: `src/wardline/clarion/identity.py`
- Test: `tests/unit/clarion/test_sei_identity.py`

- [ ] **Step 1: Write the failing model tests.**

```python
# tests/unit/clarion/test_sei_identity.py
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

# From get-api-v1-capabilities.json -> examples[0].response.body.sei
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
```

- [ ] **Step 2: Run — expect FAIL** (`ModuleNotFoundError: wardline.clarion.identity`).

Run: `uv run pytest tests/unit/clarion/test_sei_identity.py -v`

- [ ] **Step 3: Implement `identity.py`.**

```python
# src/wardline/clarion/identity.py
"""Track 3 (T3.1/T3.2): the SEI-client abstraction.

Carry Clarion's Stable Entity Identity (SEI) as the OPAQUE handle for cross-tool
bindings, with an honest two-axis status, and degrade gracefully when Clarion does
not (yet) serve SEI. Built against the spec'd wire contract (SEI standard §4 +
Clarion ADR-038 + the normative fixtures); Clarion's runtime does not serve SEI yet,
so the live path degrades and the SEI-present path is exercised with mocks.

Stdlib-only by contract: this module MUST NOT import blake3 or any extra, so importing
it never forces the [clarion] extra and the base package stays zero-dependency.

OPACITY: the SEI is an opaque token (`clarion:eid:<hex>`). This module NEVER parses,
pattern-matches, or derives meaning from it — it is carried verbatim and compared by
equality only. The two status axes are kept ORTHOGONAL and never collapsed:
  - identity axis (IdentityStatus): "is this the SAME entity?"  alive / orphaned / unavailable
  - content axis  (ContentStatus):  "has its CODE changed?"     fresh / stale / unknown
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping


class IdentityStatus(Enum):
    """Identity axis — 'is this the same entity?' Never inferred from content."""

    ALIVE = "alive"  # SEI resolves to a live binding
    ORPHANED = "orphaned"  # SEI exists but is orphaned/superseded (resolve_sei alive:false)
    UNAVAILABLE = "unavailable"  # no SEI obtainable — capability absent, or locator does not resolve


class ContentStatus(Enum):
    """Content axis — 'has its code changed?' Never inferred from identity."""

    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SeiCapability:
    """Whether a Clarion instance serves SEI (from GET /api/v1/_capabilities)."""

    supported: bool
    version: int | None = None

    @classmethod
    def from_capabilities(cls, body: Mapping[str, Any] | None) -> SeiCapability:
        """Parse the `_capabilities` body, fail-closed. Absent / non-mapping /
        malformed / `supported` not exactly True → unsupported (honest degrade);
        never raises."""
        if not isinstance(body, Mapping):
            return cls(supported=False)
        sei = body.get("sei")
        if not isinstance(sei, Mapping) or sei.get("supported") is not True:
            return cls(supported=False)
        version = sei.get("version")
        return cls(supported=True, version=version if isinstance(version, int) else None)


@dataclass(frozen=True, slots=True)
class EntityBinding:
    """A cross-tool binding handle for one entity, carrying both status axes.

    The SEI (when present) is the durable identity and the PREFERRED binding key;
    the locator is the mutable address. When no SEI is available the binding degrades
    honestly (identity=UNAVAILABLE) and the consumer keeps working on the locator —
    but the fallback is EXPLICIT (`keyed_on_sei` is False), never a silent treatment
    of a locator as a stable identity.

    `content_hash` (when set) is Clarion's ENTITY-BODY hash from resolve. It is NOT
    the same granularity as Wardline's whole-file `content_hash_at_compute`; never
    compare across the two (see `content_status`)."""

    locator: str
    sei: str | None = None
    identity: IdentityStatus = IdentityStatus.UNAVAILABLE
    content: ContentStatus = ContentStatus.UNKNOWN
    content_hash: str | None = None  # Clarion entity-body granularity

    @property
    def keyed_on_sei(self) -> bool:
        """True iff the stable identity (SEI) is the binding key."""
        return self.sei is not None

    @property
    def binding_key(self) -> str:
        """The key to bind on: the SEI when present (the stable identity), else the
        locator. Prefer-SEI per SEI standard §4 / REQ-C-04. When this returns the
        locator, `keyed_on_sei` is False and `identity` is UNAVAILABLE — the caller
        must surface that the binding is on a mutable address, not an identity."""
        return self.sei if self.sei is not None else self.locator


def content_status(stored_hash: str | None, current_hash: str | None) -> ContentStatus:
    """Compare two content hashes OF THE SAME GRANULARITY.

    The caller GUARANTEES both hashes are the same granularity (both entity-body, OR
    both whole-file). Do NOT pass Clarion's entity-body `content_hash` against
    Wardline's whole-file `content_hash_at_compute` — different spans hash differently
    and the result would be a permanent false-STALE. Cross-granularity harmonisation
    is out of scope here (SEI standard §2 note; deferred to T4.3).

    Unknown on either side → UNKNOWN (honest; never guess FRESH)."""
    if stored_hash is None or current_hash is None:
        return ContentStatus.UNKNOWN
    return ContentStatus.FRESH if stored_hash == current_hash else ContentStatus.STALE
```

(The `SeiResolver` class is added in Task 4, after the client wire methods it depends on exist — Task 3.)

- [ ] **Step 4: Run — expect GREEN.**

Run: `uv run pytest tests/unit/clarion/test_sei_identity.py -v`
Expected: all passed.

- [ ] **Step 5: Commit.**

```bash
git add src/wardline/clarion/identity.py tests/unit/clarion/test_sei_identity.py
git commit -m "feat(track3): SEI-client model — opaque EntityBinding + two-axis status + capability (T3.1)"
```

---

## Task 3: Clarion client SEI wire methods (T3.1)

**Files:**
- Modify: `src/wardline/clarion/client.py`
- Test: `tests/unit/clarion/test_sei_client_wire.py`

Three fail-soft methods for the pinned routes, sharing one private soft-JSON helper. **All fail-soft** (guardrail 2): a `None` return means "degrade" (outage / non-2xx / bad body). They never route through `_require_ok`.

- [ ] **Step 1: Write the failing wire tests.**

```python
# tests/unit/clarion/test_sei_client_wire.py
"""Track 3 T3.1 — ClarionClient SEI wire methods: correct routes/payloads, HMAC
signing, and fail-soft on every non-happy band. Built against the pinned
/api/v1/identity/* + /api/v1/_capabilities routes (Clarion delivery plan T2.4)."""

from __future__ import annotations

import json

from wardline.clarion._hmac import sign_request
from wardline.clarion.client import ClarionClient, Response


class FakeTransport:
    def __init__(self, responses=None):
        self.calls = []
        self._responses = list(responses or [])

    def request(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))
        if self._responses:
            return self._responses.pop(0)
        return Response(status=200, body="{}")


def _client(transport, **kw):
    return ClarionClient("http://clarion.example", secret="s3cr3t", project="proj", transport=transport, **kw)


def test_capabilities_gets_route_and_parses() -> None:
    body = json.dumps({"sei": {"supported": True, "version": 1}})
    t = FakeTransport([Response(status=200, body=body)])
    caps = _client(t).capabilities()
    assert caps == {"sei": {"supported": True, "version": 1}}
    method, url, _, _ = t.calls[0]
    assert method == "GET"
    assert url == "http://clarion.example/api/v1/_capabilities"


def test_capabilities_soft_none_on_404() -> None:
    # A pre-SEI Clarion 404s the route — must degrade to None, never raise.
    t = FakeTransport([Response(status=404, body="not found")])
    assert _client(t).capabilities() is None


def test_capabilities_soft_none_on_bad_body() -> None:
    t = FakeTransport([Response(status=200, body="<<not json>>")])
    assert _client(t).capabilities() is None


def test_resolve_identity_posts_locator_and_signs() -> None:
    body = json.dumps(
        {"sei": "clarion:eid:abc", "current_locator": "python:function:m.f", "content_hash": "h", "alive": True}
    )
    t = FakeTransport([Response(status=200, body=body)])
    data = _client(t).resolve_identity("python:function:m.f")
    assert data["alive"] is True and data["sei"] == "clarion:eid:abc"
    method, url, sent_body, headers = t.calls[0]
    assert method == "POST"
    assert url == "http://clarion.example/api/v1/identity/resolve"
    assert json.loads(sent_body) == {"locator": "python:function:m.f"}
    expected = sign_request("s3cr3t", "POST", "/api/v1/identity/resolve", sent_body)
    assert headers["X-Loom-Component"] == f"clarion:{expected}"


def test_resolve_identity_alive_false_is_a_value_not_an_error() -> None:
    t = FakeTransport([Response(status=200, body='{"alive": false}')])
    assert _client(t).resolve_identity("python:function:gone") == {"alive": False}


def test_resolve_identity_soft_none_on_4xx() -> None:
    t = FakeTransport([Response(status=400, body='{"code":"NOT_A_LOCATOR"}')])
    assert _client(t).resolve_identity("python:function:m.f") is None


def test_resolve_sei_gets_escaped_opaque_token() -> None:
    body = json.dumps({"current_locator": "python:function:m.f", "alive": True})
    t = FakeTransport([Response(status=200, body=body)])
    # A token with URL-significant chars proves it is escaped, never interpreted.
    data = _client(t).resolve_sei("clarion:eid:a/b c?d")
    assert data["alive"] is True
    method, url, _, _ = t.calls[0]
    assert method == "GET"
    assert url == "http://clarion.example/api/v1/identity/sei/clarion%3Aeid%3Aa%2Fb%20c%3Fd"


def test_resolve_sei_orphaned_returns_lineage_value() -> None:
    t = FakeTransport([Response(status=200, body='{"alive": false, "lineage": []}')])
    assert _client(t).resolve_sei("clarion:eid:orph") == {"alive": False, "lineage": []}


def test_resolve_sei_soft_none_on_outage() -> None:
    t = FakeTransport([Response(status=503, body="")])
    assert _client(t).resolve_sei("clarion:eid:x") is None
```

- [ ] **Step 2: Run — expect FAIL** (`AttributeError: 'ClarionClient' object has no attribute 'capabilities'`).

Run: `uv run pytest tests/unit/clarion/test_sei_client_wire.py -v`

- [ ] **Step 3: Add the methods to `ClarionClient`** (in `src/wardline/clarion/client.py`, after `batch_get`). Note: `_send` already returns `None` on outage/5xx and signs when a secret is set; these methods add the read-side soft band (any non-2xx → `None`) so the identity read path degrades rather than raising. `urllib.parse` is already imported at module top.

```python
    def _send_json_soft(self, method: str, path_and_query: str, payload: dict[str, Any] | None) -> dict[str, Any] | None:
        """Send + parse a JSON object, FAIL-SOFT on every non-happy band. Returns the
        parsed dict on a 2xx with a JSON-object body; None on outage/5xx (``_send``),
        any other non-2xx (e.g. a pre-SEI Clarion's 404, a 4xx), or a non-object/bad
        body. The SEI identity READ path degrades rather than raising — unlike the
        WRITE path, a 4xx here is not load-bearing (SEI standard §4 degrade contract).
        It never routes through ``_require_ok`` (which raises on non-2xx)."""
        resp = self._send(method, path_and_query, payload)
        if resp is None or not 200 <= resp.status < 300:
            return None
        try:
            parsed = json.loads(resp.body) if resp.body else {}
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def capabilities(self) -> dict[str, Any] | None:
        """GET /api/v1/_capabilities → the parsed capability dict, or None when the
        probe fails for ANY reason (a pre-SEI Clarion 404s the route). Lets a consumer
        detect a non-SEI Clarion and degrade rather than guess."""
        return self._send_json_soft("GET", "/api/v1/_capabilities", None)

    def resolve_identity(self, locator: str) -> dict[str, Any] | None:
        """POST /api/v1/identity/resolve {locator} → {sei, current_locator,
        content_hash, alive:true} or {alive:false}; None on a soft failure. ``locator``
        is a Wardline-side address (qualname-form), never an SEI."""
        return self._send_json_soft("POST", "/api/v1/identity/resolve", {"locator": locator})

    def resolve_sei(self, sei: str) -> dict[str, Any] | None:
        """GET /api/v1/identity/sei/{sei} → {current_locator, content_hash, alive:true}
        or {alive:false, lineage:[...]}; None on a soft failure. ``sei`` is OPAQUE — it
        is only URL-escaped for the path segment, never parsed or interpreted."""
        quoted = urllib.parse.quote(sei, safe="")
        return self._send_json_soft("GET", f"/api/v1/identity/sei/{quoted}", None)
```

- [ ] **Step 4: Run — expect GREEN.**

Run: `uv run pytest tests/unit/clarion/test_sei_client_wire.py -v`

- [ ] **Step 5: Commit.**

```bash
git add src/wardline/clarion/client.py tests/unit/clarion/test_sei_client_wire.py
git commit -m "feat(track3): ClarionClient SEI wire methods (resolve/resolve_sei/capabilities), fail-soft (T3.1)"
```

---

## Task 4: `SeiResolver` — capability gating + graceful degrade (T3.1/T3.2)

> **Post-review note (as built):** the method named `is_orphaned` below was renamed to
> `resolve_identity_status` during the code-review panel (an `is_`-prefixed method returning
> a 3-valued `IdentityStatus`, not a bool, is a footgun) and made three-way explicit:
> `alive:true`→ALIVE, `alive:false`→ORPHANED, anything else→UNAVAILABLE (never guess ORPHANED
> from a malformed/`alive`-absent body — a convergent HIGH false-green finding). The code
> blocks below reflect the original draft; the shipped code is the renamed/three-way form.

**Files:**
- Modify: `src/wardline/clarion/identity.py` (append `SeiResolver`)
- Test: `tests/unit/clarion/test_sei_resolver.py`

- [ ] **Step 1: Write the failing resolver tests** (fixture-anchored; cover the two consumer-side oracle scenarios + the never-parse proof).

```python
# tests/unit/clarion/test_sei_resolver.py
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
```

- [ ] **Step 2: Run — expect FAIL** (`ImportError: cannot import name 'SeiResolver'`).

Run: `uv run pytest tests/unit/clarion/test_sei_resolver.py -v`

- [ ] **Step 3: Append `SeiResolver` to `identity.py`** (after `content_status`). Add `from __future__` already present; `Any` already imported.

```python
class SeiResolver:
    """Resolves locators → :class:`EntityBinding` via a ClarionClient, honoring
    capability detection and degrading gracefully. The SEI is treated strictly opaque.

    DEFERRED (no T3.1–T3.3 consumer): `lineage(sei)` — Clarion serves it (SEI std §4)
    but no Wardline groundwork path consumes the event log yet (it is a Track 4 dossier
    / legis-audit concern). `resolve_sei` IS implemented because the ORPHANED identity
    status is part of this track's two-axis model. This split is intentional, not an
    omission."""

    def __init__(self, client: Any, capability: SeiCapability) -> None:
        self._client = client
        self._capability = capability

    @property
    def capability(self) -> SeiCapability:
        return self._capability

    @classmethod
    def detect(cls, client: Any) -> SeiResolver:
        """Probe `_capabilities` once and bind the resolver to the result. A probe
        that fails for ANY reason (outage / a pre-SEI Clarion's 404 / malformed body →
        `client.capabilities()` returns None) yields an unsupported capability, so the
        resolver degrades."""
        return cls(client, SeiCapability.from_capabilities(client.capabilities()))

    def resolve_locator(self, locator: str) -> EntityBinding:
        """Resolve a locator to its binding. When SEI is unsupported, return an
        UNAVAILABLE binding WITHOUT touching the wire. When supported: `alive:true`
        with a usable opaque SEI → ALIVE (SEI carried verbatim, `current_locator`
        adopted); `alive:false` / soft outage / malformed → UNAVAILABLE (no live
        identity for this locator — honest, never a guess)."""
        if not self._capability.supported:
            return EntityBinding(locator=locator)
        data = self._client.resolve_identity(locator)
        if not isinstance(data, dict) or data.get("alive") is not True:
            return EntityBinding(locator=locator)
        sei = data.get("sei")
        if not isinstance(sei, str) or not sei:
            return EntityBinding(locator=locator)
        current = data.get("current_locator")
        chash = data.get("content_hash")
        return EntityBinding(
            locator=current if isinstance(current, str) and current else locator,
            sei=sei,  # opaque — carried verbatim, never parsed
            identity=IdentityStatus.ALIVE,
            content_hash=chash if isinstance(chash, str) else None,
        )

    def is_orphaned(self, sei: str) -> IdentityStatus:
        """The identity axis for a held SEI, via resolve_sei. ALIVE / ORPHANED, or
        UNAVAILABLE when the capability is absent or the read soft-fails (never guess).
        `sei` is opaque — passed verbatim to the client, never parsed."""
        if not self._capability.supported:
            return IdentityStatus.UNAVAILABLE
        data = self._client.resolve_sei(sei)
        if not isinstance(data, dict):
            return IdentityStatus.UNAVAILABLE
        return IdentityStatus.ALIVE if data.get("alive") is True else IdentityStatus.ORPHANED
```

- [ ] **Step 4: Run — expect GREEN.**

Run: `uv run pytest tests/unit/clarion/test_sei_resolver.py -v`

- [ ] **Step 5: Commit.**

```bash
git add src/wardline/clarion/identity.py tests/unit/clarion/test_sei_resolver.py
git commit -m "feat(track3): SeiResolver — capability gating + graceful degrade + opaque carry (T3.1/T3.2)"
```

---

## Task 5: Live degrade proof (T3.2) + full gate + tracker/CHANGELOG

**Files:**
- Modify: `tests/e2e/test_clarion_live.py` (add one `clarion_e2e` test)
- Modify: `docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add a live graceful-degrade test** to `tests/e2e/test_clarion_live.py`. Reuse the file's existing `_resolve_clarion`, `_free_port`, `_wait_for_capabilities` helpers and the server-startup pattern already used by the SP9 round-trip test in that file. The real `clarion serve` (v1.0.1) advertises NO `sei` capability, so this is a genuine oracle for the degrade path — not a mock.

```python
def test_sei_capability_absent_degrades_live(tmp_path: Path) -> None:
    """The route-capable clarion serve advertises no `sei` capability yet. A consumer
    must detect that and degrade honestly (identity unavailable), never crash — the
    SEI conformance oracle's `capability_absent` scenario, proven live."""
    from wardline.clarion.client import ClarionClient
    from wardline.clarion.identity import IdentityStatus, SeiResolver

    binary = _resolve_clarion()
    if binary is None:
        pytest.skip("no route-capable clarion binary (set WARDLINE_CLARION_BIN)")
    # ... start `clarion serve` over a tmp project exactly as the SP9 round-trip test
    # in this file does (analyze -> serve -> _wait_for_capabilities), then:
    client = ClarionClient(base_url, secret=_SECRET, project=tmp_path.name)
    resolver = SeiResolver.detect(client)
    assert resolver.capability.supported is False  # no sei cap on today's Clarion
    binding = resolver.resolve_locator("python:function:does.not.matter")
    assert binding.identity is IdentityStatus.UNAVAILABLE
    assert binding.sei is None
    assert binding.binding_key == "python:function:does.not.matter"  # degrades to locator, honestly
```

> Implementer note: factor the analyze+serve boilerplate from the existing round-trip test into a small local helper or a fixture if it reduces duplication; do NOT change the existing test's behavior. If the existing test already yields a running-server fixture, reuse it.

- [ ] **Step 2: Run the live e2e** (opt-in; auto-skips if no route-capable binary).

Run: `WARDLINE_CLARION_BIN=~/clarion/target/release/clarion uv run pytest -m clarion_e2e -v`
Expected: the new test passes (or all `clarion_e2e` skip cleanly if the binary is absent — acceptable, the hermetic resolver tests already cover degrade).

- [ ] **Step 3: Run the full default gate.**

```bash
uv run pytest                                  # full suite — expect all pass
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
make test-cov                                  # 90% global floor; clarion subpackage well-covered
```

- [ ] **Step 4: Verify the two cross-cutting DoD invariants explicitly.**

```bash
# Warm/cold byte-identical findings test still green (SEI touches nothing on this path):
uv run pytest tests/unit/scanner/taint/test_summary.py tests/unit/scanner/taint/test_project_resolver.py -k "warm or cold or byte" -v
# Dogfood stays finding-clean (identity.py is plain dataclasses/enums — no trust tier, no broad except):
uv run wardline scan src/wardline --fail-on ERROR
# Base stays zero-dependency: identity.py imports stdlib only (no blake3 / extra).
uv run python -c "import ast,sys; mod=ast.parse(open('src/wardline/clarion/identity.py').read()); imps=[n.module or '' for n in ast.walk(mod) if isinstance(n,ast.ImportFrom)]+[a.name for n in ast.walk(mod) if isinstance(n,ast.Import) for a in n.names]; bad=[i for i in imps if i.split('.')[0] in {'blake3','yaml','jsonschema','click','mkdocs'}]; sys.exit('EXTRA IMPORT LEAK: '+repr(bad) if bad else 0)"
```

Expected: warm/cold green; dogfood exit 0; no extra-import leak.

- [ ] **Step 5: Update the progress tracker.** In `docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md`:
  - Track 3 table: set T3.1, T3.2, T3.3 status to ☑; set T3.4 status to ⛔ (gate already named "Clarion SEI").
  - Track 3 header: change `**☐ not started**` to `**◐ groundwork done (T3.1–T3.3); T3.4 ⛔ Clarion SEI**`.
  - Update the **Current position** line to record Track 3 groundwork complete on `feat/track3-sei-client` (branched off `loom-step-up`), the three DoD gates green (fingerprint isolation, graceful degrade, opacity/never-parse), and what is next.

- [ ] **Step 6: Add a CHANGELOG entry** under `[Unreleased] → Added`:

```
- SEI-client groundwork (Track 3, T3.1–T3.3): an opt-in `wardline[clarion]` SEI
  abstraction (`wardline.clarion.identity`) carrying Clarion's Stable Entity Identity
  as the opaque, preferred cross-tool binding handle, with honest two-axis status
  (identity alive/orphaned/unavailable × content fresh/stale/unknown) and graceful
  degrade when a Clarion instance does not advertise the `sei` capability. The SEI is
  never parsed and never enters Wardline finding fingerprints (guarded). Built against
  the spec'd wire contract (SEI standard §4 + Clarion ADR-038); the locator→SEI fact
  re-key (T3.4) is gated on Clarion shipping SEI.
```

- [ ] **Step 7: Commit the close-out.**

```bash
git add docs/superpowers/specs/2026-06-02-wardline-first-class-progress-tracker.md CHANGELOG.md tests/e2e/test_clarion_live.py
git commit -m "docs(track3): mark T3.1-T3.3 done; live degrade e2e; CHANGELOG (Track 3 groundwork)"
```

---

## Definition of Done (gate before declaring complete)

- [ ] Fingerprint-isolation guard green AND demonstrated to bite (RED-first proof in Task 1 Step 3).
- [ ] Graceful-degrade: `sei` capability absent → honest UNAVAILABLE, no crash (hermetic resolver test + live e2e proof).
- [ ] Opacity / never-parse: an atypical opaque token round-trips verbatim with no branching (Task 4).
- [ ] `make ci` equivalent passes: `ruff check` + `ruff format --check` + `mypy` (strict) + `pytest` + 90% coverage floor; clarion subpackage well-covered.
- [ ] Base stays zero-dependency (identity.py stdlib-only; verified in Task 5 Step 4).
- [ ] Dogfood finding-clean; warm/cold byte-identical test green.
- [ ] Strictly additive: `build_taint_facts` unchanged (no locator→SEI re-key — that is T3.4).
- [ ] Tracker + CHANGELOG updated and committed.
- [ ] Default code-review panel (incl. a SECURITY lens aimed at: hash-granularity false-green, a degrade path that raises, SEI leaking into the fingerprint) run; convergent must-fixes applied.
- [ ] Filigree T3.1 / T3.2 / T3.3 closed with `--actor`.
