"""Parity gate: re-running the engine over the frozen inputs must reproduce the
committed corpus BYTE-for-BYTE.

This is the cross-engine identity contract. When the Rust core lands it must pass
this test UNCHANGED — "parity corpus green" is the hard gate on the Rust cutover.
Verified determinism (see the ADR): in-process stable, path-independent,
cross-process (PYTHONHASHSEED), and cross-interpreter (CPython 3.12 == 3.13
byte-identical), so the gate runs on every CI interpreter with no skip.

Import is ``from golden.identity import _capture`` — the repo puts ``tests/`` on
``sys.path`` (pytest prepend mode), so the package is ``golden.identity``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("blake3", reason="identity facts capture needs wardline[clarion] (blake3)")

from golden.identity import _capture as c  # type: ignore[import-not-found]  # noqa: E402  (after importorskip)

_HERE = Path(__file__).parent
_INPUTS = {
    "sampleapp": _HERE / "fixtures" / "sampleapp",
    "stress": _HERE / "fixtures" / "stress",
}
_REGEN_HINT = (
    "identity corpus drift. If this is an INTENTIONAL, versioned rekey, regenerate with:\n"
    "  cd tests && PYTHONPATH=. python -m golden.identity.regen --reason '<why>'\n"
    "Otherwise this is a real regression — see /tmp/corpus_actual_<name>.json for the diff."
)


@pytest.mark.parametrize("name", sorted(_INPUTS))
def test_identity_corpus_is_byte_identical(name: str, request: pytest.FixtureRequest) -> None:
    root = _INPUTS[name]
    golden = (_HERE / "corpus" / f"{name}.json").read_text(encoding="utf-8")
    actual = c.to_json(c.capture(root))
    request.node.stash[_ACTUAL_KEY] = (name, actual)  # for the conftest dump-on-failure
    assert actual == golden, f"{name!r}: {_REGEN_HINT}"


def test_assure_posture_is_frozen(request: pytest.FixtureRequest) -> None:
    golden = (_HERE / "corpus" / "assure.json").read_text(encoding="utf-8")
    actual = c.to_json({k: c.capture_assure(v) for k, v in sorted(_INPUTS.items())})
    request.node.stash[_ACTUAL_KEY] = ("assure", actual)
    assert actual == golden, f"assure posture drift: {_REGEN_HINT}"


# --- Non-vacuity: a silently-empty/shallow corpus must NOT be allowed to pass ---
# Per input, per surface — so a fixture that stops anchoring boundaries (or a
# harness bug that empties a surface) fails loudly instead of freezing a vacuous
# oracle that the Rust engine's empty output would also satisfy.


def _capture(name: str) -> dict:
    import json

    return json.loads((_HERE / "corpus" / f"{name}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", sorted(_INPUTS))
def test_corpus_surface_non_vacuous(name: str) -> None:
    d = _capture(name)
    assert d["findings"], f"{name}: no identity-bearing findings captured"
    assert d["entity_spans"], f"{name}: no entity spans captured"
    assert d["facts"], f"{name}: no taint facts captured"
    assert d["sarif"]["runs"][0]["results"], f"{name}: empty SARIF results"
    assert d["explain"], f"{name}: no explain captured"
    rules = {f["rule_id"] for f in d["findings"]}
    assert "PY-WL-101" in rules, f"{name}: PY-WL-101 not present (rules={sorted(rules)})"
    # Every frozen span carries real line/col coordinates (the cross-engine risk).
    for span in d["entity_spans"]:
        loc = span["location"]
        assert loc["line_start"] is not None and loc["col_start"] is not None, f"{name}: null span {span['qualname']!r}"


def test_stress_freezes_span_edge_construct_spans() -> None:
    # The whole point of the stress fixture: its span-edge constructs (which
    # produce no finding) must have their spans frozen via entity_spans, so a
    # Rust parser rendering them differently is caught.
    qns = {s["qualname"] for s in _capture("stress")["entity_spans"]}
    for needle in ("func_with_unicode_café", "outer.<locals>.nested", "overloaded", "Service.make"):
        assert any(needle in q for q in qns), f"stress entity_spans missing span-edge construct {needle!r}"


def test_stress_covers_multiple_rules() -> None:
    rules = {f["rule_id"] for f in _capture("stress")["findings"]}
    assert len(rules) >= 2, f"stress fixture should exercise >=2 identity rules, got {sorted(rules)}"


def test_assure_corpus_has_no_waiver_debt() -> None:
    # Fixtures ship with no .wardline/ waivers, so waiver_debt must be empty —
    # otherwise build_posture's date.today() would date-poison the corpus.
    import json

    assure = json.loads((_HERE / "corpus" / "assure.json").read_text(encoding="utf-8"))
    for name, posture in assure.items():
        assert posture["waiver_debt"] == [], f"{name}: unexpected waiver_debt (fixture hygiene)"


# --- Fixture hygiene: nothing date/env dependent may travel with the fixtures ---


@pytest.mark.parametrize("name", sorted(_INPUTS))
def test_fixture_has_no_local_config(name: str) -> None:
    root = _INPUTS[name]
    assert not (root / ".wardline").exists(), f"{name}: fixture must not carry a .wardline/ dir"
    assert not (root / "wardline.yaml").exists(), f"{name}: fixture must not carry a wardline.yaml"


_ACTUAL_KEY = pytest.StashKey[tuple]()
