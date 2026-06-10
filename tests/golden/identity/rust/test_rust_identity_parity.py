"""Parity gate: re-running the Rust frontend over the frozen fixture crate must
reproduce the committed corpus BYTE-for-BYTE (the SP2 completion gate — RS-WL-*
finding identity graduated from provisional to baseline-eligible on this freeze).

The Rust sibling of ``golden.identity.test_identity_parity`` — same byte-equality
discipline, same regen accountability (``--reason`` stamped into META.json), same
dump-on-failure conftest. The captured surface is the PARTIAL mirror documented in
``_capture.py``/``README.md``: findings + entities + edges (no SARIF/facts/explain —
``RustAnalysisContext`` is not the Python ``AnalysisContext``).

Import is ``from golden.identity.rust import _capture`` — the repo puts ``tests/``
on ``sys.path`` (pytest prepend mode).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter", reason="Rust identity capture needs wardline[rust] (tree-sitter)")

from golden.identity.rust import _capture as c  # type: ignore[import-not-found]  # noqa: E402  (after importorskip)

_HERE = Path(__file__).parent
_INPUTS = {
    "rustapp": _HERE / "fixtures" / "rustapp",
}
_REGEN_HINT = (
    "Rust identity corpus drift. If this is an INTENTIONAL, versioned rekey, regenerate with:\n"
    "  cd tests && PYTHONPATH=. python -m golden.identity.rust.regen --reason '<why>'\n"
    "Otherwise this is a real regression — see /tmp/corpus_actual_rust_<name>.json for the diff."
)


def test_corpus_meta_has_engine_scheme() -> None:
    from wardline.core.finding import FINGERPRINT_SCHEME

    meta = json.loads((_HERE / "corpus" / "META.json").read_text(encoding="utf-8"))
    assert meta["fingerprint_scheme"] == FINGERPRINT_SCHEME


@pytest.mark.parametrize("name", sorted(_INPUTS))
def test_rust_identity_corpus_is_byte_identical(name: str, request: pytest.FixtureRequest) -> None:
    root = _INPUTS[name]
    golden = (_HERE / "corpus" / f"{name}.json").read_text(encoding="utf-8")
    actual = c.to_json(c.capture(root))
    request.node.stash[_ACTUAL_KEY] = (name, actual)  # for the conftest dump-on-failure
    assert actual == golden, f"{name!r}: {_REGEN_HINT}"


# --- Non-vacuity (Step 6.1b): a silently-empty/shallow corpus must NOT pass ---
# Permanent structural tests over the FROZEN JSON (not the live capture), so a
# fixture or harness change that hollows out a surface fails loudly instead of
# freezing a vacuous oracle.


def _corpus(name: str) -> dict:
    return json.loads((_HERE / "corpus" / f"{name}.json").read_text(encoding="utf-8"))


def test_corpus_freezes_a_finding_per_rule_with_real_fingerprints() -> None:
    findings = _corpus("rustapp")["findings"]
    by_rule: dict[str, list[dict]] = {}
    for f in findings:
        by_rule.setdefault(f["rule_id"], []).append(f)
    for rule in ("RS-WL-108", "RS-WL-112"):
        assert by_rule.get(rule), f"corpus freezes no {rule} finding (rules={sorted(by_rule)})"
        for f in by_rule[rule]:
            assert f["fingerprint"], f"{rule}: empty fingerprint frozen"
    # The whole point of SP2: identity is CRATE-prefixed (Cargo.toml name = "rust-app"
    # -> crate rust_app), not directory-named.
    assert all(f["qualname"].startswith("rust_app.") for f in findings), (
        f"finding qualnames are not crate-prefixed: {[f['qualname'] for f in findings]}"
    )


def test_corpus_freezes_the_impl_entity_surface() -> None:
    entities = _corpus("rustapp")["entities"]
    assert any(e["kind"] == "impl" for e in entities), "no impl entity row frozen"
    # The semantic `method` kind freezes as the id-kind `function`, re-parented onto
    # the impl entity (module -> impl -> method containment).
    methods = [e for e in entities if e["kind"] == "function" and e["parent"] and ".impl" in e["parent"]]
    assert methods, "no impl-method entity row (parent = impl entity) frozen"


def test_corpus_freezes_a_cfg_twin() -> None:
    qns = {e["qualname"] for e in _corpus("rustapp")["entities"]}
    assert any("@cfg(" in qn for qn in qns), f"no @cfg(...) twin qualname frozen (qualnames={sorted(qns)})"


def test_corpus_freezes_the_cross_file_crate_route() -> None:
    # A real crate prefix + cross-file module route (src/cmd/runner.rs ->
    # rust_app.cmd.runner) — NOT a directory-name stub.
    qns = {e["qualname"] for e in _corpus("rustapp")["entities"]}
    assert any(qn.startswith("rust_app.cmd.runner") for qn in qns), (
        f"no rust_app.cmd.runner-prefixed entity frozen (qualnames={sorted(qns)})"
    )


def test_corpus_freezes_edges() -> None:
    edges = _corpus("rustapp")["edges"]
    assert edges, "no edges frozen"
    kinds = {e["kind"] for e in edges}
    assert kinds == {"imports", "implements"}, f"expected both edge kinds frozen, got {sorted(kinds)}"
    for e in edges:
        assert e["confidence"] in ("resolved", "ambiguous"), f"illegal confidence frozen: {e}"


def test_corpus_entity_spans_carry_real_coordinates() -> None:
    for e in _corpus("rustapp")["entities"]:
        loc = e["location"]
        assert loc["path"] and not loc["path"].startswith("/"), f"non-relative path frozen: {e['qualname']!r}"
        assert loc["line_start"] is not None and loc["col_start"] is not None, f"null span {e['qualname']!r}"


def test_corpus_fingerprints_are_collision_free() -> None:
    # The join-key soundness gate, mirrored from the Python oracle: two distinct
    # active findings sharing a fingerprint would silently drop one on the join.
    fps = [f["fingerprint"] for f in _corpus("rustapp")["findings"]]
    assert len(fps) == len(set(fps)), f"fingerprint collision in the frozen corpus: {fps}"


# --- Fixture hygiene: nothing date/env dependent may travel with the fixture ---


@pytest.mark.parametrize("name", sorted(_INPUTS))
def test_fixture_has_no_local_config(name: str) -> None:
    root = _INPUTS[name]
    assert not (root / ".weft").exists(), f"{name}: fixture must not carry a .weft/ dir"
    assert not (root / "weft.toml").exists(), f"{name}: fixture must not carry a weft.toml"


def test_fixture_has_no_path_typed_generic_args() -> None:
    # Reserved-colon constraint (see README.md): `impl From<std::io::Error>`-style
    # path-typed generic args are an UN-DECIDED cross-tool ADR-049 case — freezing
    # one would pre-empt the pending decision. Guard the fixture against a future
    # edit re-introducing one: no `impl`/`<...>` qualname may carry a `::` path.
    src_files = sorted((_INPUTS["rustapp"] / "src").rglob("*.rs"))
    for f in src_files:
        for lineno, line in enumerate(f.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("impl") and "<" in stripped and "::" in stripped.split("for")[0]:
                pytest.fail(f"{f.name}:{lineno}: path-typed generic arg in an impl header: {stripped!r}")


_ACTUAL_KEY = pytest.StashKey[tuple]()
