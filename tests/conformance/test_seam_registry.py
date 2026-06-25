"""Fail-closed lie detector for the weft-seam conformance registry.

``tests/conformance/seam_registry.json`` is the program ledger: one row per
cross-product (or one-sided) seam, each carrying a ``bar_verdict`` that claims
how far that seam has been pinned. This test refuses to take any claim on
trust. It parses the THREE real marker sources (never a hardcoded mirror) and
re-derives, from the filesystem, whether each row's claim is backed by an
artifact that actually exists and actually fails closed.

A row that claims ``at_bar`` with a fabricated ``oracle_test`` path, an
unregistered pytest marker, or (when two-sided) a ``drift_test`` that lacks a
Layer-1 byte-pin must turn this suite RED. Green therefore comes from an HONEST
registry — never from weakening an assertion here. It is FINE for the initial
registry to carry zero ``at_bar`` rows; that is the true starting state this
program exists to fix.

This module carries NO pytest marker, so it runs in the DEFAULT PR suite and
fails closed (malformed JSON, a fabricated oracle path, or an unregistered
marker errors the default run — it never skips).

Marker taxonomy (resolve ``_e2e`` vs ``_drift`` explicitly):

* An ``_e2e`` (live-oracle) marker must appear in ALL THREE real sources:
  ``pyproject [tool.pytest.ini_options].markers``, the ``addopts`` ``-m 'not
  ...'`` exclusion, AND ``wardline._live_oracle.LIVE_ORACLE_MARKERS`` (so an
  armed ``WARDLINE_LIVE_ORACLE_REQUIRED=1`` run fails it closed instead of
  skipping clean).
* A ``_drift`` (Layer-2 live recheck) marker must appear in pyproject markers +
  the addopts exclusion. It is intentionally NOT required to be in
  ``LIVE_ORACLE_MARKERS``: the default-suite fail-closed protection for that
  two-sided seam comes instead from the Layer-1 byte-pin (an unmarked test
  pinning the vendored fixture hash, which always runs).

Strengthening notes (what this module verifies vs what it cannot):

* ``oracle_test`` / ``drift_test`` must be a REAL test file — ``tests/``-rooted,
  ``test_*.py`` basename, existing — not merely any file that happens to exist.
* A live-oracle marker declared on a ``partial`` (or ``at_bar``) row must be
  APPLIED (``@pytest.mark.<name>`` / a ``pytestmark`` assignment) in the cited
  ``oracle_test`` OR in a file listed under ``evidence_paths`` — not merely
  registered in pyproject. RESIDUAL (documented, not registry-verifiable): this
  proves a marked test is *cited by* the seam; it does NOT prove that test
  actually *exercises* this specific seam. That relevance check is semantic and
  left to review.
* A two-sided ``at_bar`` drift alarm is checked per ``oracle_shape``: a
  ``shared_signed_vector`` seam (the gold G1 mechanism) couples the two sides via
  a named-constant signing key + an offline signature round-trip and is accepted
  on that basis (it has no vendored blob to pin); all other shapes require the
  Layer-1 vendored byte-pin in ``drift_test``.
* A ``shared_signed_vector`` ``at_bar`` seam needs NO live-oracle marker: its
  fail-closed protection is the offline round-trip that runs in the DEFAULT suite
  (the same reasoning that exempts ``_drift`` seams from ``LIVE_ORACLE_MARKERS``).
  In exchange, the oracle_test is asserted to carry NO addopts-excluded marker, so
  that "runs offline in the default suite" is proven, not assumed. Without this
  exemption the marker requirement would structurally wall G1 out of ``at_bar``.

KNOWN INCONSISTENCY (out of this module's reach — needs a one-line ``src/`` fix):
``rust_e2e`` is registered in pyproject markers + the addopts exclusion but is
ABSENT from ``wardline._live_oracle.LIVE_ORACLE_MARKERS``. ``rust_e2e`` IS a live
subprocess oracle (``wardline scan --lang rust``) that SHOULD fail closed under
an armed ``WARDLINE_LIVE_ORACLE_REQUIRED=1`` run, so the taxonomy rule ("every
non-``_drift`` marker must be in ``LIVE_ORACLE_MARKERS``") is correct and the
SOURCE is the bug. The honest fix is to add ``"rust_e2e"`` to
``LIVE_ORACLE_MARKERS`` in ``src/wardline/_live_oracle.py`` (a production-source
edit, intentionally not made here). This module does NOT carve out an exception:
no row uses ``rust_e2e`` today, so there is zero current fail-open, and weakening
the (sound, fail-closed-favouring) taxonomy rule from the test side would be the
wrong direction.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from wardline._live_oracle import LIVE_ORACLE_MARKERS

_HERE = Path(__file__).parent
_REPO_ROOT = _HERE.parent.parent
_REGISTRY_PATH = _HERE / "seam_registry.json"
_PYPROJECT_PATH = _REPO_ROOT / "pyproject.toml"

_VALID_VERDICTS = frozenset({"at_bar", "partial", "deferred", "one_sided_na", "gap"})
_VALID_ORACLE_SHAPES = frozenset({"scenario", "byte_golden_corpus", "shared_signed_vector"})

# Required keys that must be a non-empty string.
_REQUIRED_STR_KEYS = ("seam", "authority", "consumer_or_second_producer", "wire", "wire_change")
# Required keys that must be either a string or null.
_STR_OR_NULL_KEYS = ("oracle_shape", "oracle_test", "marker", "drift_alarm", "drift_test", "deferred_reason")


# --------------------------------------------------------------------------- #
# Registry loading
# --------------------------------------------------------------------------- #


def _load_registry() -> list[dict[str, Any]]:
    rows = json.loads(_REGISTRY_PATH.read_text("utf-8"))
    assert isinstance(rows, list) and rows, "seam_registry.json must be a non-empty JSON array of seam rows"
    return rows


# --------------------------------------------------------------------------- #
# LIVE marker-source parsing (read the REAL sources, never a hardcoded mirror).
# --------------------------------------------------------------------------- #


def _load_pyproject() -> dict[str, Any]:
    with _PYPROJECT_PATH.open("rb") as fh:
        return tomllib.load(fh)


def _registered_marker_names(pyproject: dict[str, Any]) -> set[str]:
    """Marker NAMES from ``[tool.pytest.ini_options].markers`` — take each
    ``"name: description"`` entry's name (split on the first ``:``)."""
    raw = pyproject["tool"]["pytest"]["ini_options"]["markers"]
    return {entry.split(":", 1)[0].strip() for entry in raw}


def _addopts_excluded_markers(pyproject: dict[str, Any]) -> set[str]:
    """Tokenize the single quoted ``addopts`` ``-m 'not A and not B ...'``
    expression into the SET of excluded marker names.

    Slice the substring *inside* the single quotes first, THEN split on
    ``' and not '``, THEN strip a leading ``not `` and any stray quotes. (The
    addopts is ONE string holding a ``-m`` expression, not a list; splitting the
    raw addopts would carry the ``-m '`` prefix into the first token.)
    """
    addopts = pyproject["tool"]["pytest"]["ini_options"]["addopts"]
    assert isinstance(addopts, str), "addopts must be a single -m expression string"

    first = addopts.index("'")
    last = addopts.rindex("'")
    assert last > first, f"could not locate the quoted -m expression in addopts: {addopts!r}"
    expr = addopts[first + 1 : last]

    excluded: set[str] = set()
    for token in expr.split(" and not "):
        name = token.strip()
        if name.startswith("not "):
            name = name[len("not ") :]
        name = name.strip().strip("'\"").strip()
        if name:
            excluded.add(name)
    return excluded


_ROWS = _load_registry()
_PYPROJECT = _load_pyproject()
_REGISTERED_MARKERS = _registered_marker_names(_PYPROJECT)
_EXCLUDED_MARKERS = _addopts_excluded_markers(_PYPROJECT)


# --------------------------------------------------------------------------- #
# Self-checks of the parsers — guard against a silently-empty parse.
# --------------------------------------------------------------------------- #


def test_parsed_marker_sources_are_non_empty() -> None:
    assert _REGISTERED_MARKERS, "parsed pyproject markers set is empty — the parser is broken"
    assert _EXCLUDED_MARKERS, "parsed addopts-excluded set is empty — the parser is broken"
    assert LIVE_ORACLE_MARKERS, "LIVE_ORACLE_MARKERS is empty — fail-closed protection is gone"


def test_addopts_excludes_only_registered_markers() -> None:
    # Every excluded marker must be a registered marker (proves the tokenizer
    # extracted real names, and catches a typo'd exclusion).
    unregistered = _EXCLUDED_MARKERS - _REGISTERED_MARKERS
    assert not unregistered, (
        f"addopts excludes markers that are not declared in [markers]: {sorted(unregistered)}"
    )


def test_live_oracle_markers_are_registered_and_excluded() -> None:
    # Every live-oracle marker must be registered AND excluded from the default
    # suite, else it would run hermetically and skip clean.
    for name in LIVE_ORACLE_MARKERS:
        assert name in _REGISTERED_MARKERS, f"LIVE_ORACLE_MARKERS member {name!r} is not registered"
        assert name in _EXCLUDED_MARKERS, (
            f"LIVE_ORACLE_MARKERS member {name!r} is not in the addopts exclusion — it would leak "
            "into the hermetic default suite"
        )


# --------------------------------------------------------------------------- #
# Schema / enum validity for EVERY row, any verdict.
# --------------------------------------------------------------------------- #


def test_registry_schema_is_valid() -> None:
    for i, row in enumerate(_ROWS):
        ctx = f"row[{i}] seam={row.get('seam')!r}"
        assert isinstance(row, dict), f"{ctx}: row is not an object"

        for key in _REQUIRED_STR_KEYS:
            assert key in row, f"{ctx}: missing required key {key!r}"
            assert isinstance(row[key], str) and row[key].strip(), f"{ctx}: {key!r} must be a non-empty string"

        for key in _STR_OR_NULL_KEYS:
            assert key in row, f"{ctx}: missing required key {key!r}"
            assert row[key] is None or isinstance(row[key], str), f"{ctx}: {key!r} must be a string or null"

        assert "two_sided" in row and isinstance(row["two_sided"], bool), f"{ctx}: 'two_sided' must be a bool"

        assert "evidence_paths" in row and isinstance(row["evidence_paths"], list), (
            f"{ctx}: 'evidence_paths' must be a list"
        )
        assert all(isinstance(p, str) for p in row["evidence_paths"]), f"{ctx}: evidence_paths entries must be strings"

        assert "bar_verdict" in row, f"{ctx}: missing required key 'bar_verdict'"
        assert row["bar_verdict"] in _VALID_VERDICTS, (
            f"{ctx}: invalid bar_verdict {row['bar_verdict']!r} (allowed: {sorted(_VALID_VERDICTS)})"
        )
        if row["oracle_shape"] is not None:
            assert row["oracle_shape"] in _VALID_ORACLE_SHAPES, (
                f"{ctx}: invalid oracle_shape {row['oracle_shape']!r} (allowed: {sorted(_VALID_ORACLE_SHAPES)})"
            )

        # Optional multi-axis / self-authored fields — validate their TYPE when
        # present so they are load-bearing, not decorative. (The at_bar gate in
        # _assert_at_bar_two_sided_fail_closed enforces their SEMANTICS.)
        if "additional_drift_tests" in row:
            extra = row["additional_drift_tests"]
            assert isinstance(extra, list) and all(isinstance(p, str) and p.strip() for p in extra), (
                f"{ctx}: 'additional_drift_tests' must be a list of non-empty strings"
            )
        if "self_authored_restatement" in row:
            assert isinstance(row["self_authored_restatement"], bool), (
                f"{ctx}: 'self_authored_restatement' must be a bool"
            )


# --------------------------------------------------------------------------- #
# Per-verdict lie detector — claims must be backed by real artifacts on disk.
# --------------------------------------------------------------------------- #


# A registry path may carry a trailing ``:NN`` or ``:NN-MM`` line/range suffix
# (e.g. ``tests/e2e/test_x.py:261-302``). Strip it to recover the file path.
_LINE_SUFFIX_RE = re.compile(r":\d+(?:-\d+)?$")


def _strip_line_suffix(path_str: str) -> str:
    return _LINE_SUFFIX_RE.sub("", path_str)


def _is_real_test_file(path_str: str) -> bool:
    """True iff ``path_str`` (line-suffix already stripped) names a real test
    file: rooted under ``tests/`` AND its basename matches ``test_*.py`` AND it
    exists on disk. This kills the LIE where a non-test file (``pyproject.toml``)
    is accepted as an ``oracle_test`` merely because ``is_file()`` is True."""
    p = Path(path_str)
    if p.parts[:1] != ("tests",):
        return False
    if not (p.name.startswith("test_") and p.name.endswith(".py")):
        return False
    return (_REPO_ROOT / p).is_file()


# A pytest marker is APPLIED to a test module/function via ``@pytest.mark.<name>``
# or a module-level ``pytestmark = ...<name>...``. We require the mark FORM (not a
# bare substring) so a comment / string literal mentioning the marker name does
# not satisfy the binding (the same lesson the byte-pin needle hardening applies).
def _marker_is_applied_in_file(marker: str, path_str: str) -> bool:
    file_path = _REPO_ROOT / _strip_line_suffix(path_str)
    if not file_path.is_file():
        return False
    text = file_path.read_text("utf-8")
    name = re.escape(marker)
    decorator = re.search(rf"@pytest\.mark\.{name}\b", text)
    # ``pytestmark`` collects marks at module scope; require the marker name to
    # appear on a ``pytestmark`` assignment line (handles single + list forms).
    module_mark = any(
        re.search(r"\bpytestmark\b", line) and re.search(rf"\.{name}\b", line)
        for line in text.splitlines()
    )
    return bool(decorator) or module_mark


def _marker_applied_in_row_evidence(row: dict[str, Any], marker: str) -> bool:
    """True iff ``marker`` is APPLIED (mark form) in the row's cited
    ``oracle_test`` OR in any file listed under ``evidence_paths``. This binds a
    declared live-oracle marker to a real marked test the row itself cites,
    closing the LIE where a row declares a registered-but-unapplied marker.

    CAVEAT (semantic residual, not registry-verifiable): this proves a marked
    test file is cited by the seam — NOT that that test actually exercises this
    specific seam. The achievable bar here is real-marked-test-is-cited; full
    coverage relevance is left to review."""
    candidates: list[str] = []
    if row["oracle_test"] is not None:
        candidates.append(row["oracle_test"])
    candidates.extend(row["evidence_paths"])
    return any(_marker_is_applied_in_file(marker, c) for c in candidates)


def _has_layer1_byte_pin(text: str) -> bool:
    """True if a drift_test file carries a Layer-1 byte-pin that runs in the
    default suite — an actual PIN, not a mere mention. Requires either a 40-hex
    blob-SHA pinned-constant assignment or a live ``git hash-object`` invocation,
    so a comment or string literal merely naming ``blob_sha`` / ``git blob`` does
    NOT satisfy the check. The old loose needles (``blob %d``, ``git blob``, bare
    ``blob_sha``) are intentionally dropped as too weak.

    The pinned-constant needle accepts both the ``UPSTREAM_BLOB_SHA`` name (the
    canonical name for a blob byte-copied from the producing authority) and the
    ``VENDORED_BLOB_SHA`` name (the Python qualname axis's pin, which deliberately
    differs from upstream by a repo-local provenance wrapper — see
    test_loomweave_qualname_parity.py). Both are real fail-closed byte-pins held
    against a recomputed git-blob hash; the name difference is documentation, not
    strength. A bare ``hashlib.sha1(b"blob ...")`` recompute is NOT accepted on its
    own — the pin is the 40-hex CONSTANT the recompute is asserted against."""
    # The pinned-constant form: an assignment to a 40-char lowercase-hex SHA-1.
    if re.search(r"(?:UPSTREAM|VENDORED)_BLOB_SHA\s*=\s*[\"'][0-9a-f]{40}[\"']", text):
        return True
    # A live `git hash-object` recomputation of the vendored file's blob SHA.
    return bool(re.search(r"hash-object\b", text))


def _has_substantive_sibling_source_recheck(text: str) -> bool:
    """True if a drift_test file carries a SUBSTANTIVE authority-side recheck: it
    reads the SIBLING authority's real source (via a ``WARDLINE_*_REPO`` env-keyed
    repo locator) and asserts parsed source constants against the vendored
    restatement. This is the circular-oracle break a SELF-AUTHORED at_bar seam
    needs — the byte-pin alone pins wardline's OWN bytes (wardline-pins-wardline),
    so the gate additionally requires the test that re-derives the contract from
    the producing authority's REAL source to exist and be substantive.

    Required shape (all three): a ``WARDLINE_*_REPO`` env locator (the sibling repo
    root), a ``.read_text(`` of a sibling source file, AND an ``assert ... in
    <source>`` membership check that ties a vendored contract value to a literal
    found in that sibling source. A registered-but-no-op ``_drift`` marker (a
    ``pass``-bodied recheck) does NOT satisfy this — the substantive shape must be
    present.

    CAVEAT (semantic residual, same class as every other needle here): this is a
    TEXT match for the substantive recheck's shape — it proves the source-parsing
    code is PRESENT, not that it is reachable at runtime (e.g. a ``return`` above
    dead asserts would still match). The realistic regression this catches is the
    finding's named one: the recheck deleted or gutted to a no-op. Full
    reachability is left to review, as with the byte-pin needle."""
    has_env_locator = re.search(r"WARDLINE_[A-Z]+_REPO\b", text) is not None
    has_source_read = re.search(r"\.read_text\(", text) is not None
    # An ``assert <something> in <src>`` membership check (the source-grep form the
    # filigree_token Layer-2 uses: ``assert f'...' in token_src``).
    has_membership_assert = re.search(r"\bassert\b[^\n]*\bin\b\s+\w*src\w*", text) is not None
    return has_env_locator and has_source_read and has_membership_assert


def _has_shared_vector_pin(text: str) -> bool:
    """True if a ``shared_signed_vector`` oracle carries the shared-vector drift
    alarm: a named-constant signing-key binding plus an offline signature
    round-trip over the vector (so a wire-key rename reds without a vendored
    blob copy). This is the §3b/§4 second drift mechanism — the one G1 uses."""
    has_golden_key = re.search(r"\bGOLDEN_KEY\b", text) is not None
    has_round_trip = re.search(r"\bsign_artifact\s*\(", text) is not None
    # A ``*_FIELD`` named-constant key check ties literal wire keys to constants.
    has_field_constant = re.search(r"\b[A-Z][A-Z0-9_]*_FIELD\b", text) is not None
    return has_golden_key and has_round_trip and has_field_constant


def _assert_at_bar_marker(row: dict[str, Any], ctx: str) -> None:
    # A ``shared_signed_vector`` seam needs NO live-oracle marker: its fail-closed
    # protection is the offline signature round-trip that runs in the DEFAULT
    # suite (asserted separately in _assert_at_bar_two_sided_fail_closed), not a
    # live oracle — directly analogous to a _drift seam's exemption from
    # LIVE_ORACLE_MARKERS. Demanding a live-oracle marker here would structurally
    # wall the gold G1 mechanism out of at_bar.
    if row["oracle_shape"] == "shared_signed_vector":
        return
    # A one-sided (no-peer) ``byte_golden_corpus`` seam — wardline freezing its OWN
    # produced schema (e.g. the MCP outputSchema surface) to a committed golden — has
    # no live PEER wire to assert, so it needs no live-oracle marker; its fail-closed
    # protection is the default-suite golden byte-pin, asserted in
    # _assert_at_bar_one_sided_golden_fail_closed.
    if not row["two_sided"] and row["oracle_shape"] == "byte_golden_corpus":
        return

    marker = row["marker"]
    assert marker is not None, f"{ctx}: an at_bar row must declare a marker satisfying the taxonomy"
    if marker.endswith("_drift"):
        assert marker in _REGISTERED_MARKERS, f"{ctx}: _drift marker {marker!r} not declared in pyproject"
        assert marker in _EXCLUDED_MARKERS, f"{ctx}: _drift marker {marker!r} not in the addopts exclusion"
    else:
        # Live-oracle (_e2e-class) marker: must appear in ALL THREE sources.
        assert marker in _REGISTERED_MARKERS, f"{ctx}: live-oracle marker {marker!r} not declared in pyproject"
        assert marker in _EXCLUDED_MARKERS, f"{ctx}: live-oracle marker {marker!r} not in the addopts exclusion"
        assert marker in LIVE_ORACLE_MARKERS, (
            f"{ctx}: live-oracle marker {marker!r} not in LIVE_ORACLE_MARKERS "
            "(would skip clean instead of failing closed under an armed oracle run)"
        )
        # Bind the marker to the seam: it must be APPLIED in the cited oracle_test
        # OR a file under evidence_paths — not merely registered globally. This
        # kills the LIE where an at_bar row pairs a registered marker with an
        # unrelated seam/oracle (e.g. filigree_e2e on a loomweave seam).
        assert _marker_applied_in_row_evidence(row, marker), (
            f"{ctx}: at_bar live-oracle marker {marker!r} is not APPLIED "
            "(@pytest.mark / pytestmark) in oracle_test or any evidence_paths file — "
            "the marker is not bound to this seam's evidence"
        )


def _assert_at_bar_two_sided_fail_closed(row: dict[str, Any], ctx: str) -> None:
    """A two-sided ``at_bar`` seam must carry a drift alarm that fails CLOSED in
    the default (sibling-less) suite. The kit sanctions TWO drift mechanisms, so
    branch on ``oracle_shape`` instead of forcing every seam through the
    vendored-corpus byte-pin:

    * ``shared_signed_vector`` — the shared cross-member vector couples the two
      sides via a named-constant signing key + an offline signature round-trip
      (the gold G1 mechanism). It has NO vendored blob to pin; demanding one
      would be test theater. The alarm lives in the ``oracle_test`` itself.
    * everything else (``byte_golden_corpus`` / scenario corpora) — require the
      ``drift_test`` to carry a Layer-1 vendored byte-pin.
    """
    if row["oracle_shape"] == "shared_signed_vector":
        # The shared-vector coupling IS the drift alarm; assert it lives in the
        # oracle_test (a drift_test is not required for this mechanism).
        oracle = row["oracle_test"]
        assert oracle is not None, f"{ctx}: shared_signed_vector at_bar requires an oracle_test carrying the vector pin"
        oracle_path = _REPO_ROOT / oracle
        assert oracle_path.is_file(), f"{ctx}: shared_signed_vector at_bar oracle_test does not exist: {oracle}"
        assert _has_shared_vector_pin(oracle_path.read_text("utf-8")), (
            f"{ctx}: shared_signed_vector at_bar oracle_test lacks the shared-vector drift alarm "
            "(a GOLDEN_KEY-bound sign_artifact() round-trip + a *_FIELD named-constant key check); "
            "it would not fail closed against a silent wire-key rename"
        )
        # The "fails closed offline" claim is only true if the oracle actually
        # RUNS in the default suite. Since this seam is exempt from the live-oracle
        # marker requirement, prove the oracle is NOT excluded by any addopts
        # marker (else a row could claim shared_signed_vector while citing an
        # oracle marked e.g. filigree_e2e → never runs by default → the claim lies).
        for excluded in _EXCLUDED_MARKERS:
            assert not _marker_is_applied_in_file(excluded, oracle), (
                f"{ctx}: shared_signed_vector oracle_test carries excluded marker {excluded!r} "
                "— it would be skipped in the default suite, so the offline fail-closed claim is false"
            )
        return

    # Vendored-corpus / scenario seams: require the Layer-1 byte-pin in drift_test.
    assert row["drift_test"] is not None, f"{ctx}: two_sided at_bar requires a non-null drift_test"
    drift_path = _REPO_ROOT / row["drift_test"]
    assert drift_path.is_file(), f"{ctx}: at_bar drift_test does not exist: {row['drift_test']}"
    drift_text = drift_path.read_text("utf-8")
    assert _has_layer1_byte_pin(drift_text), (
        f"{ctx}: two_sided at_bar drift_test lacks a Layer-1 byte-pin "
        "(an (UPSTREAM|VENDORED)_BLOB_SHA = \"<40-hex>\" assignment or a git hash-object / "
        "hashlib.sha1(b\"blob ...\") recomputation); it would not fail closed in the default suite"
    )

    # Multi-axis enforcement: every axis a row declares must be gate-pinned, not
    # just the single ``drift_test``. A multi-axis at_bar row (e.g. the qualname
    # seam, Rust + Python) lists its secondary axes under ``additional_drift_tests``;
    # each MUST be a real test file carrying its own Layer-1 byte-pin, so deleting
    # or loosening a secondary-axis pin reds this gate (closing the "second axis
    # rests on prose + an unenforced evidence_path" hole).
    for extra in row.get("additional_drift_tests") or []:
        assert _is_real_test_file(extra), (
            f"{ctx}: additional_drift_tests entry is not a real test file "
            f"(must be tests/-rooted, match test_*.py, and exist): {extra}"
        )
        extra_text = (_REPO_ROOT / extra).read_text("utf-8")
        assert _has_layer1_byte_pin(extra_text), (
            f"{ctx}: multi-axis at_bar additional_drift_test {extra!r} lacks a Layer-1 byte-pin "
            "((UPSTREAM|VENDORED)_BLOB_SHA = \"<40-hex>\" or a git hash-object / "
            "hashlib.sha1(b\"blob ...\") recomputation); the second axis is not gate-protected"
        )

    # Self-authored restatement: when the vendored blob pins WARDLINE's OWN bytes
    # (the producing authority ships no fixture to byte-copy), the Layer-1 byte-pin
    # is wardline-pins-wardline — it cannot break the circular oracle on its own.
    # Such a row must declare ``self_authored_restatement: true`` AND its drift_test
    # must carry a SUBSTANTIVE authority-side recheck that re-derives the contract
    # from the sibling authority's REAL source (so a registered-but-no-op _drift
    # marker can NOT carry the at_bar claim).
    if row.get("self_authored_restatement"):
        assert _has_substantive_sibling_source_recheck(drift_text), (
            f"{ctx}: self_authored_restatement at_bar drift_test lacks a SUBSTANTIVE "
            "authority-side recheck (a WARDLINE_*_REPO-keyed read of the sibling authority "
            "source + an `assert <value> in <...src>` membership check). A self-authored "
            "byte-pin pins wardline's own bytes; the circular oracle is only broken by "
            "re-deriving the contract from the producing authority's real source"
        )


def _assert_at_bar_one_sided_golden_fail_closed(row: dict[str, Any], ctx: str) -> None:
    """A one-sided (no-peer) ``byte_golden_corpus`` at_bar seam — wardline freezing its
    OWN produced schema to a committed golden — must carry a Layer-1 byte-pin in its
    oracle_test that runs in the DEFAULT suite, so a silent schema change fails closed.
    There is no upstream peer, hence no drift_test / live-oracle marker; the golden
    byte-pin IS the fail-closed oracle (analogous to the shared_signed_vector exemption)."""
    oracle = row["oracle_test"]
    assert oracle is not None, f"{ctx}: one-sided byte_golden_corpus at_bar requires an oracle_test"
    oracle_path = _REPO_ROOT / oracle
    assert oracle_path.is_file(), f"{ctx}: one-sided at_bar oracle_test does not exist: {oracle}"
    text = oracle_path.read_text("utf-8")
    assert _has_layer1_byte_pin(text), (
        f"{ctx}: one-sided byte_golden_corpus at_bar oracle_test lacks a Layer-1 byte-pin "
        "((UPSTREAM|VENDORED)_BLOB_SHA = \"<40-hex>\" or a git hash-object / "
        "hashlib.sha1(b\"blob ...\") recomputation); a silent schema change would not fail "
        "closed in the default suite"
    )
    # The golden freeze only fails closed if it RUNS by default — reject an oracle
    # carrying any addopts-excluded marker (else it would be skipped and the claim lies).
    for excluded in _EXCLUDED_MARKERS:
        assert not _marker_is_applied_in_file(excluded, oracle), (
            f"{ctx}: one-sided golden oracle_test carries excluded marker {excluded!r} "
            "— it would be skipped in the default suite, so the fail-closed claim is false"
        )


def test_registry_verdicts_are_backed_by_real_artifacts() -> None:
    for i, row in enumerate(_ROWS):
        verdict = row["bar_verdict"]
        ctx = f"row[{i}] seam={row['seam']!r} verdict={verdict}"

        if verdict == "at_bar":
            assert row["oracle_test"] is not None, f"{ctx}: at_bar requires a non-null oracle_test"
            # An oracle_test must be a REAL test file (tests/-rooted, test_*.py),
            # not merely any existing file — a TOML/config path is not an oracle.
            assert _is_real_test_file(row["oracle_test"]), (
                f"{ctx}: at_bar oracle_test is not a real test file (must be tests/-rooted, "
                f"match test_*.py, and exist): {row['oracle_test']}"
            )
            _assert_at_bar_marker(row, ctx)
            if row["two_sided"]:
                _assert_at_bar_two_sided_fail_closed(row, ctx)
            elif row["oracle_shape"] == "byte_golden_corpus":
                _assert_at_bar_one_sided_golden_fail_closed(row, ctx)

        elif verdict == "partial":
            assert row["oracle_test"] is not None, (
                f"{ctx}: partial requires a non-null oracle_test (re-grade to gap honestly otherwise)"
            )
            assert _is_real_test_file(row["oracle_test"]), (
                f"{ctx}: partial oracle_test is not a real test file (must be tests/-rooted, "
                f"match test_*.py, and exist): {row['oracle_test']} "
                "(re-grade to gap honestly instead of claiming an oracle that is not there)"
            )
            # If the partial row declares a live-oracle marker, that marker must be
            # APPLIED (mark form) in the cited oracle_test OR in a file named under
            # evidence_paths — so a row can't declare a registered-but-unapplied
            # marker against an irrelevant file. (Residual: this proves a marked
            # test is cited by the seam, not that it exercises THIS seam.)
            marker = row["marker"]
            if marker is not None and not marker.endswith("_drift"):
                assert _marker_applied_in_row_evidence(row, marker), (
                    f"{ctx}: partial declares live-oracle marker {marker!r} but it is not APPLIED "
                    "(@pytest.mark / pytestmark) in oracle_test or any evidence_paths file — "
                    "cite the file that actually carries the marker"
                )

        elif verdict in ("deferred", "one_sided_na"):
            reason = row["deferred_reason"]
            assert isinstance(reason, str) and reason.strip(), (
                f"{ctx}: {verdict} requires a non-empty deferred_reason"
            )

        elif verdict == "gap":
            # No artifact requirement — honest under-claiming is allowed. But a gap
            # row must NOT dangle a real oracle_test: a cited oracle on a gap row is
            # either mis-graded (should be partial) or noise. Force the author to
            # null it out or re-grade honestly.
            assert row["oracle_test"] is None, (
                f"{ctx}: gap row carries a non-null oracle_test ({row['oracle_test']}) — "
                "a gap claims no oracle. Null it out, or re-grade to partial if the oracle is real "
                "(cite supporting paths under evidence_paths instead)."
            )

        else:  # pragma: no cover - guarded by the schema enum test
            raise AssertionError(f"{ctx}: unhandled bar_verdict {verdict!r}")


# --------------------------------------------------------------------------- #
# Taxonomy guard for EVERY marked row, regardless of verdict.
# --------------------------------------------------------------------------- #


def test_marker_taxonomy_guard_for_every_marked_row() -> None:
    """For every row carrying a non-null ``marker`` and/or ``drift_alarm``,
    classify each by suffix and enforce the taxonomy:

    * a non-``_drift`` (``_e2e``-class) live-oracle marker NOT in
      ``LIVE_ORACLE_MARKERS`` FAILS — this closes the fail-open for live oracles;
    * a ``_drift`` marker simply must be in pyproject markers + the addopts
      exclusion.

    The kind can be carried by ``marker`` OR by ``drift_alarm`` (e.g. a row with
    ``marker=null`` but ``drift_alarm="loomweave_drift"``), so both fields are
    gathered and classified.
    """
    for i, row in enumerate(_ROWS):
        ctx = f"row[{i}] seam={row['seam']!r}"
        for marker in (m for m in (row["marker"], row["drift_alarm"]) if m is not None):
            if marker.endswith("_drift"):
                assert marker in _REGISTERED_MARKERS, (
                    f"{ctx}: _drift marker {marker!r} not declared in pyproject markers"
                )
                assert marker in _EXCLUDED_MARKERS, (
                    f"{ctx}: _drift marker {marker!r} not in the addopts exclusion "
                    "(would run in the default PR suite without the sibling)"
                )
            else:
                assert marker in _REGISTERED_MARKERS, (
                    f"{ctx}: live-oracle marker {marker!r} not declared in pyproject markers"
                )
                assert marker in _EXCLUDED_MARKERS, (
                    f"{ctx}: live-oracle marker {marker!r} not in the addopts exclusion"
                )
                assert marker in LIVE_ORACLE_MARKERS, (
                    f"{ctx}: live-oracle marker {marker!r} not in LIVE_ORACLE_MARKERS "
                    "(an armed WARDLINE_LIVE_ORACLE_REQUIRED=1 run would skip it clean "
                    "instead of failing closed — fail-open)"
                )
