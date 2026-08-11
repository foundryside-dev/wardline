"""WLN-ENGINE-UNKNOWN-MARKER — forward vocabulary skew (P11a).

When a new marker reaches an older Wardline, a decorator rooted in the vocabulary
(``wardline.decorators`` / ``weft_markers``) that THIS engine does not recognise
takes no opinion (fail-closed), never crashes, and leaves a FACT.

This is P11a only. P11b's generic TokenSetArg contract is an S2 release gate;
S3 repeats it for the Evidence domain. A LEVEL typo represents neither gate.
"""

from __future__ import annotations

from pathlib import Path

from wardline.core.finding import Kind, Severity
from wardline.core.resolution_posture import compute_resolution_posture
from wardline.core.run import run_scan

FACT_ID = "WLN-ENGINE-UNKNOWN-MARKER"


def _scan(tmp_path: Path, src: str):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(src, encoding="utf-8")
    return run_scan(proj)


def _facts(result):
    return [f for f in result.findings if f.rule_id == FACT_ID]


def test_unknown_marker_is_no_opinion_never_a_crash(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import weft_markers\n@weft_markers.audit_record\ndef write_event(e):\n    return e\n",
    )
    (fact,) = _facts(result)
    assert fact.severity is Severity.NONE
    assert fact.kind is Kind.FACT
    assert fact.properties == {"marker": "weft_markers.audit_record", "reason": "unrecognised_vocabulary"}
    assert result.context is not None
    assert "svc.write_event" not in result.context.declared_qualnames
    assert not [f for f in result.findings if f.kind is Kind.DEFECT]


def test_from_import_form_is_detected(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from weft_markers import audit_record\n@audit_record\ndef write_event(e):\n    return e\n",
    )
    (fact,) = _facts(result)
    assert fact.properties["marker"] == "weft_markers.audit_record"


def test_nested_vocabulary_path_is_observable(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import wardline.decorators.evil\n"
        "@wardline.decorators.evil.trusted(level='INTEGRAL')\n"
        "def f(p):\n"
        "    return p\n",
    )
    (fact,) = _facts(result)
    assert fact.properties["marker"] == "wardline.decorators.evil.trusted"


def test_known_marker_malformed_call_is_not_unknown(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n@trusted(level='INTEGRAL', audit=True)\ndef f(p):\n    return p\n",
    )
    assert not _facts(result)
    assert [f for f in result.findings if f.rule_id == "PY-WL-130"]


def test_invalid_level_remains_the_separate_py_wl_114_channel(tmp_path: Path) -> None:
    # This pins channel separation; it is NOT evidence for P11b.
    result = _scan(
        tmp_path,
        "from wardline.decorators import trusted\n@trusted(level='CONFIDENTIAL')\ndef f(p):\n    return p\n",
    )
    assert result.context is not None
    assert "svc.f" not in result.context.declared_qualnames
    assert [f for f in result.findings if f.rule_id == "PY-WL-114"]
    assert not _facts(result)  # a KNOWN marker is never "unknown vocabulary"


def test_valid_builtin_seed_survives_beside_unknown_marker(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import weft_markers\n"
        "from wardline.decorators import trusted\n"
        "@weft_markers.audit_record\n"
        "@trusted(level='ASSURED')\n"
        "def f(p):\n    return p\n",
    )
    assert result.context is not None
    assert "svc.f" in result.context.declared_qualnames
    assert len(_facts(result)) == 1


def test_repeated_unknown_markers_have_distinct_fingerprints(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "import weft_markers\n"
        "@weft_markers.audit_record\n"
        "@weft_markers.audit_record\n"
        "def write_event(e):\n    return e\n",
    )

    facts = _facts(result)
    assert len(facts) == 2
    assert len({fact.fingerprint for fact in facts}) == 2


def test_shadowed_root_emits_no_fact(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / "weft_markers").mkdir(parents=True)
    (proj / "weft_markers" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "svc.py").write_text(
        "import weft_markers\n@weft_markers.audit_record\ndef f(e):\n    return e\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert not _facts(result)


def test_foreign_decorator_emits_no_fact(tmp_path: Path) -> None:
    result = _scan(tmp_path, "import functools\n@functools.cache\ndef f(p):\n    return p\n")
    assert not _facts(result)


def test_unknown_marker_does_not_make_an_inert_scan_active(tmp_path: Path) -> None:
    # A NONE/FACT observability record is not a recognised boundary: a project with no
    # trust declarations at all must stay INERT even when it carries an unknown marker,
    # or the FACT would silently clear the false-assurance banner (the very thing
    # ``compute_resolution_posture`` exists to shout about). Six functions clear the
    # exploration floor (``_MIN_FUNCTIONS`` = 5).
    ordinary = "".join(f"def plain_{i}(p):\n    return p\n\n\n" for i in range(5))
    result = _scan(
        tmp_path,
        f"import weft_markers\n\n\n{ordinary}@weft_markers.audit_record\ndef write_event(e):\n    return e\n",
    )
    assert len(_facts(result)) == 1
    posture = compute_resolution_posture(result.findings)
    assert posture.functions_analyzed >= 5
    assert posture.recognized_boundaries == 0
    assert posture.inert is True
