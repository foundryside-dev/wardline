"""Phase 4 — the delta finding filter (``core.delta_resolve.filter_to_affected``).

The filter narrows ONLY the displayed findings to the affected entities: it keeps an
anchored finding by canonical qualname (matching ``:setter``/``:deleter`` and
nested-class shapes and class-level locators) and a qualname-``None`` engine FACT on an
analyzed affected file, and drops co-located findings on other entities. It is a pure
drop-filter and never re-mints a fingerprint (INV-2).
"""

from __future__ import annotations

from wardline.core.delta_resolve import filter_to_affected
from wardline.core.finding import (
    Finding,
    Kind,
    Location,
    Severity,
    compute_finding_fingerprint,
)


def _finding(
    *,
    rule_id: str = "PY-WL-101",
    path: str = "a.py",
    qualname: str | None = "a.handler",
    severity: Severity = Severity.ERROR,
    kind: Kind = Kind.DEFECT,
) -> Finding:
    fp = compute_finding_fingerprint(rule_id=rule_id, path=path, qualname=qualname)
    return Finding(
        rule_id=rule_id,
        message="boundary not validated",
        severity=severity,
        kind=kind,
        location=Location(path=path, line_start=3, line_end=3),
        fingerprint=fp,
        qualname=qualname,
    )


def test_keeps_finding_on_affected_qualname() -> None:
    f = _finding(qualname="a.handler")
    kept = filter_to_affected([f], frozenset({"a.handler"}), frozenset({"a.py"}))
    assert kept == [f]


def test_drops_colocated_non_affected_qualname() -> None:
    keep = _finding(qualname="a.handler")
    drop = _finding(qualname="a.other")
    kept = filter_to_affected([keep, drop], frozenset({"a.handler"}), frozenset({"a.py"}))
    assert kept == [keep]


def test_keeps_setter_finding_under_base_locator() -> None:
    # Finding qualname carries ':setter'; the affected set holds the base name.
    f = _finding(qualname="cfg.Cfg.value:setter")
    kept = filter_to_affected([f], frozenset({"cfg.Cfg.value"}), frozenset({"cfg.py"}))
    assert kept == [f]


def test_keeps_deleter_finding_under_base_locator() -> None:
    f = _finding(qualname="cfg.Cfg.value:deleter")
    kept = filter_to_affected([f], frozenset({"cfg.Cfg.value"}), frozenset({"cfg.py"}))
    assert kept == [f]


def test_keeps_method_finding_under_class_level_locator() -> None:
    # A class-level affected key scopes in every method under it via the prefix rule.
    a = _finding(qualname="svc.Svc.a")
    b = _finding(qualname="svc.Svc.b")
    kept = filter_to_affected([a, b], frozenset({"svc.Svc"}), frozenset({"svc.py"}))
    assert kept == [a, b]


def test_keeps_nested_class_qualname() -> None:
    f = _finding(qualname="nest.Outer.Inner.deep")
    kept = filter_to_affected([f], frozenset({"nest.Outer.Inner.deep"}), frozenset({"nest.py"}))
    assert kept == [f]


def test_class_level_locator_does_not_match_sibling_prefix() -> None:
    # 'svc.Svc' must not match a sibling class 'svc.SvcOther' by string prefix — the
    # prefix rule appends a '.' so only true members under the class qualify.
    member = _finding(qualname="svc.Svc.a")
    sibling = _finding(qualname="svc.SvcOther.a")
    kept = filter_to_affected([member, sibling], frozenset({"svc.Svc"}), frozenset({"svc.py"}))
    assert kept == [member]


def test_keeps_engine_fact_with_none_qualname_on_affected_file() -> None:
    fact = _finding(
        rule_id="WLN-ENGINE-PARSE-ERROR",
        qualname=None,
        kind=Kind.FACT,
        severity=Severity.NONE,
        path="a.py",
    )
    kept = filter_to_affected([fact], frozenset({"a.handler"}), frozenset({"a.py"}))
    assert kept == [fact]


def test_drops_engine_fact_with_none_qualname_off_affected_file() -> None:
    fact = _finding(
        rule_id="WLN-ENGINE-PARSE-ERROR",
        qualname=None,
        kind=Kind.FACT,
        severity=Severity.NONE,
        path="other.py",
    )
    kept = filter_to_affected([fact], frozenset({"a.handler"}), frozenset({"a.py"}))
    assert kept == []


def test_does_not_remint_fingerprints() -> None:
    # INV-2: kept findings keep their exact input fingerprints; the filter never re-mints.
    keep = _finding(qualname="a.handler")
    drop = _finding(qualname="a.other")
    kept = filter_to_affected([keep, drop], frozenset({"a.handler"}), frozenset({"a.py"}))
    assert len(kept) == 1
    assert kept[0].fingerprint == keep.fingerprint
    assert kept[0] is keep  # identity preserved — not reconstructed


def test_empty_affected_set_keeps_only_facts_on_files() -> None:
    anchored = _finding(qualname="a.handler")
    fact = _finding(rule_id="WLN-ENGINE-FILE-SKIPPED", qualname=None, kind=Kind.FACT, path="a.py")
    kept = filter_to_affected([anchored, fact], frozenset(), frozenset({"a.py"}))
    assert kept == [fact]
