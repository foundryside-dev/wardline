"""P7 — canonical orderings pinned at every serialisation seam.

The declaration ledger (S1+) inherits these seams; each is pinned here so an
ordering regression is a named failure, not a byte-drift mystery."""

from __future__ import annotations

import json

from wardline.core.attest import _canonical_bytes
from wardline.core.baseline import build_baseline_document
from wardline.core.finding import Finding, Kind, Location, Severity, compute_finding_fingerprint


def _finding(rule_id: str, path: str, severity: Severity, qualname: str | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="m",
        severity=severity,
        kind=Kind.DEFECT,
        location=Location(path=path, line_start=1),
        fingerprint=compute_finding_fingerprint(rule_id=rule_id, path=path, qualname=qualname),
        qualname=qualname,
    )


def test_finding_jsonl_keys_are_sorted() -> None:
    payload = json.loads(_finding("PY-WL-101", "a.py", Severity.ERROR).to_jsonl())
    assert list(payload) == sorted(payload)


def test_attest_canonical_bytes_are_key_sorted_and_compact() -> None:
    assert _canonical_bytes({"b": 1, "a": {"d": 2, "c": 3}}) == b'{"a":{"c":3,"d":2},"b":1}'


def test_baseline_document_shape_is_pinned() -> None:
    doc = build_baseline_document([_finding("PY-WL-101", "a.py", Severity.ERROR)])
    assert list(doc) == ["fingerprint_scheme", "version", "entries"]
    assert list(doc["entries"][0]) == ["fingerprint", "rule_id", "path", "message"]


def test_baseline_orders_by_severity_then_rule_then_path_then_fingerprint() -> None:
    tie_a = _finding("PY-WL-101", "b.py", Severity.ERROR)  # no qualname
    tie_b = _finding("PY-WL-101", "b.py", Severity.ERROR, qualname="m.g")  # same (sev,rule,path), distinct fp
    findings = [
        _finding("PY-WL-108", "b.py", Severity.ERROR),
        _finding("PY-WL-101", "a.py", Severity.CRITICAL),
        tie_a,
        tie_b,
        _finding("PY-WL-101", "a.py", Severity.CRITICAL),  # duplicate fingerprint -> dedup, first wins
    ]
    doc = build_baseline_document(findings)
    assert len(doc["entries"]) == 4  # dedup collapsed the repeat
    assert [(e["rule_id"], e["path"]) for e in doc["entries"]] == [
        ("PY-WL-101", "a.py"),  # CRITICAL sorts first
        ("PY-WL-101", "b.py"),
        ("PY-WL-101", "b.py"),
        ("PY-WL-108", "b.py"),
    ]
    # The (severity, rule, path) tie breaks on the fingerprint hex, ascending.
    assert [e["fingerprint"] for e in doc["entries"][1:3]] == sorted([tie_a.fingerprint, tie_b.fingerprint])


def test_severity_outranks_rule_id_in_sort_key() -> None:
    # rule_id/path alone would rank these the OPPOSITE way (PY-WL-001 < PY-WL-999
    # lexicographically); severity must override that so this only passes if
    # severity is genuinely the primary sort key, not merely a key that happens
    # to agree with rule_id ordering on the other fixture's data.
    high_severity_high_rule = _finding("PY-WL-999", "z.py", Severity.CRITICAL)
    low_severity_low_rule = _finding("PY-WL-001", "a.py", Severity.WARN)
    doc = build_baseline_document([low_severity_low_rule, high_severity_high_rule])
    assert [e["rule_id"] for e in doc["entries"]] == ["PY-WL-999", "PY-WL-001"]


def test_dedup_keeps_first_occurrence_on_duplicate_fingerprint() -> None:
    from dataclasses import replace

    # Both share a fingerprint (same rule_id/path/qualname) but differ in an
    # observable field so first-vs-last-wins is distinguishable. The brief's own
    # dedup fixture used a field-identical duplicate, which cannot tell first-wins
    # from last-wins apart.
    first = _finding("PY-WL-101", "a.py", Severity.ERROR)
    duplicate_seen_later = replace(first, message="this later duplicate must be discarded")
    doc = build_baseline_document([first, duplicate_seen_later])
    assert len(doc["entries"]) == 1
    assert doc["entries"][0]["message"] == "m"


def test_rule_id_outranks_path_in_sort_key() -> None:
    # Same severity for both, and rule_id/path contradict each other: if path
    # outranked rule_id this would sort the OTHER way. This only passes if
    # rule_id is genuinely the second sort key, not merely a key that happens
    # to agree with path ordering on the other fixtures' data (where the
    # (sev,rule) tie group only ever contained one path, "b.py").
    high_rule_low_path = _finding("PY-WL-999", "a.py", Severity.ERROR)
    low_rule_high_path = _finding("PY-WL-001", "z.py", Severity.ERROR)
    doc = build_baseline_document([high_rule_low_path, low_rule_high_path])
    assert [e["rule_id"] for e in doc["entries"]] == ["PY-WL-001", "PY-WL-999"]


def test_path_order_is_independent_of_input_and_fingerprint_order() -> None:
    from dataclasses import replace

    a = _finding("PY-WL-101", "a.py", Severity.ERROR)
    z = _finding("PY-WL-101", "z.py", Severity.ERROR)
    # Reverse fingerprint lexicographic order so this fails if fingerprint ever
    # outranks path, and reverse the input so iteration order cannot rescue it.
    a = replace(a, fingerprint="f" * 64)
    z = replace(z, fingerprint="0" * 64)
    doc = build_baseline_document([z, a])
    assert [entry["path"] for entry in doc["entries"]] == ["a.py", "z.py"]
